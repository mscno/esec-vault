package server

// Shared projects. The server stores each project's signed chain and the
// grants that carry environment keys, sealed to their recipients. It checks
// everything with the same rules clients use, but clients trust none of it:
// they verify the chain from its first link and every signature against the
// signer's own user chain.

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/mscno/esec-vault/internal/chain"
	"github.com/mscno/esec-vault/internal/envelope"
	"github.com/mscno/esec-vault/internal/team"
	"github.com/mscno/esec-vault/internal/wire"
)

const (
	maxProjectLinksPer = 8
	maxGrantsPer       = 256
	// maxGrantsWaiting bounds the grants of one project waiting for one
	// recipient; the oldest go first.
	maxGrantsWaiting = 50
)

// projectParam returns the project id of a /v1/projects/{org}/{repo} route.
func projectParam(r *http.Request) (string, error) {
	id := r.PathValue("org") + "/" + r.PathValue("repo")
	return id, team.ValidProject(id)
}

// apiPerson returns another account's user chain and account proof, so a
// colleague can verify its keys before adding it to a project.
func (s *Server) apiPerson(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	if !s.limits.allow("people:"+c.device.ID, 300, time.Hour, s.now()) {
		writeErr(w, http.StatusTooManyRequests, wire.ErrRateLimited, "too many account lookups; try again later")
		return
	}
	ctx := r.Context()
	var u *userRow
	var err error
	if login := r.URL.Query().Get("login"); login != "" {
		if team.ValidLogin(login) != nil {
			writeErr(w, http.StatusBadRequest, wire.ErrInvalidRequest, "invalid GitHub login")
			return
		}
		u, err = s.db.userByLogin(ctx, login)
	} else {
		id := r.PathValue("id")
		if chain.ValidUser(id) != nil {
			writeErr(w, http.StatusBadRequest, wire.ErrInvalidRequest, "invalid account id")
			return
		}
		u, err = s.db.userByID(ctx, id)
	}
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if u == nil || !s.cfg.Allowed(u.GitHubID) {
		writeErr(w, http.StatusNotFound, wire.ErrNotFound, "no such account on this server; they sign in with 'esec vault login "+s.cfg.BaseURL+"' first")
		return
	}
	links, err := s.db.chainLinks(ctx, s.db.sql, u.ID, 0)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if len(links) == 0 {
		writeErr(w, http.StatusNotFound, wire.ErrNotFound, u.Login+" signed in but has not created a vault account yet")
		return
	}
	proof, err := s.db.accountProof(ctx, u.ID)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, wire.Person{User: u.wire(), Root: links[0].Hash(), Proof: proof, Links: links})
}

// apiPutProof stores the caller's GitHub SSH proof of their account.
func (s *Server) apiPutProof(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	var p wire.AccountProof
	if err := decodeStrict(c.body, &p); err != nil {
		writeErr(w, http.StatusBadRequest, wire.ErrInvalidRequest, "invalid request")
		return
	}
	ctx := r.Context()
	first, err := s.db.firstLink(ctx, c.user.ID)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	tp := team.AccountProof(p)
	if err := tp.Check(); err != nil || first == nil || p.User != c.user.ID || p.Root != first.Hash() || !strings.EqualFold(p.Login, c.user.Login) {
		writeErr(w, http.StatusBadRequest, wire.ErrInvalidRequest, "the proof is not for this account (sign in again if your GitHub login changed)")
		return
	}
	now := s.now()
	err = s.db.tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO account_proofs (user_id, login, root, signature, created_at) VALUES (?, ?, ?, ?, ?)
			ON CONFLICT(user_id) DO UPDATE SET login = excluded.login, root = excluded.root, signature = excluded.signature, created_at = excluded.created_at`,
			p.User, p.Login, p.Root, p.Signature, now.Unix()); err != nil {
			return err
		}
		return s.db.audit(ctx, tx, c.user.ID, c.device.ID, c.ip, "account_proof", p.Login, now)
	})
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, struct{}{})
}

// apiProjects lists the caller's shared projects.
func (s *Server) apiProjects(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	ctx := r.Context()
	ids, err := s.db.memberProjects(ctx, c.user.ID)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	out := wire.Projects{Projects: []wire.ProjectSummary{}}
	for _, id := range ids {
		st, err := s.listedProject(ctx, id)
		if err != nil {
			s.internalError(w, r, err)
			return
		}
		if st == nil {
			continue
		}
		m, ok := st.Member(c.user.ID)
		if !ok {
			continue
		}
		sum := wire.ProjectSummary{ID: id, Seq: st.Seq, Admin: m.Admin, Envs: st.Access(c.user.ID), Members: len(st.ActiveMembers()), Machines: len(st.ActiveMachines()), Groups: len(st.ActiveGroups()), Archived: st.Archived}
		sum.Rotate = s.exposedEnvs(ctx, st)
		sum.Rotations = len(sum.Rotate)
		if st.Successor != nil {
			sum.Successor = st.Successor.Project
		}
		out.Projects = append(out.Projects, sum)
	}
	writeJSON(w, http.StatusOK, out)
}

// listedProject loads a project for a list. A stored chain that does not
// verify is logged and left out, so one broken project cannot break every
// list and page it would appear on.
func (s *Server) listedProject(ctx context.Context, id string) (*team.State, error) {
	st, _, err := s.db.projectState(ctx, s.db.sql, id)
	if err != nil {
		if ctx.Err() != nil {
			return nil, err
		}
		s.log.Warn("shared project does not verify; leaving it out", "project", id, "error", err)
		return nil, nil
	}
	return st, nil
}

// memberState loads a project the caller is an active member of.
func (s *Server) memberState(ctx context.Context, project, user string) (*team.State, []*envelope.Envelope, error) {
	st, links, err := s.db.projectState(ctx, s.db.sql, project)
	if err != nil {
		return nil, nil, err
	}
	if st == nil {
		return nil, nil, clientErr(http.StatusNotFound, wire.ErrNotFound, "no shared project %s", project)
	}
	if _, ok := st.Member(user); !ok {
		return nil, nil, clientErr(http.StatusForbidden, wire.ErrForbidden, "you are not a member of %s", project)
	}
	return st, links, nil
}

func (s *Server) apiProjectChain(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	project, err := projectParam(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, wire.ErrInvalidRequest, err.Error())
		return
	}
	ctx := r.Context()
	st, links, err := s.memberState(ctx, project, c.user.ID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	chains, err := s.db.signerChains(ctx, s.db.sql, st)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, wire.ProjectChain{Links: links, Chains: chains})
}

func (s *Server) apiProjectStatus(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	project, err := projectParam(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, wire.ErrInvalidRequest, err.Error())
		return
	}
	ctx := r.Context()
	st, _, err := s.memberState(ctx, project, c.user.ID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	status, err := s.db.projectStatus(ctx, st)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, status)
}

func (s *Server) apiProjectCommit(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	project, err := projectParam(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, wire.ErrInvalidRequest, err.Error())
		return
	}
	var req wire.ProjectCommit
	if err := decodeStrict(c.body, &req); err != nil {
		writeErr(w, http.StatusBadRequest, wire.ErrInvalidRequest, "invalid request")
		return
	}
	if len(req.Links) == 0 && len(req.Grants) == 0 {
		writeErr(w, http.StatusBadRequest, wire.ErrInvalidRequest, "empty commit")
		return
	}
	if len(req.Links) > maxProjectLinksPer || len(req.Grants) > maxGrantsPer || slices.Contains(req.Links, nil) || slices.Contains(req.Grants, nil) {
		writeErr(w, http.StatusBadRequest, wire.ErrInvalidRequest, "commit too large or invalid")
		return
	}
	ctx := r.Context()
	var out wire.ProjectCommitResult
	var wake []string
	err = s.db.tx(ctx, func(tx *sql.Tx) error {
		res, users, err := s.projectCommit(ctx, tx, c, project, &req, false)
		if res != nil {
			out = *res
		}
		wake = users
		return err
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	for _, u := range wake {
		s.notify.wake(u)
	}
	s.kickAlerts()
	writeJSON(w, http.StatusOK, out)
}

// projectCommit applies a project commit inside tx and returns the accounts
// to wake.
func (s *Server) projectCommit(ctx context.Context, tx *sql.Tx, c *reqCtx, project string, req *wire.ProjectCommit, transfer bool) (*wire.ProjectCommitResult, []string, error) { //nolint:gocyclo // one linear validation pass, kept together for review
	now := s.now()
	chains := s.db.userChains(ctx, tx)
	caller, err := chains(c.user.ID)
	if err != nil {
		return nil, nil, clientErr(http.StatusBadRequest, wire.ErrInvalidRequest, "create your vault account first")
	}
	stored, err := s.db.projectLinks(ctx, tx, project, 0)
	if err != nil {
		return nil, nil, err
	}
	st, err := team.Verify(project, stored, chains)
	if err != nil {
		return nil, nil, fmt.Errorf("stored chain of project %s does not verify: %w", project, err)
	}
	if st.Seq > 0 {
		if _, ok := st.Member(c.user.ID); !ok {
			return nil, nil, clientErr(http.StatusForbidden, wire.ErrForbidden, "you are not a member of %s", project)
		}
	} else if len(req.Links) == 0 {
		return nil, nil, clientErr(http.StatusNotFound, wire.ErrNotFound, "no shared project %s", project)
	}
	if st.Seq+uint64(len(req.Links)) > team.MaxLinks {
		return nil, nil, clientErr(http.StatusBadRequest, wire.ErrInvalidRequest, "the project chain is full")
	}
	wake := map[string]bool{}
	var groupWoken []string
	for m := range holders(st, true) {
		wake[m] = true
	}
	for _, e := range req.Links {
		l, err := team.PeekLink(e)
		if err != nil {
			return nil, nil, clientErr(http.StatusBadRequest, wire.ErrInvalidRequest, "invalid link: %v", err)
		}
		if l.Signer != c.user.ID || l.SignerKey != caller.UKeyVersion || l.SignerSeq > caller.Seq {
			return nil, nil, clientErr(http.StatusBadRequest, wire.ErrInvalidRequest, "links must be signed with your current user key")
		}
		if l.Seq != st.Seq+1 && st.Seq > 0 {
			return nil, nil, clientErr(http.StatusConflict, wire.ErrConflict, "the project changed on the server; refresh and retry")
		}
		if l.CTime.After(now.Add(10*time.Minute)) || l.CTime.Before(now.Add(-24*time.Hour)) {
			return nil, nil, clientErr(http.StatusBadRequest, wire.ErrInvalidRequest, "link time %s is too far from the server's clock; check this machine's clock", l.CTime.Format(time.RFC3339))
		}
		if l.Type == team.TypeInit {
			var init team.InitBody
			if err := envelope.DecodeStrict(l.Body, &init); err != nil {
				return nil, nil, clientErr(http.StatusBadRequest, wire.ErrInvalidRequest, "invalid init")
			}
			if init.Predecessor != nil && !transfer {
				return nil, nil, clientErr(http.StatusBadRequest, wire.ErrInvalidRequest, "use the atomic transfer endpoint for a moved project")
			}
			var n int
			if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM projects WHERE id = ?`, project).Scan(&n); err != nil {
				return nil, nil, err
			}
			if n > 0 || st.Seq > 0 {
				return nil, nil, clientErr(http.StatusConflict, wire.ErrConflict, "%s is already a shared project; ask one of its admins to add you", project)
			}
		}
		next, err := s.appendProjectLink(ctx, tx, st, e, *l, chains, c.user.ID, c.ip, now)
		if err != nil {
			return nil, nil, err
		}
		st = next
	}
	if err := s.db.mirrorProject(ctx, tx, st, now); err != nil {
		return nil, nil, err
	}
	for m := range holders(st, true) {
		wake[m] = true
	}
	for _, e := range req.Grants {
		to, err := s.storeGrant(ctx, tx, c, caller, st, e, chains, now)
		if err != nil {
			return nil, nil, err
		}
		if _, isMember := st.Member(to); isMember {
			if err := s.db.addEvent(ctx, tx, to, wire.EventGrant, project, now); err != nil {
				return nil, nil, err
			}
		}
		// Keys sealed to a group reach its people's devices too.
		if id, isGroup := strings.CutPrefix(to, team.GroupHolderPrefix); isGroup {
			people, err := s.groupPeople(ctx, tx, id, project, now)
			if err != nil {
				return nil, nil, err
			}
			groupWoken = append(groupWoken, people...)
		}
	}
	users := groupWoken
	for u := range wake {
		if _, isMember := st.Members[u]; !isMember {
			continue
		}
		if err := s.db.addEvent(ctx, tx, u, wire.EventProject, project, now); err != nil {
			return nil, nil, err
		}
		users = append(users, u)
	}
	summary := fmt.Sprintf("%s links=%d grants=%d", project, len(req.Links), len(req.Grants))
	if err := s.db.audit(ctx, tx, c.user.ID, c.device.ID, c.ip, "project_commit", summary, now); err != nil {
		return nil, nil, err
	}
	return &wire.ProjectCommitResult{Seq: st.Seq}, users, nil
}

// appendProjectLink verifies e as the next link of st, checks what only
// the server can, and stores it with its audit entry and alert. A project's
// first link also creates the project.
func (s *Server) appendProjectLink(ctx context.Context, tx *sql.Tx, st *team.State, e *envelope.Envelope, l team.Link, chains team.Chains, actor, ip string, now time.Time) (*team.State, error) {
	next, err := st.Next(e, chains)
	if err != nil {
		return nil, clientErr(http.StatusBadRequest, wire.ErrInvalidRequest, "link rejected: %v", err)
	}
	if l.Type == team.TypeEnvRename {
		if err := renameEnvironmentMetadata(ctx, tx, st.Project, l); err != nil {
			return nil, err
		}
	}
	if err := s.checkNewMember(ctx, tx, l, chains); err != nil {
		return nil, err
	}
	if err := checkNewMachine(ctx, tx, st.Project, l); err != nil {
		return nil, err
	}
	if err := s.checkGroupSet(ctx, tx, l); err != nil {
		return nil, err
	}
	if err := s.checkPolicyProjectLink(ctx, tx, st.Project, l); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(e)
	if err != nil {
		return nil, err
	}
	if l.Type == team.TypeInit {
		if _, err := tx.ExecContext(ctx, `INSERT INTO projects (id, created_by, created_at) VALUES (?, ?, ?)`, st.Project, actor, now.Unix()); err != nil {
			return nil, err
		}
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO project_links (project, seq, hash, envelope, signer, created_at) VALUES (?, ?, ?, ?, ?, ?)`, st.Project, l.Seq, e.Hash(), raw, l.Signer, now.Unix()); err != nil {
		return nil, err
	}
	if err := s.db.projectAudit(ctx, tx, st.Project, actor, ip, "link_"+l.Type, linkSummary(st, next, l), now); err != nil {
		return nil, err
	}
	if err := s.queueProjectAlert(ctx, tx, st, next, l, ip, now); err != nil {
		return nil, err
	}
	return next, nil
}

// checkNewMember checks, for a member_add link, that the account exists on
// this server under that login and root. Clients check the root themselves;
// this only rejects mistakes early.
func (s *Server) checkNewMember(ctx context.Context, tx *sql.Tx, l team.Link, chains team.Chains) error {
	var p team.Person
	switch l.Type {
	case team.TypeInit:
		var b team.InitBody
		if err := envelope.DecodeStrict(l.Body, &b); err != nil {
			return err
		}
		p = b.Creator
	case team.TypeMemberAdd:
		var b team.MemberAddBody
		if err := envelope.DecodeStrict(l.Body, &b); err != nil {
			return err
		}
		p = b.Member
	default:
		return nil
	}
	var gh int64
	var login string
	err := tx.QueryRowContext(ctx, `SELECT github_id, login FROM users WHERE id = ?`, p.User).Scan(&gh, &login)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && !s.cfg.Allowed(gh)) {
		return clientErr(http.StatusBadRequest, wire.ErrInvalidRequest, "%s has no account on this server", p.Login)
	}
	if err != nil {
		return err
	}
	cs, err := chains(p.User)
	if err != nil || cs.Root() != p.Root || !strings.EqualFold(login, p.Login) {
		return clientErr(http.StatusBadRequest, wire.ErrInvalidRequest, "the account recorded for %s is not that person's account on this server", p.Login)
	}
	return nil
}

// checkNewMachine refuses a machine id another project uses: machine
// requests name only the id, so ids are unique on the server.
func checkNewMachine(ctx context.Context, tx *sql.Tx, project string, l team.Link) error {
	if l.Type != team.TypeMachineAdd {
		return nil
	}
	var b team.MachineAddBody
	if err := envelope.DecodeStrict(l.Body, &b); err != nil {
		return err
	}
	var n int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM project_machines WHERE id = ? AND project != ?`, b.Machine.ID, project).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return clientErr(http.StatusConflict, wire.ErrConflict, "machine id %s is taken; create the machine again", b.Machine.ID)
	}
	return nil
}

// checkGroupSet checks, for a group_set link granting environments, that
// the group exists here with that root.
func (s *Server) checkGroupSet(ctx context.Context, tx *sql.Tx, l team.Link) error {
	if l.Type != team.TypeGroupSet {
		return nil
	}
	var b team.GroupSetBody
	if err := envelope.DecodeStrict(l.Body, &b); err != nil {
		return err
	}
	if len(b.Envs) == 0 {
		return nil
	}
	var hash string
	err := tx.QueryRowContext(ctx, `SELECT hash FROM group_links WHERE group_id = ? AND seq = 1`, b.Group).Scan(&hash)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && hash != b.Root) {
		return clientErr(http.StatusBadRequest, wire.ErrInvalidRequest, "%s is not a machine group with that root on this server", b.Group)
	}
	if err != nil {
		return err
	}
	var n int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM group_access WHERE group_id = ? AND project = ?`, b.Group, l.Project).Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		return clientErr(http.StatusConflict, wire.ErrConflict, "the group %s does not take keys from %s yet; an admin of the group runs 'esec vault group set' first", b.Group, l.Project)
	}
	return nil
}

// storeGrant checks a grant against the new state and stores it; it returns
// the recipient.
func (s *Server) storeGrant(ctx context.Context, tx *sql.Tx, c *reqCtx, caller *chain.State, st *team.State, e *envelope.Envelope, chains team.Chains, now time.Time) (string, error) {
	if st.Archived {
		return "", clientErr(http.StatusConflict, wire.ErrConflict, "%s is archived: it sends no keys", st.Project)
	}
	g, err := team.CheckGrant(e, st, chains)
	if err != nil {
		return "", clientErr(http.StatusBadRequest, wire.ErrInvalidRequest, "grant rejected: %v", err)
	}
	if g.From != c.user.ID || g.FromKey != caller.UKeyVersion {
		return "", clientErr(http.StatusBadRequest, wire.ErrInvalidRequest, "grants must be signed with your current user key")
	}
	if g.CTime.After(now.Add(10*time.Minute)) || g.CTime.Before(now.Add(-24*time.Hour)) {
		return "", clientErr(http.StatusBadRequest, wire.ErrInvalidRequest, "grant time is too far from the server's clock")
	}
	if err := s.checkGrantRecipient(ctx, tx, st, g, chains); err != nil {
		return "", err
	}
	envs, err := json.Marshal(g.Envs)
	if err != nil {
		return "", err
	}
	raw, err := json.Marshal(e)
	if err != nil {
		return "", err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO project_grants (project, to_id, to_ukey_version, envs, envelope, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		st.Project, g.To, g.ToKey, string(envs), raw, c.user.ID, now.Unix()); err != nil {
		return "", err
	}
	names := make([]string, 0, len(g.Envs))
	for _, env := range g.Envs {
		names = append(names, env.Name)
	}
	return g.To, s.db.projectAudit(ctx, tx, st.Project, c.user.ID, c.ip, "grant", g.To+" "+strings.Join(names, ","), now)
}

// checkGrantRecipient checks that a grant is sealed to its recipient's
// current key. A machine keeps one grant with all of its environments, so
// its older grant is dropped.
func (s *Server) checkGrantRecipient(ctx context.Context, tx *sql.Tx, st *team.State, g *team.Grant, chains team.Chains) error {
	if _, isMember := st.Member(g.To); isMember {
		cs, err := chains(g.To)
		if err != nil {
			return err
		}
		if g.ToKey != cs.UKeyVersion || g.ToEncPub != hex.EncodeToString(cs.EncPub[:]) {
			return clientErr(http.StatusConflict, wire.ErrConflict, "%s has a new user key; refresh and retry", g.To)
		}
		return s.supersede(ctx, tx, st.Project, g)
	}
	names := make([]string, 0, len(g.Envs))
	for _, env := range g.Envs {
		names = append(names, env.Name)
	}
	if id, isGroup := strings.CutPrefix(g.To, team.GroupHolderPrefix); isGroup {
		pg, ok := st.Group(id)
		if !ok {
			return clientErr(http.StatusBadRequest, wire.ErrInvalidRequest, "grant to an unknown recipient")
		}
		gs, _, err := s.db.groupState(ctx, tx, id)
		if err != nil {
			return err
		}
		if gs == nil || gs.Root() != pg.Root {
			return clientErr(http.StatusBadRequest, wire.ErrInvalidRequest, "the group %s is not the one the project names", id)
		}
		if g.ToKey != gs.Key.Version || g.ToEncPub != gs.Key.EncPub {
			return clientErr(http.StatusConflict, wire.ErrConflict, "the group %s has a new key; refresh and retry", id)
		}
		if !slices.Equal(team.SortEnvs(names), pg.Envs) {
			return clientErr(http.StatusBadRequest, wire.ErrInvalidRequest, "a group's grant must carry all of its environments")
		}
		_, err = tx.ExecContext(ctx, `DELETE FROM project_grants WHERE project = ? AND to_id = ?`, st.Project, g.To)
		return err
	}
	m, ok := st.Machine(g.To)
	if !ok || g.ToKey != 0 || g.ToEncPub != m.EncPub {
		return clientErr(http.StatusBadRequest, wire.ErrInvalidRequest, "grant to an unknown recipient")
	}
	if !slices.Equal(team.SortEnvs(names), m.Envs) {
		return clientErr(http.StatusBadRequest, wire.ErrInvalidRequest, "a machine's grant must carry all of its environments")
	}
	_, err := tx.ExecContext(ctx, `DELETE FROM project_grants WHERE project = ? AND to_id = ?`, st.Project, g.To)
	return err
}

// supersede drops the waiting grants to g's recipient in the project that
// g makes useless (sealed to an older key, or for no environment g does
// not carry too), and the oldest beyond maxGrantsWaiting-1, so a new grant
// always fits.
func (s *Server) supersede(ctx context.Context, tx *sql.Tx, project string, g *team.Grant) error {
	waiting, err := s.db.grants(ctx, tx, `project = ? AND to_id = ?`, project, g.To)
	if err != nil {
		return err
	}
	carried := map[string]bool{}
	for _, e := range g.Envs {
		carried[e.Name] = true
	}
	keep := 0
	for i := len(waiting) - 1; i >= 0; i-- {
		old := waiting[i]
		covered := old.Version < g.ToKey
		if !covered {
			covered = true
			for _, e := range old.Envs {
				if !carried[e.Name] {
					covered = false
				}
			}
		}
		if covered || keep >= maxGrantsWaiting-1 {
			if _, err := tx.ExecContext(ctx, `DELETE FROM project_grants WHERE id = ?`, old.ID); err != nil {
				return err
			}
			continue
		}
		keep++
	}
	return nil
}

// apiGrants lists the grants waiting for the caller.
func (s *Server) apiGrants(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	ctx := r.Context()
	rows, err := s.db.grants(ctx, s.db.sql, `to_id = ? AND project IN (SELECT project FROM project_members WHERE user_id = ? AND active = 1)`, c.user.ID, c.user.ID)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	out := wire.Grants{Grants: []wire.GrantItem{}}
	for _, g := range rows {
		out.Grants = append(out.Grants, wire.GrantItem{ID: g.ID, Project: g.Project, Grant: g.Env})
	}
	writeJSON(w, http.StatusOK, out)
}

// apiGrantAck removes handled grants and records what the caller now holds.
func (s *Server) apiGrantAck(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	var req wire.GrantAck
	if err := decodeStrict(c.body, &req); err != nil || len(req.IDs) > 1000 || len(req.Holdings) > 1000 {
		writeErr(w, http.StatusBadRequest, wire.ErrInvalidRequest, "invalid request")
		return
	}
	ctx := r.Context()
	now := s.now()
	states := map[string]*team.State{}
	var projects []string
	for _, h := range req.Holdings {
		st, ok := states[h.Project]
		if !ok {
			var err error
			st, _, err = s.db.projectState(ctx, s.db.sql, h.Project)
			if err != nil {
				s.internalError(w, r, err)
				return
			}
			states[h.Project] = st
			projects = append(projects, h.Project)
		}
		if st == nil || !st.HasAccess(c.user.ID, h.Env) || st.Envs[h.Env].PublicKey != h.PublicKey {
			writeErr(w, http.StatusBadRequest, wire.ErrInvalidRequest, "holding of "+h.Project+" "+h.Env+" is not a current key you may read")
			return
		}
	}
	err := s.db.tx(ctx, func(tx *sql.Tx) error {
		for _, id := range req.IDs {
			if _, err := tx.ExecContext(ctx, `DELETE FROM project_grants WHERE id = ? AND to_id = ?`, id, c.user.ID); err != nil {
				return err
			}
		}
		for _, h := range req.Holdings {
			if _, err := tx.ExecContext(ctx, `INSERT INTO project_holdings (project, holder, env, public_key, updated_at) VALUES (?, ?, ?, ?, ?)
				ON CONFLICT(project, holder, env) DO UPDATE SET public_key = excluded.public_key, updated_at = excluded.updated_at`,
				h.Project, c.user.ID, h.Env, h.PublicKey, now.Unix()); err != nil {
				return err
			}
		}
		for _, p := range projects {
			if err := s.db.projectAudit(ctx, tx, p, c.user.ID, c.ip, "keys_received", envsOf(req.Holdings, p), now); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, struct{}{})
}

func envsOf(hs []wire.Holding, project string) string {
	var out []string
	for _, h := range hs {
		if h.Project == project {
			out = append(out, h.Env)
		}
	}
	return strings.Join(team.SortEnvs(out), ",")
}

// linkSummary describes a link for the project audit log.
func linkSummary(before, after *team.State, l team.Link) string {
	switch l.Type {
	case team.TypeArchive:
		if after.Successor != nil {
			return "moved to " + after.Successor.Project
		}
		return "archived"
	case team.TypeUnarchive:
		return "unarchived"
	case team.TypeInit:
		return "envs " + envList(after.EnvNames())
	case team.TypeMemberAdd, team.TypeMemberUpdate:
		var b struct {
			Member team.Person `json:"member"`
			User   string      `json:"user"`
		}
		_ = json.Unmarshal(l.Body, &b)
		id := b.Member.User + b.User
		m := after.Members[id]
		if m == nil {
			return id
		}
		role := "reads " + envList(m.Envs)
		if m.Admin {
			role = "admin"
		}
		return m.Login + " " + role
	case team.TypeMemberRemove:
		var b team.MemberRemoveBody
		_ = json.Unmarshal(l.Body, &b)
		if m := before.Members[b.User]; m != nil {
			return m.Login
		}
		return b.User
	case team.TypeEnvSet:
		var b team.EnvSetBody
		_ = json.Unmarshal(l.Body, &b)
		return b.Env.Name + " " + b.Env.PublicKey
	case team.TypeEnvRename:
		var b team.EnvRenameBody
		_ = json.Unmarshal(l.Body, &b)
		return b.Old + " -> " + b.New
	case team.TypeMachineAdd:
		var b team.MachineAddBody
		_ = json.Unmarshal(l.Body, &b)
		return b.Machine.Name + " reads " + envList(b.Envs)
	case team.TypeMachineRemove:
		var b team.MachineRemoveBody
		_ = json.Unmarshal(l.Body, &b)
		if m := before.Machines[b.ID]; m != nil {
			return m.Name
		}
		return b.ID
	case team.TypeGroupSet:
		var b team.GroupSetBody
		_ = json.Unmarshal(l.Body, &b)
		return "group " + b.Group + " reads " + envList(b.Envs)
	}
	return strconv.FormatUint(l.Seq, 10)
}
