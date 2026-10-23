package server

// Machine groups. The server stores each group's signed chain, the group
// key sealed to each machine, token and admin, the join requests of machines
// waiting to be let in, and changes made on the web pages until an admin's
// device signs them. Like project chains, clients trust none of it: machines
// verify the group chain from the root their key names.

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/mscno/esec-vault/internal/chain"
	"github.com/mscno/esec-vault/internal/envelope"
	"github.com/mscno/esec-vault/internal/team"
	"github.com/mscno/esec-vault/internal/wire"
)

const (
	maxGroupLinksPer     = 16
	maxKeyGrantsPer      = 1100
	maxPendingJoins      = 100
	maxPendingJoinsPerIP = 10
	joinLifetime         = 24 * time.Hour
	maxOpenProposals     = 100
	maxEnrollsPerTokenHr = 300
)

// groupParam returns the group id of a /v1/groups/{org}/{name} route.
func groupParam(r *http.Request) (string, error) {
	id := r.PathValue("org") + "/" + r.PathValue("name")
	return id, team.ValidGroup(id)
}

// apiGroups lists the groups the caller administers or whose machines
// read their projects.
func (s *Server) apiGroups(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	ctx := r.Context()
	ids, err := s.db.visibleGroups(ctx, c.user.ID)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	out := wire.Groups{Groups: []wire.GroupSummary{}}
	for _, id := range ids {
		gs, err := s.listedGroup(ctx, id)
		if err != nil {
			s.internalError(w, r, err)
			return
		}
		if gs == nil {
			continue
		}
		sum := wire.GroupSummary{ID: id, Seq: gs.Seq, Admin: gs.Admin(c.user.ID), Member: gs.Member(c.user.ID) && !gs.Admin(c.user.ID), People: len(gs.KeyHolders()), Machines: len(gs.ActiveCreds(team.KindMachine)), Tokens: len(gs.ActiveCreds(team.KindToken)), Projects: gs.Projects(), KeyExposed: len(gs.KeyExposed)}
		if sum.Admin {
			joins, err := s.db.pendingJoins(ctx, id, s.now())
			if err != nil {
				s.internalError(w, r, err)
				return
			}
			props, err := s.db.openChanges(ctx, wire.ScopeGroup, id)
			if err != nil {
				s.internalError(w, r, err)
				return
			}
			sum.Pending = len(joins) + len(props)
		}
		out.Groups = append(out.Groups, sum)
	}
	writeJSON(w, http.StatusOK, out)
}

// listedGroup loads a group for a list, leaving out one whose stored chain
// does not verify.
func (s *Server) listedGroup(ctx context.Context, id string) (*team.GroupState, error) {
	gs, _, err := s.db.groupState(ctx, s.db.sql, id)
	if err != nil {
		if ctx.Err() != nil {
			return nil, err
		}
		s.log.Warn("machine group does not verify; leaving it out", "group", id, "error", err)
		return nil, nil
	}
	return gs, nil
}

// readableGroup loads a group the caller may read.
func (s *Server) readableGroup(ctx context.Context, group, user string) (*team.GroupState, []*envelope.Envelope, error) {
	gs, links, err := s.db.groupState(ctx, s.db.sql, group)
	if err != nil {
		return nil, nil, err
	}
	if gs == nil {
		return nil, nil, clientErr(http.StatusNotFound, wire.ErrNotFound, "no machine group %s", group)
	}
	ok, err := s.db.canReadGroup(ctx, user, group)
	if err != nil {
		return nil, nil, err
	}
	if !ok {
		return nil, nil, clientErr(http.StatusForbidden, wire.ErrForbidden, "you are not an admin of %s, and it reads none of your projects", group)
	}
	return gs, links, nil
}

func (s *Server) apiGroupChain(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	group, err := groupParam(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, wire.ErrInvalidRequest, err.Error())
		return
	}
	ctx := r.Context()
	gs, links, err := s.readableGroup(ctx, group, c.user.ID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	chains := map[string][]*envelope.Envelope{}
	if err := s.db.addChains(ctx, s.db.sql, chains, groupSigners(gs)...); err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, wire.GroupChain{Links: links, Chains: chains})
}

// adminGroup loads a group the caller administers.
func (s *Server) adminGroup(ctx context.Context, group, user string) (*team.GroupState, error) {
	gs, _, err := s.db.groupState(ctx, s.db.sql, group)
	if err != nil {
		return nil, err
	}
	if gs == nil {
		return nil, clientErr(http.StatusNotFound, wire.ErrNotFound, "no machine group %s", group)
	}
	if !gs.Admin(user) {
		return nil, clientErr(http.StatusForbidden, wire.ErrForbidden, "you are not an admin of %s", group)
	}
	return gs, nil
}

func (s *Server) apiGroupStatus(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	group, err := groupParam(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, wire.ErrInvalidRequest, err.Error())
		return
	}
	ctx := r.Context()
	gs, err := s.adminGroup(ctx, group, c.user.ID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	status, err := s.db.groupStatus(ctx, gs, s.now())
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, status)
}

// keyHolderGroup loads a group the caller is an admin or member of.
func (s *Server) keyHolderGroup(ctx context.Context, group, user string) (*team.GroupState, []*envelope.Envelope, error) {
	gs, links, err := s.db.groupState(ctx, s.db.sql, group)
	if err != nil {
		return nil, nil, err
	}
	if gs == nil {
		return nil, nil, clientErr(http.StatusNotFound, wire.ErrNotFound, "no group %s", group)
	}
	if !gs.HoldsKey(user) {
		return nil, nil, clientErr(http.StatusForbidden, wire.ErrForbidden, "you are not an admin or member of %s", group)
	}
	return gs, links, nil
}

// apiGroupKeyGrants returns the caller's own grant of the group key.
func (s *Server) apiGroupKeyGrants(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	group, err := groupParam(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, wire.ErrInvalidRequest, err.Error())
		return
	}
	ctx := r.Context()
	gs, _, err := s.keyHolderGroup(ctx, group, c.user.ID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if !gs.Admin(c.user.ID) {
		if blocked, err := s.memberBlocked(ctx, group, c.user.ID); err != nil || blocked {
			if err == nil {
				err = clientErr(http.StatusForbidden, wire.ErrForbidden, "an admin of %s is removing you from it", group)
			}
			s.fail(w, r, err)
			return
		}
	}
	rows, err := s.db.keyGrants(ctx, s.db.sql, group, c.user.ID)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	out := wire.GroupKeyGrants{Grants: []*envelope.Envelope{}}
	for _, g := range rows {
		out.Grants = append(out.Grants, g.Env)
	}
	writeJSON(w, http.StatusOK, out)
}

// apiGroupKeys gives an admin or member what a machine of the group gets:
// the group chain, their grant of the group key, and each project's keys
// sealed to the group. Their device verifies all of it like a machine does.
func (s *Server) apiGroupKeys(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	group, err := groupParam(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, wire.ErrInvalidRequest, err.Error())
		return
	}
	ctx := r.Context()
	gs, links, err := s.keyHolderGroup(ctx, group, c.user.ID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if !gs.Admin(c.user.ID) {
		blocked, err := s.memberBlocked(ctx, group, c.user.ID)
		if err != nil {
			s.internalError(w, r, err)
			return
		}
		if blocked {
			writeErr(w, http.StatusForbidden, wire.ErrForbidden, "an admin of "+group+" is removing you from it")
			return
		}
	}
	out, err := s.fleetKeys(ctx, gs, links, c.user.ID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	projects := make([]string, 0, len(out.Projects))
	for _, p := range out.Projects {
		projects = append(projects, p.Project)
	}
	if err := s.db.groupAudit(ctx, s.db.sql, group, c.user.ID, c.ip, "member_keys", truncate(strings.Join(projects, ","), 500), s.now()); err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) apiGroupCommit(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	group, err := groupParam(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, wire.ErrInvalidRequest, err.Error())
		return
	}
	var req wire.GroupCommit
	if err := decodeStrict(c.body, &req); err != nil {
		writeErr(w, http.StatusBadRequest, wire.ErrInvalidRequest, "invalid request")
		return
	}
	if len(req.Links) == 0 && len(req.KeyGrants) == 0 {
		writeErr(w, http.StatusBadRequest, wire.ErrInvalidRequest, "empty commit")
		return
	}
	if len(req.Links) > maxGroupLinksPer || len(req.KeyGrants) > maxKeyGrantsPer || slices.Contains(req.Links, nil) || slices.Contains(req.KeyGrants, nil) {
		writeErr(w, http.StatusBadRequest, wire.ErrInvalidRequest, "commit too large or invalid")
		return
	}
	ctx := r.Context()
	var out wire.GroupCommitResult
	var wake []string
	err = s.db.tx(ctx, func(tx *sql.Tx) error {
		seq, users, err := s.groupCommit(ctx, tx, c, group, &req)
		out.Seq, wake = seq, users
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

// groupCommit applies a group commit inside tx and returns the new length
// and the accounts to wake.
func (s *Server) groupCommit(ctx context.Context, tx *sql.Tx, c *reqCtx, group string, req *wire.GroupCommit) (uint64, []string, error) { //nolint:gocyclo // one linear validation pass, kept together for review
	now := s.now()
	chains := s.db.userChains(ctx, tx)
	caller, err := chains(c.user.ID)
	if err != nil {
		return 0, nil, clientErr(http.StatusBadRequest, wire.ErrInvalidRequest, "create your vault account first")
	}
	stored, err := s.db.groupLinks(ctx, tx, group)
	if err != nil {
		return 0, nil, err
	}
	gs, err := team.VerifyGroup(group, stored, chains)
	if err != nil {
		return 0, nil, fmt.Errorf("stored chain of group %s does not verify: %w", group, err)
	}
	if gs.Seq > 0 && !gs.Admin(c.user.ID) {
		// A member may only leave; the chain checks that their link does.
		if !gs.Member(c.user.ID) || len(req.KeyGrants) > 0 {
			return 0, nil, clientErr(http.StatusForbidden, wire.ErrForbidden, "you are not an admin of %s", group)
		}
	}
	if gs.Seq == 0 && len(req.Links) == 0 {
		return 0, nil, clientErr(http.StatusNotFound, wire.ErrNotFound, "no machine group %s", group)
	}
	if gs.Seq+uint64(len(req.Links)) > team.MaxLinks {
		return 0, nil, clientErr(http.StatusBadRequest, wire.ErrInvalidRequest, "the group chain is full")
	}
	before := gs
	for _, e := range req.Links {
		l, err := team.PeekGroupLink(e)
		if err != nil {
			return 0, nil, clientErr(http.StatusBadRequest, wire.ErrInvalidRequest, "invalid link: %v", err)
		}
		if l.Signer != c.user.ID || l.SignerKey != caller.UKeyVersion || l.SignerSeq > caller.Seq {
			return 0, nil, clientErr(http.StatusBadRequest, wire.ErrInvalidRequest, "links must be signed with your current user key")
		}
		if l.Seq != gs.Seq+1 {
			return 0, nil, clientErr(http.StatusConflict, wire.ErrConflict, "the group changed on the server; refresh and retry")
		}
		if err := linkClock(l.CTime, now); err != nil {
			return 0, nil, err
		}
		if l.Type == team.GroupInit {
			var n int
			if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM machine_groups WHERE id = ?`, group).Scan(&n); err != nil {
				return 0, nil, err
			}
			if n > 0 || gs.Seq > 0 {
				return 0, nil, clientErr(http.StatusConflict, wire.ErrConflict, "the group %s exists already; pick another name, or ask one of its admins to add you", group)
			}
		}
		next, err := gs.Next(e, chains)
		if err != nil {
			return 0, nil, clientErr(http.StatusBadRequest, wire.ErrInvalidRequest, "link rejected: %v", err)
		}
		if err := s.checkGroupLink(ctx, tx, gs, *l, chains, now); err != nil {
			return 0, nil, err
		}
		if err := s.storeGroupLink(ctx, tx, gs, next, e, *l, c.user.ID, c.ip, now); err != nil {
			return 0, nil, err
		}
		gs = next
	}
	if err := s.db.mirrorGroup(ctx, tx, gs, now); err != nil {
		return 0, nil, err
	}
	for _, e := range req.KeyGrants {
		if err := s.storeKeyGrant(ctx, tx, gs, e, chains, func(g *team.KeyGrant) error {
			if g.From != c.user.ID || g.FromKey != caller.UKeyVersion {
				return clientErr(http.StatusBadRequest, wire.ErrInvalidRequest, "key grants must be signed with your current user key")
			}
			return nil
		}, c.user.ID, now); err != nil {
			return 0, nil, err
		}
	}
	users, err := s.groupWake(ctx, tx, before, gs, now)
	if err != nil {
		return 0, nil, err
	}
	summary := fmt.Sprintf("%s links=%d key_grants=%d", group, len(req.Links), len(req.KeyGrants))
	if err := s.db.audit(ctx, tx, c.user.ID, c.device.ID, c.ip, "group_commit", summary, now); err != nil {
		return 0, nil, err
	}
	return gs.Seq, users, nil
}

// linkClock refuses a link time far from the server's clock.
func linkClock(t, now time.Time) error {
	if t.After(now.Add(10*time.Minute)) || t.Before(now.Add(-24*time.Hour)) {
		return clientErr(http.StatusBadRequest, wire.ErrInvalidRequest, "link time %s is too far from the server's clock; check this machine's clock", t.Format(time.RFC3339))
	}
	return nil
}

// storeGroupLink stores a verified link, its audit entry and alert, and,
// for the first link, the group.
func (s *Server) storeGroupLink(ctx context.Context, tx *sql.Tx, before, after *team.GroupState, e *envelope.Envelope, l team.GroupLink, actor, ip string, now time.Time) error {
	raw, err := json.Marshal(e)
	if err != nil {
		return err
	}
	if l.Type == team.GroupInit {
		if _, err := tx.ExecContext(ctx, `INSERT INTO machine_groups (id, created_by, created_at) VALUES (?, ?, ?)`, after.Group, actor, now.Unix()); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO group_links (group_id, seq, hash, envelope, signer, created_at) VALUES (?, ?, ?, ?, ?, ?)`, after.Group, l.Seq, e.Hash(), raw, l.Signer, now.Unix()); err != nil {
		return err
	}
	if err := s.db.groupAudit(ctx, tx, after.Group, actor, ip, "link_"+l.Type, groupLinkSummary(before, after, l), now); err != nil {
		return err
	}
	return s.queueGroupAlert(ctx, tx, before, after, l, ip, now)
}

// checkGroupLink checks what the chain cannot: that a new admin is that
// person's account here, that a machine let in matches its join request,
// and that a project the group trusts exists with that root.
func (s *Server) checkGroupLink(ctx context.Context, tx *sql.Tx, gs *team.GroupState, l team.GroupLink, chains team.Chains, now time.Time) error {
	if err := s.checkPolicyGroupLink(ctx, tx, gs.Group, l); err != nil {
		return err
	}
	switch l.Type {
	case team.GroupInit:
		var b team.GroupInitBody
		if err := envelope.DecodeStrict(l.Body, &b); err != nil {
			return err
		}
		return s.checkPersonHere(ctx, tx, b.Creator, chains)
	case team.GroupAdminAdd:
		var b team.GroupAdminAddBody
		if err := envelope.DecodeStrict(l.Body, &b); err != nil {
			return err
		}
		return s.checkPersonHere(ctx, tx, b.Admin, chains)
	case team.GroupMemberAdd:
		var b team.GroupMemberAddBody
		if err := envelope.DecodeStrict(l.Body, &b); err != nil {
			return err
		}
		return s.checkPersonHere(ctx, tx, b.Member, chains)
	case team.GroupMachineAdd:
		var b team.GroupMachineAddBody
		if err := envelope.DecodeStrict(l.Body, &b); err != nil {
			return err
		}
		if b.Join == "" {
			return nil
		}
		return approveJoin(ctx, tx, gs.Group, b, now)
	case team.GroupAccessAdd:
		var b team.GroupAccessBody
		if err := envelope.DecodeStrict(l.Body, &b); err != nil {
			return err
		}
		var hash string
		err := tx.QueryRowContext(ctx, `SELECT hash FROM project_links WHERE project = ? AND seq = 1`, b.Project).Scan(&hash)
		if errors.Is(err, sql.ErrNoRows) || (err == nil && hash != b.Root) {
			return clientErr(http.StatusBadRequest, wire.ErrInvalidRequest, "%s is not a shared project with that root on this server", b.Project)
		}
		return err
	}
	return nil
}

// approveJoin marks the join request a machine_add answers approved, after
// checking the machine is the one that asked.
func approveJoin(ctx context.Context, tx *sql.Tx, group string, b team.GroupMachineAddBody, now time.Time) error {
	var machine, name, enc, sign, status string
	var expires int64
	err := tx.QueryRowContext(ctx, `SELECT machine_id, name, enc_pub, sign_pub, status, expires_at FROM group_joins WHERE id = ? AND group_id = ?`, b.Join, group).Scan(&machine, &name, &enc, &sign, &status, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return clientErr(http.StatusNotFound, wire.ErrNotFound, "no such join request")
	}
	if err != nil {
		return err
	}
	if status != wire.JoinPending || now.Unix() >= expires {
		return clientErr(http.StatusConflict, wire.ErrConflict, "the join request was already handled or expired; the machine asks again")
	}
	if machine != b.Machine.ID || name != b.Machine.Name || enc != b.Machine.EncPub || sign != b.Machine.SignPub {
		return clientErr(http.StatusBadRequest, wire.ErrInvalidRequest, "the machine does not match its join request")
	}
	_, err = tx.ExecContext(ctx, `UPDATE group_joins SET status = ? WHERE id = ?`, wire.JoinApproved, b.Join)
	return err
}

// checkPersonHere checks that p is that person's account on this server.
func (s *Server) checkPersonHere(ctx context.Context, tx *sql.Tx, p team.Person, chains team.Chains) error {
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

// storeKeyGrant checks a key grant against the group and stores it in
// place of the recipient's earlier grants. signer checks who made it.
func (s *Server) storeKeyGrant(ctx context.Context, tx *sql.Tx, gs *team.GroupState, e *envelope.Envelope, chains team.Chains, signer func(*team.KeyGrant) error, actor string, now time.Time) error {
	g, err := team.CheckKeyGrant(e, gs, chains)
	if err != nil {
		return clientErr(http.StatusBadRequest, wire.ErrInvalidRequest, "key grant rejected: %v", err)
	}
	if err := signer(g); err != nil {
		return err
	}
	if g.CTime.After(now.Add(10*time.Minute)) || g.CTime.Before(now.Add(-24*time.Hour)) {
		return clientErr(http.StatusBadRequest, wire.ErrInvalidRequest, "key grant time is too far from the server's clock")
	}
	if gs.HoldsKey(g.To) {
		cs, err := chains(g.To)
		if err != nil {
			return err
		}
		if g.ToKey != cs.UKeyVersion || g.ToEncPub != hex.EncodeToString(cs.EncPub[:]) {
			return clientErr(http.StatusConflict, wire.ErrConflict, "%s has a new user key; refresh and retry", g.To)
		}
	}
	raw, err := json.Marshal(e)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM group_key_grants WHERE group_id = ? AND to_id = ?`, gs.Group, g.To); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO group_key_grants (group_id, to_id, version, envelope, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
		gs.Group, g.To, g.Version, raw, actor, now.Unix())
	return err
}

// groupWake queues group events for the group's admins and members and,
// when the group's key or machines changed, for the admins of the projects
// granting it environments, whose devices seal those keys to the group's
// key.
func (s *Server) groupWake(ctx context.Context, tx *sql.Tx, before, after *team.GroupState, now time.Time) ([]string, error) {
	wake := map[string]bool{}
	for _, a := range after.Admins {
		wake[a.User] = true
	}
	for _, m := range after.Members {
		wake[m.User] = true
	}
	if before.Key != after.Key || before.Seq == 0 || !slices.Equal(before.Projects(), after.Projects()) {
		projects, err := s.db.projectsGranting(ctx, tx, after.Group)
		if err != nil {
			return nil, err
		}
		for _, p := range projects {
			admins, err := projectAdmins(ctx, tx, p)
			if err != nil {
				return nil, err
			}
			for _, u := range admins {
				wake[u] = true
			}
		}
	}
	out := make([]string, 0, len(wake))
	for u := range wake {
		if err := s.db.addEvent(ctx, tx, u, wire.EventGroup, after.Group, now); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	slices.Sort(out)
	return out, nil
}

// projectAdmins lists the admins of a project, as mirrored.
func projectAdmins(ctx context.Context, q queryer, project string) ([]string, error) {
	rows, err := q.QueryContext(ctx, `SELECT user_id FROM project_members WHERE project = ? AND active = 1 AND admin = 1`, project)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var u string
		if err := rows.Scan(&u); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// apiGroupRejectJoin turns a join request down.
func (s *Server) apiGroupRejectJoin(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	group, err := groupParam(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, wire.ErrInvalidRequest, err.Error())
		return
	}
	ctx := r.Context()
	if err := s.rejectJoin(ctx, group, r.PathValue("id"), c.user.ID, c.ip); err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, struct{}{})
}

func (s *Server) rejectJoin(ctx context.Context, group, id, user, ip string) error {
	if team.ValidJoinID(id) != nil {
		return clientErr(http.StatusBadRequest, wire.ErrInvalidRequest, "invalid join request id")
	}
	if _, err := s.adminGroup(ctx, group, user); err != nil {
		return err
	}
	now := s.now()
	return s.db.tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE group_joins SET status = ? WHERE id = ? AND group_id = ? AND status = ?`, wire.JoinRejected, id, group, wire.JoinPending)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return clientErr(http.StatusNotFound, wire.ErrNotFound, "no pending join request %s", id)
		}
		return s.db.groupAudit(ctx, tx, group, user, ip, "join_rejected", id, now)
	})
}

// ---- machines: no session, signed by the machine's own key ----

// apiFleetJoin records a machine's request to join a group. The machine
// shows words made from the group's root and its keys; an admin compares
// them and lets it in from a device.
func (s *Server) apiFleetJoin(w http.ResponseWriter, r *http.Request) {
	s.fleetJoin(w, r, "join")
}

// apiFleetJoinStatus tells a machine whether it was let in.
func (s *Server) apiFleetJoinStatus(w http.ResponseWriter, r *http.Request) {
	s.fleetJoin(w, r, "status")
}

func (s *Server) fleetJoin(w http.ResponseWriter, r *http.Request, action string) { //nolint:gocyclo // each check is a separate, ordered gate
	now := s.now()
	ip := s.clientIP(r)
	limit, net := 30, 300
	if action == "status" {
		limit, net = 1200, 6000
	}
	if !s.allowAnon("fleet-"+action, ip, limit, net, time.Hour) {
		writeErr(w, http.StatusTooManyRequests, wire.ErrRateLimited, "too many requests from this address")
		return
	}
	body, err := readBody(w, r, maxSmallBody)
	if err != nil {
		writeErr(w, http.StatusRequestEntityTooLarge, wire.ErrInvalidRequest, "request body too large")
		return
	}
	var req wire.GroupJoin
	if err := decodeStrict(body, &req); err != nil || team.ValidGroup(req.Group) != nil || !strings.HasPrefix(req.Machine, "m_") || team.ValidCredID(req.Machine) != nil || !machineNonce.MatchString(req.Nonce) {
		writeErr(w, http.StatusBadRequest, wire.ErrInvalidRequest, "invalid request")
		return
	}
	cred := team.Credential{ID: req.Machine, Name: req.Name, EncPub: req.EncPub, SignPub: req.SignPub}
	if chain.ValidDeviceName(cred.Name) != nil {
		writeErr(w, http.StatusBadRequest, wire.ErrInvalidRequest, "a machine name is 1-64 letters, digits, spaces or ._()'- characters")
		return
	}
	if _, err := chain.ParseKey32(cred.EncPub); err != nil {
		writeErr(w, http.StatusBadRequest, wire.ErrInvalidRequest, "invalid encryption key")
		return
	}
	pub, err := chain.ParseSignKey(cred.SignPub)
	if err != nil || !ed25519Verify(pub, team.JoinMessage(action, req.Group, cred, req.Timestamp, req.Nonce), req.Sig) {
		writeErr(w, http.StatusUnauthorized, wire.ErrUnauthorized, "bad signature")
		return
	}
	if err := s.proofClock(req.Timestamp); err != nil {
		s.fail(w, r, err)
		return
	}
	ctx := r.Context()
	if err := s.recordNonce(ctx, req.Machine, req.Nonce, now); err != nil {
		writeErr(w, http.StatusUnauthorized, wire.ErrUnauthorized, "request replayed")
		return
	}
	gs, _, err := s.db.groupState(ctx, s.db.sql, req.Group)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if gs == nil {
		writeErr(w, http.StatusNotFound, wire.ErrNotFound, "no machine group "+req.Group+" on this server")
		return
	}
	out := wire.GroupJoinResult{Root: gs.Root()}
	if m, ok := gs.Creds[req.Machine]; ok {
		out.Status = wire.JoinRejected
		if m.Active && m.EncPub == cred.EncPub && m.SignPub == cred.SignPub {
			out.Status = wire.JoinApproved
		}
		writeJSON(w, http.StatusOK, out)
		return
	}
	var status string
	var expires int64
	err = s.db.sql.QueryRowContext(ctx, `SELECT id, status, expires_at FROM group_joins WHERE group_id = ? AND machine_id = ? AND sign_pub = ? AND enc_pub = ? AND name = ?`,
		req.Group, req.Machine, cred.SignPub, cred.EncPub, cred.Name).Scan(&out.Join, &status, &expires)
	switch {
	case err == nil:
		out.Status = status
		if status == wire.JoinPending && now.Unix() >= expires {
			out.Status = wire.JoinRejected
		}
		writeJSON(w, http.StatusOK, out)
		return
	case !errors.Is(err, sql.ErrNoRows):
		s.internalError(w, r, err)
		return
	case action == "status":
		writeErr(w, http.StatusNotFound, wire.ErrNotFound, "no join request for this machine")
		return
	}
	out.Join, out.Status = randomID("j_"), wire.JoinPending
	var wake []string
	err = s.db.tx(ctx, func(tx *sql.Tx) error {
		var n int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM group_joins WHERE group_id = ? AND status = ? AND expires_at > ?`, req.Group, wire.JoinPending, now.Unix()).Scan(&n); err != nil {
			return err
		}
		if n >= maxPendingJoins {
			return clientErr(http.StatusTooManyRequests, wire.ErrRateLimited, "too many machines wait to join %s; an admin handles them first", req.Group)
		}
		var mine int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM group_joins WHERE group_id = ? AND status = ? AND expires_at > ? AND ip = ?`, req.Group, wire.JoinPending, now.Unix(), ip).Scan(&mine); err != nil {
			return err
		}
		if mine >= maxPendingJoinsPerIP {
			return clientErr(http.StatusTooManyRequests, wire.ErrRateLimited, "%d machines from this address already wait to join %s; an admin lets them in first", mine, req.Group)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO group_joins (id, group_id, machine_id, name, enc_pub, sign_pub, ip, status, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			out.Join, req.Group, req.Machine, cred.Name, cred.EncPub, cred.SignPub, ip, wire.JoinPending, now.Unix(), now.Add(joinLifetime).Unix()); err != nil {
			return err
		}
		if err := s.db.groupAudit(ctx, tx, req.Group, req.Machine, ip, "join_requested", cred.Name, now); err != nil {
			return err
		}
		for _, a := range gs.ActiveAdmins() {
			if err := s.db.addEvent(ctx, tx, a.User, wire.EventGroup, req.Group, now); err != nil {
				return err
			}
			wake = append(wake, a.User)
		}
		return nil
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	for _, u := range wake {
		s.notify.wake(u)
	}
	writeJSON(w, http.StatusOK, out)
}

// apiFleetEnroll adds a machine with an enrollment token: the machine_add
// link and the machine's key grant are both signed by the token.
func (s *Server) apiFleetEnroll(w http.ResponseWriter, r *http.Request) { //nolint:gocyclo // each check is a separate, ordered gate
	now := s.now()
	ip := s.clientIP(r)
	if !s.allowAnon("fleet-enroll", ip, 300, 1500, time.Hour) {
		writeErr(w, http.StatusTooManyRequests, wire.ErrRateLimited, "too many enrollments from this address")
		return
	}
	body, err := readBody(w, r, maxSmallBody)
	if err != nil {
		writeErr(w, http.StatusRequestEntityTooLarge, wire.ErrInvalidRequest, "request body too large")
		return
	}
	var req wire.GroupEnroll
	if err := decodeStrict(body, &req); err != nil || team.ValidGroup(req.Group) != nil || req.Link == nil || req.KeyGrant == nil {
		writeErr(w, http.StatusBadRequest, wire.ErrInvalidRequest, "invalid request")
		return
	}
	l, err := team.PeekGroupLink(req.Link)
	if err != nil || l.Type != team.GroupMachineAdd || !strings.HasPrefix(l.Signer, "t_") || team.ValidCredID(l.Signer) != nil {
		writeErr(w, http.StatusBadRequest, wire.ErrInvalidRequest, "an enrollment is a machine_add link signed by a token")
		return
	}
	ctx := r.Context()
	refused := func() {
		writeErr(w, http.StatusUnauthorized, wire.ErrUnauthorized, "unknown, removed, suspended or expired token, or a bad signature")
	}
	row, err := s.db.credRow(ctx, req.Group, l.Signer)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if row == nil || !row.Active || !row.Suspended.IsZero() || row.Kind != team.KindToken {
		refused()
		return
	}
	// The OIDC check fetches the issuer's keys, so it runs before the
	// transaction, against the token as the chain has it now.
	gs, _, err := s.db.groupState(ctx, s.db.sql, req.Group)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if gs == nil {
		refused()
		return
	}
	tok, ok := gs.Cred(l.Signer)
	if !ok || tok.Expired(now) {
		refused()
		return
	}
	// Only the token's holder counts against its limit: token ids are
	// shown on the group's page.
	if pub, err := chain.ParseSignKey(tok.SignPub); err != nil || req.Link.Require(team.KindGroupLink, pub) != nil {
		refused()
		return
	}
	if !s.limits.allow("enroll:"+req.Group+":"+l.Signer, maxEnrollsPerTokenHr, time.Hour, now) {
		writeErr(w, http.StatusTooManyRequests, wire.ErrRateLimited, "too many enrollments with this token; try again later")
		return
	}
	detail := tok.Name
	if tok.OIDC != nil {
		claims, ok := s.checkOIDC(w, r, req.OIDCToken, tok.OIDC, now)
		if !ok {
			_ = s.db.groupAudit(ctx, s.db.sql, req.Group, l.Signer, ip, "enroll_refused", tok.Name, now)
			return
		}
		detail += " " + claimsDetail(claims)
	}
	var wake []string
	err = s.db.tx(ctx, func(tx *sql.Tx) error {
		chains := s.db.userChains(ctx, tx)
		stored, err := s.db.groupLinks(ctx, tx, req.Group)
		if err != nil {
			return err
		}
		cur, err := team.VerifyGroup(req.Group, stored, chains)
		if err != nil {
			return err
		}
		if t, ok := cur.Cred(l.Signer); !ok || t.Expired(now) {
			return clientErr(http.StatusUnauthorized, wire.ErrUnauthorized, "the token was removed or expired")
		}
		if l.Seq != cur.Seq+1 {
			return clientErr(http.StatusConflict, wire.ErrConflict, "the group changed on the server; retry")
		}
		if err := linkClock(l.CTime, now); err != nil {
			return err
		}
		next, err := cur.Next(req.Link, chains)
		if err != nil {
			return clientErr(http.StatusBadRequest, wire.ErrInvalidRequest, "link rejected: %v", err)
		}
		var b team.GroupMachineAddBody
		if err := envelope.DecodeStrict(l.Body, &b); err != nil || b.Join != "" {
			return clientErr(http.StatusBadRequest, wire.ErrInvalidRequest, "invalid enrollment")
		}
		if err := s.storeGroupLink(ctx, tx, cur, next, req.Link, *l, l.Signer, ip, now); err != nil {
			return err
		}
		if err := s.db.mirrorGroup(ctx, tx, next, now); err != nil {
			return err
		}
		if err := s.storeKeyGrant(ctx, tx, next, req.KeyGrant, chains, func(g *team.KeyGrant) error {
			if g.From != l.Signer || g.To != b.Machine.ID {
				return clientErr(http.StatusBadRequest, wire.ErrInvalidRequest, "the key grant must be from the token to the new machine")
			}
			return nil
		}, l.Signer, now); err != nil {
			return err
		}
		if err := s.db.groupAudit(ctx, tx, req.Group, l.Signer, ip, "enrolled", b.Machine.Name+" by "+detail, now); err != nil {
			return err
		}
		for _, a := range next.ActiveAdmins() {
			if err := s.db.addEvent(ctx, tx, a.User, wire.EventGroup, req.Group, now); err != nil {
				return err
			}
			wake = append(wake, a.User)
		}
		_, err = tx.ExecContext(ctx, `UPDATE group_creds SET last_used_at = ?, last_ip = ?, uses = uses + 1 WHERE group_id = ? AND id = ?`, now.Unix(), ip, req.Group, l.Signer)
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
	writeJSON(w, http.StatusOK, wire.GroupCommitResult{Seq: l.Seq})
}

// checkOIDC verifies a workload's OIDC token against a policy and writes
// the refusal when it does not match.
func (s *Server) checkOIDC(w http.ResponseWriter, r *http.Request, token string, p *team.OIDCPolicy, now time.Time) (*team.Claims, bool) {
	if token == "" {
		writeErr(w, http.StatusForbidden, wire.ErrForbidden, "this needs an OIDC token from "+p.Describe()+oidcHint(p))
		return nil, false
	}
	claims, err := s.oidc.Verify(r.Context(), p, token, s.cfg.BaseURL, now)
	if err != nil {
		if errors.Is(err, errOIDC) {
			writeErr(w, http.StatusForbidden, wire.ErrForbidden, err.Error())
			return nil, false
		}
		s.internalError(w, r, err)
		return nil, false
	}
	if err := p.Allows(claims); err != nil {
		writeErr(w, http.StatusForbidden, wire.ErrForbidden, "the OIDC token does not match the policy: "+err.Error())
		return nil, false
	}
	return claims, true
}

func claimsDetail(c *team.Claims) string { return truncate(c.Detail(), 300) }

// oidcHint says how a workload gets the token a policy wants.
func oidcHint(p *team.OIDCPolicy) string {
	if p.Provider == team.ProviderFly {
		return " (esec-vault asks the Machine's /.fly/api for it; run it on a Fly.io Machine)"
	}
	return " (in GitHub Actions, give the job 'permissions: id-token: write')"
}

// apiFleetKeys gives a machine or token its sealed keys: the group key
// sealed to it, and each project's environment keys sealed to the group.
func (s *Server) apiFleetKeys(w http.ResponseWriter, r *http.Request) { //nolint:gocyclo // each check is a separate, ordered gate
	now := s.now()
	ip := s.clientIP(r)
	if !s.allowAnon("fleet-keys", ip, 1200, 6000, time.Hour) {
		writeErr(w, http.StatusTooManyRequests, wire.ErrRateLimited, "too many machine requests from this address")
		return
	}
	body, err := readBody(w, r, maxSmallBody)
	if err != nil {
		writeErr(w, http.StatusRequestEntityTooLarge, wire.ErrInvalidRequest, "request body too large")
		return
	}
	var req wire.GroupKeysRequest
	if err := decodeStrict(body, &req); err != nil || team.ValidGroup(req.Group) != nil || team.ValidCredID(req.ID) != nil || !machineNonce.MatchString(req.Nonce) {
		writeErr(w, http.StatusBadRequest, wire.ErrInvalidRequest, "invalid request")
		return
	}
	if err := s.proofClock(req.Timestamp); err != nil {
		s.fail(w, r, err)
		return
	}
	ctx := r.Context()
	unknown := func() {
		writeErr(w, http.StatusUnauthorized, wire.ErrUnauthorized, "unknown, removed, suspended or expired machine, or a bad signature")
	}
	row, err := s.db.credRow(ctx, req.Group, req.ID)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if row == nil || !row.Active || !row.Suspended.IsZero() {
		unknown()
		return
	}
	pub, err := chain.ParseSignKey(row.SignPub)
	if err != nil || !ed25519Verify(pub, team.GroupKeysMessage(req.Group, req.ID, req.Timestamp, req.Nonce, tokenHash(req.OIDCToken)), req.Sig) {
		unknown()
		return
	}
	// Counted once signed: machine ids are shown on the group's page.
	if !s.limits.allow("fleet:"+req.Group+":"+req.ID, 600, time.Hour, now) {
		writeErr(w, http.StatusTooManyRequests, wire.ErrRateLimited, "too many requests for this machine; try again later")
		return
	}
	if err := s.recordNonce(ctx, req.Group+":"+req.ID, req.Nonce, now); err != nil {
		writeErr(w, http.StatusUnauthorized, wire.ErrUnauthorized, "request replayed")
		return
	}
	gs, links, err := s.db.groupState(ctx, s.db.sql, req.Group)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if gs == nil {
		unknown()
		return
	}
	cred, ok := gs.Cred(req.ID)
	if !ok || cred.Expired(now) {
		unknown()
		return
	}
	detail := cred.Name
	if cred.OIDC != nil {
		claims, ok := s.checkOIDC(w, r, req.OIDCToken, cred.OIDC, now)
		if !ok {
			_ = s.db.groupAudit(ctx, s.db.sql, req.Group, req.ID, ip, "keys_refused", cred.Name, now)
			return
		}
		detail += " " + claimsDetail(claims)
	}
	out, err := s.fleetKeys(ctx, gs, links, req.ID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if _, err := s.db.sql.ExecContext(ctx, `UPDATE group_creds SET last_used_at = ?, last_ip = ?, uses = uses + 1 WHERE group_id = ? AND id = ?`, now.Unix(), ip, req.Group, req.ID); err != nil {
		s.internalError(w, r, err)
		return
	}
	projects := make([]string, 0, len(out.Projects))
	for _, p := range out.Projects {
		projects = append(projects, p.Project)
	}
	if err := s.db.groupAudit(ctx, s.db.sql, req.Group, req.ID, ip, "keys", truncate(detail+" "+strings.Join(projects, ","), 500), now); err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// fleetKeys collects a credential's group key grant and, for each project
// the group trusts that grants it environments, the project chain and its
// latest grant to the group.
func (s *Server) fleetKeys(ctx context.Context, gs *team.GroupState, links []*envelope.Envelope, id string) (*wire.GroupKeys, error) {
	grants, err := s.db.keyGrants(ctx, s.db.sql, gs.Group, id)
	if err != nil {
		return nil, err
	}
	var kg *envelope.Envelope
	for _, g := range grants {
		if g.Version == gs.Key.Version {
			kg = g.Env
		}
	}
	if kg == nil {
		return nil, clientErr(http.StatusNotFound, wire.ErrNotFound, "the group key was not sent to it yet; an admin's device sends it (esec vault group sync)")
	}
	out := &wire.GroupKeys{Links: links, Chains: map[string][]*envelope.Envelope{}, KeyGrant: kg, Projects: []wire.GroupProjectKeys{}}
	signers := groupSigners(gs)
	if g, err := team.PeekKeyGrant(kg); err == nil {
		signers = append(signers, g.From)
	}
	for _, p := range gs.Projects() {
		ps, plinks, err := s.db.projectState(ctx, s.db.sql, p)
		if err != nil {
			s.log.Warn("shared project does not verify; leaving it out of a machine's keys", "project", p, "error", err)
			continue
		}
		if ps == nil || ps.Root() != gs.Access[p] || ps.Archived {
			continue
		}
		pg, ok := ps.Group(gs.Group)
		if !ok || pg.Root != gs.Root() {
			continue
		}
		pk := wire.GroupProjectKeys{Project: p, Links: plinks}
		rows, err := s.db.grants(ctx, s.db.sql, `project = ? AND to_id = ? AND to_ukey_version = ?`, p, team.GroupHolder(gs.Group), gs.Key.Version)
		if err != nil {
			return nil, err
		}
		if len(rows) > 0 {
			pk.Grant = rows[len(rows)-1].Env
			if g, err := team.PeekGrant(pk.Grant); err == nil {
				signers = append(signers, g.From)
			}
		}
		for _, l := range ps.Links {
			signers = append(signers, l.Signer)
		}
		out.Projects = append(out.Projects, pk)
	}
	if err := s.db.addChains(ctx, s.db.sql, out.Chains, signers...); err != nil {
		return nil, err
	}
	return out, nil
}

// groupLinkSummary describes a group link for the audit log.
func groupLinkSummary(before, after *team.GroupState, l team.GroupLink) string {
	var b struct {
		Creator team.Person     `json:"creator"`
		Admin   team.Person     `json:"admin"`
		User    string          `json:"user"`
		Machine team.Credential `json:"machine"`
		Token   team.Credential `json:"token"`
		ID      string          `json:"id"`
		Key     team.GroupKey   `json:"key"`
		Project string          `json:"project"`
	}
	_ = json.Unmarshal(l.Body, &b)
	switch l.Type {
	case team.GroupInit:
		return "created by " + b.Creator.Login
	case team.GroupAdminAdd:
		return b.Admin.Login
	case team.GroupAdminRemove:
		if a := before.Admins[b.User]; a != nil {
			return a.Login
		}
		return b.User
	case team.GroupMemberAdd:
		var m team.GroupMemberAddBody
		_ = json.Unmarshal(l.Body, &m)
		return m.Member.Login
	case team.GroupMemberRemove:
		if m := before.Members[b.User]; m != nil {
			return m.Login
		}
		return b.User
	case team.GroupMachineAdd:
		return b.Machine.Name + " " + b.Machine.ID
	case team.GroupTokenAdd:
		return b.Token.Name + " " + b.Token.ID
	case team.GroupWorkloadAdd:
		var wl team.GroupWorkloadAddBody
		_ = json.Unmarshal(l.Body, &wl)
		return wl.Workload.Name + " " + wl.Workload.ID
	case team.GroupWorkloadRekey:
		var rk team.GroupWorkloadRekeyBody
		_ = json.Unmarshal(l.Body, &rk)
		return rk.ID + " " + rk.KMS.Provider + " " + rk.KMS.Name
	case team.GroupRemove:
		if c := before.Creds[b.ID]; c != nil {
			return c.Kind + " " + c.Name + " " + b.ID
		}
		return b.ID
	case team.GroupKeyRotate:
		return fmt.Sprintf("version %d", b.Key.Version)
	case team.GroupAccessAdd, team.GroupAccessRemove:
		return b.Project
	}
	return fmt.Sprint(after.Seq)
}

// memberBlocked reports whether a member is blocked on the web.
func (s *Server) memberBlocked(ctx context.Context, group, user string) (bool, error) {
	var at int64
	err := s.db.sql.QueryRowContext(ctx, `SELECT suspended_at FROM group_members WHERE group_id = ? AND user_id = ?`, group, user).Scan(&at)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return at != 0, err
}

// groupPeople queues a group event for the admins and members of a group
// that takes keys from project, whose devices then fetch the keys a project
// commit sealed to the group. It returns them.
func (s *Server) groupPeople(ctx context.Context, tx *sql.Tx, group, project string, now time.Time) ([]string, error) {
	gs, _, err := s.db.groupState(ctx, tx, group)
	if err != nil || gs == nil {
		return nil, err
	}
	if _, trusted := gs.Access[project]; !trusted {
		return nil, nil
	}
	var out []string
	for _, p := range gs.KeyHolders() {
		if err := s.db.addEvent(ctx, tx, p.User, wire.EventGroup, group, now); err != nil {
			return nil, err
		}
		out = append(out, p.User)
	}
	return out, nil
}

// readWorkloadRequest reads and checks a workload's request, writing the
// refusal.
func readWorkloadRequest(w http.ResponseWriter, r *http.Request) (*wire.WorkloadKeysRequest, bool) {
	body, err := readBody(w, r, maxSmallBody)
	if err != nil {
		writeErr(w, http.StatusRequestEntityTooLarge, wire.ErrInvalidRequest, "request body too large")
		return nil, false
	}
	var req wire.WorkloadKeysRequest
	if err := decodeStrict(body, &req); err != nil || team.ValidGroup(req.Group) != nil || !strings.HasPrefix(req.ID, "w_") || team.ValidCredID(req.ID) != nil {
		writeErr(w, http.StatusBadRequest, wire.ErrInvalidRequest, "invalid request")
		return nil, false
	}
	return &req, true
}

// apiWorkloadKeys gives a workload its sealed keys, like apiFleetKeys gives
// a machine its: the group chain, its group key grant (wrapped with its
// KMS key) and each project's grant to the group. A workload has no key to
// sign with; its OIDC token, checked against the policy the chain names,
// is what lets it ask, and nothing it gets opens without the KMS.
func (s *Server) apiWorkloadKeys(w http.ResponseWriter, r *http.Request) {
	now := s.now()
	ip := s.clientIP(r)
	if !s.allowAnon("workload-keys", ip, 600, 3000, time.Hour) {
		writeErr(w, http.StatusTooManyRequests, wire.ErrRateLimited, "too many workload requests from this address")
		return
	}
	req, ok := readWorkloadRequest(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	unknown := func() {
		writeErr(w, http.StatusUnauthorized, wire.ErrUnauthorized, "unknown, removed or suspended workload")
	}
	row, err := s.db.credRow(ctx, req.Group, req.ID)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if row == nil || !row.Active || !row.Suspended.IsZero() {
		unknown()
		return
	}
	if !s.limits.allow("workload:"+req.Group+":"+req.ID, 600, time.Hour, now) {
		writeErr(w, http.StatusTooManyRequests, wire.ErrRateLimited, "too many requests for this workload; try again later")
		return
	}
	gs, links, err := s.db.groupState(ctx, s.db.sql, req.Group)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if gs == nil {
		unknown()
		return
	}
	cred, ok := gs.Cred(req.ID)
	if !ok || cred.Kind != team.KindWorkload || cred.OIDC == nil {
		unknown()
		return
	}
	claims, ok := s.checkOIDC(w, r, req.OIDCToken, cred.OIDC, now)
	if !ok {
		_ = s.db.groupAudit(ctx, s.db.sql, req.Group, req.ID, ip, "keys_refused", cred.Name, now)
		return
	}
	out, err := s.fleetKeys(ctx, gs, links, req.ID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if _, err := s.db.sql.ExecContext(ctx, `UPDATE group_creds SET last_used_at = ?, last_ip = ?, uses = uses + 1 WHERE group_id = ? AND id = ?`, now.Unix(), ip, req.Group, req.ID); err != nil {
		s.internalError(w, r, err)
		return
	}
	if err := s.db.groupAudit(ctx, s.db.sql, req.Group, req.ID, ip, "keys", truncate(cred.Name+" "+claimsDetail(claims), 500), now); err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}
