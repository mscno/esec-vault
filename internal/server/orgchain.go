package server

// Organisation chains (team.OrgState): who belongs to an organisation, the
// KMS keys its admins approved, and its signed settings. The server stores
// and checks them like group chains. Once an organisation has a chain, only
// its people may create projects and groups named after it, and its
// settings join the server admins' policy (the stricter of both applies).

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/mscno/esec-vault/internal/envelope"
	"github.com/mscno/esec-vault/internal/team"
	"github.com/mscno/esec-vault/internal/wire"
)

// maxOrgLinksPer bounds the links of one commit.
const maxOrgLinksPer = 50

// orgCache holds verified organisation chains by their head. Callers must
// not change what it returns.
type orgCache struct {
	mu sync.Mutex
	m  map[string]cachedOrg
}

type cachedOrg struct {
	head  string
	os    *team.OrgState
	links []*envelope.Envelope
}

func (d *DB) orgLinks(ctx context.Context, q queryer, org string) ([]*envelope.Envelope, error) {
	out := []*envelope.Envelope{}
	err := scanAll(ctx, q, `SELECT envelope FROM org_links WHERE org = ? ORDER BY seq`, []any{org}, func(r *sql.Rows) error {
		var raw []byte
		if err := r.Scan(&raw); err != nil {
			return err
		}
		var e envelope.Envelope
		if err := json.Unmarshal(raw, &e); err != nil {
			return err
		}
		out = append(out, &e)
		return nil
	})
	return out, err
}

// orgState verifies a stored organisation chain, or returns the one
// verified at the same head before. It returns nil, nil for an organisation
// with no chain. The state is shared: callers must not change it.
func (d *DB) orgState(ctx context.Context, q queryer, org string) (*team.OrgState, []*envelope.Envelope, error) {
	org = strings.ToLower(org)
	var head string
	err := q.QueryRowContext(ctx, `SELECT hash FROM org_links WHERE org = ? ORDER BY seq DESC LIMIT 1`, org).Scan(&head)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	d.orgs.mu.Lock()
	c, ok := d.orgs.m[org]
	d.orgs.mu.Unlock()
	if ok && c.head == head {
		return c.os, c.links, nil
	}
	links, err := d.orgLinks(ctx, q, org)
	if err != nil {
		return nil, nil, err
	}
	os, err := team.VerifyOrg(org, links, d.userChains(ctx, q))
	if err != nil {
		return nil, nil, fmt.Errorf("stored chain of the organisation %s does not verify: %w", org, err)
	}
	d.orgs.mu.Lock()
	if d.orgs.m == nil {
		d.orgs.m = map[string]cachedOrg{}
	}
	d.orgs.m[org] = cachedOrg{head: os.Head(), os: os, links: links}
	d.orgs.mu.Unlock()
	return os, links, nil
}

// mirrorOrg rewrites org_people from the verified state.
func (d *DB) mirrorOrg(ctx context.Context, tx *sql.Tx, os *team.OrgState, now time.Time) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM org_people WHERE org = ?`, os.Org); err != nil {
		return err
	}
	for _, m := range []map[string]*team.GroupAdminState{os.Members, os.Admins} {
		for _, p := range m {
			if _, err := tx.ExecContext(ctx, `INSERT INTO org_people (org, user_id, login, admin, active) VALUES (?, ?, ?, ?, ?)
				ON CONFLICT(org, user_id) DO UPDATE SET login = excluded.login, admin = excluded.admin, active = excluded.active WHERE excluded.active = 1 OR org_people.active = 0`,
				os.Org, p.User, p.Login, os.Admin(p.User), p.Active); err != nil {
				return err
			}
		}
	}
	_, err := tx.ExecContext(ctx, `UPDATE orgs SET seq = ?, updated_at = ? WHERE id = ?`, os.Seq, now.Unix(), os.Org)
	return err
}

// orgsOf lists the organisations user belongs to.
func (d *DB) orgsOf(ctx context.Context, user string) ([]string, error) {
	var out []string
	err := scanAll(ctx, d.sql, `SELECT org FROM org_people WHERE user_id = ? AND active = 1 ORDER BY org`, []any{user}, func(r *sql.Rows) error {
		var o string
		if err := r.Scan(&o); err != nil {
			return err
		}
		out = append(out, o)
		return nil
	})
	return out, err
}

// orgIDs lists the projects and groups named after org.
func (d *DB) orgIDs(ctx context.Context, q queryer, org string) (projects, groups []string, err error) {
	collect := func(query string, out *[]string) error {
		return scanAll(ctx, q, query, nil, func(r *sql.Rows) error {
			var id string
			if err := r.Scan(&id); err != nil {
				return err
			}
			if team.OrgOf(id) == org {
				*out = append(*out, id)
			}
			return nil
		})
	}
	if err := collect(`SELECT id FROM projects ORDER BY id`, &projects); err != nil {
		return nil, nil, err
	}
	err = collect(`SELECT id FROM machine_groups ORDER BY id`, &groups)
	return projects, groups, err
}

// canReadOrg reports whether user may read an organisation's chain: its
// people, the members of its projects and groups (whose devices check the
// chain), and the server's admins.
func (s *Server) canReadOrg(ctx context.Context, user string, githubID int64, org string) (bool, error) {
	if s.cfg.Admin(githubID) {
		return true, nil
	}
	orgs, err := s.db.orgsOf(ctx, user)
	if err != nil || slices.Contains(orgs, org) {
		return err == nil, err
	}
	projects, err := s.db.memberProjects(ctx, user)
	if err != nil {
		return false, err
	}
	for _, p := range projects {
		if team.OrgOf(p) == org {
			return true, nil
		}
	}
	groups, err := s.db.visibleGroups(ctx, user)
	if err != nil {
		return false, err
	}
	for _, g := range groups {
		if team.OrgOf(g) == org {
			return true, nil
		}
	}
	return false, nil
}

func orgParam(r *http.Request) (string, error) {
	org := r.PathValue("org")
	if err := team.ValidOrg(org); err != nil {
		return "", err
	}
	return org, nil
}

// orgSigners lists everyone who signed a link of os.
func orgSigners(os *team.OrgState) []string {
	out := make([]string, 0, len(os.Links))
	for _, l := range os.Links {
		out = append(out, l.Signer)
	}
	return out
}

func (s *Server) apiOrgChain(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	org, err := orgParam(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, wire.ErrInvalidRequest, err.Error())
		return
	}
	ctx := r.Context()
	os, links, err := s.db.orgState(ctx, s.db.sql, org)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if os == nil {
		writeErr(w, http.StatusNotFound, wire.ErrNotFound, "the organisation "+org+" has no chain")
		return
	}
	ok, err := s.canReadOrg(ctx, c.user.ID, c.user.GitHubID, org)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if !ok {
		writeErr(w, http.StatusForbidden, wire.ErrForbidden, "you are not in "+org+", nor in any of its projects or groups")
		return
	}
	chains := map[string][]*envelope.Envelope{}
	if err := s.db.addChains(ctx, s.db.sql, chains, orgSigners(os)...); err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, wire.OrgChain{Links: links, Chains: chains})
}

// apiOrgs lists the organisations the caller belongs to.
func (s *Server) apiOrgs(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	ctx := r.Context()
	out, err := s.orgSummaries(ctx, c.user.ID)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) orgSummaries(ctx context.Context, user string) ([]wire.OrgSummary, error) {
	orgs, err := s.db.orgsOf(ctx, user)
	if err != nil {
		return nil, err
	}
	out := []wire.OrgSummary{}
	for _, o := range orgs {
		os, _, err := s.db.orgState(ctx, s.db.sql, o)
		if err != nil || os == nil {
			continue
		}
		changes, err := s.db.openChanges(ctx, wire.ScopeOrg, o)
		if err != nil {
			return nil, err
		}
		out = append(out, wire.OrgSummary{Org: o, Admin: os.Admin(user), People: len(os.People()), Keys: len(os.ActiveKMS()), Changes: len(changes)})
	}
	return out, nil
}

func (s *Server) apiOrgCommit(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	org, err := orgParam(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, wire.ErrInvalidRequest, err.Error())
		return
	}
	var req wire.OrgCommit
	if err := decodeStrict(c.body, &req); err != nil {
		writeErr(w, http.StatusBadRequest, wire.ErrInvalidRequest, "invalid request")
		return
	}
	if len(req.Links) == 0 || len(req.Links) > maxOrgLinksPer || slices.Contains(req.Links, nil) {
		writeErr(w, http.StatusBadRequest, wire.ErrInvalidRequest, "empty, too large or invalid commit")
		return
	}
	ctx := r.Context()
	var out wire.OrgCommitResult
	var wake []string
	err = s.db.tx(ctx, func(tx *sql.Tx) error {
		chains := s.db.userChains(ctx, tx)
		caller, err := chains(c.user.ID)
		if err != nil {
			return clientErr(http.StatusBadRequest, wire.ErrInvalidRequest, "create your vault account first")
		}
		for _, e := range req.Links {
			l, err := team.PeekOrgLink(e)
			if err != nil {
				return clientErr(http.StatusBadRequest, wire.ErrInvalidRequest, "invalid link: %v", err)
			}
			if l.Signer != c.user.ID || l.SignerKey != caller.UKeyVersion || l.SignerSeq > caller.Seq || l.SignerDelegate != "" {
				return clientErr(http.StatusBadRequest, wire.ErrInvalidRequest, "links must be signed with your current user key")
			}
		}
		out.Seq, wake, err = s.orgCommit(ctx, tx, org, c.user.ID, s.cfg.Admin(c.user.GitHubID), c.ip, req.Links)
		if err != nil {
			return err
		}
		return s.db.audit(ctx, tx, c.user.ID, c.device.ID, c.ip, "org_commit", fmt.Sprintf("%s links=%d", org, len(req.Links)), s.now())
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

// orgCommit verifies and stores links of an organisation chain inside tx,
// signed by actor (or their delegates), and returns the new length and the
// accounts to wake.
func (s *Server) orgCommit(ctx context.Context, tx *sql.Tx, org, actor string, serverAdmin bool, ip string, links []*envelope.Envelope) (uint64, []string, error) {
	now := s.now()
	chains := s.db.userChains(ctx, tx)
	stored, err := s.db.orgLinks(ctx, tx, org)
	if err != nil {
		return 0, nil, err
	}
	os, err := team.VerifyOrg(org, stored, chains)
	if err != nil {
		return 0, nil, fmt.Errorf("stored chain of the organisation %s does not verify: %w", org, err)
	}
	if os.Seq+uint64(len(links)) > team.MaxLinks {
		return 0, nil, clientErr(http.StatusBadRequest, wire.ErrInvalidRequest, "the organisation chain is full")
	}
	before := os
	for _, e := range links {
		l, err := team.PeekOrgLink(e)
		if err != nil {
			return 0, nil, clientErr(http.StatusBadRequest, wire.ErrInvalidRequest, "invalid link: %v", err)
		}
		if l.Signer != actor {
			return 0, nil, clientErr(http.StatusBadRequest, wire.ErrInvalidRequest, "links must be signed by you")
		}
		if l.Seq != os.Seq+1 {
			return 0, nil, clientErr(http.StatusConflict, wire.ErrConflict, "the organisation changed on the server; refresh and retry")
		}
		if err := linkClock(l.CTime, now); err != nil {
			return 0, nil, err
		}
		if l.Type == team.OrgInit {
			if err := s.checkClaim(ctx, tx, org, actor, serverAdmin); err != nil {
				return 0, nil, err
			}
		}
		next, err := os.Next(e, chains)
		if err != nil {
			return 0, nil, clientErr(http.StatusBadRequest, wire.ErrInvalidRequest, "link rejected: %v", err)
		}
		if err := s.checkOrgLink(ctx, tx, *l, chains); err != nil {
			return 0, nil, err
		}
		raw, err := json.Marshal(e)
		if err != nil {
			return 0, nil, err
		}
		if l.Type == team.OrgInit {
			if _, err := tx.ExecContext(ctx, `INSERT INTO orgs (id, created_by, created_at) VALUES (?, ?, ?)`, org, actor, now.Unix()); err != nil {
				return 0, nil, err
			}
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO org_links (org, seq, hash, envelope, signer, created_at) VALUES (?, ?, ?, ?, ?, ?)`, org, l.Seq, e.Hash(), raw, l.Signer, now.Unix()); err != nil {
			return 0, nil, err
		}
		if err := s.db.audit(ctx, tx, actor, "", ip, "org_link_"+l.Type, org+": "+team.DescribeOrgLink(next, *l), now); err != nil {
			return 0, nil, err
		}
		os = next
	}
	if err := s.db.mirrorOrg(ctx, tx, os, now); err != nil {
		return 0, nil, err
	}
	wake, err := s.orgWake(ctx, tx, before, os, now)
	return os.Seq, wake, err
}

// checkClaim lets someone start an organisation's chain: anyone while
// nothing is named after it yet; once projects or groups are, an admin of
// the first of them (whoever came first is most likely its owner; a
// project made just to claim the name comes later), or a server admin.
func (s *Server) checkClaim(ctx context.Context, tx *sql.Tx, org, user string, serverAdmin bool) error {
	var n int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM orgs WHERE id = ?`, org).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return clientErr(http.StatusConflict, wire.ErrConflict, "the organisation %s exists already; ask one of its admins to add you", org)
	}
	if serverAdmin {
		return nil
	}
	type named struct {
		id    string
		group bool
		at    int64
	}
	var first *named
	collect := func(query string, group bool) error {
		return scanAll(ctx, tx, query, nil, func(r *sql.Rows) error {
			var v named
			if err := r.Scan(&v.id, &v.at); err != nil {
				return err
			}
			v.group = group
			if team.OrgOf(v.id) == org && (first == nil || v.at < first.at) {
				first = &v
			}
			return nil
		})
	}
	if err := collect(`SELECT id, created_at FROM projects`, false); err != nil {
		return err
	}
	if err := collect(`SELECT id, created_at FROM machine_groups`, true); err != nil {
		return err
	}
	if first == nil {
		return nil
	}
	var active int
	query := `SELECT active FROM project_members WHERE project = ? AND user_id = ? AND admin = 1`
	if first.group {
		query = `SELECT active FROM group_admins WHERE group_id = ? AND user_id = ?`
	}
	err := tx.QueryRowContext(ctx, query, first.id, user).Scan(&active)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if active == 1 {
		return nil
	}
	return clientErr(http.StatusForbidden, wire.ErrForbidden, "%s/... is in use on this server: only an admin of %s, the first of it, or a server admin, can set up %s", org, first.id, org)
}

// checkOrgLink checks what the chain cannot: that people added are those
// accounts here, under the server admins' policy.
func (s *Server) checkOrgLink(ctx context.Context, tx *sql.Tx, l team.OrgLink, chains team.Chains) error {
	var p team.Person
	var verified string
	switch l.Type {
	case team.OrgInit:
		var b team.OrgInitBody
		if err := envelope.DecodeStrict(l.Body, &b); err != nil {
			return err
		}
		p = b.Creator
	case team.OrgAdminAdd:
		var b team.OrgAdminAddBody
		if err := envelope.DecodeStrict(l.Body, &b); err != nil {
			return err
		}
		p, verified = b.Admin, b.Verified
	case team.OrgMemberAdd:
		var b team.OrgMemberAddBody
		if err := envelope.DecodeStrict(l.Body, &b); err != nil {
			return err
		}
		p, verified = b.Member, b.Verified
	default:
		return nil
	}
	if err := s.checkPersonHere(ctx, tx, p, chains); err != nil {
		return err
	}
	sp, err := s.serverPolicy(ctx, tx, l.Org)
	if err != nil {
		return err
	}
	if sp.RequireGitHubProof && verified == team.VerifiedAccountKey {
		return clientErr(http.StatusForbidden, wire.ErrForbidden, "%s requires a GitHub SSH proof: %s publishes one with 'esec vault access prove', then add them without --account-key", l.Org, p.Login)
	}
	return nil
}

// orgWake records an event for everyone in the organisation, and, when
// someone left it, for the admins of its projects and groups: their
// devices take that person out of what they administer.
func (s *Server) orgWake(ctx context.Context, tx *sql.Tx, before, after *team.OrgState, now time.Time) ([]string, error) {
	users := map[string]bool{}
	for _, p := range after.People() {
		users[p.User] = true
	}
	left := false
	for _, p := range after.Former() {
		if _, was := before.Person(p.User); was {
			left = true
		}
	}
	if left {
		projects, groups, err := s.db.orgIDs(ctx, tx, after.Org)
		if err != nil {
			return nil, err
		}
		for _, p := range projects {
			ids, err := projectAdmins(ctx, tx, p)
			if err != nil {
				return nil, err
			}
			for _, u := range ids {
				users[u] = true
			}
		}
		for _, g := range groups {
			err := scanAll(ctx, tx, `SELECT user_id FROM group_admins WHERE group_id = ? AND active = 1`, []any{g}, func(r *sql.Rows) error {
				var u string
				if err := r.Scan(&u); err != nil {
					return err
				}
				users[u] = true
				return nil
			})
			if err != nil {
				return nil, err
			}
		}
	}
	out := make([]string, 0, len(users))
	for u := range users {
		if err := s.db.addEvent(ctx, tx, u, wire.EventOrg, after.Org, now); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	sort.Strings(out)
	return out, nil
}

// checkNamespace refuses a new project or group named after an
// organisation whose chain does not list its creator.
func (s *Server) checkNamespace(ctx context.Context, q queryer, id, user, login string) error {
	org := team.OrgOf(id)
	os, _, err := s.db.orgState(ctx, q, org)
	if err != nil || os == nil {
		return err
	}
	if !os.In(user) {
		return clientErr(http.StatusForbidden, wire.ErrForbidden, "%s is an organisation on this server, and you are not in it: an admin of %s adds you first (esec vault org add %s %s)", org, org, org, login)
	}
	return nil
}

// checkOrgPerson refuses someone the organisation's signed settings keep
// out of its projects and groups.
func (s *Server) checkOrgPerson(ctx context.Context, q queryer, id string, p team.Person, verified string) error {
	os, _, err := s.db.orgState(ctx, q, team.OrgOf(id))
	if err != nil || os == nil {
		return err
	}
	if err := os.CheckPerson(p.User, p.Login, verified); err != nil {
		return clientErr(http.StatusForbidden, wire.ErrForbidden, "%v", err)
	}
	return nil
}

// orgPolicy returns what the server enforces for an organisation: the
// server admins' policy, made stricter by the organisation's signed
// settings.
func (s *Server) orgPolicy(ctx context.Context, q queryer, org string) (wire.OrgPolicy, error) {
	p, err := s.serverPolicy(ctx, q, org)
	if err != nil {
		return p, err
	}
	os, _, err := s.db.orgState(ctx, q, strings.ToLower(org))
	if err != nil || os == nil {
		return p, err
	}
	st := os.Settings
	p.Signed = true
	p.RequireGitHubProof = p.RequireGitHubProof || st.RequireGitHubProof
	p.NoServerSigning = p.NoServerSigning || st.NoServerSigning
	p.MembersOnly = st.MembersOnly
	p.MaxTokenDays = stricterDays(p.MaxTokenDays, st.MaxTokenDays)
	p.ReviewDays = stricterDays(p.ReviewDays, st.ReviewDays)
	return p, nil
}

// stricterDays returns the smaller of two day limits, where 0 is none.
func stricterDays(a, b int) int {
	switch {
	case a == 0:
		return b
	case b == 0:
		return a
	}
	return min(a, b)
}
