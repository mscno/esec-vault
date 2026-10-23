package server

// Organisations: the "acme" of acme/store and acme/production. An
// organisation page gathers what the viewer can see of its projects, groups
// and people. Its policy, set by the server's admins, is enforced by the
// server on top of the signed chains: it can only refuse links, or keep the
// server from signing removals, never grant anything.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/mscno/esec/pkg/projectfile"

	"github.com/mscno/esec-vault/internal/envelope"
	"github.com/mscno/esec-vault/internal/team"
	"github.com/mscno/esec-vault/internal/wire"
)

// orgOf returns the organisation of a project or group id.
func orgOf(id string) string {
	org, _, _ := strings.Cut(id, "/")
	return org
}

// validOrg checks an organisation name, as the first part of a project id.
func validOrg(org string) bool {
	return org != "" && projectfile.ValidateOrgRepo(org+"/x") == nil
}

// serverPolicy returns the policy the server's admins set for an
// organisation (the zero policy when none is set).
func (s *Server) serverPolicy(ctx context.Context, q queryer, org string) (wire.OrgPolicy, error) {
	var p wire.OrgPolicy
	var raw, by string
	var at int64
	err := q.QueryRowContext(ctx, `SELECT policy, updated_by, updated_at FROM org_policies WHERE org = ?`, strings.ToLower(org)).Scan(&raw, &by, &at)
	if errors.Is(err, sql.ErrNoRows) {
		return p, nil
	}
	if err != nil {
		return p, err
	}
	if err := json.Unmarshal([]byte(raw), &p); err != nil {
		return p, err
	}
	p.Updated, p.UpdatedBy = fromUnix(at), by
	return p, nil
}

// checkPolicyPerson refuses a person added with account key words where the
// organisation wants GitHub proofs, and one its signed settings keep out.
func (s *Server) checkPolicyPerson(ctx context.Context, q queryer, id string, person team.Person, verified string) error {
	if err := s.checkOrgPerson(ctx, q, id, person, verified); err != nil {
		return err
	}
	if verified != team.VerifiedAccountKey {
		return nil
	}
	p, err := s.orgPolicy(ctx, q, orgOf(id))
	if err != nil {
		return err
	}
	if p.RequireGitHubProof {
		return clientErr(http.StatusForbidden, wire.ErrForbidden, "%s requires a GitHub SSH proof: %s publishes one with 'esec vault access prove', then add them without --account-key", orgOf(id), person.Login)
	}
	return nil
}

// checkPolicyLink applies an organisation's policy to a project or group
// link about to be stored.
func (s *Server) checkPolicyProjectLink(ctx context.Context, q queryer, project string, l team.Link) error {
	switch l.Type {
	case team.TypeInit:
		var b team.InitBody
		if err := envelope.DecodeStrict(l.Body, &b); err != nil {
			return err
		}
		return s.checkNamespace(ctx, q, project, b.Creator.User, b.Creator.Login)
	case team.TypeMemberAdd:
		var b team.MemberAddBody
		if err := envelope.DecodeStrict(l.Body, &b); err != nil {
			return err
		}
		return s.checkPolicyPerson(ctx, q, project, b.Member, b.Verified)
	}
	return nil
}

// checkPolicyGroupLink applies an organisation's policy to a group link:
// how people are checked, and how long tokens live.
func (s *Server) checkPolicyGroupLink(ctx context.Context, q queryer, group string, l team.GroupLink) error {
	switch l.Type {
	case team.GroupInit:
		var b team.GroupInitBody
		if err := envelope.DecodeStrict(l.Body, &b); err != nil {
			return err
		}
		return s.checkNamespace(ctx, q, group, b.Creator.User, b.Creator.Login)
	case team.GroupMemberAdd:
		var b team.GroupMemberAddBody
		if err := envelope.DecodeStrict(l.Body, &b); err != nil {
			return err
		}
		return s.checkPolicyPerson(ctx, q, group, b.Member, b.Verified)
	case team.GroupAdminAdd:
		var b team.GroupAdminAddBody
		if err := envelope.DecodeStrict(l.Body, &b); err != nil {
			return err
		}
		return s.checkPolicyPerson(ctx, q, group, b.Admin, b.Verified)
	case team.GroupTokenAdd:
		var b team.GroupTokenAddBody
		if err := envelope.DecodeStrict(l.Body, &b); err != nil {
			return err
		}
		p, err := s.orgPolicy(ctx, q, orgOf(group))
		if err != nil || p.MaxTokenDays == 0 {
			return err
		}
		limit := l.CTime.Add(time.Duration(p.MaxTokenDays) * 24 * time.Hour)
		if b.Token.Expires.IsZero() || b.Token.Expires.After(limit.Add(time.Hour)) {
			return clientErr(http.StatusForbidden, wire.ErrForbidden, "%s allows enrollment tokens of at most %d days: use --expires %dd or less", orgOf(group), p.MaxTokenDays, p.MaxTokenDays)
		}
	}
	return nil
}

// serverMaySign reports whether an organisation's policy lets the server
// sign a change for people who let it.
func (s *Server) serverMaySign(ctx context.Context, c wire.Change) (bool, error) {
	for _, id := range []string{c.Target, c.Project} {
		if id == "" {
			continue
		}
		p, err := s.orgPolicy(ctx, s.db.sql, orgOf(id))
		if err != nil {
			return false, err
		}
		if p.NoServerSigning {
			return false, nil
		}
	}
	return true, nil
}

func (s *Server) apiOrgPolicy(w http.ResponseWriter, r *http.Request, _ *reqCtx) {
	org := r.PathValue("org")
	if !validOrg(org) {
		writeErr(w, http.StatusBadRequest, wire.ErrInvalidRequest, "invalid organisation")
		return
	}
	p, err := s.orgPolicy(r.Context(), s.db.sql, org)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, p)
}

// webOrgPolicy sets an organisation's policy, for the server's admins.
func (s *Server) webOrgPolicy(w http.ResponseWriter, r *http.Request) {
	org := r.PathValue("org")
	s.pageForm(w, r, "/orgs/"+org+"/settings", func(ctx context.Context, ws *webSession) (string, error) {
		if !s.cfg.Admin(ws.user.GitHubID) {
			return "", clientErr(http.StatusForbidden, wire.ErrForbidden, "Only the server's admins set an organisation's policy.")
		}
		if !validOrg(org) {
			return "", clientErr(http.StatusBadRequest, wire.ErrInvalidRequest, "invalid organisation")
		}
		num := func(name string, limit int) (int, error) {
			v := strings.TrimSpace(r.PostForm.Get(name))
			if v == "" {
				return 0, nil
			}
			n, err := strconv.Atoi(v)
			if err != nil || n < 0 || n > limit {
				return 0, clientErr(http.StatusBadRequest, wire.ErrInvalidRequest, "%s is a number from 0 to %d", name, limit)
			}
			return n, nil
		}
		var p wire.OrgPolicy
		var err error
		if p.MaxTokenDays, err = num("max_token_days", 3660); err != nil {
			return "", err
		}
		if p.ReviewDays, err = num("review_days", 3660); err != nil {
			return "", err
		}
		p.RequireGitHubProof = r.PostForm.Get("require_github_proof") == "on"
		p.NoServerSigning = r.PostForm.Get("no_server_signing") == "on"
		raw, err := json.Marshal(p)
		if err != nil {
			return "", err
		}
		now := s.now()
		err = s.db.tx(ctx, func(tx *sql.Tx) error {
			if _, err := tx.ExecContext(ctx, `INSERT INTO org_policies (org, policy, updated_by, updated_at) VALUES (?, ?, ?, ?)
				ON CONFLICT(org) DO UPDATE SET policy = excluded.policy, updated_by = excluded.updated_by, updated_at = excluded.updated_at`, strings.ToLower(org), string(raw), ws.user.ID, now.Unix()); err != nil {
				return err
			}
			return s.db.audit(ctx, tx, ws.user.ID, "", s.clientIP(r), "org_policy", org+" "+string(raw), now)
		})
		return "Saved the policy of " + org + ". It applies to new changes from now on.", err
	}, func(ctx context.Context, ws *webSession) (map[string]any, []string, error) {
		data, err := s.orgPageData(ctx, ws, org, orgTabSettings)
		return data, []string{"org-policy"}, err
	})
}

// ---- access reviews ----

// lastReview returns a project's latest access review, or nil.
func (s *Server) lastReview(ctx context.Context, project string) (*wire.AccessReview, error) {
	var kept, removed, by string
	var at int64
	err := s.db.sql.QueryRowContext(ctx, `SELECT kept, removed, reviewed_by, reviewed_at FROM access_reviews WHERE project = ? ORDER BY id DESC LIMIT 1`, project).Scan(&kept, &removed, &by, &at)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	rv := &wire.AccessReview{Project: project, Reviewed: fromUnix(at)}
	if err := json.Unmarshal([]byte(kept), &rv.Kept); err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(removed), &rv.Removed); err != nil {
		return nil, err
	}
	logins, err := s.db.logins(ctx)
	if err != nil {
		return nil, err
	}
	rv.By = logins[by]
	return rv, nil
}

// reviewStatus says whether st's access review is due under its
// organisation's policy.
func (s *Server) reviewStatus(ctx context.Context, st *team.State) (*wire.ReviewStatus, error) {
	p, err := s.orgPolicy(ctx, s.db.sql, orgOf(st.Project))
	if err != nil {
		return nil, err
	}
	out := &wire.ReviewStatus{Project: st.Project, Days: p.ReviewDays}
	if out.Last, err = s.lastReview(ctx, st.Project); err != nil {
		return nil, err
	}
	if p.ReviewDays == 0 {
		return out, nil
	}
	since := st.Links[0].CTime
	if out.Last != nil {
		since = out.Last.Reviewed
	}
	out.Due = s.now().Sub(since) > time.Duration(p.ReviewDays)*24*time.Hour
	return out, nil
}

var reviewName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/: ()'-]{0,99}$`)

// checkReviewNames checks the names of a review before anything is done.
func checkReviewNames(rv wire.AccessReview) error {
	if len(rv.Kept)+len(rv.Removed) > team.MaxMembers+team.MaxProjectGroups+team.MaxMachines {
		return clientErr(http.StatusBadRequest, wire.ErrInvalidRequest, "review too large")
	}
	for _, n := range append(slices.Clone(rv.Kept), rv.Removed...) {
		if !reviewName.MatchString(n) {
			return clientErr(http.StatusBadRequest, wire.ErrInvalidRequest, "invalid name in the review")
		}
	}
	return nil
}

// recordReview stores an access review of a project by user.
func (s *Server) recordReview(ctx context.Context, project, user, ip string, rv wire.AccessReview) error {
	if err := checkReviewNames(rv); err != nil {
		return err
	}
	kept, err := json.Marshal(nonNilStrings(rv.Kept))
	if err != nil {
		return err
	}
	removed, err := json.Marshal(nonNilStrings(rv.Removed))
	if err != nil {
		return err
	}
	now := s.now()
	return s.db.tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO access_reviews (project, kept, removed, reviewed_by, reviewed_at) VALUES (?, ?, ?, ?, ?)`, project, string(kept), string(removed), user, now.Unix()); err != nil {
			return err
		}
		return s.db.projectAudit(ctx, tx, project, user, ip, "access_reviewed", strconv.Itoa(len(rv.Kept))+" kept, "+strconv.Itoa(len(rv.Removed))+" removed", now)
	})
}

// readersOf names everyone who reads st, as a review records them.
func readersOf(st *team.State) wire.AccessReview {
	var out wire.AccessReview
	for _, m := range st.ActiveMembers() {
		out.Kept = append(out.Kept, m.Login)
	}
	for _, g := range st.ActiveGroups() {
		out.Kept = append(out.Kept, g.Group)
	}
	for _, m := range st.ActiveMachines() {
		out.Kept = append(out.Kept, "machine:"+m.Name)
	}
	return out
}

func nonNilStrings(v []string) []string {
	if v == nil {
		return []string{}
	}
	return v
}

func (s *Server) apiReview(w http.ResponseWriter, r *http.Request, c *reqCtx) {
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
	out, err := s.reviewStatus(ctx, st)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) apiRecordReview(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	project, err := projectParam(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, wire.ErrInvalidRequest, err.Error())
		return
	}
	var req wire.AccessReview
	if err := decodeStrict(c.body, &req); err != nil {
		writeErr(w, http.StatusBadRequest, wire.ErrInvalidRequest, "invalid request")
		return
	}
	ctx := r.Context()
	st, _, err := s.memberState(ctx, project, c.user.ID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if !st.Admin(c.user.ID) {
		writeErr(w, http.StatusForbidden, wire.ErrForbidden, "only an admin of "+project+" reviews its access")
		return
	}
	if err := s.recordReview(ctx, project, c.user.ID, c.ip, req); err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, struct{}{})
}

// reviewNotices asks admins to review the projects whose review is due.
func (s *Server) reviewNotices(ctx context.Context, user string) ([]notice, error) {
	ids, err := s.db.memberProjects(ctx, user)
	if err != nil {
		return nil, err
	}
	var out []notice
	for _, id := range ids {
		st, err := s.listedProject(ctx, id)
		if err != nil {
			return nil, err
		}
		if st == nil || !st.Admin(user) {
			continue
		}
		rs, err := s.reviewStatus(ctx, st)
		if err != nil {
			return nil, err
		}
		if rs.Due {
			out = append(out, notice{Level: "info", Text: id + ": time to review who reads it (every " + plural(rs.Days, "day") + "). Keep those who still need it; remove the others.", Command: "esec vault access review --project " + id, Link: "/teams/" + id + "/review", LinkTo: "Review"})
		}
	}
	return out, nil
}

// webReviewPage lists who reads a project, to keep or remove each.
func (s *Server) webReviewPage(w http.ResponseWriter, r *http.Request) {
	ws := s.requireWeb(w, r)
	if ws == nil {
		return
	}
	project := r.PathValue("org") + "/" + r.PathValue("repo")
	data, err := s.teamPageData(r.Context(), ws, project)
	if err != nil {
		s.webFail(w, r, err)
		return
	}
	st, _ := data["State"].(*team.State)
	if st == nil || !st.Admin(ws.user.ID) {
		s.webFail(w, r, clientErr(http.StatusForbidden, wire.ErrForbidden, "Only an admin of the project reviews its access."))
		return
	}
	rs, err := s.reviewStatus(r.Context(), st)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	data["Review"] = rs
	s.render(w, http.StatusOK, "review.html", data)
}

// webReview records a review: those ticked to remove lose their access
// (signed by the server when the admin lets it, otherwise proposed), and
// everyone else keeps it, including anyone added since the page was shown.
func (s *Server) webReview(w http.ResponseWriter, r *http.Request) {
	s.teamForm(w, r, func(ctx context.Context, ws *webSession, st *team.State) (string, error) {
		drop := map[string]bool{}
		for _, k := range r.PostForm["remove"] {
			drop[k] = true
		}
		keep := func(name string) bool { return !drop[name] }
		ip := s.clientIP(r)
		var rv wire.AccessReview
		var proposed, signed []string
		removeChange := func(c wire.Change, name string) error {
			ok, err := s.serverSigns(ctx, ws.user.ID, ip, c)
			if err != nil {
				return err
			}
			if ok {
				signed = append(signed, name)
				return nil
			}
			proposed = append(proposed, name)
			return s.propose(ctx, ws.user.ID, ip, c)
		}
		if err := checkReviewNames(readersOf(st)); err != nil {
			return "", err
		}
		for _, m := range st.ActiveMembers() {
			if m.Admin || keep(m.Login) {
				rv.Kept = append(rv.Kept, m.Login)
				continue
			}
			rv.Removed = append(rv.Removed, m.Login)
			if err := removeChange(wire.Change{Scope: wire.ScopeProject, Target: st.Project, Kind: wire.ChangeMemberRemove, Subject: m.Login}, m.Login); err != nil {
				return "", err
			}
		}
		for _, g := range st.ActiveGroups() {
			if keep(g.Group) {
				rv.Kept = append(rv.Kept, g.Group)
				continue
			}
			rv.Removed = append(rv.Removed, g.Group)
			if err := removeChange(wire.Change{Scope: wire.ScopeGroup, Target: g.Group, Kind: wire.ChangeAccess, Project: st.Project}, g.Group); err != nil {
				return "", err
			}
		}
		for _, m := range st.ActiveMachines() {
			if keep("machine:" + m.ID) {
				rv.Kept = append(rv.Kept, "machine:"+m.Name)
				continue
			}
			rv.Removed = append(rv.Removed, "machine:"+m.Name)
			if err := removeChange(wire.Change{Scope: wire.ScopeProject, Target: st.Project, Kind: wire.ChangeMachineRemove, Subject: m.ID}, m.Name); err != nil {
				return "", err
			}
		}
		if err := s.recordReview(ctx, st.Project, ws.user.ID, ip, rv); err != nil {
			return "", err
		}
		msg := "Reviewed: " + plural(len(rv.Kept), "reader") + " keep their access."
		if len(signed) > 0 {
			msg += " Removed, signed by the server for you: " + strings.Join(signed, ", ") + "."
		}
		if len(proposed) > 0 {
			msg += " Proposed removing (sign with your passkey or esec vault changes): " + strings.Join(proposed, ", ") + "."
		}
		if len(rv.Removed) > 0 {
			msg += " Then rotate what they could read."
		}
		return msg, nil
	})
}
