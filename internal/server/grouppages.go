package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"time"

	"github.com/mscno/esec-vault/internal/team"
	"github.com/mscno/esec-vault/internal/wire"
)

// Web pages of machine groups. Admins see a group's machines and tokens,
// which projects it reads, and what waits for them. Changes made here (who
// reads what, removing a machine) are signed later by an admin's device:
// the server holds no key to sign them with. Removing a machine blocks it on
// the server at once.

// groupSummary is a group as the lists show it.
type groupSummary struct {
	ID         string
	Admin      bool
	Machines   int
	Tokens     int
	Projects   []string
	Pending    int
	KeyExposed int
	LastUsed   time.Time
	Updated    time.Time
}

// groupSummaries summarizes the groups user may read (every group for "").
func (s *Server) groupSummaries(ctx context.Context, user string) ([]groupSummary, error) {
	var ids []string
	var err error
	if user == "" {
		ids, err = s.db.allGroups(ctx)
	} else {
		ids, err = s.db.visibleGroups(ctx, user)
	}
	if err != nil {
		return nil, err
	}
	now := s.now()
	out := make([]groupSummary, 0, len(ids))
	for _, id := range ids {
		gs, err := s.listedGroup(ctx, id)
		if err != nil {
			return nil, err
		}
		if gs == nil {
			continue
		}
		sum := groupSummary{ID: id, Admin: gs.Admin(user), Machines: len(gs.ActiveCreds(team.KindMachine)), Tokens: len(gs.ActiveCreds(team.KindToken)), Projects: gs.Projects(), KeyExposed: len(gs.KeyExposed), Updated: gs.LastTime}
		rows, err := s.db.credRows(ctx, id)
		if err != nil {
			return nil, err
		}
		for _, r := range rows {
			if r.LastUsed.After(sum.LastUsed) {
				sum.LastUsed = r.LastUsed
			}
		}
		if sum.Admin || user == "" {
			joins, err := s.db.pendingJoins(ctx, id, now)
			if err != nil {
				return nil, err
			}
			props, err := s.db.openProposals(ctx, id)
			if err != nil {
				return nil, err
			}
			sum.Pending = len(joins) + len(props)
		}
		out = append(out, sum)
	}
	return out, nil
}

// groupNotices lists what waits for a group admin: machines asking to
// join, web changes to sign, and a group key a removed machine holds.
func (s *Server) groupNotices(ctx context.Context, user string) ([]notice, error) {
	ids, err := s.db.adminGroups(ctx, user)
	if err != nil {
		return nil, err
	}
	now := s.now()
	var out []notice
	for _, id := range ids {
		gs, err := s.listedGroup(ctx, id)
		if err != nil {
			return nil, err
		}
		if gs == nil {
			continue
		}
		link := "/groups/" + id
		joins, err := s.db.pendingJoins(ctx, id, now)
		if err != nil {
			return nil, err
		}
		props, err := s.db.openProposals(ctx, id)
		if err != nil {
			return nil, err
		}
		if len(joins) > 0 {
			out = append(out, notice{Level: "warn", Text: id + ": " + plural(len(joins), "machine") + " waiting to join. Let them in from a device, after comparing the words each machine shows.", Command: "esec vault group approve " + id, Link: link, LinkTo: "Open group"})
		}
		if len(props) > 0 {
			out = append(out, notice{Level: "info", Text: id + ": " + plural(len(props), "change") + " made on these pages wait to be signed by an admin's device.", Command: "esec vault group approve " + id, Link: link, LinkTo: "Open group"})
		}
		if len(gs.KeyExposed) > 0 {
			out = append(out, notice{Level: "warn", Text: id + ": a removed machine still holds the group key.", Command: "esec vault group rotate " + id, Link: link, LinkTo: "Open group"})
		}
	}
	return out, nil
}

// sharedNotices lists what waits for user in machine groups and shared
// projects.
func (s *Server) sharedNotices(ctx context.Context, user string) ([]notice, error) {
	groups, err := s.groupNotices(ctx, user)
	if err != nil {
		return nil, err
	}
	teams, err := s.teamNotices(ctx, user)
	return append(groups, teams...), err
}

func (s *Server) webGroups(w http.ResponseWriter, r *http.Request) {
	ws := s.requireWeb(w, r)
	if ws == nil {
		return
	}
	groups, err := s.groupSummaries(r.Context(), ws.user.ID)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	data := s.page(ws, "groups")
	data["Groups"] = groups
	s.render(w, http.StatusOK, "groups.html", data)
}

type credView struct {
	*team.CredState

	Policy    string
	LastUsed  time.Time
	LastIP    string
	Uses      int
	Suspended bool
	HasKey    bool
	AddedAt   time.Time
	AddedBy   string
}

// accessRow is one project of the access matrix.
type accessRow struct {
	Project string
	// Envs lists the project's environments, with whether the group reads
	// each; Known is false when the viewer is not a member of the project.
	Envs    []accessEnv
	Known   bool
	Trusted bool
	// CanEdit says the viewer administers the group or the project.
	CanEdit bool
	Pending bool
	Rotate  []string
}

type accessEnv struct {
	Name  string
	Reads bool
}

type groupAuditView struct {
	groupAuditRow

	ActorName string
	Label     string
}

func (s *Server) webGroup(w http.ResponseWriter, r *http.Request) {
	ws := s.requireWeb(w, r)
	if ws == nil {
		return
	}
	id := r.PathValue("org") + "/" + r.PathValue("name")
	if team.ValidGroup(id) != nil {
		s.webError(w, http.StatusNotFound, "There is no such machine group.")
		return
	}
	ctx := r.Context()
	gs, _, err := s.db.groupState(ctx, s.db.sql, id)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	readable := false
	if gs != nil {
		if readable, err = s.db.canReadGroup(ctx, ws.user.ID, id); err != nil {
			s.internalError(w, r, err)
			return
		}
	}
	if gs == nil || (!readable && !s.cfg.Admin(ws.user.GitHubID)) {
		s.webError(w, http.StatusNotFound, "There is no such machine group, or it is not yours to see.")
		return
	}
	nav := "groups"
	if !readable {
		nav = "admin"
	}
	data := s.page(ws, nav)
	if err := s.groupPage(ctx, gs, ws.user.ID, data); err != nil {
		s.internalError(w, r, err)
		return
	}
	data["Readable"] = readable
	// Addresses, join requests and the log are the group's admins' (and
	// the server admins') to see.
	data["ShowOps"] = gs.Admin(ws.user.ID) || s.cfg.Admin(ws.user.GitHubID)
	s.render(w, http.StatusOK, "group.html", data)
}

// groupPage adds what the group page shows of gs, for viewer, to data.
func (s *Server) groupPage(ctx context.Context, gs *team.GroupState, viewer string, data map[string]any) error {
	now := s.now()
	status, err := s.db.groupStatus(ctx, gs, now)
	if err != nil {
		return err
	}
	rows, err := s.db.credRows(ctx, gs.Group)
	if err != nil {
		return err
	}
	has := map[string]bool{}
	for _, c := range status.Creds {
		has[c.ID] = c.HasKey
	}
	added := map[uint64]time.Time{}
	for _, l := range gs.Links {
		added[l.Seq] = l.CTime
	}
	view := func(kind string) []credView {
		creds := gs.ActiveCreds(kind)
		out := make([]credView, 0, len(creds))
		for _, c := range creds {
			r := rows[c.ID]
			out = append(out, credView{CredState: c, Policy: c.OIDC.Describe(), LastUsed: r.LastUsed, LastIP: r.LastIP, Uses: r.Uses, Suspended: !r.Suspended.IsZero(), HasKey: has[c.ID], AddedAt: added[c.AddedSeq], AddedBy: groupActor(gs, c.AddedBy)})
		}
		return out
	}
	admin := gs.Admin(viewer)
	matrix, err := s.accessMatrix(ctx, gs, viewer, status.Proposals)
	if err != nil {
		return err
	}
	activity, err := s.db.groupAuditPage(ctx, gs.Group, 50)
	if err != nil {
		return err
	}
	logins, err := s.db.logins(ctx)
	if err != nil {
		return err
	}
	acts := make([]groupAuditView, 0, len(activity))
	for _, e := range activity {
		if len(e.Action) > 5 && e.Action[:5] == "link_" {
			continue
		}
		name := logins[e.Actor]
		if c := gs.Creds[e.Actor]; c != nil {
			name = c.Name
		}
		acts = append(acts, groupAuditView{groupAuditRow: e, ActorName: name, Label: groupAuditLabel(e.Action)})
	}
	data["Group"] = gs.Group
	data["State"] = gs
	data["MyAdmin"] = admin
	data["Admins"] = gs.ActiveAdmins()
	data["Machines"] = view(team.KindMachine)
	data["Tokens"] = view(team.KindToken)
	data["Matrix"] = matrix
	data["Joins"] = status.Joins
	data["Proposals"] = status.Proposals
	data["History"] = groupHistoryOf(gs)
	data["Activity"] = acts
	data["Created"] = gs.Links[0].CTime
	data["Creator"] = groupActor(gs, gs.Links[0].Signer)
	return nil
}

// accessMatrix lists the projects a group reads or could read: those it
// trusts, those granting it environments, and those the viewer
// administers.
func (s *Server) accessMatrix(ctx context.Context, gs *team.GroupState, viewer string, proposals []wire.Proposal) ([]accessRow, error) {
	ids := map[string]bool{}
	for p := range gs.Access {
		ids[p] = true
	}
	granting, err := s.db.projectsGranting(ctx, s.db.sql, gs.Group)
	if err != nil {
		return nil, err
	}
	for _, p := range granting {
		ids[p] = true
	}
	mine, err := s.db.memberProjects(ctx, viewer)
	if err != nil {
		return nil, err
	}
	pending := map[string]bool{}
	for _, p := range proposals {
		if p.Kind == wire.ProposalAccess {
			pending[p.Project] = true
		}
	}
	admin := gs.Admin(viewer)
	out := make([]accessRow, 0, len(ids))
	for _, p := range mine {
		st, err := s.listedProject(ctx, p)
		if err != nil {
			return nil, err
		}
		if st != nil && (st.Admin(viewer) && admin) {
			ids[p] = true
		}
	}
	for p := range ids {
		st, err := s.listedProject(ctx, p)
		if err != nil {
			return nil, err
		}
		row := accessRowOf(gs, st, viewer)
		row.Project, row.Pending = p, pending[p]
		if st == nil {
			_, row.Trusted = gs.Access[p]
		}
		out = append(out, row)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Project < out[j].Project })
	return out, nil
}

// accessRowOf is what viewer sees of one project in a group's access
// matrix; st is nil for a project that does not verify.
func accessRowOf(gs *team.GroupState, st *team.State, viewer string) accessRow {
	var row accessRow
	if st == nil {
		return row
	}
	root, trusted := gs.Access[st.Project]
	_, row.Known = st.Member(viewer)
	row.Trusted = trusted && root == st.Root()
	row.CanEdit = gs.Admin(viewer) || (st.Admin(viewer) && row.Trusted)
	if !row.Known {
		// Only the group's side is the viewer's to see.
		return row
	}
	pg, ok := st.Group(gs.Group)
	reads := ok && pg.Root == gs.Root()
	for _, n := range st.EnvNames() {
		row.Envs = append(row.Envs, accessEnv{Name: n, Reads: reads && pg.Has(n)})
	}
	for env := range team.GroupExposures(st, gs) {
		row.Rotate = append(row.Rotate, env)
	}
	row.Rotate = team.SortEnvs(row.Rotate)
	return row
}

func groupAuditLabel(action string) string {
	switch action {
	case "keys":
		return "Fetched its keys"
	case "keys_refused":
		return "Refused (OIDC)"
	case "enroll_refused":
		return "Enrollment refused (OIDC)"
	case "enrolled":
		return "Enrolled with a token"
	case "join_requested":
		return "Asked to join"
	case "join_rejected":
		return "Turned away"
	case "change_proposed":
		return "Change proposed on the web"
	case "change_applied":
		return "Change signed"
	case "change_dismissed":
		return "Change dismissed"
	case "blocked":
		return "Blocked on the web"
	}
	return action
}

// groupHistoryOf describes the group chain's links, newest first.
func groupHistoryOf(gs *team.GroupState) []teamHistory {
	out := make([]teamHistory, 0, len(gs.Links))
	for _, l := range gs.Links {
		h := teamHistory{Time: l.CTime, Actor: groupActor(gs, l.Signer), Text: groupLinkText(gs, l)}
		if l.Type == team.GroupRemove || l.Type == team.GroupAdminRemove {
			h.Tone = "bad"
		}
		out = append(out, h)
	}
	slices.Reverse(out)
	if len(out) > 100 {
		out = out[:100]
	}
	return out
}

func groupLinkText(gs *team.GroupState, l team.GroupLink) string {
	var b struct {
		Admin     team.Person     `json:"admin"`
		User      string          `json:"user"`
		Machine   team.Credential `json:"machine"`
		Token     team.Credential `json:"token"`
		ID        string          `json:"id"`
		Key       team.GroupKey   `json:"key"`
		Project   string          `json:"project"`
		Join      string          `json:"join"`
		Destroyed bool            `json:"destroyed"`
		Reason    string          `json:"reason"`
	}
	_ = json.Unmarshal(l.Body, &b)
	switch l.Type {
	case team.GroupInit:
		return "created the machine group"
	case team.GroupAdminAdd:
		return "made " + b.Admin.Login + " an admin"
	case team.GroupAdminRemove:
		if a := gs.Admins[b.User]; a != nil {
			return "removed the admin " + a.Login
		}
		return "removed an admin"
	case team.GroupMachineAdd:
		if b.Join != "" {
			return "let in the machine " + b.Machine.Name + ", which asked to join"
		}
		return "added the machine " + b.Machine.Name
	case team.GroupTokenAdd:
		t := "created the enrollment token " + b.Token.Name
		if !b.Token.Expires.IsZero() {
			t += ", valid until " + b.Token.Expires.UTC().Format("2006-01-02")
		}
		return t
	case team.GroupRemove:
		name := b.ID
		if c := gs.Creds[b.ID]; c != nil {
			name = c.Kind + " " + c.Name
		}
		if b.Destroyed {
			return "removed the " + name + " (destroyed with its keys)"
		}
		return "removed the " + name
	case team.GroupKeyRotate:
		return "gave the group a new key (version " + strconv.FormatUint(b.Key.Version, 10) + ")"
	case team.GroupAccessAdd:
		return "let the group take keys from " + b.Project
	case team.GroupAccessRemove:
		return "stopped the group taking keys from " + b.Project
	}
	return l.Type
}

// ---- forms: changes for an admin's device to sign ----

// groupForm runs a CSRF-checked group form and returns to the group page.
func (s *Server) groupForm(w http.ResponseWriter, r *http.Request, fn func(ctx context.Context, ws *webSession, gs *team.GroupState) error) {
	ws := s.requireWeb(w, r)
	if ws == nil {
		return
	}
	if !s.checkForm(r, ws) {
		s.webError(w, http.StatusForbidden, "The form expired. Reload the page and try again.")
		return
	}
	id := r.PathValue("org") + "/" + r.PathValue("name")
	if team.ValidGroup(id) != nil {
		s.webError(w, http.StatusNotFound, "There is no such machine group.")
		return
	}
	ctx := r.Context()
	gs, _, err := s.db.groupState(ctx, s.db.sql, id)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if gs == nil {
		s.webError(w, http.StatusNotFound, "There is no such machine group.")
		return
	}
	if err := fn(ctx, ws, gs); err != nil {
		var ae *apiError
		if errors.As(err, &ae) {
			s.webError(w, ae.status, ae.desc)
			return
		}
		s.internalError(w, r, err)
		return
	}
	http.Redirect(w, r, "/groups/"+id, http.StatusSeeOther) //nolint:gosec // id is a valid group id, so this stays on this site
}

// webGroupAccess proposes what the group reads of a project. An admin of
// the group or of the project may propose; their device signs their side.
func (s *Server) webGroupAccess(w http.ResponseWriter, r *http.Request) {
	s.groupForm(w, r, func(ctx context.Context, ws *webSession, gs *team.GroupState) error {
		project := r.PostForm.Get("project")
		if team.ValidProject(project) != nil {
			return clientErr(http.StatusBadRequest, wire.ErrInvalidRequest, "invalid project")
		}
		st, _, err := s.db.projectState(ctx, s.db.sql, project)
		if err != nil {
			return err
		}
		if st == nil {
			return clientErr(http.StatusNotFound, wire.ErrNotFound, "there is no shared project %s", project)
		}
		// A project admin may propose only for a project the group already
		// takes keys from: anyone can create a project.
		if root, trusted := gs.Access[project]; !gs.Admin(ws.user.ID) && (!st.Admin(ws.user.ID) || !trusted || root != st.Root()) {
			return clientErr(http.StatusForbidden, wire.ErrForbidden, "only an admin of the group, or of a project it takes keys from, can change this")
		}
		envs := team.SortEnvs(r.PostForm["env"])
		for _, n := range envs {
			if _, ok := st.Envs[n]; !ok {
				return clientErr(http.StatusBadRequest, wire.ErrInvalidRequest, "%s has no environment %s", project, n)
			}
		}
		raw, err := json.Marshal(envs)
		if err != nil {
			return err
		}
		return s.propose(ctx, gs.Group, ws.user.ID, s.clientIP(r), wire.ProposalAccess, project, string(raw), "", gs)
	})
}

// webGroupRemove blocks a machine or token at once and proposes removing
// it from the group chain.
func (s *Server) webGroupRemove(w http.ResponseWriter, r *http.Request) {
	s.groupForm(w, r, func(ctx context.Context, ws *webSession, gs *team.GroupState) error {
		if !gs.Admin(ws.user.ID) {
			return clientErr(http.StatusForbidden, wire.ErrForbidden, "only an admin of the group can remove machines")
		}
		id := r.PostForm.Get("cred")
		c, ok := gs.Cred(id)
		if !ok {
			return clientErr(http.StatusNotFound, wire.ErrNotFound, "no such machine or token")
		}
		now := s.now()
		if _, err := s.db.sql.ExecContext(ctx, `UPDATE group_creds SET suspended_at = ? WHERE group_id = ? AND id = ? AND suspended_at = 0`, now.Unix(), gs.Group, id); err != nil {
			return err
		}
		if err := s.db.groupAudit(ctx, s.db.sql, gs.Group, ws.user.ID, s.clientIP(r), "blocked", c.Kind+" "+c.Name, now); err != nil {
			return err
		}
		return s.propose(ctx, gs.Group, ws.user.ID, s.clientIP(r), wire.ProposalRemove, "", "[]", id, gs)
	})
}

// propose stores a web change for an admin's device to sign, unless the
// same one waits already, and wakes the group's admins.
func (s *Server) propose(ctx context.Context, group, user, ip, kind, project, envs, cred string, gs *team.GroupState) error {
	now := s.now()
	var wake []string
	err := s.db.tx(ctx, func(tx *sql.Tx) error {
		var n, same int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*), COALESCE(SUM(kind = ? AND project = ? AND envs = ? AND cred_id = ?), 0) FROM group_proposals WHERE group_id = ? AND status = 'open'`,
			kind, project, envs, cred, group).Scan(&n, &same); err != nil {
			return err
		}
		if same > 0 {
			return nil
		}
		if n >= maxOpenProposals {
			return clientErr(http.StatusTooManyRequests, wire.ErrRateLimited, "too many changes wait to be signed; sign or dismiss some first (esec vault group approve %s)", group)
		}
		// A newer change to the same project replaces an older one.
		if kind == wire.ProposalAccess {
			if _, err := tx.ExecContext(ctx, `UPDATE group_proposals SET status = 'dismissed', closed_at = ? WHERE group_id = ? AND status = 'open' AND kind = ? AND project = ?`, now.Unix(), group, kind, project); err != nil {
				return err
			}
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO group_proposals (group_id, kind, project, envs, cred_id, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
			group, kind, project, envs, cred, user, now.Unix()); err != nil {
			return err
		}
		if err := s.db.groupAudit(ctx, tx, group, user, ip, "change_proposed", kind+" "+project+cred, now); err != nil {
			return err
		}
		for _, a := range gs.ActiveAdmins() {
			if err := s.db.addEvent(ctx, tx, a.User, wire.EventGroup, group, now); err != nil {
				return err
			}
			wake = append(wake, a.User)
		}
		return nil
	})
	for _, u := range wake {
		s.notify.wake(u)
	}
	return err
}

func (s *Server) webGroupRejectJoin(w http.ResponseWriter, r *http.Request) {
	s.groupForm(w, r, func(ctx context.Context, ws *webSession, gs *team.GroupState) error {
		return s.rejectJoin(ctx, gs.Group, r.PathValue("id"), ws.user.ID, s.clientIP(r))
	})
}

func (s *Server) webGroupDismiss(w http.ResponseWriter, r *http.Request) {
	s.groupForm(w, r, func(ctx context.Context, ws *webSession, gs *team.GroupState) error {
		return s.closeProposal(ctx, gs.Group, r.PathValue("id"), false, ws.user.ID, s.clientIP(r))
	})
}
