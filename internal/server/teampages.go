package server

import (
	"context"
	"encoding/json"
	"html/template"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/mscno/esec-vault/internal/envelope"
	"github.com/mscno/esec-vault/internal/team"
	"github.com/mscno/esec-vault/internal/wire"
)

// Web pages of shared projects. Members see their projects; server admins
// see every project, read-only, like the rest of the admin pages.

// teamSummary is a shared project as the lists show it.
type teamSummary struct {
	ID        string
	Admin     bool
	Access    []string
	Members   int
	Machines  int
	Rotations int
	Missing   int
	Updated   time.Time
}

// teamSummaries summarizes projects for user (or every project for "").
func (s *Server) teamSummaries(ctx context.Context, user string) ([]teamSummary, error) {
	var ids []string
	var err error
	if user == "" {
		ids, err = s.db.allProjects(ctx)
	} else {
		ids, err = s.db.memberProjects(ctx, user)
	}
	if err != nil {
		return nil, err
	}
	var out []teamSummary
	for _, id := range ids {
		st, err := s.listedProject(ctx, id)
		if err != nil {
			return nil, err
		}
		if st == nil {
			continue
		}
		status, err := s.db.projectStatus(ctx, st)
		if err != nil {
			return nil, err
		}
		sum := teamSummary{ID: id, Admin: st.Admin(user), Access: st.Access(user), Members: len(st.ActiveMembers()), Machines: len(st.ActiveMachines()), Rotations: len(st.Rotations()), Updated: st.LastTime}
		for _, h := range status.Holders {
			for _, v := range h.Envs {
				if v == wire.KeyMissing {
					sum.Missing++
				}
			}
		}
		out = append(out, sum)
	}
	return out, nil
}

// teamNotices lists what needs a member's attention in their shared
// projects: keys to rotate (admins), keys still to send (admins), and keys
// waiting for the member's own devices.
func (s *Server) teamNotices(ctx context.Context, user string) ([]notice, error) {
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
		if st == nil {
			continue
		}
		link := "/teams/" + id
		admin := st.Admin(user)
		for _, e := range st.Rotations() {
			if !st.HasAccess(user, e.Name) {
				continue
			}
			var who []string
			for _, x := range e.Exposed {
				who = append(who, x.Name)
			}
			n := notice{Level: "warn", Text: id + " " + e.Name + " needs a new key: " + strings.Join(who, ", ") + " lost access but may still hold the current one.", Link: link, LinkTo: "Open project"}
			if admin {
				n.Command = "esec vault env rotate " + e.Name + " --project " + id
			} else {
				n.Level, n.Text = "info", n.Text+" An admin of the project replaces it; until then, treat its secrets as known to them."
			}
			out = append(out, n)
		}
		out = append(out, s.groupRotationNotices(ctx, st, user, admin, link)...)
		status, err := s.db.projectStatus(ctx, st)
		if err != nil {
			return nil, err
		}
		missing, waitingMine := 0, 0
		for _, h := range status.Holders {
			for _, v := range h.Envs {
				switch {
				case v == wire.KeyMissing && h.ID != user:
					missing++
				case v == wire.KeyWaiting && h.ID == user:
					waitingMine++
				}
			}
		}
		if admin && missing > 0 {
			out = append(out, notice{Level: "info", Text: id + ": " + plural(missing, "key") + " still have to be sent to members or machines. Any admin's device sends them on its next sync.", Command: "esec vault access sync", Link: link, LinkTo: "Open project"})
		}
		if waitingMine > 0 {
			out = append(out, notice{Level: "info", Text: id + ": " + plural(waitingMine, "key") + " wait for your devices. A signed-in device with the background service picks them up by itself.", Command: "esec vault access sync", Link: link, LinkTo: "Open project"})
		}
	}
	return out, nil
}

// groupRotationNotices lists the environments of st, that user reads,
// whose key a machine removed from a group may still hold.
func (s *Server) groupRotationNotices(ctx context.Context, st *team.State, user string, admin bool, link string) []notice {
	var out []notice
	for _, pg := range st.ActiveGroups() {
		gs, err := s.listedGroup(ctx, pg.Group)
		if err != nil || gs == nil {
			continue
		}
		exposed := team.GroupExposures(st, gs)
		for _, env := range team.SortEnvs(mapKeys(exposed)) {
			if !st.HasAccess(user, env) {
				continue
			}
			var who []string
			for _, x := range exposed[env] {
				who = append(who, x.Name)
			}
			n := notice{Level: "warn", Text: st.Project + " " + env + " needs a new key: " + strings.Join(who, ", ") + " left the group " + pg.Group + " but may still hold the current one.", Link: link, LinkTo: "Open project"}
			if admin {
				n.Command = "esec vault env rotate " + env + " --project " + st.Project
			} else {
				n.Level, n.Text = "info", n.Text+" An admin of the project replaces it."
			}
			out = append(out, n)
		}
	}
	return out
}

func mapKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

type teamMemberView struct {
	*team.MemberState

	Access   []string
	Keys     map[string]string
	Allowed  bool
	AddedAt  time.Time
	AddedBy  string
	Verified string
}

type teamMachineView struct {
	*team.MachineState

	Keys     map[string]string
	Policy   string
	LastUsed time.Time
	LastIP   string
	Uses     int
	AddedAt  time.Time
	AddedBy  string
}

type teamGroupView struct {
	*team.ProjectGroupState

	Keys     map[string]string
	People   []string
	Machines int
	Tokens   int
	Trusted  bool
	Rotate   []string
	AddedAt  time.Time
	AddedBy  string
}

type teamEnvView struct {
	*team.EnvState

	Readers int
}

type teamHistory struct {
	Time  time.Time
	Actor string
	Text  string
	Tone  string
}

type teamAuditView struct {
	projectAuditRow

	ActorName string
	Label     string
}

func (s *Server) webTeam(w http.ResponseWriter, r *http.Request) {
	ws := s.requireWeb(w, r)
	if ws == nil {
		return
	}
	data, err := s.teamPageData(r.Context(), ws, r.PathValue("org")+"/"+r.PathValue("repo"))
	if err != nil {
		s.webFail(w, r, err)
		return
	}
	s.render(w, http.StatusOK, "team.html", data)
}

// The parts of a project's page that refresh on their own, and those a
// submission changes too.
var (
	teamLiveParts = []string{"team-alerts", "team-tiles", "team-members", "team-machines", "team-groups", "team-changes", "team-history", "team-activity"}
	teamParts     = append([]string{"team-manage"}, teamLiveParts...)
)

func (s *Server) webTeamLive(w http.ResponseWriter, r *http.Request) {
	ws := s.dsSession(w, r)
	if ws == nil {
		return
	}
	data, err := s.teamPageData(r.Context(), ws, r.PathValue("org")+"/"+r.PathValue("repo"))
	if err != nil {
		s.dsFail(w, r, err)
		return
	}
	s.dsPatch(w, r, data, teamLiveParts...)
}

// teamPageData builds a project's page for ws, a member or a server admin.
func (s *Server) teamPageData(ctx context.Context, ws *webSession, project string) (map[string]any, error) {
	notFound := clientErr(http.StatusNotFound, wire.ErrNotFound, "There is no such project, or you are not a member of it.")
	if team.ValidProject(project) != nil {
		return nil, notFound
	}
	st, _, err := s.db.projectState(ctx, s.db.sql, project)
	if err != nil {
		return nil, err
	}
	member := false
	if st != nil {
		_, member = st.Member(ws.user.ID)
	}
	if st == nil || (!member && !s.cfg.Admin(ws.user.GitHubID)) {
		return nil, notFound
	}
	nav := "projects"
	if !member {
		nav = "admin"
	}
	data := s.page(ws, nav)
	if err := s.teamPage(ctx, st, data); err != nil {
		return nil, err
	}
	data["Member"] = member
	data["MyAdmin"] = st.Admin(ws.user.ID)
	data["MyAccess"] = st.Access(ws.user.ID)
	changes, err := s.db.openChanges(ctx, wire.ScopeProject, project)
	if err != nil {
		return nil, err
	}
	data["Changes"] = changes
	s.addPasskeys(ctx, ws, data)
	return data, nil
}

// teamForm runs a CSRF-checked form of a project's admins.
func (s *Server) teamForm(w http.ResponseWriter, r *http.Request, fn func(ctx context.Context, ws *webSession, st *team.State) (string, error)) {
	project := r.PathValue("org") + "/" + r.PathValue("repo")
	s.pageForm(w, r, "/teams/"+project, func(ctx context.Context, ws *webSession) (string, error) {
		if team.ValidProject(project) != nil {
			return "", clientErr(http.StatusNotFound, wire.ErrNotFound, "There is no such project.")
		}
		st, _, err := s.db.projectState(ctx, s.db.sql, project)
		if err != nil {
			return "", err
		}
		if st == nil || !st.Admin(ws.user.ID) {
			return "", clientErr(http.StatusForbidden, wire.ErrForbidden, "Only an admin of the project can change who reads it.")
		}
		return fn(ctx, ws, st)
	}, func(ctx context.Context, ws *webSession) (map[string]any, []string, error) {
		data, err := s.teamPageData(ctx, ws, project)
		return data, teamParts, err
	})
}

// memberForm reads a member form: a login and, unless admin, the
// environments, which must be the project's.
func memberForm(r *http.Request, st *team.State) (login string, admin bool, envs []string, err error) {
	login = r.PostForm.Get("login")
	if team.ValidLogin(login) != nil {
		return "", false, nil, clientErr(http.StatusBadRequest, wire.ErrInvalidRequest, "That is not a GitHub login.")
	}
	admin = r.PostForm.Get("admin") == "on"
	if admin {
		return login, true, nil, nil
	}
	envs = team.SortEnvs(r.PostForm["env"])
	for _, n := range envs {
		if _, ok := st.Envs[n]; !ok {
			return "", false, nil, clientErr(http.StatusBadRequest, wire.ErrInvalidRequest, "%s has no environment %s.", st.Project, n)
		}
	}
	return login, false, envs, nil
}

// memberOf finds an active member by login, ignoring case.
func memberOf(st *team.State, login string) *team.MemberState {
	for _, m := range st.ActiveMembers() {
		if strings.EqualFold(m.Login, login) {
			return m
		}
	}
	return nil
}

// webTeamAdd proposes adding a member. The admin's device checks the
// person's GitHub SSH proof before it signs.
func (s *Server) webTeamAdd(w http.ResponseWriter, r *http.Request) {
	s.teamForm(w, r, func(ctx context.Context, ws *webSession, st *team.State) (string, error) {
		login, admin, envs, err := memberForm(r, st)
		if err != nil {
			return "", err
		}
		if !admin && len(envs) == 0 {
			return "", clientErr(http.StatusBadRequest, wire.ErrInvalidRequest, "Tick what they may read, or make them an admin.")
		}
		if memberOf(st, login) != nil {
			return "", clientErr(http.StatusConflict, wire.ErrConflict, "%s is a member already; change what they read below.", login)
		}
		u, err := s.db.userByLogin(ctx, login)
		if err != nil {
			return "", err
		}
		if u != nil && !s.cfg.Allowed(u.GitHubID) {
			return "", clientErr(http.StatusBadRequest, wire.ErrInvalidRequest, "%s may not use this server.", login)
		}
		var first *envelope.Envelope
		if u != nil {
			if first, err = s.db.firstLink(ctx, u.ID); err != nil {
				return "", err
			}
		}
		if first == nil {
			// No vault account yet: the invite waits for one.
			c := wire.Change{Scope: wire.ScopeProject, Target: st.Project, Kind: wire.ChangeMemberAdd, Subject: login, Admin: admin, Envs: envs}
			if err := s.addInvite(ctx, ws.user.ID, s.clientIP(r), c); err != nil {
				return "", err
			}
			return "Invited " + login + ". They have no vault account here yet: once they sign in (esec vault login " + s.cfg.BaseURL + ") the change adding them waits for you to sign.", nil
		}
		if err := s.propose(ctx, ws.user.ID, s.clientIP(r), wire.Change{Scope: wire.ScopeProject, Target: st.Project, Kind: wire.ChangeMemberAdd, Subject: u.Login, Admin: admin, Envs: envs}); err != nil {
			return "", err
		}
		return "Proposed. Sign it with your passkey on the Changes page, or on a device: esec vault changes. Either way, " + u.Login + " gets keys only once an admin's device has checked their GitHub SSH proof.", nil
	})
}

// webTeamSet proposes changing what a member reads, or removing them.
func (s *Server) webTeamSet(w http.ResponseWriter, r *http.Request) {
	s.teamForm(w, r, func(ctx context.Context, ws *webSession, st *team.State) (string, error) {
		login, admin, envs, err := memberForm(r, st)
		if err != nil {
			return "", err
		}
		m := memberOf(st, login)
		if m == nil {
			return "", clientErr(http.StatusNotFound, wire.ErrNotFound, "%s is not a member.", login)
		}
		c := wire.Change{Scope: wire.ScopeProject, Target: st.Project, Kind: wire.ChangeMemberSet, Subject: m.Login, Admin: admin, Envs: envs}
		done := "Proposed. Sign it with your passkey on the Changes page, or on a device: esec vault changes"
		if r.PostForm.Get("remove") != "" {
			c = wire.Change{Scope: wire.ScopeProject, Target: st.Project, Kind: wire.ChangeMemberRemove, Subject: m.Login}
			done = "Proposed. Sign it with your passkey on the Changes page, or on a device: esec vault changes. Then rotate what they could read."
		}
		if signed, err := s.serverSigns(ctx, ws.user.ID, s.clientIP(r), c); err != nil || signed {
			return "Done, signed by the server for you. Rotate what " + m.Login + " can no longer read; the page lists it.", err
		}
		return done, s.propose(ctx, ws.user.ID, s.clientIP(r), c)
	})
}

func (s *Server) webTeamDismiss(w http.ResponseWriter, r *http.Request) {
	s.teamForm(w, r, func(ctx context.Context, ws *webSession, _ *team.State) (string, error) {
		return s.dismiss(ctx, ws, r)
	})
}

// teamWaiting adds a project's invites, access requests and timed access
// to data.
func (s *Server) teamWaiting(ctx context.Context, st *team.State, data map[string]any) error {
	invites, err := s.invites(ctx, wire.ScopeProject, st.Project)
	if err != nil {
		return err
	}
	data["Invites"] = invites
	if data["Requests"], err = s.projectRequests(ctx, st.Project); err != nil {
		return err
	}
	data["Expiries"], err = s.expiries(ctx, st.Project)
	return err
}

// teamPage adds what the project page shows of st to data.
func (s *Server) teamPage(ctx context.Context, st *team.State, data map[string]any) error {
	status, err := s.db.projectStatus(ctx, st)
	if err != nil {
		return err
	}
	keys := map[string]map[string]string{}
	for _, h := range status.Holders {
		keys[h.ID] = h.Envs
	}
	used, err := s.db.machineUse(ctx, st.Project)
	if err != nil {
		return err
	}
	added := map[uint64]time.Time{}
	for _, l := range st.Links {
		added[l.Seq] = l.CTime
	}
	members := st.ActiveMembers()
	memberViews := make([]teamMemberView, 0, len(members))
	for _, m := range members {
		gh := int64(0)
		if u, err := s.db.userByID(ctx, m.User); err == nil && u != nil {
			gh = u.GitHubID
		}
		memberViews = append(memberViews, teamMemberView{MemberState: m, Access: st.Access(m.User), Keys: keys[m.User], Allowed: gh != 0 && s.cfg.Allowed(gh), AddedAt: added[m.AddedSeq], AddedBy: loginOf(st, m.AddedBy), Verified: verifiedLabel(m.Verified)})
	}
	machines := st.ActiveMachines()
	machineViews := make([]teamMachineView, 0, len(machines))
	for _, m := range machines {
		u := used[m.ID]
		machineViews = append(machineViews, teamMachineView{MachineState: m, Keys: keys[m.ID], Policy: m.OIDC.Describe(), LastUsed: u.last, LastIP: u.ip, Uses: u.uses, AddedAt: added[m.AddedSeq], AddedBy: loginOf(st, m.AddedBy)})
	}
	groups := st.ActiveGroups()
	groupViews := s.teamGroups(ctx, st, keys, added)
	envs := make([]teamEnvView, 0, len(st.Envs))
	for _, n := range st.EnvNames() {
		v := teamEnvView{EnvState: st.Envs[n]}
		for _, m := range members {
			if m.Has(n) {
				v.Readers++
			}
		}
		for _, m := range machines {
			if m.Has(n) {
				v.Readers++
			}
		}
		for _, g := range groups {
			if g.Has(n) {
				v.Readers++
			}
		}
		envs = append(envs, v)
	}
	activity, err := s.teamActivity(ctx, st)
	if err != nil {
		return err
	}
	data["Project"] = st.Project
	data["State"] = st
	data["Members"] = memberViews
	if err := s.teamWaiting(ctx, st, data); err != nil {
		return err
	}
	data["Machines"] = machineViews
	data["Groups"] = groupViews
	data["Envs"] = envs
	data["Rotations"] = st.Rotations()
	data["History"] = teamHistoryOf(st)
	data["Activity"] = activity
	data["Created"] = st.Links[0].CTime
	data["Creator"] = loginOf(st, st.Links[0].Signer)
	return nil
}

// teamGroups describes the machine groups st grants environments.
func (s *Server) teamGroups(ctx context.Context, st *team.State, keys map[string]map[string]string, added map[uint64]time.Time) []teamGroupView {
	groups := st.ActiveGroups()
	out := make([]teamGroupView, 0, len(groups))
	for _, g := range groups {
		v := teamGroupView{ProjectGroupState: g, Keys: keys[team.GroupHolder(g.Group)], AddedAt: added[g.AddedSeq], AddedBy: loginOf(st, g.AddedBy)}
		if gs, err := s.listedGroup(ctx, g.Group); err == nil && gs != nil && gs.Root() == g.Root {
			v.Machines = len(gs.ActiveCreds(team.KindMachine))
			v.Tokens = len(gs.ActiveCreds(team.KindToken))
			for _, p := range gs.ActiveMembers() {
				v.People = append(v.People, p.Login)
			}
			_, v.Trusted = gs.Access[st.Project]
			for env := range team.GroupExposures(st, gs) {
				v.Rotate = append(v.Rotate, env)
			}
			v.Rotate = team.SortEnvs(v.Rotate)
		}
		out = append(out, v)
	}
	return out
}

// teamActivity lists key deliveries and machine use. Chain changes are
// left out: the history describes them from the signed chain.
func (s *Server) teamActivity(ctx context.Context, st *team.State) ([]teamAuditView, error) {
	audit, err := s.db.projectAuditPage(ctx, st.Project, 50)
	if err != nil {
		return nil, err
	}
	logins, err := s.db.logins(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]teamAuditView, 0, len(audit))
	for _, e := range audit {
		if strings.HasPrefix(e.Action, "link_") {
			continue
		}
		name := logins[e.Actor]
		if m := st.Machines[e.Actor]; m != nil {
			name = m.Name
		}
		if e.Action == "grant" {
			// "<recipient id> <envs>": show the recipient's name.
			if to, envs, ok := strings.Cut(e.Detail, " "); ok {
				if m := st.Machines[to]; m != nil {
					e.Detail = m.Name + ": " + envs
				} else if m := st.Members[to]; m != nil {
					e.Detail = m.Login + ": " + envs
				}
			}
		}
		out = append(out, teamAuditView{projectAuditRow: e, ActorName: name, Label: projectAuditLabel(e.Action)})
	}
	return out, nil
}

// keyBadge shows an environment with its key delivery state.
func keyBadge(env, state string) template.HTML {
	class, label := "badge status-pending", "not sent"
	switch state {
	case wire.KeyHeld:
		class, label = "badge status-active", "held"
	case wire.KeyWaiting:
		class, label = "badge", "waiting"
	}
	return template.HTML(`<span class="` + class + `" title="` + template.HTMLEscapeString(env+": "+label) + `">` + template.HTMLEscapeString(env) + ` · ` + label + `</span>`) //nolint:gosec // escaped above
}

func verifiedLabel(v string) string {
	switch v {
	case team.VerifiedGitHubSSH:
		return "GitHub SSH key"
	case team.VerifiedAccountKey:
		return "account key words"
	}
	return ""
}

func projectAuditLabel(action string) string {
	switch action {
	case "grant":
		return "Keys sent"
	case "keys_received":
		return "Keys received"
	case "machine_keys":
		return "Machine fetched its keys"
	case "machine_refused":
		return "Machine refused"
	case "change_proposed":
		return "Change proposed on the web"
	case "change_applied":
		return "Change signed"
	case "change_dismissed":
		return "Change dismissed"
	}
	return action
}

// teamHistoryOf describes the chain's links, newest first.
func teamHistoryOf(st *team.State) []teamHistory {
	seen := map[string]bool{}
	out := make([]teamHistory, 0, len(st.Links))
	for _, l := range st.Links {
		h := teamHistory{Time: l.CTime, Actor: loginOf(st, l.Signer), Text: linkText(st, l, seen)}
		if l.Type == team.TypeMemberRemove || l.Type == team.TypeMachineRemove {
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

// linkText describes a link for people. seen collects the environments
// earlier links created.
func linkText(st *team.State, l team.Link, seen map[string]bool) string {
	switch l.Type {
	case team.TypeInit:
		var b team.InitBody
		_ = json.Unmarshal(l.Body, &b)
		names := make([]string, 0, len(b.Envs))
		for _, e := range b.Envs {
			seen[e.Name] = true
			names = append(names, e.Name)
		}
		return "created the shared project with " + envList(names)
	case team.TypeMemberAdd:
		var b team.MemberAddBody
		_ = json.Unmarshal(l.Body, &b)
		if b.Admin {
			return "added " + b.Member.Login + " as an admin"
		}
		return "added " + b.Member.Login + ", who reads " + envList(b.Envs)
	case team.TypeMemberUpdate:
		var b team.MemberUpdateBody
		_ = json.Unmarshal(l.Body, &b)
		who := loginOf(st, b.User)
		if b.Admin {
			return "made " + who + " an admin"
		}
		return "changed " + who + " to read " + envList(b.Envs)
	case team.TypeMemberRemove:
		var b team.MemberRemoveBody
		_ = json.Unmarshal(l.Body, &b)
		if b.User == l.Signer {
			return "left the project"
		}
		return "removed " + loginOf(st, b.User)
	case team.TypeEnvSet:
		var b team.EnvSetBody
		_ = json.Unmarshal(l.Body, &b)
		if seen[b.Env.Name] {
			return "gave " + b.Env.Name + " a new key"
		}
		seen[b.Env.Name] = true
		return "added the environment " + b.Env.Name
	case team.TypeMachineAdd:
		var b team.MachineAddBody
		_ = json.Unmarshal(l.Body, &b)
		return "added the machine " + b.Machine.Name + ", which reads " + envList(b.Envs)
	case team.TypeMachineRemove:
		var b team.MachineRemoveBody
		_ = json.Unmarshal(l.Body, &b)
		if m := st.Machines[b.ID]; m != nil {
			return "removed the machine " + m.Name
		}
		return "removed a machine"
	case team.TypeGroupSet:
		var b team.GroupSetBody
		_ = json.Unmarshal(l.Body, &b)
		if len(b.Envs) == 0 {
			return "took away the machine group " + b.Group + "'s access"
		}
		return "let the machine group " + b.Group + " read " + envList(b.Envs)
	}
	return l.Type
}
