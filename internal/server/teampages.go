package server

import (
	"context"
	"encoding/json"
	"html/template"
	"net/http"
	"slices"
	"strings"
	"time"

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
			out = append(out, notice{Level: "info", Text: id + ": " + plural(missing, "key") + " still have to be sent to members or machines. Any admin's device sends them on its next sync.", Command: "esec vault team sync", Link: link, LinkTo: "Open project"})
		}
		if waitingMine > 0 {
			out = append(out, notice{Level: "info", Text: id + ": " + plural(waitingMine, "key") + " wait for your devices. A signed-in device with the background service picks them up by itself.", Command: "esec vault team sync", Link: link, LinkTo: "Open project"})
		}
	}
	return out, nil
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
	project := r.PathValue("org") + "/" + r.PathValue("repo")
	if team.ValidProject(project) != nil {
		s.webError(w, http.StatusNotFound, "There is no such project.")
		return
	}
	ctx := r.Context()
	st, _, err := s.db.projectState(ctx, s.db.sql, project)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	member := false
	if st != nil {
		_, member = st.Member(ws.user.ID)
	}
	if st == nil || (!member && !s.cfg.Admin(ws.user.GitHubID)) {
		s.webError(w, http.StatusNotFound, "There is no such project, or you are not a member of it.")
		return
	}
	nav := "projects"
	if !member {
		nav = "admin"
	}
	data := s.page(ws, nav)
	if err := s.teamPage(ctx, st, data); err != nil {
		s.internalError(w, r, err)
		return
	}
	data["Member"] = member
	data["MyAdmin"] = st.Admin(ws.user.ID)
	data["MyAccess"] = st.Access(ws.user.ID)
	s.render(w, http.StatusOK, "team.html", data)
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
		envs = append(envs, v)
	}
	activity, err := s.teamActivity(ctx, st)
	if err != nil {
		return err
	}
	data["Project"] = st.Project
	data["State"] = st
	data["Members"] = memberViews
	data["Machines"] = machineViews
	data["Envs"] = envs
	data["Rotations"] = st.Rotations()
	data["History"] = teamHistoryOf(st)
	data["Activity"] = activity
	data["Created"] = st.Links[0].CTime
	data["Creator"] = loginOf(st, st.Links[0].Signer)
	return nil
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
	}
	return l.Type
}
