package server

// Access across projects: who reads what in every shared project the viewer
// is a member of, directly or through a group, what needs doing about it,
// and one page per person, with offboarding: proposing (or, with the
// server's signature, making) every removal the viewer may sign.

import (
	"context"
	"net/http"
	"sort"
	"strings"

	"github.com/mscno/esec-vault/internal/team"
	"github.com/mscno/esec-vault/internal/wire"
)

// accessRead is what one person reads of one project, directly or through
// a group (Via).
type accessRead struct {
	Project string
	Envs    []string
	Admin   bool
	Via     string
	// CanRemove says the viewer administers where this access comes from:
	// the project, or the group.
	CanRemove bool
}

// accessPerson is everyone the viewer can see reading something.
type accessPerson struct {
	Login string
	User  string
	Reads []accessRead
	// Groups lists the groups they are a member of; AdminOf those they
	// administer.
	Groups, AdminOf []string
}

// Summary is one line of what they read.
func (p *accessPerson) Summary() string {
	parts := make([]string, 0, len(p.Reads))
	for _, r := range p.Reads {
		what := strings.Join(r.Envs, ", ")
		if r.Admin {
			what = "admin"
		}
		if what == "" {
			what = "nothing"
		}
		s := r.Project + ": " + what
		if r.Via != "" {
			s += " (through " + r.Via + ")"
		}
		parts = append(parts, s)
	}
	return strings.Join(parts, "; ")
}

// accessView collects who reads what across the projects and groups viewer
// can see.
func (s *Server) accessView(ctx context.Context, viewer string) ([]*accessPerson, error) {
	people := map[string]*accessPerson{}
	get := func(user, login string) *accessPerson {
		p, ok := people[user]
		if !ok {
			p = &accessPerson{User: user, Login: login}
			people[user] = p
		}
		return p
	}
	projects, err := s.db.memberProjects(ctx, viewer)
	if err != nil {
		return nil, err
	}
	groups := map[string]*team.GroupState{}
	group := func(id string) *team.GroupState {
		if gs, ok := groups[id]; ok {
			return gs
		}
		gs, err := s.listedGroup(ctx, id)
		if err != nil {
			gs = nil
		}
		groups[id] = gs
		return gs
	}
	for _, id := range projects {
		st, err := s.listedProject(ctx, id)
		if err != nil {
			return nil, err
		}
		if st != nil {
			projectReads(st, viewer, get, group)
		}
	}
	visible, err := s.db.visibleGroups(ctx, viewer)
	if err != nil {
		return nil, err
	}
	for _, id := range visible {
		gs := group(id)
		if gs == nil {
			continue
		}
		for _, m := range gs.ActiveMembers() {
			p := get(m.User, m.Login)
			p.Groups = append(p.Groups, id)
		}
		for _, a := range gs.ActiveAdmins() {
			p := get(a.User, a.Login)
			p.AdminOf = append(p.AdminOf, id)
		}
	}
	out := make([]*accessPerson, 0, len(people))
	for _, p := range people {
		sort.Slice(p.Reads, func(i, j int) bool {
			if p.Reads[i].Project != p.Reads[j].Project {
				return p.Reads[i].Project < p.Reads[j].Project
			}
			return p.Reads[i].Via < p.Reads[j].Via
		})
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i].Login) < strings.ToLower(out[j].Login) })
	return out, nil
}

// projectReads adds who reads what of st, directly and through groups.
func projectReads(st *team.State, viewer string, get func(user, login string) *accessPerson, group func(id string) *team.GroupState) {
	admin := st.Admin(viewer)
	for _, m := range st.ActiveMembers() {
		p := get(m.User, m.Login)
		p.Reads = append(p.Reads, accessRead{Project: st.Project, Envs: st.Access(m.User), Admin: m.Admin, CanRemove: admin && !m.Admin})
	}
	for _, pg := range st.ActiveGroups() {
		gs := group(pg.Group)
		if gs == nil || gs.Root() != pg.Root {
			continue
		}
		if _, trusted := gs.Access[st.Project]; !trusted {
			continue
		}
		for _, m := range gs.ActiveMembers() {
			p := get(m.User, m.Login)
			p.Reads = append(p.Reads, accessRead{Project: st.Project, Envs: pg.Envs, Via: pg.Group, CanRemove: gs.Admin(viewer)})
		}
	}
}

// webAccess is the access overview: what needs doing, then everyone and
// what they read.
func (s *Server) webAccess(w http.ResponseWriter, r *http.Request) {
	ws := s.requireWeb(w, r)
	if ws == nil {
		return
	}
	data, err := s.accessPageData(r.Context(), ws)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	s.render(w, http.StatusOK, "access.html", data)
}

func (s *Server) accessPageData(ctx context.Context, ws *webSession) (map[string]any, error) {
	people, err := s.accessView(ctx, ws.user.ID)
	if err != nil {
		return nil, err
	}
	notices, err := s.teamNotices(ctx, ws.user.ID)
	if err != nil {
		return nil, err
	}
	gnotices, err := s.groupNotices(ctx, ws.user.ID)
	if err != nil {
		return nil, err
	}
	rnotices, err := s.requestNotices(ctx, ws.user.ID)
	if err != nil {
		return nil, err
	}
	mine, err := s.requestsWhere(ctx, `r.user_id = ?`, ws.user.ID)
	if err != nil {
		return nil, err
	}
	data := s.page(ws, "access")
	data["People"] = people
	data["Notices"] = append(append(rnotices, notices...), gnotices...)
	data["MyRequests"] = mine
	return data, nil
}

// webPerson shows what one person reads, and offers to offboard them.
func (s *Server) webPerson(w http.ResponseWriter, r *http.Request) {
	ws := s.requireWeb(w, r)
	if ws == nil {
		return
	}
	data, err := s.personPageData(r.Context(), ws, r.PathValue("login"))
	if err != nil {
		s.webFail(w, r, err)
		return
	}
	s.render(w, http.StatusOK, "person.html", data)
}

func (s *Server) personPageData(ctx context.Context, ws *webSession, login string) (map[string]any, error) {
	if team.ValidLogin(login) != nil {
		return nil, clientErr(http.StatusNotFound, wire.ErrNotFound, "That is not a GitHub login.")
	}
	p, err := s.findPerson(ctx, ws.user.ID, login)
	if err != nil {
		return nil, err
	}
	removable := 0
	for _, r := range p.Reads {
		if r.CanRemove {
			removable++
		}
	}
	data := s.page(ws, "access")
	data["Person"] = p
	data["Removable"] = removable
	data["Command"] = "esec vault access offboard " + p.Login
	return data, nil
}

// webOffboard takes a person out of every project and group the viewer
// administers: each removal is signed by the server when the viewer lets
// it, and otherwise proposed for a passkey or device to sign. A group
// member stops getting keys at once either way.
func (s *Server) webOffboard(w http.ResponseWriter, r *http.Request) {
	login := r.PathValue("login")
	s.pageForm(w, r, "/people/"+login, func(ctx context.Context, ws *webSession) (string, error) {
		if team.ValidLogin(login) != nil {
			return "", clientErr(http.StatusNotFound, wire.ErrNotFound, "That is not a GitHub login.")
		}
		p, err := s.findPerson(ctx, ws.user.ID, login)
		if err != nil {
			return "", err
		}
		res, err := s.offboard(ctx, ws.user.ID, s.clientIP(r), p)
		if err != nil {
			return "", err
		}
		return res.message(), nil
	}, func(ctx context.Context, ws *webSession) (map[string]any, []string, error) {
		data, err := s.personPageData(ctx, ws, login)
		if err != nil {
			// Nothing of theirs is left to show.
			data = s.page(ws, "access")
		}
		return data, []string{"person-reads"}, nil
	})
}

// findPerson finds what login reads among what viewer can see.
func (s *Server) findPerson(ctx context.Context, viewer, login string) (*accessPerson, error) {
	people, err := s.accessView(ctx, viewer)
	if err != nil {
		return nil, err
	}
	for _, x := range people {
		if strings.EqualFold(x.Login, login) {
			return x, nil
		}
	}
	return nil, clientErr(http.StatusNotFound, wire.ErrNotFound, "%s reads nothing you can see.", login)
}

// offboardResult says where an offboarding removed someone.
type offboardResult struct {
	signed, proposed, left []string
}

func (o *offboardResult) message() string {
	var msg []string
	if len(o.signed) > 0 {
		msg = append(msg, "Removed, signed by the server for you: "+strings.Join(o.signed, ", ")+".")
	}
	if len(o.proposed) > 0 {
		msg = append(msg, "Proposed (sign them with your passkey on the Changes page, or on a device: esec vault changes): "+strings.Join(o.proposed, ", ")+".")
	}
	if len(o.left) > 0 {
		msg = append(msg, "Not yours to remove (an admin there does it, or they are an admin): "+strings.Join(o.left, ", ")+".")
	}
	if len(msg) == 0 {
		return "Nothing of theirs is yours to remove."
	}
	return strings.Join(msg, " ") + " Then rotate what they could read; the projects' pages list it."
}

// offboard removes p from everything viewer administers.
func (s *Server) offboard(ctx context.Context, viewer, ip string, p *accessPerson) (*offboardResult, error) {
	out := &offboardResult{}
	done := map[string]bool{}
	for _, rd := range p.Reads {
		target, scope := rd.Project, wire.ScopeProject
		if rd.Via != "" {
			target, scope = rd.Via, wire.ScopeGroup
		}
		if done[scope+"|"+target] {
			continue
		}
		done[scope+"|"+target] = true
		if !rd.CanRemove {
			out.left = append(out.left, target)
			continue
		}
		if err := s.removeFrom(ctx, viewer, ip, p, scope, target, out); err != nil {
			return nil, err
		}
	}
	// Groups they are in that read none of the viewer's projects.
	for _, g := range p.Groups {
		if done[wire.ScopeGroup+"|"+g] {
			continue
		}
		gs, err := s.listedGroup(ctx, g)
		if err != nil || gs == nil || !gs.Admin(viewer) {
			continue
		}
		if err := s.removeFrom(ctx, viewer, ip, p, wire.ScopeGroup, g, out); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// removeFrom signs, or proposes, removing p from a project or group. A
// group stops giving a member keys at once.
func (s *Server) removeFrom(ctx context.Context, viewer, ip string, p *accessPerson, scope, target string, out *offboardResult) error {
	c := wire.Change{Scope: scope, Target: target, Kind: wire.ChangeMemberRemove, Subject: p.Login}
	ok, err := s.serverSigns(ctx, viewer, ip, c)
	if err != nil {
		return err
	}
	if ok {
		out.signed = append(out.signed, target)
		return nil
	}
	if scope == wire.ScopeGroup {
		if _, err := s.db.sql.ExecContext(ctx, `UPDATE group_members SET suspended_at = ? WHERE group_id = ? AND user_id = ? AND suspended_at = 0`, s.now().Unix(), target, p.User); err != nil {
			return err
		}
	}
	if err := s.propose(ctx, viewer, ip, c); err != nil {
		return err
	}
	out.proposed = append(out.proposed, target)
	return nil
}
