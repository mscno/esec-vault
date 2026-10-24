package server

// The organisation pages: an overview of what needs doing, its people,
// the workloads of its groups, and its settings (approved KMS keys and
// rules). The server holds no key to sign with, so every form proposes a
// change; an admin's device signs it (a dialog of the background service,
// or esec vault changes), or a passkey where its scope allows. Forms that
// only take access away are signed by the server at once for people who
// let it, unless the organisation forbids that.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/mscno/esec-vault/internal/kms"
	"github.com/mscno/esec-vault/internal/team"
	"github.com/mscno/esec-vault/internal/wire"
)

// The tabs of an organisation's pages.
const (
	orgTabOverview  = "overview"
	orgTabPeople    = "people"
	orgTabWorkloads = "workloads"
	orgTabSettings  = "settings"
)

// orgPersonView is someone in an organisation.
type orgPersonView struct {
	Login    string
	User     string
	Admin    bool
	Verified string
	AddedBy  string
	Added    time.Time
	// Reads lists what they read in the organisation's projects and
	// groups.
	Reads []string
}

// orgFormerView is someone who left, with where they still read.
type orgFormerView struct {
	Login   string
	Left    time.Time
	StillIn []orgStillIn
}

// orgStillIn is a project or group someone who left is still in, and the
// admins whose devices take them out.
type orgStillIn struct {
	ID     string
	Group  bool
	Admins []string
}

// orgKMSView is an approved key.
type orgKMSView struct {
	*team.OrgKMSState

	Default     bool
	Users       int
	Fingerprint string
	AddedBy     string
}

// orgWorkloadView is a workload of one of the organisation's groups.
type orgWorkloadView struct {
	Group      string
	ID         string
	Name       string
	Runs       string
	FlyApp     string
	KMS        *kms.Key
	KMSName    string
	KeyProblem string
	Reads      []string
	LastUsed   time.Time
	Uses       int
	Suspended  bool
	Descriptor string
	CanAdmin   bool
	Rekeying   string
}

// orgChangeView is a change waiting to be signed, and whether a passkey may.
type orgChangeView struct {
	wire.Change

	Text    string
	Passkey bool
}

// orgProjectView is a project of the organisation the viewer administers,
// for the Fly.io app form.
type orgProjectView struct {
	ID   string
	Envs []string
}

func orgTabPath(org, tab string) string {
	if tab == orgTabOverview {
		return "/orgs/" + org
	}
	return "/orgs/" + org + "/" + tab
}

func (s *Server) webOrgTab(tab string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ws := s.requireWeb(w, r)
		if ws == nil {
			return
		}
		data, err := s.orgPageData(r.Context(), ws, r.PathValue("org"), tab)
		if err != nil {
			s.webFail(w, r, err)
			return
		}
		s.render(w, http.StatusOK, "org.html", data)
	}
}

func (s *Server) orgPageData(ctx context.Context, ws *webSession, org, tab string) (map[string]any, error) { //nolint:gocyclo // gathers each section in turn
	org = strings.ToLower(org)
	if team.ValidOrg(org) != nil {
		return nil, clientErr(http.StatusNotFound, wire.ErrNotFound, "That is not an organisation name.")
	}
	viewer := ws.user.ID
	in := func(id string) bool { return team.OrgOf(id) == org }
	teams, err := s.teamSummaries(ctx, viewer)
	if err != nil {
		return nil, err
	}
	teams = slices.DeleteFunc(teams, func(t teamSummary) bool { return !in(t.ID) })
	groups, err := s.groupSummaries(ctx, viewer)
	if err != nil {
		return nil, err
	}
	groups = slices.DeleteFunc(groups, func(g groupSummary) bool { return !in(g.ID) })
	os, _, err := s.db.orgState(ctx, s.db.sql, org)
	if err != nil {
		return nil, err
	}
	serverAdmin := s.cfg.Admin(ws.user.GitHubID)
	inOrg := os != nil && os.In(viewer)
	if os != nil && !inOrg && len(teams)+len(groups) == 0 && !serverAdmin {
		return nil, clientErr(http.StatusNotFound, wire.ErrNotFound, "You are not in %s, nor in any of its projects or groups.", org)
	}
	people, err := s.accessView(ctx, viewer)
	if err != nil {
		return nil, err
	}
	var mine []*accessPerson
	for _, p := range people {
		q := *p
		q.Reads = slices.DeleteFunc(slices.Clone(p.Reads), func(rd accessRead) bool { return !in(rd.Project) })
		q.Groups = slices.DeleteFunc(slices.Clone(p.Groups), func(g string) bool { return !in(g) })
		q.AdminOf = slices.DeleteFunc(slices.Clone(p.AdminOf), func(g string) bool { return !in(g) })
		if len(q.Reads)+len(q.Groups)+len(q.AdminOf) > 0 {
			mine = append(mine, &q)
		}
	}
	policy, err := s.orgPolicy(ctx, s.db.sql, org)
	if err != nil {
		return nil, err
	}
	serverPol, err := s.serverPolicy(ctx, s.db.sql, org)
	if err != nil {
		return nil, err
	}
	logins, err := s.db.logins(ctx)
	if err != nil {
		return nil, err
	}
	data := s.page(ws, "orgs")
	data["Org"] = org
	data["Tab"] = tab
	data["Teams"] = teams
	data["Groups"] = groups
	data["People"] = mine
	data["Policy"] = policy
	data["ServerPolicy"] = serverPol
	data["PolicyBy"] = logins[serverPol.UpdatedBy]
	data["CanSetPolicy"] = serverAdmin
	data["Chain"] = os
	if os == nil {
		data["CanClaim"], data["ClaimWhy"] = s.canClaim(ctx, org, viewer, serverAdmin)
		data["Claiming"], err = s.claiming(ctx, org, viewer)
		return data, err
	}
	data["Words"] = os.Words()
	// Who is in it, its keys and what waits are for its people to see;
	// the members of one of its projects see their projects and groups.
	data["Inside"] = inOrg || serverAdmin
	if !inOrg && !serverAdmin {
		data["Chain"], data["Outside"] = nil, true
		return data, nil
	}
	data["MyAdmin"] = os.Admin(viewer)
	data["MyMember"] = os.Member(viewer)
	data["Admins"] = os.ActiveAdmins()
	data["Settings"] = os.Settings
	data["SettingsBy"] = logins[os.SettingsBy]
	data["SettingsTime"] = os.SettingsTime
	data["Created"] = os.Links[0].CTime
	data["Creator"] = logins[os.Links[0].Signer]
	data["PeopleCount"] = len(os.People())
	// What each person reads costs a look at every project and group: only
	// the People tab (and the export) shows it.
	if tab == orgTabPeople {
		if data["Roster"], err = s.orgRoster(ctx, os, logins); err != nil {
			return nil, err
		}
	}
	if data["Former"], err = s.orgFormer(ctx, os, logins); err != nil {
		return nil, err
	}
	workloads, err := s.orgWorkloads(ctx, os, viewer, inOrg || serverAdmin)
	if err != nil {
		return nil, err
	}
	data["Workloads"] = workloads
	data["KMS"] = orgKMSViews(os, workloads, logins)
	changes, err := s.orgChanges(ctx, os)
	if err != nil {
		return nil, err
	}
	data["Changes"] = changes
	var problems int
	for _, wl := range workloads {
		if wl.KeyProblem != "" {
			problems++
		}
	}
	data["KeyProblems"] = problems
	if data["MyProjects"], err = s.orgAdminProjects(ctx, org, viewer); err != nil {
		return nil, err
	}
	var myGroups []string
	for _, g := range groups {
		if g.Admin {
			myGroups = append(myGroups, g.ID)
		}
	}
	data["MyGroups"] = myGroups
	s.addPasskeys(ctx, ws, data)
	return data, nil
}

// canClaim says whether viewer may set up org, and if not, why.
func (s *Server) canClaim(ctx context.Context, org, viewer string, serverAdmin bool) (bool, string) {
	err := s.db.tx(ctx, func(tx *sql.Tx) error { return s.checkClaim(ctx, tx, org, viewer, serverAdmin) })
	if err == nil {
		return true, ""
	}
	var ae *apiError
	if errors.As(err, &ae) {
		return false, ae.desc
	}
	return false, "The server could not check that; try again."
}

// claiming reports whether viewer asked to set up org already.
func (s *Server) claiming(ctx context.Context, org, viewer string) (bool, error) {
	cs, err := s.db.openChanges(ctx, wire.ScopeAccount, viewer)
	if err != nil {
		return false, err
	}
	for _, c := range cs {
		if c.Kind == wire.ChangeOrgCreate && c.Subject == org {
			return true, nil
		}
	}
	return false, nil
}

// orgRoster lists the people of os with what they read in it.
func (s *Server) orgRoster(ctx context.Context, os *team.OrgState, logins map[string]string) ([]orgPersonView, error) {
	projects, groups, err := s.db.orgIDs(ctx, s.db.sql, os.Org)
	if err != nil {
		return nil, err
	}
	reads := map[string][]string{}
	for _, p := range projects {
		st, err := s.listedProject(ctx, p)
		if err != nil || st == nil || st.Archived {
			continue
		}
		for _, m := range st.ActiveMembers() {
			what := p + ": admin"
			if !m.Admin {
				what = p + ": " + strings.Join(st.Access(m.User), ", ")
			}
			reads[m.User] = append(reads[m.User], what)
		}
	}
	for _, g := range groups {
		gs, err := s.listedGroup(ctx, g)
		if err != nil || gs == nil {
			continue
		}
		for _, p := range gs.KeyHolders() {
			role := "member of " + g
			if gs.Admin(p.User) {
				role = "admin of " + g
			}
			reads[p.User] = append(reads[p.User], role)
		}
	}
	var out []orgPersonView
	for _, p := range os.People() {
		v := orgPersonView{Login: p.Login, User: p.User, Admin: os.Admin(p.User), Verified: p.Verified, AddedBy: logins[p.AddedBy], Reads: reads[p.User]}
		if p.AddedSeq > 0 {
			v.Added = os.Links[p.AddedSeq-1].CTime
		}
		out = append(out, v)
	}
	return out, nil
}

// orgFormer lists the people who left os and still read something of it,
// added before they left, with the admins whose devices take them out.
func (s *Server) orgFormer(ctx context.Context, os *team.OrgState, logins map[string]string) ([]orgFormerView, error) { //nolint:gocyclo // projects, then groups, for each person
	former := os.Former()
	if len(former) == 0 {
		return nil, nil
	}
	projects, groups, err := s.db.orgIDs(ctx, s.db.sql, os.Org)
	if err != nil {
		return nil, err
	}
	var out []orgFormerView
	for _, f := range former {
		left, _ := os.Left(f.User)
		v := orgFormerView{Login: f.Login, Left: left}
		for _, p := range projects {
			st, err := s.listedProject(ctx, p)
			if err != nil || st == nil || st.Archived {
				continue
			}
			m, ok := st.Member(f.User)
			if !ok || m.AddedSeq == 0 || st.Links[m.AddedSeq-1].CTime.After(left) {
				continue
			}
			var admins []string
			for _, a := range adminIDs(st) {
				if a != f.User {
					admins = append(admins, logins[a])
				}
			}
			v.StillIn = append(v.StillIn, orgStillIn{ID: p, Admins: admins})
		}
		for _, g := range groups {
			gs, err := s.listedGroup(ctx, g)
			if err != nil || gs == nil {
				continue
			}
			p, ok := gs.Person(f.User)
			if !ok || p.AddedSeq == 0 || gs.Links[p.AddedSeq-1].CTime.After(left) {
				continue
			}
			var admins []string
			for _, a := range gs.ActiveAdmins() {
				if a.User != f.User {
					admins = append(admins, a.Login)
				}
			}
			v.StillIn = append(v.StillIn, orgStillIn{ID: g, Group: true, Admins: admins})
		}
		if len(v.StillIn) > 0 {
			out = append(out, v)
		}
	}
	return out, nil
}

// orgWorkloads lists the workloads of os's groups: all of them for its
// people, otherwise those of groups viewer may read.
func (s *Server) orgWorkloads(ctx context.Context, os *team.OrgState, viewer string, all bool) ([]orgWorkloadView, error) { //nolint:gocyclo // one pass over each group's workloads
	_, groups, err := s.db.orgIDs(ctx, s.db.sql, os.Org)
	if err != nil {
		return nil, err
	}
	rekeys, err := s.db.changesWhere(ctx, `scope = ? AND kind = ? AND status = 'open'`, wire.ScopeGroup, wire.ChangeWorkloadRekey)
	if err != nil {
		return nil, err
	}
	var out []orgWorkloadView
	for _, g := range groups {
		gs, err := s.listedGroup(ctx, g)
		if err != nil || gs == nil {
			continue
		}
		creds := gs.ActiveCreds(team.KindWorkload)
		if len(creds) == 0 {
			continue
		}
		if !all {
			ok, err := s.db.canReadGroup(ctx, viewer, g)
			if err != nil {
				return nil, err
			}
			if !ok {
				continue
			}
		}
		rows, err := s.db.credRows(ctx, g)
		if err != nil {
			return nil, err
		}
		reads, err := s.groupReads(ctx, gs)
		if err != nil {
			return nil, err
		}
		for _, c := range creds {
			r := rows[c.ID]
			v := orgWorkloadView{Group: g, ID: c.ID, Name: c.Name, Runs: c.OIDC.Describe(), KMS: c.KMS, Reads: reads, LastUsed: r.LastUsed, Uses: r.Uses, Suspended: !r.Suspended.IsZero(), CanAdmin: gs.Admin(viewer)}
			v.Descriptor = (&team.WorkloadRef{Server: s.cfg.BaseURL, Group: g, Root: gs.Root(), ID: c.ID}).String()
			if c.OIDC != nil && c.OIDC.Provider == team.ProviderFly && len(c.OIDC.FlyApps) == 1 {
				v.FlyApp = c.OIDC.FlyOrg + "/" + c.OIDC.FlyApps[0]
			}
			if c.KMS != nil {
				if a := os.KMSFor(*c.KMS); a != nil {
					v.KMSName = a.Name
				}
				if err := os.CheckKMS(*c.KMS, g); err != nil {
					v.KeyProblem = err.Error()
				}
			}
			for _, ch := range rekeys {
				if ch.Target == g && ch.Subject == c.ID {
					var d struct {
						KMS string `json:"kms"`
					}
					_ = json.Unmarshal(ch.Data, &d)
					v.Rekeying = d.KMS
				}
			}
			out = append(out, v)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Group != out[j].Group {
			return out[i].Group < out[j].Group
		}
		return out[i].Name < out[j].Name
	})
	return out, nil
}

// groupReads lists what a group reads, as "project envs": what projects
// grant it, of those it takes keys from.
func (s *Server) groupReads(ctx context.Context, gs *team.GroupState) ([]string, error) {
	var out []string
	for _, p := range gs.Projects() {
		st, err := s.listedProject(ctx, p)
		if err != nil {
			return nil, err
		}
		if st == nil || st.Root() != gs.Access[p] {
			continue
		}
		if pg, ok := st.Group(gs.Group); ok && pg.Root == gs.Root() && len(pg.Envs) > 0 {
			out = append(out, p+" "+strings.Join(pg.Envs, ", "))
		}
	}
	return out, nil
}

func orgKMSViews(os *team.OrgState, workloads []orgWorkloadView, logins map[string]string) []orgKMSView {
	keys := os.ActiveKMS()
	out := make([]orgKMSView, 0, len(keys))
	for _, k := range keys {
		v := orgKMSView{OrgKMSState: k, Default: k.Name == os.Settings.DefaultKMS, Fingerprint: strings.TrimPrefix(k.Key.Fingerprint(), "kms:")[:16], AddedBy: logins[k.AddedBy]}
		for _, w := range workloads {
			if w.KMS != nil && w.KMS.Fingerprint() == k.Key.Fingerprint() {
				v.Users++
			}
		}
		out = append(out, v)
	}
	return out
}

// orgChanges lists the changes to os waiting to be signed: its own, and
// workloads of its groups moving to another key.
func (s *Server) orgChanges(ctx context.Context, os *team.OrgState) ([]orgChangeView, error) {
	cs, err := s.db.openChanges(ctx, wire.ScopeOrg, os.Org)
	if err != nil {
		return nil, err
	}
	rekeys, err := s.db.changesWhere(ctx, `scope = ? AND kind = ? AND status = 'open'`, wire.ScopeGroup, wire.ChangeWorkloadRekey)
	if err != nil {
		return nil, err
	}
	for _, c := range rekeys {
		if team.OrgOf(c.Target) == os.Org {
			cs = append(cs, c)
		}
	}
	out := make([]orgChangeView, 0, len(cs))
	for _, c := range cs {
		v := orgChangeView{Change: c, Text: orgChangeText(c)}
		switch c.Kind {
		case wire.ChangeOrgAdd:
			v.Passkey = !c.Admin
		case wire.ChangeOrgRemove:
			v.Passkey = !c.Admin
		case wire.ChangeOrgKMSRemove:
			v.Passkey = true
		}
		out = append(out, v)
	}
	return out, nil
}

// orgChangeText says what a change does, for the pages.
func orgChangeText(c wire.Change) string {
	switch c.Kind {
	case wire.ChangeOrgAdd:
		if c.Admin {
			return "make " + c.Subject + " an admin"
		}
		return "add " + c.Subject
	case wire.ChangeOrgRemove:
		return "remove " + c.Subject + ", and take them out of every project and group of " + c.Target
	case wire.ChangeOrgKMSAdd:
		var req wire.KMSKeyRequest
		_ = json.Unmarshal(c.Data, &req)
		return fmt.Sprintf("approve the KMS key %s (%s %s)", req.Name, req.Provider, req.Key)
	case wire.ChangeOrgKMSRemove:
		return "withdraw the KMS key " + c.Subject
	case wire.ChangeOrgSettings:
		return "change the rules and defaults"
	case wire.ChangeFlyApp:
		var app wire.FlyApp
		_ = json.Unmarshal(c.Data, &app)
		var reads []string
		for _, r := range app.Reads {
			reads = append(reads, r.Project+" "+strings.Join(r.Envs, ","))
		}
		return fmt.Sprintf("set up the Fly.io app %s in %s, reading %s, wrapped with %s", app.App, app.Group, orNone(reads), app.KMS)
	case wire.ChangeWorkloadRekey:
		var d struct {
			KMS string `json:"kms"`
		}
		_ = json.Unmarshal(c.Data, &d)
		return fmt.Sprintf("move the workload %s of %s to the key %s", c.Subject, c.Target, d.KMS)
	}
	return c.Kind
}

func orNone(list []string) string {
	if len(list) == 0 {
		return "nothing yet"
	}
	return strings.Join(list, "; ")
}

// orgAdminProjects lists the projects of org viewer administers, with
// their environments.
func (s *Server) orgAdminProjects(ctx context.Context, org, viewer string) ([]orgProjectView, error) {
	ids, err := s.db.memberProjects(ctx, viewer)
	if err != nil {
		return nil, err
	}
	var out []orgProjectView
	for _, id := range ids {
		if team.OrgOf(id) != org {
			continue
		}
		st, err := s.listedProject(ctx, id)
		if err != nil || st == nil || st.Archived || !st.Admin(viewer) {
			continue
		}
		out = append(out, orgProjectView{ID: id, Envs: st.EnvNames()})
	}
	return out, nil
}

// ---- forms ----

// orgParts are the fragments of the organisation pages a form refreshes.
var orgParts = []string{"org-alerts", "org-body"}

// orgForm runs fn for a form of an organisation's page, with its verified
// chain (nil when it has none), and refreshes the page.
func (s *Server) orgForm(w http.ResponseWriter, r *http.Request, tab string, fn func(ctx context.Context, ws *webSession, org string, os *team.OrgState) (string, error)) {
	org := strings.ToLower(r.PathValue("org"))
	s.pageForm(w, r, orgTabPath(org, tab), func(ctx context.Context, ws *webSession) (string, error) {
		if team.ValidOrg(org) != nil {
			return "", clientErr(http.StatusNotFound, wire.ErrNotFound, "That is not an organisation name.")
		}
		os, _, err := s.db.orgState(ctx, s.db.sql, org)
		if err != nil {
			return "", err
		}
		return fn(ctx, ws, org, os)
	}, func(ctx context.Context, ws *webSession) (map[string]any, []string, error) {
		data, err := s.orgPageData(ctx, ws, org, tab)
		return data, orgParts, err
	})
}

// requireOrgAdmin refuses a form of someone who is not an admin of os.
func requireOrgAdmin(os *team.OrgState, ws *webSession, org string) error {
	if os == nil {
		return clientErr(http.StatusNotFound, wire.ErrNotFound, "%s is not set up as an organisation yet.", org)
	}
	if !os.Admin(ws.user.ID) {
		return clientErr(http.StatusForbidden, wire.ErrForbidden, "Only an admin of %s can change it.", org)
	}
	return nil
}

const signOnDevice = "Sign it on your device: your background service asks you in a dialog, or run esec vault changes."

func (s *Server) webOrgClaim(w http.ResponseWriter, r *http.Request) {
	s.orgForm(w, r, orgTabOverview, func(ctx context.Context, ws *webSession, org string, os *team.OrgState) (string, error) {
		if os != nil {
			return "", clientErr(http.StatusConflict, wire.ErrConflict, "%s is set up already.", org)
		}
		if ok, why := s.canClaim(ctx, org, ws.user.ID, s.cfg.Admin(ws.user.GitHubID)); !ok {
			return "", clientErr(http.StatusForbidden, wire.ErrForbidden, "%s", why)
		}
		c := wire.Change{Scope: wire.ScopeAccount, Target: ws.user.ID, Kind: wire.ChangeOrgCreate, Subject: org}
		return "Asked to set up " + org + ". " + signOnDevice, s.propose(ctx, ws.user.ID, s.clientIP(r), c)
	})
}

func (s *Server) webOrgAddPerson(w http.ResponseWriter, r *http.Request) {
	s.orgForm(w, r, orgTabPeople, func(ctx context.Context, ws *webSession, org string, os *team.OrgState) (string, error) {
		if err := requireOrgAdmin(os, ws, org); err != nil {
			return "", err
		}
		login := strings.TrimSpace(r.PostForm.Get("login"))
		if team.ValidLogin(login) != nil {
			return "", clientErr(http.StatusBadRequest, wire.ErrInvalidRequest, "That is not a GitHub login.")
		}
		admin := r.PostForm.Get("role") == "admin"
		p, err := s.personByLogin(ctx, login)
		if err != nil {
			return "", err
		}
		if os.Admin(p.User) || (!admin && os.Member(p.User)) {
			return "", clientErr(http.StatusConflict, wire.ErrConflict, "%s is in %s already.", login, org)
		}
		c := wire.Change{Scope: wire.ScopeOrg, Target: org, Kind: wire.ChangeOrgAdd, Subject: p.Login, Admin: admin}
		if err := s.propose(ctx, ws.user.ID, s.clientIP(r), c); err != nil {
			return "", err
		}
		if admin {
			return "Asked to make " + p.Login + " an admin. " + signOnDevice, nil
		}
		return "Asked to add " + p.Login + ". Sign it with your passkey (Changes below), or on your device.", nil
	})
}

func (s *Server) webOrgRemovePerson(w http.ResponseWriter, r *http.Request) {
	s.orgForm(w, r, orgTabPeople, func(ctx context.Context, ws *webSession, org string, os *team.OrgState) (string, error) {
		if err := requireOrgAdmin(os, ws, org); err != nil {
			return "", err
		}
		p, ok := os.PersonByLogin(r.PostForm.Get("login"))
		if !ok {
			return "", clientErr(http.StatusNotFound, wire.ErrNotFound, "They are not in %s.", org)
		}
		if p.User == ws.user.ID {
			return "", clientErr(http.StatusBadRequest, wire.ErrInvalidRequest, "To leave %s, run on your device: esec vault org remove %s %s", org, org, p.Login)
		}
		c := wire.Change{Scope: wire.ScopeOrg, Target: org, Kind: wire.ChangeOrgRemove, Subject: p.Login, Admin: os.Admin(p.User)}
		if !c.Admin {
			if done, err := s.serverSigns(ctx, ws.user.ID, s.clientIP(r), c); err != nil || done {
				return p.Login + " is removed from " + org + ", signed by the server for you. Their admins' devices now take them out of its projects and groups.", err
			}
		}
		if err := s.propose(ctx, ws.user.ID, s.clientIP(r), c); err != nil {
			return "", err
		}
		if c.Admin {
			return "Asked to remove the admin " + p.Login + ". " + signOnDevice, nil
		}
		return "Asked to remove " + p.Login + ". Sign it with your passkey (Changes below), or on your device; their admins' devices then take them out of everything of " + org + ".", nil
	})
}

func (s *Server) webOrgSettings(w http.ResponseWriter, r *http.Request) {
	s.orgForm(w, r, orgTabSettings, func(ctx context.Context, ws *webSession, org string, os *team.OrgState) (string, error) {
		if err := requireOrgAdmin(os, ws, org); err != nil {
			return "", err
		}
		num := func(name string) (int, error) {
			v := strings.TrimSpace(r.PostForm.Get(name))
			if v == "" {
				return 0, nil
			}
			n, err := strconv.Atoi(v)
			if err != nil || n < 0 || n > team.MaxOrgDays {
				return 0, clientErr(http.StatusBadRequest, wire.ErrInvalidRequest, "%s is a number from 0 to %d", strings.ReplaceAll(name, "_", " "), team.MaxOrgDays)
			}
			return n, nil
		}
		var st team.OrgSettings
		var err error
		if st.MaxTokenDays, err = num("max_token_days"); err != nil {
			return "", err
		}
		if st.ReviewDays, err = num("review_days"); err != nil {
			return "", err
		}
		st.MembersOnly = r.PostForm.Get("members_only") == "on"
		st.RequireGitHubProof = r.PostForm.Get("require_github_proof") == "on"
		st.NoServerSigning = r.PostForm.Get("no_server_signing") == "on"
		st.FlyOrg = strings.TrimSpace(r.PostForm.Get("fly_org"))
		st.DefaultKMS = r.PostForm.Get("default_kms")
		if err := os.CheckSettings(st); err != nil {
			return "", clientErr(http.StatusBadRequest, wire.ErrInvalidRequest, "%v", err)
		}
		if st == os.Settings {
			return "Nothing changed.", nil
		}
		raw, err := json.Marshal(st)
		if err != nil {
			return "", err
		}
		c := wire.Change{Scope: wire.ScopeOrg, Target: org, Kind: wire.ChangeOrgSettings, Subject: "settings", Data: raw}
		return "Asked to change the rules. " + signOnDevice, s.propose(ctx, ws.user.ID, s.clientIP(r), c)
	})
}

func (s *Server) webOrgKMSAdd(w http.ResponseWriter, r *http.Request) {
	s.orgForm(w, r, orgTabSettings, func(ctx context.Context, ws *webSession, org string, os *team.OrgState) (string, error) {
		if err := requireOrgAdmin(os, ws, org); err != nil {
			return "", err
		}
		f := func(name string) string { return strings.TrimSpace(r.PostForm.Get(name)) }
		req := wire.KMSKeyRequest{Name: f("name"), Provider: f("provider"), Key: f("key"), Audience: f("audience"), Principal: f("principal")}
		if err := team.ValidKMSLabel(req.Name); err != nil {
			return "", clientErr(http.StatusBadRequest, wire.ErrInvalidRequest, "%v", err)
		}
		if _, taken := os.KMSByName(req.Name); taken {
			return "", clientErr(http.StatusConflict, wire.ErrConflict, "%s has a key named %s already.", org, req.Name)
		}
		if err := (kms.Key{Provider: req.Provider, Name: req.Key, Audience: req.Audience, Principal: req.Principal}).ValidateNames(); err != nil {
			return "", clientErr(http.StatusBadRequest, wire.ErrInvalidRequest, "%v", err)
		}
		for _, g := range strings.FieldsFunc(f("groups"), func(r rune) bool { return r == ',' || r == ' ' }) {
			if team.ValidGroup(g) != nil || team.OrgOf(g) != org {
				return "", clientErr(http.StatusBadRequest, wire.ErrInvalidRequest, "%s is not a group of %s", g, org)
			}
			req.Groups = append(req.Groups, g)
		}
		slices.Sort(req.Groups)
		req.Groups = slices.Compact(req.Groups)
		raw, err := json.Marshal(req)
		if err != nil {
			return "", err
		}
		c := wire.Change{Scope: wire.ScopeOrg, Target: org, Kind: wire.ChangeOrgKMSAdd, Subject: req.Name, Data: raw}
		if err := s.propose(ctx, ws.user.ID, s.clientIP(r), c); err != nil {
			return "", err
		}
		return "Asked to approve " + req.Name + ". Sign it on a device that can read the key (gcloud signed in, or BAO_TOKEN set): esec vault changes. It reads the key's public half from the KMS itself.", nil
	})
}

func (s *Server) webOrgKMSRemove(w http.ResponseWriter, r *http.Request) {
	s.orgForm(w, r, orgTabSettings, func(ctx context.Context, ws *webSession, org string, os *team.OrgState) (string, error) {
		if err := requireOrgAdmin(os, ws, org); err != nil {
			return "", err
		}
		name := r.PostForm.Get("name")
		if _, ok := os.KMSByName(name); !ok {
			return "", clientErr(http.StatusNotFound, wire.ErrNotFound, "%s has no key %s.", org, name)
		}
		c := wire.Change{Scope: wire.ScopeOrg, Target: org, Kind: wire.ChangeOrgKMSRemove, Subject: name}
		if done, err := s.serverSigns(ctx, ws.user.ID, s.clientIP(r), c); err != nil || done {
			return "Withdrew " + name + ", signed by the server for you. Workloads that use it keep working until you move them.", err
		}
		return "Asked to withdraw " + name + ". Sign it with your passkey (Changes) or on your device.", s.propose(ctx, ws.user.ID, s.clientIP(r), c)
	})
}

func (s *Server) webOrgFlyApp(w http.ResponseWriter, r *http.Request) {
	s.orgForm(w, r, orgTabWorkloads, func(ctx context.Context, ws *webSession, org string, os *team.OrgState) (string, error) {
		if err := requireOrgAdmin(os, ws, org); err != nil {
			return "", err
		}
		f := func(name string) string { return strings.TrimSpace(r.PostForm.Get(name)) }
		app := wire.FlyApp{App: f("app"), FlyOrg: f("fly_org"), Group: f("group"), KMS: f("kms")}
		if app.FlyOrg == "" {
			app.FlyOrg = os.Settings.FlyOrg
		}
		if app.Group == "" {
			app.Group = org + "/" + app.App
		}
		if app.KMS == "" {
			app.KMS = os.Settings.DefaultKMS
		}
		policy := team.OIDCPolicy{Provider: team.ProviderFly, FlyOrg: app.FlyOrg, FlyApps: []string{app.App}}
		if err := policy.Validate(); err != nil {
			return "", clientErr(http.StatusBadRequest, wire.ErrInvalidRequest, "%v", err)
		}
		if team.ValidGroup(app.Group) != nil || team.OrgOf(app.Group) != org {
			return "", clientErr(http.StatusBadRequest, wire.ErrInvalidRequest, "The group is one of %s, such as %s/%s.", org, org, app.App)
		}
		k, ok := os.KMSByName(app.KMS)
		if !ok {
			return "", clientErr(http.StatusBadRequest, wire.ErrInvalidRequest, "Pick an approved KMS key: approve one under Settings first.")
		}
		if len(k.Groups) > 0 && !slices.Contains(k.Groups, app.Group) {
			return "", clientErr(http.StatusBadRequest, wire.ErrInvalidRequest, "The key %s is approved only for %s.", k.Name, strings.Join(k.Groups, ", "))
		}
		reads := map[string][]string{}
		for _, v := range r.PostForm["read"] {
			project, env, ok := strings.Cut(v, " ")
			if !ok || team.ValidProject(project) != nil || team.OrgOf(project) != org || team.ValidEnv(env) != nil {
				return "", clientErr(http.StatusBadRequest, wire.ErrInvalidRequest, "invalid project or environment")
			}
			reads[project] = append(reads[project], env)
		}
		for _, p := range mapKeysSorted(reads) {
			app.Reads = append(app.Reads, wire.ProjectEnvs{Project: p, Envs: team.SortEnvs(reads[p])})
		}
		raw, err := json.Marshal(app)
		if err != nil {
			return "", err
		}
		c := wire.Change{Scope: wire.ScopeOrg, Target: org, Kind: wire.ChangeFlyApp, Subject: app.App, Data: raw}
		if err := s.propose(ctx, ws.user.ID, s.clientIP(r), c); err != nil {
			return "", err
		}
		return "Asked to set up " + app.App + ". " + signOnDevice + " Its descriptor then shows here, to put in fly.toml.", nil
	})
}

func mapKeysSorted[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// orgGroupForm loads the group a workload form names, for one of its
// admins.
func (s *Server) orgGroupForm(ctx context.Context, ws *webSession, org string, r *http.Request) (*team.GroupState, *team.CredState, error) {
	g := r.PostForm.Get("group")
	if team.ValidGroup(g) != nil || team.OrgOf(g) != org {
		return nil, nil, clientErr(http.StatusBadRequest, wire.ErrInvalidRequest, "invalid group")
	}
	gs, _, err := s.db.groupState(ctx, s.db.sql, g)
	if err != nil {
		return nil, nil, err
	}
	if gs == nil || !gs.Admin(ws.user.ID) {
		return nil, nil, clientErr(http.StatusForbidden, wire.ErrForbidden, "Only an admin of %s can change its workloads.", g)
	}
	c, ok := gs.Cred(r.PostForm.Get("id"))
	if !ok || c.Kind != team.KindWorkload {
		return nil, nil, clientErr(http.StatusNotFound, wire.ErrNotFound, "There is no such workload.")
	}
	return gs, c, nil
}

func (s *Server) webOrgWorkloadRekey(w http.ResponseWriter, r *http.Request) {
	s.orgForm(w, r, orgTabWorkloads, func(ctx context.Context, ws *webSession, org string, os *team.OrgState) (string, error) {
		if os == nil {
			return "", clientErr(http.StatusNotFound, wire.ErrNotFound, "%s is not set up as an organisation yet.", org)
		}
		gs, c, err := s.orgGroupForm(ctx, ws, org, r)
		if err != nil {
			return "", err
		}
		name := r.PostForm.Get("kms")
		k, ok := os.KMSByName(name)
		if !ok {
			return "", clientErr(http.StatusBadRequest, wire.ErrInvalidRequest, "Pick an approved KMS key.")
		}
		if err := os.CheckKMS(k.Key, gs.Group); err != nil {
			return "", clientErr(http.StatusBadRequest, wire.ErrInvalidRequest, "%v", err)
		}
		if c.KMS != nil && c.KMS.Fingerprint() == k.Key.Fingerprint() {
			return c.Name + " uses " + name + " already.", nil
		}
		raw, err := json.Marshal(map[string]string{"kms": name})
		if err != nil {
			return "", err
		}
		ch := wire.Change{Scope: wire.ScopeGroup, Target: gs.Group, Kind: wire.ChangeWorkloadRekey, Subject: c.ID, Data: raw}
		return "Asked to move " + c.Name + " to " + name + ". " + signOnDevice, s.propose(ctx, ws.user.ID, s.clientIP(r), ch)
	})
}

func (s *Server) webOrgWorkloadRemove(w http.ResponseWriter, r *http.Request) {
	s.orgForm(w, r, orgTabWorkloads, func(ctx context.Context, ws *webSession, org string, _ *team.OrgState) (string, error) {
		gs, c, err := s.orgGroupForm(ctx, ws, org, r)
		if err != nil {
			return "", err
		}
		change := wire.Change{Scope: wire.ScopeGroup, Target: gs.Group, Kind: wire.ChangeRemove, Subject: c.ID}
		if done, err := s.serverSigns(ctx, ws.user.ID, s.clientIP(r), change); err != nil || done {
			return c.Name + " is removed, signed by the server for you.", err
		}
		now := s.now()
		if _, err := s.db.sql.ExecContext(ctx, `UPDATE group_creds SET suspended_at = ? WHERE group_id = ? AND id = ? AND suspended_at = 0`, now.Unix(), gs.Group, c.ID); err != nil {
			return "", err
		}
		if err := s.db.groupAudit(ctx, s.db.sql, gs.Group, ws.user.ID, s.clientIP(r), "blocked", c.Kind+" "+c.Name, now); err != nil {
			return "", err
		}
		if err := s.propose(ctx, ws.user.ID, s.clientIP(r), change); err != nil {
			return "", err
		}
		return c.Name + " is blocked: it gets no keys from its next start. A device removes it for good: esec vault changes", nil
	})
}

// webOrgLive refreshes what changes on an organisation's page by itself:
// changes waiting, and on the Workloads tab, when apps last started.
func (s *Server) webOrgLive(w http.ResponseWriter, r *http.Request) {
	ws := s.dsSession(w, r)
	if ws == nil {
		return
	}
	tab := r.PathValue("tab")
	if tab != orgTabPeople && tab != orgTabWorkloads && tab != orgTabSettings {
		tab = orgTabOverview
	}
	data, err := s.orgPageData(r.Context(), ws, r.PathValue("org"), tab)
	if err != nil {
		s.dsFail(w, r, err)
		return
	}
	parts := []string{"org-alerts"}
	if tab == orgTabWorkloads && data["Chain"] != nil {
		parts = append(parts, "org-workloads-list")
	}
	s.dsPatch(w, r, data, parts...)
}

func (s *Server) webOrgDismiss(w http.ResponseWriter, r *http.Request) {
	// The changes show on every tab: come back to the one it was on.
	tab := r.FormValue("tab")
	if tab != orgTabPeople && tab != orgTabWorkloads && tab != orgTabSettings {
		tab = orgTabOverview
	}
	s.orgForm(w, r, tab, func(ctx context.Context, ws *webSession, _ string, _ *team.OrgState) (string, error) {
		return s.dismiss(ctx, ws, r)
	})
}

// webOrgExport exports an organisation as JSON: its people, keys, rules
// and workloads, for scripts and agents.
func (s *Server) webOrgExport(w http.ResponseWriter, r *http.Request) {
	ws := s.requireWeb(w, r)
	if ws == nil {
		return
	}
	data, err := s.orgPageData(r.Context(), ws, r.PathValue("org"), orgTabPeople)
	if err != nil {
		s.webFail(w, r, err)
		return
	}
	type workload struct {
		Group      string   `json:"group"`
		ID         string   `json:"id"`
		Name       string   `json:"name"`
		Runs       string   `json:"runs"`
		KMS        string   `json:"kms,omitempty"`
		KeyProblem string   `json:"key_problem,omitempty"`
		Reads      []string `json:"reads"`
		LastUsed   string   `json:"last_used,omitempty"`
		Descriptor string   `json:"descriptor"`
	}
	type person struct {
		Login string   `json:"login"`
		Admin bool     `json:"admin"`
		Reads []string `json:"reads"`
	}
	out := struct {
		Org         string              `json:"org"`
		Fingerprint string              `json:"fingerprint,omitempty"`
		People      []person            `json:"people"`
		Left        []orgFormerView     `json:"left,omitempty"`
		KMS         []*team.OrgKMSState `json:"kms"`
		Settings    *team.OrgSettings   `json:"settings,omitempty"`
		Policy      wire.OrgPolicy      `json:"policy"`
		Workloads   []workload          `json:"workloads"`
	}{Org: fmt.Sprint(data["Org"]), People: []person{}, KMS: []*team.OrgKMSState{}, Workloads: []workload{}}
	out.Policy, _ = data["Policy"].(wire.OrgPolicy)
	if os, _ := data["Chain"].(*team.OrgState); os != nil {
		out.Fingerprint, out.Settings, out.KMS = os.Words(), &os.Settings, append(out.KMS, os.ActiveKMS()...)
		roster, _ := data["Roster"].([]orgPersonView)
		for _, p := range roster {
			out.People = append(out.People, person{Login: p.Login, Admin: p.Admin, Reads: nonNilStrings(p.Reads)})
		}
		out.Left, _ = data["Former"].([]orgFormerView)
		wls, _ := data["Workloads"].([]orgWorkloadView)
		for _, wl := range wls {
			v := workload{Group: wl.Group, ID: wl.ID, Name: wl.Name, Runs: wl.Runs, KMS: wl.KMSName, KeyProblem: wl.KeyProblem, Reads: nonNilStrings(wl.Reads), Descriptor: wl.Descriptor}
			if !wl.LastUsed.IsZero() {
				v.LastUsed = wl.LastUsed.UTC().Format(time.RFC3339)
			}
			out.Workloads = append(out.Workloads, v)
		}
	}
	w.Header().Set("Content-Disposition", `attachment; filename="`+out.Org+`.json"`)
	writeJSON(w, http.StatusOK, out)
}

// orgIndexRow is an organisation on the index page.
type orgIndexRow struct {
	Org      string
	Signed   bool
	Admin    bool
	People   int
	Projects int
	Groups   int
	Changes  int
}

// webOrgs lists the organisations the viewer belongs to or works in.
func (s *Server) webOrgs(w http.ResponseWriter, r *http.Request) {
	ws := s.requireWeb(w, r)
	if ws == nil {
		return
	}
	ctx := r.Context()
	rows := map[string]*orgIndexRow{}
	get := func(org string) *orgIndexRow {
		if rows[org] == nil {
			rows[org] = &orgIndexRow{Org: org}
		}
		return rows[org]
	}
	sums, err := s.orgSummaries(ctx, ws.user.ID)
	if err != nil {
		s.webFail(w, r, err)
		return
	}
	for _, o := range sums {
		row := get(o.Org)
		row.Signed, row.Admin, row.People, row.Changes = true, o.Admin, o.People, o.Changes
	}
	projects, err := s.db.memberProjects(ctx, ws.user.ID)
	if err != nil {
		s.webFail(w, r, err)
		return
	}
	for _, p := range projects {
		get(team.OrgOf(p)).Projects++
	}
	groups, err := s.db.visibleGroups(ctx, ws.user.ID)
	if err != nil {
		s.webFail(w, r, err)
		return
	}
	for _, g := range groups {
		get(team.OrgOf(g)).Groups++
	}
	list := make([]*orgIndexRow, 0, len(rows))
	for _, k := range mapKeysSorted(rows) {
		row := rows[k]
		if !row.Signed {
			if os, _, err := s.db.orgState(ctx, s.db.sql, k); err == nil && os != nil {
				row.Signed = true
			}
		}
		list = append(list, row)
	}
	data := s.page(ws, "orgs")
	data["Orgs"] = list
	s.render(w, http.StatusOK, "orgs.html", data)
}

// webOrgsNew opens the page of an organisation named in the form, where it
// can be set up.
func (s *Server) webOrgsNew(w http.ResponseWriter, r *http.Request) {
	ws := s.requireWeb(w, r)
	if ws == nil {
		return
	}
	if err := r.ParseForm(); err != nil || !s.checkForm(r, ws) {
		s.webError(w, http.StatusForbidden, "The form expired. Reload the page and try again.")
		return
	}
	org := strings.ToLower(strings.TrimSpace(r.PostForm.Get("org")))
	if team.ValidOrg(org) != nil {
		s.webError(w, http.StatusBadRequest, "That is not an organisation name: use the first part of your project ids, such as acme.")
		return
	}
	http.Redirect(w, r, "/orgs/"+org, http.StatusSeeOther) //nolint:gosec // a checked organisation name: letters, digits and -_.
}
