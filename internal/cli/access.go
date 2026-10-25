package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/mscno/esec-vault/internal/account"
	"github.com/mscno/esec-vault/internal/safetext"
	"github.com/mscno/esec-vault/internal/team"
	"github.com/mscno/esec-vault/internal/wire"
)

// One command for any reader of a project: a person by GitHub login, or a
// group (of people or machines) by its org/name id.

// AccessGrantCmd lets a person or a group read more environments.
type AccessGrantCmd struct {
	Who            string   `arg:"" help:"A GitHub login, or a group such as acme/backend"`
	Env            []string `name:"env" sep:"," help:"Environments they may read, on top of what they read already"`
	Admin          bool     `help:"Make the person an admin: they read every environment and manage the project"`
	AccountKey     string   `help:"A new person's account key words, read to you over another channel, instead of their GitHub SSH proof"`
	For            string   `name:"for" help:"Take the --env environments away again after this long, such as 8h or 3d (the server signs or proposes the removal)"`
	Project        string   `help:"Project id (default: nearest .esec-project); several, comma-separated, or a pattern of the projects you administer, such as 'acme/*'"`
	SkipMissingEnv bool     `name:"skip-missing-env" help:"With several projects: skip the --env environments a project does not have"`
	JSON           bool     `help:"Print JSON, for scripts and agents (a list, with several projects)"`
}

// AccessRevokeCmd takes environments, or all access, away.
type AccessRevokeCmd struct {
	Who     string   `arg:"" help:"A GitHub login, or a group such as acme/backend"`
	Env     []string `name:"env" sep:"," help:"Environments to take away (default: all of them: the person or group leaves the project)"`
	Reason  string   `help:"Reason recorded in the project chain"`
	Project string   `help:"Project id (default: nearest .esec-project); several, comma-separated, or a pattern of the projects you administer, such as 'acme/*'"`
	Yes     bool     `help:"Do not ask for confirmation"`
	JSON    bool     `help:"Print JSON, for scripts and agents (a list, with several projects)"`
}

// accessResult is what grant and revoke print with --json.
type accessResult struct {
	Project string   `json:"project"`
	Who     string   `json:"who"`
	Kind    string   `json:"kind"`
	Admin   bool     `json:"admin,omitempty"`
	Reads   []string `json:"reads"`
	Sent    []string `json:"sent"`
	Missing []string `json:"missing"`
	// Rotate lists environments they could read and may still hold keys
	// of: give each a new key (esec vault env rotate ENV).
	Rotate []string `json:"rotate"`
	// Pending says another admin (of the group, or of the project) still
	// has to agree.
	Pending []string `json:"pending"`
	// Gained lists the environments this grant added.
	Gained []string `json:"gained"`
	// Until is when Ending, the environments granted for a while, end.
	Until  *time.Time `json:"until,omitempty"`
	Ending []string   `json:"ending,omitempty"`
}

// isGroupRef tells a group id ("org/name") from a GitHub login.
func isGroupRef(who string) bool { return strings.Contains(who, "/") }

// Run implements access grant.
func (c *AccessGrantCmd) Run(ctx *cliCtx) error {
	if manyProjects(c.Project) {
		return c.runMany(ctx)
	}
	project, err := projectFlag(c.Project)
	if err != nil {
		return err
	}
	if !c.Admin && len(c.Env) == 0 {
		return errors.New("say what they may read with --env dev[,prod], or make a person an admin with --admin")
	}
	var ttl time.Duration
	if c.For != "" {
		if c.Admin {
			return errors.New("--for ends --env environments; an admin reads everything, so make them an admin for good or not at all")
		}
		if ttl, err = parseTTL(c.For); err != nil {
			return fmt.Errorf("%w: use hours such as 8h or days such as 3d", err)
		}
	}
	a, err := openAccount(ctx)
	if err != nil {
		return err
	}
	bg, cancel := timeout(2 * time.Minute)
	defer cancel()
	var res *accessResult
	if isGroupRef(c.Who) {
		if c.Admin || c.AccountKey != "" {
			return errors.New("--admin and --account-key are for people; a group only reads environments")
		}
		res, err = grantGroupMore(bg, a, project, c.Who, c.Env, false)
	} else {
		res, err = grantPerson(bg, a, project, c.Who, c.Env, c.Admin, c.AccountKey)
	}
	if err != nil {
		return err
	}
	if ttl > 0 && len(res.Gained) == 0 {
		fmt.Fprintf(os.Stderr, "Note: %s read %s already, so nothing ends after %s.\n", c.Who, strings.Join(c.Env, ", "), c.For)
	}
	if ttl > 0 && len(res.Gained) > 0 {
		// Only what this grant added ends: what they read before stays.
		e, err := a.EndAccessAt(bg, project, c.Who, res.Gained, a.Now().Add(ttl))
		if err != nil {
			return fmt.Errorf("granted, but the server did not take the end time (%w); take it away by hand later: esec vault access revoke %s --env %s --project %s", err, c.Who, strings.Join(c.Env, ","), project)
		}
		res.Until, res.Ending = &e.Expires, e.Envs
	}
	return printAccess(res, c.JSON)
}

// manyProjects reports whether --project names several projects.
func manyProjects(spec string) bool { return strings.ContainsAny(spec, ",*?[") }

// resolveProjects expands a --project list or pattern into the shared
// projects this account administers that it names, sorted.
func resolveProjects(ctx context.Context, a *account.Account, spec string) ([]string, error) {
	list, err := a.TeamSummaries(ctx)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, pat := range strings.Split(spec, ",") {
		pat = strings.TrimSpace(pat)
		if pat == "" {
			continue
		}
		if _, err := path.Match(pat, ""); err != nil {
			return nil, fmt.Errorf("invalid pattern %q", pat)
		}
		found := false
		for _, p := range list {
			if ok, _ := path.Match(pat, p.ID); ok && p.Admin && !p.Archived {
				found = true
				if !slices.Contains(out, p.ID) {
					out = append(out, p.ID)
				}
			}
		}
		if !found && !strings.ContainsAny(pat, "*?[") {
			return nil, fmt.Errorf("%s is not a shared project you administer", pat)
		}
	}
	// The list is the server's: say so if it leaves out a project this
	// device saw that the patterns name.
	listed := map[string]bool{}
	for _, p := range list {
		listed[p.ID] = true
	}
	if seen, err := a.SeenProjects(); err == nil {
		for _, p := range seen {
			if listed[p] {
				continue
			}
			for _, pat := range strings.Split(spec, ",") {
				if ok, _ := path.Match(strings.TrimSpace(pat), p); ok {
					fmt.Fprintf(os.Stderr, "! the server no longer lists %s, which this device saw: it is not included; check it with esec vault access show --project %s\n", p, p)
					break
				}
			}
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no shared project you administer matches %s", spec)
	}
	slices.Sort(out)
	return out, nil
}

// envsIn keeps the environments a project has, when skip is set; without
// it, the grant itself refuses one it lacks.
func envsIn(ctx context.Context, a *account.Account, project string, envs []string, skip bool) ([]string, error) {
	if !skip {
		return envs, nil
	}
	v, err := a.Team(ctx, project)
	if err != nil {
		return nil, err
	}
	return slices.DeleteFunc(slices.Clone(envs), func(n string) bool { _, ok := v.State.Envs[n]; return !ok }), nil
}

// runMany grants across several projects, one result each; it goes on past
// a project that fails, and fails at the end.
func (c *AccessGrantCmd) runMany(ctx *cliCtx) error {
	if c.For != "" || c.AccountKey != "" {
		return errors.New("--for and --account-key take one project at a time")
	}
	if !c.Admin && len(c.Env) == 0 {
		return errors.New("say what they may read with --env dev[,prod], or make a person an admin with --admin")
	}
	a, err := openAccount(ctx)
	if err != nil {
		return err
	}
	bg, cancel := timeout(30 * time.Minute)
	defer cancel()
	projects, err := resolveProjects(bg, a, c.Project)
	if err != nil {
		return err
	}
	return eachProject(projects, c.JSON, func(project string) (*accessResult, error) {
		envs, err := envsIn(bg, a, project, c.Env, c.SkipMissingEnv)
		if err != nil {
			return nil, err
		}
		if !c.Admin && len(envs) == 0 {
			return &accessResult{Project: project, Who: c.Who, Kind: "skipped", Reads: []string{}, Sent: []string{}, Missing: []string{}, Rotate: []string{}, Pending: []string{}}, nil
		}
		if isGroupRef(c.Who) {
			return grantGroupMore(bg, a, project, c.Who, envs, false)
		}
		return grantPerson(bg, a, project, c.Who, envs, c.Admin, "")
	})
}

// manyResult is one project's result of a grant or revoke over several.
type manyResult struct {
	*accessResult

	Error string `json:"error,omitempty"`
}

// eachProject runs fn on each project, prints each result, and fails if
// any did.
func eachProject(projects []string, asJSON bool, fn func(project string) (*accessResult, error)) error {
	var out []manyResult
	failed := 0
	for _, p := range projects {
		res, err := fn(p)
		if err != nil {
			failed++
			if res == nil {
				res = &accessResult{Project: p}
			}
			out = append(out, manyResult{accessResult: res, Error: err.Error()})
			if !asJSON {
				fmt.Fprintf(os.Stderr, "! %s: %v\n", p, err)
			}
			continue
		}
		out = append(out, manyResult{accessResult: res})
		if !asJSON {
			if res.Kind == "skipped" {
				fmt.Printf("- %s: has none of those environments\n", p)
				continue
			}
			if err := printAccess(res, false); err != nil {
				return err
			}
		}
	}
	if asJSON {
		if err := printJSON(out); err != nil {
			return err
		}
	}
	if failed > 0 {
		return fmt.Errorf("%d of %d project(s) failed", failed, len(projects))
	}
	return nil
}

// grantPerson adds a person, or adds to what a member reads.
func grantPerson(ctx context.Context, a *account.Account, project, login string, envs []string, admin bool, accountKey string) (*accessResult, error) {
	v, err := a.Team(ctx, project)
	if err != nil {
		return nil, err
	}
	out := &accessResult{Project: project, Who: login, Kind: "person", Sent: []string{}, Missing: []string{}, Rotate: []string{}, Pending: []string{}}
	for _, n := range envs {
		if _, ok := v.State.Envs[n]; !ok {
			return nil, fmt.Errorf("%s has no environment %s (it has %s)", project, n, strings.Join(v.State.EnvNames(), ", "))
		}
	}
	var m *team.MemberState
	for _, x := range v.State.ActiveMembers() {
		if strings.EqualFold(x.Login, login) {
			m = x
		}
	}
	if m == nil {
		res, err := a.AddMember(ctx, project, login, admin, envs, accountKey)
		if err != nil {
			return nil, err
		}
		out.Who, out.Admin, out.Sent, out.Missing = res.Login, admin, nonNil(res.Granted), nonNil(res.Missing)
		out.Reads, out.Gained = team.SortEnvs(envs), team.SortEnvs(envs)
		if admin {
			out.Reads = v.State.EnvNames()
		}
		return out, nil
	}
	if m.Admin {
		return nil, fmt.Errorf("%s is an admin of %s and reads every environment already", m.Login, project)
	}
	want := team.SortEnvs(append(slices.Clone(m.Envs), envs...))
	if !admin && slices.Equal(want, m.Envs) {
		out.Who, out.Reads = m.Login, m.Envs
		return out, nil
	}
	if admin {
		want = nil
	}
	res, err := a.UpdateMember(ctx, project, m.Login, admin, want)
	if err != nil {
		return nil, err
	}
	out.Who, out.Admin, out.Sent, out.Missing = m.Login, admin, nonNil(res.Granted), nonNil(res.Missing)
	out.Reads = want
	out.Gained = slices.DeleteFunc(slices.Clone(want), func(n string) bool { return slices.Contains(m.Envs, n) })
	if admin {
		out.Reads = v.State.EnvNames()
	}
	return out, nil
}

// grantGroupMore makes a group read envs on top of what it reads (or, with
// remove, all but envs) and reports it.
func grantGroupMore(ctx context.Context, a *account.Account, project, group string, envs []string, remove bool) (*accessResult, error) {
	v, err := a.Team(ctx, project)
	if err != nil {
		return nil, err
	}
	var current []string
	if pg, ok := v.State.Group(group); ok {
		current = pg.Envs
	}
	want := team.SortEnvs(append(slices.Clone(current), envs...))
	if remove {
		want = nil
		if len(envs) > 0 {
			want = slices.DeleteFunc(slices.Clone(current), func(n string) bool { return slices.Contains(envs, n) })
		}
	}
	res, err := a.GrantGroup(ctx, group, project, want)
	if err != nil {
		return nil, err
	}
	out := &accessResult{Project: project, Who: group, Kind: "group", Reads: nonNil(want), Sent: []string{}, Missing: nonNil(res.Missing), Rotate: nonNil(res.Exposed), Pending: []string{}}
	out.Gained = slices.DeleteFunc(slices.Clone(want), func(n string) bool { return slices.Contains(current, n) })
	if res.Sent {
		out.Sent = want
	}
	if res.NeedGroupAdmin {
		out.Pending = append(out.Pending, "an admin of "+group+" runs: esec vault access grant "+group+" --project "+project+" --env "+strings.Join(want, ","))
	}
	if res.NeedProjectAdmin {
		out.Pending = append(out.Pending, "an admin of "+project+" runs: esec vault access grant "+group+" --project "+project+" --env "+strings.Join(want, ","))
	}
	return out, nil
}

// Run implements access revoke.
func (c *AccessRevokeCmd) Run(ctx *cliCtx) error {
	if manyProjects(c.Project) {
		return c.runMany(ctx)
	}
	project, err := projectFlag(c.Project)
	if err != nil {
		return err
	}
	what := "all access to " + project
	if len(c.Env) > 0 {
		what = strings.Join(c.Env, ", ") + " of " + project
	}
	if !c.Yes && !confirm(fmt.Sprintf("Take %s away from %s?", what, c.Who)) {
		return errors.New("cancelled")
	}
	a, err := openAccount(ctx)
	if err != nil {
		return err
	}
	bg, cancel := timeout(2 * time.Minute)
	defer cancel()
	var res *accessResult
	if isGroupRef(c.Who) {
		res, err = grantGroupMore(bg, a, project, c.Who, c.Env, true)
	} else {
		res, err = revokePerson(bg, a, project, c.Who, c.Env, c.Reason)
	}
	if err != nil {
		return err
	}
	return printAccess(res, c.JSON)
}

// runMany revokes across several projects, after asking once.
func (c *AccessRevokeCmd) runMany(ctx *cliCtx) error {
	a, err := openAccount(ctx)
	if err != nil {
		return err
	}
	bg, cancel := timeout(30 * time.Minute)
	defer cancel()
	projects, err := resolveProjects(bg, a, c.Project)
	if err != nil {
		return err
	}
	what := "all access"
	if len(c.Env) > 0 {
		what = strings.Join(c.Env, ", ")
	}
	if !c.Yes && !confirm(fmt.Sprintf("Take %s away from %s in %d project(s): %s?", what, c.Who, len(projects), strings.Join(projects, ", "))) {
		return errors.New("cancelled")
	}
	return eachProject(projects, c.JSON, func(project string) (*accessResult, error) {
		if isGroupRef(c.Who) {
			return grantGroupMore(bg, a, project, c.Who, c.Env, true)
		}
		return revokePerson(bg, a, project, c.Who, c.Env, c.Reason)
	})
}

func revokePerson(ctx context.Context, a *account.Account, project, login string, envs []string, reason string) (*accessResult, error) {
	out := &accessResult{Project: project, Who: login, Kind: "person", Reads: []string{}, Sent: []string{}, Missing: []string{}, Pending: []string{}}
	if len(envs) == 0 {
		could, err := a.RemoveMember(ctx, project, login, reason)
		if err != nil {
			return nil, err
		}
		out.Rotate = nonNil(could)
		return out, nil
	}
	v, err := a.Team(ctx, project)
	if err != nil {
		return nil, err
	}
	var m *team.MemberState
	for _, x := range v.State.ActiveMembers() {
		if strings.EqualFold(x.Login, login) {
			m = x
		}
	}
	if m == nil {
		return nil, fmt.Errorf("%s is not a member of %s", login, project)
	}
	if m.Admin {
		return nil, fmt.Errorf("%s is an admin and reads every environment; make them a member who reads less with: esec vault access set %s --no-admin --env ENV", m.Login, m.Login)
	}
	want := slices.DeleteFunc(slices.Clone(m.Envs), func(n string) bool { return slices.Contains(envs, n) })
	res, err := a.UpdateMember(ctx, project, m.Login, false, want)
	if err != nil {
		return nil, err
	}
	out.Who, out.Reads, out.Rotate = m.Login, nonNil(want), nonNil(res.Exposed)
	return out, nil
}

func printAccess(r *accessResult, asJSON bool) error {
	if asJSON {
		r.Gained = nonNil(r.Gained)
		return printJSON(r)
	}
	who := safetext.Clean(r.Who)
	switch {
	case r.Admin:
		fmt.Printf("✓ %s is an admin of %s: they read every environment.\n", who, r.Project)
	case len(r.Reads) == 0:
		fmt.Printf("✓ %s reads nothing of %s.\n", who, r.Project)
	default:
		fmt.Printf("✓ %s reads %s of %s.\n", who, strings.Join(r.Reads, ", "), r.Project)
	}
	if len(r.Sent) > 0 {
		fmt.Printf("  Sent the keys of %s, sealed to them; their devices pick them up on their own.\n", strings.Join(r.Sent, ", "))
	}
	if len(r.Missing) > 0 {
		fmt.Printf("  ! This device has no current key for %s; an admin's device that has it sends it on its next sync.\n", strings.Join(r.Missing, ", "))
	}
	for _, p := range r.Pending {
		fmt.Println("  ! Not yet: " + p)
	}
	if r.Until != nil {
		fmt.Printf("  They lose %s again at %s: the server signs the removal for you if you let it (esec vault delegate server), otherwise it waits for you in esec vault changes.\n", strings.Join(r.Ending, ", "), r.Until.Local().Format("2006-01-02 15:04")) //nolint:gosmopolitan // shown to the local user
	}
	printRotations(r.Rotate, who+" could read")
	return nil
}

// AccessOffboardCmd takes away everything a person reads.
type AccessOffboardCmd struct {
	Login  string `arg:"" help:"GitHub login of the person leaving"`
	Reason string `help:"Reason recorded in each chain" default:"offboarded"`
	DryRun bool   `name:"dry-run" help:"Only list what they read, change nothing"`
	Yes    bool   `help:"Do not ask for confirmation"`
	JSON   bool   `help:"Print JSON, for scripts and agents"`
}

// offboardResult is what offboard prints with --json.
type offboardResult struct {
	Login string                 `json:"login"`
	Items []account.OffboardItem `json:"items"`
	// Removed lists the projects and groups they were taken out of;
	// Skipped those this account cannot change, with what to do.
	Removed []string `json:"removed"`
	Skipped []string `json:"skipped"`
	// Rotate maps projects to the environments to give new keys.
	Rotate map[string][]string `json:"rotate"`
	Errors []string            `json:"errors"`
}

// Run implements access offboard.
func (c *AccessOffboardCmd) Run(ctx *cliCtx) error { //nolint:gocyclo // plan, confirm, then one removal per kind
	a, err := openAccount(ctx)
	if err != nil {
		return err
	}
	bg, cancel := timeout(10 * time.Minute)
	defer cancel()
	items, err := a.OffboardPlan(bg, c.Login)
	if err != nil {
		return err
	}
	out := &offboardResult{Login: c.Login, Items: nonNil(items), Removed: []string{}, Skipped: []string{}, Rotate: map[string][]string{}, Errors: []string{}}
	if !c.JSON {
		if len(items) == 0 {
			fmt.Printf("%s reads nothing in the projects and groups you can see.\n", c.Login)
			return nil
		}
		fmt.Printf("%s reads:\n", c.Login)
		for _, it := range items {
			fmt.Println("  " + offboardLine(it))
		}
	}
	if c.DryRun || len(items) == 0 {
		if c.JSON {
			return printJSON(out)
		}
		return nil
	}
	if c.JSON && !c.Yes {
		// The plan goes to stderr: stdout stays JSON.
		fmt.Fprintf(os.Stderr, "%s reads:\n", c.Login)
		for _, it := range items {
			fmt.Fprintln(os.Stderr, "  "+offboardLine(it))
		}
	}
	if !c.Yes && !confirm(fmt.Sprintf("Take all of it away from %s?", c.Login)) {
		return errors.New("cancelled")
	}
	for _, it := range items {
		if !it.CanRemove {
			out.Skipped = append(out.Skipped, fmt.Sprintf("%s: you are not an admin there; an admin removes them", it.ID))
			continue
		}
		var err error
		switch it.Kind {
		case account.HoldsProject:
			var could []string
			if could, err = a.RemoveMember(bg, it.ID, c.Login, c.Reason); err == nil && len(could) > 0 {
				out.Rotate[it.ID] = append(out.Rotate[it.ID], could...)
			}
		case account.HoldsGroupMember, account.HoldsGroupAdmin:
			var res *account.GroupRemoveResult
			if it.Kind == account.HoldsGroupMember {
				res, err = a.RemoveGroupMember(bg, it.ID, c.Login, c.Reason)
			} else {
				res, err = a.RemoveGroupAdmin(bg, it.ID, c.Login)
			}
			if err == nil {
				for p, envs := range res.Exposed {
					out.Rotate[p] = append(out.Rotate[p], envs...)
				}
			}
		}
		if err != nil {
			out.Errors = append(out.Errors, it.ID+": "+err.Error())
			continue
		}
		out.Removed = append(out.Removed, it.ID)
	}
	for p, envs := range out.Rotate {
		out.Rotate[p] = team.SortEnvs(envs)
	}
	if c.JSON {
		if err := printJSON(out); err != nil {
			return err
		}
	} else {
		printOffboard(out)
	}
	if len(out.Errors) > 0 {
		return fmt.Errorf("could not remove %s from %d place(s)", c.Login, len(out.Errors))
	}
	return nil
}

func offboardLine(it account.OffboardItem) string {
	reads := joinOr(it.Envs, "nothing")
	note := ""
	if !it.CanRemove {
		note = "  (you are not an admin there)"
	}
	switch it.Kind {
	case account.HoldsGroupMember:
		return fmt.Sprintf("member of the group %s, which reads %s%s", it.ID, reads, note)
	case account.HoldsGroupAdmin:
		return fmt.Sprintf("admin of the group %s, which reads %s%s", it.ID, reads, note)
	}
	if it.Admin {
		return fmt.Sprintf("admin of %s (every environment: %s)%s", it.ID, reads, note)
	}
	return fmt.Sprintf("%s: %s%s", it.ID, reads, note)
}

func printOffboard(out *offboardResult) {
	for _, r := range out.Removed {
		fmt.Printf("✓ Removed %s from %s.\n", out.Login, r)
	}
	for _, s := range out.Skipped {
		fmt.Println("! Skipped " + s)
	}
	for _, e := range out.Errors {
		fmt.Println("! " + safetext.Clean(e))
	}
	projects := mapKeys(out.Rotate)
	slices.Sort(projects)
	if len(projects) > 0 {
		fmt.Printf("! %s may still hold these keys. In each repository, give them new keys, and change the secret values they may have seen:\n", out.Login)
	}
	for _, p := range projects {
		for _, e := range out.Rotate[p] {
			fmt.Printf("    esec vault env rotate %s --project %s\n", e, p)
		}
	}
}

// AccessRequestCmd asks a project's admins for environments.
type AccessRequestCmd struct {
	Env     []string `name:"env" sep:"," required:"" help:"Environments you need"`
	Reason  string   `help:"Why, for the admins"`
	Project string   `help:"Project id (default: nearest .esec-project)"`
	JSON    bool     `help:"Print JSON, for scripts and agents"`
}

// Run implements access request.
func (c *AccessRequestCmd) Run(ctx *cliCtx) error {
	project, err := projectFlag(c.Project)
	if err != nil {
		return err
	}
	a, err := openAccount(ctx)
	if err != nil {
		return err
	}
	bg, cancel := timeout(time.Minute)
	defer cancel()
	q, err := a.RequestAccess(bg, project, team.SortEnvs(c.Env), c.Reason)
	if err != nil {
		return err
	}
	if c.JSON {
		return printJSON(q)
	}
	fmt.Printf("✓ Asked for %s of %s (#%d). Its admins see it on the project's page and with 'esec vault access requests'; your devices get the keys once one grants it.\n", strings.Join(q.Envs, ", "), project, q.ID)
	return nil
}

// AccessRequestsCmd lists, grants and turns down access requests.
type AccessRequestsCmd struct {
	Project  string `help:"Only this project's requests"`
	Grant    int64  `help:"Grant request ID: the person gets what they asked for" xor:"answer"`
	Deny     int64  `help:"Turn request ID down" xor:"answer"`
	Withdraw int64  `help:"Withdraw your own request ID" xor:"answer"`
	// The server says what a request asks for, so granting one unasked
	// needs the person to say it too.
	Login string   `help:"With --grant --yes: the login the request must be from"`
	Env   []string `name:"env" sep:"," help:"With --grant --yes: the environments it must ask for"`
	Yes   bool     `help:"With --grant, --login, --env and --project: grant without asking"`
	JSON  bool     `help:"Print JSON, for scripts and agents"`
}

// Run implements access requests.
func (c *AccessRequestsCmd) Run(ctx *cliCtx) error { //nolint:gocyclo // list, or one of three answers
	a, err := openAccount(ctx)
	if err != nil {
		return err
	}
	bg, cancel := timeout(2 * time.Minute)
	defer cancel()
	list, err := a.AccessRequests(bg)
	if err != nil {
		return err
	}
	keep := func(qs []wire.AccessRequest) []wire.AccessRequest {
		if c.Project == "" {
			return qs
		}
		return slices.DeleteFunc(qs, func(q wire.AccessRequest) bool { return q.Project != c.Project })
	}
	list.ToDecide, list.Mine = keep(list.ToDecide), keep(list.Mine)
	find := func(qs []wire.AccessRequest, id int64) (*wire.AccessRequest, error) {
		for i := range qs {
			if qs[i].ID == id {
				return &qs[i], nil
			}
		}
		return nil, fmt.Errorf("no open request #%d for you to answer; list them with: esec vault access requests", id)
	}
	switch {
	case c.Grant != 0:
		q, err := find(list.ToDecide, c.Grant)
		if err != nil {
			return err
		}
		if err := c.checkGrant(q); err != nil {
			return err
		}
		res, err := grantPerson(bg, a, q.Project, q.Login, q.Envs, false, "")
		if err != nil {
			return err
		}
		if err := a.CloseRequest(bg, q.ID, true); err != nil {
			return err
		}
		return printAccess(res, c.JSON)
	case c.Deny != 0:
		q, err := find(list.ToDecide, c.Deny)
		if err != nil {
			return err
		}
		if err := a.CloseRequest(bg, q.ID, false); err != nil {
			return err
		}
		fmt.Printf("✓ Turned down %s's request for %s of %s.\n", safetext.Clean(q.Login), safetext.Clean(strings.Join(q.Envs, ", ")), safetext.Clean(q.Project))
		return nil
	case c.Withdraw != 0:
		q, err := find(list.Mine, c.Withdraw)
		if err != nil {
			return err
		}
		if err := a.CloseRequest(bg, q.ID, false); err != nil {
			return err
		}
		fmt.Printf("✓ Withdrew your request for %s of %s.\n", safetext.Clean(strings.Join(q.Envs, ", ")), safetext.Clean(q.Project))
		return nil
	}
	if c.JSON {
		return printJSON(list)
	}
	if len(list.ToDecide)+len(list.Mine) == 0 {
		fmt.Println("No access requests wait. Ask for access with: esec vault access request --env staging")
		return nil
	}
	if len(list.ToDecide) > 0 {
		fmt.Println("Waiting for you:")
		for _, q := range list.ToDecide {
			why := ""
			if q.Reason != "" {
				why = " (" + safetext.Clean(q.Reason) + ")"
			}
			fmt.Printf("  #%-5d %-20s %s of %s%s, %s\n", q.ID, safetext.Clean(q.Login), safetext.Clean(strings.Join(q.Envs, ", ")), safetext.Clean(q.Project), why, q.Created.Local().Format("2006-01-02 15:04")) //nolint:gosmopolitan // shown to the local user
		}
		fmt.Println("Answer with: esec vault access requests --grant ID (or --deny ID)")
	}
	if len(list.Mine) > 0 {
		fmt.Println("Yours, waiting for an answer:")
		for _, q := range list.Mine {
			fmt.Printf("  #%-5d %s of %s\n", q.ID, safetext.Clean(strings.Join(q.Envs, ", ")), safetext.Clean(q.Project))
		}
	}
	return nil
}

// AccessArchiveCmd archives a project.
type AccessArchiveCmd struct {
	Project string `help:"Project id (default: nearest .esec-project)"`
	Reason  string `help:"Reason recorded in the project chain"`
	Undo    bool   `help:"Unarchive it instead"`
}

// Run implements access archive.
func (c *AccessArchiveCmd) Run(ctx *cliCtx) error {
	project, err := projectFlag(c.Project)
	if err != nil {
		return err
	}
	a, err := openAccount(ctx)
	if err != nil {
		return err
	}
	bg, cancel := timeout(time.Minute)
	defer cancel()
	if c.Undo {
		if err := a.Unarchive(bg, project, c.Reason); err != nil {
			return err
		}
		fmt.Printf("✓ Unarchived %s.\n", project)
		return nil
	}
	if err := a.Archive(bg, project, c.Reason); err != nil {
		return err
	}
	fmt.Printf("✓ Archived %s: no keys are sent for it, and nothing changes in it but members leaving. Undo with: esec vault access archive --undo --project %s\n", project, project)
	return nil
}

// AccessDeleteCmd deletes an archived project from the server.
type AccessDeleteCmd struct {
	Project string `help:"Project id (default: nearest .esec-project)"`
	Yes     bool   `help:"Do not ask for confirmation"`
}

// Run implements access delete.
func (c *AccessDeleteCmd) Run(ctx *cliCtx) error {
	project, err := projectFlag(c.Project)
	if err != nil {
		return err
	}
	if !c.Yes && !confirm(fmt.Sprintf("Delete %s from the server for good? Its keys stay in keyrings.", project)) {
		return errors.New("cancelled")
	}
	a, err := openAccount(ctx)
	if err != nil {
		return err
	}
	bg, cancel := timeout(time.Minute)
	defer cancel()
	if err := a.DeleteProject(bg, project); err != nil {
		return err
	}
	fmt.Printf("✓ Deleted %s from the server. Its keys stay in your keyring, and the encrypted files in the repository.\n", project)
	return nil
}

// AccessMoveCmd moves a project to a new id.
type AccessMoveCmd struct {
	To      string `arg:"" help:"New project id, org/repo"`
	Project string `help:"Project id (default: nearest .esec-project)"`
	Yes     bool   `help:"Do not ask for confirmation"`
}

// Run implements access move.
func (c *AccessMoveCmd) Run(ctx *cliCtx) error {
	project, err := projectFlag(c.Project)
	if err != nil {
		return err
	}
	if !c.Yes && !confirm(fmt.Sprintf("Move %s to %s? A new project with the same keys and people; %s is archived.", project, c.To, project)) {
		return errors.New("cancelled")
	}
	a, err := openAccount(ctx)
	if err != nil {
		return err
	}
	bg, cancel := timeout(10 * time.Minute)
	defer cancel()
	res, err := a.MoveProject(bg, project, c.To)
	if err != nil {
		return err
	}
	for i, l := range res.Lines(project) {
		if i == 0 {
			fmt.Println("✓ " + safetext.Clean(l))
			continue
		}
		fmt.Println("  " + safetext.Clean(l))
	}
	return nil
}

// AccessHandoverCmd makes another member an admin, and this account a member.
type AccessHandoverCmd struct {
	Login    string `arg:"" help:"GitHub login of the member who becomes an admin"`
	StepDown bool   `name:"step-down" help:"Then make yourself a member who reads every environment"`
	Project  string `help:"Project id (default: nearest .esec-project)"`
}

// Run implements access handover.
func (c *AccessHandoverCmd) Run(ctx *cliCtx) error {
	project, err := projectFlag(c.Project)
	if err != nil {
		return err
	}
	a, err := openAccount(ctx)
	if err != nil {
		return err
	}
	bg, cancel := timeout(2 * time.Minute)
	defer cancel()
	if strings.EqualFold(c.Login, a.State.Login) {
		return errors.New("name someone else")
	}
	if _, err := a.UpdateMember(bg, project, c.Login, true, nil); err != nil {
		return err
	}
	fmt.Printf("✓ %s is an admin of %s.\n", c.Login, project)
	if !c.StepDown {
		return nil
	}
	v, err := a.Team(bg, project)
	if err != nil {
		return err
	}
	if _, err := a.UpdateMember(bg, project, a.State.Login, false, v.State.EnvNames()); err != nil {
		return err
	}
	fmt.Printf("✓ You are a member of %s who reads every environment, no longer an admin.\n", project)
	return nil
}

// checkGrant shows a request the server describes and asks before granting
// it; with --yes, the request must match the login, project and
// environments given on the command line instead.
func (c *AccessRequestsCmd) checkGrant(q *wire.AccessRequest) error {
	what := fmt.Sprintf("%s asks for %s of %s", safetext.Clean(q.Login), safetext.Clean(strings.Join(q.Envs, ", ")), safetext.Clean(q.Project))
	if !c.Yes {
		fmt.Println(what + ".")
		if !confirm("Grant it?") {
			return errors.New("not granted")
		}
		return nil
	}
	if c.Login == "" || c.Project == "" || len(c.Env) == 0 {
		return errors.New("--yes needs --login, --project and --env, which the request must match")
	}
	if !strings.EqualFold(c.Login, q.Login) || c.Project != q.Project || !slices.Equal(team.SortEnvs(c.Env), team.SortEnvs(q.Envs)) {
		return fmt.Errorf("request #%d is not what you named: %s", q.ID, what)
	}
	return nil
}
