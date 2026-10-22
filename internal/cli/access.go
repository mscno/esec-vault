package cli

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/mscno/esec-vault/internal/account"
	"github.com/mscno/esec-vault/internal/safetext"
	"github.com/mscno/esec-vault/internal/team"
)

// One command for any reader of a project: a person by GitHub login, or a
// group (of people or machines) by its org/name id.

// AccessGrantCmd lets a person or a group read more environments.
type AccessGrantCmd struct {
	Who        string   `arg:"" help:"A GitHub login, or a group such as acme/backend"`
	Env        []string `name:"env" sep:"," help:"Environments they may read, on top of what they read already"`
	Admin      bool     `help:"Make the person an admin: they read every environment and manage the project"`
	AccountKey string   `help:"A new person's account key words, read to you over another channel, instead of their GitHub SSH proof"`
	Project    string   `help:"Project id (default: nearest .esec-project)"`
	JSON       bool     `help:"Print JSON, for scripts and agents"`
}

// AccessRevokeCmd takes environments, or all access, away.
type AccessRevokeCmd struct {
	Who     string   `arg:"" help:"A GitHub login, or a group such as acme/backend"`
	Env     []string `name:"env" sep:"," help:"Environments to take away (default: all of them: the person or group leaves the project)"`
	Reason  string   `help:"Reason recorded in the project chain"`
	Project string   `help:"Project id (default: nearest .esec-project)"`
	Yes     bool     `help:"Do not ask for confirmation"`
	JSON    bool     `help:"Print JSON, for scripts and agents"`
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
}

// isGroupRef tells a group id ("org/name") from a GitHub login.
func isGroupRef(who string) bool { return strings.Contains(who, "/") }

// Run implements access grant.
func (c *AccessGrantCmd) Run(ctx *cliCtx) error {
	project, err := projectFlag(c.Project)
	if err != nil {
		return err
	}
	if !c.Admin && len(c.Env) == 0 {
		return errors.New("say what they may read with --env dev[,prod], or make a person an admin with --admin")
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
	return printAccess(res, c.JSON)
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
		out.Reads = team.SortEnvs(envs)
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
