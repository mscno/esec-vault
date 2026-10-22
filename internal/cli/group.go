package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/mscno/esec-vault/internal/account"
	"github.com/mscno/esec-vault/internal/safetext"
	"github.com/mscno/esec-vault/internal/storage"
	"github.com/mscno/esec-vault/internal/team"
	"github.com/mscno/esec-vault/internal/wire"
)

// GroupCmd manages groups: sets of people (a team such as acme/backend) or
// machines (production or staging servers), or both, that read the same
// environments of one or more projects.
type GroupCmd struct {
	List       GroupListCmd       `cmd:"" default:"withargs" help:"List your groups (default)."`
	Show       GroupShowCmd       `cmd:"" help:"Show a group: its people, machines, tokens, projects and what needs doing."`
	Create     GroupCreateCmd     `cmd:"" help:"Create a group, with you as its admin."`
	Add        GroupAddCmd        `cmd:"" help:"Add a person to a group: they read what it reads."`
	Grant      GroupGrantCmd      `cmd:"" help:"Let a group read environments of a shared project (replacing what it read)."`
	Revoke     GroupRevokeCmd     `cmd:"" help:"Stop a group reading a project."`
	Token      GroupTokenCmd      `cmd:"" help:"Create an enrollment token: CI jobs use it directly, and machines join the group with it."`
	AddMachine GroupAddMachineCmd `cmd:"" name:"add-machine" help:"Create a machine of the group and print its key, for a machine you set up yourself."`
	Approve    GroupApproveCmd    `cmd:"" help:"Let in machines waiting to join, and sign changes made on the web pages."`
	Remove     GroupRemoveCmd     `cmd:"" help:"Remove a person, machine or token; the group gets a new key."`
	Leave      GroupLeaveCmd      `cmd:"" help:"Leave a group you are a member of."`
	Rotate     GroupRotateCmd     `cmd:"" help:"Give the group a new key, sealed to every machine still in it."`
	Admin      GroupAdminCmd      `cmd:"" help:"Make someone an admin of a group."`
	Sync       TeamSyncCmd        `cmd:"" help:"Send keys machines and admins are missing (the background service does this too)."`
}

// groupID returns a group id, taking a bare name as this account's own:
// "production" is LOGIN/production.
func groupID(a *account.Account, name string) (string, error) {
	if !strings.Contains(name, "/") {
		name = strings.ToLower(a.State.Login) + "/" + name
	}
	return name, team.ValidGroup(name)
}

// GroupListCmd lists groups.
type GroupListCmd struct {
	JSON bool `help:"Print JSON, for scripts and agents"`
}

// Run implements group list.
func (c *GroupListCmd) Run(ctx *cliCtx) error {
	a, err := openAccount(ctx)
	if err != nil {
		return err
	}
	bg, cancel := timeout(time.Minute)
	defer cancel()
	list, err := a.Groups(bg)
	if err != nil {
		return err
	}
	if c.JSON {
		return printJSON(nonNil(list))
	}
	if len(list) == 0 {
		fmt.Println("No groups. Create one with: esec vault group create acme/backend (people) or acme/production (machines)")
		return nil
	}
	for _, g := range list {
		role := "reads your projects"
		switch {
		case g.Admin:
			role = "admin"
		case g.Member:
			role = "member"
		}
		extra := ""
		if g.Pending > 0 {
			extra += fmt.Sprintf("  %d waiting for approval", g.Pending)
		}
		if g.KeyExposed > 0 {
			extra += "  needs a new group key"
		}
		fmt.Println(safetext.CleanN(fmt.Sprintf("%-28s %-20s %d people, %d machine(s), %d token(s), reads %s%s", g.ID, role, g.People, g.Machines, g.Tokens, joinOr(g.Projects, "no projects"), extra), 2000))
	}
	return nil
}

// GroupShowCmd shows a group.
type GroupShowCmd struct {
	Group string `arg:"" help:"Group, such as acme/production"`
	JSON  bool   `help:"Print JSON, for scripts and agents"`
}

// Run implements group show.
func (c *GroupShowCmd) Run(ctx *cliCtx) error { //nolint:gocyclo // one report, section by section
	a, err := openAccount(ctx)
	if err != nil {
		return err
	}
	id, err := groupID(a, c.Group)
	if err != nil {
		return err
	}
	bg, cancel := timeout(2 * time.Minute)
	defer cancel()
	v, err := a.Group(bg, id)
	if err != nil {
		return err
	}
	gs := v.State
	used := map[string]wire.CredStatus{}
	if v.Status != nil {
		for _, s := range v.Status.Creds {
			used[s.ID] = s
		}
	}
	if c.JSON {
		return printJSON(groupJSON(id, a.State.Server, v, used))
	}
	fmt.Printf("%s  (key version %d, %d signed changes; %s/groups/%s)\n", id, gs.Key.Version, gs.Seq, a.State.Server, id)
	fmt.Printf("Fingerprint: %s\n", team.GroupWords(id, gs.Root()))
	var admins []string
	for _, ad := range gs.ActiveAdmins() {
		admins = append(admins, safetext.Clean(ad.Login))
	}
	fmt.Println("Admins:", strings.Join(admins, ", "))
	if ms := gs.ActiveMembers(); len(ms) > 0 {
		var names []string
		for _, m := range ms {
			names = append(names, safetext.Clean(m.Login))
		}
		fmt.Printf("Members (%d): %s\n", len(ms), strings.Join(names, ", "))
	}
	for _, kind := range []string{team.KindMachine, team.KindToken} {
		creds := gs.ActiveCreds(kind)
		if len(creds) == 0 {
			continue
		}
		fmt.Printf("%ss (%d):\n", strings.ToUpper(kind[:1])+kind[1:], len(creds))
		for _, cr := range creds {
			u := used[cr.ID]
			line := "never used"
			if !u.LastUsed.IsZero() {
				line = fmt.Sprintf("last used %s from %s (%d times)", u.LastUsed.Local().Format("2006-01-02 15:04"), u.LastIP, u.Uses) //nolint:gosmopolitan // shown to the local user
			}
			var notes []string
			if u.Suspended {
				notes = append(notes, "blocked on the web, waiting for approval")
			}
			if v.Status != nil && !u.HasKey && !u.Suspended {
				notes = append(notes, "group key not sent yet")
			}
			if !cr.Expires.IsZero() {
				notes = append(notes, "expires "+cr.Expires.Local().Format("2006-01-02")) //nolint:gosmopolitan // shown to the local user
			}
			if cr.OIDC != nil {
				notes = append(notes, "only "+cr.OIDC.Describe())
			}
			if strings.HasPrefix(cr.AddedBy, "t_") {
				if t := gs.Creds[cr.AddedBy]; t != nil {
					notes = append(notes, "enrolled with "+safetext.Clean(t.Name))
				}
			}
			extra := ""
			if len(notes) > 0 {
				extra = "  [" + strings.Join(notes, "; ") + "]"
			}
			fmt.Printf("  %-20s %-34s %s%s\n", safetext.Clean(cr.Name), cr.ID, line, extra)
		}
	}
	fmt.Println("Reads:")
	if len(v.Projects) == 0 {
		fmt.Println("  nothing yet; let it read a project with: esec vault group grant " + id + " --project ORG/REPO --env prod")
	}
	for _, p := range v.Projects {
		state := ""
		switch {
		case !p.Visible:
			state = "(you are not a member of the project)"
		case !p.Trusted:
			state = "(the group does not take its keys yet; an admin of the group runs 'esec vault group grant')"
		case len(p.Envs) == 0:
			state = "(the project grants nothing yet; an admin of the project runs 'esec vault group grant')"
		case !p.Delivered:
			state = "(keys not sealed to the group's current key yet)"
		}
		fmt.Printf("  %-32s %-20s %s\n", p.Project, joinOr(p.Envs, "-"), state)
		if len(p.Rotate) > 0 {
			fmt.Printf("  ! %s: %s need(s) a new key, since a removed machine may hold it: esec vault env rotate ENV --project %s\n", p.Project, strings.Join(p.Rotate, ", "), p.Project)
		}
	}
	if len(gs.KeyExposed) > 0 {
		fmt.Printf("! A removed machine still holds the group key: esec vault group rotate %s\n", id)
	}
	if v.Status != nil {
		if n := len(v.Status.Joins) + len(v.Status.Changes); n > 0 {
			fmt.Printf("! %d machine(s) or web change(s) wait for approval: esec vault group approve %s\n", n, id)
		}
	}
	return nil
}

// GroupCreateCmd creates a group.
type GroupCreateCmd struct {
	Group string `arg:"" help:"Group name: ORG/NAME, or NAME for LOGIN/NAME"`
}

// Run implements group create.
func (c *GroupCreateCmd) Run(ctx *cliCtx) error {
	a, err := openAccount(ctx)
	if err != nil {
		return err
	}
	id, err := groupID(a, c.Group)
	if err != nil {
		return err
	}
	bg, cancel := timeout(time.Minute)
	defer cancel()
	gs, err := a.CreateGroup(bg, id)
	if err != nil {
		return err
	}
	fmt.Printf("✓ Created the group %s, with you as its admin.\n", id)
	fmt.Println("Next:")
	fmt.Printf("  let it read a project:   esec vault access grant %s --project ORG/REPO --env prod\n", id)
	fmt.Printf("  add people:              esec vault group add %s LOGIN\n", id)
	fmt.Printf("  a token for CI and new machines:  esec vault group token %s autoscale --expires 90d\n", id)
	fmt.Printf("  or, on a machine:        esec-vault machine join %s --server %s --fingerprint %s\n", id, a.State.Server, team.GroupWords(id, gs.Root()))
	return nil
}

// GroupGrantCmd sets what a group reads of a project.
type GroupGrantCmd struct {
	Group   string   `arg:"" help:"Group, such as acme/production"`
	Env     []string `name:"env" sep:"," required:"" help:"Environments the group may read (replaces what it read before)"`
	Project string   `help:"Project id (default: nearest .esec-project)"`
}

// Run implements group grant.
func (c *GroupGrantCmd) Run(ctx *cliCtx) error {
	project, err := projectFlag(c.Project)
	if err != nil {
		return err
	}
	return grantGroup(ctx, c.Group, project, c.Env)
}

// GroupRevokeCmd stops a group reading a project.
type GroupRevokeCmd struct {
	Group   string `arg:"" help:"Group, such as acme/production"`
	Project string `help:"Project id (default: nearest .esec-project)"`
}

// Run implements group revoke.
func (c *GroupRevokeCmd) Run(ctx *cliCtx) error {
	project, err := projectFlag(c.Project)
	if err != nil {
		return err
	}
	return grantGroup(ctx, c.Group, project, nil)
}

func grantGroup(ctx *cliCtx, group, project string, envs []string) error {
	a, err := openAccount(ctx)
	if err != nil {
		return err
	}
	id, err := groupID(a, group)
	if err != nil {
		return err
	}
	bg, cancel := timeout(2 * time.Minute)
	defer cancel()
	res, err := a.GrantGroup(bg, id, project, envs)
	if err != nil {
		return err
	}
	printGrant(id, project, envs, res)
	return nil
}

func printGrant(id, project string, envs []string, res *account.GrantResult) {
	switch {
	case len(envs) == 0 && (res.Granted || res.Trusted):
		fmt.Printf("✓ %s no longer reads %s.\n", id, project)
	case len(envs) == 0:
		fmt.Printf("%s did not read %s.\n", id, project)
	case res.Granted || res.Trusted:
		fmt.Printf("✓ %s reads %s of %s.\n", id, strings.Join(team.SortEnvs(envs), ", "), project)
	default:
		fmt.Printf("%s already reads %s of %s.\n", id, strings.Join(team.SortEnvs(envs), ", "), project)
	}
	if res.Sent {
		fmt.Println("  Sealed the keys to the group: its machines read them at once.")
	}
	if len(res.Missing) > 0 {
		fmt.Printf("  ! This device has no current key for %s; an admin of %s who has them sends them on their next sync.\n", strings.Join(res.Missing, ", "), project)
	}
	if res.NeedGroupAdmin {
		fmt.Printf("  ! An admin of %s still has to agree: esec vault group grant %s --project %s --env %s\n", id, id, project, strings.Join(envs, ","))
	}
	if res.NeedProjectAdmin {
		fmt.Printf("  ! An admin of %s still has to grant it: esec vault group grant %s --project %s --env %s\n", project, id, project, strings.Join(envs, ","))
	}
	printRotations(res.Exposed, id+" can no longer read")
}

// GroupTokenCmd creates an enrollment token.
type GroupTokenCmd struct {
	oidcFlags

	Group   string `arg:"" help:"Group, such as acme/production"`
	Name    string `arg:"" help:"Token name, such as autoscale or github-deploy"`
	Expires string `default:"90d" help:"How long the token works: 90d, 12h, or never"`
	Out     string `help:"Write the token to this file (0600), or - for standard output only"`
}

// oidcFlags bind a key to GitHub Actions jobs.
type oidcFlags struct {
	GitHubRepo        string   `name:"github-repo" help:"Hand its keys only to GitHub Actions jobs of this owner/name repository (OIDC)"`
	GitHubRepoID      int64    `name:"github-repo-id" help:"The repository's numeric id, which survives renames (gh api repos/OWNER/NAME --jq .id)"`
	GitHubRef         []string `name:"github-ref" sep:"," help:"Only these refs, e.g. refs/heads/main or refs/tags/v* (with --github-repo)"`
	GitHubEnvironment []string `name:"github-environment" sep:"," help:"Only jobs in these GitHub deployment environments (with --github-repo)"`
}

func (f oidcFlags) policy() (*team.OIDCPolicy, error) {
	if f.GitHubRepo == "" {
		if f.GitHubRepoID != 0 || len(f.GitHubRef) > 0 || len(f.GitHubEnvironment) > 0 {
			return nil, errors.New("--github-repo-id, --github-ref and --github-environment need --github-repo")
		}
		return nil, nil
	}
	p := &team.OIDCPolicy{Provider: team.ProviderGitHub, Repository: f.GitHubRepo, RepositoryID: f.GitHubRepoID, Refs: f.GitHubRef, Environments: f.GitHubEnvironment}
	return p, p.Validate()
}

// Run implements group token.
func (c *GroupTokenCmd) Run(ctx *cliCtx) error {
	var ttl time.Duration
	if e := strings.ToLower(strings.TrimSpace(c.Expires)); e != "never" && e != "0" {
		var err error
		if ttl, err = parseTTL(e); err != nil {
			return fmt.Errorf("%w: use a number of days such as 90d, hours such as 12h, or never", err)
		}
	}
	return newCred(ctx, c.Group, team.KindToken, c.Name, ttl, c.oidcFlags, c.Out)
}

// GroupAddMachineCmd creates a machine key.
type GroupAddMachineCmd struct {
	oidcFlags

	Group string `arg:"" help:"Group, such as acme/production"`
	Name  string `arg:"" help:"Machine name, such as web-1"`
	Out   string `help:"Write the key to this file (0600), or - for standard output only"`
}

// Run implements group add-machine.
func (c *GroupAddMachineCmd) Run(ctx *cliCtx) error {
	return newCred(ctx, c.Group, team.KindMachine, c.Name, 0, c.oidcFlags, c.Out)
}

func newCred(ctx *cliCtx, group, kind, name string, ttl time.Duration, flags oidcFlags, out string) error {
	policy, err := flags.policy()
	if err != nil {
		return err
	}
	a, err := openAccount(ctx)
	if err != nil {
		return err
	}
	id, err := groupID(a, group)
	if err != nil {
		return err
	}
	var expires time.Time
	if ttl > 0 {
		expires = a.Now().Add(ttl).UTC().Truncate(time.Second)
	}
	bg, cancel := timeout(time.Minute)
	defer cancel()
	key, err := a.NewCred(bg, id, kind, name, expires, policy)
	if err != nil {
		return err
	}
	info := os.Stdout
	if out == "-" {
		info = os.Stderr
	}
	what := "Machine"
	if kind == team.KindToken {
		what = "Token"
	}
	fmt.Fprintf(info, "✓ %s %s (%s) of %s: it reads whatever the group reads.\n", what, name, key.ID, id)
	if !expires.IsZero() {
		fmt.Fprintf(info, "  It works until %s.\n", expires.Local().Format("2006-01-02 15:04")) //nolint:gosmopolitan // shown to the local user
	}
	if policy != nil {
		fmt.Fprintf(info, "  Its keys are handed out only to %s; the job needs 'permissions: id-token: write'.\n", policy.Describe())
	}
	secret := key.String()
	switch out {
	case "-":
		fmt.Println(secret)
	case "":
		fmt.Fprintln(info, "\nIts key, shown once:")
		fmt.Fprintln(info, "\n  "+secret+"\n")
	default:
		if err := storage.Write(out, []byte(secret+"\n")); err != nil {
			return err
		}
		fmt.Fprintf(info, "  Wrote it to %s.\n", out)
	}
	if kind == team.KindToken {
		fmt.Fprintln(info, "Use it directly as the secret ESEC_VAULT_MACHINE_KEY of a CI job or app (gh secret set / fly secrets set),")
		fmt.Fprintln(info, "or let machines join with it:  ESEC_VAULT_ENROLL_TOKEN=... esec-vault machine join")
	} else {
		fmt.Fprintf(info, "On the machine, save it as %s (0600), or set ESEC_VAULT_MACHINE_KEY to it.\n", "/etc/esec-vault/machine.key")
	}
	fmt.Fprintln(info, "Then:  esec-vault machine run -- esec run prod -- ./your-command")
	return nil
}

// GroupApproveCmd lets machines in and signs web changes.
type GroupApproveCmd struct {
	Group string `arg:"" help:"Group, such as acme/production"`
	Words string `help:"The words the waiting machine shows, to approve it without asking"`
	Yes   bool   `help:"Sign removals asked for on the web without asking (access changes and machines are always asked)"`
}

// Run implements group approve.
func (c *GroupApproveCmd) Run(ctx *cliCtx) error {
	a, err := openAccount(ctx)
	if err != nil {
		return err
	}
	id, err := groupID(a, c.Group)
	if err != nil {
		return err
	}
	bg, cancel := timeout(10 * time.Minute)
	defer cancel()
	root, joins, err := a.PendingJoins(bg, id)
	if err != nil {
		return err
	}
	changes, err := a.Changes(bg)
	if err != nil {
		return err
	}
	changes = slices.DeleteFunc(changes, func(c account.ChangeView) bool { return c.Scope != wire.ScopeGroup || c.Target != id })
	if len(joins)+len(changes) == 0 {
		fmt.Printf("Nothing waits for approval in %s.\n", id)
		return nil
	}
	for _, j := range joins {
		words := team.JoinWords(id, root, team.Credential{ID: j.Machine, Name: j.Name, EncPub: j.EncPub, SignPub: j.SignPub})
		fmt.Printf("\nThe machine %s (%s) asks to join %s, from %s at %s.\n", safetext.Clean(j.Name), j.Machine, id, j.IP, j.Created.Local().Format("2006-01-02 15:04")) //nolint:gosmopolitan // shown to the local user
		var ok bool
		switch {
		case c.Words != "":
			ok = normalizeFingerprint(c.Words) == words
			if !ok {
				fmt.Println("  Its words are not the ones given; skipping it.")
				continue
			}
		default:
			fmt.Println("Type the words it shows (or press Enter to skip, 'no' to turn it away):")
			fmt.Fprint(os.Stderr, "> ")
			typed, err := readLine()
			if err != nil {
				return err
			}
			switch {
			case strings.EqualFold(strings.TrimSpace(typed), "no"):
				if err := a.RejectJoin(bg, id, j.ID); err != nil {
					return err
				}
				fmt.Println("  Turned it away.")
				continue
			case strings.TrimSpace(typed) == "":
				continue
			}
			ok = normalizeFingerprint(typed) == words
			if !ok {
				fmt.Println("  ! Those are not its words. Someone may be posing as it; it was not let in.")
				continue
			}
		}
		if err := a.ApproveJoin(bg, id, j); err != nil {
			return err
		}
		fmt.Printf("  ✓ Let %s in; it reads whatever %s reads.\n", safetext.Clean(j.Name), id)
	}
	return signChanges(bg, a, changes, c.Yes)
}

// GroupAddCmd adds a person to a group.
type GroupAddCmd struct {
	Group      string `arg:"" help:"Group, such as acme/backend"`
	Login      string `arg:"" help:"GitHub login of the person"`
	AccountKey string `help:"Their account key words, read to you over another channel, instead of their GitHub SSH proof"`
}

// Run implements group add.
func (c *GroupAddCmd) Run(ctx *cliCtx) error {
	a, err := openAccount(ctx)
	if err != nil {
		return err
	}
	id, err := groupID(a, c.Group)
	if err != nil {
		return err
	}
	bg, cancel := timeout(2 * time.Minute)
	defer cancel()
	res, err := a.AddGroupMember(bg, id, c.Login, c.AccountKey)
	if err != nil {
		return err
	}
	fmt.Printf("✓ Added %s to %s (checked with %s; account key %s).\n", safetext.Clean(res.Login), id, verifiedText(res.Verified), res.AccountWords)
	if len(res.Granted) > 0 {
		fmt.Printf("  They read %s; their devices pick up the keys on their next sync.\n", strings.Join(res.Granted, ", "))
	} else {
		fmt.Printf("  The group reads nothing yet: esec vault access grant %s --project ORG/REPO --env dev\n", id)
	}
	return nil
}

// GroupLeaveCmd leaves a group.
type GroupLeaveCmd struct {
	Group string `arg:"" help:"Group, such as acme/backend"`
	Yes   bool   `help:"Do not ask for confirmation"`
}

// Run implements group leave.
func (c *GroupLeaveCmd) Run(ctx *cliCtx) error {
	a, err := openAccount(ctx)
	if err != nil {
		return err
	}
	id, err := groupID(a, c.Group)
	if err != nil {
		return err
	}
	if !c.Yes && !confirm(fmt.Sprintf("Leave %s? You keep the keys you have; its admins should replace them.", id)) {
		return errors.New("cancelled")
	}
	bg, cancel := timeout(2 * time.Minute)
	defer cancel()
	if _, err := a.RemoveGroupMember(bg, id, a.State.Login, "left"); err != nil {
		return err
	}
	fmt.Printf("✓ Left %s. Its admins' devices give it a new key, and they are told to replace the keys you read.\n", id)
	return nil
}

// GroupRemoveCmd removes a person, machine or token.
type GroupRemoveCmd struct {
	Group     string `arg:"" help:"Group, such as acme/production"`
	Machine   string `arg:"" help:"Person (GitHub login), or machine or token (name or id)"`
	Reason    string `help:"Reason recorded in the group chain"`
	Destroyed bool   `help:"Its keys are gone with it (a deleted VM or container): nothing needs a new key"`
	Yes       bool   `help:"Do not ask for confirmation"`
}

// Run implements group remove.
func (c *GroupRemoveCmd) Run(ctx *cliCtx) error {
	a, err := openAccount(ctx)
	if err != nil {
		return err
	}
	id, err := groupID(a, c.Group)
	if err != nil {
		return err
	}
	if !c.Yes && !confirm(fmt.Sprintf("Remove %s from %s? It stops getting keys at once.", c.Machine, id)) {
		return errors.New("cancelled")
	}
	bg, cancel := timeout(5 * time.Minute)
	defer cancel()
	isPerson, err := groupPerson(bg, a, id, c.Machine)
	if err != nil {
		return err
	}
	var res *account.GroupRemoveResult
	if isPerson {
		if c.Destroyed {
			return errors.New("--destroyed is for machines; a person keeps what they read")
		}
		res, err = a.RemoveGroupMember(bg, id, c.Machine, c.Reason)
	} else {
		res, err = a.RemoveCred(bg, id, c.Machine, c.Reason, c.Destroyed)
	}
	if err != nil {
		return err
	}
	printRemoved(id, res)
	return nil
}

// groupPerson reports whether name is a member of a group rather than one
// of its machines or tokens, refusing a name that is both.
func groupPerson(ctx context.Context, a *account.Account, id, name string) (bool, error) {
	v, err := a.Group(ctx, id)
	if err != nil {
		return false, err
	}
	person, machine := false, false
	for _, m := range v.State.ActiveMembers() {
		person = person || strings.EqualFold(m.Login, name)
	}
	for _, c := range v.State.ActiveCreds("") {
		machine = machine || c.Name == name || c.ID == name
	}
	if person && machine {
		return false, fmt.Errorf("%s names both a member and a machine of %s; remove the machine by its id", name, id)
	}
	if !person && !machine {
		for _, ad := range v.State.ActiveAdmins() {
			if strings.EqualFold(ad.Login, name) {
				return false, fmt.Errorf("%s is an admin of %s; remove an admin with: esec vault group admin %s %s --remove", name, id, id, name)
			}
		}
	}
	return person, nil
}

func printRemoved(id string, res *account.GroupRemoveResult) {
	it, they := "it", "It"
	if res.Cred.Kind == "member" {
		it, they = "them", "They"
	}
	fmt.Printf("✓ Removed the %s %s from %s; the server no longer gives %s keys.\n", res.Cred.Kind, safetext.Clean(res.Cred.Name), id, it)
	printRotated(id, res)
	projects := make([]string, 0, len(res.Exposed))
	for p := range res.Exposed {
		projects = append(projects, p)
	}
	slices.Sort(projects)
	for _, p := range projects {
		fmt.Printf("! %s could read %s of %s. In that repository, give each a new key: esec vault env rotate ENV\n", they, strings.Join(res.Exposed[p], ", "), p)
	}
}

func printRotated(id string, res *account.GroupRemoveResult) {
	if !res.Rotated {
		return
	}
	fmt.Printf("  %s has a new group key, sealed to every machine still in it.\n", id)
	if len(res.Resealed) > 0 {
		fmt.Printf("  Sealed the keys of %s to it.\n", strings.Join(res.Resealed, ", "))
	}
	if len(res.Pending) > 0 {
		fmt.Printf("  The admins' devices of %s seal theirs on their next sync.\n", strings.Join(res.Pending, ", "))
	}
}

// GroupRotateCmd rotates the group key.
type GroupRotateCmd struct {
	Group  string `arg:"" help:"Group, such as acme/production"`
	Reason string `help:"Reason recorded in the group chain"`
}

// Run implements group rotate.
func (c *GroupRotateCmd) Run(ctx *cliCtx) error {
	a, err := openAccount(ctx)
	if err != nil {
		return err
	}
	id, err := groupID(a, c.Group)
	if err != nil {
		return err
	}
	bg, cancel := timeout(5 * time.Minute)
	defer cancel()
	res, err := a.RotateGroupKey(bg, id, c.Reason)
	if err != nil {
		return err
	}
	printRotated(id, res)
	return nil
}

// GroupAdminCmd adds or removes a group admin.
type GroupAdminCmd struct {
	Group      string `arg:"" help:"Group, such as acme/production"`
	Login      string `arg:"" help:"GitHub login of the admin"`
	AccountKey string `help:"Their account key words, read to you over another channel, instead of their GitHub SSH proof"`
	Remove     bool   `help:"Remove them as an admin (or yourself, to leave); the group gets a new key"`
}

// Run implements group admin.
func (c *GroupAdminCmd) Run(ctx *cliCtx) error {
	a, err := openAccount(ctx)
	if err != nil {
		return err
	}
	id, err := groupID(a, c.Group)
	if err != nil {
		return err
	}
	bg, cancel := timeout(2 * time.Minute)
	defer cancel()
	if c.Remove {
		res, err := a.RemoveGroupAdmin(bg, id, c.Login)
		if err != nil {
			return err
		}
		fmt.Printf("✓ %s is no longer an admin of %s.\n", c.Login, id)
		printRotated(id, res)
		return nil
	}
	res, err := a.AddGroupAdmin(bg, id, c.Login, c.AccountKey)
	if err != nil {
		return err
	}
	fmt.Printf("✓ %s is an admin of %s (checked by %s).\n", res.Login, id, verifiedText(res.Verified))
	return nil
}

func groupTodoText(g account.GroupTodo) string {
	return fmt.Sprintf("%d machine(s) wait to join", g.Joins)
}

func verifiedText(v string) string {
	if v == team.VerifiedAccountKey {
		return "the account key words you typed"
	}
	return "their GitHub SSH key"
}
