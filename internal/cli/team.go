package cli

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/mscno/esec-vault/internal/account"
	"github.com/mscno/esec-vault/internal/safetext"
	"github.com/mscno/esec-vault/internal/share"
	"github.com/mscno/esec-vault/internal/sshagent"
	"github.com/mscno/esec-vault/internal/team"
	"github.com/mscno/esec-vault/internal/wire"
)

// TeamCmd shares projects through the vault server.
type TeamCmd struct {
	List    TeamListCmd    `cmd:"" default:"withargs" help:"List your shared projects (default)."`
	Show    TeamShowCmd    `cmd:"" help:"Show a shared project: members, machines, keys and what needs doing."`
	Create  TeamCreateCmd  `cmd:"" help:"Share this project with your team, as its first admin."`
	Add     TeamAddCmd     `cmd:"" help:"Add a member and send them the keys they may read."`
	Set     TeamSetCmd     `cmd:"" help:"Change what a member reads, or make them an admin."`
	Remove  TeamRemoveCmd  `cmd:"" help:"Remove a member."`
	Leave   TeamLeaveCmd   `cmd:"" help:"Leave a shared project."`
	Sync    TeamSyncCmd    `cmd:"" help:"Receive keys sent to you and, as an admin, send keys others are missing."`
	Publish TeamPublishCmd `cmd:"" help:"Make this device's key for an environment the project's key (a new environment, or one rotated by hand)."`
	Prove   TeamProveCmd   `cmd:"" help:"Prove with your GitHub SSH key that your vault account is yours, so admins can add you."`
}

// TeamListCmd lists shared projects.
type TeamListCmd struct {
	JSON bool `help:"Print JSON, for scripts and agents"`
}

// Run implements team list.
func (c *TeamListCmd) Run(ctx *cliCtx) error {
	a, err := openAccount(ctx)
	if err != nil {
		return err
	}
	bg, cancel := timeout(time.Minute)
	defer cancel()
	list, err := a.TeamSummaries(bg)
	if err != nil {
		return err
	}
	if c.JSON {
		return printJSON(nonNil(list))
	}
	if len(list) == 0 {
		fmt.Println("No shared projects. Share one from its repository with: esec vault team create")
		return nil
	}
	for _, p := range list {
		role := "reads " + joinOr(p.Envs, "nothing")
		if p.Admin {
			role = "admin"
		}
		extra := ""
		if p.Rotations > 0 {
			extra = fmt.Sprintf("  %d key(s) to rotate", p.Rotations)
		}
		fmt.Printf("%-32s %-24s %d member(s), %d machine(s)%s\n", p.ID, role, p.Members, p.Machines, extra)
	}
	return nil
}

func joinOr(list []string, empty string) string {
	if len(list) == 0 {
		return empty
	}
	return strings.Join(list, ", ")
}

// projectFlag resolves --project or the nearest .esec-project.
func projectFlag(p string) (string, error) {
	id, err := resolveProject(p)
	if err != nil {
		return "", fmt.Errorf("name the project with --project org/repo, or run this in its repository: %w", err)
	}
	return id, team.ValidProject(id)
}

// TeamShowCmd shows one shared project.
type TeamShowCmd struct {
	Project string `help:"Project id (default: nearest .esec-project)"`
	JSON    bool   `help:"Print JSON, for scripts and agents"`
}

// Run implements team show.
func (c *TeamShowCmd) Run(ctx *cliCtx) error {
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
	v, err := a.Team(bg, project)
	if err != nil {
		return err
	}
	st := v.State
	keys := map[string]map[string]string{}
	for _, h := range v.Status.Holders {
		keys[h.ID] = h.Envs
	}
	if c.JSON {
		return printJSON(teamJSON(project, a.State.Server, v, keys))
	}
	fmt.Printf("%s  (%d signed changes; %s/teams/%s)\n", project, st.Seq, a.State.Server, project)
	fmt.Println("Environments:")
	for _, n := range st.EnvNames() {
		e := st.Envs[n]
		fmt.Printf("  %-12s %s\n", n, e.PublicKey)
	}
	fmt.Println("Members:")
	for _, m := range st.ActiveMembers() {
		role := "reads " + joinOr(m.Envs, "nothing")
		if m.Admin {
			role = "admin"
		}
		fmt.Printf("  %-20s %-28s %s\n", safetext.Clean(m.Login), role, keyStates(keys[m.User]))
	}
	if ms := st.ActiveMachines(); len(ms) > 0 {
		fmt.Println("Machines:")
		for _, m := range ms {
			from := "anywhere with its key"
			if m.OIDC != nil {
				from = m.OIDC.Describe()
			}
			fmt.Printf("  %-20s reads %-20s %s; %s\n", safetext.Clean(m.Name), strings.Join(m.Envs, ", "), keyStates(keys[m.ID]), from)
		}
	}
	if gs := st.ActiveGroups(); len(gs) > 0 {
		fmt.Println("Machine groups:")
		for _, g := range gs {
			fmt.Printf("  %-20s reads %-20s %s\n", g.Group, strings.Join(g.Envs, ", "), keyStates(keys[team.GroupHolder(g.Group)]))
		}
	}
	for _, e := range st.Rotations() {
		var who []string
		for _, x := range e.Exposed {
			who = append(who, safetext.Clean(x.Name)+" ("+x.Reason+")")
		}
		fmt.Printf("! %s needs a new key: %s may still hold it. Run in the repository: esec vault env rotate %s\n", e.Name, strings.Join(who, ", "), e.Name)
	}
	for _, n := range team.SortEnvs(mapKeys(v.GroupExposed)) {
		var who []string
		for _, x := range v.GroupExposed[n] {
			who = append(who, safetext.Clean(x.Name)+" ("+x.Reason+")")
		}
		fmt.Printf("! %s needs a new key: %s may still hold it. Run in the repository: esec vault env rotate %s\n", n, strings.Join(who, ", "), n)
	}
	return nil
}

func mapKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func keyStates(m map[string]string) string {
	if len(m) == 0 {
		return ""
	}
	names := make([]string, 0, len(m))
	for n := range m {
		names = append(names, n)
	}
	sort.Strings(names)
	parts := make([]string, 0, len(names))
	for _, n := range names {
		state := m[n]
		if state == wire.KeyMissing {
			state = "not sent"
		}
		parts = append(parts, n+": "+state)
	}
	return "[" + strings.Join(parts, ", ") + "]"
}

// TeamCreateCmd creates a shared project.
type TeamCreateCmd struct {
	Project string   `help:"Project id (default: nearest .esec-project)"`
	Env     []string `name:"env" sep:"," help:"Environments to share (default: every environment in your keyring for the project)"`
}

// Run implements team create.
func (c *TeamCreateCmd) Run(ctx *cliCtx) error {
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
	st, err := a.CreateTeam(bg, project, c.Env)
	if err != nil {
		return err
	}
	fmt.Printf("✓ Shared %s with you as its admin. Environments: %s.\n", project, strings.Join(st.EnvNames(), ", "))
	fmt.Println("Add people with: esec vault team add LOGIN --env dev")
	fmt.Printf("See it on the web: %s/teams/%s\n", a.State.Server, project)
	return nil
}

// TeamAddCmd adds a member.
type TeamAddCmd struct {
	Login      string   `arg:"" help:"GitHub login of the person to add"`
	Env        []string `name:"env" sep:"," help:"Environments they may read"`
	Admin      bool     `help:"Make them an admin: they read every environment and manage the project"`
	AccountKey string   `help:"Their account key words, read to you over another channel, instead of their GitHub SSH proof"`
	Project    string   `help:"Project id (default: nearest .esec-project)"`
}

// Run implements team add.
func (c *TeamAddCmd) Run(ctx *cliCtx) error {
	project, err := projectFlag(c.Project)
	if err != nil {
		return err
	}
	if !c.Admin && len(c.Env) == 0 {
		return errors.New("say what they may read with --env dev[,prod], or make them an admin with --admin")
	}
	a, err := openAccount(ctx)
	if err != nil {
		return err
	}
	bg, cancel := timeout(2 * time.Minute)
	defer cancel()
	res, err := a.AddMember(bg, project, c.Login, c.Admin, c.Env, c.AccountKey)
	if err != nil {
		return err
	}
	how := "their GitHub SSH key"
	if res.Verified == team.VerifiedAccountKey {
		how = "the account key words you typed"
	}
	fmt.Printf("✓ Added %s to %s (checked with %s; account key %s).\n", safetext.Clean(res.Login), project, how, res.AccountWords)
	if len(res.Granted) > 0 {
		fmt.Printf("  Sent the keys of %s, sealed to their key; their devices pick them up on their own.\n", strings.Join(res.Granted, ", "))
	}
	if len(res.Missing) > 0 {
		fmt.Printf("  This device has no current key for %s; an admin's device that has it sends it on its next sync.\n", strings.Join(res.Missing, ", "))
	}
	return nil
}

// TeamSetCmd changes a member's access.
type TeamSetCmd struct {
	Login   string   `arg:"" help:"GitHub login of the member"`
	Env     []string `name:"env" sep:"," help:"Every environment they may read from now on"`
	Admin   bool     `help:"Make them an admin" xor:"role"`
	NoAdmin bool     `help:"Make them a member who reads only --env" xor:"role"`
	Project string   `help:"Project id (default: nearest .esec-project)"`
	Yes     bool     `help:"Do not ask for confirmation when they lose access"`
}

// Run implements team set.
func (c *TeamSetCmd) Run(ctx *cliCtx) error {
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
	admin := c.Admin
	if !c.Admin && !c.NoAdmin {
		v, err := a.Team(bg, project)
		if err != nil {
			return err
		}
		for _, m := range v.State.ActiveMembers() {
			if strings.EqualFold(m.Login, c.Login) {
				admin = m.Admin && len(c.Env) == 0
			}
		}
	}
	if !admin && len(c.Env) == 0 && !c.Yes && !confirm(fmt.Sprintf("%s would read no environment of %s. Continue?", c.Login, project)) {
		return errors.New("cancelled")
	}
	res, err := a.UpdateMember(bg, project, c.Login, admin, c.Env)
	if err != nil {
		return err
	}
	fmt.Printf("✓ Updated %s in %s.\n", c.Login, project)
	if len(res.Granted) > 0 {
		fmt.Printf("  Sent the keys of %s.\n", strings.Join(res.Granted, ", "))
	}
	if len(res.Missing) > 0 {
		fmt.Printf("  This device has no current key for %s; another admin's device sends it.\n", strings.Join(res.Missing, ", "))
	}
	printRotations(res.Exposed, c.Login+" can no longer read")
	return nil
}

func printRotations(envs []string, why string) {
	if len(envs) == 0 {
		return
	}
	fmt.Printf("! %s %s, but may still hold their keys. In the project's repository, give each a new key:\n", why, strings.Join(envs, ", "))
	for _, e := range envs {
		fmt.Printf("    esec vault env rotate %s\n", e)
	}
	fmt.Println("  and change the secret values themselves where they may have been seen.")
}

// TeamRemoveCmd removes a member.
type TeamRemoveCmd struct {
	Login   string `arg:"" help:"GitHub login of the member"`
	Reason  string `help:"Reason recorded in the project chain"`
	Project string `help:"Project id (default: nearest .esec-project)"`
	Yes     bool   `help:"Do not ask for confirmation"`
}

// Run implements team remove.
func (c *TeamRemoveCmd) Run(ctx *cliCtx) error {
	project, err := projectFlag(c.Project)
	if err != nil {
		return err
	}
	if !c.Yes && !confirm(fmt.Sprintf("Remove %s from %s?", c.Login, project)) {
		return errors.New("cancelled")
	}
	a, err := openAccount(ctx)
	if err != nil {
		return err
	}
	bg, cancel := timeout(2 * time.Minute)
	defer cancel()
	could, err := a.RemoveMember(bg, project, c.Login, c.Reason)
	if err != nil {
		return err
	}
	fmt.Printf("✓ Removed %s from %s. The other members are told.\n", c.Login, project)
	printRotations(could, c.Login+" could read")
	return nil
}

// TeamLeaveCmd leaves a project.
type TeamLeaveCmd struct {
	Project string `help:"Project id (default: nearest .esec-project)"`
	Yes     bool   `help:"Do not ask for confirmation"`
}

// Run implements team leave.
func (c *TeamLeaveCmd) Run(ctx *cliCtx) error {
	project, err := projectFlag(c.Project)
	if err != nil {
		return err
	}
	if !c.Yes && !confirm(fmt.Sprintf("Leave %s? You keep the keys you have; an admin should replace them.", project)) {
		return errors.New("cancelled")
	}
	a, err := openAccount(ctx)
	if err != nil {
		return err
	}
	bg, cancel := timeout(2 * time.Minute)
	defer cancel()
	if _, err := a.RemoveMember(bg, project, a.State.Login, "left"); err != nil {
		return err
	}
	fmt.Printf("✓ Left %s. Its admins are told so they can replace the keys you held.\n", project)
	return nil
}

// TeamSyncCmd runs a team sync.
type TeamSyncCmd struct {
	Yes bool `help:"Accept every shared project you were added to without asking"`
}

// Run implements team sync.
func (c *TeamSyncCmd) Run(ctx *cliCtx) error {
	a, err := openAccount(ctx)
	if err != nil {
		return err
	}
	bg, cancel := timeout(5 * time.Minute)
	defer cancel()
	accept := func(inv account.Invite) bool {
		reads := "you read " + joinOr(inv.Envs, "nothing")
		if inv.Admin {
			reads = "you are an admin"
		}
		fmt.Printf("%s added you to the shared project %s (%s).\n", safetext.Clean(inv.AddedBy), inv.Project, reads)
		return c.Yes || confirm("Take in its keys on this device? Say no if you did not expect it")
	}
	res, err := a.TeamSync(bg, account.TeamSyncOptions{Interactive: true, Accept: accept})
	if err != nil {
		return err
	}
	printTeamSync(res)
	if len(res.Imported) > 0 {
		markDirty("team sync")
	}
	return nil
}

func printTeamSync(res *account.TeamSyncResult) {
	for _, s := range res.Imported {
		fmt.Println("  + " + s)
	}
	for _, s := range res.Sent {
		fmt.Println("  → " + safetext.Clean(s))
	}
	for _, s := range res.Conflicts {
		fmt.Printf("  ! %s: kept this device's own key; run 'esec vault team sync' in a terminal to replace it\n", s)
	}
	for _, s := range res.Dropped {
		fmt.Println("  - dropped an out-of-date grant: " + safetext.Clean(s))
	}
	for _, s := range res.Unsent {
		fmt.Println("  ! no current key here to send " + safetext.Clean(s))
	}
	for _, s := range res.Elsewhere {
		fmt.Println("  · your account, on another device: " + safetext.Clean(s))
	}
	for _, s := range res.Problems {
		fmt.Println("  ! " + safetext.Clean(s))
	}
	for _, inv := range res.Invites {
		fmt.Printf("  ! did not take in the keys of %s; run 'esec vault team sync' again to accept it\n", inv.Project)
	}
	projects := make([]string, 0, len(res.Rotations))
	for p := range res.Rotations {
		projects = append(projects, p)
	}
	sort.Strings(projects)
	for _, p := range projects {
		if res.Admin[p] {
			fmt.Printf("  ! %s: %s need(s) a new key: esec vault env rotate ENV --project %s\n", p, strings.Join(res.Rotations[p], ", "), p)
		} else {
			fmt.Printf("  ! %s: %s need(s) a new key, since someone who could read it left; an admin replaces it\n", p, strings.Join(res.Rotations[p], ", "))
		}
	}
	for _, g := range res.GroupTodos {
		fmt.Printf("  ! %s: %s; approve on this device with: esec vault group approve %s\n", g.Group, groupTodoText(g), g.Group)
	}
	if res.Changes > 0 {
		fmt.Printf("  ! %d change(s) made on the web wait for you to sign them: esec vault changes\n", res.Changes)
	}
	for _, g := range res.GroupRotations {
		fmt.Printf("  ! %s: a removed machine still holds the group key: esec vault group rotate %s\n", g, g)
	}
	if len(res.Imported)+len(res.Sent)+len(res.Conflicts)+len(res.Dropped)+len(res.Unsent)+len(res.Rotations)+len(res.Invites)+len(res.Problems)+len(res.GroupTodos)+len(res.GroupRotations)+res.Changes == 0 {
		fmt.Println("✓ Shared projects are up to date.")
	}
}

// TeamPublishCmd publishes an environment key.
type TeamPublishCmd struct {
	Env     string `arg:"" help:"Environment name"`
	Project string `help:"Project id (default: nearest .esec-project)"`
}

// Run implements team publish.
func (c *TeamPublishCmd) Run(ctx *cliCtx) error {
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
	res, err := a.PublishEnv(bg, project, c.Env, "published")
	if err != nil {
		return err
	}
	fmt.Printf("✓ %s %s is now %s.\n", project, c.Env, res.PublicKey)
	if len(res.Sent) > 0 {
		fmt.Printf("  Sent it to %s.\n", strings.Join(res.Sent, ", "))
	}
	return nil
}

// TeamProveCmd publishes a GitHub SSH proof of the account.
type TeamProveCmd struct {
	SSHKey string `name:"ssh-key" help:"SSH private key file (or its .pub, for a key in your agent) registered on GitHub; default: the first agent key GitHub lists for you"`
}

// Run implements team prove.
func (c *TeamProveCmd) Run(ctx *cliCtx) error {
	a, err := openAccount(ctx)
	if err != nil {
		return err
	}
	bg, cancel := timeout(2 * time.Minute)
	defer cancel()
	sign := func(msg []byte) ([]byte, error) {
		if c.SSHKey != "" {
			return share.SignWithKeyFile(c.SSHKey, team.ProofNamespace, msg)
		}
		return signWithAgentGitHubKey(a.State.Login, msg)
	}
	if err := a.ProveAccount(bg, sign); err != nil {
		return err
	}
	fmt.Printf("✓ Published proof that this vault account belongs to GitHub user %s. Admins can now add you with: esec vault team add %s --env ENV\n", a.State.Login, a.State.Login)
	return nil
}

// signWithAgentGitHubKey signs with the first SSH-agent key that GitHub
// lists for login.
func signWithAgentGitHubKey(login string, msg []byte) ([]byte, error) {
	ag, err := sshagent.Dial()
	if err != nil {
		return nil, fmt.Errorf("%w; or pass --ssh-key with a key file registered on GitHub", err)
	}
	defer ag.Close()
	gh, err := share.FetchGitHubKeys(login, nil, "")
	if err != nil {
		return nil, err
	}
	keys, err := ag.Keys()
	if err != nil {
		return nil, err
	}
	for i := range keys {
		k := &keys[i]
		for _, g := range gh {
			if string(g.Marshal()) != string(k.Public.Marshal()) || sshagent.Supported(k.Public) != nil {
				continue
			}
			sig, err := ag.Sign(k, team.ProofNamespace, msg)
			if err != nil {
				return nil, err
			}
			return share.ArmorSSHSIG(k.Public, team.ProofNamespace, sig), nil
		}
	}
	return nil, fmt.Errorf("none of the keys in your SSH agent is an Ed25519 or RSA key registered on GitHub for %s; pass --ssh-key", login)
}

// sharedProject reports whether project is a shared project, and refuses
// when it is one this account cannot change keys of. It is false, without
// an error, when this machine is not signed in or the server is down.
func sharedProject(ctx *cliCtx, project string) (bool, error) {
	a, err := openAccount(ctx)
	if err != nil {
		// Not signed in: the project is local only.
		return false, nil
	}
	bg, cancel := timeout(30 * time.Second)
	defer cancel()
	shared, admin, err := a.SharedRole(bg, project)
	if err != nil {
		ctx.Logger.Debug("could not check whether the project is shared", "error", err)
		return false, nil
	}
	if shared && !admin {
		return true, fmt.Errorf("%s is a shared project and only its admins change its keys; ask one of them", project)
	}
	return shared, nil
}

// publishShared publishes a new or rotated key of a shared project and
// tells the person what happened.
func publishShared(ctx *cliCtx, project, env, reason string) {
	a, err := openAccount(ctx)
	if err != nil {
		fmt.Printf("! Publish the new %s key to the team with: esec vault team publish %s\n", env, env)
		return
	}
	bg, cancel := timeout(2 * time.Minute)
	defer cancel()
	res, err := a.PublishEnv(bg, project, env, reason)
	if err != nil {
		fmt.Printf("! The team does not have the new %s key yet (%v). Retry with: esec vault team publish %s --project %s\n", env, err, env, project)
		return
	}
	if len(res.Sent) > 0 {
		fmt.Printf("✓ Sent the new %s key to %s.\n", env, strings.Join(res.Sent, ", "))
	} else {
		fmt.Printf("✓ The team's %s key is now %s.\n", env, res.PublicKey)
	}
}
