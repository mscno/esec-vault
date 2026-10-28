package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/mscno/esec-vault/internal/machine"
	"github.com/mscno/esec-vault/internal/runcmd"
	"github.com/mscno/esec-vault/internal/safetext"
	"github.com/mscno/esec-vault/internal/storage"
	"github.com/mscno/esec-vault/internal/team"
)

// MachineCmd manages machine identities: keys for CI jobs and apps.
type MachineCmd struct {
	Create MachineCreateCmd `cmd:"" help:"Give a CI job or app its own key to a shared project's environments."`
	List   MachineListCmd   `cmd:"" help:"List a shared project's machines."`
	Remove MachineRemoveCmd `cmd:"" help:"Remove a machine; its key stops working."`
	Join   MachineJoinCmd   `cmd:"" help:"(On the machine) join a machine group: with an enrollment token at once, or by asking an admin."`
	Whoami MachineWhoamiCmd `cmd:"" help:"(On the machine) show which machine this is and what it reads."`
	Run    MachineRunCmd    `cmd:"" help:"(On the machine) run a command with the machine's environment keys set."`
	Env    MachineEnvCmd    `cmd:"" help:"(On the machine) print the machine's environment keys as variables."`
}

// MachineCreateCmd creates a machine.
type MachineCreateCmd struct {
	oidcFlags

	Name    string   `arg:"" help:"Machine name, e.g. deploy or ci"`
	Env     []string `name:"env" sep:"," required:"" help:"Environments it may read"`
	Project string   `help:"Project id (default: nearest esec.toml)"`
	Out     string   `help:"Write the machine key to this file (0600), or - for standard output only"`
}

// Run implements machine create.
func (c *MachineCreateCmd) Run(ctx *cliCtx) error {
	project, err := projectFlag(c.Project)
	if err != nil {
		return err
	}
	policy, err := c.policy()
	if err != nil {
		return err
	}
	a, err := openAccount(ctx)
	if err != nil {
		return err
	}
	bg, cancel := timeout(2 * time.Minute)
	defer cancel()
	key, err := a.CreateMachine(bg, project, c.Name, c.Env, policy)
	if err != nil {
		return err
	}
	token := key.Token()
	info := os.Stdout
	if c.Out == "-" {
		info = os.Stderr
	}
	fmt.Fprintf(info, "✓ Machine %s (%s) reads %s of %s.\n", c.Name, key.ID, strings.Join(team.SortEnvs(c.Env), ", "), project)
	printPolicy(info, policy)
	switch c.Out {
	case "-":
		fmt.Println(token)
	case "":
		fmt.Fprintln(info, "\nIts key, shown once (store it as the secret ESEC_VAULT_MACHINE_KEY of the job or app):")
		fmt.Fprintln(info, "\n  "+token+"\n")
	default:
		if err := storage.Write(c.Out, []byte(token+"\n")); err != nil {
			return err
		}
		fmt.Fprintf(info, "  Wrote its key to %s; store it as the secret ESEC_VAULT_MACHINE_KEY, then delete the file.\n", c.Out)
	}
	fmt.Fprintln(info, "For example:  gh secret set ESEC_VAULT_MACHINE_KEY   or   fly secrets set ESEC_VAULT_MACHINE_KEY=...")
	fmt.Fprintln(info, "In the job:   esec-vault machine run -- esec run "+team.SortEnvs(c.Env)[0]+" -- ./your-command")
	return nil
}

// MachineListCmd lists machines.
type MachineListCmd struct {
	Project string `help:"Project id (default: nearest esec.toml)"`
	JSON    bool   `help:"Print JSON, for scripts and agents"`
}

// Run implements machine list.
func (c *MachineListCmd) Run(ctx *cliCtx) error {
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
	used := map[string]time.Time{}
	for _, h := range v.Status.Holders {
		used[h.ID] = h.LastUsed
	}
	ms := v.State.ActiveMachines()
	if c.JSON {
		return printJSON(machinesJSON(ms, used))
	}
	if len(ms) == 0 {
		fmt.Println("No machines. Create one with: esec vault machine create NAME --env ENV")
		return nil
	}
	for _, m := range ms {
		last := "never used"
		if t := used[m.ID]; !t.IsZero() {
			last = "last used " + t.Local().Format("2006-01-02 15:04") //nolint:gosmopolitan // shown to the local user
		}
		from := "anywhere with its key"
		if m.OIDC != nil {
			from = m.OIDC.Describe()
		}
		fmt.Printf("%-16s %-18s reads %-20s %s; %s\n", m.ID, safetext.Clean(m.Name), strings.Join(m.Envs, ", "), last, from)
	}
	return nil
}

// MachineRemoveCmd removes a machine.
type MachineRemoveCmd struct {
	Machine string `arg:"" help:"Machine name or id"`
	Reason  string `help:"Reason recorded in the project chain"`
	Project string `help:"Project id (default: nearest esec.toml)"`
	Yes     bool   `help:"Do not ask for confirmation"`
}

// Run implements machine remove.
func (c *MachineRemoveCmd) Run(ctx *cliCtx) error {
	project, err := projectFlag(c.Project)
	if err != nil {
		return err
	}
	if !c.Yes && !confirm(fmt.Sprintf("Remove machine %s from %s? Its key stops working at once.", c.Machine, project)) {
		return errors.New("cancelled")
	}
	a, err := openAccount(ctx)
	if err != nil {
		return err
	}
	bg, cancel := timeout(time.Minute)
	defer cancel()
	m, err := a.RemoveMachine(bg, project, c.Machine, c.Reason)
	if err != nil {
		return err
	}
	fmt.Printf("✓ Removed machine %s; the server no longer gives it keys.\n", m.Name)
	printRotations(m.Envs, "It could read")
	return nil
}

// fetchMachineKeys loads the machine key and fetches its keys.
func fetchMachineKeys() (*machine.Keys, error) {
	cred, err := machine.LoadCredential()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	token, err := machine.WorkloadToken(ctx, cred.Server())
	if err != nil {
		return nil, err
	}
	keys, err := cred.Fetch(ctx, token)
	if err != nil {
		return nil, err
	}
	for _, p := range keys.Problems {
		fmt.Fprintln(os.Stderr, "esec-vault: warning:", p)
	}
	return keys, nil
}

// machineProject is --project, else the nearest esec.toml, else "".
func machineProject(flag string) string {
	if flag != "" {
		return flag
	}
	p, err := resolveProject("")
	if err != nil {
		return ""
	}
	return p
}

// MachineRunCmd runs a command with the machine's keys.
type MachineRunCmd struct {
	Env     []string `name:"env" sep:"," help:"Only these environments (default: every one the machine reads)"`
	Project string   `help:"Project whose keys are also set by environment name (default: nearest esec.toml, or the only one)"`
	Command []string `arg:"" passthrough:"" help:"Command to run"`
}

// Run implements machine run.
func (c *MachineRunCmd) Run(ctx *cliCtx) error {
	keys, err := fetchMachineKeys()
	if err != nil {
		return err
	}
	env, err := keys.Environ(os.Environ(), machineProject(c.Project), c.Env)
	if err != nil {
		return err
	}
	cmd := c.Command
	if len(cmd) > 0 && cmd[0] == "--" {
		cmd = cmd[1:]
	}
	err = runcmd.Exec(cmd, env)
	var ee *runcmd.ExitError
	if errors.As(err, &ee) {
		return &forwardedExitError{code: ee.Code}
	}
	return err
}

// MachineEnvCmd prints the machine's keys.
type MachineEnvCmd struct {
	Env     []string `name:"env" sep:"," help:"Only these environments (default: every one the machine reads)"`
	Project string   `help:"Project whose keys are also set by environment name (default: nearest esec.toml, or the only one)"`
	Format  string   `default:"env" enum:"env,github" help:"env: NAME=value lines; github: append to $GITHUB_ENV and mask the values"`
}

// Run implements machine env.
func (c *MachineEnvCmd) Run(ctx *cliCtx) error {
	keys, err := fetchMachineKeys()
	if err != nil {
		return err
	}
	lines, err := keys.Environ(nil, machineProject(c.Project), c.Env)
	if err != nil {
		return err
	}
	if c.Format == "env" {
		for _, l := range lines {
			fmt.Println(l)
		}
		return nil
	}
	path := os.Getenv("GITHUB_ENV")
	if path == "" {
		return errors.New("GITHUB_ENV is not set; --format github works in GitHub Actions only")
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0) //nolint:gosec // GitHub Actions' own file
	if err != nil {
		return err
	}
	defer f.Close()
	for _, l := range lines {
		name, value, _ := strings.Cut(l, "=")
		fmt.Println("::add-mask::" + value)
		if _, err := fmt.Fprintf(f, "%s=%s\n", name, value); err != nil {
			return err
		}
		fmt.Fprintln(os.Stderr, "set", name)
	}
	return nil
}

// MachineJoinCmd joins this host to a machine group.
type MachineJoinCmd struct {
	Group       string `arg:"" optional:"" help:"Group to join, such as acme/production (not needed with --token)"`
	Server      string `help:"Vault server URL (not needed with --token)" env:"ESEC_VAULT_SERVER"`
	Name        string `help:"This machine's name (default: the host name)"`
	Token       string `help:"Enrollment token from 'esec vault group token' (or @file): join at once, without an admin" env:"ESEC_VAULT_ENROLL_TOKEN"`
	Fingerprint string `help:"The group's fingerprint words from 'esec vault group show', so the server cannot put this machine in a look-alike group"`
	File        string `help:"Where to keep this machine's key (default: /etc/esec-vault/machine.key as root on Linux, else in the esec config directory)"`
}

// Run implements machine join.
func (c *MachineJoinCmd) Run(ctx *cliCtx) error {
	name := c.Name
	if name == "" {
		h, err := os.Hostname()
		if err != nil {
			return errors.New("name the machine with --name")
		}
		name = strings.Split(h, ".")[0]
	}
	file := c.File
	if file == "" {
		file = machine.DefaultFile()
	}
	if _, err := os.Stat(file); err == nil {
		return fmt.Errorf("this host already has a machine key in %s; remove it to join again", file)
	}
	opts := machine.JoinOptions{Group: c.Group, Server: c.Server, Name: name, Fingerprint: c.Fingerprint}
	bg, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	if c.Token != "" {
		v := c.Token
		if path, ok := strings.CutPrefix(v, "@"); ok {
			data, err := os.ReadFile(path) //nolint:gosec // the operator names the file
			if err != nil {
				return err
			}
			v = string(data)
		}
		tok, err := team.ParseCredKey(v)
		if err != nil {
			return err
		}
		if c.Group != "" && c.Group != tok.Group {
			return fmt.Errorf("the token is for %s, not %s", tok.Group, c.Group)
		}
		opts.Token, opts.Group = tok, tok.Group
		if opts.OIDCToken, err = machine.WorkloadToken(bg, tok.Server); err != nil {
			return err
		}
	} else {
		if c.Group == "" || c.Server == "" {
			return errors.New("name the group and --server, or join with --token")
		}
		fmt.Fprintf(os.Stderr, "Asking to join %s as %s...\n", c.Group, name)
		shown := false
		opts.Wait = func(words string) bool {
			if !shown {
				fmt.Fprintf(os.Stderr, "\nAn admin of %s lets this machine in from their device with:\n\n  esec vault group approve %s\n\nand checks that it shows these words:\n\n  %s\n\nWaiting (Ctrl-C to stop)...\n", c.Group, c.Group, words)
				shown = true
			}
			return true
		}
	}
	key, err := machine.Join(bg, opts)
	if err != nil {
		return err
	}
	if err := machine.SaveKey(file, key); err != nil {
		return err
	}
	fmt.Printf("✓ This machine is %s (%s) in %s. Its key is in %s.\n", name, key.ID, key.Group, file)
	if file != machine.DefaultFile() {
		fmt.Printf("  Point %s at it, or set %s=@%s.\n", machine.FileEnv, machine.KeyEnv, file)
	}
	fmt.Println("Run commands with its keys:  esec-vault machine run -- esec run prod -- ./your-command")
	return nil
}

// MachineWhoamiCmd shows the machine and what it reads.
type MachineWhoamiCmd struct {
	JSON bool `help:"Print JSON, for scripts and agents"`
}

// Run implements machine whoami.
func (c *MachineWhoamiCmd) Run(ctx *cliCtx) error {
	cred, err := machine.LoadCredential()
	if err != nil {
		return err
	}
	keys, err := fetchMachineKeys()
	if err != nil {
		return err
	}
	if c.JSON {
		return printJSON(whoamiJSON(cred, keys))
	}
	where := "project " + keys.Project
	if keys.Group != "" {
		kind := "machine"
		switch {
		case cred.Workload != nil:
			kind = "workload (keys unwrapped with its KMS key)"
		case cred.Group.Kind() == team.KindToken:
			kind = "token"
		}
		where = kind + " of the group " + keys.Group
	}
	fmt.Printf("%s (%s), %s, on %s\nKey from %s\n", safetext.Clean(keys.Name), keys.Machine, where, cred.Server(), cred.From)
	ids := keys.ProjectIDs()
	if len(ids) == 0 {
		fmt.Println("It reads no project yet.")
	}
	for _, p := range ids {
		fmt.Printf("  %-32s %s\n", p, strings.Join(keys.Names(p), ", "))
	}
	return nil
}
