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
	Run    MachineRunCmd    `cmd:"" help:"(In the job) run a command with the machine's environment keys set."`
	Env    MachineEnvCmd    `cmd:"" help:"(In the job) print the machine's environment keys as variables."`
}

// MachineCreateCmd creates a machine.
type MachineCreateCmd struct {
	Name              string   `arg:"" help:"Machine name, e.g. deploy or ci"`
	Env               []string `name:"env" sep:"," required:"" help:"Environments it may read"`
	Project           string   `help:"Project id (default: nearest .esec-project)"`
	GitHubRepo        string   `name:"github-repo" help:"Hand its keys only to GitHub Actions jobs of this owner/name repository (OIDC)"`
	GitHubRepoID      int64    `name:"github-repo-id" help:"The repository's numeric id, which survives renames (gh api repos/OWNER/NAME --jq .id)"`
	GitHubRef         []string `name:"github-ref" sep:"," help:"Only these refs, e.g. refs/heads/main or refs/tags/v* (with --github-repo)"`
	GitHubEnvironment []string `name:"github-environment" sep:"," help:"Only jobs in these GitHub deployment environments (with --github-repo)"`
	Out               string   `help:"Write the machine key to this file (0600), or - for standard output only"`
}

// Run implements machine create.
func (c *MachineCreateCmd) Run(ctx *cliCtx) error {
	project, err := projectFlag(c.Project)
	if err != nil {
		return err
	}
	var policy *team.OIDCPolicy
	if c.GitHubRepo != "" {
		policy = &team.OIDCPolicy{Provider: team.ProviderGitHub, Repository: c.GitHubRepo, RepositoryID: c.GitHubRepoID, Refs: c.GitHubRef, Environments: c.GitHubEnvironment}
		if err := policy.Validate(); err != nil {
			return err
		}
	} else if c.GitHubRepoID != 0 || len(c.GitHubRef) > 0 || len(c.GitHubEnvironment) > 0 {
		return errors.New("--github-repo-id, --github-ref and --github-environment need --github-repo")
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
	if policy != nil {
		fmt.Fprintf(info, "  Its keys are handed out only to %s; the job needs 'permissions: id-token: write'.\n", policy.Describe())
	}
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
	Project string `help:"Project id (default: nearest .esec-project)"`
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
	Project string `help:"Project id (default: nearest .esec-project)"`
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
	key, err := machine.Load()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	token, err := machine.GitHubToken(ctx, key.Server)
	if err != nil {
		return nil, err
	}
	return machine.Fetch(ctx, key, token)
}

// MachineRunCmd runs a command with the machine's keys.
type MachineRunCmd struct {
	Env     []string `name:"env" sep:"," help:"Only these environments (default: every one the machine reads)"`
	Command []string `arg:"" passthrough:"" help:"Command to run"`
}

// Run implements machine run.
func (c *MachineRunCmd) Run(ctx *cliCtx) error {
	keys, err := fetchMachineKeys()
	if err != nil {
		return err
	}
	env, err := keys.Environ(os.Environ(), c.Env)
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
	Env    []string `name:"env" sep:"," help:"Only these environments (default: every one the machine reads)"`
	Format string   `default:"env" enum:"env,github" help:"env: NAME=value lines; github: append to $GITHUB_ENV and mask the values"`
}

// Run implements machine env.
func (c *MachineEnvCmd) Run(ctx *cliCtx) error {
	keys, err := fetchMachineKeys()
	if err != nil {
		return err
	}
	lines, err := keys.Environ(nil, c.Env)
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
