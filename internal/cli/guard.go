package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/mscno/esec/pkg/projectfile"

	"github.com/mscno/esec-vault/internal/guard"
	"github.com/mscno/esec-vault/internal/keystore"
	"github.com/mscno/esec-vault/internal/safetext"
	"github.com/mscno/esec-vault/internal/seal"
	"github.com/mscno/esec-vault/internal/securitykey"
	"github.com/mscno/esec-vault/internal/workspace"
)

// GuardCmd guards environments: their keys are sealed to the readers'
// security keys only, so every read needs a touch no agent can make.
type GuardCmd struct {
	Status  GuardStatusCmd  `cmd:"" default:"withargs" help:"Which environments are guarded, in every checkout here, and your security keys (default)."`
	Enable  GuardEnableCmd  `cmd:"" help:"Guard environments: seal their keys to the readers' security keys only."`
	Disable GuardDisableCmd `cmd:"" help:"Stop guarding environments: seal their keys to the readers' user keys again."`
}

// guardProject is a project with guarded environments.
type guardProject struct {
	Project string   `json:"project"`
	Envs    []string `json:"envs"`
	Keys    int      `json:"keys"`
	// Clear lists guarded environments whose key is still in this
	// device's keyring (from before they were guarded).
	Clear []string `json:"clear,omitempty"`
}

// guardStatus is what guard prints, for people, agents and the Mac app.
type guardStatus struct {
	// SetUp is whether this person has a security key to guard with.
	SetUp bool `json:"set_up"`
	// Holders are the recipients of this person's security keys.
	Holders  []string       `json:"holders"`
	Projects []guardProject `json:"projects"`
}

// readGuardStatus reads the guarded environments of every checkout this
// machine knows, and this person's security keys.
func readGuardStatus() (*guardStatus, error) {
	out := &guardStatus{Holders: []string{}, Projects: []guardProject{}}
	registered, err := securitykey.Mine(context.Background(), nil)
	if err != nil {
		return nil, err
	}
	for _, k := range registered {
		out.Holders = append(out.Holders, k.Recipient)
	}
	standIns, err := guard.StandInRecipients()
	if err != nil {
		return nil, err
	}
	out.SetUp = len(registered)+len(standIns) > 0
	reg, err := workspace.Load()
	if err != nil {
		return nil, err
	}
	ks := keystore.New()
	seen := map[string]bool{}
	for _, co := range reg.Checkouts {
		if seen[co.Project] || workspace.Check(co) != workspace.StatusOK {
			continue
		}
		pf, err := projectfile.Load(co.Path)
		if err != nil {
			continue
		}
		seen[co.Project] = true
		gp := guardProject{Project: pf.Project}
		entries, _ := ks.Read(pf.Project)
		for _, env := range pf.Envs() {
			e := pf.Env[env]
			if !seal.Guarded(e.Guard) {
				continue
			}
			gp.Envs = append(gp.Envs, env)
			gp.Keys++
			if e.Key != "" && entries[keystore.PubEntry(e.Key)] != "" {
				gp.Clear = append(gp.Clear, env)
			}
		}
		if len(gp.Envs) > 0 {
			out.Projects = append(out.Projects, gp)
		}
	}
	sort.Slice(out.Projects, func(i, j int) bool { return out.Projects[i].Project < out.Projects[j].Project })
	return out, nil
}

// GuardStatusCmd shows the guard.
type GuardStatusCmd struct {
	JSON bool `help:"Print JSON, for scripts and agents"`
}

// Run implements guard.
func (c *GuardStatusCmd) Run(_ *cliCtx) error {
	st, err := readGuardStatus()
	if err != nil {
		return err
	}
	if c.JSON {
		return printJSON(st)
	}
	if !st.SetUp {
		fmt.Println("No security key yet: plug in your YubiKey and run esec vault security-keys add.")
	} else {
		fmt.Printf("%d registered security key(s) open guarded environments: esec vault security-keys\n", len(st.Holders))
	}
	if len(st.Projects) == 0 {
		fmt.Println("No guarded environment in the checkouts here. Guard prod with: esec vault guard enable --env prod")
		return nil
	}
	for _, p := range st.Projects {
		fmt.Printf("%-34s %s\n", safetext.Clean(p.Project), strings.Join(p.Envs, ", "))
		if len(p.Clear) > 0 {
			fmt.Printf("  ! still in this device's keyring: %s; esec vault guard enable --project %s\n", strings.Join(p.Clear, ", "), p.Project)
		}
	}
	return nil
}

// GuardEnableCmd guards environments.
type GuardEnableCmd struct {
	Env     []string `name:"env" sep:"," help:"Environments to guard, such as prod (default: every environment esec.toml guards)"`
	Project string   `help:"Project id (default: the checkout here)"`
	Level   string   `default:"touch" enum:"touch,session" help:"touch: every read needs a touch; session: one touch per broker session"`
}

// Run implements guard enable.
func (c *GuardEnableCmd) Run(ctx *cliCtx) error {
	return setGuard(ctx, c.Project, c.Env, c.Level, true)
}

// GuardDisableCmd stops guarding environments.
type GuardDisableCmd struct {
	Env     []string `name:"env" sep:"," required:"" help:"Environments to stop guarding"`
	Project string   `help:"Project id (default: the checkout here)"`
}

// Run implements guard disable.
func (c *GuardDisableCmd) Run(ctx *cliCtx) error {
	return setGuard(ctx, c.Project, c.Env, projectfile.GuardNone, false)
}

// setGuard reseals envs at level. Guarding also removes the key from this
// device's keyring, where it was cached in the clear.
func setGuard(ctx *cliCtx, project string, envs []string, level string, enable bool) error {
	root, pf, err := checkoutFor(project)
	if err != nil {
		return err
	}
	if len(envs) == 0 && enable {
		for _, env := range pf.Envs() {
			if seal.Guarded(pf.Env[env].Guard) {
				envs = append(envs, env)
			}
		}
	}
	if len(envs) == 0 {
		return errors.New("name the environments: --env prod")
	}
	s, err := newSealing(ctx)
	if err != nil {
		return err
	}
	for _, env := range envs {
		if err := guardOne(s, root, pf, env, level, enable); err != nil {
			return err
		}
	}
	fmt.Println("Commit .esec/ and esec.toml. Other devices that cached the key keep it until they run esec vault guard enable there; rotate (esec vault env rotate ENV) to be sure no copy is left.")
	return nil
}

// guardOne reseals one environment at level (none given: esec.toml's, else
// touch) and keeps this device's keyring in step: guarded keys leave it,
// unguarded ones are cached.
func guardOne(s *sealing, root string, pf *projectfile.File, env, level string, enable bool) error {
	if err := validateEnvName(env); err != nil {
		return err
	}
	e, ok := pf.Env[env]
	if !ok || e.Key == "" {
		return fmt.Errorf("%s has no environment %s", pf.Project, env)
	}
	k, err := s.open(root, pf, env, fmt.Sprintf("change how %s is guarded", env))
	if err != nil {
		return err
	}
	want := level
	if enable && !seal.Guarded(want) {
		want = e.GuardLevel()
		if !seal.Guarded(want) {
			want = projectfile.GuardTouch
		}
	}
	if k.Guard != want {
		readers, err := readersOf(pf, env)
		if err != nil {
			return err
		}
		if err := s.seal(root, pf, env, k.Private, want, readers); err != nil {
			return err
		}
	}
	if enable {
		gone, err := s.ks.Forget(pf.Project, k.Private)
		if err != nil {
			return err
		}
		if len(gone) > 0 {
			fmt.Fprintf(os.Stderr, "Removed %s's key from this device's keyring; it opens only with a touch now.\n", env)
		}
	} else if err := s.cache(pf.Project, env, k.Private); err != nil {
		return err
	}
	fmt.Printf("✓ %s %s: %s\n", pf.Project, env, guardText(want))
	return nil
}

func guardText(level string) string {
	switch level {
	case projectfile.GuardTouch:
		return "guarded: every read needs a touch of a reader's security key"
	case projectfile.GuardSession:
		return "guarded: one touch opens it for a broker session"
	}
	return "not guarded: readers' devices open it"
}

// checkoutFor returns the checkout of project (or the one here) and its
// esec.toml.
func checkoutFor(project string) (string, *projectfile.File, error) {
	pf, root, err := projectRoot(".")
	if err == nil && (project == "" || pf.Project == project) {
		return root, pf, nil
	}
	if project == "" {
		return "", nil, fmt.Errorf("no esec.toml here or above: pass --project: %w", projectfile.ErrNotFound)
	}
	if dir := checkoutOf(project); dir != "" {
		pf, err := projectfile.Load(dir)
		if err != nil {
			return "", nil, err
		}
		return dir, pf, nil
	}
	return "", nil, fmt.Errorf("no checkout of %s on this machine (esec vault projects scan DIR)", project)
}
