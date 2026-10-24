package cli

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/mscno/esec-vault/internal/account"
	"github.com/mscno/esec-vault/internal/kms"
	"github.com/mscno/esec-vault/internal/safetext"
)

// TodoCmd lists what waits for you across every project, group and
// organisation.
type TodoCmd struct {
	JSON bool `help:"Print JSON, for scripts and agents"`
}

// Run implements todo.
func (c *TodoCmd) Run(ctx *cliCtx) error {
	a, err := openAccount(ctx)
	if err != nil {
		return err
	}
	bg, cancel := timeout(10 * time.Minute)
	defer cancel()
	list, err := a.Todos(bg)
	if err != nil {
		return err
	}
	if c.JSON {
		return printJSON(nonNil(list))
	}
	if len(list) == 0 {
		fmt.Println("✓ Nothing waits for you.")
		return nil
	}
	kind := ""
	titles := map[string]string{"rotate": "Keys to rotate", "changes": "Changes to sign", "joins": "Machines asking to join", "org-confirm": "Organisations to confirm", "org-left": "People who left, still in", "workload-key": "Workloads on keys not approved"}
	for _, t := range list {
		if t.Kind != kind {
			kind = t.Kind
			fmt.Println(titles[kind] + ":")
		}
		line := "  " + safetext.Clean(t.Text)
		if t.Command != "" {
			line += "\n      " + safetext.Clean(t.Command)
		}
		fmt.Println(line)
	}
	return nil
}

// OrgWorkloadsCmd lists an organisation's workloads.
type OrgWorkloadsCmd struct {
	Org          string `arg:"" help:"Organisation, such as acme"`
	KMS          string `name:"kms" help:"Only those using this approved key"`
	NeverStarted bool   `name:"never-started" help:"Only those that never fetched their keys"`
	Idle         string `help:"Only those not started for this long, such as 30d"`
	Problems     bool   `help:"Only those on a key the organisation does not approve for them"`
	JSON         bool   `help:"Print JSON, for scripts and agents"`
}

// Run implements org workloads.
func (c *OrgWorkloadsCmd) Run(ctx *cliCtx) error {
	var idle time.Duration
	if c.Idle != "" {
		var err error
		if idle, err = parseTTL(c.Idle); err != nil {
			return fmt.Errorf("--idle: %w: use days such as 30d", err)
		}
	}
	a, err := openAccount(ctx)
	if err != nil {
		return err
	}
	bg, cancel := timeout(5 * time.Minute)
	defer cancel()
	list, err := a.Workloads(bg, strings.ToLower(c.Org))
	if err != nil {
		return err
	}
	now := a.Now()
	var out []account.WorkloadView
	for _, w := range list {
		switch {
		case c.KMS != "" && w.KMS != c.KMS,
			c.NeverStarted && !w.LastUsed.IsZero(),
			idle > 0 && !w.LastUsed.IsZero() && now.Sub(w.LastUsed) < idle,
			c.Problems && w.KeyProblem == "":
			continue
		}
		out = append(out, w)
	}
	if c.JSON {
		return printJSON(nonNil(out))
	}
	if len(out) == 0 {
		fmt.Println("No workloads match.")
		return nil
	}
	for _, w := range out {
		last := "never started"
		if !w.LastUsed.IsZero() {
			last = "started " + w.LastUsed.Local().Format("2006-01-02 15:04") //nolint:gosmopolitan // shown to the local user
		}
		key := w.KMS
		if key == "" {
			key = "unapproved key"
		}
		fmt.Printf("%-28s %-24s %-16s %s\n", safetext.Clean(w.Group), safetext.Clean(w.Name), safetext.Clean(key), last)
		if w.KeyProblem != "" {
			fmt.Println("    ! " + safetext.Clean(w.KeyProblem))
		}
	}
	fmt.Printf("%d workload(s). Descriptors: --json\n", len(out))
	return nil
}

// OrgRekeyCmd moves workloads to another approved key, across groups.
type OrgRekeyCmd struct {
	Org    string `arg:"" help:"Organisation, such as acme"`
	To     string `required:"" help:"The approved key to move to"`
	From   string `help:"Only workloads using this approved key (default: all that do not use --to)"`
	DryRun bool   `name:"dry-run" help:"Only list what would move"`
	Yes    bool   `help:"Do not ask"`
	JSON   bool   `help:"Print JSON, for scripts and agents"`
}

// Run implements org rekey.
func (c *OrgRekeyCmd) Run(ctx *cliCtx) error {
	a, err := openAccount(ctx)
	if err != nil {
		return err
	}
	bg, cancel := timeout(30 * time.Minute)
	defer cancel()
	org := strings.ToLower(c.Org)
	plan, err := a.RekeyOrg(bg, org, c.From, c.To, true)
	if err != nil {
		return err
	}
	if c.DryRun || len(plan) == 0 {
		if c.JSON {
			return printJSON(nonNil(plan))
		}
		if len(plan) == 0 {
			fmt.Println("Nothing to move among the groups you administer.")
		}
		for _, r := range plan {
			fmt.Printf("  %s %s\n", safetext.Clean(r.Group), safetext.Clean(r.Name))
		}
		return nil
	}
	if !c.Yes && !confirm(fmt.Sprintf("Move %d workload(s) of %s to the key %s?", len(plan), org, c.To)) {
		return errors.New("not moved")
	}
	done, err := a.RekeyOrg(bg, org, c.From, c.To, false)
	if err != nil {
		return err
	}
	if c.JSON {
		return printJSON(nonNil(done))
	}
	failed := 0
	for _, r := range done {
		switch {
		case r.Error != "":
			failed++
			fmt.Printf("  ! %s %s: %s\n", safetext.Clean(r.Group), safetext.Clean(r.Name), safetext.Clean(r.Error))
		case r.Done:
			fmt.Printf("  ✓ %s %s\n", safetext.Clean(r.Group), safetext.Clean(r.Name))
		}
	}
	fmt.Println("Their descriptors stay; they unwrap with the new key from their next start. If the old key may be compromised, also: esec vault group rotate GROUP")
	if failed > 0 {
		return fmt.Errorf("%d workload(s) not moved", failed)
	}
	return nil
}

// kmsKeyFromOrg returns an organisation's approved key, for commands that
// take --kms NAME instead of the key's names.
func kmsKeyFromOrg(a *account.Account, group, name string) (kms.Key, error) {
	bg, cancel := timeout(time.Minute)
	defer cancel()
	k, err := a.OrgKMSKey(bg, orgName(group), name)
	if err != nil {
		return kms.Key{}, err
	}
	return k.Key, nil
}
