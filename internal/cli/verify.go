package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"filippo.io/age"
	"github.com/tyler-smith/go-bip39"

	"github.com/mscno/esec-vault/internal/account"
	"github.com/mscno/esec-vault/internal/guard"
	"github.com/mscno/esec-vault/internal/identity"
	"github.com/mscno/esec-vault/internal/keystore"
	"github.com/mscno/esec-vault/internal/remote"
	"github.com/mscno/esec-vault/internal/safetext"
	"github.com/mscno/esec-vault/internal/vaultfile"
	"github.com/mscno/esec-vault/internal/verify"
	"github.com/mscno/esec-vault/internal/workspace"
)

// VerifyCmd checks that no key can be lost.
type VerifyCmd struct {
	Root    []string `type:"path" help:"Also find (and remember) the checkouts under these directories, such as ~/src"`
	History bool     `default:"true" negatable:"" help:"Also check every key the checkouts' git history used"`
	Server  bool     `default:"true" negatable:"" help:"Check the vault server's copy"`
	Backup  bool     `default:"true" negatable:"" help:"Check the newest backup"`
	JSON    bool     `help:"Print JSON, for scripts, agents and the Mac app"`
	Last    bool     `help:"Print the last check (the background service runs one daily) instead of checking now"`
}

// Run implements verify.
func (c *VerifyCmd) Run(ctx *cliCtx) error {
	if c.Last {
		last, err := verify.LoadLast()
		if err != nil {
			return err
		}
		if c.JSON {
			return printJSON(last)
		}
		if last.At.IsZero() {
			fmt.Println("Keys never checked: esec vault verify")
			return nil
		}
		fmt.Printf("Last checked %s UTC.\n", last.At.UTC().Format(time.DateTime))
		if last.Report != nil {
			printVerify(last.Report)
		}
		return nil
	}
	bg, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	opts := verify.Options{Roots: c.Root, History: c.History, Server: c.Server, Backup: c.Backup, Keyring: ctx.Keyring,
		OpenAccount: func() (*account.Account, error) { return openAccount(ctx) }}
	rep, runErr := verify.Run(bg, opts)
	if rep == nil {
		return runErr
	}
	// Only a full check is kept for doctor, the daemon and the Mac app: one
	// that skipped places would report every key as held in one place.
	if c.History && c.Server && c.Backup {
		_ = verify.SaveLast(rep, runErr, time.Now().UTC())
	}
	if c.JSON {
		if err := printJSON(rep); err != nil {
			return err
		}
	} else {
		printVerify(rep)
	}
	if runErr != nil {
		fmt.Fprintln(os.Stderr, "! "+runErr.Error())
	}
	if !rep.OK() {
		return fmt.Errorf("%d key(s) need attention (%d lost)", rep.Problems, rep.Lost)
	}
	return nil
}

func printVerify(rep *verify.Report) {
	fmt.Printf("%d key(s) used by %d secrets file(s) in %d checkout(s), and their git history.\n", len(rep.Keys), rep.Files, rep.Checkouts)
	for _, s := range rep.Sources {
		switch {
		case s.Checked:
			fmt.Printf("  ✓ checked %s\n", s.Name)
		default:
			fmt.Printf("  - not checked: %s (%s)\n", s.Name, safetext.Clean(s.Error))
		}
	}
	if rep.Checkouts == 0 {
		fmt.Println("No checkouts known on this machine: esec vault verify --root ~/src finds them.")
	}
	for _, k := range rep.Keys {
		if len(k.Problems) == 0 || k.Unheld {
			continue
		}
		u := k.Uses[0]
		where := u.Path
		if u.Commit != "" {
			where += " (git history)"
		}
		fmt.Printf("\n%s… %s %s\n  used by %s", k.Public[:12], safetext.Clean(u.Project), safetext.Clean(u.Env), safetext.Clean(tildePath(where)))
		if len(k.Uses) > 1 {
			fmt.Printf(" and %d more", len(k.Uses)-1)
		}
		fmt.Println()
		for _, p := range k.Problems {
			fmt.Println("  ! " + safetext.Clean(p))
		}
	}
	if rep.Unheld > 0 {
		fmt.Printf("\n%d key(s) belong to projects you hold no key of anywhere checked (another person's project, or an environment you cannot read):\n", rep.Unheld)
		for _, k := range rep.Keys {
			if k.Unheld {
				fmt.Printf("  %s… %s %s\n", k.Public[:12], safetext.Clean(k.Uses[0].Project), safetext.Clean(k.Uses[0].Env))
			}
		}
		fmt.Println("  If one of them is yours, its key is lost: esec vault restore, or ask whoever holds it.")
	}
	if rep.OK() {
		fmt.Printf("✓ Every key is in at least two places, and none serves two projects.\n")
	}
}

// DrillCmd proves a cold recovery works: the newest backup opens with the
// recovery phrase alone, holds every key the checkouts use, and the
// recovery key opens the guard.
type DrillCmd struct {
	Remote  string `help:"Backup destination (default: the default one)"`
	History bool   `default:"true" negatable:"" help:"Also require the keys the checkouts' git history used"`
}

// Run implements drill.
func (c *DrillCmd) Run(_ *cliCtx) error {
	cfg, err := remote.Load()
	if err != nil {
		return err
	}
	if c.Remote == "" && cfg.Default == "" {
		return errors.New("no backup destination to drill: esec vault remote add")
	}
	bg, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	key, blob, err := remote.Latest(bg, cfg, c.Remote)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "Downloaded %s. Nothing is written to disk; the phrase opens it in memory.\n", key)
	mnemonic, err := promptMnemonic("Paste your 24-word recovery phrase: ")
	if err != nil {
		return err
	}
	if !bip39.IsMnemonicValid(mnemonic) {
		return errors.New("that is not a valid 24-word recovery phrase")
	}
	passphrase, err := promptSecret("Passphrase (empty if none): ")
	if err != nil {
		return err
	}
	keys, err := identity.DeriveMasterKeys(mnemonic, passphrase)
	if err != nil {
		return err
	}
	v, err := vaultfile.OpenWithMaster(blob, &keys.Public, &keys.Private)
	if err != nil {
		return fmt.Errorf("the phrase does not open the newest backup: %w", err)
	}
	fmt.Printf("✓ The phrase opens %s (generation %d, %s).\n", key, v.Generation, v.CreatedAt.Format(time.DateOnly))

	guarded, err := drillGuard(v.Projects, keys.Private)
	if err != nil {
		return err
	}
	if guarded >= 0 {
		fmt.Printf("✓ The recovery key opens the guard and its %d guarded key(s).\n", guarded)
	}

	reg, err := workspace.Load()
	if err != nil {
		return err
	}
	var checkouts []string
	for _, co := range reg.Checkouts {
		if workspace.Check(co) == workspace.StatusOK {
			checkouts = append(checkouts, co.Path)
		}
	}
	uses, _, collectErr := verify.Collect(bg, checkouts, c.History)
	rep := verify.Build(uses, []verify.Source{{Name: "backup", Projects: v.Projects}})
	if rep.Lost > 0 {
		for _, k := range rep.Keys {
			if k.Places == 0 && !k.Unheld {
				fmt.Printf("  ✗ %s… (%s %s) is not in the backup\n", k.Public[:12], safetext.Clean(k.Uses[0].Project), safetext.Clean(k.Uses[0].Env))
			}
		}
		return fmt.Errorf("drill failed: %d key(s) your checkouts use are not in the backup; push a new one (esec vault backup --verify --push) and drill again", rep.Lost)
	}
	if collectErr != nil {
		fmt.Fprintln(os.Stderr, "! "+collectErr.Error())
	}
	fmt.Printf("✓ It holds all %d key(s) your %d checkout(s) use.\n", len(rep.Keys), len(checkouts))
	_ = verify.SaveDrill(time.Now().UTC())
	fmt.Println("Drill passed. Do it again every few months, and after changing the passphrase.")
	return nil
}

// drillGuard opens the guard in v with the recovery key, and every guarded
// key with the guard. It returns -1 when there is no guard.
func drillGuard(projects map[string]map[string]string, recoveryPriv [32]byte) (int, error) {
	g, err := guard.FromEntries(projects["default"])
	if errors.Is(err, guard.ErrNotSetUp) {
		return -1, nil
	}
	if err != nil {
		return 0, err
	}
	s, err := guard.X25519IdentityString(recoveryPriv)
	if err != nil {
		return 0, err
	}
	rec, err := age.ParseX25519Identity(s)
	if err != nil {
		return 0, err
	}
	id, err := g.Open(rec)
	if err != nil {
		return 0, fmt.Errorf("the recovery key does not open the guard (was it set up with --no-recovery?): %w", err)
	}
	n := 0
	for p, entries := range projects {
		for k, val := range entries {
			if !keystore.IsGuardEntry(k) {
				continue
			}
			pub := strings.ToLower(strings.TrimPrefix(k, "ESEC_GUARD_"))
			if _, err := guard.Unwrap(id, val, pub, keystore.PublicHex); err != nil {
				return n, fmt.Errorf("guarded key %s… of %s does not open: %w", pub[:12], p, err)
			}
			n++
		}
	}
	return n, nil
}
