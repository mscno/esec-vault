package cli

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/mscno/esec/pkg/projectfile"
	coreseal "github.com/mscno/esec/pkg/seal"
	"github.com/tyler-smith/go-bip39"

	"github.com/mscno/esec-vault/internal/account"
	"github.com/mscno/esec-vault/internal/identity"
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
	Backup  bool     `default:"true" negatable:"" hidden:"" help:"Obsolete: backups are stored on the vault server"`
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
	opts := verify.Options{Roots: c.Root, History: c.History, Server: c.Server,
		OpenAccount: func() (*account.Account, error) { return openAccount(ctx) }}
	rep, runErr := verify.Run(bg, opts)
	if rep == nil {
		return runErr
	}
	// Only a full check is kept for doctor, the daemon and the Mac app.
	if c.History && c.Server {
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
		return fmt.Errorf("%d key(s) need attention (%d current keys not found, %d historical keys not found)", rep.Problems, rep.Lost, rep.HistoryMissing)
	}
	return nil
}

func printVerify(rep *verify.Report) {
	fmt.Printf("%d key(s) used by %d secrets file(s) in %d checkout(s), and their git history.\n", len(rep.Keys), rep.Files, rep.Checkouts)
	for _, s := range rep.Sources {
		switch {
		case s.Checked:
			fmt.Printf("  ✓ checked %s\n", s.Name)
			if s.Error != "" {
				fmt.Printf("    ! incomplete: %s\n", safetext.Clean(s.Error))
			}
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
		fmt.Println("  If one of them is yours, check its repository seals or ask a reader who can open it.")
	}
	if rep.OK() {
		fmt.Printf("✓ Every checked key is preserved in a repository seal with recovery recipients or in multiple keyring copies; none serves two projects.\n")
	}
}

// DrillCmd proves a cold recovery works: the newest backup opens with the
// recovery phrase alone, holds every key the checkouts use, and the
// recovery key opens the guard.
type DrillCmd struct {
	Remote  string `hidden:"" help:"Removed external backup destination"`
	History bool   `default:"true" negatable:"" help:"Also require the keys the checkouts' git history used"`
}

// Run implements drill.
func (c *DrillCmd) Run(ctx *cliCtx) error { //nolint:gocyclo // keep the ordered recovery proof and its failure boundaries together
	if c.Remote != "" {
		return errors.New("external backup sync was removed; drill checks your vault server backup")
	}
	bg, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	a, err := openAccount(ctx)
	if err != nil {
		return err
	}
	blob, err := a.Backup(bg)
	if err != nil {
		return fmt.Errorf("download the vault server backup: %w", err)
	}
	key := "vault server backup"
	fmt.Fprintln(os.Stderr, "Downloaded your encrypted vault server backup. The phrase opens it in memory; nothing is written.")
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
		return fmt.Errorf("the phrase does not open the vault server backup: %w", err)
	}
	fmt.Printf("✓ The phrase opens %s (generation %d, %s).\n", key, v.Generation, v.CreatedAt.Format(time.DateOnly))
	archived, err := a.VerifyArchive(bg, v)
	if err != nil {
		return fmt.Errorf("drill failed: archived project data is incomplete or corrupt: %w", err)
	}
	fmt.Printf("✓ All %d archived encrypted file revisions authenticate.\n", archived)

	n, failed := drillSeals(keys.Private)
	for _, f := range failed {
		fmt.Printf("  ✗ %s\n", safetext.Clean(f))
	}
	if len(failed) > 0 {
		return fmt.Errorf("drill failed: the phrase does not open %d sealed key(s); seal them again (esec vault seal sync in each checkout) and drill again", len(failed))
	}
	fmt.Printf("✓ The phrase alone opens all %d key(s) sealed in your checkouts, guarded ones too.\n", n)

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
	sealed, sealErr := verify.RepositorySource(bg, checkouts, c.History)
	if sealErr != nil {
		return sealErr
	}
	rep := verify.Build(uses, []verify.Source{{Name: "vault server backup", Projects: v.Projects}, sealed})
	if rep.Lost > 0 {
		for _, k := range rep.Keys {
			if k.Places == 0 && !k.Unheld {
				fmt.Printf("  ✗ %s… (%s %s) is not in the backup\n", k.Public[:12], safetext.Clean(k.Uses[0].Project), safetext.Clean(k.Uses[0].Env))
			}
		}
		return fmt.Errorf("drill failed: %d key(s) your checkouts use are not in the server backup or repository seals; sync a new one (esec vault sync --server) and drill again", rep.Lost)
	}
	if collectErr != nil {
		fmt.Fprintln(os.Stderr, "! "+collectErr.Error())
	}
	fmt.Printf("✓ The server backup and repository seals preserve all %d checked key(s) in %d checkout(s).\n", len(rep.Keys), len(checkouts))
	_ = verify.SaveDrill(time.Now().UTC())
	fmt.Println("Drill passed. Do it again every few months, and after changing the passphrase.")
	return nil
}

// drillSeals opens every seal in every checkout this machine knows with
// the recovery key alone, as a cold recovery would. It returns how many
// opened, and which did not.
func drillSeals(recoveryPriv [32]byte) (int, []string) {
	id, err := coreseal.X25519Identity(hex.EncodeToString(recoveryPriv[:]))
	if err != nil {
		return 0, []string{err.Error()}
	}
	reg, err := workspace.Load()
	if err != nil {
		return 0, []string{err.Error()}
	}
	n := 0
	var failed []string
	seen := map[string]bool{}
	for _, co := range reg.Checkouts {
		if workspace.Check(co) != workspace.StatusOK {
			continue
		}
		pf, err := projectfile.Load(co.Path)
		if err != nil || seen[pf.Project] {
			continue
		}
		seen[pf.Project] = true
		for _, env := range pf.Envs() {
			data, err := coreseal.Read(co.Path, env)
			if err != nil {
				continue
			}
			if _, err := coreseal.Open(data, pf.Project, env, pf.Env[env].Key, id); err != nil {
				failed = append(failed, pf.Project+" "+env+": "+err.Error())
				continue
			}
			n++
		}
	}
	return n, failed
}
