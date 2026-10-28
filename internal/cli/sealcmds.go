package cli

import (
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/mscno/esec/pkg/projectfile"
	coreseal "github.com/mscno/esec/pkg/seal"
	"github.com/tyler-smith/go-bip39"

	"github.com/mscno/esec-vault/internal/identity"
	"github.com/mscno/esec-vault/internal/safetext"
	"github.com/mscno/esec-vault/internal/seal"
	"github.com/mscno/esec-vault/internal/workspace"
)

// SealCmd manages the keys sealed in repositories.
type SealCmd struct {
	Status  SealStatusCmd  `cmd:"" default:"withargs" help:"Who each environment's key is sealed to, and what needs sealing again (default)."`
	Sync    SealSyncCmd    `cmd:"" help:"Seal again what changed (readers, their security keys, people who signed up) and open what this device can into its cache."`
	Check   SealCheckCmd   `cmd:"" help:"Check the seals with no network: every key sealed, recorded, signed, with a recovery key."`
	Migrate SealMigrateCmd `cmd:"" help:"Seal every environment whose key this device holds but no seal does yet."`
	Recover SealRecoverCmd `cmd:"" help:"Open every seal with your recovery phrase and seal it again for its readers, with no security key."`
}

// sealTarget is one checkout a seal command works on.
type sealTarget struct {
	root string
	pf   *projectfile.File
}

// sealTargets are the checkout here (or of project), or with all, one
// checkout of every project this machine knows.
func sealTargets(project string, all bool) ([]sealTarget, error) {
	if !all {
		root, pf, err := checkoutFor(project)
		if err != nil {
			return nil, err
		}
		return []sealTarget{{root, pf}}, nil
	}
	reg, err := workspace.Load()
	if err != nil {
		return nil, err
	}
	var out []sealTarget
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
		out = append(out, sealTarget{co.Path, pf})
	}
	return out, nil
}

// sealView is one environment's seal, as seal status shows it.
type sealView struct {
	Project string           `json:"project"`
	Root    string           `json:"root"`
	Env     string           `json:"env"`
	Guard   string           `json:"guard"`
	Sealed  bool             `json:"sealed"`
	Readers []sealReaderView `json:"readers"`
	// Stale says why it should be sealed again; StaleError why that could
	// not be told (offline, a reader's chain unreachable).
	Stale      []string       `json:"stale,omitempty"`
	StaleError string         `json:"stale_error,omitempty"`
	Problems   []seal.Problem `json:"problems,omitempty"`
}

type sealReaderView struct {
	Reader  string `json:"reader"`
	Display string `json:"display"`
	Keys    int    `json:"keys"`
	Pending string `json:"pending,omitempty"`
}

// SealStatusCmd shows seals.
type SealStatusCmd struct {
	Project string `help:"Project id (default: the checkout here)"`
	All     bool   `help:"Every project with a checkout on this machine"`
	JSON    bool   `help:"Print JSON, for scripts, agents and the Mac app"`
}

// Run implements seal status.
func (c *SealStatusCmd) Run(ctx *cliCtx) error {
	targets, err := sealTargets(c.Project, c.All)
	if err != nil {
		return err
	}
	s, err := newSealing(ctx)
	if err != nil {
		return err
	}
	views := []sealView{}
	for _, t := range targets {
		views = append(views, sealViews(s, t)...)
	}
	if c.JSON {
		return printJSON(views)
	}
	stale := 0
	for _, v := range views {
		mark := "✓"
		switch {
		case !v.Sealed:
			mark = "✗"
		case len(v.Stale) > 0:
			mark, stale = "→", stale+1
		}
		var names []string
		for _, r := range v.Readers {
			n := r.Display
			if r.Pending != "" {
				n += " (pending)"
			}
			names = append(names, n)
		}
		fmt.Printf("%s %-28s %-8s %-7s %s\n", mark, safetext.Clean(v.Project), safetext.Clean(v.Env), v.Guard, safetext.Clean(strings.Join(names, ", ")))
		for _, w := range v.Stale {
			fmt.Printf("    seal again: %s\n", safetext.Clean(w))
		}
		if v.StaleError != "" {
			fmt.Printf("    could not tell whether to seal again: %s\n", safetext.Clean(v.StaleError))
		}
		for _, p := range v.Problems {
			if p.Level == seal.Fail {
				fmt.Printf("    ! %s\n", safetext.Clean(p.Detail))
			}
		}
	}
	if stale > 0 {
		fmt.Printf("\n%d seal(s) to make again: esec vault seal sync%s\n", stale, map[bool]string{true: " --all", false: ""}[c.All])
	}
	return nil
}

// sealViews describes a checkout's seals.
func sealViews(s *sealing, t sealTarget) []sealView {
	recs, _ := seal.LoadRecords(t.root)
	problems := seal.Check(t.pf, recs, func(env string) ([]byte, error) { return coreseal.Read(t.root, env) })
	var out []sealView
	for _, env := range t.pf.Envs() {
		e := t.pf.Env[env]
		if e.Key == "" {
			continue
		}
		v := sealView{Project: t.pf.Project, Root: t.root, Env: env, Guard: e.GuardLevel(), Readers: []sealReaderView{}}
		rec := recs[env]
		if rec != nil {
			v.Sealed = true
			for _, sf := range rec.Readers {
				r, err := seal.ParseReader(sf.Reader)
				display := sf.Reader
				if err == nil {
					display = r.Display()
				}
				v.Readers = append(v.Readers, sealReaderView{Reader: sf.Reader, Display: display, Keys: len(sf.Recipients), Pending: sf.Pending})
			}
		}
		if why, err := seal.Stale(s.bg(), s.dir, e, rec, s.sign); err == nil {
			v.Stale = why
		} else {
			v.StaleError = err.Error()
		}
		for _, p := range problems {
			if p.Env == env {
				v.Problems = append(v.Problems, p)
			}
		}
		out = append(out, v)
	}
	return out
}

// SealSyncCmd reseals what changed.
type SealSyncCmd struct {
	Project string `help:"Project id (default: the checkout here)"`
	All     bool   `help:"Every project with a checkout on this machine"`
	Guarded bool   `help:"Only guarded environments (after adding or removing a security key)"`
}

// Run implements seal sync.
func (c *SealSyncCmd) Run(ctx *cliCtx) error {
	targets, err := sealTargets(c.Project, c.All)
	if err != nil {
		return err
	}
	s, err := newSealing(ctx)
	if err != nil {
		return err
	}
	resealed, opened, failed := 0, 0, 0
	for _, t := range targets {
		recs, err := seal.LoadRecords(t.root)
		if err != nil {
			return err
		}
		for _, env := range t.pf.Envs() {
			e := t.pf.Env[env]
			if e.Key == "" || (c.Guarded && !seal.Guarded(e.Guard)) {
				continue
			}
			why, err := seal.Stale(s.bg(), s.dir, e, recs[env], s.sign)
			if err != nil {
				fmt.Fprintf(os.Stderr, "! %s %s: %s\n", t.pf.Project, env, err)
				failed++
				continue
			}
			if len(why) == 0 {
				continue
			}
			if err := resealEnv(s, t, env, nil); err != nil {
				var cannot *cannotOpenError
				if errors.As(err, &cannot) {
					// Only a reader who can open it can seal it again.
					fmt.Fprintf(os.Stderr, "→ %s %s should be sealed again (%s), by one of its readers who can open it: %s\n", t.pf.Project, env, strings.Join(why, "; "), cannot.err)
					continue
				}
				fmt.Fprintf(os.Stderr, "✗ %s %s: %s\n", t.pf.Project, env, err)
				failed++
				continue
			}
			fmt.Printf("✓ %s %s sealed again (%s)\n", t.pf.Project, env, strings.Join(why, "; "))
			resealed++
		}
		opened += s.unsealAll(t.root, t.pf)
	}
	if resealed+opened == 0 && failed == 0 {
		fmt.Println("✓ Every seal is current.")
	}
	if opened > 0 {
		fmt.Printf("Opened %d key(s) into this device's keyring.\n", opened)
	}
	if resealed > 0 {
		fmt.Println("Commit .esec/ and esec.toml in each repository.")
	}
	if failed > 0 {
		return fmt.Errorf("%d seal(s) could not be made again", failed)
	}
	return nil
}

// resealEnv opens env's key and seals it again for readers (nil: the ones
// esec.toml names).
func resealEnv(s *sealing, t sealTarget, env string, readers []seal.Reader) error {
	k, err := s.open(t.root, t.pf, env, "seal it again for its readers")
	if err != nil {
		return &cannotOpenError{err}
	}
	if readers == nil {
		if readers, err = readersOf(t.pf, env); err != nil {
			return err
		}
	}
	return s.seal(t.root, t.pf, env, k.Private, k.Guard, readers)
}

// cannotOpenError is an environment this person cannot open, to seal it again.
type cannotOpenError struct{ err error }

func (e *cannotOpenError) Error() string { return "cannot open it here: " + e.err.Error() }
func (e *cannotOpenError) Unwrap() error { return e.err }

// SealCheckCmd checks seals without a network.
type SealCheckCmd struct {
	Root string `type:"path" help:"Where to look (default: the checkout here)"`
	JSON bool   `help:"Print JSON, for scripts and agents"`
}

// Run implements seal check.
func (c *SealCheckCmd) Run(_ *cliCtx) error {
	pf, root, err := projectRoot(c.Root)
	if err != nil {
		return err
	}
	recs, err := seal.LoadRecords(root)
	if err != nil {
		return err
	}
	problems := seal.Check(pf, recs, func(env string) ([]byte, error) { return coreseal.Read(root, env) })
	if c.JSON {
		if err := printJSON(nonNil(problems)); err != nil {
			return err
		}
	}
	failed := 0
	for _, p := range problems {
		if !c.JSON {
			mark := "!"
			if p.Level == seal.Fail {
				mark = "✗"
			}
			fmt.Printf("%s %s: %s\n", mark, p.Env, safetext.Clean(p.Detail))
			if p.Fix != "" {
				fmt.Println("    " + p.Fix)
			}
		}
		if p.Level == seal.Fail {
			failed++
		}
	}
	if failed > 0 {
		return fmt.Errorf("%d seal problem(s)", failed)
	}
	if !c.JSON && len(problems) == 0 {
		fmt.Printf("✓ Every key of %s is sealed, signed, and recoverable.\n", pf.Project)
	}
	return nil
}

// SealMigrateCmd seals keys this device holds but no seal does yet.
type SealMigrateCmd struct {
	Project string `help:"Project id (default: the checkout here)"`
	All     bool   `help:"Every project with a checkout on this machine"`
}

// Run implements seal migrate.
func (c *SealMigrateCmd) Run(ctx *cliCtx) error {
	targets, err := sealTargets(c.Project, c.All)
	if err != nil {
		return err
	}
	s, err := newSealing(ctx)
	if err != nil {
		return err
	}
	sealed, missing := 0, 0
	for _, t := range targets {
		for _, env := range t.pf.Envs() {
			e := t.pf.Env[env]
			if e.Key == "" {
				continue
			}
			if _, err := coreseal.Read(t.root, env); err == nil {
				continue
			}
			priv, ok := s.cached(t.pf.Project, env, e.Key)
			if !ok {
				fmt.Fprintf(os.Stderr, "! %s %s: its key is not on this device; run this where it is, or rotate it (esec vault env rotate %s)\n", t.pf.Project, env, env)
				missing++
				continue
			}
			readers, err := readersOf(t.pf, env)
			if err != nil {
				return err
			}
			if err := s.seal(t.root, t.pf, env, priv, e.GuardLevel(), readers); err != nil {
				return fmt.Errorf("%s %s: %w", t.pf.Project, env, err)
			}
			if seal.Guarded(e.Guard) {
				if _, err := s.ks.Forget(t.pf.Project, priv); err != nil {
					return err
				}
			}
			fmt.Printf("✓ %s %s sealed\n", t.pf.Project, env)
			sealed++
		}
	}
	fmt.Printf("%d key(s) sealed. Commit .esec/ and esec.toml in each repository.\n", sealed)
	if missing > 0 {
		return fmt.Errorf("%d key(s) not on this device", missing)
	}
	return nil
}

// SealRecoverCmd reseals with the recovery phrase.
type SealRecoverCmd struct {
	Project string `help:"Project id (default: the checkout here)"`
	All     bool   `help:"Every project with a checkout on this machine"`
	Guarded bool   `default:"true" negatable:"" help:"Only guarded environments (the ones a lost security key affects)"`
}

// Run implements seal recover.
func (c *SealRecoverCmd) Run(ctx *cliCtx) error {
	targets, err := sealTargets(c.Project, c.All)
	if err != nil {
		return err
	}
	s, err := newSealing(ctx)
	if err != nil {
		return err
	}
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
	rec, err := coreseal.X25519Identity(hex.EncodeToString(keys.Private[:]))
	if err != nil {
		return err
	}
	n, failed := 0, 0
	for _, t := range targets {
		for _, env := range t.pf.Envs() {
			e := t.pf.Env[env]
			if e.Key == "" || (c.Guarded && !seal.Guarded(e.Guard)) {
				continue
			}
			p, err := seal.Open(t.root, t.pf.Project, env, e.Key, rec)
			if err != nil {
				fmt.Fprintf(os.Stderr, "✗ %s %s: %s\n", t.pf.Project, env, err)
				failed++
				continue
			}
			readers, err := readersOf(t.pf, env)
			if err != nil {
				return err
			}
			if err := s.seal(t.root, t.pf, env, p.Private, p.Guard, readers); err != nil {
				fmt.Fprintf(os.Stderr, "✗ %s %s: %s\n", t.pf.Project, env, err)
				failed++
				continue
			}
			fmt.Printf("✓ %s %s sealed again\n", t.pf.Project, env)
			n++
		}
	}
	fmt.Printf("%d seal(s) made again with the phrase. Commit .esec/ and esec.toml in each repository.\n", n)
	if failed > 0 {
		return fmt.Errorf("%d seal(s) the phrase does not open", failed)
	}
	return nil
}

// removeReader drops readers matching who from a list.
func removeReader(readers []seal.Reader, who seal.Reader) ([]seal.Reader, bool) {
	out := slices.DeleteFunc(slices.Clone(readers), func(r seal.Reader) bool {
		if who.Kind == seal.KindKey && who.ID == "" {
			return r.Kind == seal.KindKey && r.Label == who.Label
		}
		return r.Kind == who.Kind && r.ID == who.ID
	})
	return out, len(out) != len(readers)
}
