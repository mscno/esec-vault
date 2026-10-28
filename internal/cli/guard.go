package cli

import (
	"bufio"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"filippo.io/age"
	"github.com/mscno/esec/pkg/projectfile"
	"github.com/tyler-smith/go-bip39"

	"github.com/mscno/esec-vault/internal/account"
	"github.com/mscno/esec-vault/internal/caller"
	"github.com/mscno/esec-vault/internal/guard"
	"github.com/mscno/esec-vault/internal/identity"
	"github.com/mscno/esec-vault/internal/keystore"
	"github.com/mscno/esec-vault/internal/safetext"
)

// GuardCmd manages the hardware guard: environment keys that only a touch
// of your security key opens.
type GuardCmd struct {
	Status  GuardStatusCmd  `cmd:"" default:"withargs" help:"Show the guard's holders and which keys it guards (default)."`
	Init    GuardInitCmd    `cmd:"" help:"Set up the guard: your YubiKeys (age-plugin-yubikey) and your recovery phrase hold it."`
	Enable  GuardEnableCmd  `cmd:"" help:"Guard environment keys: from now on every read needs a touch (or one per session)."`
	Holders GuardHoldersCmd `cmd:"" help:"Add or remove a security key that holds the guard."`
	Recover GuardRecoverCmd `cmd:"" help:"Lost your security keys? Open the guard with the recovery phrase and give it to new ones."`
	Check   GuardCheckCmd   `cmd:"" help:"Open the guard once and check every guarded key opens and belongs to its public key."`
	Export  GuardExportCmd  `cmd:"" help:"Write the guard and every guarded key as plain age files, to open with rage if esec is gone."`
}

func guardStore() *keystore.Store { return keystore.New() }

// openGuard asks the person, then opens the guard: one touch. what names
// what the touch allows, as the dialog shows it.
func openGuard(what string) (*age.X25519Identity, error) {
	g, err := guard.Load(guardStore())
	if err != nil {
		return nil, err
	}
	text := what + "\n\nAsked by: " + caller.Describe(caller.Chain(os.Getpid())) + "\n\nTouch your security key only if you started this."
	id, err := guard.DefaultPresence.Open(g, "esec: allow a guarded key?", text)
	if err != nil {
		return nil, err
	}
	if g.Recipient != "" && g.Recipient != id.Recipient().String() {
		return nil, errors.New("the stored guard recipient does not match the guard identity; run esec vault guard check")
	}
	return id, nil
}

// ---- status ----

// GuardStatusCmd shows the guard.
type GuardStatusCmd struct {
	JSON bool `help:"Print JSON, for scripts and agents"`
}

type guardProject struct {
	Project string   `json:"project"`
	Envs    []string `json:"envs"`
	Keys    int      `json:"keys"`
	// Clear lists guarded keys this device still holds in the clear.
	Clear []string `json:"clear,omitempty"`
}

type guardStatus struct {
	SetUp     bool           `json:"set_up"`
	Recipient string         `json:"recipient,omitempty"`
	Holders   []string       `json:"holders"`
	Projects  []guardProject `json:"projects"`
}

func readGuardStatus() (*guardStatus, error) {
	ks := guardStore()
	out := &guardStatus{Holders: []string{}, Projects: []guardProject{}}
	if g, err := guard.Load(ks); err == nil {
		out.SetUp, out.Recipient, out.Holders = true, g.Recipient, g.Holders
	} else if !errors.Is(err, guard.ErrNotSetUp) {
		return nil, err
	}
	projects, err := ks.List()
	if err != nil {
		return nil, err
	}
	for _, p := range projects {
		entries, err := ks.Read(p)
		if err != nil {
			return nil, err
		}
		gp := guardProject{Project: p, Envs: []string{}}
		inClear := map[string]bool{}
		for k, v := range entries {
			switch {
			case keystore.IsGuardEntry(k):
				gp.Keys++
			case strings.HasPrefix(k, keystore.GuardEnvPrefix):
				if env, ok := keystore.EnvName(k); ok {
					gp.Envs = append(gp.Envs, env)
				}
			default:
				// Any entry holding a guarded key in the clear, by any name.
				if pub, err := keystore.PublicHex(v); err == nil && entries[keystore.GuardEntry(pub)] != "" && !inClear[pub] {
					inClear[pub] = true
					gp.Clear = append(gp.Clear, pub[:12])
				}
			}
		}
		if gp.Keys > 0 {
			sort.Strings(gp.Envs)
			sort.Strings(gp.Clear)
			out.Projects = append(out.Projects, gp)
		}
	}
	return out, nil
}

// Run implements guard status.
func (c *GuardStatusCmd) Run(_ *cliCtx) error {
	st, err := readGuardStatus()
	if err != nil {
		return err
	}
	if c.JSON {
		return printJSON(st)
	}
	if !st.SetUp {
		fmt.Println("No guard yet. Set one up with your YubiKeys: esec vault guard init")
		return nil
	}
	fmt.Printf("Guard %s, held by %d:\n", st.Recipient, len(st.Holders))
	for _, h := range st.Holders {
		fmt.Println("  " + describeHolder(h))
	}
	if len(st.Holders) < 2 {
		fmt.Println("  ! one holder: lose it and the guarded keys are gone. Plug in a second YubiKey too and run: esec vault guard holders add")
	}
	if len(st.Projects) == 0 {
		fmt.Println("No guarded keys yet: esec vault guard enable --env prod")
	}
	for _, p := range st.Projects {
		envs := strings.Join(p.Envs, ", ")
		if envs == "" {
			envs = "retired keys only"
		}
		fmt.Printf("%-32s %s (%d key(s))\n", safetext.Clean(p.Project), safetext.Clean(envs), p.Keys)
		if len(p.Clear) > 0 {
			fmt.Printf("  ! still in the clear on this device: %s… — run esec vault guard enable --project %s here\n", strings.Join(p.Clear, "…, "), p.Project)
		}
	}
	return nil
}

func describeHolder(h string) string {
	switch name := guard.PluginName(h); name {
	case "":
		return h + "  (software key; the recovery key if it came from guard init)"
	default:
		return h + "  (" + name + ")"
	}
}

// ---- init ----

// GuardInitCmd sets the guard up.
type GuardInitCmd struct {
	Holder     []string `name:"holder" sep:"," help:"Recipients that hold the guard (age1yubikey1…); default: every YubiKey age-plugin-yubikey lists"`
	NoRecovery bool     `name:"no-recovery" help:"Do not let the recovery phrase open the guard (then losing your YubiKeys loses the guarded keys)"`
}

// Run implements guard init.
func (c *GuardInitCmd) Run(ctx *cliCtx) error {
	ks := guardStore()
	if _, err := guard.Load(ks); err == nil {
		return errors.New("the guard is set up already; change who holds it with esec vault guard holders add/remove")
	} else if !errors.Is(err, guard.ErrNotSetUp) {
		return err
	}
	if err := noGuardOnServer(ctx); err != nil {
		return err
	}
	holders := c.Holder
	if len(holders) == 0 {
		found, notes, err := listYubiKeys()
		if err != nil {
			return err
		}
		holders = found
		for _, n := range notes {
			fmt.Fprintln(os.Stderr, "! "+n)
		}
	}
	hardware := len(holders)
	if hardware == 0 {
		return errors.New("no security key to hold the guard: set a YubiKey up with age-plugin-yubikey (touch policy always), or pass --holder")
	}
	if !c.NoRecovery {
		rec, err := recoveryRecipient(ctx)
		if err != nil {
			return fmt.Errorf("the recovery key: %w (or pass --no-recovery)", err)
		}
		holders = append(holders, rec)
	}
	if _, err := guard.ParseRecipients(holders); err != nil {
		return err
	}
	g, _, err := guard.New(holders)
	if err != nil {
		return err
	}
	if err := guard.Save(ks, g); err != nil {
		return err
	}
	markDirty("guard init")
	storeNow(ctx, "guard init")
	fmt.Printf("Guard %s set up, held by:\n", g.Recipient)
	for _, h := range g.Holders {
		fmt.Println("  " + describeHolder(h))
	}
	if hardware < 2 {
		fmt.Fprintln(os.Stderr, "! one security key: plug in your spare too and run esec vault guard holders add")
	}
	fmt.Println("Guard an environment: esec vault guard enable --env prod")
	return nil
}

// noGuardOnServer refuses a second guard: when this device is signed in to
// a vault server whose vault has a guard already (set up on another
// device), this one would replace it there, or conflict with it.
func noGuardOnServer(ctx *cliCtx) error {
	a, err := openAccount(ctx)
	if errors.Is(err, account.ErrNotLoggedIn) {
		return nil
	}
	if err != nil {
		return err
	}
	bg, cancel := timeout(time.Minute)
	defer cancel()
	projects, err := a.ServerProjects(bg)
	if err != nil {
		return fmt.Errorf("check the vault server for a guard set up on another device: %w", err)
	}
	if projects["default"][guard.EntryIdentity] != "" {
		return errors.New("another device set up the guard already: get it here with esec vault sync --server, then let this Mac's YubiKey open it with esec vault guard holders add")
	}
	return nil
}

// recoveryRecipient is the age recipient of the recovery key, the X25519
// key the 24-word phrase derives. Its private half is stored nowhere.
func recoveryRecipient(ctx *cliCtx) (string, error) {
	id, err := identity.Load(ctx.Keyring)
	if err != nil {
		return "", err
	}
	_, masterPub, err := identity.BackupMaterial(id)
	if err != nil {
		return "", err
	}
	return guard.X25519Recipient(*masterPub)
}

// listYubiKeys asks age-plugin-yubikey for its recipients, with notes on
// slots whose touch policy lets a touch be reused.
func listYubiKeys() (recipients, notes []string, err error) {
	path, err := exec.LookPath("age-plugin-yubikey")
	if err != nil {
		return nil, nil, errors.New("age-plugin-yubikey is not installed (brew install age-plugin-yubikey); or pass --holder")
	}
	cctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(cctx, path, "--list").Output()
	if err != nil {
		return nil, nil, fmt.Errorf("age-plugin-yubikey --list: %w", err)
	}
	return parseYubiKeyList(string(out))
}

func parseYubiKeyList(out string) (recipients, notes []string, err error) {
	sc := bufio.NewScanner(strings.NewReader(out))
	var policy string
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if p, ok := strings.CutPrefix(strings.TrimLeft(line, "# "), "Touch policy:"); ok {
			policy = strings.TrimSpace(p)
			continue
		}
		if strings.HasPrefix(line, "age1yubikey1") {
			recipients = append(recipients, line)
			if policy != "" && !strings.EqualFold(policy, "Always") {
				notes = append(notes, fmt.Sprintf("%s… has touch policy %s: a touch then also lets other programs in for a while. Make a slot with --touch-policy always", line[:20], policy))
			}
			policy = ""
		}
	}
	return recipients, notes, sc.Err()
}

// ---- enable ----

// GuardEnableCmd guards environment keys.
type GuardEnableCmd struct {
	Env     []string `name:"env" sep:"," help:"Environments to guard, such as prod (default: every environment esec.toml guards)"`
	Project string   `help:"Project id (default: nearest esec.toml)"`
	Level   string   `default:"touch" enum:"touch,session" help:"touch: every read needs a touch; session: one touch per broker session"`
	Retired bool     `help:"Also guard the project's old keys no environment uses any more (rotated away from; they open old git history)"`
}

// Run implements guard enable.
func (c *GuardEnableCmd) Run(ctx *cliCtx) error { //nolint:gocyclo // which environments, guard them, record it
	project, pf, dir, err := projectAndFile(c.Project)
	if err != nil {
		return err
	}
	envs := c.Env
	if len(envs) == 0 && pf != nil {
		for _, name := range pf.Envs() {
			if lvl := pf.Env[name].GuardLevel(); lvl != projectfile.GuardNone {
				envs = append(envs, name)
			}
		}
	}
	if len(envs) == 0 && !c.Retired {
		return errors.New("name the environments to guard: --env prod")
	}
	for _, env := range envs {
		if err := validateEnvName(env); err != nil {
			return err
		}
	}
	ks := guardStore()
	if _, err := ks.Read(project); err != nil {
		return fmt.Errorf("no keys of %s on this device: %w", project, err)
	}
	id, err := openGuard(fmt.Sprintf("Guard the keys of %s: %s", project, strings.Join(append(envs, retiredNote(c.Retired)...), ", ")))
	if err != nil {
		return err
	}
	// Read the keyring after the dialog and touch, which take a while: a
	// sync in between must not be undone.
	entries, err := ks.Read(project)
	if err != nil {
		return err
	}
	var guarded, cleared []string
	for _, env := range envs {
		did, err := guardEnv(entries, id, project, env, c.levelFor(pf, env))
		if err != nil {
			return err
		}
		if did != "" {
			guarded = append(guarded, env+" ("+did+")")
		}
	}
	if c.Retired {
		named := map[string]bool{}
		for k, v := range entries {
			if _, ok := keystore.EnvName(k); ok && strings.HasPrefix(k, "ESEC_PRIVATE_KEY") {
				if pub, err := keystore.PublicHex(v); err == nil {
					named[pub] = true
				}
			}
		}
		for k, v := range entries {
			if !keystore.IsPubEntry(k) {
				continue
			}
			pub := strings.ToLower(strings.TrimPrefix(k, "ESEC_PRIVATE_KEY_"))
			if named[pub] {
				continue
			}
			if err := guardKey(entries, id, project, "", c.Level, pub, v); err != nil {
				return err
			}
			cleared = append(cleared, pub[:12]+"…")
		}
	}
	if err := ks.WriteGuarded(project, entries); err != nil {
		return err
	}
	if pf != nil && pf.Project == project {
		for _, env := range envs {
			e := pf.Env[env]
			e.Guard = c.levelFor(pf, env)
			if pub := entries[keystore.GuardEnvEntry(env)]; pub != "" {
				e.Key = pub
			}
			if pf.Env == nil {
				pf.Env = map[string]projectfile.Env{}
			}
			pf.Env[env] = e
		}
		if err := pf.Save(dir); err != nil {
			return err
		}
	}
	markDirty("guard enable")
	storeNow(ctx, "guard enable")
	for _, g := range guarded {
		fmt.Printf("Guarded %s %s\n", project, g)
	}
	if len(cleared) > 0 {
		fmt.Printf("Guarded %d retired key(s) of %s: %s\n", len(cleared), project, strings.Join(cleared, ", "))
	}
	fmt.Fprintln(os.Stderr, "Run it through the background service from now on: esec vault run prod -- ./deploy (each read asks, then waits for a touch).")
	fmt.Fprintln(os.Stderr, "Older vault backups still hold these keys in software form: for full protection, rotate the key and its values once (esec vault env rotate ENV).")
	return nil
}

func retiredNote(retired bool) []string {
	if retired {
		return []string{"and its retired keys"}
	}
	return nil
}

func (c *GuardEnableCmd) levelFor(pf *projectfile.File, env string) string {
	if len(c.Env) == 0 && pf != nil {
		if lvl := pf.Env[env].GuardLevel(); lvl != projectfile.GuardNone {
			return lvl
		}
	}
	return c.Level
}

// guardEnv guards an environment's current key in entries. It returns what
// it did, "" when the environment was guarded already.
func guardEnv(entries map[string]string, id *age.X25519Identity, project, env, level string) (string, error) {
	named := keystore.EnvEntry(env)
	priv, ok := entries[named]
	if !ok {
		pub := strings.ToLower(entries[keystore.GuardEnvEntry(env)])
		if pub == "" {
			return "", fmt.Errorf("no %s key of %s on this device", env, project)
		}
		// Guarded already, maybe on another device: a clear copy synced
		// here before still goes.
		clearCopy, isClear := entries[keystore.PubEntry(pub)]
		if !isClear {
			return "", nil
		}
		if err := guardKey(entries, id, project, env, level, pub, clearCopy); err != nil {
			return "", err
		}
		return "removed the clear copy", nil
	}
	pub, err := keystore.PublicHex(priv)
	if err != nil {
		return "", err
	}
	if err := guardKey(entries, id, project, env, level, pub, priv); err != nil {
		return "", err
	}
	delete(entries, named)
	entries[keystore.GuardEnvEntry(env)] = pub
	return level, nil
}

// guardKey replaces a clear key by its guarded form. A key another device
// guarded already is checked to open to the same key, then the clear copy
// goes.
func guardKey(entries map[string]string, id *age.X25519Identity, project, env, level, pub, priv string) error {
	if v := entries[keystore.GuardEntry(pub)]; v != "" {
		k, err := guard.Unwrap(id, v, pub, keystore.PublicHex)
		if err != nil || k.Private != priv {
			return fmt.Errorf("the guarded copy of %s… does not open to this device's key; leaving both: %v", pub[:12], err)
		}
	} else {
		v, err := guard.Wrap(id.Recipient(), guard.Key{Project: project, Env: env, Level: level, Private: priv})
		if err != nil {
			return err
		}
		entries[keystore.GuardEntry(pub)] = v
	}
	// Every clear copy goes, whatever its name: the public-key entry, the
	// environment's name, and any other name pointing at the same key.
	for k, v := range entries {
		if keystore.IsGuardEntry(k) || strings.HasPrefix(k, keystore.GuardEnvPrefix) || !strings.EqualFold(strings.TrimSpace(v), strings.TrimSpace(priv)) {
			continue
		}
		delete(entries, k)
		if other, ok := keystore.EnvName(k); ok && other != env && !isHex64(other) && entries[keystore.GuardEnvEntry(other)] == "" {
			entries[keystore.GuardEnvEntry(other)] = pub
		}
	}
	return nil
}

func isHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

// projectAndFile resolves the project and, where there is one, its
// esec.toml and directory.
func projectAndFile(explicit string) (project string, pf *projectfile.File, dir string, err error) {
	cwd, err := os.Getwd()
	if err != nil {
		return "", nil, "", err
	}
	f, path, ferr := projectfile.Find(cwd)
	if ferr != nil && !errors.Is(ferr, projectfile.ErrNotFound) {
		return "", nil, "", ferr
	}
	if explicit != "" {
		if err := projectfile.ValidateOrgRepo(explicit); err != nil {
			return "", nil, "", err
		}
		if f != nil && f.Project == explicit {
			return explicit, f, filepath.Dir(path), nil
		}
		return explicit, nil, "", nil
	}
	if f == nil {
		return "", nil, "", fmt.Errorf("no esec.toml here or above: pass --project: %w", projectfile.ErrNotFound)
	}
	return f.Project, f, filepath.Dir(path), nil
}

// ---- holders ----

// GuardHoldersCmd changes who holds the guard.
type GuardHoldersCmd struct {
	Add    GuardHolderAddCmd    `cmd:"" help:"Let another security key open the guard (one touch of a current one)."`
	Remove GuardHolderRemoveCmd `cmd:"" help:"Stop a security key opening the guard, such as a lost one."`
}

// GuardHolderAddCmd adds a holder.
type GuardHolderAddCmd struct {
	Recipient string `arg:"" optional:"" help:"The holder's recipient, such as age1yubikey1… (default: every plugged-in YubiKey that does not hold it yet)"`
}

// Run implements guard holders add.
func (c *GuardHolderAddCmd) Run(ctx *cliCtx) error {
	var add []string
	if c.Recipient != "" {
		add = []string{c.Recipient}
	}
	return changeHolders(ctx, "Let another security key open the guard", func(h []string) ([]string, error) {
		if add == nil {
			found, _, err := listYubiKeys()
			if err != nil {
				return nil, err
			}
			add = newHolders(h, found)
			if len(add) == 0 {
				return nil, errors.New("every plugged-in YubiKey holds the guard already: plug in the spare as well (set up with age-plugin-yubikey --generate --touch-policy always), or pass its recipient")
			}
		}
		for _, r := range add {
			if slices.Contains(h, r) {
				return nil, fmt.Errorf("%s holds the guard already", describeHolder(r))
			}
		}
		return append(h, add...), nil
	})
}

// newHolders is the recipients in found that are not in holders.
func newHolders(holders, found []string) []string {
	var out []string
	for _, r := range found {
		if !slices.Contains(holders, r) && !slices.Contains(out, r) {
			out = append(out, r)
		}
	}
	return out
}

// GuardHolderRemoveCmd removes a holder.
type GuardHolderRemoveCmd struct {
	Recipient string `arg:"" help:"The holder's recipient"`
}

// Run implements guard holders remove.
func (c *GuardHolderRemoveCmd) Run(ctx *cliCtx) error {
	err := changeHolders(ctx, "Stop "+c.Recipient+" opening the guard", func(h []string) ([]string, error) {
		var out []string
		for _, x := range h {
			if x != c.Recipient {
				out = append(out, x)
			}
		}
		if len(out) == len(h) {
			return nil, errors.New("it does not hold the guard")
		}
		if len(out) == 0 {
			return nil, errors.New("the guard needs at least one holder")
		}
		return out, nil
	})
	if err == nil {
		fmt.Fprintln(os.Stderr, "A lost key with its PIN still opens older copies of the guard in backups: if the PIN may be known, rotate the guarded keys (esec vault env rotate ENV).")
	}
	return err
}

func changeHolders(ctx *cliCtx, what string, change func([]string) ([]string, error)) error {
	ks := guardStore()
	g, err := guard.Load(ks)
	if err != nil {
		return err
	}
	holders, err := change(append([]string(nil), g.Holders...))
	if err != nil {
		return err
	}
	if _, err := guard.ParseRecipients(holders); err != nil {
		return err
	}
	id, err := openGuard(what)
	if err != nil {
		return err
	}
	return saveHolders(ctx, g, id, holders)
}

// saveHolders rewraps the opened guard to holders and stores it, unless
// the guard changed while the person was asked (a sync in between).
func saveHolders(ctx *cliCtx, before *guard.Guard, id *age.X25519Identity, holders []string) error {
	ks := guardStore()
	now, err := guard.Load(ks)
	if err != nil {
		return err
	}
	if now.Recipient != before.Recipient || !slices.Equal(now.Holders, before.Holders) {
		return errors.New("the guard changed on this device meanwhile (a sync?): run the command again")
	}
	if id.Recipient().String() != now.Recipient {
		return errors.New("the opened guard identity is not the stored guard's")
	}
	next, err := guard.Rewrap(id, holders)
	if err != nil {
		return err
	}
	if err := guard.Save(ks, next); err != nil {
		return err
	}
	markDirty("guard holders")
	storeNow(ctx, "guard holders")
	fmt.Printf("The guard is held by %d:\n", len(next.Holders))
	for _, h := range next.Holders {
		fmt.Println("  " + describeHolder(h))
	}
	return nil
}

// ---- recover ----

// GuardRecoverCmd opens the guard with the recovery phrase, as when every
// security key is lost, and rewraps it to the security keys plugged in now.
type GuardRecoverCmd struct {
	Holder []string `name:"holder" sep:"," help:"New holders (age1yubikey1…); default: every plugged-in YubiKey that does not hold it yet"`
	Remove []string `name:"remove" sep:"," help:"Holders to drop, such as the lost YubiKeys"`
}

// Run implements guard recover.
func (c *GuardRecoverCmd) Run(ctx *cliCtx) error {
	g, err := guard.Load(guardStore())
	if err != nil {
		return err
	}
	add := c.Holder
	if len(add) == 0 {
		found, notes, err := listYubiKeys()
		if err != nil {
			return err
		}
		for _, n := range notes {
			fmt.Fprintln(os.Stderr, "! "+n)
		}
		add = newHolders(g.Holders, found)
	}
	var holders []string
	for _, h := range g.Holders {
		if !slices.Contains(c.Remove, h) {
			holders = append(holders, h)
		}
	}
	holders = append(holders, newHolders(holders, add)...)
	if len(add) == 0 && len(c.Remove) == 0 {
		return errors.New("nothing to change: plug in the new YubiKey (age-plugin-yubikey --generate --touch-policy always), or pass --holder or --remove")
	}
	if _, err := guard.ParseRecipients(holders); err != nil {
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
	s, err := guard.X25519IdentityString(keys.Private)
	if err != nil {
		return err
	}
	rec, err := age.ParseX25519Identity(s)
	if err != nil {
		return err
	}
	id, err := g.Open(rec)
	if err != nil {
		return fmt.Errorf("the phrase does not open the guard (was it set up with --no-recovery, or with another phrase?): %w", err)
	}
	if err := saveHolders(ctx, g, id, holders); err != nil {
		return err
	}
	if len(c.Remove) > 0 {
		fmt.Fprintln(os.Stderr, "A lost key with its PIN still opens older copies of the guard in backups: if the PIN may be known, rotate the guarded keys (esec vault env rotate ENV).")
	}
	return nil
}

// ---- check ----

// GuardCheckCmd opens every guarded key.
type GuardCheckCmd struct {
	JSON bool `help:"Print JSON, for scripts and agents"`
}

type guardCheck struct {
	Holders int      `json:"holders"`
	Keys    int      `json:"keys"`
	Bad     []string `json:"bad"`
}

// Run implements guard check.
func (c *GuardCheckCmd) Run(_ *cliCtx) error {
	ks := guardStore()
	g, err := guard.Load(ks)
	if err != nil {
		return err
	}
	id, err := openGuard("Check that every guarded key opens (nothing is read out)")
	if err != nil {
		return err
	}
	res := guardCheck{Holders: len(g.Holders), Bad: []string{}}
	projects, err := ks.List()
	if err != nil {
		return err
	}
	for _, p := range projects {
		entries, err := ks.Read(p)
		if err != nil {
			return err
		}
		for k, v := range entries {
			if !keystore.IsGuardEntry(k) {
				continue
			}
			res.Keys++
			pub := strings.ToLower(strings.TrimPrefix(k, "ESEC_GUARD_"))
			if key, err := guard.Unwrap(id, v, pub, keystore.PublicHex); err != nil || (key.Project != "" && key.Project != p) {
				res.Bad = append(res.Bad, p+" "+pub[:12]+"…")
			}
		}
	}
	sort.Strings(res.Bad)
	if c.JSON {
		if err := printJSON(res); err != nil {
			return err
		}
	} else {
		fmt.Printf("The guard opens; %d holder(s); %d guarded key(s) checked.\n", res.Holders, res.Keys)
		for _, b := range res.Bad {
			fmt.Println("  ! does not open, or belongs elsewhere: " + safetext.Clean(b))
		}
	}
	if len(res.Bad) > 0 {
		return fmt.Errorf("%d guarded key(s) failed the check", len(res.Bad))
	}
	return nil
}

// ---- export ----

// GuardExportCmd writes the guard as plain age files.
type GuardExportCmd struct {
	Out string `required:"" type:"path" help:"An empty directory to write to"`
}

// Run implements guard export. Everything it writes is ciphertext.
func (c *GuardExportCmd) Run(_ *cliCtx) error {
	ks := guardStore()
	g, err := guard.Load(ks)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(c.Out, 0700); err != nil {
		return err
	}
	if ents, err := os.ReadDir(c.Out); err != nil {
		return err
	} else if len(ents) > 0 {
		return fmt.Errorf("%s is not empty", c.Out)
	}
	write := func(name string, data []byte) error {
		return os.WriteFile(filepath.Join(c.Out, name), data, 0600)
	}
	if err := write("guard.age", g.Wrapped); err != nil {
		return err
	}
	if err := write("holders.txt", []byte(strings.Join(g.Holders, "\n")+"\n")); err != nil {
		return err
	}
	projects, err := ks.List()
	if err != nil {
		return err
	}
	n := 0
	for _, p := range projects {
		entries, err := ks.Read(p)
		if err != nil {
			return err
		}
		names := map[string]string{}
		for k, v := range entries {
			if env, ok := keystore.EnvName(k); ok && strings.HasPrefix(k, "ESEC_GUARD_ENV_") {
				names[strings.ToLower(v)] = env
			}
		}
		for k, v := range entries {
			if !keystore.IsGuardEntry(k) {
				continue
			}
			raw, err := guardRaw(v)
			if err != nil {
				return err
			}
			pub := strings.ToLower(strings.TrimPrefix(k, "ESEC_GUARD_"))
			label := names[pub]
			if label == "" {
				label = "retired"
			}
			if err := write(fmt.Sprintf("%s.%s.%s.age", strings.ReplaceAll(p, "/", "_"), label, pub[:12]), raw); err != nil {
				return err
			}
			n++
		}
	}
	readme := `These are age files. Nothing here is readable without a holder of the guard.

1. Open the guard with a YubiKey (age-plugin-yubikey installed, key plugged in):
     rage -d -j yubikey -o guard.key guard.age        (or: age -d -j yubikey …)
   or with the recovery phrase: esec vault guard export prints nothing secret,
   so derive the recovery identity with esec vault drill on a working install.
2. Open a key with the guard identity:
     rage -d -i guard.key acme_store.prod.0123456789ab.age
   It prints {"project":…,"env":…,"private":"<hex>"}: the esec private key.
3. Delete guard.key when done.
`
	if err := write("README.txt", []byte(readme)); err != nil {
		return err
	}
	fmt.Printf("Wrote the guard and %d guarded key(s) to %s (all ciphertext).\n", n, c.Out)
	return nil
}

func guardRaw(value string) ([]byte, error) {
	g, err := guard.FromEntries(map[string]string{guard.EntryIdentity: value})
	if err != nil {
		return nil, err
	}
	return g.Wrapped, nil
}

// storeNow pushes a key change to the vault server (or the default backup
// destination) and waits, so a key exists in a second place before anything
// is encrypted to it. It reports, and does not fail, when that cannot happen.
func storeNow(ctx *cliCtx, reason string) {
	if err := storeKeysNow(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "! %s: the new keys are on this device only until the next backup: %v\n", reason, err)
	}
}
