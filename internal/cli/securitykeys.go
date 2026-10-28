package cli

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"

	"filippo.io/age"
	"filippo.io/age/plugin"
	"golang.org/x/term"

	"github.com/mscno/esec-vault/internal/account"
	"github.com/mscno/esec-vault/internal/chain"
	"github.com/mscno/esec-vault/internal/safetext"
	"github.com/mscno/esec-vault/internal/securitykey"
)

// SecurityKeysCmd manages the security keys (YubiKeys) that open your
// guarded environments.
type SecurityKeysCmd struct {
	List   SecurityKeysListCmd   `cmd:"" default:"withargs" help:"Your security keys, and the YubiKeys plugged in now (default)."`
	Add    SecurityKeysAddCmd    `cmd:"" help:"Register the plugged-in YubiKeys, so seals made for you include them."`
	Remove SecurityKeysRemoveCmd `cmd:"" help:"Stop a security key opening new seals, such as a lost one."`
	Setup  SecurityKeysSetupCmd  `cmd:"" help:"Give a plugged-in YubiKey an age identity (touch for every use), then register it."`
	Test   SecurityKeysTestCmd   `cmd:"" help:"Prove a security key still decrypts: encrypt a random value to it and open it (a touch)."`
}

// securityKeysChanged runs after keys are added or removed: it reseals the
// guarded environments the change affects. The seal code sets it.
var securityKeysChanged = resealGuarded

// securityKeyAccount opens the signed-in account, nil when this machine is
// not signed in: the keys are then this machine's list alone.
func securityKeyAccount(ctx *cliCtx) (*account.Account, error) {
	if _, err := account.LoadState(); errors.Is(err, account.ErrNotLoggedIn) {
		return nil, nil
	}
	return openAccount(ctx)
}

// myKeys returns the person's keys and where they come from.
func myKeys(bg context.Context, ctx *cliCtx) ([]chain.SecurityKey, *account.Account, error) {
	a, err := securityKeyAccount(ctx)
	if err != nil {
		return nil, nil, err
	}
	keys, err := securitykey.Mine(bg, a)
	return keys, a, err
}

// ---- list ----

// SecurityKeysListCmd lists security keys.
type SecurityKeysListCmd struct {
	JSON bool `help:"Print JSON, for scripts, agents and the Mac app"`
}

type securityKeyView struct {
	ID        string     `json:"id"`
	Kind      string     `json:"kind"`
	Name      string     `json:"name"`
	Serial    string     `json:"serial,omitempty"`
	Recipient string     `json:"recipient"`
	PluggedIn bool       `json:"plugged_in"`
	Tested    *time.Time `json:"tested,omitempty"`
}

type unregisteredKeyView struct {
	securitykey.Detected

	Command string `json:"command"`
}

type securityKeysView struct {
	// Source is account (the keys are in your account's chain) or local
	// (this machine's list; not signed in).
	Source        string                `json:"source"`
	Keys          []securityKeyView     `json:"keys"`
	Unregistered  []unregisteredKeyView `json:"unregistered"`
	Unprovisioned []string              `json:"unprovisioned"`
	// Detect says why plugged-in keys could not be listed, if so.
	Detect string `json:"detect,omitempty"`
}

// Run implements security-keys list.
func (c *SecurityKeysListCmd) Run(ctx *cliCtx) error {
	bg, cancel := timeout(time.Minute)
	defer cancel()
	keys, a, err := myKeys(bg, ctx)
	if err != nil {
		return err
	}
	v := securityKeysView{Source: "local", Keys: []securityKeyView{}, Unregistered: []unregisteredKeyView{}, Unprovisioned: []string{}}
	if a != nil {
		v.Source = "account"
	}
	plugged, detectErr := securitykey.Detect(bg)
	if detectErr != nil {
		v.Detect = detectErr.Error()
	}
	in := map[string]bool{}
	for _, d := range plugged {
		in[d.Recipient] = true
	}
	reg, _ := securitykey.Load()
	registered := map[string]bool{}
	for _, k := range keys {
		registered[k.Recipient] = true
		kv := securityKeyView{ID: k.ID, Kind: k.Kind, Name: k.Name, Serial: k.Serial, Recipient: k.Recipient, PluggedIn: in[k.Recipient]}
		if reg != nil {
			for _, e := range reg.Keys {
				if e.Recipient == k.Recipient && !e.Tested.IsZero() {
					t := e.Tested
					kv.Tested = &t
				}
			}
		}
		v.Keys = append(v.Keys, kv)
	}
	for _, d := range plugged {
		if !registered[d.Recipient] {
			v.Unregistered = append(v.Unregistered, unregisteredKeyView{Detected: d, Command: "esec vault security-keys add"})
		}
	}
	if none, err := securitykey.DetectUnprovisioned(bg); err == nil {
		v.Unprovisioned = append(v.Unprovisioned, none...)
	}
	if c.JSON {
		return printJSON(v)
	}
	printSecurityKeys(v)
	return nil
}

func printSecurityKeys(v securityKeysView) {
	if len(v.Keys) == 0 {
		fmt.Println("No security keys registered.")
	}
	for _, k := range v.Keys {
		state := ""
		if k.PluggedIn {
			state = "  (plugged in)"
		}
		tested := "never tested"
		if k.Tested != nil {
			tested = "tested " + k.Tested.Format(time.DateOnly)
		}
		fmt.Printf("  🔑 %-28s %-26s %s%s\n", safetext.Clean(k.Name), safetext.Clean(k.ID), tested, state)
	}
	if v.Source == "local" && len(v.Keys) > 0 {
		fmt.Println("  (this machine's list: sign in to a vault server to share it with your other machines and teammates)")
	}
	for _, d := range v.Unregistered {
		fmt.Printf("  + plugged in, not registered: YubiKey %s slot %s (%s): %s\n", safetext.Clean(d.Serial), safetext.Clean(d.Slot), safetext.Clean(d.Name), d.Command)
	}
	for _, s := range v.Unprovisioned {
		fmt.Printf("  + YubiKey %s has no age identity yet: esec vault security-keys setup --serial %s\n", safetext.Clean(s), safetext.Clean(s))
	}
	if v.Detect != "" {
		fmt.Println("  ! plugged-in keys not listed: " + safetext.Clean(v.Detect))
	}
	if len(v.Keys) == 1 {
		fmt.Println("One security key: add a spare (esec vault security-keys add), or losing it means recovering from your phrase.")
	}
}

// ---- add ----

// SecurityKeysAddCmd registers security keys.
type SecurityKeysAddCmd struct {
	Name      string `help:"Name for the key (with one key plugged in, or with --recipient)"`
	Recipient string `help:"Register this recipient instead of the plugged-in YubiKeys (age1yubikey1…, age1se1…)"`
	Kind      string `enum:"yubikey,se" default:"yubikey" help:"With --recipient: yubikey or se (Secure Enclave)"`
	Serial    string `help:"With --recipient: the YubiKey's serial"`
}

// Run implements security-keys add.
func (c *SecurityKeysAddCmd) Run(ctx *cliCtx) error {
	bg, cancel := timeout(2 * time.Minute)
	defer cancel()
	keys, a, err := myKeys(bg, ctx)
	if err != nil {
		return err
	}
	have := map[string]bool{}
	for _, k := range keys {
		have[k.Recipient] = true
	}
	var add []chain.SecurityKey
	if c.Recipient != "" {
		add = append(add, manualKey(c.Kind, c.Recipient, c.Name, c.Serial))
	} else {
		plugged, err := securitykey.Detect(bg)
		if err != nil {
			return err
		}
		var fresh []securitykey.Detected
		for _, d := range plugged {
			if !have[d.Recipient] {
				fresh = append(fresh, d)
			}
		}
		if len(fresh) == 0 {
			if len(plugged) == 0 {
				return errors.New("no YubiKey with an age identity is plugged in: plug one in, or give one an identity with esec vault security-keys setup")
			}
			fmt.Println("Every plugged-in YubiKey is registered already.")
			return nil
		}
		if c.Name != "" && len(fresh) > 1 {
			return fmt.Errorf("%d YubiKeys are plugged in: --name names one; unplug the others, or leave --name out to be asked", len(fresh))
		}
		for _, d := range fresh {
			if !d.TouchAlways() && d.TouchPolicy != "" {
				fmt.Fprintf(os.Stderr, "! YubiKey %s slot %s has touch policy %s: after one touch, other programs can decrypt for a while. For esec, make a slot with: esec vault security-keys setup --serial %s\n", d.Serial, d.Slot, d.TouchPolicy, d.Serial)
			}
			add = append(add, securitykey.FromDetected(d, keyName(c.Name, d)))
		}
	}
	for _, k := range add {
		if have[k.Recipient] {
			return fmt.Errorf("%s is registered already", k.Name)
		}
		if err := registerKey(bg, a, k); err != nil {
			return err
		}
		fmt.Printf("✓ Registered %s (%s)", k.Name, k.ID)
		if a != nil {
			fmt.Print(" in your account")
		}
		fmt.Println()
	}
	if err := securityKeysChanged(ctx); err != nil {
		return fmt.Errorf("registered, but resealing guarded environments failed: %w; run esec vault seal sync", err)
	}
	return nil
}

// manualKey is a security key given by its recipient.
func manualKey(kind, recipient, name, serial string) chain.SecurityKey {
	id := kind + ":" + strings.ToLower(recipient[max(0, len(recipient)-12):])
	if serial != "" && kind == chain.SecurityKeyYubiKey {
		id = securitykey.ID(serial, "")
	}
	if name == "" {
		name = map[string]string{chain.SecurityKeyYubiKey: "YubiKey", chain.SecurityKeySE: "Secure Enclave"}[kind]
	}
	return chain.SecurityKey{ID: id, Kind: kind, Recipient: strings.TrimSpace(recipient), Name: name, Serial: serial}
}

// keyName is the name for a detected key: given, asked on a terminal, or
// the default.
func keyName(given string, d securitykey.Detected) string {
	if given != "" {
		return given
	}
	def := securitykey.DefaultName(d)
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return def
	}
	answer, err := promptLine(fmt.Sprintf("Name for YubiKey %s slot %s, such as \"blue, on my keychain\" [%s]: ", d.Serial, d.Slot, def))
	if err != nil || answer == "" {
		return def
	}
	return answer
}

// registerKey adds a key to the account, or to this machine's list when
// not signed in.
func registerKey(bg context.Context, a *account.Account, k chain.SecurityKey) error {
	if err := chain.ValidateSecurityKey(k); err != nil {
		return err
	}
	if a != nil {
		if err := a.AddSecurityKey(bg, k); err != nil {
			return err
		}
		_, err := securitykey.Mine(bg, a)
		return err
	}
	reg, err := securitykey.Load()
	if err != nil {
		return err
	}
	if err := reg.Add(k); err != nil {
		return err
	}
	return reg.Save()
}

// ---- remove ----

// SecurityKeysRemoveCmd removes a security key.
type SecurityKeysRemoveCmd struct {
	Key    string `arg:"" help:"The key's name or id"`
	Reason string `help:"Why, for your account's history, such as lost"`
}

// Run implements security-keys remove.
func (c *SecurityKeysRemoveCmd) Run(ctx *cliCtx) error {
	bg, cancel := timeout(time.Minute)
	defer cancel()
	keys, a, err := myKeys(bg, ctx)
	if err != nil {
		return err
	}
	k, err := findKey(keys, c.Key)
	if err != nil {
		return err
	}
	if len(keys) == 1 {
		fmt.Fprintln(os.Stderr, "! This is your only security key: guarded environments then open only with your recovery phrase until you add another.")
	}
	if a != nil {
		if err := a.RemoveSecurityKey(bg, k.ID, c.Reason); err != nil {
			return err
		}
		if _, err := securitykey.Mine(bg, a); err != nil {
			return err
		}
	} else {
		reg, err := securitykey.Load()
		if err != nil {
			return err
		}
		reg.Remove(k.Recipient)
		if err := reg.Save(); err != nil {
			return err
		}
	}
	fmt.Printf("✓ %s no longer opens new seals.\n", k.Name)
	fmt.Fprintln(os.Stderr, "Seals made before, in git history, still open with it. If it is lost and its PIN may be known, rotate the guarded environments (esec vault env rotate ENV).")
	if err := securityKeysChanged(ctx); err != nil {
		return fmt.Errorf("removed, but resealing guarded environments failed: %w; run esec vault seal sync", err)
	}
	return nil
}

// findKey finds a key by id, then by name.
func findKey(keys []chain.SecurityKey, idOrName string) (chain.SecurityKey, error) {
	for _, k := range keys {
		if k.ID == idOrName || k.Recipient == idOrName {
			return k, nil
		}
	}
	var found []chain.SecurityKey
	for _, k := range keys {
		if strings.EqualFold(k.Name, idOrName) {
			found = append(found, k)
		}
	}
	switch len(found) {
	case 1:
		return found[0], nil
	case 0:
		return chain.SecurityKey{}, fmt.Errorf("no security key %q (esec vault security-keys lists them)", idOrName)
	}
	return chain.SecurityKey{}, fmt.Errorf("several keys are called %q: give the id", idOrName)
}

// ---- setup ----

// SecurityKeysSetupCmd gives a YubiKey an age identity.
type SecurityKeysSetupCmd struct {
	Serial string `help:"The YubiKey to set up, when several are plugged in"`
	Name   string `help:"Name to register it under"`
}

// setupCommand runs an interactive command on the terminal; tests replace it.
var setupCommand = func(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	return cmd.Run()
}

// Run implements security-keys setup.
func (c *SecurityKeysSetupCmd) Run(ctx *cliCtx) error {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return errors.New("setting a YubiKey up asks for its PIN and a touch: run it in a terminal (the Mac app opens one)")
	}
	if _, err := exec.LookPath("age-plugin-yubikey"); err != nil {
		return securitykey.ErrNoPlugin
	}
	host, _ := os.Hostname()
	host = strings.TrimSuffix(strings.Split(host, ".")[0], ".local")
	fmt.Println(`This makes a new age identity in a free slot of your YubiKey:
  - every decryption needs a touch (touch policy always), so no program can use it unseen;
  - its PIN is asked once per session (the default PIN is 123456: change it with ykman piv access change-pin);
  - the private key never leaves the YubiKey.
Then it is registered, and your guarded environments are sealed to it too.`)
	args := []string{"--generate", "--touch-policy", "always", "--pin-policy", "once", "--name", "esec " + host}
	if c.Serial != "" {
		args = append(args, "--serial", c.Serial)
	}
	if err := setupCommand("age-plugin-yubikey", args...); err != nil {
		return fmt.Errorf("age-plugin-yubikey --generate: %w", err)
	}
	return (&SecurityKeysAddCmd{Name: c.Name}).Run(ctx)
}

// ---- test ----

// SecurityKeysTestCmd checks that a security key decrypts.
type SecurityKeysTestCmd struct {
	Key string `arg:"" optional:"" help:"The key's name or id (default: each registered key plugged in)"`
}

// Run implements security-keys test.
func (c *SecurityKeysTestCmd) Run(ctx *cliCtx) error {
	bg, cancel := timeout(5 * time.Minute)
	defer cancel()
	keys, _, err := myKeys(bg, ctx)
	if err != nil {
		return err
	}
	var test []chain.SecurityKey
	if c.Key != "" {
		k, err := findKey(keys, c.Key)
		if err != nil {
			return err
		}
		test = append(test, k)
	} else {
		plugged, err := securitykey.Detect(bg)
		if err != nil {
			return err
		}
		in := map[string]bool{}
		for _, d := range plugged {
			in[d.Recipient] = true
		}
		for _, k := range keys {
			if in[k.Recipient] {
				test = append(test, k)
			}
		}
		if len(test) == 0 {
			return errors.New("no registered security key is plugged in")
		}
	}
	reg, err := securitykey.Load()
	if err != nil {
		return err
	}
	for _, k := range test {
		fmt.Printf("Testing %s: touch it when it blinks…\n", k.Name)
		if err := testDecrypt(k); err != nil {
			return fmt.Errorf("%s did not decrypt: %w", k.Name, err)
		}
		fmt.Printf("✓ %s decrypts.\n", k.Name)
		if e, ok := reg.Find(k.ID); ok {
			e.Tested = time.Now().UTC().Truncate(time.Second)
		} else if err := reg.Add(k); err == nil {
			reg.Keys[len(reg.Keys)-1].Tested = time.Now().UTC().Truncate(time.Second)
		}
	}
	return reg.Save()
}

// testDecrypt encrypts a random value to k and decrypts it with its plugin.
var testDecrypt = func(k chain.SecurityKey) error {
	ui := plugin.NewTerminalUI(func(f string, v ...any) { fmt.Fprintf(os.Stderr, f+"\n", v...) },
		func(f string, v ...any) { fmt.Fprintf(os.Stderr, "! "+f+"\n", v...) })
	r, err := plugin.NewRecipient(k.Recipient, ui)
	if err != nil {
		return err
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return err
	}
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, r)
	if err != nil {
		return err
	}
	if _, err := w.Write(secret); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	id, err := plugin.NewIdentityWithoutData(k.Kind, ui)
	if err != nil {
		return err
	}
	out, err := age.Decrypt(&buf, id)
	if err != nil {
		return err
	}
	got, err := io.ReadAll(out)
	if err != nil {
		return err
	}
	if !bytes.Equal(got, secret) {
		return errors.New("it decrypted to something else")
	}
	return nil
}

// resealGuarded seals guarded environments again after this person's
// security keys changed, so a new key opens them and a removed one opens no
// new seal. Each needs the key opened once: a touch of a key that still
// works, or the recovery phrase once for all (esec vault seal recover).
func resealGuarded(ctx *cliCtx) error {
	st, err := readGuardStatus()
	if err != nil || len(st.Projects) == 0 {
		return err
	}
	n := 0
	for _, p := range st.Projects {
		n += len(p.Envs)
	}
	fmt.Printf("%d guarded environment(s) in %d project(s) are sealed to your old set of security keys.\n", n, len(st.Projects))
	if !term.IsTerminal(int(os.Stdin.Fd())) || !confirm("Seal them again now? Each needs one touch of a key that already opens it (or answer no and run esec vault seal recover --all to use your phrase once)") {
		fmt.Println("Later: esec vault seal sync --all --guarded (a touch each), or esec vault seal recover --all (your phrase once).")
		return nil
	}
	return (&SealSyncCmd{All: true, Guarded: true}).Run(ctx)
}
