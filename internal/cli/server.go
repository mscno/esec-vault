package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/mscno/esec/pkg/keyringfile"
	"github.com/mscno/esec/pkg/secretstore"

	"github.com/mscno/esec-vault/internal/account"
	"github.com/mscno/esec-vault/internal/chain"
	"github.com/mscno/esec-vault/internal/daemon"
	"github.com/mscno/esec-vault/internal/identity"
	"github.com/mscno/esec-vault/internal/keyring"
	"github.com/mscno/esec-vault/internal/keystore"
	"github.com/mscno/esec-vault/internal/paths"
	"github.com/mscno/esec-vault/internal/remote"
	"github.com/mscno/esec-vault/internal/safetext"
	"github.com/mscno/esec-vault/internal/sshagent"
	"github.com/mscno/esec-vault/internal/storage"
)

// cliUI implements account.UI on the terminal.
type cliUI struct{ quiet bool }

func (u cliUI) Printf(format string, args ...any) {
	if !u.quiet {
		fmt.Printf(format, args...)
	}
}
func (cliUI) Confirm(q string) bool               { return confirm(q) }
func (cliUI) Secret(label string) (string, error) { return promptSecret(label) }

func openAccount(ctx *cliCtx) (*account.Account, error) {
	a, err := account.Open(ctx.Keyring, cliUI{quiet: ctx.Quiet})
	if err != nil {
		return nil, err
	}
	a.KeyringLocked = ctx.keyringLocked
	a.OpenKey = openKeyFor(ctx)
	return a, nil
}

func timeout(d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), d)
}

// LoginCmd signs this machine in to a vault server.
type LoginCmd struct {
	PersonalNamespace string `help:"Choose this personal namespace if your GitHub username is unavailable"`
	Server            string `arg:"" optional:"" help:"Server origin, e.g. https://vault.example.com (default: the current server or ESEC_VAULT_SERVER)"`
	SSHAgent          bool   `name:"ssh-agent" help:"Unlock with an SSH-agent unlock slot instead of waiting for approval"`
	SSHKey            string `name:"ssh-key" help:"With --ssh-agent: use only this key (.pub file or SHA256 fingerprint); otherwise every agent key is tried"`
	Recover           bool   `help:"Unlock with the recovery phrase instead of waiting for approval"`
	Name              string `help:"Device name (default: hostname)"`
	ReplaceIdentity   bool   `help:"Replace a different local identity with the account's without asking"`
	NoBrowser         bool   `help:"Do not try to open a browser"`
	NoSeal            bool   `help:"Do not seal keyrings on this machine"`
	NoIndex           bool   `help:"Do not publish project and environment names for the web UI"`
	AccountKey        string `help:"Expected account key words (as shown by 'esec vault status' on another device); skips the interactive check"`
}

// Run implements login.
func (c *LoginCmd) Run(ctx *cliCtx) error {
	if c.SSHAgent && c.Recover {
		return errors.New("choose one of --ssh-agent and --recover")
	}
	method := account.LoginApproval
	switch {
	case c.SSHAgent:
		method = account.LoginSSHAgent
	case c.Recover:
		method = account.LoginRecover
	}
	sshKey := ""
	if c.SSHKey != "" {
		if data, err := os.ReadFile(c.SSHKey); err == nil {
			if _, sshKey, err = sshagent.ParseAuthorizedKey(data); err != nil {
				return err
			}
		} else {
			sshKey = sshagent.NormalizeFingerprint(c.SSHKey)
		}
	}
	if _, err := secretstore.EnsureSelected(); err != nil {
		return fmt.Errorf("secret store: %w", err)
	}
	opts := account.LoginOptions{Server: c.Server, Name: c.Name, Method: method, ReplaceIdentity: c.ReplaceIdentity, NoIndex: c.NoIndex, AccountKey: c.AccountKey, SSHKey: sshKey,
		// The account creation token is read from the environment or a hidden
		// prompt, never a flag: command lines are visible to other users.
		BootstrapToken: os.Getenv("ESEC_VAULT_BOOTSTRAP_TOKEN")}
	if !c.NoBrowser {
		opts.OpenBrowser = openBrowser
	}
	bg, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	a, err := account.Login(bg, ctx.Keyring, cliUI{quiet: ctx.Quiet}, opts)
	if err != nil {
		return err
	}
	if err := finishPersonalLogin(a, c.PersonalNamespace); err != nil {
		return err
	}

	if !c.NoSeal {
		if err := enableSealing(ctx); err != nil {
			fmt.Fprintln(os.Stderr, "! keyrings stay plain:", err)
		}
	}
	res, err := a.Sync(bg, account.SyncOptions{Interactive: true})
	if err != nil {
		return fmt.Errorf("signed in, but the vault sync failed: %w", err)
	}
	printSync(ctx, res)
	afterKeyChange(ctx)
	return nil
}

// afterKeyChange wakes the daemon, or snapshots directly when none runs, so
// local backups include keys a command wrote outside the mutation hook.
func afterKeyChange(ctx *cliCtx) {
	if daemon.Notify() {
		return
	}
	if id, err := identity.Load(ctx.Keyring); err == nil {
		if _, err := remote.BuildSnapshot(id, keystore.New()); err != nil {
			ctx.Logger.Warn("keys saved, but the local backup snapshot is pending", "error", err)
		}
	}
}

func printSync(ctx *cliCtx, res *account.SyncResult) {
	if ctx.Quiet || res == nil {
		return
	}
	switch {
	case res.Pushed:
		fmt.Printf("✓ Vault synced (version %d, generation %d, uploaded local changes).\n", res.VaultVersion, res.Generation)
	default:
		fmt.Printf("✓ Vault synced (version %d, generation %d).\n", res.VaultVersion, res.Generation)
	}
	for _, a := range res.Added {
		fmt.Println("  + " + a)
	}
	if res.KeyChanged {
		fmt.Println("  Your user key was rotated by another device; installed the new key.")
	}
}

// openBrowser opens url when a graphical session is likely available.
func openBrowser(url string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "linux":
		if os.Getenv("DISPLAY") == "" && os.Getenv("WAYLAND_DISPLAY") == "" {
			return errors.New("no display")
		}
		cmd = exec.Command("xdg-open", url)
	default:
		return errors.New("unsupported platform")
	}
	return cmd.Start()
}

// esecSupportsSealed reports whether the esec on PATH reads sealed keyrings.
func esecSupportsSealed() error {
	path, err := exec.LookPath("esec")
	if err != nil {
		return errors.New("esec is not on PATH; install esec v0.9.0 or later before sealing keyrings")
	}
	c, cancel := timeout(5 * time.Second)
	defer cancel()
	out, err := exec.CommandContext(c, path, "capabilities").Output()
	if err != nil || !strings.Contains(string(out), keyringfile.Capability) {
		return errors.New("the esec on PATH cannot read sealed keyrings; upgrade it to v0.9.0 or later")
	}
	return nil
}

// enableSealing creates the cache key, seals new keyrings by default, and
// seals existing plain keyrings, if the installed esec can read them.
func enableSealing(ctx *cliCtx) error {
	if err := esecSupportsSealed(); err != nil {
		return err
	}
	n, err := sealAll(ctx, true)
	if err != nil {
		return err
	}
	if n > 0 && !ctx.Quiet {
		fmt.Printf("✓ Sealed %d keyring(s) with this machine's cache key.\n", n)
	}
	return nil
}

// sealAll seals or unseals every keyring and records the default.
func secretStoreFor(ctx *cliCtx) (secretstore.Store, error) { return keyring.SecretStore(ctx.Keyring) }

func sealAll(ctx *cliCtx, seal bool) (int, error) {
	if !ctx.keyringLocked {
		unlock, err := storage.Lock(paths.KeyringDir())
		if err != nil {
			return 0, err
		}
		defer unlock()
	}
	store, err := secretStoreFor(ctx)
	if err != nil {
		return 0, err
	}
	if seal {
		if _, err := keyringfile.EnsureCacheKey(store); err != nil {
			return 0, err
		}
	}
	cfg, err := secretstore.LoadConfig()
	if err != nil {
		return 0, err
	}
	if cfg.Backend == "" {
		cfg.Backend = store.Backend()
	}
	cfg.SealKeyrings = seal
	if err := secretstore.SaveConfig(cfg); err != nil {
		return 0, err
	}
	ks := keystore.New()
	projects, err := ks.List()
	if err != nil {
		return 0, err
	}
	n := 0
	for _, p := range projects {
		is, err := ks.IsSealed(p)
		if err != nil {
			return n, err
		}
		if is == seal {
			continue
		}
		if err := ks.SetSealed(p, seal); err != nil {
			return n, fmt.Errorf("%s: %w", p, err)
		}
		n++
	}
	return n, nil
}

// LogoutCmd ends the server session.
type LogoutCmd struct {
	ForgetDevice bool `help:"Also delete this device's keys and account record; the next login enrolls a new device"`
}

// Run implements logout.
func (c *LogoutCmd) Run(ctx *cliCtx) error {
	a, err := openAccount(ctx)
	if err != nil {
		return err
	}
	bg, cancel := timeout(30 * time.Second)
	defer cancel()
	if err := a.Logout(bg, c.ForgetDevice); err != nil {
		return err
	}
	fmt.Println("Signed out. Your identity and keyrings stay on this machine.")
	return nil
}

// DevicesCmd manages the account's devices.
type DevicesCmd struct {
	List    DevicesListCmd    `cmd:"" default:"withargs" help:"List devices (default)."`
	Approve DevicesApproveCmd `cmd:"" help:"Approve a device waiting for approval."`
	Revoke  DevicesRevokeCmd  `cmd:"" help:"Revoke a device and rotate your user key."`
	Rename  DevicesRenameCmd  `cmd:"" help:"Rename a device."`
	Suspend DevicesSuspendCmd `cmd:"" help:"Block a device on the server at once (revoke it afterwards)."`
}

// DevicesListCmd lists devices.
type DevicesListCmd struct {
	JSON bool `help:"Print JSON, for scripts and agents"`
}

// Run implements devices list.
func (c *DevicesListCmd) Run(ctx *cliCtx) error {
	a, err := openAccount(ctx)
	if err != nil {
		return err
	}
	bg, cancel := timeout(30 * time.Second)
	defer cancel()
	devices, err := a.Devices(bg)
	if err != nil {
		return err
	}
	if c.JSON {
		return printJSON(devicesJSON(a, devices))
	}
	fmt.Printf("Account: %s  key: %s\n", safetext.Clean(a.State.Login), a.State.Chain.AccountWords)
	for _, d := range devices {
		mark := " "
		if d.Self {
			mark = "*"
		}
		status := d.Status
		if d.ServerStatus == "suspended" && d.Status == chain.StatusActive {
			status = "suspended (run: esec vault devices revoke " + d.ID + ")"
		}
		seen := "never"
		if !d.LastSeen.IsZero() {
			seen = d.LastSeen.Local().Format("2006-01-02 15:04") //nolint:gosmopolitan // shown to the local user
		}
		method := d.Method
		if method == "" {
			method = "-"
		}
		fmt.Printf("%s %-16s %-24s %-10s %-9s %-40s last seen %s\n", mark, safetext.Clean(d.ID), safetext.Clean(d.Name), safetext.Clean(status), safetext.Clean(method), d.Words, seen)
	}
	return nil
}

// DevicesApproveCmd approves pending devices.
type DevicesApproveCmd struct {
	ID string `arg:"" optional:"" help:"Device id (default: every pending device, one at a time)"`
}

// Run implements devices approve.
func (c *DevicesApproveCmd) Run(ctx *cliCtx) error {
	a, err := openAccount(ctx)
	if err != nil {
		return err
	}
	bg, cancel := timeout(2 * time.Minute)
	defer cancel()
	pending, err := a.PendingDevices(bg)
	if err != nil {
		return err
	}
	if len(pending) == 0 {
		return errors.New("no device is waiting for approval (a new device appears after it signs in with 'esec vault login')")
	}
	approved := 0
	for _, p := range pending {
		if c.ID != "" && p.Info.ID != c.ID {
			continue
		}
		fmt.Printf("Pending: %s  %s  from %s  %s ago\n", p.Proof.Device.Name, p.Proof.Device.Platform, safetext.IP(p.Info.LastIP), time.Since(p.Proof.Device.Created).Round(time.Second))
		fmt.Printf("Account key: %s\n", a.State.Chain.AccountWords)
		// The fingerprint is not shown here: typing it from the new device's
		// own terminal proves the person approving can see that machine. A
		// device someone else signed in (for example with a phished code)
		// cannot be approved by just answering yes.
		typed, err := promptLine("Type the fingerprint words shown on the new device to approve it (Enter skips): ")
		if err != nil && typed == "" {
			fmt.Println("Skipped.")
			continue
		}
		if normalizeFingerprint(typed) != p.Words {
			if typed != "" {
				fmt.Println("That fingerprint does not match this device; not approved.")
			} else {
				fmt.Println("Skipped.")
			}
			continue
		}
		if err := a.Approve(bg, p); err != nil {
			return err
		}
		fmt.Printf("✓ Approved %s.\n", p.Proof.Device.Name)
		approved++
	}
	if approved == 0 && c.ID != "" {
		return fmt.Errorf("device %s is not waiting for approval", c.ID)
	}
	return nil
}

// DevicesRevokeCmd revokes a device.
type DevicesRevokeCmd struct {
	ID     string `arg:"" help:"Device id"`
	Reason string `help:"Reason recorded in the chain"`
	Yes    bool   `help:"Do not ask for confirmation"`
}

// Run implements devices revoke.
func (c *DevicesRevokeCmd) Run(ctx *cliCtx) error {
	a, err := openAccount(ctx)
	if err != nil {
		return err
	}
	if !c.Yes && !confirm(fmt.Sprintf("Revoke device %s and rotate your user key?", c.ID)) {
		return errors.New("revocation cancelled")
	}
	bg, cancel := timeout(5 * time.Minute)
	defer cancel()
	res, err := a.Revoke(bg, c.ID, c.Reason)
	if err != nil {
		return err
	}
	fmt.Printf("✓ Revoked %s (%s). Your user key is now version %d; every other device picks it up on its next sync.\n", res.Device.Name, res.Device.ID, res.UKeyVersion)
	rewrapSlots(bg, a, res.Slots)
	if len(res.Projects) > 0 {
		fmt.Println("The revoked device could read the keys of these projects:")
		for _, p := range res.Projects {
			fmt.Println("  " + p)
		}
		fmt.Println("If it may be compromised, rotate their environment keys with 'esec vault env rotate ENV' in each project,")
		fmt.Println("and change the secret values themselves at their providers: a rotated key does not change values the device already saw.")
	}
	return nil
}

// DevicesRenameCmd renames a device.
type DevicesRenameCmd struct {
	ID   string `arg:"" help:"Device id"`
	Name string `arg:"" help:"New name"`
}

// Run implements devices rename.
func (c *DevicesRenameCmd) Run(ctx *cliCtx) error {
	a, err := openAccount(ctx)
	if err != nil {
		return err
	}
	bg, cancel := timeout(time.Minute)
	defer cancel()
	if err := a.Rename(bg, c.ID, c.Name); err != nil {
		return err
	}
	fmt.Printf("✓ Renamed %s to %q.\n", c.ID, c.Name)
	return nil
}

// DevicesSuspendCmd blocks a device on the server.
type DevicesSuspendCmd struct {
	ID string `arg:"" help:"Device id"`
}

// Run implements devices suspend.
func (c *DevicesSuspendCmd) Run(ctx *cliCtx) error {
	a, err := openAccount(ctx)
	if err != nil {
		return err
	}
	bg, cancel := timeout(time.Minute)
	defer cancel()
	if err := a.Suspend(bg, c.ID); err != nil {
		return err
	}
	fmt.Printf("✓ Suspended %s on the server. Complete the revocation with: esec vault devices revoke %s\n", c.ID, c.ID)
	return nil
}

// AgentUnlockCmd manages SSH-agent unlock slots.
type AgentUnlockCmd struct {
	Enable  AgentUnlockEnableCmd  `cmd:"" help:"Let a key in your SSH agent unlock new devices."`
	List    AgentUnlockListCmd    `cmd:"" help:"List unlock slots."`
	Disable AgentUnlockDisableCmd `cmd:"" help:"Disable an unlock slot."`
}

// AgentUnlockEnableCmd creates a slot.
type AgentUnlockEnableCmd struct {
	Key     string `required:"" help:"SSH public key file (.pub) or SHA256 fingerprint of a key in your agent"`
	Expires string `default:"90d" help:"Slot lifetime, e.g. 30d, 90d, 365d"`
}

// Run implements agent-unlock enable.
func (c *AgentUnlockEnableCmd) Run(ctx *cliCtx) error {
	ttl, err := parseTTL(c.Expires)
	if err != nil {
		return err
	}
	fp := c.Key
	if data, err := os.ReadFile(c.Key); err == nil {
		_, fp, err = sshagent.ParseAuthorizedKey(data)
		if err != nil {
			return err
		}
	} else {
		fp = sshagent.NormalizeFingerprint(fp)
	}
	ag, err := sshagent.Dial()
	if err != nil {
		return err
	}
	defer ag.Close()
	key, err := ag.Find(fp)
	if err != nil {
		return err
	}
	if err := sshagent.Supported(key.Public); err != nil {
		return err
	}
	a, err := openAccount(ctx)
	if err != nil {
		return err
	}
	bg, cancel := timeout(2 * time.Minute)
	defer cancel()
	fmt.Println("Signing a test challenge twice; your agent may ask for confirmation.")
	id, err := a.EnableAgentSlot(bg, ag, key, ttl)
	if err != nil {
		return err
	}
	fmt.Printf("✓ Slot %s: key %s can unlock new devices until %s.\n", id, key.Fingerprint, time.Now().Add(ttl).Format("2006-01-02"))
	fmt.Println("On a new machine (with agent forwarding): esec vault login --ssh-agent")
	fmt.Println("Each use is recorded in your device chain and the server audit log, and your other devices are notified.")
	fmt.Println("Prefer a dedicated key with per-use confirmation (ssh-add -c, or your agent's prompt).")
	return nil
}

// AgentUnlockListCmd lists slots.
type AgentUnlockListCmd struct{}

// Run implements agent-unlock list.
func (c *AgentUnlockListCmd) Run(ctx *cliCtx) error {
	a, err := openAccount(ctx)
	if err != nil {
		return err
	}
	bg, cancel := timeout(time.Minute)
	defer cancel()
	slots, err := a.AgentSlots(bg)
	if err != nil {
		return err
	}
	if len(slots) == 0 {
		fmt.Println("No unlock slots.")
		return nil
	}
	now := time.Now()
	for _, s := range slots {
		state := "enabled"
		switch {
		case !s.Active:
			state = "removed"
		case s.ServerDisabled:
			state = "disabled on server"
		case !now.Before(s.Expires):
			state = "expired"
		case s.UKeyVersion != a.State.Chain.UKeyVersion:
			state = "stale (user key rotated)"
		}
		fmt.Printf("%s  %s  expires %s  %s\n", s.SlotID, s.SSHKeyFP, s.Expires.Local().Format("2006-01-02"), state) //nolint:gosmopolitan // shown to the local user
	}
	return nil
}

// AgentUnlockDisableCmd disables a slot.
type AgentUnlockDisableCmd struct {
	ID string `arg:"" help:"Slot id"`
}

// Run implements agent-unlock disable.
func (c *AgentUnlockDisableCmd) Run(ctx *cliCtx) error {
	a, err := openAccount(ctx)
	if err != nil {
		return err
	}
	bg, cancel := timeout(time.Minute)
	defer cancel()
	if err := a.DisableAgentSlot(bg, c.ID); err != nil {
		return err
	}
	fmt.Printf("✓ Disabled slot %s.\n", c.ID)
	return nil
}

// rewrapSlots re-creates agent unlock slots that a key rotation disabled,
// for keys the SSH agent still holds, keeping their original expiry.
func rewrapSlots(ctx context.Context, a *account.Account, slots []chain.SlotState) {
	if len(slots) == 0 {
		return
	}
	ag, err := sshagent.Dial()
	if err != nil {
		fmt.Printf("The rotation disabled %d SSH-agent unlock slot(s). Re-enable them with: esec vault agent-unlock enable --key <key>\n", len(slots))
		return
	}
	defer ag.Close()
	for _, s := range slots {
		ttl := time.Until(s.Expires)
		key, err := ag.Find(s.SSHKeyFP)
		if err != nil || ttl < time.Minute {
			fmt.Printf("Slot %s (%s) was disabled by the rotation; re-enable it with: esec vault agent-unlock enable --key %s\n", s.SlotID, s.SSHKeyFP, s.SSHKeyFP)
			continue
		}
		// A revoked device may have held this SSH key; re-creating the
		// slot would let it back in. Only an explicit yes re-creates it.
		if !confirm(fmt.Sprintf("The rotation disabled SSH-agent unlock for %s. Re-create it? Answer yes only if no revoked device ever had this SSH key", s.SSHKeyFP)) {
			fmt.Printf("Left slot %s disabled.\n", s.SlotID)
			continue
		}
		id, err := a.EnableAgentSlot(ctx, ag, key, ttl)
		if err != nil {
			fmt.Printf("! Could not re-create the slot for %s: %v\n", s.SSHKeyFP, err)
			continue
		}
		fmt.Printf("✓ Re-created SSH-agent unlock slot %s for %s.\n", id, s.SSHKeyFP)
	}
}

// normalizeFingerprint accepts fingerprint words separated by spaces,
// dashes or commas, in any case.
func normalizeFingerprint(s string) string {
	return strings.Join(strings.FieldsFunc(strings.ToLower(s), func(r rune) bool { return r == '-' || r == ' ' || r == ',' }), "-")
}

// parseTTL accepts Go durations plus a "d" (days) suffix.
func parseTTL(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if days, ok := strings.CutSuffix(s, "d"); ok {
		n, err := strconv.Atoi(days)
		if err != nil || n <= 0 {
			return 0, fmt.Errorf("invalid lifetime %q", s)
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("invalid lifetime %q", s)
	}
	return d, nil
}

// serverSync runs a vault sync when this machine is signed in.
func serverSync(ctx *cliCtx, interactive bool) error {
	a, err := openAccount(ctx)
	if errors.Is(err, account.ErrNotLoggedIn) {
		return err
	}
	if err != nil {
		return err
	}
	bg, cancel := timeout(2 * time.Minute)
	defer cancel()
	res, err := a.Sync(bg, account.SyncOptions{Interactive: interactive})
	if err != nil {
		return err
	}
	printSync(ctx, res)
	return nil
}

// accountRotate rotates the user key through the server.
func accountRotate(ctx *cliCtx) error {
	a, err := openAccount(ctx)
	if err != nil {
		return err
	}
	bg, cancel := timeout(5 * time.Minute)
	defer cancel()
	v, slots, err := a.RotateUserKey(bg, "manual rotation")
	if err != nil {
		return err
	}
	rewrapSlots(bg, a, slots)
	id, err := identity.Load(ctx.Keyring)
	if err != nil {
		return err
	}
	fmt.Printf("✓ Rotated your user key to version %d (fingerprint %s). Other devices pick it up on their next sync; your recovery phrase is unchanged.\n", v, identity.ShortFingerprint(id.Fingerprint()))
	return nil
}
