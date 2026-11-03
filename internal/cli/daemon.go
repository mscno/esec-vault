package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/mscno/esec-vault/internal/daemon"
	"github.com/mscno/esec-vault/internal/paths"
	"github.com/mscno/esec-vault/internal/service"
	"github.com/mscno/esec-vault/internal/storage"
)

// DaemonCmd owns the OS-managed background process.
type DaemonCmd struct {
	Install   DaemonInstallCmd   `cmd:"" help:"Install the user service and its stable executable copy."`
	Upgrade   DaemonUpgradeCmd   `cmd:"" help:"Replace the managed copy with this binary and restart it."`
	Start     DaemonStartCmd     `cmd:"" help:"Enable and start the installed service."`
	Stop      DaemonStopCmd      `cmd:"" help:"Stop the service (preserve login startup)."`
	Disable   DaemonDisableCmd   `cmd:"" help:"Stop and disable login startup."`
	Restart   DaemonRestartCmd   `cmd:"" help:"Restart the service in locked state."`
	Uninstall DaemonUninstallCmd `cmd:"" help:"Remove service and runtime files, preserving keys."`
	Run       DaemonRunCmd       `cmd:"" hidden:"" help:"Foreground service entry point for launchd/systemd."`
	Status    DaemonStatusCmd    `cmd:"" help:"Show service registration and broker session state."`
	Logs      DaemonLogsCmd      `cmd:"" help:"Show recent service logs."`
	Job       DaemonJobCmd       `cmd:"" help:"Inspect an asynchronous backup job."`
	Reload    DaemonReloadCmd    `cmd:"" help:"Reload broker policy."`
}

// DaemonInstallCmd installs without requiring a shell session to stay open.
type DaemonInstallCmd struct {
	Start bool `help:"Start immediately as well as at login"`
}

// Run installs using an owned, stable copy of the current executable.
func (c *DaemonInstallCmd) Run(app *cliCtx) error {
	return installManaged(c.Start)
}

// DaemonUpgradeCmd replaces the managed copy after the CLI itself was upgraded.
type DaemonUpgradeCmd struct {
	Start bool `help:"Start the service immediately as well as at login" default:"true"`
}

// Run refreshes the managed executable. Upgrading the CLI on disk does not
// touch the daemon, because the service runs its own private copy.
func (c *DaemonUpgradeCmd) Run(app *cliCtx) error {
	return installManaged(c.Start)
}

// installManaged copies this executable into the managed location. It is a
// no-op when the copy and unit already match, so a healthy daemon is not
// bounced and its broker session survives.
func installManaged(start bool) error {
	if err := refuseAppServiceControl(); err != nil {
		return err
	}
	if !daemon.ManagedSocket() {
		return fmt.Errorf("managed service requires the default broker socket; unset ESEC_VAULT_SOCK")
	}
	m, err := service.New()
	if err != nil {
		return err
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	same, err := m.Current(exe)
	if err != nil {
		return err
	}
	if err := m.Install(ctx, exe, start); err != nil {
		return err
	}
	if err := m.UseService(); err != nil {
		return err
	}
	if start {
		if err := waitDaemon(ctx); err != nil {
			return fmt.Errorf("service installed but not ready; inspect daemon logs: %w", err)
		}
	}
	if same {
		fmt.Fprintln(os.Stderr, "Already up to date:", m.Manifest.Binary)
		return nil
	}
	fmt.Fprintln(os.Stderr, "Installed", m.Manifest.Unit)
	if start {
		fmt.Fprintln(os.Stderr, "The daemon starts locked; run: esec-vault unlock")
	}
	return nil
}

// DaemonRunCmd is the supervised foreground process.
type DaemonRunCmd struct {
	AppOwned bool `help:"Run while the owning Mac app keeps stdin open"`
}

// Run starts locked and exits on OS cancellation.
func (c *DaemonRunCmd) Run(app *cliCtx) error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if c.AppOwned {
		if runtime.GOOS != "darwin" || !daemon.ManagedSocket() {
			return fmt.Errorf("app-owned helper requires macOS and the default broker socket")
		}
		info, err := os.Stdin.Stat()
		if err != nil || info.Mode()&os.ModeNamedPipe == 0 {
			return fmt.Errorf("app-owned helper requires a private lifetime pipe on stdin")
		}
		return daemon.WithParent(ctx, os.Stdin, 5*time.Second, func(ctx context.Context) error {
			unlock, err := storage.Lock(filepath.Join(paths.Home(), "app-helper"))
			if err != nil {
				return fmt.Errorf("another EsecVault app already owns the helper: %w", err)
			}
			defer unlock()
			m, err := service.New()
			if err != nil {
				return err
			}
			migration, migrationCancel := context.WithTimeout(ctx, 45*time.Second)
			defer migrationCancel()
			if err := m.UseApp(migration); err != nil {
				return err
			}
			return runDaemon(ctx, app, "app")
		})
	}
	return runDaemon(ctx, app, "service")
}

func runDaemon(ctx context.Context, app *cliCtx, owner string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s, err := daemon.New(app.Keyring, app.Logger)
	if err != nil {
		return err
	}
	s.Owner = owner
	return s.Serve(ctx)
}

func refuseAppServiceControl() error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if resp, err := daemon.Call(ctx, daemon.Request{Op: "status"}); err == nil && resp.Owner == "app" {
		return fmt.Errorf("EsecVault owns this helper; quit the menu-bar app to stop it, or use Restart Helper in the app")
	}
	return nil
}

// DaemonStartCmd enables and starts a service.
type DaemonStartCmd struct{}

// Run starts the service and waits for the socket handshake.
func (c *DaemonStartCmd) Run(app *cliCtx) error { return manageService("start") }

// DaemonStopCmd stops a process without disabling startup.
type DaemonStopCmd struct{}

// Run stops a managed or foreground daemon.
func (c *DaemonStopCmd) Run(app *cliCtx) error { return manageService("stop") }

// DaemonDisableCmd disables startup and stops the service.
type DaemonDisableCmd struct{}

// Run disables the user service.
func (c *DaemonDisableCmd) Run(app *cliCtx) error { return manageService("disable") }

// DaemonRestartCmd restarts locked.
type DaemonRestartCmd struct{}

// Run restarts the service.
func (c *DaemonRestartCmd) Run(app *cliCtx) error { return manageService("restart") }

// DaemonUninstallCmd removes installation-owned artifacts.
type DaemonUninstallCmd struct{}

// Run removes the service while retaining vault data.
func (c *DaemonUninstallCmd) Run(app *cliCtx) error { return manageService("uninstall") }

func manageService(action string) error {
	if err := refuseAppServiceControl(); err != nil {
		return err
	}
	m, err := service.New()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	switch action {
	case "start":
		if err := m.Start(ctx); err != nil {
			return err
		}
		if err := waitDaemon(ctx); err != nil {
			return err
		}
		return m.UseService()
	case "stop":
		if err := m.Stop(ctx); err != nil {
			return err
		}
		// A foreground daemon has no registration; it can stop over its socket.
		if _, err := os.Stat(filepath.Join(paths.Home(), "daemon-install.json")); errors.Is(err, os.ErrNotExist) {
			_, callErr := daemon.Call(ctx, daemon.Request{Op: "shutdown"})
			if callErr == nil {
				return waitDaemonStopped(ctx)
			}
		}
		return nil
	case "disable":
		return m.Disable(ctx)
	case "restart":
		// Restarting re-executes the managed copy, not the binary on PATH.
		// Refuse when that copy is stale so an upgrade is never mistaken for
		// one that already took effect.
		if err := requireCurrent(m); err != nil {
			return err
		}
		if err := m.Stop(ctx); err != nil {
			return err
		}
		if err := m.Start(ctx); err != nil {
			return err
		}
		if err := waitDaemon(ctx); err != nil {
			return err
		}
		return m.UseService()
	case "uninstall":
		return m.Uninstall(ctx)
	default:
		return fmt.Errorf("unknown service action")
	}
}

// requireCurrent fails when the managed executable differs from this binary.
// Restarting or starting a stale copy silently keeps the old code running
// after an upgrade, which is the failure mode this guards against.
func requireCurrent(m *service.Manager) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	return requireCurrentWith(m, exe)
}

// requireCurrentWith is the testable form: it compares source against the
// managed copy instead of assuming the current process.
func requireCurrentWith(m *service.Manager, source string) error {
	if !m.Installed() {
		return nil
	}
	same, err := m.BinaryCurrent(source)
	if err != nil {
		return err
	}
	if same {
		return nil
	}
	return fmt.Errorf("the managed daemon at %s is older than this binary; run: esec-vault daemon upgrade", m.Manifest.Binary)
}

func waitDaemon(ctx context.Context) error {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		if _, err := daemon.Call(ctx, daemon.Request{Op: "ping"}); err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}
func waitDaemonStopped(ctx context.Context) error {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		if _, err := daemon.Call(ctx, daemon.Request{Op: "ping"}); err != nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

// DaemonStatusCmd reports OS ownership and socket state.
type DaemonStatusCmd struct{}

// daemonStatusView keeps service installation separate from the broker's
// reachability and session. A stopped service still reports its build status.
type daemonStatusView struct {
	*daemon.Response

	Installed  bool   `json:"installed"`
	Reachable  bool   `json:"reachable"`
	Managed    bool   `json:"managed"`
	Unit       string `json:"unit,omitempty"`
	AppManaged bool   `json:"app_managed"`
}

// Run prints the service and session status.
func (c *DaemonStatusCmd) Run(app *cliCtx) error {
	m, err := service.New()
	if err != nil {
		return err
	}
	v := daemonStatusView{Response: &daemon.Response{CLI: app.Version}, Installed: m.Installed(), Managed: daemon.ManagedSocket(), Unit: m.Manifest.Unit}
	v.AppManaged = service.AppManaged()
	if v.Installed && !v.AppManaged {
		if exe, exeErr := os.Executable(); exeErr == nil {
			v.UpToDate, _ = m.BinaryCurrent(exe)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := daemon.Call(ctx, daemon.Request{Op: "status"})
	if err == nil {
		managedCurrent := v.UpToDate
		v.Response, v.Reachable = resp, true
		resp.CLI = app.Version
		v.AppManaged = v.AppManaged || resp.Owner == "app"
		resp.UpToDate = sameHelperBuild(resp.Version, app.Version) && (v.AppManaged || !v.Installed || managedCurrent)
		if !resp.UpToDate {
			fmt.Fprintln(os.Stderr, "!", daemonBuildAdvice(resp, app.Version))
		}
		return printJSON(v)
	}
	v.Error = err.Error()
	return printJSON(v)
}

func daemonBuildAdvice(resp *daemon.Response, version string) string {
	fix := "run: esec-vault daemon upgrade"
	if resp.Owner == "app" {
		fix = "update and reopen EsecVault, and use the matching CLI release"
	}
	return fmt.Sprintf("helper runs %s but this CLI is %s; %s", orUnknown(resp.Version), orUnknown(version), fix)
}

// orUnknown labels a missing build string so status output stays unambiguous
// when talking to a daemon that predates version reporting.
func orUnknown(v string) string {
	if v == "" {
		return "unknown"
	}
	return v
}

// UnlockCmd starts a bounded broker session, never changing service lifetime.
type UnlockCmd struct {
	TTL time.Duration `default:"4h" help:"Broker session duration (maximum 24h)"`
}

// Run requests a broker session using the OS keyring on the daemon side.
func (c *UnlockCmd) Run(app *cliCtx) error {
	resp, err := daemon.Call(context.Background(), daemon.Request{Op: "unlock", TTL: c.TTL})
	if err != nil {
		if resp == nil && service.AppManaged() {
			return fmt.Errorf("open EsecVault and check its local helper status: %w", err)
		}
		return err
	}
	// Say what unlocking does not need: a YubiKey touched now, with nothing
	// waiting for it, types its one-time password into the terminal.
	fmt.Fprintln(os.Stderr, "Unlocked until", resp.Expires.Format(time.RFC3339)+"; unlocking needs no security key.")
	fmt.Fprintln(os.Stderr, "A guarded environment requests passkey or security-key approval when read with esec vault decrypt ENV or esec vault run ENV -- COMMAND;")
	fmt.Fprintln(os.Stderr, "one guarded for the session then stays open, without asking, until the vault locks.")
	return nil
}

// LockCmd ends broker access without stopping backups.
type LockCmd struct{}

// Run clears the daemon's broker cache.
func (c *LockCmd) Run(app *cliCtx) error {
	_, err := daemon.Call(context.Background(), daemon.Request{Op: "lock"})
	return err
}

// DaemonJobCmd inspects one job.
type DaemonJobCmd struct {
	ID string `arg:"" help:"Job id"`
}

// Run prints queued/completed/failed job metadata.
func (c *DaemonJobCmd) Run(app *cliCtx) error {
	resp, err := daemon.Call(context.Background(), daemon.Request{Op: "job", ID: c.ID})
	if err != nil {
		return err
	}
	return printJSON(resp.Job)
}

// DaemonReloadCmd reloads fixed-location policy.
type DaemonReloadCmd struct{}

// Run refreshes policy without changing the unlock deadline.
func (c *DaemonReloadCmd) Run(app *cliCtx) error {
	_, err := daemon.Call(context.Background(), daemon.Request{Op: "reload"})
	return err
}

// DaemonLogsCmd displays recent platform-managed service logs.
type DaemonLogsCmd struct {
	Lines int `default:"100" help:"Number of recent lines"`
}

// Run reads launchd's managed file or the systemd user journal.
func (c *DaemonLogsCmd) Run(app *cliCtx) error {
	if service.AppManaged() {
		return fmt.Errorf("EsecVault owns this helper; startup and retry errors are shown in the app's Local helper section")
	}
	if c.Lines < 1 || c.Lines > 10000 {
		return fmt.Errorf("lines must be between 1 and 10000")
	}
	m, err := service.New()
	if err != nil {
		return err
	}
	if runtime.GOOS == "linux" {
		cmd := exec.Command("journalctl", "--user", "-u", m.Manifest.Name, "-n", fmt.Sprint(c.Lines), "--no-pager")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			// Exit code 1 can also mean "no entries"; only surface a real failure.
			var exit *exec.ExitError
			if errors.As(err, &exit) && exit.ExitCode() == 1 {
				return nil
			}
			return fmt.Errorf("journalctl: %w", err)
		}
		return nil
	}
	data, err := os.ReadFile(m.Manifest.Log)
	if err != nil {
		return err
	}
	lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	if len(lines) > c.Lines {
		lines = lines[len(lines)-c.Lines:]
	}
	fmt.Println(strings.Join(lines, "\n"))
	return nil
}

// UninstallCmd removes the service, and optionally all known local vault data.
type UninstallCmd struct {
	Purge  bool `help:"Delete local keys, backups, settings and OS-keyring identity"`
	Yes    bool `help:"Confirm deletion without an interactive prompt"`
	DryRun bool `help:"Preview paths without changing anything"`
}

// Run requires explicit purge consent; cloud objects and transport credentials remain external.
func (c *UninstallCmd) Run(app *cliCtx) error {
	m, err := service.New()
	if err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "Service:", m.Manifest.Unit, "\nManaged executable:", m.Manifest.Binary, "\nRuntime:", m.Manifest.Runtime)
	var preview []string
	if c.Purge {
		preview, err = service.PurgePaths()
		if err != nil {
			return err
		}
		for _, p := range preview {
			fmt.Fprintln(os.Stderr, p)
		}
		fmt.Fprintln(os.Stderr, "OS keyring: esec-vault identity-private and identity-public")
	}
	if c.DryRun {
		return nil
	}
	if err := refuseAppServiceControl(); err != nil {
		return err
	}
	if c.Purge && !c.Yes && !confirm("Permanently delete these local private keys, snapshots and identity entries?") {
		return fmt.Errorf("purge cancelled")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	if err := m.Uninstall(ctx); err != nil {
		return err
	}
	if c.Purge {
		return service.Purge(app.Keyring, preview)
	}
	return nil
}
