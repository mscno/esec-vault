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
	"github.com/mscno/esec-vault/internal/identity"
	"github.com/mscno/esec-vault/internal/paths"
	"github.com/mscno/esec-vault/internal/service"
)

// DaemonCmd owns the OS-managed background process.
type DaemonCmd struct {
	Install   DaemonInstallCmd   `cmd:"" help:"Install the user service and its stable executable copy."`
	Start     DaemonStartCmd     `cmd:"" help:"Enable and start the installed service."`
	Stop      DaemonStopCmd      `cmd:"" help:"Stop the service (preserve login startup)."`
	Disable   DaemonDisableCmd   `cmd:"" help:"Stop and disable login startup."`
	Restart   DaemonRestartCmd   `cmd:"" help:"Restart the service in locked state."`
	Uninstall DaemonUninstallCmd `cmd:"" help:"Remove service and runtime files, preserving keys."`
	Run       DaemonRunCmd       `cmd:"" help:"Foreground service entry point for launchd/systemd."`
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
	if err := m.Install(ctx, exe, c.Start); err != nil {
		return err
	}
	if c.Start {
		if err := waitDaemon(ctx); err != nil {
			return fmt.Errorf("service installed but not ready; inspect daemon logs: %w", err)
		}
	}
	fmt.Fprintln(os.Stderr, "Installed", m.Manifest.Unit)
	return nil
}

// DaemonRunCmd is the supervised foreground process.
type DaemonRunCmd struct{}

// Run starts locked and exits on OS cancellation.
func (c *DaemonRunCmd) Run(app *cliCtx) error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	s, err := daemon.New(app.Keyring, app.Logger)
	if err != nil {
		return err
	}
	return s.Serve(ctx)
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
		return waitDaemon(ctx)
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
		if err := m.Stop(ctx); err != nil {
			return err
		}
		if err := m.Start(ctx); err != nil {
			return err
		}
		return waitDaemon(ctx)
	case "uninstall":
		return m.Uninstall(ctx)
	default:
		return fmt.Errorf("unknown service action")
	}
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

// Run prints the service and session status.
func (c *DaemonStatusCmd) Run(app *cliCtx) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := daemon.Call(ctx, daemon.Request{Op: "status"})
	if err == nil {
		return printJSON(resp)
	}
	m, managerErr := service.New()
	if managerErr != nil {
		return managerErr
	}
	_, statErr := os.Stat(filepath.Join(paths.Home(), "daemon-install.json"))
	if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
		return statErr
	}
	return printJSON(map[string]any{"installed": statErr == nil, "reachable": false, "unit": m.Manifest.Unit, "error": err.Error()})
}

// UnlockCmd starts a bounded broker session, never changing service lifetime.
type UnlockCmd struct {
	TTL time.Duration `default:"4h" help:"Broker session duration (maximum 24h)"`
}

// Run requests a broker session using the OS keyring on the daemon side.
func (c *UnlockCmd) Run(app *cliCtx) error {
	resp, err := daemon.Call(context.Background(), daemon.Request{Op: "unlock", TTL: c.TTL})
	if err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "Unlocked until", resp.Expires.Format(time.RFC3339))
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
		return cmd.Run()
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

// SetupCmd guides identity, destination and managed-service setup.
type SetupCmd struct {
	NoDaemon bool `help:"Skip managed service installation"`
}

// Run preserves existing identity and settings while filling missing setup steps.
func (c *SetupCmd) Run(app *cliCtx) error {
	if _, err := identity.Load(app.Keyring); errors.Is(err, identity.ErrNotFound) {
		if err := (&InitCmd{}).Run(app); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	if confirm("Configure a backup destination?") {
		if err := (&RemoteAddCmd{Prefix: "personal/v2"}).Run(app); err != nil {
			return err
		}
		if err := (&RemoteTestCmd{}).Run(app); err != nil {
			return err
		}
		if err := (&BackupCmd{Verify: true, Push: true}).Run(app); err != nil {
			return err
		}
	}
	if !c.NoDaemon && confirm("Install and start the per-user background service?") {
		return (&DaemonInstallCmd{Start: true}).Run(app)
	}
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
