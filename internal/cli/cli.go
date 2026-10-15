// Package cli implements the esec-vault command-line interface.
package cli

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/alecthomas/kong"

	"github.com/mscno/esec-vault/internal/account"
	"github.com/mscno/esec-vault/internal/daemon"
	"github.com/mscno/esec-vault/internal/identity"
	"github.com/mscno/esec-vault/internal/keyring"
	"github.com/mscno/esec-vault/internal/keystore"
	"github.com/mscno/esec-vault/internal/paths"
	"github.com/mscno/esec-vault/internal/remote"
	"github.com/mscno/esec-vault/internal/storage"
)

type cliCtx struct {
	Logger  *slog.Logger
	Keyring keyring.Keyring
	Quiet   bool
	// Version is this binary's build string, compared against the daemon's.
	Version string
	// keyringLocked is set while a mutating command holds the keyring lock.
	keyringLocked bool
}

type cli struct {
	Setup     SetupCmd     `cmd:"" help:"Guided identity, remote and background-service setup."`
	Daemon    DaemonCmd    `cmd:"" help:"Manage the OS-supervised user daemon."`
	Unlock    UnlockCmd    `cmd:"" help:"Unlock the broker for a bounded session."`
	Lock      LockCmd      `cmd:"" help:"Lock the broker while backups continue."`
	Uninstall UninstallCmd `cmd:"" help:"Remove service; optionally purge local vault data."`
	Init      InitCmd      `cmd:"" help:"Set up an identity and first backup in one go."`
	Status    StatusCmd    `cmd:"" help:"Show identity, vault and backup status."`
	Doctor    DoctorCmd    `cmd:"" help:"Diagnose setup problems (unmigrated keyrings, loose permissions)."`
	Identity  IdentityCmd  `cmd:"" help:"Manage your identity keypair (mnemonic-backed)."`
	Keyring   KeyringCmd   `cmd:"" help:"Manage the global keyring store."`
	Project   ProjectCmd   `cmd:"" help:"Scaffold projects and environments."`
	Env       EnvCmd       `cmd:"" help:"Manage environment keys."`
	Backup    BackupCmd    `cmd:"" help:"Seal all keyrings and your identity into the vault blob."`
	Restore   RestoreCmd   `cmd:"" help:"Restore keyrings from the vault blob."`
	Recover   RecoverCmd   `cmd:"" help:"Full cold recovery: phrase + backup -> identity -> keyrings."`
	Agent     AgentCmd     `cmd:"" help:"Run the broker daemon holding keys in memory."`
	Run       RunCmd       `cmd:"" help:"Run a command with broker-decrypted secrets injected."`
	Approve   ApproveCmd   `cmd:"" help:"Approve a pending broker request by id."`
	Members   MembersCmd   `cmd:"" help:"Manage team member identity proofs."`
	Share     ShareCmd     `cmd:"" help:"Seal project keys to team members (writes committed blobs)."`
	Sync      SyncCmd      `cmd:"" help:"Open your committed share blobs into the global keyring store."`
	Remote    RemoteCmd    `cmd:"" help:"Manage cloud backup destinations."`

	Login       LoginCmd       `cmd:"" help:"Sign in to a vault server and get your keys on this machine."`
	Logout      LogoutCmd      `cmd:"" help:"End this machine's vault server session."`
	Devices     DevicesCmd     `cmd:"" help:"List, approve, revoke and rename your devices."`
	AgentUnlock AgentUnlockCmd `cmd:"" name:"agent-unlock" help:"Let an SSH-agent key unlock new devices (optional)."`
	Index       IndexCmd       `cmd:"" help:"Publish project and environment names (no secrets) for the web UI: on or off."`

	Version kong.VersionFlag `help:"Show version"`
	Debug   bool             `help:"Enable debug logging" env:"ESEC_DEBUG"`
	Quiet   bool             `help:"Suppress non-essential output" short:"q"`
}

// Execute runs the CLI.
func Execute(version string) {
	// The daemon reports this string over the control socket so a CLI can
	// detect that a managed service still runs an older executable copy.
	daemon.BuildVersion = version
	var c cli
	ctx := kong.Parse(&c,
		kong.ShortUsageOnError(),
		kong.Name("esec-vault"),
		kong.Description("Identity, backup and team sharing for esec keyrings"),
		kong.Vars{"version": version},
	)

	level := slog.LevelInfo
	if c.Debug {
		level = slog.LevelDebug
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	app := &cliCtx{Logger: logger, Keyring: keyring.NewOS(), Quiet: c.Quiet, Version: version}
	mutation := isMutation(ctx.Command())
	app.keyringLocked = mutation
	err := runCommand(func() error { return ctx.Run(app) }, mutation)
	if mutation && !daemon.Notify() {
		// Persist even partially successful imports; offline upload failures leave
		// the local snapshot and pending marker intact for the watch worker.
		if id, loadErr := identity.Load(app.Keyring); loadErr == nil {
			if _, backupErr := remote.BuildSnapshot(id, keystore.New()); backupErr != nil {
				logger.Warn("keys saved, but backup is pending", "error", backupErr)
			}
			maybeAutoPush(app)
		}
		// Without a daemon, push key changes to the vault server right away.
		if err == nil && !strings.HasPrefix(ctx.Command(), "sync") {
			if syncErr := serverSync(&cliCtx{Logger: logger, Keyring: app.Keyring, Quiet: true}, false); syncErr != nil && !errors.Is(syncErr, account.ErrNotLoggedIn) {
				logger.Warn("keys saved, but the vault server sync is pending", "error", syncErr)
			}
		}
	}
	// Never exit on a failure without telling the user why. Both branches below
	// used to os.Exit silently, which made a failing command look like success
	// with no output at all.
	//
	// Suppression is keyed on a sentinel type, never on the error text: many
	// real failures (rclone, launchctl, git) legitimately embed "exit status"
	// in a message that carries the only diagnostic we have.
	var forwarded *forwardedExitError
	if errors.As(err, &forwarded) {
		os.Exit(forwarded.code)
	}
	var codeErr *exitCodeError
	if errors.As(err, &codeErr) {
		if codeErr.msg != "" {
			fmt.Fprintln(os.Stderr, "esec-vault: error:", codeErr.msg)
		}
		os.Exit(codeErr.code)
	}
	ctx.FatalIfErrorf(err)
}

// isMutation reports whether a command changes keyrings, so it runs under the
// keyring lock and is followed by a snapshot and a server push.
func isMutation(command string) bool {
	for _, prefix := range []string{"project init", "env add", "env rotate", "keyring add", "keyring migrate", "keyring seal", "keyring unseal", "sync", "restore"} {
		if strings.HasPrefix(command, prefix) {
			return true
		}
	}
	return false
}

func runCommand(run func() error, mutation bool) error {
	if !mutation {
		return run()
	}
	unlock, err := storage.Lock(paths.KeyringDir())
	if err != nil {
		return err
	}
	defer unlock()
	return run()
}

// exitCodeError carries a desired process exit code plus the reason for it.
// The message is mandatory for any non-empty failure: a bare exit code leaves
// the user with no way to tell success from failure.
type exitCodeError struct {
	code int
	msg  string
}

func (e *exitCodeError) Error() string {
	if e.msg == "" {
		return fmt.Sprintf("exit status %d", e.code)
	}
	return e.msg
}

// forwardedExitError signals that a child process already reported its own
// failure on stderr, so only the exit code should be propagated. It is the one
// case where exiting silently is correct.
type forwardedExitError struct{ code int }

func (e *forwardedExitError) Error() string { return fmt.Sprintf("exit status %d", e.code) }
