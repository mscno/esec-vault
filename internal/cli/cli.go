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
	Setup  SetupCmd  `cmd:"" group:"start" help:"Guided identity, remote and background-service setup."`
	Init   InitCmd   `cmd:"" group:"start" help:"Set up an identity and first backup in one go."`
	Login  LoginCmd  `cmd:"" group:"start" help:"Sign in to a vault server and get your keys on this machine."`
	Logout LogoutCmd `cmd:"" group:"start" help:"End this machine's vault server session."`
	Status StatusCmd `cmd:"" group:"start" help:"Show identity, vault and backup status."`
	Doctor DoctorCmd `cmd:"" group:"start" help:"Diagnose setup problems (unmigrated keyrings, loose permissions)."`

	Project ProjectCmd `cmd:"" group:"secrets" help:"Scaffold projects and environments."`
	Env     EnvCmd     `cmd:"" group:"secrets" help:"Manage environment keys: add, list, rotate."`
	Run     RunCmd     `cmd:"" group:"secrets" help:"Run a command with broker-decrypted secrets injected."`
	Keyring KeyringCmd `cmd:"" group:"secrets" help:"Manage the global keyring store."`

	Access      TeamCmd        `cmd:"" name:"access" aliases:"team" group:"team" help:"Who reads which environments of a shared project: share it, grant, revoke, offboard."`
	Group       GroupCmd       `cmd:"" group:"team" help:"Groups of people or machines that read the same environments (acme/backend, acme/production)."`
	Org         OrgCmd         `cmd:"" group:"team" help:"An organisation's projects, groups and policy (acme of acme/store)."`
	Changes     ChangesCmd     `cmd:"" group:"team" help:"Sign the changes made on the web pages (members, access, machines)."`
	Delegate    DelegateCmd    `cmd:"" group:"team" help:"Passkeys and the server, which may sign some changes for you on the web."`
	Devices     DevicesCmd     `cmd:"" group:"team" help:"List, approve, revoke and rename your devices."`
	Index       IndexCmd       `cmd:"" group:"team" help:"Publish project and environment names (no secrets) for the web UI: on or off."`
	AgentUnlock AgentUnlockCmd `cmd:"" group:"team" name:"agent-unlock" help:"Let an SSH-agent key unlock new devices (optional)."`

	Machine MachineCmd `cmd:"" group:"machines" help:"Give CI jobs and apps their own keys to a shared project."`

	Backup   BackupCmd   `cmd:"" group:"backup" help:"Seal all keyrings and your identity into the vault blob."`
	Restore  RestoreCmd  `cmd:"" group:"backup" help:"Restore keyrings from the vault blob."`
	Recover  RecoverCmd  `cmd:"" group:"backup" help:"Full cold recovery: phrase + backup -> identity -> keyrings."`
	Remote   RemoteCmd   `cmd:"" group:"backup" help:"Manage cloud backup destinations."`
	Identity IdentityCmd `cmd:"" group:"backup" help:"Manage your identity keypair (mnemonic-backed)."`

	Daemon    DaemonCmd    `cmd:"" group:"service" help:"Manage the OS-supervised user daemon."`
	Unlock    UnlockCmd    `cmd:"" group:"service" help:"Unlock the broker for a bounded session."`
	Lock      LockCmd      `cmd:"" group:"service" help:"Lock the broker while backups continue."`
	Agent     AgentCmd     `cmd:"" group:"service" help:"Run the broker daemon holding keys in memory."`
	Approve   ApproveCmd   `cmd:"" group:"service" help:"Approve a pending broker request by id."`
	Uninstall UninstallCmd `cmd:"" group:"service" help:"Remove service; optionally purge local vault data."`

	Members MembersCmd `cmd:"" group:"git" help:"Manage team member identity proofs."`
	Share   ShareCmd   `cmd:"" group:"git" help:"Seal project keys to team members (writes committed blobs)."`
	Sync    SyncCmd    `cmd:"" group:"git" help:"Open your committed share blobs into the global keyring store."`

	Version kong.VersionFlag `help:"Show version"`
	Debug   bool             `help:"Enable debug logging" env:"ESEC_DEBUG"`
	Quiet   bool             `help:"Suppress non-essential output" short:"q"`
}

// commandGroups titles the sections of the top-level help.
var commandGroups = []kong.Group{
	{Key: "start", Title: "Get started:"},
	{Key: "secrets", Title: "Secrets in a project:"},
	{Key: "team", Title: "Share with people and machines (vault server):"},
	{Key: "machines", Title: "On machines, CI jobs and servers:"},
	{Key: "backup", Title: "Backup and recovery:"},
	{Key: "service", Title: "Background service:"},
	{Key: "git", Title: "Sharing through git, without a server:"},
}

const description = `Identity, backup and team sharing for esec keyrings. Every command also runs as "esec vault ...".

Start here:

    esec vault setup                          # identity, backup and background service
    esec vault login https://vault.example.com
    esec vault project init acme/api          # in a repository: project file and env keys
    esec vault access create                  # share it; you become its admin
    esec vault access grant alice --env dev   # alice's devices get the dev key
    esec vault group create acme/backend      # a team: people who read the same things
    esec vault group add acme/backend bob
    esec vault access grant acme/backend --env dev,staging

Scripts and agents: list and show commands take --json; commands that ask take --yes (or --force); "esec vault help <command>" explains one. Exit codes: 0 done, 1 failed, 80 bad usage; run and machine run return their command's code.`

// Execute runs the CLI.
func Execute(version string) {
	// The daemon reports this string over the control socket so a CLI can
	// detect that a managed service still runs an older executable copy.
	daemon.BuildVersion = version
	var c cli
	parser := kong.Must(&c,
		kong.ShortUsageOnError(),
		kong.Name("esec-vault"),
		kong.Description(description),
		kong.ExplicitGroups(commandGroups),
		kong.ConfigureHelp(kong.HelpOptions{NoExpandSubcommands: true}),
		kong.Help(func(o kong.HelpOptions, ctx *kong.Context) error {
			// One line per command at the top; below it, each with its arguments.
			o.Compact = ctx.Selected() == nil
			return kong.DefaultHelpPrinter(o, ctx)
		}),
		kong.Vars{"version": version},
	)
	addDetails(parser.Model)
	ctx, err := parser.Parse(helpArgs(os.Args[1:]))
	if err != nil {
		// Usage goes to stderr with the error, so stdout stays clean.
		parser.Stdout = os.Stderr
		parser.FatalIfErrorf(err)
	}

	level := slog.LevelInfo
	if c.Debug {
		level = slog.LevelDebug
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	app := &cliCtx{Logger: logger, Keyring: keyring.NewOS(), Quiet: c.Quiet, Version: version}
	mutation := isMutation(ctx.Command())
	app.keyringLocked = mutation
	err = runCommand(func() error { return ctx.Run(app) }, mutation)
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
	if err != nil {
		fmt.Fprintln(os.Stderr, "esec-vault: error:", err)
		for _, h := range hints(err, ctx.Selected()) {
			fmt.Fprintln(os.Stderr, "hint:", h)
		}
		os.Exit(1)
	}
}

// isMutation reports whether a command changes keyrings, so it runs under the
// keyring lock and is followed by a snapshot and a server push.
func isMutation(command string) bool {
	for _, prefix := range []string{"project init", "env add", "env rotate", "keyring add", "keyring migrate", "keyring seal", "keyring unseal", "sync", "restore", "access sync", "group sync"} {
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
