// Package cli implements the esec-vault command-line interface.
package cli

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

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
	Setup    SetupCmd    `cmd:"" group:"start" help:"Set this machine up in one go (identity, keys, backup, service, checkouts, guard), or --check what is left."`
	Init     InitCmd     `cmd:"" hidden:"" help:"Now esec vault setup."`
	Login    LoginCmd    `cmd:"" group:"start" help:"Sign in to a vault server and get your keys on this machine."`
	Logout   LogoutCmd   `cmd:"" group:"start" help:"End this machine's vault server session."`
	Status   StatusCmd   `cmd:"" group:"start" help:"Show identity, vault and backup status."`
	Doctor   DoctorCmd   `cmd:"" group:"start" help:"Diagnose setup problems (unmigrated keyrings, loose permissions)."`
	Activity ActivityCmd `cmd:"" group:"start" help:"Which programs and agents asked for keys, and what was allowed: the local audit log."`
	Verify   VerifyCmd   `cmd:"" group:"start" help:"Check no key can be lost: every key your checkouts and their git history use is here and in a second place, and none serves two projects."`

	Project      ProjectCmd      `cmd:"" group:"secrets" help:"Scaffold projects and environments."`
	Projects     ProjectsCmd     `cmd:"" group:"secrets" help:"Every project on this machine: where it is checked out, its environments, its keys here."`
	Env          EnvCmd          `cmd:"" group:"secrets" help:"Manage environment keys: add, list, rotate, and what picked a change up."`
	Hook         HookCmd         `cmd:"" group:"secrets" help:"A git pre-commit hook that refuses secrets in the clear and files encrypted to the wrong key."`
	Secrets      SecretsCmd      `cmd:"" group:"secrets" help:"Find, set and rotate values in secrets files; check them before a commit."`
	Run          RunCmd          `cmd:"" group:"secrets" help:"Run a command with broker-decrypted secrets injected."`
	Decrypt      DecryptCmd      `cmd:"" group:"secrets" help:"Print an environment's secrets, or one value, decrypted by the background service: a guarded one after a touch."`
	Forward      ForwardCmd      `cmd:"" group:"secrets" help:"SSH to a machine that may then ask this one for guarded keys, each read after your touch here."`
	Keyring      KeyringCmd      `cmd:"" group:"secrets" help:"Manage the global keyring store."`
	Seal         SealCmd         `cmd:"" group:"secrets" help:"Environment keys sealed in the repository (.esec/), for their readers and a recovery key: status, sync, check."`
	Share        ShareCmd        `cmd:"" group:"secrets" help:"Share environments with GitHub users (pinned by id), groups or keys: their keys are sealed in."`
	Unshare      UnshareCmd      `cmd:"" group:"secrets" help:"Stop sharing environments with someone, and optionally rotate."`
	CI           CICmd           `cmd:"" name:"ci" group:"secrets" help:"Give CI jobs and deploys their own age key, sealed into environments; they need only esec."`
	Guard        GuardCmd        `cmd:"" group:"secrets" help:"Guard environments: sealed to your YubiKeys only, every read needs your touch, which no agent can make."`
	SecurityKeys SecurityKeysCmd `cmd:"" name:"security-keys" group:"secrets" help:"Your YubiKeys: register the plugged-in ones, set one up, test, remove. Nobody types a recipient."`
	Keys         SecurityKeysCmd `cmd:"" hidden:"" help:"Now security-keys."`

	Sync        SyncCmd        `cmd:"" group:"team" help:"Bring this machine up to date with the vault server: your keys, and the shared projects' (accept invitations, send keys others are missing). The background service does this by itself."`
	Access      TeamCmd        `cmd:"" name:"access" group:"team" help:"Who reads which environments of a project shared on the server: create, grant, revoke, offboard."`
	Team        TeamCmd        `cmd:"" hidden:"" help:"Now access."`
	Group       GroupCmd       `cmd:"" group:"team" help:"Groups of people or machines that read the same environments (acme/backend, acme/production)."`
	Org         OrgCmd         `cmd:"" group:"team" help:"An organisation's projects, groups and policy (acme of acme/store)."`
	Personal    PersonalCmd    `cmd:"" group:"team" help:"Choose or rename your personal namespace without changing your GitHub identity."`
	Transfers   TransfersCmd   `cmd:"" group:"team" help:"Review, accept, reject or cancel signed project transfer offers."`
	Changes     ChangesCmd     `cmd:"" group:"team" help:"Sign the changes made on the web pages (members, access, machines)."`
	Todo        TodoCmd        `cmd:"" group:"team" help:"What waits for you across every project, group and organisation."`
	Delegate    DelegateCmd    `cmd:"" group:"team" help:"Passkeys and the server, which may sign some changes for you on the web."`
	Devices     DevicesCmd     `cmd:"" group:"team" help:"List, approve, revoke and rename your devices."`
	Index       IndexCmd       `cmd:"" group:"team" help:"Publish project and environment names (no secrets) for the web UI: on or off."`
	AgentUnlock AgentUnlockCmd `cmd:"" group:"team" name:"agent-unlock" help:"Let an SSH-agent key unlock new devices (optional)."`

	Machine MachineCmd `cmd:"" group:"machines" help:"Machine keys to a project shared on the server (most CI needs only esec vault ci add)."`
	App     AppCmd     `cmd:"" group:"machines" help:"Set up an app to read its secrets with no secret of its own, and check it before each deploy."`
	KMS     KMSCmd     `cmd:"" name:"kms" group:"machines" help:"Set up a cloud KMS key for workloads that hold no secret."`

	Backup   BackupCmd   `cmd:"" group:"backup" help:"Encrypt all keyrings and your identity into a backup; --push uploads it."`
	Restore  RestoreCmd  `cmd:"" group:"backup" help:"Restore keyrings from the backup."`
	Recover  RecoverCmd  `cmd:"" group:"backup" help:"Full cold recovery: phrase + backup -> identity -> keyrings."`
	Drill    DrillCmd    `cmd:"" group:"backup" help:"Prove a cold recovery works: the newest backup opens with the phrase alone and holds every key."`
	Remote   RemoteCmd   `cmd:"" group:"backup" help:"Manage cloud backup destinations."`
	Identity IdentityCmd `cmd:"" group:"backup" help:"Manage your identity keypair (mnemonic-backed)."`

	Daemon    DaemonCmd    `cmd:"" group:"service" help:"Manage the OS-supervised user daemon."`
	Unlock    UnlockCmd    `cmd:"" group:"service" help:"Unlock the broker for a bounded session."`
	Lock      LockCmd      `cmd:"" group:"service" help:"Lock the broker while backups continue."`
	Agent     AgentCmd     `cmd:"" group:"service" help:"Run the broker daemon holding keys in memory."`
	Approve   ApproveCmd   `cmd:"" group:"service" help:"Approve a pending broker request by id."`
	Uninstall UninstallCmd `cmd:"" group:"service" help:"Remove service; optionally purge local vault data."`

	Version kong.VersionFlag `help:"Show version"`
	Debug   bool             `help:"Enable debug logging" env:"ESEC_DEBUG"`
	Quiet   bool             `help:"Suppress non-essential output" short:"q"`
}

// commandGroups titles the sections of the top-level help.
var commandGroups = []kong.Group{
	{Key: "start", Title: "Get started:"},
	{Key: "secrets", Title: "Secrets in a project:"},
	{Key: "team", Title: "With a vault server: people, groups, organisations, devices:"},
	{Key: "machines", Title: "Machines and workloads without a secret (vault server; most CI needs only ci add):"},
	{Key: "backup", Title: "Backup and recovery:"},
	{Key: "service", Title: "Background service:"},
}

const description = `Identity, backup and team sharing for esec keyrings. Every command also runs as "esec vault ...".

Start here:

    esec vault setup                              # identity, backup and background service
    esec vault project init acme/api              # in a repository: esec.toml and env keys
    esec vault share dev,staging --with alice     # alice reads them; commit .esec/
    esec vault ci add deploy --env prod --github acme/api   # CI needs esec alone
    esec vault guard enable --env prod            # every prod read needs your touch
    esec vault run prod -- ./deploy               # or: esec run prod -- ./deploy

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
			if ctx.Selected() != nil || showAllHelp {
				return kong.DefaultHelpPrinter(o, ctx)
			}
			return everydayHelp(o, ctx)
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

	if now := renamed(ctx.Command()); now != "" && !c.Quiet {
		fmt.Fprintf(os.Stderr, "esec-vault: this command is now %s; the old name goes away in a later release\n", now)
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

// everydayCommands are the top-level commands the short help shows; the
// rest are in esec vault help all.
var everydayCommands = map[string]bool{
	"setup": true, "login": true, "status": true,
	"project": true, "env": true, "secrets": true, "run": true, "decrypt": true,
	"share": true, "unshare": true, "ci": true, "guard": true, "security-keys": true,
	"sync": true,
}

// showAllHelp is set by esec vault help all.
var showAllHelp bool

// everydayHelp prints the top-level help with the everyday commands only,
// and says how to see the rest.
func everydayHelp(o kong.HelpOptions, ctx *kong.Context) error {
	// Hidden commands also leave their sections, or the sections print
	// with nothing under them. Everything is put back after printing.
	type state struct {
		hidden bool
		group  *kong.Group
	}
	saved := map[*kong.Node]state{}
	more := 0
	for _, n := range ctx.Model.Children {
		saved[n] = state{n.Hidden, n.Group}
		if !n.Hidden && !everydayCommands[n.Name] {
			n.Hidden = true
			more++
		}
		if n.Hidden {
			n.Group = nil
		}
	}
	defer func() {
		for n, st := range saved {
			n.Hidden, n.Group = st.hidden, st.group
		}
	}()
	if err := kong.DefaultHelpPrinter(o, ctx); err != nil {
		return err
	}
	_, err := fmt.Fprintf(ctx.Stdout, "\n%d more commands (vault server, groups, machines, backups, the background service): esec vault help all\n", more)
	return err
}

// renamedCommands maps old command names, which still run for now, to what
// replaced them.
var renamedCommands = []struct{ old, now string }{
	{"init", "esec vault setup (in a script: esec vault identity init, then esec vault backup --verify)"},
	{"team", "esec vault access"},
	{"keys", "esec vault security-keys"},
	{"access sync", "esec vault sync"},
	{"group sync", "esec vault sync"},
	{"group grant", "esec vault group set"},
	{"remote push", "esec vault backup --push"},
	{"keyring seal", "esec vault keyring protect"},
	{"keyring unseal", "esec vault keyring unprotect"},
}

// renamed returns what replaced command, "" when it is current.
func renamed(command string) string {
	for _, r := range renamedCommands {
		if command == r.old || strings.HasPrefix(command, r.old+" ") {
			return r.now
		}
	}
	return ""
}

// isMutation reports whether a command changes keyrings, so it runs under the
// keyring lock and is followed by a snapshot and a server push.
func isMutation(command string) bool {
	for _, prefix := range []string{"project init", "env add", "env rename", "env rotate", "keyring add", "keyring migrate", "keyring protect", "keyring unprotect", "keyring seal", "keyring unseal", "keyring repair", "sync", "restore", "access sync", "team sync", "group sync", "guard enable", "guard disable", "seal sync", "seal migrate", "seal recover", "share", "unshare", "ci add", "ci remove", "security-keys add", "security-keys remove", "keys add", "keys remove"} {
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
	// Agents run many commands at once: wait for another one (which may be
	// waiting for a touch or the network) rather than fail.
	unlock, err := storage.LockWait(paths.KeyringDir(), 3*time.Minute, func() {
		fmt.Fprintln(os.Stderr, "Waiting for another esec-vault command that is changing keys (it may be waiting for a touch or the network)…")
	})
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
