// Package cli implements the esec-vault command-line interface.
package cli

import (
	"bufio"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/alecthomas/kong"

	"github.com/mscno/esec-vault/internal/keyring"
)

type cliCtx struct {
	Logger  *slog.Logger
	Keyring keyring.Keyring
}

type cli struct {
	Identity IdentityCmd `cmd:"" help:"Manage your identity keypair (mnemonic-backed)."`
	Keyring  KeyringCmd  `cmd:"" help:"Manage the global keyring store."`
	Backup   BackupCmd   `cmd:"" help:"Seal all keyrings into the vault blob."`
	Restore  RestoreCmd  `cmd:"" help:"Restore keyrings from the vault blob."`
	Recover  RecoverCmd  `cmd:"" help:"Full cold recovery: mnemonic -> identity -> keyrings."`
	Agent    AgentCmd    `cmd:"" help:"Run the broker daemon holding keys in memory."`
	Run      RunCmd      `cmd:"" help:"Run a command with broker-decrypted secrets injected."`
	Approve  ApproveCmd  `cmd:"" help:"Approve a pending broker request by id."`
	Members  MembersCmd  `cmd:"" help:"Manage team member identity proofs."`
	Share    ShareCmd    `cmd:"" help:"Seal project keys to team members (writes committed blobs)."`
	Sync     SyncCmd     `cmd:"" help:"Open your committed share blobs into the global keyring store."`

	Version kong.VersionFlag `help:"Show version"`
	Debug   bool             `help:"Enable debug logging" env:"ESEC_DEBUG"`
}

// Execute runs the CLI.
func Execute(version string) {
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

	err := ctx.Run(&cliCtx{Logger: logger, Keyring: keyring.NewOS()})
	var exitErr interface{ ExitCode() int }
	if errors.As(err, &exitErr) {
		os.Exit(exitErr.ExitCode())
	}
	var codeErr *exitCodeError
	if errors.As(err, &codeErr) {
		os.Exit(codeErr.code)
	}
	ctx.FatalIfErrorf(err)
}

// exitCodeError carries a desired process exit code.
type exitCodeError struct{ code int }

func (e *exitCodeError) Error() string { return fmt.Sprintf("exit status %d", e.code) }

// confirm prompts the user with a y/N question on the terminal.
func confirm(question string) bool {
	fmt.Printf("%s [y/N]: ", question)
	reader := bufio.NewReader(os.Stdin)
	answer, err := reader.ReadString('\n')
	if err != nil {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(answer), "y")
}
