package cli

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/mscno/esec-vault/internal/identity"
)

// IdentityCmd groups identity management.
type IdentityCmd struct {
	Init    IdentityInitCmd    `cmd:"" help:"Create a new identity; prints your 24-word recovery phrase."`
	Recover IdentityRecoverCmd `cmd:"" help:"Recover your identity from the 24-word recovery phrase."`
	Rotate  IdentityRotateCmd  `cmd:"" help:"Rotate the identity keypair (re-wraps to your master key)."`
	Show    IdentityShowCmd    `cmd:"" help:"Show your public key and fingerprint."`
}

// IdentityInitCmd creates a new identity.
type IdentityInitCmd struct{}

// Run implements the init command.
func (c *IdentityInitCmd) Run(ctx *cliCtx) error {
	mnemonic, err := identity.Init(ctx.Keyring, func() bool {
		return confirm("An identity already exists. Overwrite it? Old vault blobs become unreadable.")
	})
	if err != nil {
		if errors.Is(err, identity.ErrExists) {
			return fmt.Errorf("aborted; existing identity kept")
		}
		return err
	}
	fmt.Println("Your recovery phrase (write it down, store it safely — it is the ONLY cold recovery path):")
	fmt.Println()
	fmt.Println("  " + mnemonic)
	fmt.Println()
	fmt.Println("Confirm you have written it down by re-entering it:")
	fmt.Print("> ")
	reader := bufio.NewReader(os.Stdin)
	entered, err := reader.ReadString('\n')
	if err != nil {
		return err
	}
	if strings.Join(strings.Fields(strings.TrimSpace(entered)), " ") != mnemonic {
		return fmt.Errorf("recovery phrase did not match; identity was created anyway — recover with the phrase you wrote down")
	}
	fmt.Println("Identity created.")
	return nil
}

// IdentityRecoverCmd recovers from the mnemonic.
type IdentityRecoverCmd struct{}

// Run implements the recover command.
func (c *IdentityRecoverCmd) Run(ctx *cliCtx) error {
	fmt.Println("Paste your 24-word recovery phrase:")
	fmt.Print("> ")
	reader := bufio.NewReader(os.Stdin)
	entered, err := reader.ReadString('\n')
	if err != nil {
		return err
	}
	mnemonic := strings.Join(strings.Fields(strings.TrimSpace(entered)), " ")
	err = identity.Recover(ctx.Keyring, mnemonic, func() bool {
		return confirm("An identity already exists. Overwrite it?")
	})
	if err != nil {
		if errors.Is(err, identity.ErrExists) {
			return fmt.Errorf("aborted; existing identity kept")
		}
		return err
	}
	fmt.Println("Identity recovered and stored in the OS keyring.")
	return nil
}

// IdentityRotateCmd rotates the identity keypair.
type IdentityRotateCmd struct{}

// Run implements the rotate command.
func (c *IdentityRotateCmd) Run(ctx *cliCtx) error {
	fmt.Println("Paste your 24-word recovery phrase to authorize rotation:")
	fmt.Print("> ")
	reader := bufio.NewReader(os.Stdin)
	entered, err := reader.ReadString('\n')
	if err != nil {
		return err
	}
	mnemonic := strings.Join(strings.Fields(strings.TrimSpace(entered)), " ")
	id, err := identity.Rotate(ctx.Keyring, mnemonic)
	if err != nil {
		return err
	}
	fmt.Println("Identity rotated.")
	fmt.Println("New public key:", id.PublicHex())
	fmt.Println("New fingerprint:", id.Fingerprint())
	fmt.Println("Note: re-run 'esec-vault backup' and ask teammates to re-share; old sealed blobs are unreadable.")
	return nil
}

// IdentityShowCmd shows the public key and fingerprint.
type IdentityShowCmd struct{}

// Run implements the show command.
func (c *IdentityShowCmd) Run(ctx *cliCtx) error {
	id, err := identity.Load(ctx.Keyring)
	if err != nil {
		return err
	}
	fmt.Println("Public key:  ", id.PublicHex())
	fmt.Println("Fingerprint: ", id.Fingerprint())
	return nil
}
