package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"time"

	"github.com/tyler-smith/go-bip39"

	"github.com/mscno/esec-vault/internal/identity"
	"github.com/mscno/esec-vault/internal/identity/legacy"
	"github.com/mscno/esec-vault/internal/paths"
	"github.com/mscno/esec-vault/internal/storage"
	"github.com/mscno/esec-vault/internal/vaultfile"
)

// IdentityCmd groups identity management.
type IdentityCmd struct {
	Init       IdentityInitCmd       `cmd:"" help:"Create a new identity; prints your 24-word recovery phrase."`
	Recover    IdentityRecoverCmd    `cmd:"" help:"Recover your identity from the recovery phrase and a vault backup."`
	Rotate     IdentityRotateCmd     `cmd:"" help:"Rotate the identity keypair (re-wraps to your master key)."`
	Show       IdentityShowCmd       `cmd:"" help:"Show your public key and fingerprint."`
	Passphrase IdentityPassphraseCmd `cmd:"" help:"Set, change or remove the identity passphrase."`
	Migrate    IdentityMigrateCmd    `cmd:"" help:"Upgrade a pre-v2 identity to the current derivation."`
}

// IdentityInitCmd creates a new identity.
type IdentityInitCmd struct {
	Passphrase   bool `help:"Prompt for a passphrase to protect the recovery phrase"`
	NoPassphrase bool `help:"Create without a passphrase (recovery phrase only)"`
	Force        bool `help:"Overwrite an existing identity without prompting"`
	SkipConfirm  bool `help:"Skip the re-entry confirmation of the recovery phrase"`
}

// Run implements the init command.
func (c *IdentityInitCmd) Run(ctx *cliCtx) error {
	if c.Passphrase && c.NoPassphrase {
		return fmt.Errorf("--passphrase and --no-passphrase are mutually exclusive")
	}
	var passphrase string
	if !c.NoPassphrase {
		p, err := promptPassphrase("for your identity")
		if err != nil {
			return err
		}
		passphrase = p
	}

	var confirmOverwrite func() bool
	if !c.Force {
		confirmOverwrite = func() bool {
			return confirm("An identity already exists. Overwrite it? Old vault blobs become unreadable.")
		}
	} else {
		confirmOverwrite = func() bool { return true }
	}

	_, err := identity.InitConfirmed(ctx.Keyring, passphrase, confirmOverwrite, func(mnemonic string) error {
		fmt.Fprintln(os.Stderr, "Write down this recovery phrase and keep it offline:\n\n  "+mnemonic+"\n")
		if c.SkipConfirm {
			return nil
		}
		return confirmMnemonic(mnemonic)
	})
	if err != nil {
		if errors.Is(err, identity.ErrExists) {
			return fmt.Errorf("aborted; existing identity kept")
		}
		return err
	}

	id, err := identity.Load(ctx.Keyring)
	if err != nil {
		return err
	}
	fmt.Println("Identity created.")
	fmt.Println("Fingerprint:", id.Fingerprint())
	if passphrase != "" {
		fmt.Println("Protection:   recovery phrase + passphrase")
	} else {
		fmt.Println("Protection:   recovery phrase only (consider 'esec-vault identity passphrase')")
	}
	fmt.Println()
	fmt.Println("Next: back it up — 'esec-vault backup'. The backup embeds this identity,")
	fmt.Println("so the phrase plus one backup file can rebuild this machine.")
	return nil
}

// IdentityRecoverCmd recovers from the mnemonic and a vault backup.
type IdentityRecoverCmd struct {
	File  string `help:"Vault blob to recover from (default: ~/.config/esec/vault.esec)" type:"path"`
	Force bool   `help:"Overwrite an existing identity without prompting"`
}

// Run implements the recover command.
//
// The blob is opened with the master key derived from the recovery phrase, not
// with an existing identity. That is what makes cold recovery possible: a
// machine that has lost its identity has none to open the blob with, so
// requiring one first would leave the embedded identity unreachable.
func (c *IdentityRecoverCmd) Run(ctx *cliCtx) error {
	file := c.File
	if file == "" {
		file = paths.VaultFile()
	}

	mnemonic, err := promptMnemonic("Paste your 24-word recovery phrase: ")
	if err != nil {
		return err
	}
	if !bip39.IsMnemonicValid(mnemonic) {
		return fmt.Errorf("that is not a valid 24-word recovery phrase (check spelling and word count)")
	}

	passphrase, err := promptSecret("Passphrase (empty if none): ")
	if err != nil {
		return err
	}

	masterPub, masterPriv, err := identity.DeriveMaster(mnemonic, passphrase)
	if err != nil {
		return err
	}

	v, err := vaultfile.ReadWithMaster(file, &masterPub, &masterPriv)
	if err != nil {
		return fmt.Errorf("cannot recover from %s (check phrase and passphrase): %w", file, err)
	}
	if err := validateRestore(v); err != nil {
		return err
	}
	if len(v.Identity) == 0 {
		return fmt.Errorf("backup lacks identity")
	}
	wrapped := v.Identity
	check, err := identity.UnwrapBytes(wrapped, masterPub, masterPriv, passphrase != "")
	if err != nil {
		return err
	}
	if check.Fingerprint() != v.IdentityFingerprint {
		return fmt.Errorf("backup identity mismatch")
	}
	hot, err := vaultfile.Read(file, &check.Public, &check.Private)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(hot, v) {
		return fmt.Errorf("identity and recovery copies disagree")
	}

	confirmOverwrite := func() bool { return true }
	if !c.Force {
		confirmOverwrite = func() bool { return confirm("An identity already exists. Overwrite it?") }
	}

	id, err := identity.Recover(ctx.Keyring, mnemonic, passphrase, wrapped, confirmOverwrite)
	if err != nil {
		if errors.Is(err, identity.ErrExists) {
			return fmt.Errorf("aborted; existing identity kept")
		}
		return err
	}
	fmt.Println("Identity recovered and stored in the OS keyring.")
	fmt.Println("Fingerprint:", id.Fingerprint())
	if len(wrapped) > 0 {
		fmt.Println("Source:      the identity embedded in your backup")
	}
	return nil
}

// IdentityRotateCmd rotates the identity keypair.
type IdentityRotateCmd struct{}

// Run implements the rotate command.
func (c *IdentityRotateCmd) Run(ctx *cliCtx) error {
	mnemonic, err := promptMnemonic("Paste your 24-word recovery phrase to authorize rotation: ")
	if err != nil {
		return err
	}
	if !bip39.IsMnemonicValid(mnemonic) {
		return fmt.Errorf("that is not a valid 24-word recovery phrase")
	}
	passphrase, err := promptSecret("Passphrase (empty if none): ")
	if err != nil {
		return err
	}
	before, _ := identity.Load(ctx.Keyring)
	id, err := identity.Rotate(ctx.Keyring, mnemonic, passphrase)
	if err != nil {
		return err
	}
	fmt.Println("Identity rotated.")
	fmt.Println("New public key:", id.PublicHex())
	fmt.Println("New fingerprint:", id.Fingerprint())
	if before != nil {
		fmt.Println("Old fingerprint:", before.Fingerprint())
	}
	fmt.Println()
	fmt.Println("Ask teammates to re-share to the new identity. Old backups retain their original recovery phrase/passphrase requirements.")
	if err := archiveVault(); err != nil {
		return err
	}
	return (&BackupCmd{Verify: true}).Run(ctx)
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
	if id.PassphraseProtected {
		fmt.Println("Protection:   recovery phrase + passphrase")
	} else {
		fmt.Println("Protection:   recovery phrase only")
	}
	return nil
}

// IdentityPassphraseCmd sets, changes or removes the passphrase.
type IdentityPassphraseCmd struct {
	Remove bool `help:"Remove the passphrase (recovery phrase becomes the only secret)"`
}

// Run implements the passphrase command.
func (c *IdentityPassphraseCmd) Run(ctx *cliCtx) error {
	if _, err := identity.Load(ctx.Keyring); err != nil {
		return err
	}
	fmt.Println("This re-wraps your identity key under a new master key.")
	fmt.Println("Your keypairs, vault blobs and teammates' shares stay valid.")

	mnemonic, err := promptMnemonic("Paste your 24-word recovery phrase: ")
	if err != nil {
		return err
	}
	if !bip39.IsMnemonicValid(mnemonic) {
		return fmt.Errorf("that is not a valid 24-word recovery phrase")
	}
	oldPass, err := promptSecret("Current passphrase (empty if none): ")
	if err != nil {
		return err
	}
	newPass := ""
	if !c.Remove {
		newPass, err = promptPassphrase("for your identity")
		if err != nil {
			return err
		}
	}

	id, err := identity.ChangePassphrase(ctx.Keyring, mnemonic, oldPass, newPass)
	if err != nil {
		return err
	}
	fmt.Println("Passphrase updated.")
	fmt.Println("Fingerprint:", id.Fingerprint(), "(unchanged)")
	if newPass == "" {
		fmt.Println("Protection:   recovery phrase only")
	} else {
		fmt.Println("Protection:   recovery phrase + passphrase")
	}
	fmt.Println()
	fmt.Println("Your keypairs and vault blobs are unaffected — they are sealed to the")
	fmt.Println("identity, which did not change.")
	fmt.Println()
	fmt.Println("However, backups taken BEFORE this change embed an identity wrapped to")
	fmt.Println("the old master key, so cold-recovering them needs the old passphrase.")
	return (&BackupCmd{Verify: true}).Run(ctx)
}

// IdentityMigrateCmd upgrades a pre-v2 identity to the current derivation.
type IdentityMigrateCmd struct {
	Force bool `help:"Overwrite the existing identity file without a backup copy"`
}

// Run implements the migrate command. It reads the old identity.esec with the
// v1 derivation and re-wraps the SAME identity keypair under v2, so vault
// blobs and teammates' shares remain readable.
func (c *IdentityMigrateCmd) Run(ctx *cliCtx) error {
	path := paths.IdentityFile()
	raw, err := os.ReadFile(path) //nolint:gosec // trusted home path
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("no identity file at %s — nothing to migrate; run 'esec-vault identity init'", path)
		}
		return err
	}
	if !legacy.IsLegacy(raw) {
		fmt.Println("Identity already uses the current derivation — nothing to do.")
		return nil
	}

	fmt.Println("This upgrades your identity file to the current derivation.")
	fmt.Println("Your keypairs do not change: vault blobs and teammate shares stay readable.")
	fmt.Println()
	mnemonic, err := promptMnemonic("Paste your 24-word recovery phrase: ")
	if err != nil {
		return err
	}
	if !bip39.IsMnemonicValid(mnemonic) {
		return fmt.Errorf("that is not a valid 24-word recovery phrase")
	}

	masterPub, masterPriv, err := legacy.MasterKeypairV1(mnemonic, bip39.EntropyFromMnemonic)
	if err != nil {
		return err
	}
	priv, err := legacy.UnwrapV1(path, masterPub, masterPriv)
	if err != nil {
		return err
	}

	// Keep a copy of the old file so a mistake here is recoverable.
	if !c.Force {
		backup := path + ".v1.bak"
		if _, err := os.Lstat(backup); err == nil {
			return fmt.Errorf("%s already exists; preserve it before retrying migration", backup)
		}
		if err := storage.Write(backup, raw); err != nil {
			return fmt.Errorf("failed to save a backup of the old identity file: %w", err)
		}
		fmt.Println("Saved the old identity file to", backup)
	}

	newPub, _, err := identity.DeriveMaster(mnemonic, "")
	if err != nil {
		return err
	}
	id := &identity.Identity{Public: identity.PublicFromPrivate(priv), Private: priv}
	if current, err := identity.Load(ctx.Keyring); err == nil && current.Public != id.Public {
		return fmt.Errorf("keychain identity differs from legacy wrapped identity")
	} else if err != nil && !errors.Is(err, identity.ErrNotFound) {
		return err
	}
	if err := identity.CommitMigrated(ctx.Keyring, id, &newPub); err != nil {
		return err
	}

	fmt.Println("Identity migrated to the current derivation.")
	fmt.Println("Fingerprint:", id.Fingerprint(), "(unchanged)")
	fmt.Println("Protection:   recovery phrase only")
	fmt.Println()
	fmt.Println("Next: 'esec-vault identity passphrase' to add a passphrase, then")
	fmt.Println("'esec-vault backup' to re-seal with the identity embedded.")
	if err := archiveVault(); err != nil {
		return err
	}
	return (&BackupCmd{Verify: true}).Run(ctx)
}

func archiveVault() error {
	if _, err := os.Stat(paths.VaultFile()); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	dir := filepath.Join(paths.Home(), "snapshots")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	return os.Rename(paths.VaultFile(), filepath.Join(dir, "before-identity-change-"+time.Now().UTC().Format("20060102T150405.000000000")+".esec"))
}
