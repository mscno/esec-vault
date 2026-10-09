// Package cli_test exercises the recovery guarantee end to end: a brand-new
// machine holding only the recovery phrase and one vault blob must end up with
// the same identity and the same project keys.
package cli_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tyler-smith/go-bip39"

	"github.com/mscno/esec-vault/internal/identity"
	"github.com/mscno/esec-vault/internal/keyring"
	"github.com/mscno/esec-vault/internal/keystore"
	"github.com/mscno/esec-vault/internal/paths"
	"github.com/mscno/esec-vault/internal/vaultfile"
)

// TestFreshMachineRecoveryFromPhraseAndBlobOnly is the regression test for the
// gap where a backup sealed only the keyrings: the identity private key lived
// solely in identity.esec and the OS keyring, so a fresh machine holding the
// phrase plus vault.esec could not open anything.
func TestFreshMachineRecoveryFromPhraseAndBlobOnly(t *testing.T) { //nolint:gocyclo // sequential disaster recovery scenario with explicit failure checks
	home := t.TempDir()
	t.Setenv("ESEC_VAULT_HOME", home)

	// --- Machine 1: set up an identity and two project keyrings. ---
	kr1 := keyring.NewMemory()
	mnemonic, err := identity.Init(kr1, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	id1, err := identity.Load(kr1)
	if err != nil {
		t.Fatal(err)
	}

	ks := keystore.New()
	if err := ks.Write("org/app", map[string]string{"ESEC_PRIVATE_KEY_DEV": "aaaa"}, true); err != nil {
		t.Fatal(err)
	}
	if err := ks.Write("org/api", map[string]string{"ESEC_PRIVATE_KEY": "bbbb", "ESEC_PRIVATE_KEY_PROD": "cccc"}, true); err != nil {
		t.Fatal(err)
	}

	// Seal a backup that embeds the identity and carries a master-sealed copy.
	masterPub, _, err := identity.DeriveMaster(mnemonic, "")
	if err != nil {
		t.Fatal(err)
	}
	wrapped, err := identity.Wrapped(id1, &masterPub, false)
	if err != nil {
		t.Fatal(err)
	}
	v := &vaultfile.Vault{
		Projects: map[string]map[string]string{
			"org/app": {"ESEC_PRIVATE_KEY_DEV": "aaaa"},
			"org/api": {"ESEC_PRIVATE_KEY": "bbbb", "ESEC_PRIVATE_KEY_PROD": "cccc"},
		},
		Identity:            wrapped,
		IdentityFingerprint: id1.Fingerprint(),
		Generation:          1,
		CreatedAt:           time.Now().UTC(),
	}
	backupPath := filepath.Join(home, "vault.esec")
	if err := vaultfile.Write(backupPath, v, &id1.Public, &masterPub); err != nil {
		t.Fatal(err)
	}

	// Keep only the blob and the phrase, as if the machine were lost.
	blobCopy := filepath.Join(t.TempDir(), "offsite-vault.esec")
	data, err := os.ReadFile(backupPath) //nolint:gosec // test-owned path
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(blobCopy, data, 0600); err != nil { //nolint:gosec // test-owned path
		t.Fatal(err)
	}

	// --- Machine 2: nothing but the phrase and that one file. ---
	freshHome := t.TempDir()
	t.Setenv("ESEC_VAULT_HOME", freshHome)
	if _, err := os.Stat(paths.IdentityFile()); err == nil {
		t.Fatal("precondition: a fresh machine must have no identity.esec")
	}

	kr2 := keyring.NewMemory()
	if _, err := identity.Load(kr2); err == nil {
		t.Fatal("precondition: a fresh machine must have an empty OS keyring")
	}

	// The critical step: with no identity available, the blob is opened using
	// the master key derived from the phrase alone. This is what makes the
	// embedded identity reachable in the first place.
	freshMasterPub, freshMasterPriv, err := identity.DeriveMaster(mnemonic, "")
	if err != nil {
		t.Fatal(err)
	}
	opened, err := vaultfile.OpenWithMaster(data, &freshMasterPub, &freshMasterPriv)
	if err != nil {
		t.Fatalf("a fresh machine must be able to open the blob from the phrase: %v", err)
	}
	if len(opened.Identity) == 0 {
		t.Fatal("backup must embed the identity for cold recovery")
	}

	recovered, err := identity.Recover(kr2, mnemonic, "", opened.Identity, nil)
	if err != nil {
		t.Fatalf("cold recovery from phrase + blob must work: %v", err)
	}
	if recovered.Public != id1.Public {
		t.Fatal("recovered a different identity than was backed up")
	}
	if recovered.Fingerprint() != id1.Fingerprint() {
		t.Fatal("fingerprint changed across recovery")
	}

	// The restored identity must open the same blobs.
	again, err := vaultfile.Open(data, &recovered.Public, &recovered.Private)
	if err != nil {
		t.Fatal("restored identity must open the backup it came from")
	}
	if len(again.Projects) != 2 || again.Projects["org/api"]["ESEC_PRIVATE_KEY_PROD"] != "cccc" {
		t.Fatalf("projects did not survive: %+v", again.Projects)
	}

	// And restore must recreate the keyring store.
	ks2 := keystore.New()
	for project, entries := range again.Projects {
		if err := ks2.Write(project, entries, true); err != nil {
			t.Fatal(err)
		}
	}
	restored, err := ks2.Read("org/api")
	if err != nil {
		t.Fatal(err)
	}
	if restored["ESEC_PRIVATE_KEY_PROD"] != "cccc" {
		t.Fatalf("restored keyring wrong: %+v", restored)
	}

	// The OS keyring now holds the identity, so the second machine is usable.
	fromKeyring, err := identity.Load(kr2)
	if err != nil {
		t.Fatal(err)
	}
	if fromKeyring.Public != id1.Public {
		t.Fatal("identity in the OS keyring differs")
	}
}

// A passphrase-protected identity must also recover from phrase + blob alone.
func TestFreshMachineRecoveryWithPassphrase(t *testing.T) {
	home := t.TempDir()
	t.Setenv("ESEC_VAULT_HOME", home)

	kr1 := keyring.NewMemory()
	mnemonic, err := identity.Init(kr1, "a good passphrase", nil)
	if err != nil {
		t.Fatal(err)
	}
	id1, err := identity.Load(kr1)
	if err != nil {
		t.Fatal(err)
	}
	masterPub, _, err := identity.DeriveMaster(mnemonic, "a good passphrase")
	if err != nil {
		t.Fatal(err)
	}
	wrapped, err := identity.Wrapped(id1, &masterPub, true)
	if err != nil {
		t.Fatal(err)
	}
	data, err := vaultfile.Seal(&vaultfile.Vault{
		Projects:            map[string]map[string]string{"org/x": {"K": "v"}},
		Identity:            wrapped,
		IdentityFingerprint: id1.Fingerprint(),
	}, &id1.Public, &masterPub)
	if err != nil {
		t.Fatal(err)
	}

	t.Setenv("ESEC_VAULT_HOME", t.TempDir())
	_, masterPriv, _ := identity.DeriveMaster(mnemonic, "a good passphrase")
	opened, err := vaultfile.OpenWithMaster(data, &masterPub, &masterPriv)
	if err != nil {
		t.Fatal(err)
	}

	// The phrase alone is not enough; the passphrase is required.
	if _, err := identity.Recover(keyring.NewMemory(), mnemonic, "", opened.Identity, nil); err == nil {
		t.Fatal("recovery must fail without the passphrase")
	}
	got, err := identity.Recover(keyring.NewMemory(), mnemonic, "a good passphrase", opened.Identity, nil)
	if err != nil {
		t.Fatalf("recovery with the passphrase must succeed: %v", err)
	}
	if got.Public != id1.Public {
		t.Fatal("wrong identity recovered")
	}
}

// Changing the passphrase must not invalidate existing backups: the identity
// keypair is preserved, so blobs sealed to it still open.
func TestPassphraseChangeKeepsBackupsReadable(t *testing.T) {
	t.Setenv("ESEC_VAULT_HOME", t.TempDir())
	kr := keyring.NewMemory()
	mnemonic, err := identity.Init(kr, "first", nil)
	if err != nil {
		t.Fatal(err)
	}
	id, err := identity.Load(kr)
	if err != nil {
		t.Fatal(err)
	}
	// Seal with a master copy, then change the passphrase. The blob must still
	// open with the identity key, because the identity itself is unchanged.
	masterPub, _, err := identity.DeriveMaster(mnemonic, "first")
	if err != nil {
		t.Fatal(err)
	}
	blob, err := vaultfile.Seal(&vaultfile.Vault{
		Projects: map[string]map[string]string{"org/x": {"K": "v"}},
	}, &id.Public, &masterPub)
	if err != nil {
		t.Fatal(err)
	}

	changed, err := identity.ChangePassphrase(kr, mnemonic, "first", "second")
	if err != nil {
		t.Fatal(err)
	}
	if changed.Public != id.Public {
		t.Fatal("passphrase change must not rotate the identity")
	}
	if _, err := vaultfile.Open(blob, &changed.Public, &changed.Private); err != nil {
		t.Fatalf("a backup taken before the passphrase change must still open: %v", err)
	}
}

// Changing the passphrase re-wraps the identity under a new master key. A
// backup taken *before* the change still opens with the identity key, but its
// master copy was sealed to the old master key, so cold-recovering from that
// older blob requires the old passphrase. This is why the passphrase command
// tells the user to re-back-up.
func TestPassphraseChangeRequiresRebackupForColdRecovery(t *testing.T) {
	t.Setenv("ESEC_VAULT_HOME", t.TempDir())
	kr := keyring.NewMemory()
	mnemonic, err := identity.Init(kr, "first", nil)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := identity.Load(kr)

	oldMasterPub, _, err := identity.DeriveMaster(mnemonic, "first")
	if err != nil {
		t.Fatal(err)
	}
	wrapped, err := identity.Wrapped(id, &oldMasterPub, true)
	if err != nil {
		t.Fatal(err)
	}
	old, err := vaultfile.Seal(&vaultfile.Vault{Identity: wrapped}, &id.Public, &oldMasterPub)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := identity.ChangePassphrase(kr, mnemonic, "first", "second"); err != nil {
		t.Fatal(err)
	}

	newMasterPub, newMasterPriv, err := identity.DeriveMaster(mnemonic, "second")
	if err != nil {
		t.Fatal(err)
	}
	// The new master key cannot open the old blob's recovery copy.
	if _, err := vaultfile.OpenWithMaster(old, &newMasterPub, &newMasterPriv); err == nil {
		t.Fatal("the new master key must not open a blob sealed to the old one")
	}

	// Re-backing up after the change fixes it.
	newWrapped, err := identity.Wrapped(id, &newMasterPub, true)
	if err != nil {
		t.Fatal(err)
	}
	fresh, err := vaultfile.Seal(&vaultfile.Vault{Identity: newWrapped}, &id.Public, &newMasterPub)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := vaultfile.OpenWithMaster(fresh, &newMasterPub, &newMasterPriv); err != nil {
		t.Fatalf("a backup taken after the change must be cold-recoverable: %v", err)
	}
}

// A legacy v1 blob must be rejected with the actionable message rather than a
// generic corruption error, since it cannot rebuild a machine.
func TestLegacyBlobIsRejectedWithGuidance(t *testing.T) {
	blob := append([]byte("ESECVLT"), 1)
	blob = append(blob, make([]byte, 8)...)
	blob = append(blob, make([]byte, 96)...)
	if _, err := vaultfile.Open(blob, &[32]byte{}, &[32]byte{}); err == nil {
		t.Fatal("expected an error")
	} else if !strings.Contains(err.Error(), "re-run 'esec-vault backup'") {
		t.Fatalf("error should tell the user what to do, got: %v", err)
	}
}

// Recovery must not accept a wrong phrase even when a wrapped blob is present.
func TestRecoveryRejectsWrongPhrase(t *testing.T) {
	t.Setenv("ESEC_VAULT_HOME", t.TempDir())
	kr := keyring.NewMemory()
	if _, err := identity.Init(kr, "", nil); err != nil {
		t.Fatal(err)
	}
	id, _ := identity.Load(kr)
	pub, _, _ := identity.DeriveMaster(mustMnemonic(t), "")
	wrapped, err := identity.Wrapped(id, &pub, false)
	if err != nil {
		t.Fatal(err)
	}
	wrong := "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title"
	if _, err := identity.Recover(keyring.NewMemory(), wrong, "", wrapped, nil); err == nil {
		t.Fatal("a wrong phrase must not recover an identity")
	}
}

func mustMnemonic(t *testing.T) string {
	t.Helper()
	entropy, err := bip39.NewEntropy(256)
	if err != nil {
		t.Fatal(err)
	}
	m, err := bip39.NewMnemonic(entropy)
	if err != nil {
		t.Fatal(err)
	}
	return m
}
