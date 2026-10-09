package identity

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/mscno/esec-vault/internal/keyring"
	"github.com/mscno/esec-vault/internal/paths"
	"github.com/tyler-smith/go-bip39"
)

func setup(t *testing.T) *keyring.Memory {
	t.Helper()
	t.Setenv("ESEC_VAULT_HOME", t.TempDir())
	return keyring.NewMemory()
}

const validMnemonic = "legal winner thank year wave sausage worth useful legal winner thank yellow"

func TestInitAndLoad(t *testing.T) {
	kr := setup(t)
	mnemonic, err := Init(kr, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if mnemonic == "" {
		t.Fatal("empty mnemonic")
	}
	id, err := Load(kr)
	if err != nil {
		t.Fatal(err)
	}
	if id.Public == [32]byte{} {
		t.Fatal("empty public key")
	}
	if len(id.Fingerprint()) != 64 {
		t.Fatalf("unexpected fingerprint: %s", id.Fingerprint())
	}
	if id.PassphraseProtected {
		t.Fatal("identity created without a passphrase should not report as protected")
	}
}

func TestInitRefusesOverwriteWithoutConfirm(t *testing.T) {
	kr := setup(t)
	if _, err := Init(kr, "", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := Init(kr, "", nil); !errors.Is(err, ErrExists) {
		t.Fatalf("expected ErrExists, got %v", err)
	}
	if _, err := Init(kr, "", func() bool { return false }); !errors.Is(err, ErrExists) {
		t.Fatalf("expected ErrExists, got %v", err)
	}
	if _, err := Init(kr, "", func() bool { return true }); err != nil {
		t.Fatalf("confirmed overwrite should succeed: %v", err)
	}
}

func TestRecoverRoundTrip(t *testing.T) {
	kr := setup(t)
	mnemonic, err := Init(kr, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	original, err := Load(kr)
	if err != nil {
		t.Fatal(err)
	}

	// Simulate a fresh machine: new keyring, same home (identity.esec stays).
	fresh := keyring.NewMemory()
	if _, err := Recover(fresh, mnemonic, "", nil, nil); err != nil {
		t.Fatal(err)
	}
	recovered, err := Load(fresh)
	if err != nil {
		t.Fatal(err)
	}
	if recovered.Public != original.Public || recovered.Private != original.Private {
		t.Fatal("recovered identity differs from original")
	}
}

func TestRecoverWrongMnemonic(t *testing.T) {
	kr := setup(t)
	if _, err := Init(kr, "", nil); err != nil {
		t.Fatal(err)
	}
	wrong := "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title"
	if _, err := Recover(keyring.NewMemory(), wrong, "", nil, nil); err == nil {
		t.Fatal("expected failure recovering with a different mnemonic")
	}
}

func TestRecoverMissingWrappedFile(t *testing.T) {
	kr := setup(t)
	mnemonic, err := Init(kr, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	// Different home directory: identity.esec is missing there.
	t.Setenv("ESEC_VAULT_HOME", t.TempDir())
	_, err = Recover(keyring.NewMemory(), mnemonic, "", nil, nil)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

// The wrapped identity travels inside the vault backup, so a fresh machine can
// recover from the phrase plus that blob even with no identity.esec present.
func TestRecoverFromWrappedBlobAlone(t *testing.T) {
	kr := setup(t)
	mnemonic, err := Init(kr, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	original, err := Load(kr)
	if err != nil {
		t.Fatal(err)
	}
	masterPub, _, err := DeriveMaster(mnemonic, "")
	if err != nil {
		t.Fatal(err)
	}
	wrapped, err := Wrapped(original, &masterPub, false)
	if err != nil {
		t.Fatal(err)
	}

	// Fresh machine: no identity.esec, empty OS keyring, only the blob.
	t.Setenv("ESEC_VAULT_HOME", t.TempDir())
	fresh := keyring.NewMemory()
	recovered, err := Recover(fresh, mnemonic, "", wrapped, nil)
	if err != nil {
		t.Fatalf("recovery from the backup blob alone must work: %v", err)
	}
	if recovered.Public != original.Public {
		t.Fatal("recovered a different identity than the one backed up")
	}
	if _, err := os.Stat(paths.IdentityFile()); err != nil {
		t.Fatal("recovery should have written identity.esec")
	}
}

func TestPassphraseChangesMasterButNotIdentity(t *testing.T) {
	kr := setup(t)
	mnemonic, err := Init(kr, "correct horse", nil)
	if err != nil {
		t.Fatal(err)
	}
	before, err := Load(kr)
	if err != nil {
		t.Fatal(err)
	}
	if !before.PassphraseProtected {
		t.Fatal("expected passphrase protection")
	}

	// Wrong passphrase must not open the identity.
	if _, err := Recover(keyring.NewMemory(), mnemonic, "wrong", nil, nil); err == nil {
		t.Fatal("a wrong passphrase must not recover the identity")
	}

	changed, err := ChangePassphrase(kr, mnemonic, "correct horse", "battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if changed.Public != before.Public {
		t.Fatal("changing the passphrase must not change the identity keypair")
	}

	// Old passphrase now fails, new one succeeds, same identity.
	if _, err := Recover(keyring.NewMemory(), mnemonic, "correct horse", nil, nil); err == nil {
		t.Fatal("the old passphrase should no longer work")
	}
	back, err := Recover(keyring.NewMemory(), mnemonic, "battery staple", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if back.Public != before.Public {
		t.Fatal("identity changed across the passphrase change")
	}
}

func TestChangePassphraseToEmpty(t *testing.T) {
	kr := setup(t)
	mnemonic, err := Init(kr, "secret", nil)
	if err != nil {
		t.Fatal(err)
	}
	before, _ := Load(kr)
	id, err := ChangePassphrase(kr, mnemonic, "secret", "")
	if err != nil {
		t.Fatal(err)
	}
	if id.PassphraseProtected {
		t.Fatal("expected protection to be removed")
	}
	if id.Public != before.Public {
		t.Fatal("identity must not change")
	}
}

func TestChangePassphraseRejectsWrongPhrase(t *testing.T) {
	kr := setup(t)
	if _, err := Init(kr, "", nil); err != nil {
		t.Fatal(err)
	}
	wrong := validMnemonic
	if _, err := ChangePassphrase(kr, wrong, "", "new"); err == nil {
		t.Fatal("a wrong recovery phrase must not be able to re-wrap the identity")
	}
}

func TestDeriveMasterIsDeterministic(t *testing.T) {
	p1, s1, err := DeriveMaster(validMnemonic, "pw")
	if err != nil {
		t.Fatal(err)
	}
	p2, s2, err := DeriveMaster(validMnemonic, "pw")
	if err != nil {
		t.Fatal(err)
	}
	if p1 != p2 || s1 != s2 {
		t.Fatal("derivation is not deterministic")
	}
	p3, _, err := DeriveMaster(validMnemonic, "different")
	if err != nil {
		t.Fatal(err)
	}
	if p1 == p3 {
		t.Fatal("a different passphrase must derive a different master key")
	}
	if p1 == ([32]byte{}) {
		t.Fatal("empty master public key")
	}
}

func TestDeriveMasterRejectsBadMnemonic(t *testing.T) {
	if _, _, err := DeriveMaster("not a real mnemonic at all", ""); err == nil {
		t.Fatal("expected an error for an invalid mnemonic")
	}
}

func TestProtectReportsProtection(t *testing.T) {
	kr := setup(t)
	if _, ok := Protect(); ok {
		t.Fatal("no identity file should exist yet")
	}
	if _, err := Init(kr, "", nil); err != nil {
		t.Fatal(err)
	}
	passphrased, known := Protect()
	if !known {
		t.Fatal("expected the identity file to be readable")
	}
	if passphrased {
		t.Fatal("expected no passphrase")
	}
}

func TestIdentityFileHasHeaderAnd0600(t *testing.T) {
	kr := setup(t)
	if _, err := Init(kr, "pw", nil); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(paths.IdentityFile())
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0600 {
		t.Fatalf("identity file must be 0600, got %o", fi.Mode().Perm())
	}
	raw, err := os.ReadFile(paths.IdentityFile())
	if err != nil {
		t.Fatal(err)
	}
	h, sealed, err := decodeHeader(raw)
	if err != nil {
		t.Fatal(err)
	}
	if h.Magic != fileMagic {
		t.Fatalf("bad magic %q", h.Magic)
	}
	if h.Derivation != masterInfo {
		t.Fatalf("expected derivation %q, got %q", masterInfo, h.Derivation)
	}
	if !h.Passphrased {
		t.Fatal("header should record the passphrase")
	}
	if len(sealed) == 0 {
		t.Fatal("no sealed box after the header")
	}
}

func TestRotate(t *testing.T) {
	kr := setup(t)
	mnemonic, err := Init(kr, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	before, err := Load(kr)
	if err != nil {
		t.Fatal(err)
	}
	after, err := Rotate(kr, mnemonic, "")
	if err != nil {
		t.Fatal(err)
	}
	if after.Public == before.Public {
		t.Fatal("rotation produced the same key")
	}
	// Old wrapped blob must be replaced: recover from mnemonic yields new key.
	fresh := keyring.NewMemory()
	if _, err := Recover(fresh, mnemonic, "", nil, nil); err != nil {
		t.Fatal(err)
	}
	recovered, err := Load(fresh)
	if err != nil {
		t.Fatal(err)
	}
	if recovered.Public != after.Public {
		t.Fatal("recovery after rotation did not yield the rotated key")
	}
}

func TestUnwrapBytesRejectsWrongDerivation(t *testing.T) {
	kr := setup(t)
	mnemonic, err := Init(kr, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := Load(kr)
	pub, _, _ := DeriveMaster(mnemonic, "")
	wrapped, err := Wrapped(id, &pub, false)
	if err != nil {
		t.Fatal(err)
	}
	// Corrupt the derivation string so it disagrees with this build.
	h, sealed, _ := decodeHeader(wrapped)
	h.Derivation = "esec-master-v1"
	bad := append(encodeHeader(h), sealed...)
	if _, err := UnwrapBytes(bad, pub, pub, false); err == nil {
		t.Fatal("expected a derivation mismatch error")
	}
}

func TestUnwrapBytesRejectsTruncated(t *testing.T) {
	if _, err := UnwrapBytes([]byte("ESEC"), [32]byte{}, [32]byte{}, false); err == nil {
		t.Fatal("expected an error for a truncated blob")
	}
}

func TestShortFingerprint(t *testing.T) {
	if got := ShortFingerprint("deadbeefcafe"); got != "deadbeef" {
		t.Fatalf("got %q", got)
	}
	if got := ShortFingerprint("abc"); got != "abc" {
		t.Fatalf("short input should pass through, got %q", got)
	}
}

func TestPublicFromPrivateMatchesDerive(t *testing.T) {
	kr := setup(t)
	if _, err := Init(kr, "", nil); err != nil {
		t.Fatal(err)
	}
	id, err := Load(kr)
	if err != nil {
		t.Fatal(err)
	}
	if got := PublicFromPrivate(id.Private); got != id.Public {
		t.Fatal("PublicFromPrivate disagrees with the stored public key")
	}
}

func TestIdentityFileIsRestorableFromBackupBytes(t *testing.T) {
	// The bytes embedded in a backup must unwrap to the same identity as
	// identity.esec. They are not byte-identical: every seal uses a fresh
	// random ephemeral key, which is exactly why the backup is safe to publish.
	kr := setup(t)
	mnemonic, _ := Init(kr, "pw", nil)
	id, _ := Load(kr)
	pub, priv, _ := DeriveMaster(mnemonic, "pw")
	wrapped, err := Wrapped(id, &pub, true)
	if err != nil {
		t.Fatal(err)
	}
	onDisk, err := os.ReadFile(filepath.Join(paths.Home(), "identity.esec"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(wrapped, onDisk) {
		t.Fatal("sealed bytes should differ per seal (random ephemeral key)")
	}
	fromBackup, err := UnwrapBytes(wrapped, pub, priv, true)
	if err != nil {
		t.Fatal(err)
	}
	fromDisk, err := UnwrapBytes(onDisk, pub, priv, true)
	if err != nil {
		t.Fatal(err)
	}
	if fromBackup.Public != id.Public || fromDisk.Public != id.Public {
		t.Fatal("both sealed forms must unwrap to the stored identity")
	}
	if !bip39.IsMnemonicValid(mnemonic) {
		t.Fatal("generated mnemonic should be valid")
	}
}
