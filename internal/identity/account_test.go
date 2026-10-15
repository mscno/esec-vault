package identity

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"os"
	"testing"

	"github.com/mscno/esec-vault/internal/keyring"
	"github.com/mscno/esec-vault/internal/paths"
)

// writeV2 creates an identity in the pre-signing-key format, as an existing
// installation would have it.
func writeV2(t *testing.T, kr *keyring.Memory, mnemonic, passphrase string) *Identity {
	t.Helper()
	masterPub, _, err := DeriveMaster(mnemonic, passphrase)
	if err != nil {
		t.Fatal(err)
	}
	id, err := NewRandom()
	if err != nil {
		t.Fatal(err)
	}
	id.Sign = nil
	id.PassphraseProtected = passphrase != ""
	if err := commit(kr, id, &masterPub); err != nil {
		t.Fatal(err)
	}
	h, err := ReadHeader(mustRead(t))
	if err != nil || h.Version != 2 {
		t.Fatalf("setup did not write a v2 file: %v", err)
	}
	return id
}

func mustRead(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile(paths.IdentityFile())
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestEnsureSigningKeyUpgradesWithoutPhrase(t *testing.T) {
	kr := setup(t)
	before := writeV2(t, kr, validMnemonic, "pw")

	id, upgraded, err := EnsureSigningKey(kr)
	if err != nil {
		t.Fatal(err)
	}
	if !upgraded || id.Sign == nil {
		t.Fatal("signing key not added")
	}
	if id.Public != before.Public || id.Private != before.Private {
		t.Fatal("upgrade must keep the encryption key")
	}
	h, err := ReadHeader(mustRead(t))
	if err != nil {
		t.Fatal(err)
	}
	if h.Version != 3 || !bytes.Equal(h.SignPublic[:], id.SignPublic()) || !h.Passphrased {
		t.Fatalf("header after upgrade: %+v", h)
	}

	// The phrase (and passphrase) still open the upgraded file and yield the
	// signing key too.
	masterPub, masterPriv, err := DeriveMaster(validMnemonic, "pw")
	if err != nil {
		t.Fatal(err)
	}
	opened, err := UnwrapBytes(mustRead(t), masterPub, masterPriv, true)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(opened.Sign, id.Sign) {
		t.Fatal("recovered signing key differs")
	}

	loaded, err := Load(kr)
	if err != nil || !bytes.Equal(loaded.Sign, id.Sign) {
		t.Fatalf("signing key not persisted in keyring: %v", err)
	}
	again, upgraded, err := EnsureSigningKey(kr)
	if err != nil || upgraded || !bytes.Equal(again.Sign, id.Sign) {
		t.Fatal("second call must be a no-op")
	}
}

func TestEnsureSigningKeyRejectsDisagreement(t *testing.T) {
	kr := setup(t)
	if _, err := Init(kr, "", nil); err != nil {
		t.Fatal(err)
	}
	if err := kr.Delete(keyring.IdentitySignPrivateKey); err != nil {
		t.Fatal(err)
	}
	if _, _, err := EnsureSigningKey(kr); err == nil {
		t.Fatal("a v3 file without the keychain signing key must not get a new key")
	}
}

func TestInstallChecksWrappedHeader(t *testing.T) {
	kr := setup(t)
	if _, err := Init(kr, "", nil); err != nil {
		t.Fatal(err)
	}
	src, err := Load(kr)
	if err != nil {
		t.Fatal(err)
	}
	wrapped := mustRead(t)

	fresh := keyring.NewMemory()
	other, err := NewRandom()
	if err != nil {
		t.Fatal(err)
	}
	if err := Install(fresh, other, wrapped); !errors.Is(err, ErrWrappedMismatch) {
		t.Fatalf("mismatched wrapped identity accepted: %v", err)
	}
	clone, err := FromKeys(src.Private, src.Sign.Seed())
	if err != nil {
		t.Fatal(err)
	}
	if err := Install(fresh, clone, wrapped); err != nil {
		t.Fatal(err)
	}
	got, err := Load(fresh)
	if err != nil || got.Public != src.Public || !bytes.Equal(got.Sign, src.Sign) {
		t.Fatalf("installed identity differs: %v", err)
	}
}

func TestWrapForMasterKeepsRecoveryPhrase(t *testing.T) {
	kr := setup(t)
	if _, err := Init(kr, "", nil); err != nil {
		t.Fatal(err)
	}
	next, err := NewRandom()
	if err != nil {
		t.Fatal(err)
	}
	wrapped, err := WrapForMaster(next, mustRead(t))
	if err != nil {
		t.Fatal(err)
	}
	h, err := ReadHeader(wrapped)
	if err != nil || h.IdentityPublic != next.Public {
		t.Fatal("rotated wrap names the wrong identity")
	}
	old, err := ReadHeader(mustRead(t))
	if err != nil || old.MasterPublic != h.MasterPublic {
		t.Fatal("rotated wrap must target the same master key")
	}
}

func TestUnwrapRejectsSwappedSigningKey(t *testing.T) {
	kr := setup(t)
	mnemonic, err := Init(kr, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	raw := mustRead(t)
	h, _, err := decodeHeader(raw)
	if err != nil {
		t.Fatal(err)
	}
	// Replace the cleartext signing key in the header; the sealed payload
	// still carries the original header and seed.
	_, fake, _ := ed25519.GenerateKey(nil)
	tampered := bytes.Replace(raw, h.SignPublic[:], fake.Public().(ed25519.PublicKey), 1)
	masterPub, masterPriv, err := DeriveMaster(mnemonic, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnwrapBytes(raw, masterPub, masterPriv, false); err != nil {
		t.Fatalf("untampered file must open: %v", err)
	}
	if _, err := UnwrapBytes(tampered, masterPub, masterPriv, false); err == nil {
		t.Fatal("tampered header accepted")
	}
}
