package identity

import (
	"errors"
	"testing"

	"github.com/mscno/esec-vault/internal/keyring"
)

func setup(t *testing.T) *keyring.Memory {
	t.Helper()
	t.Setenv("ESEC_VAULT_HOME", t.TempDir())
	return keyring.NewMemory()
}

func TestInitAndLoad(t *testing.T) {
	kr := setup(t)
	mnemonic, err := Init(kr, nil)
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
}

func TestInitRefusesOverwriteWithoutConfirm(t *testing.T) {
	kr := setup(t)
	if _, err := Init(kr, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := Init(kr, nil); !errors.Is(err, ErrExists) {
		t.Fatalf("expected ErrExists, got %v", err)
	}
	if _, err := Init(kr, func() bool { return false }); !errors.Is(err, ErrExists) {
		t.Fatalf("expected ErrExists, got %v", err)
	}
	if _, err := Init(kr, func() bool { return true }); err != nil {
		t.Fatalf("confirmed overwrite should succeed: %v", err)
	}
}

func TestRecoverRoundTrip(t *testing.T) {
	kr := setup(t)
	mnemonic, err := Init(kr, nil)
	if err != nil {
		t.Fatal(err)
	}
	original, err := Load(kr)
	if err != nil {
		t.Fatal(err)
	}

	// Simulate a fresh machine: new keyring, same home (identity.esec stays).
	fresh := keyring.NewMemory()
	if err := Recover(fresh, mnemonic, nil); err != nil {
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
	if _, err := Init(kr, nil); err != nil {
		t.Fatal(err)
	}
	wrong := "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title"
	if err := Recover(keyring.NewMemory(), wrong, nil); err == nil {
		t.Fatal("expected failure recovering with a different mnemonic")
	}
}

func TestRecoverMissingWrappedFile(t *testing.T) {
	kr := setup(t)
	mnemonic, err := Init(kr, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Different home directory: identity.esec is missing there.
	t.Setenv("ESEC_VAULT_HOME", t.TempDir())
	err = Recover(keyring.NewMemory(), mnemonic, nil)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestRotate(t *testing.T) {
	kr := setup(t)
	mnemonic, err := Init(kr, nil)
	if err != nil {
		t.Fatal(err)
	}
	before, err := Load(kr)
	if err != nil {
		t.Fatal(err)
	}
	after, err := Rotate(kr, mnemonic)
	if err != nil {
		t.Fatal(err)
	}
	if after.Public == before.Public {
		t.Fatal("rotation produced the same key")
	}
	// Old wrapped blob must be replaced: recover from mnemonic yields new key.
	fresh := keyring.NewMemory()
	if err := Recover(fresh, mnemonic, nil); err != nil {
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
