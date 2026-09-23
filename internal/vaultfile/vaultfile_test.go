package vaultfile

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/mscno/esec/pkg/crypto"
)

func testKey(t *testing.T) (pub, priv [32]byte) {
	t.Helper()
	var kp crypto.Keypair
	if err := kp.Generate(); err != nil {
		t.Fatal(err)
	}
	return kp.Public, kp.Private
}

func TestSealOpenRoundTrip(t *testing.T) {
	pub, priv := testKey(t)
	v := &Vault{Projects: map[string]map[string]string{
		"org/repo": {"ESEC_PRIVATE_KEY_DEV": "abcd"},
		"o/r2":     {"ESEC_PRIVATE_KEY": "1234", "ESEC_PRIVATE_KEY_PROD": "beef"},
	}}
	data, err := Seal(v, time.Unix(1700000000, 0), &pub)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) < headerLen+48 {
		t.Fatal("sealed blob suspiciously small")
	}
	back, err := Open(data, &pub, &priv)
	if err != nil {
		t.Fatal(err)
	}
	if back.Projects["org/repo"]["ESEC_PRIVATE_KEY_DEV"] != "abcd" {
		t.Fatalf("round trip mismatch: %+v", back.Projects)
	}
	if back.Projects["o/r2"]["ESEC_PRIVATE_KEY_PROD"] != "beef" {
		t.Fatalf("round trip mismatch: %+v", back.Projects)
	}
}

func TestOpenTampered(t *testing.T) {
	pub, priv := testKey(t)
	v := &Vault{Projects: map[string]map[string]string{"org/repo": {"ESEC_PRIVATE_KEY_DEV": "abcd"}}}
	data, err := Seal(v, time.Now(), &pub)
	if err != nil {
		t.Fatal(err)
	}
	data[len(data)-3] ^= 0xff
	if _, err := Open(data, &pub, &priv); err == nil {
		t.Fatal("expected tamper detection")
	}
}

func TestOpenWrongKey(t *testing.T) {
	pub, _ := testKey(t)
	_, evePriv := testKey(t)
	_, evePub := testKey(t)
	v := &Vault{Projects: map[string]map[string]string{"org/repo": {"K": "v"}}}
	data, err := Seal(v, time.Now(), &pub)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(data, &evePub, &evePriv); err == nil {
		t.Fatal("expected decryption failure with wrong key")
	}
}

func TestOpenBadMagicAndVersion(t *testing.T) {
	pub, priv := testKey(t)
	v := &Vault{}
	data, err := Seal(v, time.Now(), &pub)
	if err != nil {
		t.Fatal(err)
	}

	bad := append([]byte(nil), data...)
	copy(bad, "XXXXXXX")
	if _, err := Open(bad, &pub, &priv); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("expected ErrCorrupt for bad magic, got %v", err)
	}

	bad = append([]byte(nil), data...)
	bad[7] = 99
	if _, err := Open(bad, &pub, &priv); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("expected ErrCorrupt for bad version, got %v", err)
	}
}

func TestWriteReadFile(t *testing.T) {
	pub, priv := testKey(t)
	path := filepath.Join(t.TempDir(), "sub", "vault.esec")
	v := &Vault{Projects: map[string]map[string]string{"org/repo": {"K": "v"}}}
	if err := Write(path, v, time.Now(), &pub); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0600 {
		t.Fatalf("vault file must be 0600, got %o", fi.Mode().Perm())
	}
	back, err := Read(path, &pub, &priv)
	if err != nil {
		t.Fatal(err)
	}
	if back.Projects["org/repo"]["K"] != "v" {
		t.Fatalf("round trip mismatch: %+v", back.Projects)
	}
}
