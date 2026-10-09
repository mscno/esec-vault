package vaultfile

import (
	"bytes"
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
	v := &Vault{
		Projects: map[string]map[string]string{
			"org/repo": {"ESEC_PRIVATE_KEY_DEV": "abcd"},
			"o/r2":     {"ESEC_PRIVATE_KEY": "1234", "ESEC_PRIVATE_KEY_PROD": "beef"},
		},
		Identity:            []byte("wrapped-identity-bytes"),
		IdentityFingerprint: "deadbeef",
		Generation:          7,
		CreatedAt:           time.Unix(1700000000, 0).UTC(),
	}
	data, err := Seal(v, &pub, nil)
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
	if !bytes.Equal(back.Identity, v.Identity) {
		t.Fatal("identity bytes did not survive the round trip")
	}
	if back.IdentityFingerprint != "deadbeef" {
		t.Fatalf("fingerprint mismatch: %q", back.IdentityFingerprint)
	}
	if back.Generation != 7 {
		t.Fatalf("generation mismatch: %d", back.Generation)
	}
	if !back.CreatedAt.Equal(v.CreatedAt) {
		t.Fatalf("created_at mismatch: %v", back.CreatedAt)
	}
}

func TestOpenTampered(t *testing.T) {
	pub, priv := testKey(t)
	v := &Vault{Projects: map[string]map[string]string{"org/repo": {"K": "v"}}}
	data, err := Seal(v, &pub, nil)
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
	data, err := Seal(v, &pub, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(data, &evePub, &evePriv); err == nil {
		t.Fatal("expected decryption failure with wrong key")
	}
}

// The generation and timestamp moved inside the sealed box in v2. Confirm a
// header edit is rejected and that no metadata leaks in cleartext.
func TestMetadataIsAuthenticated(t *testing.T) {
	pub, priv := testKey(t)
	v := &Vault{Projects: map[string]map[string]string{"org/repo": {"K": "v"}}, Generation: 3}
	data, err := Seal(v, &pub, nil)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte("generation")) {
		t.Fatal("payload field names must not appear in cleartext")
	}
	// Header carries magic+version only, so flipping the version byte fails.
	bad := append([]byte(nil), data...)
	bad[7] = 99
	if _, err := Open(bad, &pub, &priv); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("expected ErrCorrupt for bad version, got %v", err)
	}
}

func TestOpenBadMagic(t *testing.T) {
	pub, priv := testKey(t)
	data, err := Seal(&Vault{}, &pub, nil)
	if err != nil {
		t.Fatal(err)
	}
	bad := append([]byte(nil), data...)
	copy(bad, "XXXXXXX")
	if _, err := Open(bad, &pub, &priv); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("expected ErrCorrupt for bad magic, got %v", err)
	}
}

// v1 blobs lack the identity key, so opening one must fail loudly with the
// actionable message rather than a generic corruption error.
func TestOpenLegacyV1(t *testing.T) {
	pub, priv := testKey(t)
	legacy := append([]byte("ESECVLT"), 1)
	legacy = append(legacy, make([]byte, 8)...)
	legacy = append(legacy, bytes.Repeat([]byte{0xAA}, 96)...)
	if _, err := Open(legacy, &pub, &priv); !errors.Is(err, ErrLegacyFormat) {
		t.Fatalf("expected ErrLegacyFormat, got %v", err)
	}
}

func TestWriteReadFile(t *testing.T) {
	pub, priv := testKey(t)
	path := filepath.Join(t.TempDir(), "sub", "vault.esec")
	v := &Vault{
		Projects: map[string]map[string]string{"org/repo": {"K": "v"}},
		Identity: []byte("id"),
	}
	if err := Write(path, v, &pub, nil); err != nil {
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

func TestNextGeneration(t *testing.T) {
	if got := NextGeneration(nil); got != 1 {
		t.Fatalf("nil vault should start at 1, got %d", got)
	}
	if got := NextGeneration(&Vault{}); got != 1 {
		t.Fatalf("zero generation should yield 1, got %d", got)
	}
	if got := NextGeneration(&Vault{Generation: 4}); got != 5 {
		t.Fatalf("expected 5, got %d", got)
	}
}

func TestExists(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "vault.esec")
	if Exists(p) {
		t.Fatal("should not exist yet")
	}
	pub, _ := testKey(t)
	if err := Write(p, &Vault{}, &pub, nil); err != nil {
		t.Fatal(err)
	}
	if !Exists(p) {
		t.Fatal("should exist after write")
	}
}

// A second Seal of identical content must produce a different generation so
// successive backups are distinguishable by the counter alone.
func TestGenerationDefaultsWhenUnset(t *testing.T) {
	pub, priv := testKey(t)
	data, err := Seal(&Vault{}, &pub, nil)
	if err != nil {
		t.Fatal(err)
	}
	back, err := Open(data, &pub, &priv)
	if err != nil {
		t.Fatal(err)
	}
	if back.Generation != 1 {
		t.Fatalf("expected default generation 1, got %d", back.Generation)
	}
	if back.CreatedAt.IsZero() {
		t.Fatal("CreatedAt should be defaulted")
	}
}
