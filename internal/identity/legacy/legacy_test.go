package legacy

import (
	"bytes"
	"crypto/sha256"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/mscno/esec/pkg/crypto"
	"github.com/tyler-smith/go-bip39"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/nacl/box"
)

// v1Seal reproduces the original identity file: a bare sealed box with no
// header and no version byte.
func v1Seal(priv *[32]byte, masterPub *[32]byte) []byte {
	boxed, err := crypto.SealAnonymous(priv[:], masterPub)
	if err != nil {
		panic(err)
	}
	return boxed
}

func TestV1RoundTrip(t *testing.T) {
	entropy, err := bip39.NewEntropy(256)
	if err != nil {
		t.Fatal(err)
	}
	mnemonic, err := bip39.NewMnemonic(entropy)
	if err != nil {
		t.Fatal(err)
	}
	masterPub, masterPriv, err := MasterKeypairV1(mnemonic, bip39.EntropyFromMnemonic)
	if err != nil {
		t.Fatal(err)
	}
	// A random identity keypair, as v1 would have created.
	var idPriv [32]byte
	copy(idPriv[:], bytes.Repeat([]byte{0x42}, 32))

	path := filepath.Join(t.TempDir(), "identity.esec")
	if err := os.WriteFile(path, v1Seal(&idPriv, &masterPub), 0600); err != nil {
		t.Fatal(err)
	}

	got, err := UnwrapV1(path, masterPub, masterPriv)
	if err != nil {
		t.Fatal(err)
	}
	if got != idPriv {
		t.Fatal("recovered the wrong identity private key")
	}
}

func TestV1DerivationIsDeterministic(t *testing.T) {
	entropy, _ := bip39.NewEntropy(256)
	mnemonic, _ := bip39.NewMnemonic(entropy)
	p1, s1, err := MasterKeypairV1(mnemonic, bip39.EntropyFromMnemonic)
	if err != nil {
		t.Fatal(err)
	}
	p2, s2, err := MasterKeypairV1(mnemonic, bip39.EntropyFromMnemonic)
	if err != nil {
		t.Fatal(err)
	}
	if p1 != p2 || s1 != s2 {
		t.Fatal("v1 derivation must be deterministic")
	}
}

func TestV1RejectsWrongPhrase(t *testing.T) {
	entropy, _ := bip39.NewEntropy(256)
	mnemonic, _ := bip39.NewMnemonic(entropy)
	masterPub, _, err := MasterKeypairV1(mnemonic, bip39.EntropyFromMnemonic)
	if err != nil {
		t.Fatal(err)
	}
	var idPriv [32]byte
	path := filepath.Join(t.TempDir(), "identity.esec")
	if err := os.WriteFile(path, v1Seal(&idPriv, &masterPub), 0600); err != nil {
		t.Fatal(err)
	}
	wrongEntropy, _ := bip39.NewEntropy(256)
	wrong, _ := bip39.NewMnemonic(wrongEntropy)
	_, wMasterPriv, _ := MasterKeypairV1(wrong, bip39.EntropyFromMnemonic)
	if _, err := UnwrapV1(path, masterPub, wMasterPriv); err == nil {
		t.Fatal("a wrong phrase must not unwrap a v1 identity")
	}
}

func TestIsLegacy(t *testing.T) {
	if !IsLegacy([]byte("raw sealed box bytes....")) {
		t.Fatal("a bare box should be detected as legacy")
	}
	if IsLegacy([]byte("ESECID2somepayload")) {
		t.Fatal("a v2 file must not be detected as legacy")
	}
}

func TestUnwrapV1RejectsV2File(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.esec")
	if err := os.WriteFile(path, []byte("ESECID2esec-master-v2\x00payload"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := UnwrapV1(path, [32]byte{}, [32]byte{}); err != ErrNotLegacy {
		t.Fatalf("expected ErrNotLegacy, got %v", err)
	}
}

func TestUnwrapV1MissingFile(t *testing.T) {
	if _, err := UnwrapV1(filepath.Join(t.TempDir(), "nope"), [32]byte{}, [32]byte{}); err == nil {
		t.Fatal("expected an error for a missing file")
	}
}

// The v1 and v2 derivations must not coincide, or the migration would be a
// no-op that silently "worked" without re-wrapping anything.
func TestV1AndV2DerivationsDiffer(t *testing.T) {
	entropy, _ := bip39.NewEntropy(256)
	mnemonic, _ := bip39.NewMnemonic(entropy)
	v1Pub, _, err := MasterKeypairV1(mnemonic, bip39.EntropyFromMnemonic)
	if err != nil {
		t.Fatal(err)
	}
	v2Pub := deriveV2Pub(t, mnemonic, "")
	if v1Pub == v2Pub {
		t.Fatal("v1 and v2 must derive different master keys")
	}
}

// deriveV2Pub reproduces the current derivation inline. The legacy package
// deliberately does not import its parent, so the test re-derives rather than
// sharing code.
func deriveV2Pub(t *testing.T, mnemonic, passphrase string) [32]byte {
	t.Helper()
	seed := bip39.NewSeed(mnemonic, passphrase)
	stretched := argon2.IDKey(seed, []byte("esec-identity-derivation-v1"), 3, 64*1024, 2, 32)
	var out [32]byte
	r := hkdf.New(sha256.New, stretched, []byte("esec-key-derivation-v1"), []byte("esec-master-v2"))
	if _, err := io.ReadFull(r, out[:]); err != nil {
		t.Fatal(err)
	}
	pub, _, err := box.GenerateKey(bytes.NewReader(out[:]))
	if err != nil {
		t.Fatal(err)
	}
	return *pub
}
