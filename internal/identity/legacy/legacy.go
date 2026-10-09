// Package legacy reads identity files written before the v2 derivation.
//
// v1 derived the master key straight from the mnemonic's entropy via
// HKDF-SHA256 with a fixed salt and no passphrase. It exists only so
// `esec-vault identity migrate` can re-wrap an existing identity under the v2
// derivation. Nothing else may use it, and it can be deleted once no machine
// needs migrating.
//
// The v1 file format is a bare sealed box: no header, no version byte. v2 files
// begin with the "ESECID2" magic, so the two are trivially distinguishable.
package legacy

import (
	"bytes"
	"errors"
	"fmt"
	"os"

	"github.com/mscno/esec/pkg/crypto"
	"golang.org/x/crypto/nacl/box"
)

// masterInfoV1 is the HKDF info string used by the original derivation.
const masterInfoV1 = "esec-master-v1"

// deriveSaltV1 matches the fixed salt in esec's crypto.DeriveKey.
var deriveSaltV1 = []byte("esec-key-derivation-v1")

// ErrNotLegacy is returned when the file is not a v1 identity file.
var ErrNotLegacy = errors.New("not a legacy v1 identity file")

// v2Magic is the current identity file magic; its presence rules out v1.
const v2Magic = "ESECID2"

// IsLegacy reports whether data looks like a v1 identity file.
func IsLegacy(data []byte) bool {
	return !bytes.HasPrefix(data, []byte(v2Magic))
}

// MasterKeypairV1 reproduces the v1 master keypair from the mnemonic entropy.
// The v1 scheme derived from the raw entropy rather than the BIP39 seed, and
// ignored any passphrase.
func MasterKeypairV1(mnemonic string, entropyFromMnemonic func(string) ([]byte, error)) (pub, priv [32]byte, err error) {
	entropy, err := entropyFromMnemonic(mnemonic)
	if err != nil {
		return pub, priv, fmt.Errorf("invalid recovery phrase: %w", err)
	}
	seed, err := hkdfSHA256(entropy, deriveSaltV1, masterInfoV1)
	if err != nil {
		return pub, priv, err
	}
	p, s, err := box.GenerateKey(bytes.NewReader(seed))
	if err != nil {
		return pub, priv, fmt.Errorf("failed to derive master keypair: %w", err)
	}
	return *p, *s, nil
}

// UnwrapV1 opens a v1 identity file with the v1 master keypair and returns the
// 32-byte identity private key.
func UnwrapV1(path string, masterPub, masterPriv [32]byte) ([32]byte, error) {
	var priv [32]byte
	data, err := os.ReadFile(path) //nolint:gosec // path is the trusted identity file
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return priv, fmt.Errorf("identity file not found at %s", path)
		}
		return priv, err
	}
	if !IsLegacy(data) {
		return priv, ErrNotLegacy
	}
	raw, err := crypto.OpenAnonymous(data, &masterPub, &masterPriv)
	if err != nil {
		return priv, fmt.Errorf("failed to unwrap legacy identity (wrong recovery phrase?): %w", err)
	}
	if len(raw) != 32 {
		return priv, fmt.Errorf("legacy identity has unexpected length %d", len(raw))
	}
	copy(priv[:], raw)
	return priv, nil
}
