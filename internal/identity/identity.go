// Package identity manages the esec-vault identity keypair.
//
// Hierarchy:
//
//	mnemonic (BIP39, cold) → HKDF "esec-master-v1" → master keypair
//	master keypair wraps → random identity keypair (daily use, OS keyring)
//
// The mnemonic is the only cold-recovery secret. The identity key can be
// rotated without changing the mnemonic; the wrapped identity key is stored
// in <home>/identity.esec so a fresh machine can be recovered from the
// mnemonic alone.
package identity

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"

	"github.com/mscno/esec/pkg/crypto"
	"github.com/tyler-smith/go-bip39"
	"golang.org/x/crypto/nacl/box"

	"github.com/mscno/esec-vault/internal/keyring"
	"github.com/mscno/esec-vault/internal/paths"
)

// masterInfo is the HKDF info string separating master-key derivation.
const masterInfo = "esec-master-v1"

// ErrExists is returned when an identity already exists and overwrite was not
// confirmed.
var ErrExists = errors.New("identity already exists")

// ErrNotFound is returned when no identity is available.
var ErrNotFound = errors.New("no identity found; run 'esec-vault identity init' or 'esec-vault identity recover'")

// Identity is the user's day-to-day keypair.
type Identity struct {
	Public  [32]byte
	Private [32]byte
}

// PublicHex returns the hex-encoded public key.
func (i *Identity) PublicHex() string { return hex.EncodeToString(i.Public[:]) }

// Fingerprint returns the human-comparable identity fingerprint.
func (i *Identity) Fingerprint() string { return Fingerprint(i.Public) }

// Fingerprint returns the SHA-256 fingerprint of a public key, hex encoded.
func Fingerprint(pub [32]byte) string {
	sum := sha256.Sum256(pub[:])
	return hex.EncodeToString(sum[:])
}

// masterKeypair deterministically derives the master keypair from a mnemonic.
func masterKeypair(mnemonic string) (pub, priv [32]byte, err error) {
	entropy, err := bip39.EntropyFromMnemonic(mnemonic)
	if err != nil {
		return pub, priv, fmt.Errorf("invalid recovery phrase: %w", err)
	}
	seed, err := crypto.DeriveKey(entropy, masterInfo)
	if err != nil {
		return pub, priv, err
	}
	p, s, err := box.GenerateKey(bytes.NewReader(seed[:]))
	if err != nil {
		return pub, priv, fmt.Errorf("failed to derive master keypair: %w", err)
	}
	return *p, *s, nil
}

// writeWrapped seals the identity private key to the master public key and
// stores it at identity.esec (0600, atomic).
func writeWrapped(id *Identity, masterPub *[32]byte) error {
	sealed, err := crypto.SealAnonymous(id.Private[:], masterPub)
	if err != nil {
		return err
	}
	if err := paths.EnsureHome(); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(paths.Home(), ".identity-*.tmp")
	if err != nil {
		return err
	}
	if _, err := tmp.Write(sealed); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	return os.Rename(tmp.Name(), paths.IdentityFile())
}

// unwrap reads identity.esec and opens it with the master keypair.
func unwrap(masterPub, masterPriv [32]byte) (*Identity, error) {
	sealed, err := os.ReadFile(paths.IdentityFile())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("%w: wrapped identity file missing", ErrNotFound)
		}
		return nil, err
	}
	priv, err := crypto.OpenAnonymous(sealed, &masterPub, &masterPriv)
	if err != nil {
		return nil, fmt.Errorf("failed to unwrap identity key: %w", err)
	}
	if len(priv) != 32 {
		return nil, fmt.Errorf("wrapped identity key has unexpected length %d", len(priv))
	}
	var id Identity
	copy(id.Private[:], priv)
	pub, _, err := box.GenerateKey(bytes.NewReader(id.Private[:]))
	if err != nil {
		return nil, fmt.Errorf("failed to derive identity public key: %w", err)
	}
	id.Public = *pub
	return &id, nil
}

// store persists the identity in the OS keyring.
func store(kr keyring.Keyring, id *Identity) error {
	if err := kr.Set(keyring.IdentityPrivateKey, hex.EncodeToString(id.Private[:])); err != nil {
		return err
	}
	if err := kr.Set(keyring.IdentityPublicKey, hex.EncodeToString(id.Public[:])); err != nil {
		_ = kr.Delete(keyring.IdentityPrivateKey)
		return err
	}
	return nil
}

// Load returns the identity from the OS keyring.
func Load(kr keyring.Keyring) (*Identity, error) {
	privHex, err := kr.Get(keyring.IdentityPrivateKey)
	if err != nil {
		if errors.Is(err, keyring.ErrNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	priv, err := hex.DecodeString(privHex)
	if err != nil || len(priv) != 32 {
		return nil, fmt.Errorf("invalid identity private key in keyring")
	}
	var id Identity
	copy(id.Private[:], priv)
	pub, _, err := box.GenerateKey(bytes.NewReader(id.Private[:]))
	if err != nil {
		return nil, fmt.Errorf("failed to derive identity public key: %w", err)
	}
	id.Public = *pub
	return &id, nil
}

// Init creates a brand-new identity and returns the mnemonic recovery phrase.
// If an identity already exists, confirmOverwrite is consulted first; a false
// answer aborts with ErrExists.
func Init(kr keyring.Keyring, confirmOverwrite func() bool) (mnemonic string, err error) {
	if _, err := Load(kr); err == nil {
		if confirmOverwrite == nil || !confirmOverwrite() {
			return "", ErrExists
		}
	} else if !errors.Is(err, ErrNotFound) {
		return "", err
	}

	entropy, err := bip39.NewEntropy(256)
	if err != nil {
		return "", fmt.Errorf("failed to generate entropy: %w", err)
	}
	mnemonic, err = bip39.NewMnemonic(entropy)
	if err != nil {
		return "", fmt.Errorf("failed to generate mnemonic: %w", err)
	}

	// Master keypair from the same entropy the mnemonic encodes.
	seed, err := crypto.DeriveKey(entropy, masterInfo)
	if err != nil {
		return "", err
	}
	masterPub, _, err := box.GenerateKey(bytes.NewReader(seed[:]))
	if err != nil {
		return "", fmt.Errorf("failed to derive master keypair: %w", err)
	}

	var id Identity
	pub, priv, err := box.GenerateKey(rand.Reader) // random identity keypair
	if err != nil {
		return "", err
	}
	id.Public, id.Private = *pub, *priv

	if err := writeWrapped(&id, masterPub); err != nil {
		return "", fmt.Errorf("failed to store wrapped identity: %w", err)
	}
	if err := store(kr, &id); err != nil {
		return "", fmt.Errorf("failed to store identity in keyring: %w", err)
	}
	return mnemonic, nil
}

// Recover rebuilds the identity from the mnemonic recovery phrase: it derives
// the master keypair, unwraps identity.esec, and stores the identity in the OS
// keyring. If the wrapped file is missing or undecryptable the mnemonic cannot
// recover the old identity, and an error is returned.
func Recover(kr keyring.Keyring, mnemonic string, confirmOverwrite func() bool) error {
	if _, err := Load(kr); err == nil {
		if confirmOverwrite == nil || !confirmOverwrite() {
			return ErrExists
		}
	} else if !errors.Is(err, ErrNotFound) {
		return err
	}

	masterPub, masterPriv, err := masterKeypair(mnemonic)
	if err != nil {
		return err
	}
	id, err := unwrap(masterPub, masterPriv)
	if err != nil {
		return err
	}
	return store(kr, id)
}

// Rotate generates a new random identity keypair, re-wraps it to the master
// keypair derived from the mnemonic, and updates the OS keyring. Vault and
// share blobs sealed to the old identity must be re-sealed afterwards.
func Rotate(kr keyring.Keyring, mnemonic string) (*Identity, error) {
	masterPub, _, err := masterKeypair(mnemonic)
	if err != nil {
		return nil, err
	}
	var id Identity
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	id.Public, id.Private = *pub, *priv
	if err := writeWrapped(&id, &masterPub); err != nil {
		return nil, err
	}
	if err := store(kr, &id); err != nil {
		return nil, err
	}
	return &id, nil
}
