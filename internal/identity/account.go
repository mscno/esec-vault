package identity

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"os"

	"golang.org/x/crypto/nacl/box"

	"github.com/mscno/esec-vault/internal/keyring"
	"github.com/mscno/esec-vault/internal/paths"
)

// Header is the public, unauthenticated summary of a wrapped identity file.
type Header struct {
	Version        int
	Passphrased    bool
	MasterPublic   [32]byte
	IdentityPublic [32]byte
	// SignPublic is zero for version 2 files.
	SignPublic [32]byte
}

// ReadHeader parses the cleartext header of a wrapped identity.
func ReadHeader(wrapped []byte) (*Header, error) {
	h, _, err := decodeHeader(wrapped)
	if err != nil {
		return nil, err
	}
	out := &Header{Version: 2, Passphrased: h.Passphrased, MasterPublic: h.MasterPublic, IdentityPublic: h.IdentityPublic, SignPublic: h.SignPublic}
	if h.Magic == fileMagicV3 {
		out.Version = 3
	}
	return out, nil
}

// NewRandom returns a fresh identity with both an X25519 and an Ed25519 key.
func NewRandom() (*Identity, error) {
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	_, sign, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Identity{Public: *pub, Private: *priv, Sign: sign, Derivation: masterInfo}, nil
}

// FromKeys rebuilds an identity from raw private material received from
// another device.
func FromKeys(encPriv [32]byte, signSeed []byte) (*Identity, error) {
	id, err := identityFromPrivate(encPriv)
	if err != nil {
		return nil, err
	}
	if len(signSeed) != ed25519.SeedSize {
		return nil, fmt.Errorf("signing key has the wrong length")
	}
	id.Sign = ed25519.NewKeyFromSeed(signSeed)
	return id, nil
}

// EnsureSigningKey adds an Ed25519 signing key to an identity that lacks
// one and rewrites identity.esec as version 3.
//
// No recovery phrase is needed: the file is sealed to the master PUBLIC key,
// which the version 2 header already records. Only opening it needs the
// phrase, so the phrase remains the only way to recover the identity.
func EnsureSigningKey(kr keyring.Keyring) (*Identity, bool, error) {
	id, err := Load(kr)
	if err != nil {
		return nil, false, err
	}
	raw, err := os.ReadFile(paths.IdentityFile())
	if err != nil {
		return nil, false, fmt.Errorf("read wrapped identity: %w", err)
	}
	h, err := ReadHeader(raw)
	if err != nil {
		return nil, false, err
	}
	if h.IdentityPublic != id.Public {
		return nil, false, fmt.Errorf("keychain and wrapped identity disagree")
	}
	if id.Sign != nil {
		if h.Version != 3 || !bytes.Equal(h.SignPublic[:], id.SignPublic()) {
			return nil, false, fmt.Errorf("keychain signing key does not match identity.esec")
		}
		return id, false, nil
	}
	if h.Version == 3 {
		return nil, false, fmt.Errorf("identity.esec has a signing key but the keychain does not; recover the identity with 'esec vault identity recover'")
	}
	_, sign, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, false, err
	}
	id.Sign = sign
	id.PassphraseProtected = h.Passphrased
	master := h.MasterPublic
	if err := commit(kr, id, &master); err != nil {
		return nil, false, err
	}
	return id, true, nil
}

// ErrWrappedMismatch is returned when a wrapped identity does not belong to
// the identity being installed.
var ErrWrappedMismatch = errors.New("wrapped identity does not match the identity keys")

// Install stores an identity received from another device together with its
// master-wrapped file. The wrapped file must be version 3 and name exactly
// these keys in its header.
func Install(kr keyring.Keyring, id *Identity, wrapped []byte) error {
	if id.Sign == nil {
		return fmt.Errorf("identity has no signing key")
	}
	h, err := ReadHeader(wrapped)
	if err != nil {
		return err
	}
	if h.Version != 3 || h.IdentityPublic != id.Public || !bytes.Equal(h.SignPublic[:], id.SignPublic()) {
		return ErrWrappedMismatch
	}
	id.PassphraseProtected = h.Passphrased
	id.Derivation = masterInfo
	return commitWrapped(kr, id, wrapped)
}

// WrapForMaster seals id to the master public key recorded in an existing
// wrapped identity. Rotation uses it to produce the new identity.esec without
// the recovery phrase.
func WrapForMaster(id *Identity, current []byte) ([]byte, error) {
	h, err := ReadHeader(current)
	if err != nil {
		return nil, err
	}
	master := h.MasterPublic
	return Wrapped(id, &master, h.Passphrased)
}

// WrappedFile returns the bytes of identity.esec.
func WrappedFile() ([]byte, error) {
	return os.ReadFile(paths.IdentityFile())
}
