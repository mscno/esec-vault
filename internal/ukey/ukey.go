// Package ukey moves the user key (U) between devices without exposing it to
// the server: sealed to one device's X25519 key ("device box"), or wrapped
// under a key derived from an SSH-agent signature ("agent slot").
package ukey

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"

	"github.com/mscno/esec/pkg/crypto"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"

	"github.com/mscno/esec-vault/internal/chain"
	"github.com/mscno/esec-vault/internal/envelope"
	"github.com/mscno/esec-vault/internal/identity"
)

// Material is the private user key at one version.
type Material struct {
	User        string `json:"user"`
	UKeyVersion uint64 `json:"ukey_version"`
	EncPriv     []byte `json:"enc_priv"`
	SignSeed    []byte `json:"sign_seed"`
}

// FromIdentity captures id as material for user at version.
func FromIdentity(user string, version uint64, id *identity.Identity) (*Material, error) {
	if id.Sign == nil {
		return nil, fmt.Errorf("identity has no signing key")
	}
	return &Material{User: user, UKeyVersion: version, EncPriv: bytes.Clone(id.Private[:]), SignSeed: bytes.Clone(id.Sign.Seed())}, nil
}

// Identity rebuilds the identity from m.
func (m *Material) Identity() (*identity.Identity, error) {
	if len(m.EncPriv) != 32 {
		return nil, fmt.Errorf("user key has the wrong length")
	}
	var priv [32]byte
	copy(priv[:], m.EncPriv)
	return identity.FromKeys(priv, m.SignSeed)
}

// Check verifies that m is the current user key of the verified chain s.
// This is what stops a forged box from installing a key the user's other
// devices never signed for.
func (m *Material) Check(s *chain.State) (*identity.Identity, error) {
	if m.User != s.User {
		return nil, fmt.Errorf("user key belongs to a different account")
	}
	if m.UKeyVersion != s.UKeyVersion {
		return nil, fmt.Errorf("user key version %d is not the current version %d", m.UKeyVersion, s.UKeyVersion)
	}
	id, err := m.Identity()
	if err != nil {
		return nil, err
	}
	if id.Public != s.EncPub || !bytes.Equal(id.SignPublic(), s.SignPub) {
		return nil, fmt.Errorf("user key does not match the verified chain")
	}
	return id, nil
}

// SealToDevice seals m to a device's X25519 public key.
func SealToDevice(m *Material, devEncPub [32]byte) ([]byte, error) {
	plain, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	return crypto.SealAnonymous(plain, &devEncPub)
}

// OpenDeviceBox opens a device box with the device's X25519 keypair.
func OpenDeviceBox(box []byte, pub, priv *[32]byte) (*Material, error) {
	plain, err := crypto.OpenAnonymous(box, pub, priv)
	if err != nil {
		return nil, fmt.Errorf("device box could not be opened: %w", err)
	}
	return decode(plain)
}

func decode(plain []byte) (*Material, error) {
	var m Material
	if err := envelope.DecodeStrict(plain, &m); err != nil {
		return nil, fmt.Errorf("invalid user key payload: %w", err)
	}
	if len(m.EncPriv) != 32 || len(m.SignSeed) != ed25519.SeedSize {
		return nil, fmt.Errorf("invalid user key payload")
	}
	return &m, nil
}

// SlotChallenge is the message an SSH agent signs to unlock a slot. It is
// signed as SSHSIG in namespace SlotNamespace.
func SlotChallenge(user, slotID string, salt []byte) []byte {
	return []byte("esec-vault agent-unlock v1\n" + user + "\n" + slotID + "\n" + hex.EncodeToString(salt) + "\n")
}

// SlotNamespace is the SSHSIG namespace for unlock signatures. It differs
// from the "esec-vault" identity-proof namespace, so an identity proof can
// never double as an unlock signature.
const SlotNamespace = "esec-vault-unlock"

// SlotKEK derives the slot wrapping key from the raw signature bytes.
func SlotKEK(signature, salt []byte) (*[32]byte, error) {
	if len(salt) != 32 {
		return nil, fmt.Errorf("slot salt must be 32 bytes")
	}
	r := hkdf.New(sha256.New, signature, salt, []byte("esec-vault agent-unlock kek v1"))
	var k [32]byte
	if _, err := io.ReadFull(r, k[:]); err != nil {
		return nil, err
	}
	return &k, nil
}

func slotAAD(user, slotID string) []byte {
	return []byte("esec-vault agent-unlock box v1\n" + slotID + "\n" + user)
}

// SealSlot wraps m under kek for slot slotID of user.
func SealSlot(m *Material, kek *[32]byte, user, slotID string) ([]byte, error) {
	plain, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.NewX(kek[:])
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize(), aead.NonceSize()+len(plain)+aead.Overhead())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return aead.Seal(nonce, nonce, plain, slotAAD(user, slotID)), nil
}

// OpenSlot unwraps a slot box.
func OpenSlot(box []byte, kek *[32]byte, user, slotID string) (*Material, error) {
	aead, err := chacha20poly1305.NewX(kek[:])
	if err != nil {
		return nil, err
	}
	if len(box) < aead.NonceSize()+aead.Overhead() {
		return nil, fmt.Errorf("slot box truncated")
	}
	plain, err := aead.Open(nil, box[:aead.NonceSize()], box[aead.NonceSize():], slotAAD(user, slotID))
	if err != nil {
		return nil, fmt.Errorf("slot box could not be opened with this SSH key")
	}
	return decode(plain)
}
