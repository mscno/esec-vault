// Package identity manages the esec-vault identity keypair.
//
// Hierarchy:
//
//	mnemonic (BIP39, cold) [+ optional passphrase]
//	  → BIP39 seed (PBKDF2-HMAC-SHA512)
//	  → Argon2id (memory-hard)
//	  → HKDF "esec-master-v2" → master keypair (deterministic)
//	  → wraps → identity keypair (random; daily use, lives in the OS keyring)
//
// The identity keypair is random and independent of the derivation: it is only
// ever re-wrapped, never regenerated, by a passphrase change or a derivation
// upgrade. That is what keeps vault blobs and teammates' share blobs readable
// across such changes — they are sealed to the identity key, not the master.
//
// Because the random private half exists nowhere but the OS keyring and the
// wrapped file, identity.esec is included in the vault backup. The recovery
// phrase plus one vault file is therefore sufficient to rebuild a machine.
package identity

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/mscno/esec/pkg/crypto"
	"github.com/tyler-smith/go-bip39"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/nacl/box"

	"github.com/mscno/esec-vault/internal/keyring"
	"github.com/mscno/esec-vault/internal/paths"
	"github.com/mscno/esec-vault/internal/storage"
)

// masterInfo is the HKDF info string for the current master-key derivation.
const masterInfo = "esec-master-v2"

// Argon2id parameters for stretching the BIP39 seed into a master key. 64 MiB
// and three passes provide a memory-hard interactive setting: expensive
// enough to make offline guessing of a weak passphrase costly, cheap enough
// for interactive unlock. These parameters are fixed by esec-master-v2.
const (
	argonTime    = 3
	argonMemory  = 64 * 1024 // KiB
	argonThreads = 2
	argonKeyLen  = 32
)

// derivationSalt namespaces the Argon2id stretch. It is a fixed constant, not
// a secret: its job is domain separation, and the entropy it protects comes
// from the BIP39 seed.
var derivationSalt = []byte("esec-identity-derivation-v1")

// ErrExists is returned when an identity already exists and overwrite was not
// confirmed.
var ErrExists = errors.New("identity already exists")

// ErrNotFound is returned when no identity is available.
var ErrNotFound = errors.New("no identity found; run 'esec-vault identity init' or 'esec-vault identity recover'")

// ErrPassphraseRequired is returned when an identity was created with a
// passphrase and none was supplied.
var ErrPassphraseRequired = errors.New("this identity is protected by a passphrase")

// Identity is the user's day-to-day keypair.
type Identity struct {
	Public  [32]byte
	Private [32]byte

	// PassphraseProtected records whether the master key was derived with a
	// non-empty passphrase. Surfaced by `esec-vault status`.
	PassphraseProtected bool

	// Derivation is the HKDF info string the master key came from.
	Derivation string
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

// ShortFingerprint returns the first 8 hex characters, for filenames and
// human-facing status lines.
func ShortFingerprint(fp string) string {
	if len(fp) <= 8 {
		return fp
	}
	return fp[:8]
}

// DeriveMaster deterministically derives the master keypair from a mnemonic and
// optional passphrase:
//
//	BIP39 seed → Argon2id → HKDF-SHA256 → X25519 keypair
//
// The passphrase may be empty, which yields an identity protected by the
// mnemonic alone.
func DeriveMaster(mnemonic string, passphrase string) (pub, priv [32]byte, err error) {
	seed, err := bip39.NewSeedWithErrorChecking(mnemonic, passphrase)
	if err != nil {
		return pub, priv, fmt.Errorf("invalid recovery phrase: %w", err)
	}
	stretched := argon2.IDKey(seed, derivationSalt, argonTime, argonMemory, argonThreads, argonKeyLen)
	masterSeed, err := crypto.DeriveKey(stretched, masterInfo)
	if err != nil {
		return pub, priv, err
	}
	p, s, err := box.GenerateKey(bytes.NewReader(masterSeed[:]))
	if err != nil {
		return pub, priv, fmt.Errorf("failed to derive master keypair: %w", err)
	}
	return *p, *s, nil
}

// identityFromPrivate recovers the public half from a private key.
func identityFromPrivate(priv [32]byte) (*Identity, error) {
	var id Identity
	id.Private = priv
	pub, _, err := box.GenerateKey(bytes.NewReader(priv[:]))
	if err != nil {
		return nil, fmt.Errorf("failed to derive identity public key: %w", err)
	}
	id.Public = *pub
	id.Derivation = masterInfo
	return &id, nil
}

// fileHeader is the cleartext prefix of identity.esec. It carries no secret
// material; its purpose is to let `status` report how an identity is protected
// and to keep the sealed box aligned.
//
// Layout:
//
//	magic "ESECID2" | derivation string length uint16 | derivation bytes |
//	flags uint8 | sealed box
//
// Flag bit 0 set means the master key was derived with a non-empty passphrase.
const (
	fileMagic       = "ESECID2"
	flagPassphrased = 1
)

type fileHeader struct {
	Magic          string   `json:"magic"`
	Derivation     string   `json:"derivation"`
	Passphrased    bool     `json:"passphrased"`
	MasterPublic   [32]byte `json:"master_public"`
	IdentityPublic [32]byte `json:"identity_public"`
}

func encodeHeader(h fileHeader) []byte {
	out := []byte(h.Magic)
	var l [2]byte
	binary.BigEndian.PutUint16(l[:], uint16(len(h.Derivation))) //nolint:gosec // derivation identifiers are fixed internal constants
	out = append(out, l[:]...)
	out = append(out, h.Derivation...)
	var flags byte
	if h.Passphrased {
		flags |= flagPassphrased
	}
	out = append(out, flags)
	out = append(out, h.MasterPublic[:]...)
	return append(out, h.IdentityPublic[:]...)
}

func decodeHeader(data []byte) (fileHeader, []byte, error) {
	var h fileHeader
	if len(data) < len(fileMagic)+2+1 {
		return h, nil, fmt.Errorf("identity file is truncated")
	}
	if string(data[:len(fileMagic)]) != fileMagic {
		return h, nil, fmt.Errorf("identity file has an unrecognised format")
	}
	rest := data[len(fileMagic):]
	n := int(binary.BigEndian.Uint16(rest[:2]))
	rest = rest[2:]
	if len(rest) < n+1+64 {
		return h, nil, fmt.Errorf("identity file is truncated")
	}
	h.Magic = fileMagic
	h.Derivation = string(rest[:n])
	h.Passphrased = rest[n]&flagPassphrased != 0
	if rest[n] & ^byte(flagPassphrased) != 0 || h.Derivation != masterInfo {
		return h, nil, fmt.Errorf("unsupported identity derivation or flags")
	}
	copy(h.MasterPublic[:], rest[n+1:n+33])
	copy(h.IdentityPublic[:], rest[n+33:n+65])
	return h, rest[n+65:], nil
}

// writeWrapped seals the identity private key to the master public key and
// stores it at identity.esec (0600, atomic).
func writeWrapped(id *Identity, masterPub *[32]byte, passphraseProtected bool) error {
	body, err := Wrapped(id, masterPub, passphraseProtected)
	if err != nil {
		return err
	}
	return storage.Write(paths.IdentityFile(), body)
}

// Wrapped returns the on-disk bytes of the master-wrapped identity key, for
// embedding in a vault backup.
func Wrapped(id *Identity, masterPub *[32]byte, passphraseProtected bool) ([]byte, error) {
	h := fileHeader{Magic: fileMagic, Derivation: masterInfo, Passphrased: passphraseProtected, MasterPublic: *masterPub, IdentityPublic: id.Public}
	plain, err := json.Marshal(wrappedPayload{Header: h, Private: id.Private})
	if err != nil {
		return nil, err
	}
	sealed, err := crypto.SealAnonymous(plain, masterPub)
	if err != nil {
		return nil, err
	}
	body := encodeHeader(h)
	return append(body, sealed...), nil
}

// unwrap reads identity.esec and opens it with the master keypair.
func unwrap(masterPub, masterPriv [32]byte, passphraseProtected bool) (*Identity, error) {
	raw, err := os.ReadFile(paths.IdentityFile())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("%w: wrapped identity file missing", ErrNotFound)
		}
		return nil, err
	}
	return UnwrapBytes(raw, masterPub, masterPriv, passphraseProtected)
}

// UnwrapBytes opens a master-wrapped identity blob taken from a vault backup
// and returns the identity. Used by the recovery path so a fresh machine can
// restore from the vault blob alone.
func UnwrapBytes(data []byte, masterPub, masterPriv [32]byte, passphraseProtected bool) (*Identity, error) {
	h, sealed, err := decodeHeader(data)
	if err != nil {
		return nil, err
	}
	if h.Derivation != masterInfo {
		return nil, fmt.Errorf("identity was wrapped with derivation %q but this build derives %q", h.Derivation, masterInfo)
	}
	plain, err := crypto.OpenAnonymous(sealed, &masterPub, &masterPriv)
	if err != nil {
		return nil, fmt.Errorf("failed to unwrap identity key: %w", err)
	}
	var p wrappedPayload
	if err := json.Unmarshal(plain, &p); err != nil {
		return nil, err
	}
	if p.Header != h || h.MasterPublic != masterPub || h.Passphrased != passphraseProtected {
		return nil, fmt.Errorf("identity header authentication failed")
	}
	id, err := identityFromPrivate(p.Private)
	if err != nil {
		return nil, err
	}
	if id.Public != h.IdentityPublic {
		return nil, fmt.Errorf("identity public key mismatch")
	}
	id.PassphraseProtected = h.Passphrased
	return id, nil
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
	priv, err := hex.DecodeString(strings.TrimSpace(privHex))
	if err != nil || len(priv) != 32 {
		return nil, fmt.Errorf("invalid identity private key in keyring")
	}
	var key [32]byte
	copy(key[:], priv)
	id, err := identityFromPrivate(key)
	if err != nil {
		return nil, err
	}
	// Recover passphrase protection from the wrapped file when it is present,
	// so `status` can report it without a mnemonic.
	if raw, err := os.ReadFile(paths.IdentityFile()); err == nil {
		if h, _, err := decodeHeader(raw); err == nil {
			id.PassphraseProtected = h.Passphrased
			id.Derivation = h.Derivation
		}
	}
	return id, nil
}

// Protect reports whether the identity file at the default location is
// passphrase-protected. It is a best-effort probe for status output.
func Protect() (passphrased bool, known bool) {
	raw, err := os.ReadFile(paths.IdentityFile())
	if err != nil {
		return false, false
	}
	h, _, err := decodeHeader(raw)
	if err != nil {
		return false, false
	}
	return h.Passphrased, true
}

// Init creates a brand-new identity and returns the mnemonic recovery phrase.
// If an identity already exists, confirmOverwrite is consulted first; a false
// answer aborts with ErrExists.
func Init(kr keyring.Keyring, passphrase string, confirmOverwrite func() bool) (mnemonic string, err error) {
	return InitConfirmed(kr, passphrase, confirmOverwrite, nil)
}

// InitConfirmed confirms the phrase before persisting an identity.
func InitConfirmed(kr keyring.Keyring, passphrase string, confirmOverwrite func() bool, confirmPhrase func(string) error) (mnemonic string, err error) {
	if _, err := Load(kr); err == nil {
		if confirmOverwrite == nil || !confirmOverwrite() {
			return "", ErrExists
		}
	} else if !errors.Is(err, ErrNotFound) {
		return "", err
	}
	if _, err := os.Stat(paths.IdentityFile()); err == nil {
		if _, loadErr := Load(kr); errors.Is(loadErr, ErrNotFound) {
			return "", fmt.Errorf("wrapped identity already exists; recover it before initializing")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
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

	masterPub, _, err := DeriveMaster(mnemonic, passphrase)
	if err != nil {
		return "", err
	}

	var id Identity
	pub, priv, err := box.GenerateKey(rand.Reader) // random identity keypair
	if err != nil {
		return "", err
	}
	id.Public, id.Private = *pub, *priv
	id.Derivation = masterInfo
	id.PassphraseProtected = passphrase != ""
	if confirmPhrase != nil {
		if err := confirmPhrase(mnemonic); err != nil {
			return "", err
		}
	}

	if err := commit(kr, &id, &masterPub); err != nil {
		return "", fmt.Errorf("failed to store identity in keyring: %w", err)
	}
	return mnemonic, nil
}

// Recover rebuilds the identity from the mnemonic recovery phrase and the
// wrapped identity blob, then stores the identity in the OS keyring. The
// wrapped blob is read from the vault backup so a fresh machine needs only the
// phrase and the backup. If wrapped is nil the on-disk identity.esec is used.
func Recover(kr keyring.Keyring, mnemonic, passphrase string, wrapped []byte, confirmOverwrite func() bool) (*Identity, error) {
	if _, err := Load(kr); err == nil {
		if confirmOverwrite == nil || !confirmOverwrite() {
			return nil, ErrExists
		}
	} else if !errors.Is(err, ErrNotFound) {
		return nil, err
	}

	masterPub, masterPriv, err := DeriveMaster(mnemonic, passphrase)
	if err != nil {
		return nil, err
	}

	var id *Identity
	if len(wrapped) > 0 {
		id, err = UnwrapBytes(wrapped, masterPub, masterPriv, passphrase != "")
	} else {
		id, err = unwrap(masterPub, masterPriv, passphrase != "")
	}
	if err != nil {
		return nil, err
	}
	if err := commit(kr, id, &masterPub); err != nil {
		return nil, err
	}
	return id, nil
}

// ChangePassphrase re-wraps the existing identity under a master key derived
// with a new passphrase. The identity keypair itself is preserved, so vault
// blobs and teammates' share blobs remain readable; only identity.esec changes.
func ChangePassphrase(kr keyring.Keyring, mnemonic, oldPassphrase, newPassphrase string) (*Identity, error) {
	current, err := Load(kr)
	if err != nil {
		return nil, err
	}
	oldPub, oldPriv, err := DeriveMaster(mnemonic, oldPassphrase)
	if err != nil {
		return nil, err
	}
	// Verify the phrase+old passphrase actually open this identity before
	// writing anything.
	verified, err := unwrap(oldPub, oldPriv, oldPassphrase != "")
	if err != nil {
		return nil, fmt.Errorf("recovery phrase and current passphrase did not open the identity: %w", err)
	}
	if verified.Public != current.Public {
		return nil, fmt.Errorf("keychain and wrapped identity disagree")
	}
	newPub, _, err := DeriveMaster(mnemonic, newPassphrase)
	if err != nil {
		return nil, err
	}
	current.Derivation = masterInfo
	current.PassphraseProtected = newPassphrase != ""
	if err := commit(kr, current, &newPub); err != nil {
		return nil, err
	}
	return current, nil
}

// Rotate generates a new random identity keypair, re-wraps it to the master
// keypair derived from the mnemonic, and updates the OS keyring. Vault and
// share blobs sealed to the old identity must be re-sealed afterwards — use
// ChangePassphrase instead if the goal is only to change protection.
func Rotate(kr keyring.Keyring, mnemonic, passphrase string) (*Identity, error) {
	masterPub, masterPriv, err := DeriveMaster(mnemonic, passphrase)
	if err != nil {
		return nil, err
	}
	verified, err := unwrap(masterPub, masterPriv, passphrase != "")
	if err != nil {
		return nil, err
	}
	current, err := Load(kr)
	if err != nil {
		return nil, err
	}
	if current.Public != verified.Public {
		return nil, fmt.Errorf("keychain and wrapped identity disagree")
	}
	var id Identity
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	id.Public, id.Private = *pub, *priv
	id.Derivation = masterInfo
	id.PassphraseProtected = passphrase != ""
	if err := commit(kr, &id, &masterPub); err != nil {
		return nil, err
	}
	return &id, nil
}

// MaxMemoryHint reports the Argon2id memory cost in MiB, so callers can warn
// on constrained machines.
func MaxMemoryHint() uint { return uint(argonMemory / 1024) }

// PublicFromPrivate derives the public half of an X25519 keypair.
func PublicFromPrivate(priv [32]byte) [32]byte {
	pub, _, err := box.GenerateKey(bytes.NewReader(priv[:]))
	if err != nil {
		return [32]byte{}
	}
	return *pub
}

// CommitMigrated persists a v1 identity under the current derivation.
func CommitMigrated(kr keyring.Keyring, id *Identity, masterPub *[32]byte) error {
	id.Derivation = masterInfo
	id.PassphraseProtected = false
	return commit(kr, id, masterPub)
}
