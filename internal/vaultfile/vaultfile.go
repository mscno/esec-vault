// Package vaultfile implements the sealed vault blob format: an encrypted
// backup of every keyring plus the identity key that can open it, sealed to
// the owner's identity key.
//
// Layout on disk (multi-byte fields little-endian):
//
//	magic "ESECVLT" | version byte (2) | flags byte | sealed box | sealed box
//
// The blob is sealed twice. The first box is sealed to the identity key and is
// what daily use opens. The second is sealed to the master key, which is
// derived from the recovery phrase — that copy is what makes cold recovery
// possible, since a fresh machine can derive the master key from the phrase
// alone and needs no existing identity to begin.
//
// Sealing twice is necessary rather than merely convenient: the payload carries
// the master-wrapped identity, but a blob sealed only to the identity could not
// be opened on a machine that has lost its identity, so the wrapped copy inside
// it would be unreachable.
//
// The header carries no other metadata: in v1 the timestamp sat in cleartext
// outside the sealed box and was never authenticated, so a rollback could
// rewrite it undetected. Everything else lives inside the sealed payload.
//
// The sealed JSON payload holds the keyring index, the owner's master-wrapped
// identity key, a monotonic generation counter and an inner SHA-256 of the
// canonical body, so truncation and bit flips are caught even beyond the box's
// Poly1305 authentication.
//
// Including the wrapped identity is what makes a backup self-sufficient: the
// recovery phrase plus this one file reconstruct every key. The identity
// keypair is stable across re-wraps, so blobs stay readable after a passphrase
// change or derivation upgrade.
package vaultfile

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/mscno/esec-vault/internal/storage"
	"github.com/mscno/esec/pkg/crypto"
)

const (
	magic   = "ESECVLT"
	version = 2
)

// headerLen = len(magic) + 1 (version) + 1 (flags) + 4 (identity box length)
const headerLen = 7 + 1 + 1 + 4

// lenField is the width of the identity-sealed box length in the header.
const lenField = 4

// Flags bit 0: a master-sealed copy of the payload follows the identity copy.
const flagHasMasterCopy = 1

// Vault is the decrypted content of a vault blob: project identifier →
// keyring entries (e.g. ESEC_PRIVATE_KEY_DEV → hex key).
type Vault struct {
	Projects map[string]map[string]string `json:"projects"`
	Files    map[string][]byte            `json:"files,omitempty"`

	// Identity is the master-wrapped identity private key, base64 encoded as
	// stored in identity.esec. When present the blob is self-sufficient: the
	// recovery phrase alone can restore the full setup on a fresh machine.
	Identity []byte `json:"identity,omitempty"`

	// IdentityFingerprint is the SHA-256 fingerprint of the identity public
	// key. It lets `status` confirm a blob belongs to the identity at hand.
	IdentityFingerprint string `json:"identity_fingerprint,omitempty"`

	// Generation counts backups taken with this keyring set, starting at 1.
	// It increments on every successful backup so a stale remote copy is
	// detectable by comparison alone.
	Generation uint64 `json:"generation"`

	// CreatedAt is when this generation was sealed. Authenticated by being
	// inside the sealed box.
	CreatedAt time.Time `json:"created_at"`
}

// payload is the sealed JSON body. SHA256 covers the canonical encoding of
// every other field, binding the hash to the content it describes.
type payload struct {
	Projects            map[string]map[string]string `json:"projects"`
	Files               map[string][]byte            `json:"files,omitempty"`
	Identity            []byte                       `json:"identity,omitempty"`
	IdentityFingerprint string                       `json:"identity_fingerprint,omitempty"`
	Generation          uint64                       `json:"generation"`
	CreatedAt           time.Time                    `json:"created_at"`
	SHA256              string                       `json:"sha256"`
	HasRecovery         bool                         `json:"has_recovery"`
	RecoveryHash        string                       `json:"recovery_hash,omitempty"`
}

// ErrCorrupt is returned when a vault blob fails structural or integrity
// checks.
var ErrCorrupt = errors.New("vault blob is corrupt")

// ErrLegacyFormat is returned when a v1 blob is opened. v1 blobs did not carry
// the identity key, so they cannot restore a machine on their own; re-back up
// from a machine that still has identity.esec.
var ErrLegacyFormat = errors.New("vault blob is a legacy v1 backup that does not contain the identity key; re-run 'esec-vault backup' from a machine that still has identity.esec")

// ErrNoMasterCopy is returned when a blob is opened from the recovery phrase
// but carries no master-sealed copy.
var ErrNoMasterCopy = errors.New("vault blob has no master-sealed copy")

// canonical encodes the hash-covered body deterministically. encoding/json
// sorts map keys, so equal content always yields equal bytes.
func canonical(p *payload) ([]byte, error) {
	shadow := *p
	shadow.SHA256 = ""
	return json.Marshal(&shadow)
}

func digest(p *payload) (string, error) {
	b, err := canonical(p)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// NextGeneration returns the generation a new backup should carry.
func NextGeneration(v *Vault) uint64 {
	if v == nil {
		return 1
	}
	return v.Generation + 1
}

// Seal serializes v and seals it to recipientPub. When masterPub is non-nil a
// second copy sealed to the master key is appended, which is what allows a
// machine with no identity to recover from the recovery phrase alone.
func Seal(v *Vault, recipientPub *[32]byte, masterPub *[32]byte) ([]byte, error) {
	if v == nil {
		v = &Vault{}
	}
	if v.Projects == nil {
		v.Projects = map[string]map[string]string{}
	}
	if v.Generation == 0 {
		v.Generation = 1
	}
	if v.CreatedAt.IsZero() {
		v.CreatedAt = time.Now().UTC()
	}
	p := &payload{
		Projects:            v.Projects,
		Files:               v.Files,
		Identity:            v.Identity,
		IdentityFingerprint: v.IdentityFingerprint,
		Generation:          v.Generation,
		CreatedAt:           v.CreatedAt.UTC(),
		HasRecovery:         masterPub != nil,
	}
	var masterBox []byte
	if masterPub != nil {
		var err error
		masterBox, err = sealPayload(p, masterPub)
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(masterBox)
		p.RecoveryHash = hex.EncodeToString(sum[:])
	}
	boxed, err := sealPayload(p, recipientPub)
	if err != nil {
		return nil, err
	}

	var flags byte
	out := make([]byte, 0, headerLen+len(boxed)*2)
	out = append(out, magic...)
	out = append(out, version)

	var lenbuf [lenField]byte
	if uint64(len(boxed)) > uint64(^uint32(0)) {
		return nil, fmt.Errorf("vault exceeds format size limit")
	}
	binary.BigEndian.PutUint32(lenbuf[:], uint32(len(boxed))) //nolint:gosec // bounded above

	if masterPub != nil {
		flags |= flagHasMasterCopy
		out = append(out, flags)
		out = append(out, lenbuf[:]...)
		out = append(out, boxed...)
		return append(out, masterBox...), nil
	}
	out = append(out, flags)
	out = append(out, lenbuf[:]...)
	return append(out, boxed...), nil
}

func sealPayload(p *payload, pub *[32]byte) ([]byte, error) {
	sum, err := digest(p)
	if err != nil {
		return nil, err
	}
	p.SHA256 = sum
	body, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	return crypto.SealAnonymous(body, pub)
}

// Open verifies and decrypts a vault blob using the identity key. It also
// accepts master keys, since a master-sealed copy may be the one that opens.
func Open(data []byte, pub, priv *[32]byte) (*Vault, error) {
	return openWith(data, pub, priv, false)
}

// OpenWithMaster verifies and decrypts the master-sealed copy of a blob. This
// is the cold-recovery entry point: the master key comes from the recovery
// phrase, so it works on a machine with no identity.
func OpenWithMaster(data []byte, masterPub, masterPriv *[32]byte) (*Vault, error) {
	return openWith(data, masterPub, masterPriv, true)
}

func openWith(data []byte, pub, priv *[32]byte, requireMaster bool) (*Vault, error) {
	firstLen, hasMaster, err := framing(data)
	if err != nil {
		return nil, err
	}
	if requireMaster && !hasMaster {
		return nil, ErrNoMasterCopy
	}
	if requireMaster {
		plain, err := openMasterCopy(data, pub, priv)
		if err != nil {
			return nil, err
		}
		return decodePayload(plain, true, nil)
	}
	plain, err := crypto.OpenAnonymous(data[headerLen:headerLen+firstLen], pub, priv)
	if err != nil && hasMaster {
		if master, merr := openMasterCopy(data, pub, priv); merr == nil {
			return decodePayload(master, true, nil)
		}
	}
	if err != nil {
		return nil, fmt.Errorf("failed to open vault blob: %w", err)
	}
	var recoveryBox []byte
	if hasMaster {
		recoveryBox = data[headerLen+firstLen:]
	}
	return decodePayload(plain, hasMaster, recoveryBox)
}

func framing(data []byte) (int, bool, error) {
	if len(data) < headerLen {
		return 0, false, fmt.Errorf("%w: too short", ErrCorrupt)
	}
	if string(data[:7]) != magic {
		return 0, false, fmt.Errorf("%w: bad magic", ErrCorrupt)
	}
	switch data[7] {
	case version:
	case 1:
		return 0, false, ErrLegacyFormat
	default:
		return 0, false, fmt.Errorf("%w: unsupported version %d", ErrCorrupt, data[7])
	}
	flags := data[8]
	if flags & ^byte(flagHasMasterCopy) != 0 {
		return 0, false, ErrCorrupt
	}
	hasMaster := flags&flagHasMasterCopy != 0
	firstLen := int(binary.BigEndian.Uint32(data[headerLen-lenField : headerLen]))
	if firstLen <= 0 || headerLen+firstLen > len(data) {
		return 0, false, fmt.Errorf("%w: bad box framing", ErrCorrupt)
	}
	if !hasMaster && headerLen+firstLen != len(data) {
		return 0, false, fmt.Errorf("%w: trailing data after the sealed box", ErrCorrupt)
	}
	if hasMaster && len(data)-headerLen-firstLen < 48 {
		return 0, false, fmt.Errorf("%w: truncated recovery copy", ErrCorrupt)
	}
	return firstLen, hasMaster, nil
}

// openMasterCopy extracts and decrypts the trailing master-sealed box.
//
// The header records the length of the identity box, so the master box starts
// at a known offset. Sealed boxes are otherwise not self-delimiting: neither
// carries its own length, so locating the second box by trial would mean
// attempting decryption at every offset.
func openMasterCopy(data []byte, pub, priv *[32]byte) ([]byte, error) {
	if len(data) < headerLen || data[8]&flagHasMasterCopy == 0 {
		return nil, fmt.Errorf("no master copy")
	}
	firstLen := int(binary.BigEndian.Uint32(data[headerLen-lenField : headerLen]))
	offset := headerLen + firstLen
	if firstLen <= 0 || offset >= len(data) {
		return nil, fmt.Errorf("%w: bad box framing", ErrCorrupt)
	}
	return crypto.OpenAnonymous(data[offset:], pub, priv)
}

func decodePayload(plain []byte, hasRecovery bool, recoveryBox []byte) (*Vault, error) {
	var p payload
	if err := json.Unmarshal(plain, &p); err != nil {
		return nil, fmt.Errorf("%w: bad payload: %v", ErrCorrupt, err)
	}
	got, err := digest(&p)
	if err != nil {
		return nil, err
	}
	if got != p.SHA256 {
		return nil, fmt.Errorf("%w: inner hash mismatch", ErrCorrupt)
	}
	if p.HasRecovery != hasRecovery {
		return nil, fmt.Errorf("%w: recovery flag mismatch", ErrCorrupt)
	}
	if recoveryBox != nil {
		sum := sha256.Sum256(recoveryBox)
		if p.RecoveryHash != hex.EncodeToString(sum[:]) {
			return nil, fmt.Errorf("%w: recovery ciphertext changed", ErrCorrupt)
		}
	}
	if p.Projects == nil {
		p.Projects = map[string]map[string]string{}
	}
	return &Vault{
		Projects:            p.Projects,
		Files:               p.Files,
		Identity:            p.Identity,
		IdentityFingerprint: p.IdentityFingerprint,
		Generation:          p.Generation,
		CreatedAt:           p.CreatedAt,
	}, nil
}

// writeAtomic writes data to path via a temp file and rename, with mode 0600.
func writeAtomic(path string, data []byte) error {
	return storage.Write(path, data)
}

// Write seals v to recipientPub (and to masterPub when non-nil) and writes it
// atomically to path (0600).
func Write(path string, v *Vault, recipientPub *[32]byte, masterPub *[32]byte) error {
	data, err := Seal(v, recipientPub, masterPub)
	if err != nil {
		return err
	}
	return writeAtomic(path, data)
}

// Read opens the vault blob at path.
func Read(path string, pub, priv *[32]byte) (*Vault, error) {
	data, err := os.ReadFile(path) //nolint:gosec // path is constructed from trusted home dir
	if err != nil {
		return nil, err
	}
	return Open(data, pub, priv)
}

// ReadWithMaster opens the master-sealed copy of the blob at path.
func ReadWithMaster(path string, masterPub, masterPriv *[32]byte) (*Vault, error) {
	data, err := os.ReadFile(path) //nolint:gosec // path is constructed from trusted home dir
	if err != nil {
		return nil, err
	}
	return OpenWithMaster(data, masterPub, masterPriv)
}

// HasMasterCopy reports whether a blob carries a master-sealed copy, and so
// whether it can be opened from the recovery phrase alone.
func HasMasterCopy(data []byte) bool {
	return len(data) >= headerLen && data[8]&flagHasMasterCopy != 0
}

// Exists reports whether a vault blob is present at path.
func Exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
