// Package vaultfile implements the sealed vault blob format: an encrypted
// backup of every keyring, sealed to the owner's identity key.
//
// Layout on disk (multi-byte fields little-endian):
//
//	magic "ESECVLT" | version byte (1) | timestamp unix64 | sealed box of JSON
//
// The sealed JSON contains the keyring index plus an inner SHA-256 of the
// canonical projects JSON, so truncation/bit flips are detected even beyond
// the box's Poly1305 authentication.
package vaultfile

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/mscno/esec/pkg/crypto"
)

const (
	magic   = "ESECVLT"
	version = 1
)

// headerLen = len(magic) + 1 (version) + 8 (timestamp)
const headerLen = 7 + 1 + 8

// Vault is the decrypted content of a vault blob: project identifier →
// keyring entries (e.g. ESEC_PRIVATE_KEY_DEV → hex key).
type Vault struct {
	Projects map[string]map[string]string `json:"projects"`
}

type payload struct {
	Projects map[string]map[string]string `json:"projects"`
	SHA256   string                       `json:"sha256"`
}

// ErrCorrupt is returned when a vault blob fails structural or integrity
// checks.
var ErrCorrupt = errors.New("vault blob is corrupt")

func canonical(projects map[string]map[string]string) ([]byte, error) {
	// encoding/json marshals maps with sorted keys, so this is canonical.
	return json.Marshal(projects)
}

// Seal serializes v and seals it to recipientPub.
func Seal(v *Vault, ts time.Time, recipientPub *[32]byte) ([]byte, error) {
	if v == nil {
		v = &Vault{}
	}
	if v.Projects == nil {
		v.Projects = map[string]map[string]string{}
	}
	inner, err := canonical(v.Projects)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(inner)
	p, err := json.Marshal(payload{Projects: v.Projects, SHA256: hex.EncodeToString(sum[:])})
	if err != nil {
		return nil, err
	}
	boxed, err := crypto.SealAnonymous(p, recipientPub)
	if err != nil {
		return nil, err
	}

	out := make([]byte, 0, headerLen+len(boxed))
	out = append(out, magic...)
	out = append(out, version)
	var tsbuf [8]byte
	unix := ts.Unix()
	if unix < 0 {
		return nil, fmt.Errorf("vault timestamp before epoch")
	}
	binary.LittleEndian.PutUint64(tsbuf[:], uint64(unix))
	out = append(out, tsbuf[:]...)
	return append(out, boxed...), nil
}

// Open verifies and decrypts a vault blob.
func Open(data []byte, pub, priv *[32]byte) (*Vault, error) {
	if len(data) < headerLen {
		return nil, fmt.Errorf("%w: too short", ErrCorrupt)
	}
	if string(data[:7]) != magic {
		return nil, fmt.Errorf("%w: bad magic", ErrCorrupt)
	}
	if data[7] != version {
		return nil, fmt.Errorf("%w: unsupported version %d", ErrCorrupt, data[7])
	}
	// Timestamp is informational; ignore it for now.

	plain, err := crypto.OpenAnonymous(data[headerLen:], pub, priv)
	if err != nil {
		return nil, fmt.Errorf("failed to open vault blob: %w", err)
	}
	var p payload
	if err := json.Unmarshal(plain, &p); err != nil {
		return nil, fmt.Errorf("%w: bad payload: %v", ErrCorrupt, err)
	}
	inner, err := canonical(p.Projects)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCorrupt, err)
	}
	sum := sha256.Sum256(inner)
	if hex.EncodeToString(sum[:]) != p.SHA256 {
		return nil, fmt.Errorf("%w: inner hash mismatch", ErrCorrupt)
	}
	return &Vault{Projects: p.Projects}, nil
}

// Write seals v to recipientPub and writes it atomically to path (0600).
func Write(path string, v *Vault, ts time.Time, recipientPub *[32]byte) error {
	data, err := Seal(v, ts, recipientPub)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".vault-*.tmp")
	if err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
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
	return os.Rename(tmp.Name(), path)
}

// Read opens the vault blob at path.
func Read(path string, pub, priv *[32]byte) (*Vault, error) {
	data, err := os.ReadFile(path) //nolint:gosec // path is constructed from trusted home dir
	if err != nil {
		return nil, err
	}
	return Open(data, pub, priv)
}
