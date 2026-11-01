// Package snapshot creates local encrypted exports. The vault server is the only sync destination.
package snapshot

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"time"

	"github.com/mscno/esec-vault/internal/identity"
	"github.com/mscno/esec-vault/internal/keystore"
	"github.com/mscno/esec-vault/internal/paths"
	"github.com/mscno/esec-vault/internal/storage"
	"github.com/mscno/esec-vault/internal/vaultfile"
)

// Snapshot contains the exact persisted encrypted generation.
type Snapshot struct {
	Blob        []byte
	Generation  uint64
	Fingerprint string
	CreatedAt   time.Time
	Projects    int
}

// BuildSnapshot snapshots current keyrings and recovery material. Unchanged
// content reuses the exact ciphertext; changed content creates a new generation.
// Only the recovery PUBLIC key is needed, so this works unattended.
func BuildSnapshot(id *identity.Identity, ks *keystore.Store) (*Snapshot, error) {
	unlock, err := storage.LockWait(paths.Home(), 30*time.Second, nil)
	if err != nil {
		return nil, err
	}
	defer unlock()
	if !ks.Locked {
		unlockKeys, err := storage.LockWait(ks.Dir, 30*time.Second, nil)
		if err != nil {
			return nil, err
		}
		defer unlockKeys()
	}
	v, master, err := collect(id, ks)
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(paths.VaultFile())
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if err == nil {
		old, openErr := vaultfile.Open(raw, &id.Public, &id.Private)
		if openErr != nil {
			return nil, fmt.Errorf("existing backup cannot be opened; move it aside before creating a replacement: %w", openErr)
		}
		if reflect.DeepEqual(old.Projects, v.Projects) && reflect.DeepEqual(old.Files, v.Files) && bytes.Equal(old.Identity, v.Identity) && old.IdentityFingerprint == v.IdentityFingerprint {
			return snapshot(old, raw), nil
		}
		v.Generation = old.Generation + 1
		if v.Generation == 0 {
			return nil, fmt.Errorf("generation overflow")
		}
	}
	if v.Generation == 0 {
		v.Generation = 1
	}
	v.CreatedAt = time.Now().UTC()
	raw, err = vaultfile.Seal(v, &id.Public, master)
	if err != nil {
		return nil, err
	}
	if _, err := vaultfile.Open(raw, &id.Public, &id.Private); err != nil {
		return nil, err
	}
	// Retain a local history as well as the current generation.
	archive := filepath.Join(paths.Home(), "snapshots", filepath.Base(GenerationName(v.CreatedAt, v.Generation, v.IdentityFingerprint)))
	if err := storage.Write(archive, raw); err != nil {
		return nil, err
	}
	if err := storage.Write(paths.VaultFile(), raw); err != nil {
		return nil, err
	}
	return snapshot(v, raw), nil
}

func snapshot(v *vaultfile.Vault, raw []byte) *Snapshot {
	return &Snapshot{Blob: raw, Generation: v.Generation, Fingerprint: v.IdentityFingerprint, CreatedAt: v.CreatedAt, Projects: len(v.Projects)}
}

func collect(id *identity.Identity, ks *keystore.Store) (*vaultfile.Vault, *[32]byte, error) {
	wrapped, master, err := identity.BackupMaterial(id)
	if err != nil {
		return nil, nil, err
	}
	v := &vaultfile.Vault{Projects: map[string]map[string]string{}, Identity: wrapped, IdentityFingerprint: id.Fingerprint()}
	projects, err := ks.List()
	if err != nil {
		return nil, nil, err
	}
	for _, project := range projects {
		entries, err := ks.Read(project)
		if err != nil {
			return nil, nil, err
		}
		v.Projects[project] = entries
	}
	for _, name := range []string{"policy.toml", "trusted.toml"} {
		data, err := os.ReadFile(filepath.Join(paths.Home(), name)) //nolint:gosec // fixed allowlist under configured home
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, nil, err
		}
		if v.Files == nil {
			v.Files = map[string][]byte{}
		}
		v.Files[name] = data
	}
	return v, master, nil
}

// GenerationName names a retained local encrypted snapshot.
func GenerationName(ts time.Time, generation uint64, fingerprint string) string {
	return fmt.Sprintf("vaults/%s-gen%020d-%s.esec", ts.UTC().Format("20060102T150405.000000000Z"), generation, fingerprint)
}
