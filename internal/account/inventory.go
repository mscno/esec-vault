package account

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/mscno/esec-vault/internal/identity"
	"github.com/mscno/esec-vault/internal/keyring"
	"github.com/mscno/esec-vault/internal/keystore"
	"github.com/mscno/esec-vault/internal/paths"
	"github.com/mscno/esec-vault/internal/storage"
	"github.com/mscno/esec-vault/internal/vaultfile"
)

// PendingPath contains one encrypted working revision, never a history of
// local snapshots. It survives network errors and must not be cache-pruned.
func PendingPath() string { return filepath.Join(paths.Home(), "vault-pending.esec") }

// StagingIssue is a metadata-only marker: errors can contain local paths or
// parser input, so the UI reads a fixed explanation rather than error text.
func StagingIssue() bool {
	_, err := os.Stat(filepath.Join(paths.Home(), "vault-staging-failed"))
	return err == nil
}

// CachePolicy controls local project materialization independently of server retention.
type CachePolicy struct {
	Projects map[string]string `json:"projects"`
}

func cachePolicyPath() string { return filepath.Join(paths.Home(), "cache-policy.json") }

// LoadCachePolicy reads and validates this device’s cache preferences.
func LoadCachePolicy() (*CachePolicy, error) {
	p := &CachePolicy{Projects: map[string]string{}}
	b, err := os.ReadFile(cachePolicyPath())
	if errors.Is(err, os.ErrNotExist) {
		return p, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, p); err != nil {
		return nil, errors.New("invalid local cache policy")
	}
	if p.Projects == nil {
		p.Projects = map[string]string{}
	}
	for _, mode := range p.Projects {
		if mode != "offline" && mode != "none" {
			return nil, errors.New("invalid local cache mode")
		}
	}
	return p, nil
}

// Save atomically persists cache preferences.
func (p *CachePolicy) Save() error {
	b, err := json.Marshal(p)
	if err != nil {
		return err
	}
	return storage.Write(cachePolicyPath(), b)
}

func (a *Account) readLocalVault(path string, id *identity.Identity) (*vaultfile.Vault, error) {
	b, err := os.ReadFile(path) //nolint:gosec // fixed internal pending/base paths
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	v, err := vaultfile.Open(b, &a.Device.EncPub, &a.Device.EncPriv)
	if err != nil {
		v, err = vaultfile.Open(b, &id.Public, &id.Private)
	}
	if err != nil {
		return nil, fmt.Errorf("cannot open pending or acknowledged vault data: %w", err)
	}
	return v, nil
}

func keyRecord(project, pub string) string { return project + "/" + strings.ToLower(pub) }

// collectInventory preserves acknowledged records independently of which
// projects this device materializes as keyring files.
func (a *Account) collectInventory(id *identity.Identity, remote *vaultfile.Vault, explicit ...guardIntent) (*vaultfile.Vault, error) {
	base, err := a.readLocalVault(basePath(), id)
	if err != nil {
		return nil, err
	}
	pending, err := a.readLocalVault(PendingPath(), id)
	if err != nil {
		return nil, err
	}
	v := &vaultfile.Vault{Projects: map[string]map[string]string{}, Files: map[string][]byte{}}
	c := v.EnsureCatalog()
	c.User = a.State.User
	for _, source := range []*vaultfile.Vault{base, pending, remote} {
		if source != nil {
			if err := mergeInventorySource(v, source); err != nil {
				return nil, err
			}
		}
	}
	local, err := a.localProjects()
	if err != nil {
		return nil, err
	}
	previous := base
	if pending != nil {
		previous = pending
	}
	for project, entries := range local {
		if v.Projects[project] == nil {
			v.Projects[project] = map[string]string{}
		}
		maps.Copy(v.Projects[project], entries)
		if previous != nil {
			for name, value := range previous.Projects[project] {
				if _, exists := entries[name]; !exists && isAlias(name) {
					recordAlias(c, previous, project, name, value, true)
				}
			}
			for name, value := range entries {
				if previous.Projects[project][name] != value && isAlias(name) {
					recordAlias(c, previous, project, name, value, false)
				}
			}
		}
	}
	profile, err := a.captureProfile()
	if err != nil {
		return nil, err
	}
	c.Profiles[a.State.DeviceID] = profile
	for _, intent := range explicit {
		key := keyRecord(intent.project, intent.pub)
		c.Guards[key] = vaultfile.GuardState{Version: c.Guards[key].Version + 1, Guarded: intent.guarded}
	}
	if err := a.collectArtifacts(v); err != nil {
		return nil, err
	}
	applyDeleted(v)
	return v, nil
}

func sameInventory(a, b *vaultfile.Vault) bool {
	if a == nil || b == nil {
		return false
	}
	left := &vaultfile.Vault{Projects: a.Projects, Files: a.Files, Catalog: a.Catalog}
	right := &vaultfile.Vault{Projects: b.Projects, Files: b.Files, Catalog: b.Catalog}
	x, err := json.Marshal(left)
	if err != nil {
		return false
	}
	y, err := json.Marshal(right)
	return err == nil && bytes.Equal(x, y)
}

// writeLocalVault omits keys deliberately not retained on this device, even
// from the encrypted merge base. They remain in the server's inventory.
func (a *Account) writeLocalVault(path string, v *vaultfile.Vault) error {
	p, err := LoadCachePolicy()
	if err != nil {
		return err
	}
	filtered := *v
	filtered.Projects = maps.Clone(v.Projects)
	var previous *vaultfile.Vault
	if path == PendingPath() {
		id, err := identity.Load(a.KR)
		if err != nil {
			return err
		}
		previous, err = a.readLocalVault(PendingPath(), id)
		if err != nil {
			return err
		}
	}
	for project, mode := range p.Projects {
		if mode == "none" {
			delete(filtered.Projects, project)
			// An explicit import into an uncached project is still pending
			// user data. Keep its local edits until the server acknowledges them.
			if path == PendingPath() {
				entries, err := a.pendingUncachedKeys(v, previous, project)
				if err != nil {
					return err
				}
				if len(entries) > 0 {
					filtered.Projects[project] = entries
				}
			}
		}
	}
	b, err := vaultfile.Seal(&filtered, &a.Device.EncPub, nil)
	if err != nil {
		return err
	}
	return storage.Write(path, b)
}

func (a *Account) pendingUncachedKeys(v, previous *vaultfile.Vault, project string) (map[string]string, error) {
	needed := map[string]string{}
	if previous != nil {
		maps.Copy(needed, previous.Projects[project])
	}
	local, err := a.KS.Read(project)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	maps.Copy(needed, local)
	for name := range needed {
		if value, ok := v.Projects[project][name]; ok {
			needed[name] = value
		} else {
			delete(needed, name)
		}
	}
	return needed, nil
}

// StagePending captures durable encrypted changes before attempting network I/O.
func StagePending(kr keyring.Keyring) error { return StagePendingWithLock(kr, false) }

// StagePendingWithLock reuses a CLI mutation lock when already held.
func StagePendingWithLock(kr keyring.Keyring, keysLocked bool) error {
	a, err := Open(kr, nil)
	if err != nil {
		return err
	}
	a.KeyringLocked = keysLocked
	return a.Locked(a.stagePending)
}

func (a *Account) stagePending() (stageErr error) {
	defer func() {
		path := filepath.Join(paths.Home(), "vault-staging-failed")
		if stageErr != nil {
			_ = storage.Write(path, []byte("Project backup could not be prepared. Run sync to inspect the error.\n"))
		} else {
			_ = os.Remove(path)
		}
	}()
	id, err := identity.Load(a.KR)
	if err != nil {
		return err
	}
	v, err := a.collectInventory(id, nil)
	if err != nil {
		return err
	}
	base, err := a.readLocalVault(basePath(), id)
	if err != nil {
		return err
	}
	if sameInventory(v, base) {
		return clearPending()
	}
	if err := a.writeLocalVault(PendingPath(), v); err != nil {
		return err
	}
	return prunePendingObjects(v, base)
}

func prunePendingObjects(pending, base *vaultfile.Vault) error {
	keep := map[string]bool{}
	if pending != nil && pending.Catalog != nil {
		for id, ref := range pending.Catalog.Artifacts {
			if base != nil && base.Catalog != nil {
				if _, ok := base.Catalog.Artifacts[id]; ok {
					continue
				}
			}
			keep[ref.Object] = true
		}
	}
	dir := filepath.Join(paths.Home(), "pending-objects")
	files, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, file := range files {
		if !file.Type().IsRegular() || len(file.Name()) != 64 || keep[file.Name()] {
			continue
		}
		if err := os.Remove(filepath.Join(dir, file.Name())); err != nil {
			return err
		}
	}
	return nil
}

func applyDeleted(v *vaultfile.Vault) {
	if v.Catalog == nil {
		return
	}
	for project, entries := range v.Projects {
		for name, value := range entries {
			if v.Catalog.Aliases[aliasRecord(project, name, value)].Removed {
				delete(entries, name)
				continue
			}
			if strings.HasPrefix(name, "ESEC_PRIVATE_KEY") && guardedHere(entries, value) {
				delete(entries, name)
				continue
			}
			if pub, err := publicEntry(name, value); err == nil {
				if v.Catalog.Guards[keyRecord(project, pub)].Guarded && strings.HasPrefix(name, "ESEC_PRIVATE_KEY") {
					delete(entries, name)
					continue
				}
				if _, gone := v.Catalog.Deleted[keyRecord(project, pub)]; gone {
					delete(entries, name)
				}
				if _, retired := v.Catalog.Retired[keyRecord(project, pub)]; retired && !keystore.IsPubEntry(name) && !keystore.IsGuardEntry(name) {
					delete(entries, name)
				}
			}
		}
	}
}

func isAlias(name string) bool {
	return (strings.HasPrefix(name, "ESEC_PRIVATE_KEY") && !keystore.IsPubEntry(name)) || strings.HasPrefix(name, keystore.GuardEnvPrefix) || name == "ESEC_ACTIVE_KEY" || name == "ESEC_ACTIVE_ENVIRONMENT"
}

func aliasRecord(project, name, value string) string {
	return project + "\x00" + name + "\x00" + sha([]byte(value))
}

func mergeAlias(states map[string]vaultfile.AliasState, key string, event vaultfile.AliasState) {
	old := states[key]
	if event.Version > old.Version || (event.Version == old.Version && event.Removed) {
		states[key] = event
	}
}

func recordAlias(c *vaultfile.Catalog, base *vaultfile.Vault, project, name, value string, removed bool) {
	key := aliasRecord(project, name, value)
	var version uint64
	if base.Catalog != nil {
		version = base.Catalog.Aliases[key].Version
	}
	mergeAlias(c.Aliases, key, vaultfile.AliasState{Version: version + 1, Removed: removed})
}

type guardIntent struct {
	project, pub string
	guarded      bool
}

// RecordGuardChange is called only after an explicit guard operation has
// successfully opened and resealed the key. Scanning never grants unguarded access.
func (a *Account) RecordGuardChange(project, pub string, guarded bool) error {
	return a.Locked(func() error {
		id, err := identity.Load(a.KR)
		if err != nil {
			return err
		}
		v, err := a.collectInventory(id, nil, guardIntent{project: project, pub: pub, guarded: guarded})
		if err != nil {
			return err
		}
		// Re-read after the explicit unguard so the staged inventory retains
		// the newly cached key that collectInventory previously filtered out.
		if !guarded {
			entries, err := a.KS.Read(project)
			if err != nil {
				return err
			}
			v.Projects[project] = entries
		}
		applyDeleted(v)
		return a.writeLocalVault(PendingPath(), v)
	})
}

func publicEntry(name, value string) (string, error) {
	if keystore.IsGuardEntry(name) {
		return strings.ToLower(strings.TrimPrefix(name, "ESEC_GUARD_")), nil
	}
	if strings.HasPrefix(name, keystore.GuardEnvPrefix) && len(value) == 64 {
		return strings.ToLower(value), nil
	}
	return keystore.PublicHex(value)
}

func (a *Account) saveBase(blob []byte, id *identity.Identity) error {
	v, err := vaultfile.Open(blob, &id.Public, &id.Private)
	if err != nil {
		return err
	}
	return a.writeLocalVault(basePath(), v)
}

func mergeInventorySource(v, source *vaultfile.Vault) error {
	c := v.EnsureCatalog()
	for project, entries := range source.Projects {
		if v.Projects[project] == nil {
			v.Projects[project] = map[string]string{}
		}
		maps.Copy(v.Projects[project], entries)
	}
	maps.Copy(v.Files, source.Files)
	if source.Catalog == nil {
		return nil
	}
	maps.Copy(c.Profiles, source.Catalog.Profiles)
	for key, event := range source.Catalog.Aliases {
		mergeAlias(c.Aliases, key, event)
	}
	for k, capture := range source.Catalog.Captures {
		if old, ok := c.Captures[k]; ok && !reflect.DeepEqual(old, capture) {
			return errors.New("conflicting immutable project revision")
		}
		c.Captures[k] = capture
	}
	for k, artifact := range source.Catalog.Artifacts {
		if old, ok := c.Artifacts[k]; ok && !reflect.DeepEqual(old, artifact) {
			return errors.New("conflicting immutable file revision")
		}
		c.Artifacts[k] = artifact
	}
	maps.Copy(c.Deleted, source.Catalog.Deleted)
	maps.Copy(c.Retired, source.Catalog.Retired)
	for key, event := range source.Catalog.Guards {
		old := c.Guards[key]
		if event.Version > old.Version || (event.Version == old.Version && event.Guarded) {
			c.Guards[key] = event
		}
	}
	return nil
}

func (a *Account) captureProfile() (vaultfile.Profile, error) {
	profile := vaultfile.Profile{Name: a.State.DeviceName, UID: uint32(os.Getuid()), Settings: map[string][]byte{}} //nolint:gosec // platform uid fits the schema
	for _, name := range []string{"policy.toml", "trusted.toml"} {
		b, err := os.ReadFile(filepath.Join(paths.Home(), name)) //nolint:gosec // two fixed settings names
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return vaultfile.Profile{}, err
		}
		if len(b) > 1<<20 {
			return vaultfile.Profile{}, errors.New("vault settings file exceeds 1 MiB")
		}
		profile.Settings[name] = b
	}
	return profile, nil
}
