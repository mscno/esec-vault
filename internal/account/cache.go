package account

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"os"
	"reflect"
	"strings"

	"github.com/mscno/esec-vault/internal/identity"
	"github.com/mscno/esec-vault/internal/keystore"
	"github.com/mscno/esec-vault/internal/vaultfile"
	"github.com/mscno/esec/pkg/projectfile"
)

// ReadVault returns authenticated account data without materializing keys.
func (a *Account) ReadVault(ctx context.Context) (*vaultfile.Vault, error) {
	var v *vaultfile.Vault
	err := a.Locked(func() error { var err error; v, err = a.readVault(ctx); return err })
	return v, err
}

func (a *Account) readVault(ctx context.Context) (*vaultfile.Vault, error) {
	st, err := a.VerifiedChain(ctx)
	if err != nil {
		return nil, err
	}
	id, err := a.userKey(ctx, st)
	if err != nil {
		return nil, err
	}
	r, err := a.Client.Vault(ctx)
	if err != nil {
		return nil, err
	}
	v, err := a.openRemote(st, id, r)
	if err != nil {
		return nil, err
	}
	a.State.pin(st)
	return v, a.State.Save()
}

// CachedVault is the last acknowledged device-encrypted manifest. It omits
// evicted keys, and is explicitly labelled stale when used while offline.
func (a *Account) CachedVault() (*vaultfile.Vault, error) {
	id, err := identity.Load(a.KR)
	if err != nil {
		return nil, err
	}
	v, err := a.readLocalVault(basePath(), id)
	if err == nil && v == nil {
		return nil, errors.New("no acknowledged vault cached on this device")
	}
	return v, err
}

// CacheProject changes only this device's materialization policy. Eviction is
// allowed only after a successful server acknowledgement of all local changes.
func (a *Account) CacheProject(ctx context.Context, project, mode string) error {
	if err := projectfile.ValidateOrgRepo(project); err != nil {
		return err
	}
	if mode != "offline" && mode != "none" {
		return errors.New("cache mode must be offline or none")
	}
	return a.Locked(func() error {
		if _, err := a.sync(ctx, SyncOptions{}); err != nil {
			return fmt.Errorf("sync before changing cache: %w", err)
		}
		v, err := a.readVault(ctx)
		if err != nil {
			return err
		}
		if _, ok := v.Projects[project]; !ok {
			return errors.New("project is not stored in the server vault")
		}
		p, err := LoadCachePolicy()
		if err != nil {
			return err
		}
		p.Projects[project] = mode
		if err := p.Save(); err != nil {
			return err
		}
		if mode == "none" {
			if err := a.KS.Delete(project); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
		} else {
			if _, _, err := a.merge(map[string]map[string]string{project: v.Projects[project]}, nil, false); err != nil {
				return err
			}
		}
		return a.writeLocalVault(basePath(), v)
	})
}

// ExportProject returns a conventional standalone keyring. Guarded material
// is excluded, including stale clear copies of a guarded private key.
func (a *Account) ExportProject(ctx context.Context, project string) (map[string]string, error) {
	v, err := a.ReadVault(ctx)
	if err != nil {
		return nil, err
	}
	entries, ok := v.Projects[project]
	if !ok {
		return nil, errors.New("project is not in the server vault")
	}
	applyDeleted(v)
	out := map[string]string{}
	for name, value := range entries {
		if !strings.HasPrefix(name, "ESEC_PRIVATE_KEY") || guardedHere(entries, value) {
			continue
		}
		if _, err := keystore.PublicHex(value); err != nil {
			continue
		}
		out[name] = value
	}
	if len(out) == 0 {
		return nil, errors.New("no exportable local keys; guarded keys stay sealed")
	}
	return out, nil
}

// ChangeKey records a retirement or permanent tombstone by public key. Old
// devices cannot resurrect a tombstoned key during a later merge.
func (a *Account) ChangeKey(ctx context.Context, project, pub string, deleted bool) error {
	if err := projectfile.ValidateOrgRepo(project); err != nil {
		return err
	}
	if len(pub) != 64 || !keystore.IsPubEntry(keystore.PubEntry(pub)) {
		return errors.New("expected a 64-character public key")
	}
	return a.Locked(func() error {
		if _, err := a.sync(ctx, SyncOptions{}); err != nil {
			return err
		}
		v, err := a.readVault(ctx)
		if err != nil {
			return err
		}
		found := false
		for name, value := range v.Projects[project] {
			if key, e := publicEntry(name, value); e == nil && strings.EqualFold(key, pub) {
				found = true
			}
		}
		if !found {
			return errors.New("key not found in the server vault")
		}
		c := v.EnsureCatalog()
		record := keyRecord(project, pub)
		if deleted {
			c.Deleted[record] = a.Now()
		} else {
			c.Retired[record] = a.Now()
		}
		applyDeleted(v)
		if err := a.writeLocalVault(PendingPath(), v); err != nil {
			return err
		}
		if err := a.applyKeyState(v); err != nil {
			return err
		}
		_, err = a.sync(ctx, SyncOptions{})
		return err
	})
}

func (a *Account) applyKeyState(v *vaultfile.Vault) error {
	if v.Catalog == nil {
		return nil
	}
	projects, err := a.KS.List()
	if err != nil {
		return err
	}
	for _, project := range projects {
		entries, err := a.KS.Read(project)
		if err != nil {
			return err
		}
		filtered := maps.Clone(entries)
		applyDeleted(&vaultfile.Vault{Projects: map[string]map[string]string{project: filtered}, Catalog: v.Catalog})
		if !reflect.DeepEqual(filtered, entries) {
			if err := a.KS.Reconcile(project, filtered); err != nil {
				return err
			}
		}
	}
	return nil
}

// LocalInventory is for diagnostics and explicit exports; it never fetches
// new data or recreates intentionally evicted keyrings.
func (a *Account) LocalInventory() (*vaultfile.Vault, error) {
	id, err := identity.Load(a.KR)
	if err != nil {
		return nil, err
	}
	return a.collectInventory(id, nil)
}
