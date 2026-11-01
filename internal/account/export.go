package account

import (
	"context"
	"errors"

	"github.com/mscno/esec-vault/internal/identity"
	"github.com/mscno/esec-vault/internal/vaultfile"
)

// RecoveryExport is an explicit portable export, including file objects.
// Automatic operation keeps only a device-encrypted pending revision/cache.
func (a *Account) RecoveryExport(ctx context.Context) ([]byte, error) {
	var data []byte
	err := a.Locked(func() error { var err error; data, err = a.recoveryExport(ctx); return err })
	return data, err
}

func (a *Account) recoveryExport(ctx context.Context) ([]byte, error) {
	v, err := a.readVault(ctx)
	if err != nil {
		return nil, err
	}
	id, err := identity.Load(a.KR)
	if err != nil {
		return nil, err
	}
	h, err := identity.ReadHeader(v.Identity)
	if err != nil {
		return nil, err
	}
	v.Objects = map[string][]byte{}
	total := 0
	if v.Catalog != nil {
		for _, ref := range v.Catalog.Artifacts {
			if _, ok := v.Objects[ref.Object]; ok {
				continue
			}
			b, err := a.Client.VaultObject(ctx, ref.Object)
			if err != nil {
				return nil, err
			}
			if digestBytes(b) != ref.Object {
				return nil, errors.New("server archive digest mismatch")
			}
			total += len(b)
			if total > 256<<20 {
				return nil, errors.New("portable export exceeds 256 MiB; restore projects separately")
			}
			v.Objects[ref.Object] = b
		}
	}
	if _, err := a.VerifyArchive(ctx, v); err != nil {
		return nil, err
	}
	return vaultfile.Seal(v, &id.Public, &h.MasterPublic)
}

// VerifyArchive authenticates every archived object and complete-capture
// reference without writing files or opening inner guarded keys.
func (a *Account) VerifyArchive(ctx context.Context, v *vaultfile.Vault) (int, error) {
	if v.Catalog == nil {
		return 0, nil
	}
	for _, capture := range v.Catalog.Captures {
		for path, id := range capture.Files {
			ref, ok := v.Catalog.Artifacts[id]
			if !ok || ref.Path != path || ref.Project != capture.Project || ref.Checkout != capture.Checkout {
				return 0, errors.New("invalid project revision reference")
			}
		}
	}
	count := 0
	for _, ref := range v.Catalog.Artifacts {
		if _, err := a.openArtifact(ctx, ref, v.Objects); err != nil {
			return count, err
		}
		count++
	}
	return count, nil
}

// RestoreProjectArchive also works offline after recovering an exported
// identity. Its manifest carries the account used to authenticate file objects.
func RestoreProjectArchive(v *vaultfile.Vault, project, origin, dest string, revision ...string) error {
	if v.Catalog == nil || v.Catalog.User == "" {
		return errors.New("export has no project archive")
	}
	a := &Account{State: &State{User: v.Catalog.User}}
	return a.restoreProject(context.Background(), v, project, origin, dest, revision...)
}
