package account

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/mscno/esec-vault/internal/paths"
	"github.com/mscno/esec-vault/internal/policy"
	"github.com/mscno/esec-vault/internal/storage"
	"github.com/mscno/esec-vault/internal/vaultfile"
	"github.com/pelletier/go-toml/v2"
)

// RestoreProfile is explicit: a new machine never silently inherits a policy
// that grants access to a numeric uid belonging to somebody else there.
func (a *Account) RestoreProfile(ctx context.Context, profile string, mapUser, replace bool) error {
	return a.Locked(func() error {
		v, err := a.readVault(ctx)
		if err != nil {
			return err
		}
		return RestoreProfileArchive(v, profile, mapUser, replace)
	})
}

// RestoreProfileArchive restores reviewed settings from an opened recovery export.
func RestoreProfileArchive(v *vaultfile.Vault, profile string, mapUser, replace bool) error {
	if v.Catalog == nil {
		return errors.New("no device settings have been backed up")
	}
	p, ok := v.Catalog.Profiles[profile]
	if !ok {
		return errors.New("unknown device profile")
	}
	prepared := map[string][]byte{}
	for name, b := range p.Settings {
		if name != "policy.toml" && name != "trusted.toml" {
			return errors.New("unsupported settings file")
		}
		var raw map[string]any
		if err := toml.Unmarshal(b, &raw); err != nil {
			return errors.New("invalid backed-up settings")
		}
		if name == "policy.toml" {
			preparedPolicy, err := mapProfilePolicy(b, p.UID, mapUser)
			if err != nil {
				return err
			}
			b = preparedPolicy
		}
		if _, err := os.Lstat(filepath.Join(paths.Home(), name)); err == nil && !replace {
			return errors.New("settings already exist; use --replace after reviewing the source profile")
		} else if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		prepared[name] = b
	}
	for name, b := range prepared {
		if err := storage.Write(filepath.Join(paths.Home(), name), b); err != nil {
			return err
		}
	}
	return nil
}

func mapProfilePolicy(b []byte, owner uint32, mapUser bool) ([]byte, error) {
	var rules policy.Policy
	if err := toml.Unmarshal(b, &rules); err != nil {
		return nil, errors.New("invalid backed-up policy")
	}
	for i, r := range rules.Rules {
		if r.UID == nil {
			continue
		}
		uid := uint32(os.Getuid()) //nolint:gosec // platform uid
		if *r.UID == owner && *r.UID != uid {
			if !mapUser {
				return nil, errors.New("this profile uses another local uid; review it and use --map-user to map its owner to you")
			}
			rules.Rules[i].UID = &uid
		}
		if *r.UID != owner {
			return nil, fmt.Errorf("policy includes another user's uid %d; restore and review this rule manually", *r.UID)
		}
	}
	encoded, err := toml.Marshal(rules)
	if err != nil {
		return nil, err
	}
	return encoded, nil
}
