package keystore

import (
	"errors"
	"fmt"
	"os"
)

// RenameEnv moves only mutable names, retaining immutable public-key records.
// A dry run checks collisions before a remote rename; retries are safe.
func (s *Store) RenameEnv(project, old, next, public string, dry bool) error {
	entries, err := s.Read(project)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	pairs := [][2]string{{EnvEntry(old), EnvEntry(next)}, {GuardEnvEntry(old), GuardEnvEntry(next)}}
	for i, pair := range pairs {
		if pair[0] == pair[1] {
			return fmt.Errorf("environment names map to the same keyring entry")
		}
		if value, ok := entries[pair[0]]; ok {
			if err := checkRenameKey(value, public, i == 1); err != nil {
				return err
			}
		}
		if value, ok := entries[pair[1]]; ok {
			if _, oldExists := entries[pair[0]]; oldExists || dry {
				return fmt.Errorf("destination keyring entry %s exists", pair[1])
			}
			if err := checkRenameKey(value, public, i == 1); err != nil {
				return err
			}
		}
	}
	changed := false
	for _, pair := range pairs {
		if value, ok := entries[pair[0]]; ok {
			entries[pair[1]] = value
			delete(entries, pair[0])
			changed = true
		}
	}
	if dry || !changed {
		return nil
	}
	return s.Write(project, entries, true)
}

func checkRenameKey(value, public string, guarded bool) error {
	if public == "" {
		return nil
	}
	pub := value
	if !guarded {
		var err error
		pub, err = PublicHex(value)
		if err != nil {
			return err
		}
	}
	if pub != public {
		return fmt.Errorf("named keyring entry differs from the environment key; sync or repair it first")
	}
	return nil
}
