package identity

import (
	"encoding/hex"
	"errors"
	"os"

	"github.com/mscno/esec-vault/internal/keyring"
	"github.com/mscno/esec-vault/internal/paths"
	"github.com/mscno/esec-vault/internal/storage"
)

func commit(kr keyring.Keyring, id *Identity, master *[32]byte) error {
	body, err := Wrapped(id, master, id.PassphraseProtected)
	if err != nil {
		return err
	}
	return commitWrapped(kr, id, body)
}

// commitWrapped stores id in the keyring and wrapped as identity.esec. The
// previous identity file is kept as identity.esec.previous, and keyring
// entries are rolled back if any step fails.
func commitWrapped(kr keyring.Keyring, id *Identity, wrapped []byte) error {
	names := []string{keyring.IdentityPrivateKey, keyring.IdentityPublicKey, keyring.IdentitySignPrivateKey}
	old := map[string]string{}
	for _, name := range names {
		v, err := kr.Get(name)
		if err != nil && !errors.Is(err, keyring.ErrNotFound) {
			return err
		}
		old[name] = v
	}
	raw, err := os.ReadFile(paths.IdentityFile())
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if len(raw) > 0 {
		if err := storage.Write(paths.IdentityFile()+".previous", raw); err != nil {
			return err
		}
		// Also keep each replaced identity under its own fingerprint, and
		// never overwrite such a copy: backups and shares sealed to an old
		// identity stay recoverable with its recovery phrase.
		if h, _, err := decodeHeader(raw); err == nil && h.IdentityPublic != id.Public {
			keep := paths.IdentityFile() + ".previous-" + ShortFingerprint(Fingerprint(h.IdentityPublic))
			if _, err := os.Stat(keep); errors.Is(err, os.ErrNotExist) {
				if err := storage.Write(keep, raw); err != nil {
					return err
				}
			}
		}
	}
	rollback := func() error {
		var errs []error
		for k, v := range old {
			if v == "" {
				errs = append(errs, kr.Delete(k))
			} else {
				errs = append(errs, kr.Set(k, v))
			}
		}
		return errors.Join(errs...)
	}
	next := map[string]string{
		keyring.IdentityPrivateKey: hex.EncodeToString(id.Private[:]),
		keyring.IdentityPublicKey:  id.PublicHex(),
	}
	if id.Sign != nil {
		next[keyring.IdentitySignPrivateKey] = hex.EncodeToString(id.Sign.Seed())
	}
	for _, name := range names {
		v, ok := next[name]
		var err error
		if ok {
			err = kr.Set(name, v)
		} else {
			err = kr.Delete(name)
		}
		if err != nil {
			return errors.Join(err, rollback())
		}
	}
	if err := storage.Write(paths.IdentityFile(), wrapped); err != nil {
		return errors.Join(err, rollback())
	}
	return nil
}
