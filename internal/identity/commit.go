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
	old, err := kr.Get(keyring.IdentityPrivateKey)
	if err != nil && !errors.Is(err, keyring.ErrNotFound) {
		return err
	}
	oldPub, err := kr.Get(keyring.IdentityPublicKey)
	if err != nil && !errors.Is(err, keyring.ErrNotFound) {
		return err
	}
	raw, err := os.ReadFile(paths.IdentityFile())
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if len(raw) > 0 {
		if err := storage.Write(paths.IdentityFile()+".previous", raw); err != nil {
			return err
		}
	}
	rollback := func() error {
		var errs []error
		for k, v := range map[string]string{keyring.IdentityPrivateKey: old, keyring.IdentityPublicKey: oldPub} {
			if v == "" {
				errs = append(errs, kr.Delete(k))
			} else {
				errs = append(errs, kr.Set(k, v))
			}
		}
		return errors.Join(errs...)
	}
	if err := kr.Set(keyring.IdentityPrivateKey, hex.EncodeToString(id.Private[:])); err != nil {
		return err
	}
	if err := kr.Set(keyring.IdentityPublicKey, id.PublicHex()); err != nil {
		return errors.Join(err, rollback())
	}
	if err := writeWrapped(id, master, id.PassphraseProtected); err != nil {
		return errors.Join(err, rollback())
	}
	return nil
}
