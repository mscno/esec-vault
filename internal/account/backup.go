package account

import (
	"context"
	"crypto/ed25519"
	"errors"

	"github.com/mscno/esec-vault/internal/wire"
)

// Backup downloads the personal vault and verifies its signature against the
// pinned account chain. Opening its recovery copy still requires the phrase.
func (a *Account) Backup(ctx context.Context) ([]byte, error) {
	if err := a.requireConfirmed(); err != nil {
		return nil, err
	}
	st, err := a.VerifiedChain(ctx)
	if err != nil {
		return nil, err
	}
	v, err := a.Client.Vault(ctx)
	if err != nil {
		return nil, err
	}
	if !ed25519.Verify(st.SignPub, wire.VaultMessage(a.State.User, v.Blob), v.Sig) {
		return nil, errors.New("vault server backup signature does not match the verified account")
	}
	return v.Blob, nil
}
