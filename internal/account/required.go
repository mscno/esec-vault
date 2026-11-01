package account

import (
	"fmt"

	"github.com/mscno/esec-vault/internal/devicekey"
	"github.com/mscno/esec-vault/internal/keyring"
)

// RequireLogin checks the persisted enrollment and session without a network
// round trip. Server requests still verify session expiry and revocation.
func RequireLogin(kr keyring.Keyring) error {
	st, err := LoadState()
	if err != nil {
		return err
	}
	if st.Chain.Root == "" {
		return ErrUnconfirmed
	}
	if _, err := devicekey.Load(kr); err != nil {
		return fmt.Errorf("vault device unavailable; run 'esec vault login': %w", err)
	}
	token, err := kr.Get(SessionTokenName)
	if err != nil || token == "" {
		return ErrNotLoggedIn
	}
	return nil
}
