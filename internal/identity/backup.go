package identity

import (
	"fmt"
	"os"

	"github.com/mscno/esec-vault/internal/paths"
)

type wrappedPayload struct {
	Header  fileHeader `json:"header"`
	Private [32]byte   `json:"private"`
}

// BackupMaterial returns the existing encrypted identity and recovery public
// key. No recovery secret is required for unattended encryption.
func BackupMaterial(id *Identity) ([]byte, *[32]byte, error) {
	raw, err := os.ReadFile(paths.IdentityFile())
	if err != nil {
		return nil, nil, err
	}
	h, _, err := decodeHeader(raw)
	if err != nil {
		return nil, nil, fmt.Errorf("identity needs migration: %w", err)
	}
	if h.IdentityPublic != id.Public {
		return nil, nil, fmt.Errorf("wrapped identity does not match keychain identity")
	}
	return raw, &h.MasterPublic, nil
}
