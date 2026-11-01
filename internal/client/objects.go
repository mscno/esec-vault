package client

import (
	"context"
	"net/http"
	"net/url"

	"github.com/mscno/esec-vault/internal/wire"
)

// PutVaultObject uploads immutable account-scoped ciphertext.
func (c *Client) PutVaultObject(ctx context.Context, id string, blob []byte) error {
	return c.do(ctx, http.MethodPut, "/v1/vault/objects/"+url.PathEscape(id), authenticated, wire.VaultObject{Blob: blob}, nil)
}

// VaultObject retrieves ciphertext belonging to the authenticated account.
func (c *Client) VaultObject(ctx context.Context, id string) ([]byte, error) {
	var out wire.VaultObject
	err := c.do(ctx, http.MethodGet, "/v1/vault/objects/"+url.PathEscape(id), authenticated, nil, &out)
	return out.Blob, err
}
