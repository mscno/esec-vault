package client

import (
	"context"
	"net/http"
	"net/url"

	"github.com/mscno/esec-vault/internal/envelope"
	"github.com/mscno/esec-vault/internal/wire"
)

// RequestTransfer publishes a source-signed offer with encrypted key delivery.
func (c *Client) RequestTransfer(ctx context.Context, e *envelope.Envelope) (string, error) {
	var out struct {
		ID string `json:"id"`
	}
	err := c.do(ctx, http.MethodPost, "/v1/transfers", authenticated, &wire.TransferRequest{Offer: e}, &out)
	return out.ID, err
}

// Transfers lists pending incoming and outgoing offers.
func (c *Client) Transfers(ctx context.Context) ([]wire.TransferSummary, error) {
	var out []wire.TransferSummary
	err := c.do(ctx, http.MethodGet, "/v1/transfers", authenticated, nil, &out)
	return out, err
}

// Transfer reads an offer and its verifying chains, without decrypting keys.
func (c *Client) Transfer(ctx context.Context, id string) (*wire.TransferView, error) {
	var out wire.TransferView
	return &out, c.do(ctx, http.MethodGet, "/v1/transfers/"+url.PathEscape(id), authenticated, nil, &out)
}

// AcceptTransfer countersigns and atomically completes a pending offer.
func (c *Client) AcceptTransfer(ctx context.Context, id string, init *envelope.Envelope) error {
	return c.do(ctx, http.MethodPost, "/v1/transfers/"+url.PathEscape(id)+"/accept", authenticated, &wire.TransferAccept{Init: init}, nil)
}

// CancelTransfer rejects or withdraws an offer without changing projects.
func (c *Client) CancelTransfer(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodPost, "/v1/transfers/"+url.PathEscape(id)+"/cancel", authenticated, nil, nil)
}
