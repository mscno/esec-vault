// Package client calls the esec vault server API. Every authenticated request
// is signed with the device key (package apisig); the client refuses
// redirects so credentials are never replayed to another URL.
package client

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/mscno/esec-vault/internal/apisig"
	"github.com/mscno/esec-vault/internal/envelope"
	"github.com/mscno/esec-vault/internal/safetext"
	"github.com/mscno/esec-vault/internal/wire"
)

// Client is an API client for one server.
type Client struct {
	Base     string
	HTTP     *http.Client
	DeviceID string
	Key      ed25519.PrivateKey
	Token    string
	Now      func() time.Time
}

// APIError is a structured error returned by the server.
type APIError struct {
	Status      int
	Code        string
	Description string
}

func (e *APIError) Error() string {
	if e.Description != "" {
		return fmt.Sprintf("server: %s (%s)", safetext.Clean(e.Description), safetext.Clean(e.Code))
	}
	return fmt.Sprintf("server: HTTP %d %s", e.Status, safetext.Clean(e.Code))
}

// IsCode reports whether err is an APIError with the given code.
func IsCode(err error, code string) bool {
	var ae *APIError
	return errors.As(err, &ae) && ae.Code == code
}

// ValidateBase checks a server origin: https, or http on loopback only.
func ValidateBase(raw string) (string, error) {
	raw = strings.TrimRight(strings.TrimSpace(raw), "/")
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("server must be an origin such as https://vault.example.com")
	}
	host := u.Hostname()
	loopback := host == "localhost" || host == "127.0.0.1" || host == "::1"
	if u.Scheme != "https" && (u.Scheme != "http" || !loopback) {
		return "", fmt.Errorf("server must use https (http is allowed only for localhost)")
	}
	return u.Scheme + "://" + u.Host, nil
}

// New returns a client for base.
func New(base string) (*Client, error) {
	b, err := ValidateBase(base)
	if err != nil {
		return nil, err
	}
	return &Client{
		Base: b,
		HTTP: &http.Client{
			Timeout: 60 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		Now: time.Now,
	}, nil
}

type mode int

const (
	unsigned mode = iota
	signedOnly
	authenticated
)

// RegisterDevice starts the device authorization grant.
func (c *Client) RegisterDevice(ctx context.Context, req wire.DeviceRegisterRequest) (*wire.DeviceRegisterResponse, error) {
	var out wire.DeviceRegisterResponse
	return &out, c.do(ctx, http.MethodPost, "/v1/auth/device", unsigned, req, &out)
}

// PollToken asks once for the session behind a device code.
func (c *Client) PollToken(ctx context.Context, deviceCode string) (*wire.TokenResponse, error) {
	var out wire.TokenResponse
	return &out, c.do(ctx, http.MethodPost, "/v1/auth/token", signedOnly, wire.TokenRequest{DeviceCode: deviceCode}, &out)
}

// Logout ends this session on the server.
func (c *Client) Logout(ctx context.Context) error {
	return c.do(ctx, http.MethodPost, "/v1/auth/logout", authenticated, struct{}{}, nil)
}

// Me returns the session's account and device.
func (c *Client) Me(ctx context.Context) (*wire.Me, error) {
	var out wire.Me
	return &out, c.do(ctx, http.MethodGet, "/v1/me", authenticated, nil, &out)
}

// Chain returns the links after seq.
func (c *Client) Chain(ctx context.Context, after uint64) ([]*envelope.Envelope, error) {
	var out wire.Chain
	err := c.do(ctx, http.MethodGet, "/v1/chain?after="+strconv.FormatUint(after, 10), authenticated, nil, &out)
	return out.Links, err
}

// UploadProof stores this device's self-signed proof.
func (c *Client) UploadProof(ctx context.Context, proof *envelope.Envelope) error {
	return c.do(ctx, http.MethodPost, "/v1/devices/self/proof", authenticated, wire.DeviceProofUpload{Proof: proof}, nil)
}

// DeviceBox returns this device's sealed user key.
func (c *Client) DeviceBox(ctx context.Context) (*wire.DeviceBox, error) {
	var out wire.DeviceBox
	return &out, c.do(ctx, http.MethodGet, "/v1/devices/self/box", authenticated, nil, &out)
}

// Identity returns the master-wrapped user key.
func (c *Client) Identity(ctx context.Context) (*wire.IdentityBlob, error) {
	var out wire.IdentityBlob
	return &out, c.do(ctx, http.MethodGet, "/v1/identity", authenticated, nil, &out)
}

// AgentSlots returns usable agent unlock slots.
func (c *Client) AgentSlots(ctx context.Context) ([]wire.AgentSlot, error) {
	var out wire.AgentSlots
	err := c.do(ctx, http.MethodGet, "/v1/agent-slots", authenticated, nil, &out)
	return out.Slots, err
}

// Recovery proves the recovery phrase and returns the chain and identity.
func (c *Client) Recovery(ctx context.Context, req wire.RecoveryRequest) (*wire.RecoveryResponse, error) {
	var out wire.RecoveryResponse
	return &out, c.do(ctx, http.MethodPost, "/v1/recovery", authenticated, req, &out)
}

// AgentUnlock proves an SSH key and returns the chain and its slot.
func (c *Client) AgentUnlock(ctx context.Context, req wire.AgentUnlockRequest) (*wire.AgentUnlockResponse, error) {
	var out wire.AgentUnlockResponse
	return &out, c.do(ctx, http.MethodPost, "/v1/agent-slots/unlock", authenticated, req, &out)
}

// DisableSlot disables an agent slot on the server.
func (c *Client) DisableSlot(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodDelete, "/v1/agent-slots/"+url.PathEscape(id), authenticated, nil, nil)
}

// Commit applies chain links and their objects atomically.
func (c *Client) Commit(ctx context.Context, cm *wire.Commit) (*wire.CommitResult, error) {
	var out wire.CommitResult
	return &out, c.do(ctx, http.MethodPost, "/v1/commit", authenticated, cm, &out)
}

// Devices lists the account's devices.
func (c *Client) Devices(ctx context.Context) ([]wire.DeviceInfo, error) {
	var out wire.Devices
	err := c.do(ctx, http.MethodGet, "/v1/devices", authenticated, nil, &out)
	return out.Devices, err
}

// Suspend blocks a device on the server.
func (c *Client) Suspend(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodPost, "/v1/devices/"+url.PathEscape(id)+"/suspend", authenticated, struct{}{}, nil)
}

// Vault returns the latest vault version.
func (c *Client) Vault(ctx context.Context) (*wire.Vault, error) {
	var out wire.Vault
	return &out, c.do(ctx, http.MethodGet, "/v1/vault", authenticated, nil, &out)
}

// VaultVersion returns one stored vault version.
func (c *Client) VaultVersion(ctx context.Context, v uint64) (*wire.Vault, error) {
	var out wire.Vault
	return &out, c.do(ctx, http.MethodGet, "/v1/vault/versions/"+strconv.FormatUint(v, 10), authenticated, nil, &out)
}

// VaultVersions lists stored vault versions.
func (c *Client) VaultVersions(ctx context.Context) ([]wire.Vault, error) {
	var out wire.VaultVersions
	err := c.do(ctx, http.MethodGet, "/v1/vault/versions", authenticated, nil, &out)
	return out.Versions, err
}

// PutVault stores a new vault version.
func (c *Client) PutVault(ctx context.Context, put wire.VaultPut) (*wire.Vault, error) {
	var out wire.Vault
	return &out, c.do(ctx, http.MethodPut, "/v1/vault", authenticated, put, &out)
}

// Events long-polls for events after id, waiting up to wait.
func (c *Client) Events(ctx context.Context, after int64, wait time.Duration) (*wire.Events, error) {
	var out wire.Events
	path := fmt.Sprintf("/v1/events?after=%d&wait=%d", after, int(wait/time.Second))
	return &out, c.do(ctx, http.MethodGet, path, authenticated, nil, &out)
}

// Audit returns recent audit entries.
func (c *Client) Audit(ctx context.Context, limit int) ([]wire.AuditEntry, error) {
	var out wire.Audit
	err := c.do(ctx, http.MethodGet, "/v1/audit?limit="+strconv.Itoa(limit), authenticated, nil, &out)
	return out.Entries, err
}

func (c *Client) do(ctx context.Context, method, path string, m mode, in, out any) error {
	var body []byte
	if in != nil {
		var err error
		body, err = json.Marshal(in)
		if err != nil {
			return err
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, c.Base+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "esec-vault")
	if m != unsigned {
		if c.DeviceID == "" || c.Key == nil {
			return errors.New("client has no device key")
		}
		if err := apisig.Sign(req, body, c.DeviceID, c.Key, c.Now()); err != nil {
			return err
		}
	}
	if m == authenticated {
		if c.Token == "" {
			return &APIError{Status: http.StatusUnauthorized, Code: wire.ErrUnauthorized, Description: "not signed in; run 'esec vault login'"}
		}
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode >= 300 {
		var e wire.Error
		if json.Unmarshal(raw, &e) == nil && e.Code != "" {
			return &APIError{Status: resp.StatusCode, Code: e.Code, Description: e.Description}
		}
		return &APIError{Status: resp.StatusCode, Code: "http_" + strconv.Itoa(resp.StatusCode)}
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("invalid server response: %w", err)
	}
	return nil
}
