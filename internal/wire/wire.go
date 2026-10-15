// Package wire defines the JSON types of the esec vault server API, shared by
// the server and the CLI client. Byte slices travel as base64.
package wire

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/mscno/esec-vault/internal/envelope"
)

// Prefix is the API version prefix.
const Prefix = "/v1"

// Error codes. The device-flow codes follow RFC 8628.
const (
	ErrAuthorizationPending = "authorization_pending"
	ErrSlowDown             = "slow_down"
	ErrExpiredToken         = "expired_token"
	ErrAccessDenied         = "access_denied"
	ErrInvalidRequest       = "invalid_request"
	ErrUnauthorized         = "unauthorized"
	ErrForbidden            = "forbidden"
	ErrNotFound             = "not_found"
	ErrConflict             = "conflict"
	ErrRateLimited          = "rate_limited"
	ErrDeviceRevoked        = "device_revoked"
	ErrPendingExpired       = "pending_expired"
	ErrBootstrapRequired    = "bootstrap_required"
	ErrInternal             = "internal"
)

// Error is the body of every non-2xx response.
type Error struct {
	Code        string `json:"error"`
	Description string `json:"error_description,omitempty"`
}

// Device statuses on the server.
const (
	DeviceRegistering = "registering"
	DevicePending     = "pending"
	DeviceActive      = "active"
	DeviceSuspended   = "suspended"
	DeviceRevoked     = "revoked"
)

// DeviceRegisterRequest starts the device authorization grant. Sig is the
// device key's signature over RegistrationMessage, proving the registrant
// holds the private key it registers.
type DeviceRegisterRequest struct {
	Name      string `json:"name"`
	Platform  string `json:"platform"`
	EncPub    string `json:"enc_pub"`
	SignPub   string `json:"sign_pub"`
	Timestamp int64  `json:"timestamp"`
	Sig       []byte `json:"sig"`
}

// RegistrationMessage returns the bytes a registration signature covers.
func RegistrationMessage(r *DeviceRegisterRequest) []byte {
	return []byte(fmt.Sprintf("esec-vault register v1\n%s\n%s\n%s\n%s\n%d", r.Name, r.Platform, r.EncPub, r.SignPub, r.Timestamp))
}

// DeviceRegisterResponse carries the codes for the device authorization grant.
type DeviceRegisterResponse struct {
	DeviceID                string    `json:"device_id"`
	DeviceCreated           time.Time `json:"device_created"`
	DeviceCode              string    `json:"device_code"`
	UserCode                string    `json:"user_code"`
	VerificationURI         string    `json:"verification_uri"`
	VerificationURIComplete string    `json:"verification_uri_complete"`
	Interval                int       `json:"interval"`
	ExpiresIn               int       `json:"expires_in"`
}

// TokenRequest polls for the session. The request is signed by the device key
// registered with the device code.
type TokenRequest struct {
	DeviceCode string `json:"device_code"`
}

// User is an account.
type User struct {
	ID       string `json:"id"`
	GitHubID int64  `json:"github_id"`
	Login    string `json:"login"`
}

// DeviceInfo is a device as the server knows it.
type DeviceInfo struct {
	ID       string             `json:"id"`
	Name     string             `json:"name"`
	Platform string             `json:"platform"`
	EncPub   string             `json:"enc_pub"`
	SignPub  string             `json:"sign_pub"`
	Status   string             `json:"status"`
	Method   string             `json:"method,omitempty"`
	Created  time.Time          `json:"created"`
	LastSeen time.Time          `json:"last_seen,omitzero"`
	LastIP   string             `json:"last_ip,omitempty"`
	Proof    *envelope.Envelope `json:"proof,omitempty"`
}

// TokenResponse returns the session after the user confirmed the code.
type TokenResponse struct {
	SessionToken string     `json:"session_token"`
	ExpiresAt    time.Time  `json:"expires_at"`
	User         User       `json:"user"`
	Device       DeviceInfo `json:"device"`
}

// Me describes the calling session.
type Me struct {
	User           User       `json:"user"`
	Device         DeviceInfo `json:"device"`
	ChainSeq       uint64     `json:"chain_seq"`
	SessionExpires time.Time  `json:"session_expires"`
	PendingExpires time.Time  `json:"pending_expires,omitzero"`
}

// Chain lists chain links.
type Chain struct {
	Links []*envelope.Envelope `json:"links"`
}

// DeviceProofUpload registers the device's self-signed proof.
type DeviceProofUpload struct {
	Proof *envelope.Envelope `json:"proof"`
}

// Devices lists the account's devices.
type Devices struct {
	Devices []DeviceInfo `json:"devices"`
}

// DeviceBox is the user key sealed to one device.
type DeviceBox struct {
	DeviceID    string `json:"device_id"`
	UKeyVersion uint64 `json:"ukey_version"`
	Box         []byte `json:"box"`
}

// AgentSlot is an SSH-agent unlock slot.
type AgentSlot struct {
	SlotID      string    `json:"slot_id"`
	SSHKeyFP    string    `json:"ssh_key_fp"`
	Salt        []byte    `json:"salt"`
	Box         []byte    `json:"box"`
	UKeyVersion uint64    `json:"ukey_version"`
	Expires     time.Time `json:"expires"`
	Disabled    bool      `json:"disabled,omitempty"`
}

// AgentSlots lists slots.
type AgentSlots struct {
	Slots []AgentSlot `json:"slots"`
}

// VaultPut writes a new vault version. IfMatch is the version the client
// last saw (0 when it has seen none). Sig is the user key's signature over
// the blob (see VaultMessage); a vault blob is sealed to a public key, so
// without the signature anyone could create one.
type VaultPut struct {
	Blob    []byte `json:"blob"`
	Sig     []byte `json:"sig"`
	IfMatch uint64 `json:"if_match"`
	// Index optionally publishes non-secret metadata (project ids,
	// environment names, public keys) for the web UI, signed separately.
	Index    []byte `json:"index,omitempty"`
	IndexSig []byte `json:"index_sig,omitempty"`
}

// VaultIndex is the plaintext, non-secret summary of a vault: what exists,
// never a private key or a secret value.
type VaultIndex struct {
	Generation uint64         `json:"generation"`
	Projects   []IndexProject `json:"projects"`
}

// IndexProject lists one project's environments.
type IndexProject struct {
	ID           string     `json:"id"`
	Environments []IndexEnv `json:"environments"`
	// OtherKeys counts keys stored only under their public key (retired
	// keys kept for git history, or unnamed keys).
	OtherKeys int `json:"other_keys"`
}

// IndexEnv is one named environment key.
type IndexEnv struct {
	Name      string `json:"name"`
	PublicKey string `json:"public_key"`
}

// IndexMessage returns the bytes an index signature covers.
func IndexMessage(user string, index []byte) []byte {
	sum := sha256.Sum256(index)
	return []byte("esec-vault/index/v1\n" + user + "\n" + hex.EncodeToString(sum[:]))
}

// VaultMessage returns the bytes a vault signature covers.
func VaultMessage(user string, blob []byte) []byte {
	sum := sha256.Sum256(blob)
	return []byte("esec-vault/vault/v1\n" + user + "\n" + hex.EncodeToString(sum[:]))
}

// Vault is one stored vault version.
type Vault struct {
	Version   uint64    `json:"version"`
	Blob      []byte    `json:"blob,omitempty"`
	Sig       []byte    `json:"sig,omitempty"`
	SHA256    string    `json:"sha256"`
	Size      int       `json:"size"`
	CreatedAt time.Time `json:"created_at"`
	PushedBy  string    `json:"pushed_by"`
}

// VaultVersions lists stored versions, newest first, without blobs.
type VaultVersions struct {
	Versions []Vault `json:"versions"`
}

// Commit applies chain links and the objects they need in one transaction.
type Commit struct {
	Links       []*envelope.Envelope `json:"links,omitempty"`
	DeviceBoxes []DeviceBox          `json:"device_boxes,omitempty"`
	Identity    []byte               `json:"identity,omitempty"`
	Vault       *VaultPut            `json:"vault,omitempty"`
	AgentSlots  []AgentSlot          `json:"agent_slots,omitempty"`
	// BootstrapToken authorizes creating an account (an init link). The
	// server operator hands it out; a GitHub login alone cannot create one.
	BootstrapToken string `json:"bootstrap_token,omitempty"`
}

// CommitResult reports the state after a commit.
type CommitResult struct {
	ChainSeq     uint64 `json:"chain_seq"`
	VaultVersion uint64 `json:"vault_version,omitempty"`
}

// IdentityBlob is the master-wrapped user key.
type IdentityBlob struct {
	UKeyVersion uint64 `json:"ukey_version"`
	Blob        []byte `json:"blob"`
}

// Event types.
const (
	EventChain         = "chain"
	EventVault         = "vault"
	EventDevicePending = "device_pending"
	EventDeviceStatus  = "device_status"
)

// Event notifies clients of a change.
type Event struct {
	ID      int64     `json:"id"`
	Type    string    `json:"type"`
	Created time.Time `json:"created"`
	Detail  string    `json:"detail,omitempty"`
}

// Events is a page of events.
type Events struct {
	Events []Event `json:"events"`
	Next   int64   `json:"next"`
}

// AuditEntry is one audit log record.
type AuditEntry struct {
	ID       int64     `json:"id"`
	Time     time.Time `json:"time"`
	DeviceID string    `json:"device_id,omitempty"`
	IP       string    `json:"ip,omitempty"`
	Action   string    `json:"action"`
	Detail   string    `json:"detail,omitempty"`
}

// Audit is a page of audit entries, newest first.
type Audit struct {
	Entries []AuditEntry `json:"entries"`
}
