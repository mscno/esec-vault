package broker

import "github.com/mscno/esec"

// Ops supported by the broker protocol.
const (
	OpPing         = "ping"
	OpListEnvs     = "list_envs"
	OpGetSecrets   = "get_secrets"
	OpReadDocument = "read_document"
	OpInspectRead  = "inspect_read"
	OpApprove      = "approve"
)

// Request is a single JSON-lines protocol request.
type Request struct {
	Op        string `json:"op"`
	Digest    string `json:"digest,omitempty"`
	resolved  *esec.ReadTarget
	readEpoch uint64
	Project   string `json:"project,omitempty"`
	Env       string `json:"env,omitempty"`
	Path      string `json:"path,omitempty"`   // get_secrets: absolute path of the encrypted secrets file
	Format    string `json:"format,omitempty"` // get_secrets: esec file format, e.g. ".ejson"
	ID        string `json:"id,omitempty"`     // approve: pending request id
	// Session labels the agent session a request comes from (ESEC_VAULT_SESSION).
	Session string `json:"session,omitempty"`
	// Content is the encrypted secrets file itself, for a request forwarded
	// from another machine, where Path names a file on that machine.
	Content []byte `json:"content,omitempty"`
	// Host names the machine a forwarded request comes from.
	Host string `json:"host,omitempty"`
	// Seal is the environment's sealed key (.esec/<env>.age), for a
	// request forwarded from another machine.
	Seal []byte `json:"seal,omitempty"`
}

// GuardRequest is a read of a guarded key, as the guard is asked for it.
type GuardRequest struct {
	Project, Env, PublicKey string
	Protection              string
	// Path is the secrets file to decrypt; Host is the name a forwarded
	// request claims for its machine.
	Path, Host string
	// Forwarded is set by the broker that received the request (the
	// forward socket), never by the request.
	Forwarded bool
	UID, PID  uint32
	// Caller is the asking program and its parents; Command is the asking
	// program's command line, which tells a run from a decrypt.
	Caller, Command string
	Session         string
	// Seal is the sealed key a forwarded request carries.
	Seal []byte
}

// Guarder opens guarded keys: it asks the person, then waits for the
// hardware touch.
type Guarder interface {
	// Has reports whether the read is of a guarded key. An error means it
	// could not tell: the broker then serves nothing.
	Has(req GuardRequest) (bool, error)
	// Key returns the private key, after the person allowed it.
	Key(req GuardRequest) (priv string, how string, err error)
}

// Response is a single JSON-lines protocol response.
type Response struct {
	OK         bool                 `json:"ok"`
	Code       string               `json:"code,omitempty"`
	Document   []byte               `json:"document,omitempty"`
	Inspection *esec.ReadInspection `json:"inspection,omitempty"`
	Error      string               `json:"error,omitempty"`
	Envs       []string             `json:"envs,omitempty"`    // list_envs
	Secrets    map[string]string    `json:"secrets,omitempty"` // get_secrets
	VaultEnv   map[string]string    `json:"-"`                 // unused
	Pending    string               `json:"pending,omitempty"` // informational
}
