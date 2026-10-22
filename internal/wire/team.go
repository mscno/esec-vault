package wire

import (
	"time"

	"github.com/mscno/esec-vault/internal/envelope"
)

// Event types of shared projects. Detail is the project id.
const (
	// EventProject: the project chain or its delivery status changed.
	EventProject = "project"
	// EventGrant: environment keys are waiting for this account.
	EventGrant = "grant"
)

// AccountProof binds a GitHub account to an esec vault account (see
// team.AccountProof).
type AccountProof struct {
	User      string `json:"user"`
	Login     string `json:"login"`
	Root      string `json:"root"`
	Signature string `json:"signature"`
}

// Person is another account as a colleague's device sees it: enough to
// verify its user key from its own chain.
type Person struct {
	User  User                 `json:"user"`
	Root  string               `json:"root"`
	Proof *AccountProof        `json:"proof,omitempty"`
	Links []*envelope.Envelope `json:"links"`
}

// ProjectSummary is a shared project the caller belongs to.
type ProjectSummary struct {
	ID        string   `json:"id"`
	Seq       uint64   `json:"seq"`
	Admin     bool     `json:"admin"`
	Envs      []string `json:"envs"`
	Members   int      `json:"members"`
	Machines  int      `json:"machines"`
	Groups    int      `json:"groups"`
	Rotations int      `json:"rotations"`
	// Archived says the project is stopped; Successor names where it
	// moved, when it did.
	Archived  bool   `json:"archived,omitempty"`
	Successor string `json:"successor,omitempty"`
}

// Projects lists shared projects.
type Projects struct {
	Projects []ProjectSummary `json:"projects"`
}

// ProjectChain lists project chain links, with the user chains of everyone
// who signed one, so the caller can verify them.
type ProjectChain struct {
	Links  []*envelope.Envelope            `json:"links"`
	Chains map[string][]*envelope.Envelope `json:"chains,omitempty"`
}

// ProjectCommit appends links to a project chain and stores grants, in one
// transaction. Every link and grant is signed by the caller.
type ProjectCommit struct {
	Links  []*envelope.Envelope `json:"links,omitempty"`
	Grants []*envelope.Envelope `json:"grants,omitempty"`
}

// ProjectCommitResult reports the chain length after a commit.
type ProjectCommitResult struct {
	Seq uint64 `json:"seq"`
}

// Key delivery states of a holder's environment.
const (
	// KeyHeld: the holder confirmed it has the current key.
	KeyHeld = "held"
	// KeyWaiting: a grant with the current key waits for the holder.
	KeyWaiting = "waiting"
	// KeyMissing: an admin's device still has to send the current key.
	KeyMissing = "missing"
)

// HolderStatus is the key delivery state of one member or machine.
type HolderStatus struct {
	ID string `json:"id"`
	// Kind is "member", "machine" or "group".
	Kind string `json:"kind"`
	// UKeyVersion is a member's current user key version.
	UKeyVersion uint64            `json:"ukey_version,omitempty"`
	Envs        map[string]string `json:"envs"`
	LastUsed    time.Time         `json:"last_used,omitzero"`
}

// ProjectStatus reports key delivery for every holder of a project.
type ProjectStatus struct {
	Seq     uint64         `json:"seq"`
	Holders []HolderStatus `json:"holders"`
}

// GrantItem is a grant waiting for the caller.
type GrantItem struct {
	ID      int64              `json:"id"`
	Project string             `json:"project"`
	Grant   *envelope.Envelope `json:"grant"`
}

// Grants lists grants waiting for the caller.
type Grants struct {
	Grants []GrantItem `json:"grants"`
}

// Holding is an environment key a member's devices now hold.
type Holding struct {
	Project   string `json:"project"`
	Env       string `json:"env"`
	PublicKey string `json:"public_key"`
}

// GrantAck removes handled grants and records the keys now held. A grant
// that turned out stale is acknowledged without a holding.
type GrantAck struct {
	IDs      []int64   `json:"ids"`
	Holdings []Holding `json:"holdings,omitempty"`
}

// MachineKeysRequest is a machine asking for its keys. It is not signed in:
// Sig is the machine key's signature over team.KeysMessage, and OIDCToken
// proves the workload when the machine's policy requires one.
type MachineKeysRequest struct {
	Machine   string `json:"machine"`
	Project   string `json:"project"`
	Timestamp int64  `json:"timestamp"`
	Nonce     string `json:"nonce"`
	OIDCToken string `json:"oidc_token,omitempty"`
	Sig       []byte `json:"sig"`
}

// MachineKeys returns what a machine needs to verify and open its keys.
type MachineKeys struct {
	Links  []*envelope.Envelope            `json:"links"`
	Chains map[string][]*envelope.Envelope `json:"chains"`
	Grant  *envelope.Envelope              `json:"grant"`
}
