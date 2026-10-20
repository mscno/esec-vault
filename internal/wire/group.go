package wire

import (
	"time"

	"github.com/mscno/esec-vault/internal/envelope"
)

// EventGroup is the event of a machine group that changed, or that a
// machine asks to join. Detail is the group id.
const EventGroup = "group"

// GroupSummary is a machine group the caller administers, or one a project
// of theirs grants environments to.
type GroupSummary struct {
	ID       string   `json:"id"`
	Seq      uint64   `json:"seq"`
	Admin    bool     `json:"admin"`
	Machines int      `json:"machines"`
	Tokens   int      `json:"tokens"`
	Projects []string `json:"projects"`
	// KeyExposed counts removed machines that held the group's current key.
	KeyExposed int `json:"key_exposed"`
	// Pending counts join requests and web changes waiting for approval.
	Pending int `json:"pending"`
}

// Groups lists machine groups.
type Groups struct {
	Groups []GroupSummary `json:"groups"`
}

// GroupChain lists group chain links, with the user chains of everyone who
// signed one.
type GroupChain struct {
	Links  []*envelope.Envelope            `json:"links"`
	Chains map[string][]*envelope.Envelope `json:"chains,omitempty"`
}

// GroupCommit appends links to a group chain and stores key grants, in one
// transaction, signed by the caller.
type GroupCommit struct {
	Links     []*envelope.Envelope `json:"links,omitempty"`
	KeyGrants []*envelope.Envelope `json:"key_grants,omitempty"`
}

// GroupCommitResult reports the chain length after a commit.
type GroupCommitResult struct {
	Seq uint64 `json:"seq"`
}

// CredStatus is a machine or token as the server sees it.
type CredStatus struct {
	ID string `json:"id"`
	// HasKey: a grant of the current group key waits for it.
	HasKey    bool      `json:"has_key"`
	Suspended bool      `json:"suspended,omitempty"`
	LastUsed  time.Time `json:"last_used,omitzero"`
	LastIP    string    `json:"last_ip,omitempty"`
	Uses      int       `json:"uses"`
}

// JoinRequest is a machine asking to join a group.
type JoinRequest struct {
	ID      string    `json:"id"`
	Machine string    `json:"machine"`
	Name    string    `json:"name"`
	EncPub  string    `json:"enc_pub"`
	SignPub string    `json:"sign_pub"`
	IP      string    `json:"ip"`
	Created time.Time `json:"created"`
}

// Proposal kinds: changes made on the web pages, which an admin's device
// signs (esec vault group approve).
const (
	ProposalAccess = "access"
	ProposalRemove = "remove"
)

// Proposal is a change waiting for an admin's device to sign it.
type Proposal struct {
	ID      int64     `json:"id"`
	Kind    string    `json:"kind"`
	Project string    `json:"project,omitempty"`
	Envs    []string  `json:"envs,omitempty"`
	Cred    string    `json:"cred,omitempty"`
	By      string    `json:"by"`
	Created time.Time `json:"created"`
}

// GroupStatus reports what the server knows of a group beyond its chain.
type GroupStatus struct {
	Seq   uint64       `json:"seq"`
	Creds []CredStatus `json:"creds"`
	// AdminsWithKey lists admins a grant of the current group key waits
	// for.
	AdminsWithKey []string      `json:"admins_with_key"`
	Joins         []JoinRequest `json:"joins"`
	Proposals     []Proposal    `json:"proposals"`
}

// GroupKeyGrants returns the key grants waiting for the caller.
type GroupKeyGrants struct {
	Grants []*envelope.Envelope `json:"grants"`
}

// ProposalClose marks a proposal applied or dismissed.
type ProposalClose struct {
	Applied bool `json:"applied"`
}

// GroupJoin is a machine asking to join a group, or asking whether it was
// let in. Sig is the machine key's signature over team.JoinMessage.
type GroupJoin struct {
	Group     string `json:"group"`
	Machine   string `json:"machine"`
	Name      string `json:"name"`
	EncPub    string `json:"enc_pub"`
	SignPub   string `json:"sign_pub"`
	Timestamp int64  `json:"timestamp"`
	Nonce     string `json:"nonce"`
	Sig       []byte `json:"sig"`
}

// Join states.
const (
	JoinPending  = "pending"
	JoinApproved = "approved"
	JoinRejected = "rejected"
)

// GroupJoinResult is the state of a join request. Root is the group's
// root as the server reports it; the approver's words prove it.
type GroupJoinResult struct {
	Join   string `json:"join"`
	Root   string `json:"root"`
	Status string `json:"status"`
}

// GroupEnroll adds a machine with an enrollment token: a machine_add link
// and a key grant to the machine, both signed by the token.
type GroupEnroll struct {
	Group     string             `json:"group"`
	Link      *envelope.Envelope `json:"link"`
	KeyGrant  *envelope.Envelope `json:"key_grant"`
	OIDCToken string             `json:"oidc_token,omitempty"`
}

// GroupKeysRequest is a machine or token asking for its keys. Sig is its
// signature over team.GroupKeysMessage.
type GroupKeysRequest struct {
	Group     string `json:"group"`
	ID        string `json:"id"`
	Timestamp int64  `json:"timestamp"`
	Nonce     string `json:"nonce"`
	OIDCToken string `json:"oidc_token,omitempty"`
	Sig       []byte `json:"sig"`
}

// GroupProjectKeys is one project's chain and its grant to the group.
type GroupProjectKeys struct {
	Project string               `json:"project"`
	Links   []*envelope.Envelope `json:"links"`
	Grant   *envelope.Envelope   `json:"grant,omitempty"`
}

// GroupKeys returns what a machine needs to verify and open its keys: the
// group chain, the user chains of everyone who signed anything, its group
// key grant, and each project's chain and grant to the group.
type GroupKeys struct {
	Links    []*envelope.Envelope            `json:"links"`
	Chains   map[string][]*envelope.Envelope `json:"chains"`
	KeyGrant *envelope.Envelope              `json:"key_grant"`
	Projects []GroupProjectKeys              `json:"projects"`
}
