package wire

import "time"

// OrgPolicy is what the server enforces for the shared projects and groups
// of one organisation (the "acme" of acme/store). The server can only
// refuse with it, never grant: it is a check on top of the signed chains,
// set by the server's admins.
type OrgPolicy struct {
	// MaxTokenDays bounds the lifetime of a group's enrollment tokens, and
	// refuses tokens that never expire; 0 sets no bound.
	MaxTokenDays int `json:"max_token_days,omitempty"`
	// RequireGitHubProof refuses people added with account key words
	// instead of a GitHub SSH proof.
	RequireGitHubProof bool `json:"require_github_proof,omitempty"`
	// NoServerSigning keeps the server from signing removals made on the
	// web pages, even for people who let it: they wait for a passkey or a
	// device instead.
	NoServerSigning bool `json:"no_server_signing,omitempty"`
	// ReviewDays asks each project's admins to review who reads it every
	// so many days; 0 never.
	ReviewDays int `json:"review_days,omitempty"`
	// Updated and UpdatedBy say who set it, and when.
	Updated   time.Time `json:"updated,omitzero"`
	UpdatedBy string    `json:"updated_by,omitempty"`
}

// AccessReview records that an admin reviewed who reads a project: who
// keeps access, and who they took it away from.
type AccessReview struct {
	Project  string    `json:"project,omitempty"`
	Kept     []string  `json:"kept"`
	Removed  []string  `json:"removed"`
	By       string    `json:"by,omitempty"`
	Reviewed time.Time `json:"reviewed,omitzero"`
}

// ReviewStatus says whether a project's access review is due.
type ReviewStatus struct {
	Project string        `json:"project"`
	Days    int           `json:"days"`
	Due     bool          `json:"due"`
	Last    *AccessReview `json:"last,omitempty"`
}
