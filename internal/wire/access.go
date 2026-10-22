package wire

import "time"

// AccessRequest is someone asking an admin of a project for environments.
// The server only passes it on: an admin grants it from a device or a
// passkey like any other access.
type AccessRequest struct {
	ID      int64     `json:"id"`
	Project string    `json:"project"`
	Login   string    `json:"login"`
	Envs    []string  `json:"envs"`
	Reason  string    `json:"reason,omitempty"`
	Created time.Time `json:"created"`
}

// AccessRequestNew asks for envs of a project.
type AccessRequestNew struct {
	Project string   `json:"project"`
	Envs    []string `json:"envs"`
	Reason  string   `json:"reason,omitempty"`
}

// AccessRequests lists the requests the caller can decide (in projects
// they administer) and their own that wait.
type AccessRequests struct {
	ToDecide []AccessRequest `json:"to_decide"`
	Mine     []AccessRequest `json:"mine"`
}

// AccessRequestClose answers a request (an admin), or withdraws it (its
// asker). Granted says the access was given.
type AccessRequestClose struct {
	Granted bool `json:"granted"`
}

// AccessExpiry takes envs of a project away from a person (a GitHub login)
// or a group (org/name) at Expires: the server signs the removal for the
// admin who set it when they let it sign removals, and otherwise proposes
// it for their passkey or device to sign.
type AccessExpiry struct {
	ID      int64     `json:"id,omitempty"`
	Project string    `json:"project,omitempty"`
	Subject string    `json:"subject"`
	Envs    []string  `json:"envs"`
	Expires time.Time `json:"expires"`
	By      string    `json:"by,omitempty"`
	// Error says why access past its time has not ended yet; the server
	// keeps trying.
	Error string `json:"error,omitempty"`
}

// AccessExpiries lists a project's timed access.
type AccessExpiries struct {
	Expiries []AccessExpiry `json:"expiries"`
}
