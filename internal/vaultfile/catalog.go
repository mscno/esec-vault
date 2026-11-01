package vaultfile

import "time"

// Catalog is authenticated inside a format-3 vault. Its object references
// carry the keys for independently encrypted, immutable file revisions.
type Catalog struct {
	Profiles  map[string]Profile    `json:"profiles,omitempty"`
	Artifacts map[string]Artifact   `json:"artifacts,omitempty"`
	Captures  map[string]Capture    `json:"captures,omitempty"`
	Aliases   map[string]AliasState `json:"aliases,omitempty"`
	Deleted   map[string]time.Time  `json:"deleted,omitempty"`
	Retired   map[string]time.Time  `json:"retired,omitempty"`
	Guards    map[string]GuardState `json:"guards,omitempty"`
	User      string                `json:"user,omitempty"`
}

// GuardState tracks deliberate guard changes; protection wins concurrent ties.
type GuardState struct {
	Version uint64 `json:"version"`
	Guarded bool   `json:"guarded"`
}

// AliasState tracks explicit local alias edits relative to an acknowledged
// base. Logical versions avoid relying on synchronized device clocks.
type AliasState struct {
	Version uint64 `json:"version"`
	Removed bool   `json:"removed"`
}

// Capture is a complete, immutable checkout revision. Only its listed files
// are restored, so files deleted later do not reappear in a latest restore.
type Capture struct {
	Sequence uint64            `json:"sequence"`
	Project  string            `json:"project"`
	Checkout string            `json:"checkout"`
	Device   string            `json:"device"`
	Label    string            `json:"label"`
	Files    map[string]string `json:"files"`
	At       time.Time         `json:"at"`
}

// Profile preserves portable settings together with their originating user.
// Device credentials and active approvals are never backed up.
type Profile struct {
	Name     string            `json:"name"`
	UID      uint32            `json:"uid"`
	Settings map[string][]byte `json:"settings"`
}

// Artifact identifies one immutable revision, not a file to overwrite on sync.
// Path is project-relative; Checkout identifies its origin without a local path.
type Artifact struct {
	Project  string    `json:"project"`
	Checkout string    `json:"checkout"`
	Path     string    `json:"path"`
	Kind     string    `json:"kind"`
	Digest   string    `json:"digest"`
	Object   string    `json:"object"`
	Key      []byte    `json:"key"`
	Size     int       `json:"size"`
	At       time.Time `json:"at"`
}

// EnsureCatalog upgrades the payload while preserving the legacy key map.
func (v *Vault) EnsureCatalog() *Catalog {
	if v.Catalog == nil {
		v.Catalog = &Catalog{}
	}
	c := v.Catalog
	if c.Aliases == nil {
		c.Aliases = map[string]AliasState{}
	}
	if c.Profiles == nil {
		c.Profiles = map[string]Profile{}
	}
	if c.Artifacts == nil {
		c.Artifacts = map[string]Artifact{}
	}
	if c.Captures == nil {
		c.Captures = map[string]Capture{}
	}
	if c.Deleted == nil {
		c.Deleted = map[string]time.Time{}
	}
	if c.Retired == nil {
		c.Retired = map[string]time.Time{}
	}
	if c.Guards == nil {
		c.Guards = map[string]GuardState{}
	}
	return c
}

// FormatVersion reports a validated envelope version without decrypting it.
func FormatVersion(data []byte) (byte, error) {
	if _, _, err := framing(data); err != nil {
		return 0, err
	}
	return data[7], nil
}
