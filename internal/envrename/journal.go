package envrename

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/mscno/esec-vault/internal/storage"
)

// Journal contains only public metadata and encrypted seals, never private keys.
// It is retained until both the vault and local changes have completed.
type Journal struct {
	Project string   `json:"project"`
	Old     string   `json:"old"`
	New     string   `json:"new"`
	Public  string   `json:"public"`
	Shared  bool     `json:"shared"`
	Changes []Change `json:"changes"`
}

// Change is a checked rename, replacement, or deletion (To empty).
type Change struct {
	From   string `json:"from"`
	To     string `json:"to"`
	Before string `json:"before"`
	After  string `json:"after"`
	Data   []byte `json:"data,omitempty"`
	Mode   uint32 `json:"mode"`
}

// Path is deliberately outside the secrets filename search.
func Path(root string) string { return filepath.Join(root, ".esec", "env-rename.json") }

// Load reads an interrupted operation, if any.
func Load(root string) (*Journal, error) {
	if err := safePath(root, Path(root)); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(Path(root))
	if err != nil {
		return nil, err
	}
	var j Journal
	if err := json.Unmarshal(data, &j); err != nil {
		return nil, err
	}
	return &j, nil
}

// Save atomically publishes the complete plan before any remote mutation.
func (j *Journal) Save(root string) error {
	if err := safePath(root, Path(root)); err != nil {
		return err
	}
	data, err := json.MarshalIndent(j, "", "  ")
	if err != nil {
		return err
	}
	return storage.Write(Path(root), data)
}

func digest(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }

// Add snapshots a regular file's identity, not its contents, for checked changes.
func (j *Journal) Add(root, from, to string, data []byte) error {
	if err := safePath(root, from); err != nil {
		return err
	}
	if to != "" {
		if err := safePath(root, to); err != nil {
			return err
		}
	}
	info, err := os.Lstat(from)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("refusing nonregular file %s", from)
	}
	original, err := os.ReadFile(from) //nolint:gosec // confined regular path checked above
	if err != nil {
		return err
	}
	a, err := filepath.Rel(root, from)
	if err != nil {
		return err
	}
	b := ""
	if to != "" {
		b, err = filepath.Rel(root, to)
		if err != nil {
			return err
		}
	}
	after := digest(original)
	if data != nil {
		after = digest(data)
	}
	j.Changes = append(j.Changes, Change{From: a, To: b, Before: digest(original), After: after, Data: data, Mode: uint32(info.Mode().Perm())})
	return nil
}

func safePath(root, path string) error {
	rel, err := filepath.Rel(root, path)
	if err != nil || !filepath.IsLocal(rel) {
		return fmt.Errorf("path outside project: %s", path)
	}
	for p := path; p != root; p = filepath.Dir(p) {
		info, err := os.Lstat(p)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing symlink %s", p)
		}
		if p == path && !info.Mode().IsRegular() {
			return fmt.Errorf("refusing nonregular file %s", p)
		}
	}
	return nil
}

// Apply is idempotent. Changed files or occupied destinations fail closed;
// rerunning the command completes the same plan after interruption.
func (j *Journal) Apply(root string) error {
	for _, c := range j.Changes {
		if err := c.apply(root); err != nil {
			return err
		}
	}
	return nil
}

func (c Change) apply(root string) error {
	if c.Data != nil && digest(c.Data) != c.After {
		return fmt.Errorf("rename journal data checksum mismatch")
	}
	from := filepath.Join(root, c.From)
	if err := safePath(root, from); err != nil {
		return err
	}
	to := ""
	if c.To != "" {
		to = filepath.Join(root, c.To)
		if err := safePath(root, to); err != nil {
			return err
		}
	}
	data, err := os.ReadFile(from) //nolint:gosec // confined regular path checked above
	if os.IsNotExist(err) {
		if to == "" {
			return nil
		}
		dest, err := os.ReadFile(to) //nolint:gosec // confined regular destination checked above
		if err == nil && digest(dest) == c.After {
			return nil
		}
		return fmt.Errorf("rename source missing: %s", from)
	}
	if err != nil {
		return err
	}
	if from == to && digest(data) == c.After {
		return nil
	}
	if digest(data) != c.Before {
		return fmt.Errorf("file changed during rename: %s", from)
	}
	if to == "" {
		return os.Remove(from)
	}
	if from == to {
		return storage.WriteKeepMode(from, c.Data)
	}
	return c.publish(from, to)
}

func (c Change) publish(from, to string) error {
	if err := os.MkdirAll(filepath.Dir(to), 0750); err != nil {
		return err
	}
	if c.Data == nil {
		// Link never overwrites a destination. If interrupted between link and
		// unlink, both paths name the same inode and the retry finishes it.
		if err := os.Link(from, to); err != nil {
			a, e1 := os.Stat(from)
			b, e2 := os.Stat(to)
			if e1 != nil || e2 != nil || !os.SameFile(a, b) {
				return err
			}
		}
		return os.Remove(from)
	}
	// A newly resealed key must be written without replacing an occupied name.
	f, err := os.CreateTemp(filepath.Dir(to), ".env-rename-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err := f.Chmod(os.FileMode(c.Mode)); err != nil {
		f.Close()
		return err
	}
	if _, err = f.Write(c.Data); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err := os.Link(f.Name(), to); err != nil {
		dest, e := os.ReadFile(to) //nolint:gosec // confined destination validated by apply
		if e != nil || digest(dest) != c.After {
			return fmt.Errorf("destination exists or cannot be created: %s: %w", to, err)
		}
	}
	return os.Remove(from)
}
