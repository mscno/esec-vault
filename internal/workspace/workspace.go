// Package workspace remembers where projects are checked out on this
// machine, the way a git client keeps a list of local repositories: each
// checkout is a directory with an esec.toml, tied to its project's global
// id ("acme/store"). One project may have several checkouts (clones,
// worktrees). The list is this machine's own and holds no secret.
package workspace

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/mscno/esec/pkg/projectfile"
	"github.com/pelletier/go-toml/v2"

	"github.com/mscno/esec-vault/internal/paths"
	"github.com/mscno/esec-vault/internal/storage"
)

// Checkout is one directory holding a project's esec.toml.
type Checkout struct {
	Project string    `toml:"project" json:"project"`
	Path    string    `toml:"path" json:"path"`
	Added   time.Time `toml:"added" json:"added"`
	// Seen is when a command last found the project there.
	Seen time.Time `toml:"seen" json:"seen"`
}

// Registry is the list of checkouts.
type Registry struct {
	Checkouts []Checkout `toml:"checkout"`
}

// File is where the registry lives.
func File() string { return filepath.Join(paths.Home(), "projects.toml") }

// Load reads the registry; a missing file is an empty one.
func Load() (*Registry, error) {
	data, err := os.ReadFile(File())
	if errors.Is(err, fs.ErrNotExist) {
		return &Registry{}, nil
	}
	if err != nil {
		return nil, err
	}
	var r Registry
	if err := toml.NewDecoder(bytes.NewReader(data)).DisallowUnknownFields().Decode(&r); err != nil {
		return nil, fmt.Errorf("invalid %s: %w", File(), err)
	}
	return &r, nil
}

// Update loads the registry, changes it and saves it, holding a lock so
// many commands at once (agents in many checkouts) lose no change.
func Update(change func(*Registry) error) error {
	unlock, err := storage.LockWait(filepath.Join(paths.Home(), "locks", "projects"), 30*time.Second, nil)
	if err != nil {
		return err
	}
	defer unlock()
	r, err := Load()
	if err != nil {
		return err
	}
	if err := change(r); err != nil {
		return err
	}
	return r.Save()
}

// Save writes the registry atomically. Use Update, which locks.
func (r *Registry) Save() error {
	sort.Slice(r.Checkouts, func(i, j int) bool {
		if r.Checkouts[i].Project != r.Checkouts[j].Project {
			return r.Checkouts[i].Project < r.Checkouts[j].Project
		}
		return r.Checkouts[i].Path < r.Checkouts[j].Path
	})
	var buf bytes.Buffer
	buf.WriteString("# Where projects are checked out on this machine (esec vault projects).\n")
	if err := toml.NewEncoder(&buf).Encode(r); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(File()), 0700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(File()), ".projects-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(buf.Bytes()); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), File())
}

// Add records the checkout at dir (which must hold an esec.toml), or
// refreshes it. It reports whether the checkout is new.
func (r *Registry) Add(dir string, now time.Time) (Checkout, bool, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return Checkout{}, false, err
	}
	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		abs = resolved
	}
	f, err := projectfile.Load(abs)
	if err != nil {
		return Checkout{}, false, fmt.Errorf("%s: %w", abs, err)
	}
	for i, c := range r.Checkouts {
		if c.Path == abs {
			r.Checkouts[i].Project, r.Checkouts[i].Seen = f.Project, now
			return r.Checkouts[i], false, nil
		}
	}
	c := Checkout{Project: f.Project, Path: abs, Added: now, Seen: now}
	r.Checkouts = append(r.Checkouts, c)
	return c, true, nil
}

// Remove forgets the checkout at dir. It reports whether there was one.
func (r *Registry) Remove(dir string) bool {
	abs, _ := filepath.Abs(dir)
	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		abs = resolved
	}
	for i, c := range r.Checkouts {
		if c.Path == abs || c.Path == dir {
			r.Checkouts = append(r.Checkouts[:i], r.Checkouts[i+1:]...)
			return true
		}
	}
	return false
}

// Status says whether a checkout is still there.
type Status string

// Checkout statuses.
const (
	StatusOK    Status = "ok"
	StatusGone  Status = "gone"  // the directory or its esec.toml is gone
	StatusMoved Status = "moved" // its esec.toml names another project now
)

// Check looks at a checkout on disk.
func Check(c Checkout) Status {
	f, err := projectfile.Load(c.Path)
	switch {
	case err != nil:
		return StatusGone
	case f.Project != c.Project:
		return StatusMoved
	}
	return StatusOK
}

// Prune forgets checkouts that are gone, returning them.
func (r *Registry) Prune() []Checkout {
	var kept, gone []Checkout
	for _, c := range r.Checkouts {
		if Check(c) == StatusGone {
			gone = append(gone, c)
			continue
		}
		kept = append(kept, c)
	}
	r.Checkouts = kept
	return gone
}

// Projects groups the checkouts by project id.
func (r *Registry) Projects() map[string][]Checkout {
	out := map[string][]Checkout{}
	for _, c := range r.Checkouts {
		out[c.Project] = append(out[c.Project], c)
	}
	return out
}

// skipDirs are never searched by Scan.
var skipDirs = map[string]bool{
	".git": true, "node_modules": true, "vendor": true, ".venv": true, "target": true,
	"dist": true, "build": true, ".cache": true, "Library": true, ".Trash": true,
}

// Scan finds every esec.toml under root, at most depth levels down, and
// adds each checkout. It returns the checkouts it found.
func (r *Registry) Scan(root string, depth int, now time.Time) ([]Checkout, error) {
	root, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	if resolved, err := filepath.EvalSymlinks(root); err == nil {
		root = resolved // WalkDir does not follow a symlinked root (~/src → /Volumes/…)
	}
	base := strings.Count(root, string(filepath.Separator))
	var found []Checkout
	var errs []error
	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if p == root {
				return err
			}
			return nil
		}
		if !d.IsDir() {
			return nil
		}
		if p != root && (skipDirs[d.Name()] || strings.Count(p, string(filepath.Separator))-base > depth) {
			return filepath.SkipDir
		}
		if _, statErr := os.Stat(filepath.Join(p, projectfile.ProjectFileName)); statErr != nil {
			return nil //nolint:nilerr // no esec.toml here: keep looking
		}
		c, _, err := r.Add(p, now)
		if err != nil {
			errs = append(errs, err)
			return nil
		}
		found = append(found, c)
		return nil
	})
	if err != nil {
		return found, err
	}
	return found, errors.Join(errs...)
}

// GitRepo returns the git common directory of the repository holding dir
// (the same for all its worktrees), and whether dir is in its main
// worktree. common is "" outside git.
func GitRepo(dir string) (common string, main bool) {
	out, err := exec.Command("git", "-C", dir, "rev-parse", "--path-format=absolute", "--git-common-dir", "--git-dir").Output()
	if err != nil {
		return "", false
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) != 2 {
		return "", false
	}
	return lines[0], lines[0] == lines[1]
}
