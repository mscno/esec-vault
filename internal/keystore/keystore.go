// Package keystore manages the global keyring store: project-keyed keyring
// files living outside repository working directories (by default
// ~/.config/esec/keyrings/<org>_<repo>.keyring).
package keystore

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/joho/godotenv"
	"github.com/mscno/esec"
	"github.com/mscno/esec/pkg/projectfile"

	"github.com/mscno/esec-vault/internal/paths"
)

// Store is the global keyring store rooted at Dir.
type Store struct {
	Dir string
}

// New returns the default store honoring ESEC_KEYRING_DIR / ~/.config.
func New() *Store { return &Store{Dir: paths.KeyringDir()} }

// Read returns the keyring entries for a project.
func (s *Store) Read(project string) (map[string]string, error) {
	p, err := s.path(project)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(p) //nolint:gosec // path derived from a validated project id inside the store dir
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return godotenv.Parse(f)
}

// Write atomically writes the project's keyring (0600). It refuses to follow
// symlinks and, unless force is set, to overwrite an existing file.
func (s *Store) Write(project string, entries map[string]string, force bool) error {
	p, err := s.path(project)
	if err != nil {
		return err
	}
	if _, err := os.Lstat(p); err == nil {
		if !force {
			return fmt.Errorf("keyring already exists at %s (use force to overwrite)", p)
		}
		if fi, _ := os.Lstat(p); fi.Mode()&fs.ModeSymlink != 0 {
			return fmt.Errorf("refusing to follow symlink at %s", p)
		}
	}
	if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
		return err
	}

	var buf bytes.Buffer
	buf.WriteString("###########################################################\n")
	buf.WriteString("### Private key file - Do not commit to version control ###\n")
	buf.WriteString("###########################################################\n\n")
	keys := make([]string, 0, len(entries))
	for k := range entries {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(&buf, "%s=%s\n", k, entries[k])
	}

	tmp, err := os.CreateTemp(filepath.Dir(p), ".keyring-*.tmp")
	if err != nil {
		return err
	}
	if _, err := tmp.Write(buf.Bytes()); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	return os.Rename(tmp.Name(), p)
}

// Delete removes a project's keyring.
func (s *Store) Delete(project string) error {
	p, err := s.path(project)
	if err != nil {
		return err
	}
	return os.Remove(p)
}

// List returns the project identifiers with keyrings in the store.
func (s *Store) List() ([]string, error) {
	entries, err := os.ReadDir(s.Dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var projects []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".keyring") || name == esec.DefaultKeyringBasename {
			continue
		}
		stem := strings.TrimSuffix(name, ".keyring")
		// GitHub org names cannot contain underscores, so the first underscore
		// is the org/repo separator; repo names may contain further underscores.
		org, repo, ok := strings.Cut(stem, "_")
		if !ok || projectfile.ValidateOrgRepo(org+"/"+repo) != nil {
			continue
		}
		projects = append(projects, org+"/"+repo)
	}
	sort.Strings(projects)
	return projects, nil
}

// Migrate walks repoDir for repo-local .esec-keyring files and moves each into
// the global store, keyed by the nearest .esec-project (monorepo subtrees with
// their own marker get their own store entry). It returns the migrated project
// identifiers; per-directory failures are collected and returned together.
func (s *Store) Migrate(repoDir string, deleteLocal bool, confirm func(question string) bool) ([]string, error) {
	var migrated []string
	var errs []error
	err := filepath.WalkDir(repoDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Name() != esec.DefaultKeyringFilename {
			return nil
		}
		dir := filepath.Dir(path)
		project, _, perr := projectfile.FindProjectFile(dir)
		if perr != nil {
			errs = append(errs, fmt.Errorf("%s: no .esec-project found: %w", dir, perr))
			return nil
		}
		if err := s.migrateOne(dir, project, deleteLocal, confirm); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", dir, err))
			return nil
		}
		migrated = append(migrated, project)
		return nil
	})
	if err != nil {
		return migrated, err
	}
	if len(migrated) == 0 && len(errs) == 0 {
		return nil, fmt.Errorf("no repo-local %s files found under %s", esec.DefaultKeyringFilename, repoDir)
	}
	return migrated, errors.Join(errs...)
}

// migrateOne moves a single repo-local keyring into the global store.
// The repo-local file is removed only after the global copy has been verified
// by reading it back, and only when deleteLocal is set and confirmed.
// ".esec-keyring" is ensured in the repo's .gitignore.
func (s *Store) migrateOne(repoDir, project string, deleteLocal bool, confirm func(question string) bool) error {
	localPath := filepath.Join(repoDir, esec.DefaultKeyringFilename)
	f, err := os.Open(localPath) //nolint:gosec // repoDir is user-provided
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("no repo-local keyring at %s", localPath)
		}
		return err
	}
	entries, err := godotenv.Parse(f)
	f.Close()
	if err != nil {
		return fmt.Errorf("failed to parse %s: %w", localPath, err)
	}

	if err := s.Write(project, entries, false); err != nil {
		return err
	}

	// Verify the written copy before any deletion.
	back, err := s.Read(project)
	if err != nil || !equalMap(entries, back) {
		return fmt.Errorf("verification failed after writing global keyring; local file left untouched")
	}

	if deleteLocal {
		if confirm != nil && !confirm(fmt.Sprintf("Delete repo-local %s?", localPath)) {
			return fmt.Errorf("aborted before deleting local file; global copy is in place")
		}
		if err := os.Remove(localPath); err != nil {
			return fmt.Errorf("failed to remove %s: %w", localPath, err)
		}
	}

	// Ensure gitignore at the git root (or the keyring's own directory).
	root := repoDir
	if _, gitErr := os.Stat(filepath.Join(repoDir, ".git")); gitErr != nil {
		if gitRoot, found := findGitRoot(repoDir); found {
			root = gitRoot
		}
	}
	if err := ensureGitignore(root, esec.DefaultKeyringFilename); err != nil {
		return fmt.Errorf("keyring migrated, but failed to update .gitignore: %w", err)
	}
	return nil
}

// findGitRoot walks up from dir looking for a .git entry.
func findGitRoot(dir string) (string, bool) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return dir, false
	}
	for {
		if _, err := os.Stat(filepath.Join(abs, ".git")); err == nil {
			return abs, true
		}
		parent := filepath.Dir(abs)
		if parent == abs {
			return "", false
		}
		abs = parent
	}
}

// path returns the keyring path for a project identifier.
func (s *Store) path(project string) (string, error) {
	if err := projectfile.ValidateOrgRepo(project); err != nil {
		return "", err
	}
	return filepath.Join(s.Dir, projectfile.KeyringName(project)), nil
}

func equalMap(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

func ensureGitignore(repoDir, entry string) error {
	path := filepath.Join(repoDir, ".gitignore")
	data, err := os.ReadFile(path) //nolint:gosec // repoDir is user-provided
	if err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.TrimSpace(line) == entry {
				return nil
			}
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644) //nolint:gosec // repoDir is user-provided
	if err != nil {
		return err
	}
	defer f.Close()
	prefix := ""
	if len(data) > 0 && !strings.HasSuffix(string(data), "\n") {
		prefix = "\n"
	}
	_, err = f.WriteString(prefix + entry + "\n")
	return err
}
