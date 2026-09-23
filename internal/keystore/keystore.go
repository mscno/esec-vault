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

// Migrate moves a repository's repo-local .esec-keyring into the global store.
// The project identifier comes from the repo's .esec-project. When deleteLocal
// is set, the repo-local file is removed only after the global copy has been
// verified by reading it back. ".esec-keyring" is ensured in .gitignore.
func (s *Store) Migrate(repoDir string, deleteLocal bool, confirm func(question string) bool) (string, error) {
	project, err := projectfile.ReadProjectFile(repoDir)
	if err != nil {
		return "", fmt.Errorf("%s: %w (create one with ESEC_PROJECT=org/repo)", repoDir, err)
	}

	localPath := filepath.Join(repoDir, esec.DefaultKeyringFilename)
	f, err := os.Open(localPath) //nolint:gosec // repoDir is user-provided
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("no repo-local keyring at %s", localPath)
		}
		return "", err
	}
	entries, err := godotenv.Parse(f)
	f.Close()
	if err != nil {
		return "", fmt.Errorf("failed to parse %s: %w", localPath, err)
	}

	if err := s.Write(project, entries, false); err != nil {
		return "", err
	}

	// Verify the written copy before any deletion.
	back, err := s.Read(project)
	if err != nil || !equalMap(entries, back) {
		return "", fmt.Errorf("verification failed after writing global keyring; local file left untouched")
	}

	if deleteLocal {
		if confirm != nil && !confirm(fmt.Sprintf("Delete repo-local %s?", localPath)) {
			return project, fmt.Errorf("aborted before deleting local file; global copy is in place")
		}
		if err := os.Remove(localPath); err != nil {
			return "", fmt.Errorf("failed to remove %s: %w", localPath, err)
		}
	}

	if err := ensureGitignore(repoDir, esec.DefaultKeyringFilename); err != nil {
		return project, fmt.Errorf("keyring migrated, but failed to update .gitignore: %w", err)
	}
	return project, nil
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
