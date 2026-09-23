package keystore

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mscno/esec"
	"github.com/mscno/esec/pkg/projectfile"
)

func TestWriteReadList(t *testing.T) {
	s := &Store{Dir: filepath.Join(t.TempDir(), "keyrings")}
	entries := map[string]string{"ESEC_PRIVATE_KEY_DEV": "aaaa", "ESEC_PRIVATE_KEY_PROD": "bbbb"}
	if err := s.Write("org/repo_name", entries, false); err != nil {
		t.Fatal(err)
	}
	// Underscores in the repo name must survive the round trip.
	back, err := s.Read("org/repo_name")
	if err != nil {
		t.Fatal(err)
	}
	if back["ESEC_PRIVATE_KEY_DEV"] != "aaaa" {
		t.Fatalf("round trip mismatch: %v", back)
	}

	// File permissions.
	p := filepath.Join(s.Dir, "org_repo_name.keyring")
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0600 {
		t.Fatalf("keyring must be 0600, got %o", fi.Mode().Perm())
	}

	// Refuse overwrite without force.
	if err := s.Write("org/repo_name", entries, false); err == nil {
		t.Fatal("expected overwrite refusal")
	}
	if err := s.Write("org/repo_name", entries, true); err != nil {
		t.Fatal(err)
	}

	projects, err := s.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(projects) != 1 || projects[0] != "org/repo_name" {
		t.Fatalf("unexpected list: %v", projects)
	}
}

func TestWriteRefusesSymlink(t *testing.T) {
	s := &Store{Dir: t.TempDir()}
	p := filepath.Join(s.Dir, "org_repo.keyring")
	target := filepath.Join(t.TempDir(), "target")
	if err := os.WriteFile(target, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, p); err != nil {
		t.Fatal(err)
	}
	err := s.Write("org/repo", map[string]string{"K": "V"}, true)
	if err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("expected symlink refusal, got %v", err)
	}
}

func TestMigrate(t *testing.T) {
	// isolation from any real global store
	t.Setenv(esec.EsecKeyringDir, t.TempDir())

	s := &Store{Dir: filepath.Join(t.TempDir(), "keyrings")}
	repo := t.TempDir()
	if err := projectfile.WriteProjectFile(repo, "org/repo"); err != nil {
		t.Fatal(err)
	}
	local := filepath.Join(repo, esec.DefaultKeyringFilename)
	content := "ESEC_PRIVATE_KEY_DEV=aaaa\n"
	if err := os.WriteFile(local, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	project, err := s.Migrate(repo, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if project != "org/repo" {
		t.Fatalf("unexpected project %s", project)
	}
	// Local file kept (no deleteLocal), global copy present.
	if _, err := os.Stat(local); err != nil {
		t.Fatal("local keyring should still exist")
	}
	back, err := s.Read("org/repo")
	if err != nil || back["ESEC_PRIVATE_KEY_DEV"] != "aaaa" {
		t.Fatalf("global keyring wrong: %v %v", back, err)
	}
	// .gitignore updated.
	gi, err := os.ReadFile(filepath.Join(repo, ".gitignore"))
	if err != nil || !strings.Contains(string(gi), esec.DefaultKeyringFilename) {
		t.Fatalf(".gitignore missing entry: %v %v", string(gi), err)
	}

	// Second migrate must refuse to clobber a different existing global copy.
	if err := os.WriteFile(local, []byte("ESEC_PRIVATE_KEY_DEV=cccc\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Migrate(repo, false, nil); err == nil {
		t.Fatal("expected refusal to overwrite existing global keyring")
	}

	// With deleteLocal + confirmed, the local file goes away.
	if err := os.WriteFile(local, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	_, err = s.Migrate(repo, true, func(string) bool { return true })
	// overwrites allowed? No: Write(force=false) fails because global exists.
	if err == nil {
		t.Fatal("expected refusal because global keyring exists")
	}
}

func TestMigrateDeleteLocal(t *testing.T) {
	s := &Store{Dir: filepath.Join(t.TempDir(), "keyrings")}
	repo := t.TempDir()
	if err := projectfile.WriteProjectFile(repo, "org/repo"); err != nil {
		t.Fatal(err)
	}
	local := filepath.Join(repo, esec.DefaultKeyringFilename)
	if err := os.WriteFile(local, []byte("ESEC_PRIVATE_KEY_DEV=aaaa\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Migrate(repo, true, func(string) bool { return true }); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(local); !os.IsNotExist(err) {
		t.Fatal("local keyring should be deleted")
	}
}
