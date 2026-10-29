package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/mscno/esec-vault/internal/keystore"
	"github.com/mscno/esec/pkg/projectfile"
	coreseal "github.com/mscno/esec/pkg/seal"
)

func TestEnvironmentRenameLocalAndGuarded(t *testing.T) { //nolint:gocyclo // sequential guarded and unguarded lifecycle assertions
	r := newGuardRig(t)
	repo := initTestRepo(t)
	r.must(repo, "", "project", "init", "acme/rename", "--env", "dev,prod", "--guard", "prod", "--format", "env")
	pf, err := projectfile.Load(repo)
	if err != nil {
		t.Fatal(err)
	}
	old := pf.Env["prod"]
	before, err := os.ReadFile(filepath.Join(repo, ".env.prod")) //nolint:gosec // test checkout
	if err != nil {
		t.Fatal(err)
	}
	r.must(repo, "", "env", "rename", "prod", "production", "--yes")
	after, err := os.ReadFile(filepath.Join(repo, ".env.production")) //nolint:gosec // test checkout
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("ciphertext changed: %v", err)
	}
	pf, err = projectfile.Load(repo)
	if err != nil {
		t.Fatal(err)
	}
	if pf.Env["production"].Key != old.Key || pf.Env["production"].Guard != old.Guard {
		t.Fatal("rename changed key or guard")
	}
	if _, ok := pf.Env["prod"]; ok {
		t.Fatal("old marker environment remains")
	}
	data, err := coreseal.Read(repo, "production")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := coreseal.Open(data, pf.Project, "production", old.Key, r.yubi); err != nil {
		t.Fatal(err)
	}
	r.must(repo, "", "seal", "check")
	t.Setenv("ESEC_VAULT_HOME", r.home)
	t.Setenv("ESEC_KEYRING_DIR", "")
	entries, err := keystore.New().Read(pf.Project)
	if err != nil {
		t.Fatal(err)
	}
	if entries[keystore.EnvEntry("production")] != "" || entries[keystore.PubEntry(old.Key)] != "" {
		t.Fatal("guarded private key cached in clear")
	}
	// Files are optional; an unguarded rename still updates its sealed key.
	if err := os.Remove(filepath.Join(repo, ".env.dev")); err != nil {
		t.Fatal(err)
	}
	r.must(repo, "", "env", "rename", "dev", "development", "--yes")
	r.must(repo, "", "seal", "check")
	entries, err = keystore.New().Read(pf.Project)
	if err != nil {
		t.Fatal(err)
	}
	if entries[keystore.EnvEntry("development")] == "" || entries[keystore.EnvEntry("dev")] != "" {
		t.Fatal("named keyring entries not moved")
	}
	// Existing destinations must not be overwritten, even for filename aliases.
	if err := os.WriteFile(filepath.Join(repo, ".env.live"), []byte("do not replace"), 0600); err != nil {
		t.Fatal(err)
	}
	if out, code := r.run(repo, "", "env", "rename", "production", "live", "--yes"); code == 0 {
		t.Fatalf("collision accepted: %s", out)
	}
	pf, err = projectfile.Load(repo)
	if err != nil {
		t.Fatal(err)
	}
	if pf.Env["production"].Key != old.Key {
		t.Fatal("collision changed marker")
	}
}
