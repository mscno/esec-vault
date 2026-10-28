package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/mscno/esec/pkg/projectfile"

	"github.com/mscno/esec-vault/internal/keystore"
)

// Running project init again on a project whose prod key is guarded keeps
// that key: it never makes a clear prod key beside it.
func TestProjectInitAgainKeepsGuardedKey(t *testing.T) {
	r := newGuardRig(t)
	repo := initTestRepo(t)
	r.must(repo, "", "project", "init", "acme/store", "--env", "dev,prod", "--format", "env", "--offline")
	r.must(repo, "", "guard", "enable", "--env", "prod")
	before, _ := projectfile.Load(repo)

	r.must(repo, "", "project", "init", "acme/store", "--env", "dev,prod", "--guard", "prod", "--format", "env", "--offline")
	after, _ := projectfile.Load(repo)
	if after.Env["prod"] != before.Env["prod"] {
		t.Fatalf("prod changed: %+v → %+v", before.Env["prod"], after.Env["prod"])
	}
	t.Setenv("ESEC_VAULT_HOME", r.home)
	t.Setenv("ESEC_KEYRING_DIR", "")
	entries, err := keystore.New().Read("acme/store")
	if err != nil {
		t.Fatal(err)
	}
	if _, inClear := entries[keystore.EnvEntry("prod")]; inClear {
		t.Fatalf("a clear prod key was made beside the guarded one: %v", keys(entries))
	}
}

// Agents run many commands at once: none fails because another holds the
// keys, none loses another's change to esec.toml or the registry, and the
// person's comments in esec.toml stay.
func TestManyAgentsAtOnce(t *testing.T) {
	r := newGuardRig(t)
	repo := initTestRepo(t)
	r.must(repo, "", "project", "init", "acme/store", "--env", "dev", "--format", "env", "--offline")
	toml := filepath.Join(repo, projectfile.ProjectFileName)
	data, err := os.ReadFile(toml) //nolint:gosec // a test checkout
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(toml, append([]byte("# Owner: platform team\n"), data...), 0o600); err != nil { //nolint:gosec // a test checkout
		t.Fatal(err)
	}

	envs := []string{"qa", "staging", "preview", "perf", "demo", "sandbox"}
	var wg sync.WaitGroup
	errs := make(chan string, len(envs))
	for _, env := range envs {
		wg.Go(func() {
			if out, code := r.run(repo, "", "env", "add", env, "--offline"); code != 0 {
				errs <- fmt.Sprintf("env add %s: %d %s", env, code, out)
			}
		})
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Error(e)
	}
	f, err := projectfile.Load(repo)
	if err != nil {
		t.Fatal(err)
	}
	for _, env := range append(envs, "dev") {
		if f.Env[env].Key == "" {
			t.Errorf("esec.toml lost %s: %v", env, f.Envs())
		}
	}
	if data, _ := os.ReadFile(toml); !strings.HasPrefix(string(data), "# Owner: platform team\n") { //nolint:gosec // a test checkout
		t.Errorf("comment lost:\n%s", data)
	}

	// Many checkouts found at once are all remembered.
	src := t.TempDir()
	dirs := make([]string, 0, 12)
	for i := range 12 {
		dir := filepath.Join(src, fmt.Sprintf("p%d", i))
		if err := os.MkdirAll(dir, 0o750); err != nil {
			t.Fatal(err)
		}
		if err := projectfile.WriteProjectFile(dir, fmt.Sprintf("acme/p%d", i)); err != nil {
			t.Fatal(err)
		}
		dirs = append(dirs, dir)
	}
	for _, dir := range dirs {
		wg.Go(func() { r.run(dir, "", "env", "list") })
	}
	wg.Wait()
	var views []projectView
	if err := json.Unmarshal([]byte(r.must("", "", "projects", "--json")), &views); err != nil {
		t.Fatal(err)
	}
	if len(views) != 13 {
		t.Fatalf("registry kept %d of 13 projects", len(views))
	}

	// A symlinked root is followed.
	link := filepath.Join(t.TempDir(), "src")
	if err := os.Symlink(src, link); err != nil {
		t.Fatal(err)
	}
	if out := r.must("", "", "projects", "scan", link); !strings.Contains(out, "12 checkout(s)") {
		t.Fatalf("scan through a symlink: %s", out)
	}
}

// secrets lint checks each file against the key esec.toml names, with no
// network: a file copied from another environment fails.
func TestLintAgainstProjectFile(t *testing.T) {
	r := newGuardRig(t)
	repo := initTestRepo(t)
	r.must(repo, "", "project", "init", "acme/store", "--env", "dev,staging", "--format", "env", "--offline")
	if out := r.must(repo, "", "secrets", "lint"); !strings.Contains(out, "every value encrypted") {
		t.Fatalf("lint: %s", out)
	}
	data, err := os.ReadFile(filepath.Join(repo, ".env.staging")) //nolint:gosec // a test checkout
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, ".env.dev"), data, 0o600); err != nil { //nolint:gosec // a test checkout
		t.Fatal(err)
	}
	if out, code := r.run(repo, "", "secrets", "lint"); code == 0 || !strings.Contains(out, "esec.toml names") {
		t.Fatalf("lint passed a file encrypted to another environment's key: %d %s", code, out)
	}
}
