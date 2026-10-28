package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
	"github.com/mscno/esec/pkg/projectfile"

	"github.com/mscno/esec-vault/internal/keystore"
)

// guardEnv is a machine with a guard held by a software key standing in
// for a YubiKey: ESEC_VAULT_GUARD_IDENTITIES points at it.
type guardRig struct {
	t    *testing.T
	bin  string
	home string
	env  []string
}

func newGuardRig(t *testing.T) *guardRig {
	t.Helper()
	home := t.TempDir()
	yubi, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	idFile := filepath.Join(t.TempDir(), "identities.txt")
	if err := os.WriteFile(idFile, []byte(yubi.String()+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	r := &guardRig{t: t, bin: buildCLI(t), home: home, env: append(os.Environ(),
		"ESEC_VAULT_HOME="+home, "ESEC_KEYRING_DIR=", "ESEC_CONFIG=", "ESEC_VAULT_DIALOGS=off",
		"ESEC_VAULT_GUARD_IDENTITIES="+idFile, "ESEC_VAULT_SERVER=", "XDG_CONFIG_HOME=",
		// Never the person's keychain: a 0600 file in the test's home.
		"ESEC_SECRET_STORE=file")}
	r.must("", "", "guard", "init", "--holder", yubi.Recipient().String(), "--no-recovery")
	return r
}

func (r *guardRig) run(dir, stdin string, args ...string) (string, int) {
	r.t.Helper()
	cmd := exec.Command(r.bin, args...)
	cmd.Dir, cmd.Env = dir, r.env
	cmd.Stdin = strings.NewReader(stdin)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	if exit, ok := err.(*exec.ExitError); ok {
		return out.String(), exit.ExitCode()
	} else if err != nil {
		r.t.Fatal(err)
	}
	return out.String(), 0
}

func (r *guardRig) must(dir, stdin string, args ...string) string {
	r.t.Helper()
	out, code := r.run(dir, stdin, args...)
	if code != 0 {
		r.t.Fatalf("esec-vault %v: exit %d\n%s", args, code, out)
	}
	return out
}

func TestGuardedProjectLifecycle(t *testing.T) { //nolint:gocyclo // one story, step by step
	r := newGuardRig(t)
	repo := initTestRepo(t)

	// Born guarded: prod's key never exists in the clear on disk.
	r.must(repo, "", "project", "init", "acme/store", "--env", "dev,prod", "--guard", "prod", "--format", "env")
	pf, err := projectfile.Load(repo)
	if err != nil {
		t.Fatal(err)
	}
	if pf.Env["prod"].Guard != "touch" || pf.Env["prod"].Key == "" || pf.Env["dev"].GuardLevel() != "none" || pf.Files.Format != "env" {
		t.Fatalf("esec.toml: %+v", pf)
	}
	t.Setenv("ESEC_VAULT_HOME", r.home)
	t.Setenv("ESEC_KEYRING_DIR", "")
	entries, err := keystore.New().Read("acme/store")
	if err != nil {
		t.Fatal(err)
	}
	if _, isClear := entries[keystore.EnvEntry("prod")]; isClear || entries[keystore.GuardEnvEntry("prod")] != pf.Env["prod"].Key || entries[keystore.GuardEntry(pf.Env["prod"].Key)] == "" {
		t.Fatalf("prod key not guarded: %v", keys(entries))
	}
	if _, isClear := entries[keystore.PubEntry(pf.Env["prod"].Key)]; isClear {
		t.Fatal("prod key filed in the clear")
	}

	// Listed as guarded; never printed.
	var list []struct {
		Env     string `json:"env"`
		Guarded bool   `json:"guarded"`
	}
	if err := json.Unmarshal([]byte(r.must(repo, "", "env", "list", "--json")), &list); err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 || !list[1].Guarded || list[1].Env != "prod" {
		t.Fatalf("env list: %+v", list)
	}
	if out, code := r.run(repo, "y\n", "env", "show-key", "prod"); code == 0 {
		t.Fatalf("show-key printed a guarded key: %s", out)
	}

	// Writing a prod value needs only the public key.
	r.must(repo, "sk_live_123\n", "secrets", "set", "API_KEY", "--env", "prod", "--create")
	if out := r.must(repo, "", "guard", "check"); !strings.Contains(out, "1 guarded key(s) checked") {
		t.Fatalf("check: %s", out)
	}

	// Rotation opens the old key with the guard and guards the new one.
	r.must(repo, "", "env", "rotate", "prod", "--yes")
	pf2, _ := projectfile.Load(repo)
	if pf2.Env["prod"].Key == pf.Env["prod"].Key || pf2.Env["prod"].Guard != "touch" {
		t.Fatalf("rotation: %+v", pf2.Env["prod"])
	}
	entries, _ = keystore.New().Read("acme/store")
	if entries[keystore.GuardEntry(pf.Env["prod"].Key)] == "" || entries[keystore.GuardEntry(pf2.Env["prod"].Key)] == "" {
		t.Fatalf("rotation lost a guarded key: %v", keys(entries))
	}
	if out := r.must(repo, "", "guard", "check"); !strings.Contains(out, "2 guarded key(s) checked") {
		t.Fatalf("check after rotate: %s", out)
	}

	// Guarding an existing environment later.
	r.must(repo, "", "guard", "enable", "--env", "dev", "--level", "session")
	pf3, _ := projectfile.Load(repo)
	if pf3.Env["dev"].Guard != "session" {
		t.Fatalf("enable: %+v", pf3.Env["dev"])
	}
	status := r.must(repo, "", "guard", "--json")
	if !strings.Contains(status, `"envs": [`) || !strings.Contains(status, `"dev"`) {
		t.Fatalf("status: %s", status)
	}

	// Export writes plain age files.
	out := filepath.Join(t.TempDir(), "export")
	r.must(repo, "", "guard", "export", "--out", out)
	files, _ := filepath.Glob(filepath.Join(out, "acme_store.*.age"))
	if len(files) != 3 {
		t.Fatalf("export: %v", files)
	}
}

func TestGuardInitRefusesTwice(t *testing.T) {
	r := newGuardRig(t)
	if out, code := r.run("", "", "guard", "init", "--holder", "age1qyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqs3290gq", "--no-recovery"); code == 0 || !strings.Contains(out, "set up already") {
		t.Fatalf("second init: %d %s", code, out)
	}
}

func keys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestProjectsRegistryAndVerify(t *testing.T) {
	r := newGuardRig(t)
	src := t.TempDir()
	a, b := filepath.Join(src, "a"), filepath.Join(src, "b")
	for dir, id := range map[string]string{a: "acme/a", b: "acme/b"} {
		if err := os.MkdirAll(dir, 0750); err != nil {
			t.Fatal(err)
		}
		if _, err := runGit(dir, "init"); err != nil {
			t.Fatal(err)
		}
		r.must(dir, "", "project", "init", id, "--env", "dev,prod", "--format", "env")
	}
	// project init remembered both checkouts.
	var views []projectView
	if err := json.Unmarshal([]byte(r.must("", "", "projects", "--json")), &views); err != nil {
		t.Fatal(err)
	}
	if len(views) != 2 || len(views[0].Checkouts) != 1 || len(views[0].Envs) != 2 || views[0].Envs[0].Here != "clear" {
		t.Fatalf("projects: %+v", views)
	}
	// Forget one, find it again by scanning.
	r.must("", "", "projects", "remove", b)
	if out := r.must("", "", "projects", "scan", src); !strings.Contains(out, "2 checkout(s)") {
		t.Fatalf("scan: %s", out)
	}

	// Each key is unique and on this device only: one place, no reuse.
	out, code := r.run("", "", "verify", "--no-server", "--no-backup", "--json")
	if code == 0 || !strings.Contains(out, "in one place only") || strings.Contains(out, "several projects") {
		t.Fatalf("verify: %d %s", code, out)
	}
	// A secrets file copied from a to b: one key now serves two projects.
	data, err := os.ReadFile(filepath.Join(a, ".env.prod")) //nolint:gosec // a test checkout
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(b, ".env.staging"), data, 0600); err != nil { //nolint:gosec // a test checkout
		t.Fatal(err)
	}
	out, _ = r.run("", "", "verify", "--no-server", "--no-backup")
	if !strings.Contains(out, "one key serves several projects: acme/a, acme/b") {
		t.Fatalf("reuse not caught: %s", out)
	}
	// Only a full check is kept for doctor and the Mac app.
	if _, err := os.Stat(filepath.Join(r.home, "verify.json")); err == nil {
		t.Fatal("a partial check was kept")
	}
	r.run("", "", "verify")
	if _, err := os.Stat(filepath.Join(r.home, "verify.json")); err != nil {
		t.Fatal(err)
	}
}
