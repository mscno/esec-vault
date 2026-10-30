package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"filippo.io/age"
	"github.com/mscno/esec"
	"github.com/mscno/esec/pkg/projectfile"
	coreseal "github.com/mscno/esec/pkg/seal"

	"github.com/mscno/esec-vault/internal/keystore"
)

// guardEnv is a machine with a guard held by a software key standing in
// for a YubiKey: ESEC_VAULT_GUARD_IDENTITIES points at it.
type guardRig struct {
	t    *testing.T
	bin  string
	home string
	env  []string
	// yubi stands in for a YubiKey: its recipient counts as this person's
	// security key.
	yubi *age.X25519Identity
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
	r.must("", "", "identity", "init", "--no-passphrase", "--skip-confirm")
	r.yubi = yubi
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

	// Born sealed: dev for me, prod for my security key; both to my
	// recovery key. prod's key never exists in the clear on this device.
	r.must(repo, "", "project", "init", "acme/store", "--env", "dev,prod", "--guard", "prod", "--format", "env")
	pf, err := projectfile.Load(repo)
	if err != nil {
		t.Fatal(err)
	}
	if pf.Env["prod"].Guard != "touch" || pf.Env["prod"].Key == "" || pf.Env["dev"].GuardLevel() != "none" || len(pf.Env["dev"].Readers) != 1 {
		t.Fatalf("esec.toml: %+v", pf)
	}
	for _, env := range []string{"dev", "prod"} {
		if _, err := os.Stat(filepath.Join(repo, ".esec", env+".age")); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("ESEC_VAULT_HOME", r.home)
	t.Setenv("ESEC_KEYRING_DIR", "")
	entries, err := keystore.New().Read("acme/store")
	if err != nil {
		t.Fatal(err)
	}
	if entries[keystore.PubEntry(pf.Env["prod"].Key)] != "" || entries[keystore.EnvEntry("prod")] != "" {
		t.Fatalf("prod's key is in the clear here: %v", keys(entries))
	}
	if entries[keystore.PubEntry(pf.Env["dev"].Key)] == "" {
		t.Fatal("dev's key was not cached")
	}
	// The seals are standard age files: the stand-in YubiKey opens prod's;
	// dev's does not open with it.
	prodSeal, _ := os.ReadFile(filepath.Join(repo, ".esec", "prod.age")) //nolint:gosec // a test checkout
	if _, err := coreseal.Open(prodSeal, "acme/store", "prod", pf.Env["prod"].Key, r.yubi); err != nil {
		t.Fatalf("the security key does not open prod: %v", err)
	}
	devSeal, _ := os.ReadFile(filepath.Join(repo, ".esec", "dev.age")) //nolint:gosec // a test checkout
	if _, err := coreseal.Open(devSeal, "acme/store", "dev", "", r.yubi); err == nil {
		t.Fatal("dev is sealed to the security key: it should need only the user key")
	}
	if out := r.must(repo, "", "seal", "check"); !strings.Contains(out, "sealed, signed, and recoverable") {
		t.Fatalf("seal check: %s", out)
	}

	// Never printed.
	if out, code := r.run(repo, "y\n", "env", "show-key", "prod"); code == 0 {
		t.Fatalf("show-key printed a guarded key: %s", out)
	}
	// Writing a prod value needs only the public key.
	r.must(repo, "sk_live_123\n", "secrets", "set", "API_KEY", "--env", "prod", "--create")

	// Rotation opens the old key with the security key and seals the new
	// one the same way.
	r.must(repo, "", "env", "rotate", "prod", "--yes")
	pf2, _ := projectfile.Load(repo)
	if pf2.Env["prod"].Key == pf.Env["prod"].Key || pf2.Env["prod"].Guard != "touch" {
		t.Fatalf("rotation: %+v", pf2.Env["prod"])
	}
	prodSeal, _ = os.ReadFile(filepath.Join(repo, ".esec", "prod.age")) //nolint:gosec // a test checkout
	p, err := coreseal.Open(prodSeal, "acme/store", "prod", pf2.Env["prod"].Key, r.yubi)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := esec.DecryptFile(filepath.Join(repo, ".env.prod"), "", p.Private)
	if err != nil || !strings.Contains(string(plain), "sk_live_123") {
		t.Fatalf("rotated prod: %s %v", plain, err)
	}

	// Guarding an existing environment later, and back.
	r.must(repo, "", "guard", "enable", "--env", "dev", "--level", "session")
	pf3, _ := projectfile.Load(repo)
	entries, _ = keystore.New().Read("acme/store")
	if pf3.Env["dev"].Guard != "session" || entries[keystore.PubEntry(pf3.Env["dev"].Key)] != "" {
		t.Fatalf("enable: %+v, cached: %v", pf3.Env["dev"], keys(entries))
	}
	if status := r.must(repo, "", "guard", "--json"); !strings.Contains(status, `"dev"`) || !strings.Contains(status, `"set_up": true`) {
		t.Fatalf("status: %s", status)
	}
	r.must(repo, "", "guard", "disable", "--env", "dev")
	entries, _ = keystore.New().Read("acme/store")
	if entries[keystore.PubEntry(pf3.Env["dev"].Key)] == "" {
		t.Fatal("disable did not cache dev's key again")
	}

	// A CI key reads prod with plain esec and ESEC_AGE_IDENTITY.
	out := r.must(repo, "", "ci", "add", "deploy", "--env", "prod")
	var ciKey string
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "AGE-SECRET-KEY-1") {
			ciKey = line
		}
	}
	if ciKey == "" {
		t.Fatalf("no CI key printed: %s", out)
	}
	esecDecrypt := func() ([]byte, error) {
		cmd := exec.Command(buildEsec(t), "decrypt", "prod")
		cmd.Dir = repo
		cmd.Env = append(os.Environ(), "ESEC_AGE_IDENTITY="+ciKey, "ESEC_KEYRING_DIR="+t.TempDir(), "ESEC_VAULT_HOME="+t.TempDir(), "ESEC_CONFIG=")
		return cmd.CombinedOutput()
	}
	if got, err := esecDecrypt(); err != nil || !strings.Contains(string(got), "sk_live_123") {
		t.Fatalf("CI with esec alone: %v\n%s", err, got)
	}
	r.must(repo, "", "ci", "remove", "deploy")
	if _, err := esecDecrypt(); err == nil {
		t.Fatal("a removed CI key still reads prod")
	}

	// Tampering with esec.toml is caught with no network.
	data, _ := os.ReadFile(filepath.Join(repo, "esec.toml")) //nolint:gosec // a test checkout
	swapped := strings.Replace(string(data), pf3.Env["dev"].Key, strings.Repeat("b", 64), 1)
	if err := os.WriteFile(filepath.Join(repo, "esec.toml"), []byte(swapped), 0o600); err != nil { //nolint:gosec // a test checkout
		t.Fatal(err)
	}
	if out, code := r.run(repo, "", "seal", "check"); code == 0 || !strings.Contains(out, "names key") {
		t.Fatalf("a swapped key passed: %s", out)
	}
	if err := os.WriteFile(filepath.Join(repo, "esec.toml"), data, 0o600); err != nil { //nolint:gosec // a test checkout
		t.Fatal(err)
	}
}

var (
	esecOnce     sync.Once
	esecBin      string
	errEsecBuild error
)

// buildEsec builds core esec once, for tests of machines that have only it.
func buildEsec(t *testing.T) string {
	t.Helper()
	esecOnce.Do(func() {
		dir, err := os.MkdirTemp("", "esec-core-bin-") //nolint:usetesting // shared by every test in the run
		if err != nil {
			errEsecBuild = err
			return
		}
		esecBin = filepath.Join(dir, "esec")
		// Build in core's module so its CLI-only dependencies use core's
		// go.mod/go.sum rather than this module's pruned library graph.
		moduleDir, err := exec.Command("go", "list", "-m", "-f", "{{.Dir}}", "github.com/mscno/esec").CombinedOutput()
		if err != nil {
			errEsecBuild = fmt.Errorf("locate esec module: %w\n%s", err, moduleDir)
			return
		}
		cmd := exec.Command("go", "build", "-o", esecBin, "./cmd/esec")
		cmd.Dir = strings.TrimSpace(string(moduleDir))
		out, err := cmd.CombinedOutput()
		if err != nil {
			errEsecBuild = fmt.Errorf("build esec: %w\n%s", err, out)
		}
	})
	if errEsecBuild != nil {
		t.Fatal(errEsecBuild)
	}
	return esecBin
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

	// Each key is unique, on this device and sealed in its repository with
	// a recovery key: two places, no reuse.
	out, code := r.run("", "", "verify", "--no-server", "--no-backup", "--json")
	if code != 0 || !strings.Contains(out, "sealed in the repository") || strings.Contains(out, "several projects") {
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
