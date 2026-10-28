package cli

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mscno/esec/pkg/projectfile"

	"github.com/mscno/esec-vault/internal/keystore"
)

// stdout runs a command and returns its standard output only.
func (r *guardRig) stdout(dir string, args ...string) string {
	r.t.Helper()
	cmd := exec.Command(r.bin, args...)
	cmd.Dir, cmd.Env = dir, r.env
	out, err := cmd.Output()
	if err != nil {
		r.t.Fatalf("esec-vault %v: %v", args, err)
	}
	return string(out)
}

// project init --json says what it set up; run again, it creates nothing
// and keeps every key.
func TestProjectInitJSON(t *testing.T) {
	r := newGuardRig(t)
	repo := initTestRepo(t)
	var first initResult
	if err := json.Unmarshal([]byte(r.stdout(repo, "project", "init", "acme/store", "--env", "dev,prod", "--guard", "prod", "--format", "env", "--offline", "--json")), &first); err != nil {
		t.Fatal(err)
	}
	if first.Project != "acme/store" || first.IDFrom != "argument" || first.Format != "env" || len(first.Envs) != 2 ||
		first.Envs[1].Guard != "touch" || first.Envs[0].Key == "" || len(first.Created) != 2 || len(first.Next) == 0 {
		t.Fatalf("first: %+v", first)
	}
	var again initResult
	if err := json.Unmarshal([]byte(r.stdout(repo, "project", "init", "acme/store", "--env", "dev,prod", "--guard", "prod", "--format", "env", "--offline", "--json")), &again); err != nil {
		t.Fatal(err)
	}
	if len(again.Created) != 0 || again.Envs[0].Key != first.Envs[0].Key || again.Envs[1].Key != first.Envs[1].Key {
		t.Fatalf("again: %+v", again)
	}
}

// The pre-commit hook refuses a value in the clear and a plain secrets
// file for one of the project's environments, and lets a clean commit by.
func TestPreCommitHook(t *testing.T) {
	r := newGuardRig(t)
	repo := initTestRepo(t)
	r.must(repo, "", "project", "init", "acme/store", "--env", "dev,prod", "--format", "env", "--offline")
	r.must(repo, "", "hook", "install")
	if out := r.must(repo, "", "hook", "install"); !strings.Contains(out, "already") {
		t.Fatalf("second install: %s", out)
	}
	// The hook finds esec-vault on PATH.
	env := append(append([]string(nil), r.env...), "PATH="+filepath.Dir(r.bin)+string(os.PathListSeparator)+os.Getenv("PATH"))
	git := func(args ...string) (string, error) {
		cmd := exec.Command("git", append([]string{"-c", "user.email=t@example.com", "-c", "user.name=t", "-c", "commit.gpgsign=false"}, args...)...)
		cmd.Dir, cmd.Env = repo, env
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	if out, err := git("add", "-A"); err != nil {
		t.Fatal(out)
	}
	if out, err := git("commit", "-q", "-m", "init"); err != nil {
		t.Fatalf("a clean commit was refused: %s", out)
	}

	// A value pasted in the clear.
	dev := filepath.Join(repo, ".env.dev")
	data, _ := os.ReadFile(dev)                                                                               //nolint:gosec // a test checkout
	if err := os.WriteFile(dev, append(data, []byte("API_TOKEN=plain-text-value\n")...), 0o600); err != nil { //nolint:gosec // a test checkout
		t.Fatal(err)
	}
	_, _ = git("add", ".env.dev")
	if out, err := git("commit", "-q", "-m", "leak"); err == nil || !strings.Contains(out, "in the clear") {
		t.Fatalf("a value in the clear was committed: %v %s", err, out)
	}
	// The working tree being fixed does not help: what is staged counts.
	if err := os.WriteFile(dev, data, 0o600); err != nil { //nolint:gosec // a test checkout
		t.Fatal(err)
	}
	if out, err := git("commit", "-q", "-m", "leak"); err == nil {
		t.Fatalf("the staged leak was committed: %s", out)
	}
	_, _ = git("add", ".env.dev")

	// A plain .env.prod for an environment esec.toml declares.
	prod := filepath.Join(repo, ".env.prod")
	if err := os.WriteFile(prod, []byte("DATABASE_URL=postgres://u:p@db/prod\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _ = git("add", ".env.prod")
	if out, err := git("commit", "-q", "-m", "plain prod"); err == nil || !strings.Contains(out, "no public key") {
		t.Fatalf("a plain prod file was committed: %v %s", err, out)
	}

	// Uninstall removes the hook it wrote.
	r.must(repo, "", "hook", "uninstall")
	if _, err := os.Stat(filepath.Join(repo, ".git", "hooks", "pre-commit")); err == nil {
		t.Fatal("hook still there")
	}

	// Another tool's hook is kept; --append adds the check to it.
	hook := filepath.Join(repo, ".git", "hooks", "pre-commit")
	if err := os.WriteFile(hook, []byte("#!/bin/sh\necho other tool\n"), 0o755); err != nil { //nolint:gosec // a hook must be executable
		t.Fatal(err)
	}
	if out, code := r.run(repo, "", "hook", "install"); code == 0 || !strings.Contains(out, "--append") {
		t.Fatalf("overwrote another hook: %s", out)
	}
	r.must(repo, "", "hook", "install", "--append")
	r.must(repo, "", "hook", "uninstall")
	if got, _ := os.ReadFile(hook); string(got) != "#!/bin/sh\necho other tool\n" { //nolint:gosec // a test checkout
		t.Fatalf("other hook changed: %q", got)
	}
}

// setup reports what is left without changing anything, then sets up what
// it can: it finds the checkouts and guards here the keys guarded elsewhere.
func TestSetupChecksThenSetsUp(t *testing.T) { //nolint:gocyclo // one story, step by step
	r := newGuardRig(t)
	src := t.TempDir()
	repo := filepath.Join(src, "store")
	if err := os.MkdirAll(repo, 0o750); err != nil {
		t.Fatal(err)
	}
	if _, err := runGit(repo, "init"); err != nil {
		t.Fatal(err)
	}
	r.env = append(r.env, "ESEC_VAULT_NO_REGISTER=1")
	r.must(repo, "", "project", "init", "acme/store", "--env", "dev,prod", "--format", "env", "--offline")
	pf, _ := projectfile.Load(repo)

	steps := func(out string) map[string]setupStep {
		var list []setupStep
		if err := json.Unmarshal([]byte(out), &list); err != nil {
			t.Fatalf("%v: %s", err, out)
		}
		m := map[string]setupStep{}
		for _, s := range list {
			m[s.Step] = s
		}
		return m
	}

	// No identity yet: setup says so and does not make one unasked.
	out, code := r.run("", "", "setup", "--check", "--json", "--no-daemon", "--root", src)
	if code != 0 {
		t.Fatalf("check: %d %s", code, out)
	}
	m := steps(fromJSON(out))
	if m["identity"].Status != "todo" || !strings.Contains(m["identity"].Command, "esec vault init") {
		t.Fatalf("identity: %+v", m["identity"])
	}
	if m["checkouts"].Status != "todo" && m["checkouts"].Status != "ok" {
		t.Fatalf("checkouts: %+v", m["checkouts"])
	}
	out, _ = r.run("", "", "setup", "--no-daemon", "--root", src)
	if strings.Contains(out, "identity: created") {
		t.Fatalf("setup made an identity unasked: %s", out)
	}

	// With an identity: prod is guarded elsewhere, but its clear copy is
	// still here (synced from before).
	r.must("", "", "identity", "init", "--no-passphrase", "--skip-confirm")
	t.Setenv("ESEC_VAULT_HOME", r.home)
	t.Setenv("ESEC_KEYRING_DIR", "")
	before, err := keystore.New().Read("acme/store")
	if err != nil {
		t.Fatal(err)
	}
	r.must(repo, "", "guard", "enable", "--env", "prod")
	entries, _ := keystore.New().Read("acme/store")
	entries[keystore.PubEntry(pf.Env["prod"].Key)] = before[keystore.PubEntry(pf.Env["prod"].Key)]
	if err := keystore.New().Write("acme/store", entries, true); err != nil {
		t.Fatal(err)
	}

	m = steps(r.must("", "", "setup", "--check", "--json", "--no-daemon", "--root", src))
	if m["guard"].Status != "todo" || m["identity"].Status != "ok" {
		t.Fatalf("check with a clear copy: %+v", m)
	}
	out, _ = r.run("", "", "setup", "--yes", "--json", "--no-daemon", "--root", src)
	m = steps(fromJSON(out))
	if m["guard"].Status != "done" || m["checkouts"].Detail != "1 checkout(s) of 1 project(s)" || m["keys here"].Status != "ok" {
		t.Fatalf("setup: %+v", m)
	}
	entries, _ = keystore.New().Read("acme/store")
	if _, isClear := entries[keystore.PubEntry(pf.Env["prod"].Key)]; isClear {
		t.Fatal("the clear copy is still here")
	}
	if m["spare YubiKey"].Status != "todo" || m["recovery drill"].Status != "todo" {
		t.Fatalf("advice: %+v", m)
	}
}

// fromJSON drops what a command printed to stderr before its JSON.
func fromJSON(out string) string {
	if i := strings.Index(out, "["); i >= 0 {
		return out[i:]
	}
	return out
}
