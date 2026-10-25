package cli_test

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	vaultmachine "github.com/mscno/esec-vault/internal/machine"
	"github.com/mscno/esec-vault/internal/server"
	"github.com/mscno/esec-vault/internal/servertest"
)

// TestAppAndRotationEndToEnd sets up a new app the foolproof way, then
// rotates a database credential everywhere it is used: the checks catch a
// secret in the clear and a .dockerignore that drops the secrets, app init
// wires the app and fly.toml, env status shows which deployments picked up a
// change, and secrets rotate gives two repositories the same new value.
func TestAppAndRotationEndToEnd(t *testing.T) { //nolint:gocyclo,maintidx // one sequential story with explicit checks
	if testing.Short() {
		t.Skip("builds binaries")
	}
	if runtime.GOOS == "windows" {
		t.Skip("unix sockets")
	}
	bin := buildBinaries(t)
	fly := servertest.NewFakeFly(t, "acme", "store")
	bao := servertest.NewFakeOpenBao(t, map[string]any{"org_name": "acme", "app_name": "store"})
	h := servertest.StartWith(t, []server.Option{server.WithRegistrationLimits(100, 1000), server.WithFlyOIDCBase(fly.URL)}, 53101343, 2002)
	h.GitHub.AddUser(53101343, "mscno")
	gh := "ESEC_VAULT_GITHUB_URL=" + h.GitHub.URL

	owner := newMachine(t, bin, "owner").with(gh, "BAO_TOKEN=root", "BAO_ADDR="+bao.URL)
	owner.run("", "identity", "init", "--no-passphrase", "--skip-confirm")
	src := t.TempDir()
	repo, worker := filepath.Join(src, "store"), filepath.Join(src, "worker")
	for _, d := range []string{repo, worker} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	owner.run("", "project", "init", "acme/store", "--dir", repo, "--env", "dev,prod", "--format", "env")
	owner.run("", "project", "init", "acme/worker", "--dir", worker, "--env", "prod", "--format", "env")
	writeSecret(t, owner, repo, "prod", "DATABASE_URL=postgres://db-old")
	writeSecret(t, owner, worker, "prod", "DATABASE_URL=postgres://db-old")
	login(t, h, owner.with("ESEC_VAULT_BOOTSTRAP_TOKEN="+servertest.BootstrapToken), "").wait(true)
	owner.run("", "access", "create", "--project=acme/store")
	owner.run("", "access", "create", "--project=acme/worker")
	owner.run("", "org", "create", "acme")
	owner.run("", "org", "kms", "add", "acme", "esec-store", "--openbao-key", bao.KeyName(), "--openbao-role", "jwt/"+bao.Role, "--openbao-audience", bao.Audience, "--groups", "acme/store")
	owner.run("", "org", "set", "acme", "--fly-org", "acme")
	inRepo := func(dir string, args ...string) (string, error) {
		o, err := owner.cmd(dir, "", "esec-vault", args...).CombinedOutput()
		return string(o), err
	}

	// --- Checks catch a secret pasted in the clear. ---
	if out, err := inRepo(repo, "secrets", "lint"); err != nil || !strings.Contains(out, "every value encrypted") {
		t.Fatalf("lint: %v\n%s", err, out)
	}
	devFile := filepath.Join(repo, ".env.dev")
	clean, _ := os.ReadFile(devFile)                                                                   //nolint:gosec // test temp dir
	if err := os.WriteFile(devFile, append(clean, []byte("LEAK=plaintext\n")...), 0o600); err != nil { //nolint:gosec // test temp dir
		t.Fatal(err)
	}
	if out, err := inRepo(repo, "secrets", "lint"); err == nil || !strings.Contains(out, "in the clear: LEAK") {
		t.Fatalf("lint with a secret in the clear: %v\n%s", err, out)
	}
	if err := os.WriteFile(devFile, clean, 0o600); err != nil { //nolint:gosec // test temp dir
		t.Fatal(err)
	}

	// --- A new app: the checks catch an image that would lack its secrets. ---
	write := func(name, content string) {
		if err := os.WriteFile(filepath.Join(repo, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("fly.toml", "app = \"store\"\nprimary_region = \"ams\"\n\n[http_service]\n  internal_port = 8080\n")
	write("Dockerfile", "FROM alpine\nCMD [\"/app/server\"]\n")
	write(".dockerignore", ".git\n.env*\n")
	if out, err := inRepo(repo, "app", "check", "--env", "prod"); err == nil || !strings.Contains(out, "left out of the image by .dockerignore") || !strings.Contains(out, "no ESEC_VAULT_WORKLOAD") || !strings.Contains(out, "never mentions esec-vault") {
		t.Fatalf("app check before setup: %v\n%s", err, out)
	}
	if out, err := inRepo(repo, "app", "init", "--env", "prod", "--yes"); err == nil || !strings.Contains(out, "fix the repository first") {
		t.Fatalf("app init on a broken repository: %v\n%s", err, out)
	}
	write(".dockerignore", ".git\n.env*\n!.env.prod\n")
	write("Dockerfile", "FROM alpine\nCMD [\"esec-vault\", \"machine\", \"run\", \"--\", \"esec\", \"run\", \".env.prod\", \"--\", \"/app/server\"]\n")
	out, err := inRepo(repo, "app", "init", "--env", "prod", "--yes")
	if err != nil || !strings.Contains(out, "Created the group acme/store") || !strings.Contains(out, "Wrote it into fly.toml") || !strings.Contains(out, "Ready to deploy") {
		t.Fatalf("app init: %v\n%s", err, out)
	}
	toml, _ := os.ReadFile(filepath.Join(repo, "fly.toml")) //nolint:gosec // test temp dir
	desc := regexpFind(t, string(toml), `ESEC_VAULT_WORKLOAD = "(esecw1_[A-Za-z0-9_-]+)"`)
	if !strings.Contains(string(toml), "internal_port = 8080") {
		t.Fatalf("fly.toml lost its settings:\n%s", toml)
	}
	// Running it again changes nothing.
	if out, err := inRepo(repo, "app", "init", "--env", "prod", "--yes"); err != nil || !strings.Contains(out, "fly.toml has the descriptor already") {
		t.Fatalf("app init again: %v\n%s", err, out)
	}

	app := newMachine(t, bin, "app").with(vaultmachine.WorkloadEnv+"="+desc, vaultmachine.FlyAPIEnv+"="+fly.Socket)
	runApp := func() string {
		t.Helper()
		o, err := app.cmd(repo, "", "esec-vault", "machine", "run", "--", "esec", "decrypt", ".env.prod").CombinedOutput()
		if err != nil {
			t.Fatalf("the app: %v\n%s", err, o)
		}
		return string(o)
	}
	if out := runApp(); !strings.Contains(out, "postgres://db-old") {
		t.Fatalf("the app reads:\n%s", out)
	}
	if out, err := inRepo(repo, "env", "status", "prod"); err != nil || !strings.Contains(out, "picked it up") {
		t.Fatalf("env status: %v\n%s", err, out)
	}

	// --- The database credential is rotated, in both services. ---
	if out, err := inRepo(src, "secrets", "where", "DATABASE_URL", "--root", src); err != nil || !strings.Contains(out, "acme/store") || !strings.Contains(out, "acme/worker") {
		t.Fatalf("secrets where: %v\n%s", err, out)
	}
	before, _ := os.ReadFile(filepath.Join(repo, ".env.prod")) //nolint:gosec // test temp dir
	// Times count in seconds: the change comes a second after the start.
	time.Sleep(1100 * time.Millisecond)
	since := time.Now().UTC().Format(time.RFC3339)
	c := owner.cmd(src, "", "esec-vault", "secrets", "rotate", "DATABASE_URL", "--env", "prod", "--root", src, "--yes")
	c.Stdin = strings.NewReader("postgres://db-new\n")
	if o, err := c.CombinedOutput(); err != nil || !strings.Contains(string(o), "in 2 file(s)") || strings.Contains(string(o), "db-new") {
		t.Fatalf("secrets rotate: %v\n%s", err, o)
	}
	after, _ := os.ReadFile(filepath.Join(repo, ".env.prod")) //nolint:gosec // test temp dir
	if changed := diffLines(string(before), string(after)); changed != 1 {
		t.Fatalf("%d lines changed in .env.prod", changed)
	}
	for _, d := range []string{repo, worker} {
		if ok, out := decrypts(owner, d, "prod"); !ok || !strings.Contains(out, "postgres://db-new") {
			t.Fatalf("%s after rotate:\n%s", d, out)
		}
	}
	// The app runs with the old value until it restarts.
	if out, err := inRepo(repo, "env", "status", "prod", "--since", since); err == nil || !strings.Contains(out, "have not started since") {
		t.Fatalf("env status before the restart: %v\n%s", err, out)
	}
	if out := runApp(); !strings.Contains(out, "postgres://db-new") {
		t.Fatalf("the app after the deploy:\n%s", out)
	}
	if out, err := inRepo(repo, "env", "status", "prod", "--since", since); err != nil || !strings.Contains(out, "picked it up") {
		t.Fatalf("env status after the restart: %v\n%s", err, out)
	}
	if out, err := inRepo(repo, "app", "check"); err != nil || !strings.Contains(out, "Ready to deploy") {
		t.Fatalf("app check: %v\n%s", err, out)
	}

	// --- One value by hand, in one file. ---
	c = owner.cmd(repo, "", "esec-vault", "secrets", "set", "API_KEY", "--env", "prod", "--create")
	c.Stdin = strings.NewReader("k-123\n")
	if o, err := c.CombinedOutput(); err != nil || !strings.Contains(string(o), "checked with this device's prod key") {
		t.Fatalf("secrets set: %v\n%s", err, o)
	}
	if ok, out := decrypts(owner, repo, "prod"); !ok || !strings.Contains(out, "API_KEY=k-123") {
		t.Fatalf("after secrets set:\n%s", out)
	}
}

func diffLines(a, b string) int {
	x, y := strings.Split(a, "\n"), strings.Split(b, "\n")
	if len(x) != len(y) {
		return -1
	}
	n := 0
	for i := range x {
		if x[i] != y[i] {
			n++
		}
	}
	return n
}
