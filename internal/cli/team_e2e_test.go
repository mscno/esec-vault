package cli_test

import (
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/mscno/esec-vault/internal/server"
	"github.com/mscno/esec-vault/internal/servertest"
)

// writeSecret appends a value to an env file and encrypts it.
func writeSecret(t *testing.T, m *machine, repo, env, line string) {
	t.Helper()
	p := filepath.Join(repo, ".env."+env)
	data, err := os.ReadFile(p) //nolint:gosec // test temp dir
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, append(data, []byte(line+"\n")...), 0o600); err != nil { //nolint:gosec // test temp dir
		t.Fatal(err)
	}
	m.tool(repo, "encrypt", env, "-f", "env")
}

// decrypts reports whether m can decrypt the file of env, and its output.
func decrypts(m *machine, repo, env string) (bool, string) {
	out, err := m.cmd(repo, "", "esec", "decrypt", ".env."+env).CombinedOutput()
	return err == nil, string(out)
}

// TestTeamsEndToEnd shares a project between two people and two machines:
// a GitHub-proven member, access changes, a CI machine with its own key, a
// machine bound to GitHub Actions OIDC, removal with its rotation to-do, and
// a rotation that reaches everyone who still has access.
func TestTeamsEndToEnd(t *testing.T) { //nolint:gocyclo,maintidx // one sequential story with explicit checks
	if testing.Short() {
		t.Skip("builds binaries")
	}
	if runtime.GOOS == "windows" {
		t.Skip("unix sockets")
	}
	bin := buildBinaries(t)
	oidc := servertest.NewFakeOIDC(t)
	h := servertest.StartWith(t, []server.Option{server.WithRegistrationLimits(100, 1000), server.WithOIDCIssuer(oidc.URL, oidc.JWKS())}, 53101343, 2002)
	h.GitHub.AddUser(53101343, "mscno")
	h.GitHub.AddUser(2002, "alice")
	sock, _, aliceKey := testAgentKey(t)
	h.GitHub.AddKey("alice", aliceKey)
	gh := "ESEC_VAULT_GITHUB_URL=" + h.GitHub.URL
	const p = "--project=acme/store"

	// --- The owner has the project and its keys. ---
	owner := newMachine(t, bin, "owner").with(gh)
	owner.run("", "identity", "init", "--no-passphrase", "--skip-confirm")
	repo := t.TempDir()
	owner.run("", "project", "init", "acme/store", "--dir", repo, "--env", "dev,prod", "--format", "env")
	writeSecret(t, owner, repo, "dev", "DATABASE_URL=postgres://db-dev")
	writeSecret(t, owner, repo, "prod", "DATABASE_URL=postgres://db-prod")
	login(t, h, owner.with("ESEC_VAULT_BOOTSTRAP_TOKEN="+servertest.BootstrapToken), "").wait(true)

	// --- Alice has an account and proves it with her GitHub SSH key. ---
	alice := newMachine(t, bin, "alice").with(gh, "SSH_AUTH_SOCK="+sock)
	alice.run("", "identity", "init", "--no-passphrase", "--skip-confirm")
	loginAs(t, h, "alice", alice.with("ESEC_VAULT_BOOTSTRAP_TOKEN="+server.UserBootstrapToken(servertest.BootstrapSecret, 2002)), "").wait(true)
	if out := alice.run("", "team", "prove"); !strings.Contains(out, "Published proof") {
		t.Fatalf("team prove:\n%s", out)
	}

	// --- The owner shares the project and adds alice to dev. ---
	if out := owner.run("", "team", "create", p); !strings.Contains(out, "Environments: dev, prod") {
		t.Fatalf("team create:\n%s", out)
	}
	out := owner.run("", "team", "add", "alice", "--env", "dev", p)
	if !strings.Contains(out, "checked with their GitHub SSH key") || !strings.Contains(out, "Sent the keys of dev") {
		t.Fatalf("team add:\n%s", out)
	}
	if ok, _ := decrypts(alice, repo, "dev"); ok {
		t.Fatal("alice decrypted dev before her device picked up the key")
	}
	// Her device asks before taking in a project's keys the first time.
	if out := alice.run("n\n", "team", "sync"); !strings.Contains(out, "mscno added you to the shared project acme/store (you read dev)") || strings.Contains(out, "+ acme/store") {
		t.Fatalf("alice team sync, declined:\n%s", out)
	}
	if out := alice.run("y\n", "team", "sync"); !strings.Contains(out, "+ acme/store dev") {
		t.Fatalf("alice team sync:\n%s", out)
	}
	if ok, out := decrypts(alice, repo, "dev"); !ok || !strings.Contains(out, "postgres://db-dev") {
		t.Fatalf("alice cannot decrypt dev:\n%s", out)
	}
	if ok, _ := decrypts(alice, repo, "prod"); ok {
		t.Fatal("alice decrypted prod without access")
	}
	// A member who is not an admin changes nothing.
	for args, want := range map[string]string{
		"team add mscno --env prod":       "only an admin",
		"env rotate dev --yes --dir REPO": "only its admins change its keys",
	} {
		cmd := alice.cmd(alice.home, "", "esec-vault", append(strings.Fields(strings.ReplaceAll(args, "REPO", repo)), p)...)
		out, err := cmd.CombinedOutput()
		if err == nil || !strings.Contains(string(out), want) {
			t.Fatalf("alice: %s: %v\n%s", args, err, out)
		}
	}

	// --- Access to prod reaches her too. ---
	owner.run("", "team", "set", "alice", "--env", "dev,prod", p)
	if out := alice.run("", "team", "sync"); !strings.Contains(out, "+ acme/store prod") {
		t.Fatalf("alice team sync after set:\n%s", out)
	}
	if ok, out := decrypts(alice, repo, "prod"); !ok || !strings.Contains(out, "postgres://db-prod") {
		t.Fatalf("alice cannot decrypt prod:\n%s", out)
	}

	// --- A CI machine gets its own key to prod. ---
	token, err := owner.cmd(owner.home, "", "esec-vault", "machine", "create", "ci", "--env", "prod", p, "--out", "-").Output()
	if err != nil {
		t.Fatalf("machine create: %v", err)
	}
	ci := newMachine(t, bin, "ci").with("ESEC_VAULT_MACHINE_KEY=" + strings.TrimSpace(string(token)))
	ciRun := func() (bool, string) {
		out, err := ci.cmd(repo, "", "esec-vault", "machine", "run", "--", "esec", "decrypt", ".env.prod").CombinedOutput()
		return err == nil, string(out)
	}
	if ok, out := ciRun(); !ok || !strings.Contains(out, "postgres://db-prod") {
		t.Fatalf("ci machine run:\n%s", out)
	}
	if out, err := ci.cmd(repo, "", "esec-vault", "machine", "run", "--env", "dev", "--", "true").CombinedOutput(); err == nil {
		t.Fatalf("the ci machine read dev:\n%s", out)
	}

	// --- A deploy machine works only from GitHub Actions in this repository. ---
	token, err = owner.cmd(owner.home, "", "esec-vault", "machine", "create", "deploy", "--env", "dev", p, "--github-repo", "acme/store", "--github-ref", "refs/heads/main", "--out", "-").Output()
	if err != nil {
		t.Fatalf("machine create with OIDC: %v", err)
	}
	deploy := newMachine(t, bin, "deploy").with("ESEC_VAULT_MACHINE_KEY=" + strings.TrimSpace(string(token)))
	if out, err := deploy.cmd(repo, "", "esec-vault", "machine", "env").CombinedOutput(); err == nil || !strings.Contains(string(out), "id-token: write") {
		t.Fatalf("deploy without OIDC:\n%s", out)
	}
	oidc.SetClaims(map[string]any{"repository": "acme/store", "ref": "refs/heads/main", "run_id": "42"})
	job := deploy.with(oidc.JobEnv()...)
	out2, err := job.cmd(repo, "", "esec-vault", "machine", "env").CombinedOutput()
	if err != nil || !strings.Contains(string(out2), "ESEC_PRIVATE_KEY_DEV=") {
		t.Fatalf("deploy with OIDC: %v\n%s", err, out2)
	}
	oidc.SetClaims(map[string]any{"repository": "acme/store", "ref": "refs/heads/feature"})
	if out, err := job.cmd(repo, "", "esec-vault", "machine", "env").CombinedOutput(); err == nil {
		t.Fatalf("deploy from another branch:\n%s", out)
	}

	// --- Removing alice leaves a rotation to-do, shown everywhere. ---
	out = owner.run("", "team", "remove", "alice", "--yes", p)
	if !strings.Contains(out, "esec vault env rotate dev") || !strings.Contains(out, "esec vault env rotate prod") {
		t.Fatalf("team remove:\n%s", out)
	}
	if out := owner.run("", "team", "show", p); !strings.Contains(out, "prod needs a new key: alice") {
		t.Fatalf("team show:\n%s", out)
	}
	status, page, err := h.Browser("mscno").Get("/teams/acme/store")
	if err != nil || status != http.StatusOK || !strings.Contains(page, "needs a new key") || !strings.Contains(page, "removed alice") {
		t.Fatalf("project page: %d %v\n%s", status, err, page)
	}
	if status, _, _ := h.Browser("alice").Get("/teams/acme/store"); status != http.StatusNotFound {
		t.Fatalf("a removed member saw the project page: %d", status)
	}

	// --- Rotating prod reaches the CI machine and clears the to-do. ---
	out = owner.run("", "env", "rotate", "prod", p, "--dir", repo, "--yes")
	if !strings.Contains(out, "re-encrypted .env.prod") || !strings.Contains(out, "Sent the new prod key to ci") {
		t.Fatalf("env rotate:\n%s", out)
	}
	if ok, out := ciRun(); !ok || !strings.Contains(out, "postgres://db-prod") {
		t.Fatalf("ci after rotation:\n%s", out)
	}
	if ok, _ := decrypts(alice, repo, "prod"); ok {
		t.Fatal("alice decrypted the rotated prod file")
	}
	if out := owner.run("", "team", "show", p); strings.Contains(out, "prod needs a new key") || !strings.Contains(out, "dev needs a new key") {
		t.Fatalf("team show after rotation:\n%s", out)
	}
	alice.run("", "team", "sync")
	if out := alice.run("", "team"); !strings.Contains(out, "No shared projects") {
		t.Fatalf("alice still lists the project:\n%s", out)
	}
	if out, err := alice.cmd(alice.home, "", "esec-vault", "team", "show", p).CombinedOutput(); err == nil || !strings.Contains(string(out), "not a member") {
		t.Fatalf("a removed member read the project: %v\n%s", err, out)
	}

	// --- Removing the CI machine stops it. ---
	owner.run("", "machine", "remove", "ci", "--yes", p)
	if ok, out := ciRun(); ok {
		t.Fatalf("a removed machine still ran:\n%s", out)
	}
	if out := owner.run("", "team"); !regexp.MustCompile(`acme/store\s+admin`).MatchString(out) {
		t.Fatalf("team list:\n%s", out)
	}
}
