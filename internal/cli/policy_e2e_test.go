package cli_test

import (
	"net/http"
	"net/url"
	"runtime"
	"strings"
	"testing"

	"github.com/mscno/esec-vault/internal/server"
	"github.com/mscno/esec-vault/internal/servertest"
)

// TestPolicyAndReviewEndToEnd: a server admin sets an organisation's
// policy on the web, and the server holds every new change to it; an
// admin reviews who reads a project and the review is recorded.
func TestPolicyAndReviewEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("builds binaries")
	}
	if runtime.GOOS == "windows" {
		t.Skip("unix sockets")
	}
	bin := buildBinaries(t)
	h := servertest.StartWith(t, []server.Option{server.WithRegistrationLimits(100, 1000)}, 53101343, 2002, 2003)
	h.Config.Access.AdminGitHubIDs = []int64{53101343}
	h.GitHub.AddUser(53101343, "mscno")
	h.GitHub.AddUser(2002, "alice")
	h.GitHub.AddUser(2003, "bob")
	sock, _, aliceKey := testAgentKey(t)
	h.GitHub.AddKey("alice", aliceKey)
	gh := "ESEC_VAULT_GITHUB_URL=" + h.GitHub.URL
	const p = "--project=acme/store"

	owner := newMachine(t, bin, "owner").with(gh)
	owner.run("", "identity", "init", "--no-passphrase", "--skip-confirm")
	repo := t.TempDir()
	owner.run("", "project", "init", "acme/store", "--dir", repo, "--env", "dev,prod", "--format", "env")
	login(t, h, owner.with("ESEC_VAULT_BOOTSTRAP_TOKEN="+servertest.BootstrapToken), "").wait(true)
	alice := newMachine(t, bin, "alice").with(gh, "SSH_AUTH_SOCK="+sock)
	alice.run("", "identity", "init", "--no-passphrase", "--skip-confirm")
	loginAs(t, h, "alice", alice.with("ESEC_VAULT_BOOTSTRAP_TOKEN="+server.UserBootstrapToken(servertest.BootstrapSecret, 2002)), "").wait(true)
	alice.run("", "access", "prove")
	bob := newMachine(t, bin, "bob").with(gh)
	bob.run("", "identity", "init", "--no-passphrase", "--skip-confirm")
	loginAs(t, h, "bob", bob.with("ESEC_VAULT_BOOTSTRAP_TOKEN="+server.UserBootstrapToken(servertest.BootstrapSecret, 2003)), "").wait(true)
	bobWords := regexpFind(t, bob.run("", "status", "--json"), `"account_key": "([^"]+)"`)
	owner.run("", "access", "create", p)
	owner.run("", "group", "create", "acme/backend")

	// --- The server's admin sets acme's policy on its page. ---
	b := h.Browser("mscno")
	if _, _, err := b.Get("/account"); err != nil {
		t.Fatal(err)
	}
	_, page, err := b.Get("/orgs/acme")
	if err != nil || !strings.Contains(page, "acme/store") || !strings.Contains(page, "Change the policy") {
		t.Fatalf("org page: %v\n%s", err, page)
	}
	form := url.Values{"max_token_days": {"30"}, "review_days": {"1"}, "require_github_proof": {"on"}}
	if status, _, err := b.Post("/orgs/acme/policy", servertest.CSRF(page), form); err != nil || status != http.StatusOK {
		t.Fatalf("set the policy: %d %v", status, err)
	}
	if out := owner.run("", "org", "acme"); !strings.Contains(out, "tokens last at most 30 days") || !strings.Contains(out, "only with a GitHub SSH proof") {
		t.Fatalf("org acme:\n%s", out)
	}

	// --- The server holds changes to it. ---
	if out, err := owner.cmd(owner.home, "", "esec-vault", "group", "token", "acme/backend", "ci", "--expires", "never", "--out", "-").CombinedOutput(); err == nil || !strings.Contains(string(out), "at most 30 days") {
		t.Fatalf("a token that never expires: %v\n%s", err, out)
	}
	owner.run("", "group", "token", "acme/backend", "ci", "--expires", "10d", "--out", "-")
	if out, err := owner.cmd(owner.home, "", "esec-vault", "access", "grant", "bob", "--env", "dev", "--account-key", bobWords, p).CombinedOutput(); err == nil || !strings.Contains(string(out), "requires a GitHub SSH proof") {
		t.Fatalf("bob added without a GitHub proof: %v\n%s", err, out)
	}
	owner.run("", "access", "grant", "alice", "--env", "dev", p)

	// --- The admin reviews who reads it, and alice goes. ---
	if out := owner.run("", "access", "review", "--remove", "alice", "--yes", p); !strings.Contains(out, "Took acme/store away from alice") || !strings.Contains(out, "1 kept, 1 removed") {
		t.Fatalf("access review:\n%s", out)
	}
	_, page, _ = b.Get("/teams/acme/store/review")
	if !strings.Contains(page, "Last reviewed by mscno") {
		t.Fatalf("review page:\n%s", page)
	}
}
