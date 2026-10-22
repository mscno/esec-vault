package cli_test

import (
	"context"
	"encoding/json"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/mscno/esec-vault/internal/server"
	"github.com/mscno/esec-vault/internal/servertest"
)

// TestRequestsAndTimedAccessEndToEnd: a member asks for more, an admin
// grants it from a device; access granted for a while ends when its time
// comes, as a removal waiting for the admin's signature.
func TestRequestsAndTimedAccessEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("builds binaries")
	}
	if runtime.GOOS == "windows" {
		t.Skip("unix sockets")
	}
	bin := buildBinaries(t)
	h := servertest.StartWith(t, []server.Option{server.WithRegistrationLimits(100, 1000)}, 53101343, 2002)
	h.GitHub.AddUser(53101343, "mscno")
	h.GitHub.AddUser(2002, "alice")
	sock, _, aliceKey := testAgentKey(t)
	h.GitHub.AddKey("alice", aliceKey)
	gh := "ESEC_VAULT_GITHUB_URL=" + h.GitHub.URL
	const p = "--project=acme/store"

	owner := newMachine(t, bin, "owner").with(gh)
	owner.run("", "identity", "init", "--no-passphrase", "--skip-confirm")
	repo := t.TempDir()
	owner.run("", "project", "init", "acme/store", "--dir", repo, "--env", "dev,prod", "--format", "env")
	writeSecret(t, owner, repo, "prod", "DATABASE_URL=postgres://db-prod")
	login(t, h, owner.with("ESEC_VAULT_BOOTSTRAP_TOKEN="+servertest.BootstrapToken), "").wait(true)
	alice := newMachine(t, bin, "alice").with(gh, "SSH_AUTH_SOCK="+sock)
	alice.run("", "identity", "init", "--no-passphrase", "--skip-confirm")
	loginAs(t, h, "alice", alice.with("ESEC_VAULT_BOOTSTRAP_TOKEN="+server.UserBootstrapToken(servertest.BootstrapSecret, 2002)), "").wait(true)
	alice.run("", "access", "prove")
	owner.run("", "access", "create", p)
	owner.run("", "access", "grant", "alice", "--env", "dev", p)
	alice.run("y\n", "access", "sync")

	// --- Alice asks for prod; the owner grants it from a device. ---
	if out := alice.run("", "access", "request", "--env", "prod", "--reason", "on call", p); !strings.Contains(out, "Asked for prod of acme/store") {
		t.Fatalf("access request:\n%s", out)
	}
	var list struct {
		ToDecide []struct {
			ID    int64  `json:"id"`
			Login string `json:"login"`
		} `json:"to_decide"`
	}
	raw := owner.run("", "access", "requests", "--json")
	if err := json.Unmarshal([]byte(raw), &list); err != nil || len(list.ToDecide) != 1 || list.ToDecide[0].Login != "alice" {
		t.Fatalf("access requests --json: %v\n%s", err, raw)
	}
	// --yes needs the request spelled out, and it must match.
	if out, err := owner.cmd(owner.home, "", "esec-vault", "access", "requests", "--grant", strconv.FormatInt(list.ToDecide[0].ID, 10), "--yes", "--login", "alice", "--project", "acme/store", "--env", "dev").CombinedOutput(); err == nil || !strings.Contains(string(out), "not what you named") {
		t.Fatalf("grant --yes of another request: %v\n%s", err, out)
	}
	if out := owner.run("y\n", "access", "requests", "--grant", strconv.FormatInt(list.ToDecide[0].ID, 10)); !strings.Contains(out, "alice reads dev, prod of acme/store") {
		t.Fatalf("grant the request:\n%s", out)
	}
	if out := alice.run("", "access", "requests"); !strings.Contains(out, "No access requests wait") {
		t.Fatalf("alice's requests after the grant:\n%s", out)
	}
	alice.run("", "access", "sync")
	if ok, _ := decrypts(alice, repo, "prod"); !ok {
		t.Fatal("alice cannot decrypt prod after the grant")
	}
	owner.run("", "access", "revoke", "alice", "--env", "prod", "--yes", p)

	// --- Timed access ends by itself, waiting for the owner's signature. ---
	if out := owner.run("", "access", "grant", "alice", "--env", "prod", "--for", "2s", p); !strings.Contains(out, "They lose prod again at") {
		t.Fatalf("access grant --for:\n%s", out)
	}
	if out := owner.run("", "access", "show", p); !strings.Contains(out, "Access that ends by itself") || !strings.Contains(out, "alice") {
		t.Fatalf("access show lacks the timed access:\n%s", out)
	}
	time.Sleep(3 * time.Second)
	h.Server.ExpireAccess(context.Background())
	if out := owner.run("", "changes", "--list"); !strings.Contains(out, "let alice read dev") {
		t.Fatalf("the expiry's removal does not wait:\n%s", out)
	}
	if out := owner.run("", "changes", "--yes"); !strings.Contains(out, "alice now reads dev of acme/store") {
		t.Fatalf("sign the expiry's removal:\n%s", out)
	}
	if out := owner.run("", "access", "show", p); strings.Contains(out, "Access that ends by itself") {
		t.Fatalf("the timed access is still listed:\n%s", out)
	}
}
