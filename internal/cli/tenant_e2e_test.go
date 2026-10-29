package cli_test

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/mscno/esec-vault/internal/server"
	"github.com/mscno/esec-vault/internal/servertest"
)

func TestSelfServiceTenantsAndAcceptedTransfer(t *testing.T) {
	if testing.Short() {
		t.Skip("builds binaries")
	}
	if runtime.GOOS == "windows" {
		t.Skip("unix sockets")
	}
	bin := buildBinaries(t)
	h := servertest.StartConfig(t, []server.Option{server.WithRegistrationLimits(100, 1000)}, func(c *server.Config) {
		c.Namespaces = append(c.Namespaces, server.NamespaceConfig{Name: "alice", OwnerGitHubID: 53101343})
	}, 53101343, 2002)
	h.GitHub.AddUser(53101343, "mscno")
	h.GitHub.AddUser(2002, "alice")
	gh := "ESEC_VAULT_GITHUB_URL=" + h.GitHub.URL
	ownerSock, _, ownerKey := testAgentKey(t)
	aliceSock, _, aliceKey := testAgentKey(t)
	h.GitHub.AddKey("mscno", ownerKey)
	h.GitHub.AddKey("alice", aliceKey)
	owner := newMachine(t, bin, "owner").with(gh, "SSH_AUTH_SOCK="+ownerSock)
	owner.run("", "identity", "init", "--no-passphrase", "--skip-confirm")
	login(t, h, owner.with("ESEC_VAULT_BOOTSTRAP_TOKEN="+servertest.BootstrapToken), "").wait(true)
	owner.run("", "access", "prove")
	owner.run("", "org", "create", "mscno")
	alice := newMachine(t, bin, "alice").with(gh, "SSH_AUTH_SOCK="+aliceSock)
	alice.run("", "identity", "init", "--no-passphrase", "--skip-confirm")
	loginAs(t, h, "alice", alice.with("ESEC_VAULT_BOOTSTRAP_TOKEN="+server.UserBootstrapToken(servertest.BootstrapSecret, 2002)), "", "--personal-namespace", "alice-personal").wait(true)
	if out := alice.run("", "personal", "--json"); !strings.Contains(out, `"name": "alice-personal"`) {
		t.Fatalf("personal collision picker:\n%s", out)
	}
	alice.run("", "access", "prove")
	alice.run("", "org", "create", "receiving")
	owner.run("", "org", "create", "geoman")
	owner.run("", "org", "create", "paraplyventures")
	var before struct {
		TenantID string `json:"tenant_id"`
	}
	// The namespace endpoint, CLI listing and signed profile retain one identity.
	owner.runJSON(&before, "personal")
	owner.run("", "personal", "rename", "mads-personal")
	var after struct {
		TenantID string `json:"tenant_id"`
	}
	owner.runJSON(&after, "personal")
	if before.TenantID == "" || before.TenantID != after.TenantID {
		t.Fatal("personal namespace rename created another identity")
	}
	failsWith(t, alice, "exists already", "org", "create", "mscno")
	repo := t.TempDir()
	owner.run("", "project", "init", "geoman/api", "--dir", repo, "--env", "dev", "--format", "env")
	writeSecret(t, owner, repo, "dev", "DATABASE_URL=postgres://tenant-transfer")
	owner.run("", "access", "create", "--project=geoman/api")
	owner.run("", "access", "grant", "alice", "--env", "dev", "--project=geoman/api")
	alice.run("y\n", "access", "sync")
	owner.run("", "org", "rename", "geoman", "geoman-work", "--display-name", "Geoman Work")
	if out := owner.run("", "org", "geoman-work"); !strings.Contains(out, "geoman/api") {
		t.Fatalf("rename hid existing projects:\n%s", out)
	}
	owner.run("", "access", "move", "geoman-work/api", "--project=geoman/api", "--yes")
	alice.run("", "access", "sync")
	owner.run("", "org", "create", "roles")
	owner.run("", "org", "add", "roles", "alice", "--admin")
	var words struct {
		Fingerprint string `json:"fingerprint"`
	}
	owner.runJSON(&words, "org", "roles")
	alice.run("", "org", "trust", "roles", "--fingerprint", words.Fingerprint)
	failsWith(t, alice, "only a tenant owner", "org", "owner", "roles", "mscno", "--remove")
	failsWith(t, owner, "at least one owner", "org", "owner", "roles", "mscno", "--remove")
	owner.run("", "org", "owner", "roles", "alice")
	owner.run("", "org", "owner", "roles", "mscno", "--remove")
	failsWith(t, owner, "only a tenant owner", "org", "rename", "roles", "stolen")
	alice.run("", "org", "owner", "roles", "mscno")
	out := owner.run("", "project", "transfer", "geoman-work/api", "--to", "receiving/api", "--recipient", "alice", "--yes")
	id := regexpFind(t, out, `Transfer offered: (tr_[a-f0-9]+)`)
	if out := alice.run("", "transfers", "show", id); !strings.Contains(out, "receiving/api") {
		t.Fatalf("incoming offer:\n%s", out)
	}
	alice.run("", "transfers", "accept", id, "--yes")
	failsWith(t, alice, "no longer pending", "transfers", "accept", id, "--yes")
	var readers int
	if err := h.DB.SQL().QueryRow(`SELECT COUNT(*) FROM project_members WHERE project='receiving/api' AND active=1`).Scan(&readers); err != nil || readers != 1 {
		t.Fatalf("destination readers: %d %v", readers, err)
	}
	dest := t.TempDir()
	alice.run("", "project", "init", "receiving/api", "--dir", dest, "--env", "dev", "--format", "env")
	cipher, err := os.ReadFile(filepath.Join(repo, ".env.dev")) //nolint:gosec // both repository paths are test TempDirs
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dest, ".env.dev"), cipher, 0o600); err != nil { //nolint:gosec // test TempDir destination
		t.Fatal(err)
	}
	if ok, out := decrypts(alice, dest, "dev"); !ok || !strings.Contains(out, "postgres://tenant-transfer") {
		t.Fatalf("receiver cannot use transferred keys:\n%s", out)
	}
	// Rejected and expired offers do not archive the source.
	repo2 := t.TempDir()
	owner.run("", "project", "init", "mads-personal/cancel", "--dir", repo2, "--env", "dev", "--format", "env")
	owner.run("", "access", "create", "--project=mads-personal/cancel")
	out = owner.run("", "project", "transfer", "mads-personal/cancel", "--to", "receiving/cancel", "--recipient", "alice", "--yes")
	cancelID := regexpFind(t, out, `Transfer offered: (tr_[a-f0-9]+)`)
	alice.run("", "transfers", "reject", cancelID)
	failsWith(t, alice, "no longer pending", "transfers", "accept", cancelID, "--yes")
	out = owner.run("", "project", "transfer", "mads-personal/cancel", "--to", "receiving/expired", "--recipient", "alice", "--yes")
	expired := regexpFind(t, out, `Transfer offered: (tr_[a-f0-9]+)`)
	if _, err := h.DB.SQL().Exec(`UPDATE transfer_requests SET expires_at=? WHERE id=?`, time.Now().Add(-time.Second).Unix(), expired); err != nil {
		t.Fatal(err)
	}
	failsWith(t, alice, "expired", "transfers", "accept", expired, "--yes")
	if out := owner.run("", "access", "show", "--project=mads-personal/cancel"); strings.Contains(out, "is archived") {
		t.Fatalf("unaccepted offer archived the source:\n%s", out)
	}
}
