package cli_test

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/mscno/esec-vault/internal/server"
	"github.com/mscno/esec-vault/internal/servertest"
)

func TestSharedEnvironmentRenameCLI(t *testing.T) {
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
	sock, _, key := testAgentKey(t)
	h.GitHub.AddKey("alice", key)
	gh := "ESEC_VAULT_GITHUB_URL=" + h.GitHub.URL
	owner := newMachine(t, bin, "owner").with(gh)
	alice := newMachine(t, bin, "alice").with(gh, "SSH_AUTH_SOCK="+sock)
	owner.run("", "identity", "init", "--no-passphrase", "--skip-confirm")
	alice.run("", "identity", "init", "--no-passphrase", "--skip-confirm")
	login(t, h, owner.with("ESEC_VAULT_BOOTSTRAP_TOKEN="+servertest.BootstrapToken), "").wait(true)
	loginAs(t, h, "alice", alice.with("ESEC_VAULT_BOOTSTRAP_TOKEN="+server.UserBootstrapToken(servertest.BootstrapSecret, 2002)), "").wait(true)
	alice.run("", "access", "prove")
	repo := t.TempDir()
	owner.run("", "project", "init", "acme/rename", "--dir", repo, "--env", "prod", "--format", "env")
	writeSecret(t, owner, repo, "prod", "TOKEN=rename-keeps-this")
	owner.run("", "access", "create", "--project=acme/rename")
	owner.run("", "access", "grant", "alice", "--env", "prod", "--project=acme/rename")
	// Alice has not downloaded the old-name grant yet. After rename its
	// original ciphertext must still verify and open under the new name.
	cmd := alice.cmd(repo, "", "esec-vault", "env", "rename", "prod", "stolen", "--yes")
	out, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(out), "only project admins") {
		t.Fatalf("non-admin rename: %v %s", err, out)
	}
	owner.run("", "env", "rename", "prod", "production", "--dir", repo, "--yes")
	alice.run("y\n", "access", "sync")
	if ok, out := decrypts(alice, repo, "production"); !ok || !strings.Contains(out, "rename-keeps-this") {
		t.Fatalf("old grant no longer decrypts renamed environment: %s", out)
	}
	if _, err := os.Stat(filepath.Join(repo, ".env.prod")); !os.IsNotExist(err) {
		t.Fatal("old file not removed")
	}
	if out := owner.run("", "access", "show", "--project=acme/rename"); !strings.Contains(out, "production") {
		t.Fatalf("vault environment not renamed: %s", out)
	}
}
