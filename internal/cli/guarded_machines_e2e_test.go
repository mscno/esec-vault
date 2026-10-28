package cli_test

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"filippo.io/age"

	"github.com/mscno/esec-vault/internal/server"
	"github.com/mscno/esec-vault/internal/servertest"
)

// TestGuardedKeysReachMachines: a guarded key lives only in its seal, yet
// machines get it over the network: one with a root secret (its machine
// key), one with only a GitHub Actions OIDC token. The owner's touch sends
// it, and a rotation reaches both with no change where they run.
func TestGuardedKeysReachMachines(t *testing.T) {
	if testing.Short() {
		t.Skip("builds binaries")
	}
	if runtime.GOOS == "windows" {
		t.Skip("unix sockets")
	}
	bin := buildBinaries(t)
	oidc := servertest.NewFakeOIDC(t)
	h := servertest.StartWith(t, []server.Option{server.WithRegistrationLimits(100, 1000), server.WithOIDCIssuer(oidc.URL, oidc.JWKS())}, 53101343)
	h.GitHub.AddUser(53101343, "mscno")
	const p = "--project=acme/store"

	// The owner's stand-in YubiKey: a software key whose "touch" always
	// succeeds.
	yubi, _ := age.GenerateX25519Identity()
	ids := filepath.Join(t.TempDir(), "yubi.txt")
	if err := os.WriteFile(ids, []byte(yubi.String()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	owner := newMachine(t, bin, "owner").with("ESEC_VAULT_GITHUB_URL="+h.GitHub.URL, "ESEC_VAULT_GUARD_IDENTITIES="+ids, "ESEC_VAULT_DIALOGS=off")
	owner.run("", "identity", "init", "--no-passphrase", "--skip-confirm")
	login(t, h, owner.with("ESEC_VAULT_BOOTSTRAP_TOKEN="+servertest.BootstrapToken), "").wait(true)
	repo := t.TempDir()
	owner.run("", "project", "init", "acme/store", "--dir", repo, "--env", "dev,prod", "--format", "env")
	writeSecret(t, owner, repo, "prod", "DATABASE_URL=postgres://db-prod")
	owner.run("", "guard", "enable", "--env", "prod", p)
	owner.run("", "projects", "add", repo)

	// Shared on the server: prod comes from its seal, with a touch.
	if out := owner.run("", "team", "create", p); !strings.Contains(out, "Environments: dev, prod") {
		t.Fatalf("team create:\n%s", out)
	}
	token, err := owner.cmd(owner.home, "", "esec-vault", "machine", "create", "ci", "--env", "prod", p, "--out", "-").Output()
	if err != nil {
		t.Fatalf("machine create: %v", err)
	}
	ci := newMachine(t, bin, "ci").with("ESEC_VAULT_MACHINE_KEY=" + strings.TrimSpace(string(token)))
	token, err = owner.cmd(owner.home, "", "esec-vault", "machine", "create", "deploy", "--env", "prod", p, "--github-repo", "acme/store", "--github-ref", "refs/heads/main", "--out", "-").Output()
	if err != nil {
		t.Fatalf("machine create with OIDC: %v", err)
	}
	oidc.SetClaims(map[string]any{"repository": "acme/store", "ref": "refs/heads/main", "run_id": "42"})
	deploy := newMachine(t, bin, "deploy").with("ESEC_VAULT_MACHINE_KEY=" + strings.TrimSpace(string(token))).with(oidc.JobEnv()...)

	// The machines have no security key and no dialogs: they read guarded
	// prod with what they hold, never a touch.
	reads := func(m *machine, want string) {
		t.Helper()
		out, err := m.cmd(repo, "", "esec-vault", "machine", "run", "--", "esec", "decrypt", ".env.prod").CombinedOutput()
		if err != nil || !strings.Contains(string(out), want) {
			t.Fatalf("%s cannot read prod: %v\n%s", m.name, err, out)
		}
	}
	reads(ci, "postgres://db-prod")
	reads(deploy, "postgres://db-prod")

	// Rotated: the new key goes to both, from the rotation itself (the
	// key is not kept in the keyring, and is not opened again).
	out := owner.run("", "env", "rotate", "prod", p, "--dir", repo, "--yes")
	if !strings.Contains(out, "Sent the new prod key to") || !strings.Contains(out, "ci") || !strings.Contains(out, "deploy") {
		t.Fatalf("env rotate:\n%s", out)
	}
	writeSecret(t, owner, repo, "prod", "API_TOKEN=after-rotation")
	reads(ci, "after-rotation")
	reads(deploy, "after-rotation")
}
