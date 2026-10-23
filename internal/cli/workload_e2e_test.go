package cli_test

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	vaultmachine "github.com/mscno/esec-vault/internal/machine"
	"github.com/mscno/esec-vault/internal/server"
	"github.com/mscno/esec-vault/internal/servertest"
)

// TestWorkloadKMSEndToEnd runs an app with no secret at all: it proves
// where it runs with its Fly.io OIDC token, and Cloud KMS (faked) unwraps its
// group key. A new group key reaches it too; another app gets nothing.
func TestWorkloadKMSEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("builds binaries")
	}
	if runtime.GOOS == "windows" {
		t.Skip("unix sockets")
	}
	bin := buildBinaries(t)
	fly := servertest.NewFakeFly(t, "acme", "store")
	gcp := servertest.NewFakeGCP(t)
	gcp.SetAllow(func(c map[string]any) bool { return c["org_name"] == "acme" && c["app_name"] == "store" })
	h := servertest.StartWith(t, []server.Option{server.WithRegistrationLimits(100, 1000), server.WithFlyOIDCBase(fly.URL)}, 53101343)
	h.GitHub.AddUser(53101343, "mscno")
	const p = "--project=acme/store"

	owner := newMachine(t, bin, "owner").with("ESEC_VAULT_GITHUB_URL=" + h.GitHub.URL)
	owner.run("", "identity", "init", "--no-passphrase", "--skip-confirm")
	repo := t.TempDir()
	owner.run("", "project", "init", "acme/store", "--dir", repo, "--env", "prod", "--format", "env")
	writeSecret(t, owner, repo, "prod", "DATABASE_URL=postgres://db-prod")
	login(t, h, owner.with("ESEC_VAULT_BOOTSTRAP_TOKEN="+servertest.BootstrapToken), "").wait(true)
	owner.run("", "access", "create", p)
	owner.run("", "group", "create", "acme/production")
	owner.run("", "access", "grant", "acme/production", "--env", "prod", p)

	pemFile := filepath.Join(t.TempDir(), "key.pem")
	if err := os.WriteFile(pemFile, []byte(gcp.PublicKeyPEM()), 0o600); err != nil {
		t.Fatal(err)
	}
	out := owner.run("", "group", "workload", "acme/production", "store", "--fly-org", "acme", "--fly-app", "store",
		"--gcp-key", gcp.KeyName, "--gcp-provider", gcp.Provider, "--public-key", pemFile)
	desc := regexpFind(t, out, `ESEC_VAULT_WORKLOAD = "(esecw1_[A-Za-z0-9_-]+)"`)
	if gcp.Decrypts() != 0 {
		t.Fatal("adding a workload called the KMS")
	}

	app := newMachine(t, bin, "app").with(append(gcp.Env(), vaultmachine.WorkloadEnv+"="+desc, vaultmachine.FlyAPIEnv+"="+fly.Socket)...)
	run := func(m *machine) (bool, string) {
		o, err := m.cmd(repo, "", "esec-vault", "machine", "run", "--", "esec", "decrypt", ".env.prod").CombinedOutput()
		return err == nil, string(o)
	}
	if ok, out := run(app); !ok || !strings.Contains(out, "postgres://db-prod") {
		t.Fatalf("the workload:\n%s", out)
	}
	if gcp.Decrypts() != 1 {
		t.Fatalf("KMS decrypts: %d", gcp.Decrypts())
	}
	if out := app.run("", "machine", "whoami"); !strings.Contains(out, "workload") {
		t.Fatalf("whoami:\n%s", out)
	}

	// Another app is refused by the vault's policy; if it got past that, by
	// the KMS's attribute condition.
	fly.SetMachine("acme", "web")
	if ok, out := run(app); ok || !strings.Contains(out, `the Fly.io app "web" is not allowed`) {
		t.Fatalf("another app:\n%s", out)
	}
	fly.SetMachine("acme", "store")

	// A new group key, after a machine is removed, is wrapped for the
	// workload too, with no KMS call on the admin's side.
	owner.run("", "group", "add-machine", "acme/production", "old", "--out", "-")
	owner.run("", "group", "remove", "acme/production", "old", "--yes")
	before := gcp.Decrypts()
	if ok, out := run(app); !ok || !strings.Contains(out, "postgres://db-prod") {
		t.Fatalf("the workload after a new group key:\n%s", out)
	}
	if gcp.Decrypts() != before+1 {
		t.Fatal("the admin's device called the KMS")
	}

	// Removing the workload stops it at its next start.
	owner.run("", "group", "remove", "acme/production", "store", "--yes")
	if ok, out := run(app); ok {
		t.Fatalf("a removed workload:\n%s", out)
	}
}

// TestWorkloadRekeyEndToEnd moves a workload from Google Cloud KMS to a
// self-hosted OpenBao, keeping its descriptor: the app restarts and reads
// on, now through OpenBao.
func TestWorkloadRekeyEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("builds binaries")
	}
	if runtime.GOOS == "windows" {
		t.Skip("unix sockets")
	}
	bin := buildBinaries(t)
	fly := servertest.NewFakeFly(t, "acme", "store")
	gcp := servertest.NewFakeGCP(t)
	bao := servertest.NewFakeOpenBao(t, map[string]any{"org_name": "acme", "app_name": "store"})
	h := servertest.StartWith(t, []server.Option{server.WithRegistrationLimits(100, 1000), server.WithFlyOIDCBase(fly.URL)}, 53101343)
	h.GitHub.AddUser(53101343, "mscno")
	const p = "--project=acme/store"
	owner := newMachine(t, bin, "owner").with("ESEC_VAULT_GITHUB_URL="+h.GitHub.URL, "BAO_TOKEN=root", "BAO_ADDR="+bao.URL)
	owner.run("", "identity", "init", "--no-passphrase", "--skip-confirm")
	repo := t.TempDir()
	owner.run("", "project", "init", "acme/store", "--dir", repo, "--env", "prod", "--format", "env")
	writeSecret(t, owner, repo, "prod", "DATABASE_URL=postgres://db-prod")
	login(t, h, owner.with("ESEC_VAULT_BOOTSTRAP_TOKEN="+servertest.BootstrapToken), "").wait(true)
	owner.run("", "access", "create", p)
	owner.run("", "group", "create", "acme/store")
	owner.run("", "access", "grant", "acme/store", "--env", "prod", p)
	pemFile := filepath.Join(t.TempDir(), "key.pem")
	if err := os.WriteFile(pemFile, []byte(gcp.PublicKeyPEM()), 0o600); err != nil {
		t.Fatal(err)
	}
	out := owner.run("", "group", "workload", "acme/store", "store", "--fly-org", "acme", "--fly-app", "store", "--gcp-key", gcp.KeyName, "--gcp-provider", gcp.Provider, "--public-key", pemFile)
	desc := regexpFind(t, out, `ESEC_VAULT_WORKLOAD = "(esecw1_[A-Za-z0-9_-]+)"`)
	app := newMachine(t, bin, "app").with(append(gcp.Env(), vaultmachine.WorkloadEnv+"="+desc, vaultmachine.FlyAPIEnv+"="+fly.Socket)...)
	run := func() (bool, string) {
		o, err := app.cmd(repo, "", "esec-vault", "machine", "run", "--", "esec", "decrypt", ".env.prod").CombinedOutput()
		return err == nil, string(o)
	}
	if ok, out := run(); !ok || !strings.Contains(out, "postgres://db-prod") {
		t.Fatalf("through Cloud KMS:\n%s", out)
	}
	if out := owner.run("", "group", "rekey-workloads", "acme/store", "--openbao-key", bao.KeyName(), "--openbao-role", "jwt/"+bao.Role, "--openbao-audience", bao.Audience); !strings.Contains(out, "store now unwrap with") {
		t.Fatalf("rekey-workloads:\n%s", out)
	}
	gcpBefore := gcp.Decrypts()
	if ok, out := run(); !ok || !strings.Contains(out, "postgres://db-prod") {
		t.Fatalf("through OpenBao, with the same descriptor:\n%s", out)
	}
	if gcp.Decrypts() != gcpBefore || bao.Decrypts() != 1 {
		t.Fatalf("decrypts: gcp %d (was %d), openbao %d", gcp.Decrypts(), gcpBefore, bao.Decrypts())
	}
}
