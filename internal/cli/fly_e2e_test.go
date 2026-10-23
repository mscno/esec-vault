package cli_test

import (
	"runtime"
	"strings"
	"testing"

	vaultmachine "github.com/mscno/esec-vault/internal/machine"
	"github.com/mscno/esec-vault/internal/server"
	"github.com/mscno/esec-vault/internal/servertest"
)

// TestFlyOIDCEndToEnd binds a machine and a group token to a Fly.io app:
// their keys reach only Machines of that app, proven with the Machine's own
// OIDC token from its API socket.
func TestFlyOIDCEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("builds binaries")
	}
	if runtime.GOOS == "windows" {
		t.Skip("unix sockets")
	}
	bin := buildBinaries(t)
	fly := servertest.NewFakeFly(t, "acme", "store")
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

	// --- A machine of the project, bound to the Fly.io app store. ---
	out := owner.run("", "machine", "create", "store", "--env", "prod", p, "--fly-org", "acme", "--fly-app", "store", "--out", "-")
	key := regexpFind(t, out, `(esecm1_[A-Za-z0-9_-]+)`)
	app := newMachine(t, bin, "app").with("ESEC_VAULT_MACHINE_KEY="+key, vaultmachine.FlyAPIEnv+"="+fly.Socket)
	run := func(m *machine) (bool, string) {
		o, err := m.cmd(repo, "", "esec-vault", "machine", "run", "--", "esec", "decrypt", ".env.prod").CombinedOutput()
		return err == nil, string(o)
	}
	if ok, out := run(app); !ok || !strings.Contains(out, "postgres://db-prod") {
		t.Fatalf("the Fly.io app's machine:\n%s", out)
	}
	// Off Fly.io, or from another app, the key alone is not enough.
	if ok, out := run(newMachine(t, bin, "laptop").with("ESEC_VAULT_MACHINE_KEY=" + key)); ok || !strings.Contains(out, "Fly.io") {
		t.Fatalf("the key off Fly.io:\n%s", out)
	}
	fly.SetMachine("acme", "other")
	if ok, out := run(app); ok || !strings.Contains(out, `the Fly.io app "other" is not allowed`) {
		t.Fatalf("another app:\n%s", out)
	}
	fly.SetMachine("evil", "store")
	if ok, out := run(app); ok {
		t.Fatalf("another organisation's Machine:\n%s", out)
	}
	fly.SetMachine("acme", "store")

	// --- A group token bound to the app, for many Machines. ---
	owner.run("", "group", "create", "acme/production")
	owner.run("", "access", "grant", "acme/production", "--env", "prod", p)
	out = owner.run("", "group", "token", "acme/production", "fly-store", "--expires", "30d", "--fly-org", "acme", "--fly-app", "store", "--out", "-")
	if !strings.Contains(out, "Fly.io Machines of acme (app store)") {
		t.Fatalf("group token:\n%s", out)
	}
	tok := regexpFind(t, out, `(esecg1_[A-Za-z0-9_-]+)`)
	web := newMachine(t, bin, "web").with("ESEC_VAULT_MACHINE_KEY="+tok, vaultmachine.FlyAPIEnv+"="+fly.Socket)
	if ok, out := run(web); !ok || !strings.Contains(out, "postgres://db-prod") {
		t.Fatalf("the group token on the app:\n%s", out)
	}
	fly.SetMachine("acme", "other")
	if ok, _ := run(web); ok {
		t.Fatal("the group token worked from another app")
	}
}
