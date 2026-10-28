package broker

import (
	"errors"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/mscno/esec-vault/internal/policy"
)

type fakeGuard struct {
	priv   string
	allow  bool
	asked  atomic.Int32
	caller string
}

func (g *fakeGuard) Has(project, env, pub string) bool { return project == "acme/store" }

func (g *fakeGuard) Key(req GuardRequest) (string, string, error) {
	g.asked.Add(1)
	g.caller = req.Caller
	if !g.allow {
		return "", "", errors.New("the guarded read was denied")
	}
	return g.priv, "touch", nil
}

func TestBrokerGuardedRead(t *testing.T) {
	skipUnlessUnix(t)
	path, keys := encryptedFixture(t, t.TempDir())
	// The broker holds no clear key: only the guard can open it, and no
	// policy rule is needed.
	client, auditPath, srv := startTestBroker(t, nil, &policy.Policy{Default: policy.Deny})
	g := &fakeGuard{priv: keys["ESEC_PRIVATE_KEY_DEV"], allow: true}
	srv.Guard, srv.Chain = g, func(uint32) string { return "zsh ▸ claude ▸ esec" }

	secrets, err := client.GetSecretsRequest(&Request{Op: OpGetSecrets, Project: "acme/store", Env: "dev", Path: path, Format: ".ejson", Session: "claude-1"})
	if err != nil || secrets["API_KEY"] != "s3cret" {
		t.Fatalf("guarded read: %v %v", secrets, err)
	}
	if g.asked.Load() != 1 || g.caller != "zsh ▸ claude ▸ esec" {
		t.Fatalf("guard asked %d times, caller %q", g.asked.Load(), g.caller)
	}
	// Denied at the dialog: nothing served.
	g.allow = false
	if _, err := client.GetSecrets("acme/store", "dev", path, ".ejson"); err == nil || !strings.Contains(err.Error(), "denied") {
		t.Fatalf("denied read: %v", err)
	}
	// A policy rule that denies still wins, before any dialog.
	srv.ReloadPolicy(&policy.Policy{Default: policy.Allow, Rules: []policy.Rule{{Project: "acme/store", Action: policy.Deny}}})
	before := g.asked.Load()
	if _, err := client.GetSecrets("acme/store", "dev", path, ".ejson"); err == nil || g.asked.Load() != before {
		t.Fatalf("policy deny: %v (asked %d)", err, g.asked.Load()-before)
	}
	var sawAllow bool
	for _, e := range readAudit(t, auditPath) {
		if e.Decision == "allow" && e.Detail == "guard touch" && e.Session == "claude-1" && e.Caller != "" {
			sawAllow = true
		}
	}
	if !sawAllow {
		t.Fatalf("audit: %+v", readAudit(t, auditPath))
	}
}

func TestForwardedBrokerServesGuardedOnly(t *testing.T) {
	skipUnlessUnix(t)
	path, keys := encryptedFixture(t, t.TempDir())
	client, _, srv := startTestBroker(t, map[string]map[string]string{"acme/other": keys}, &policy.Policy{Default: policy.Allow})
	srv.Forwarded = true
	srv.Guard = &fakeGuard{priv: keys["ESEC_PRIVATE_KEY_DEV"], allow: true}
	content := mustRead(t, path)
	// The file comes in the request; the path is the other machine's.
	got, err := client.GetSecretsRequest(&Request{Op: OpGetSecrets, Project: "acme/store", Env: "dev", Path: "/srv/app/.ejson.dev", Format: ".ejson", Content: content, Host: "web-1"})
	if err != nil || got["API_KEY"] != "s3cret" {
		t.Fatalf("forwarded guarded read: %v %v", got, err)
	}
	if _, err := client.GetSecretsRequest(&Request{Op: OpGetSecrets, Project: "acme/other", Env: "dev", Path: "/srv/app/.ejson.dev", Format: ".ejson", Content: content}); err == nil || !strings.Contains(err.Error(), "not guarded") {
		t.Fatalf("forwarded unguarded read: %v", err)
	}
	if _, err := client.GetSecretsRequest(&Request{Op: OpGetSecrets, Project: "acme/store", Env: "dev", Path: path, Format: ".ejson"}); err == nil {
		t.Fatal("a forwarded broker read a local path")
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path) //nolint:gosec // test fixture
	if err != nil {
		t.Fatal(err)
	}
	return data
}
