package broker

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/mscno/esec"

	"github.com/mscno/esec-vault/internal/policy"
)

func skipUnlessUnix(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("broker requires unix sockets")
	}
}

// startTestBroker starts a broker on a temp socket with the given keys and
// policy, and returns the client, audit log path, and server (for white-box
// assertions).
func startTestBroker(t *testing.T, keys map[string]map[string]string, pol *policy.Policy) (*Client, string, *Server) {
	t.Helper()
	// The socket path must stay short (104-char unix socket limit on darwin).
	sockDir, err := os.MkdirTemp("", "ev")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(sockDir) })
	sock := filepath.Join(sockDir, "b.sock")
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "audit.log")
	audit, err := NewAuditLogger(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	srv := NewServer(keys, pol, audit, nil)
	srv.ApproveTimeout = 2 * time.Second
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = srv.Serve(ctx, sock) }()

	client := NewClient(sock)
	deadline := time.Now().Add(5 * time.Second)
	for {
		if err := client.Ping(); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("broker did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	return client, auditPath, srv
}

// encryptedFixture writes a real encrypted .ejson.dev file and returns its
// path plus the project keyring entries.
func encryptedFixture(t *testing.T, dir string) (string, map[string]string) {
	t.Helper()
	pub, priv, err := esec.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	plain := `{"_ESEC_PUBLIC_KEY": "` + pub + `", "DATABASE_URL": "postgres://x", "API_KEY": "s3cret"}`
	var out strings.Builder
	if _, err := esec.Encrypt(strings.NewReader(plain), &out, esec.FileFormatEjson); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, ".ejson.dev")
	if err := os.WriteFile(path, []byte(out.String()), 0644); err != nil {
		t.Fatal(err)
	}
	return path, map[string]string{"ESEC_PRIVATE_KEY_DEV": priv}
}

func readAudit(t *testing.T, path string) []AuditEntry {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var entries []AuditEntry
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line == "" {
			continue
		}
		var e AuditEntry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatal(err)
		}
		entries = append(entries, e)
	}
	return entries
}

func TestBrokerAllowDeny(t *testing.T) {
	skipUnlessUnix(t)
	dir := t.TempDir()
	secretsPath, entries := encryptedFixture(t, dir)
	keys := map[string]map[string]string{"org/repo": entries}

	pol := &policy.Policy{
		Default: policy.Deny,
		Rules: []policy.Rule{
			{Project: "*", Env: []string{"dev"}, Action: policy.Allow},
		},
	}
	client, auditPath, _ := startTestBroker(t, keys, pol)

	// list_envs
	resp, err := client.Call(&Request{Op: OpListEnvs, Project: "org/repo"})
	if err != nil || !resp.OK {
		t.Fatalf("list_envs failed: %v %+v", err, resp)
	}
	if len(resp.Envs) != 1 || resp.Envs[0] != "dev" {
		t.Fatalf("unexpected envs: %v", resp.Envs)
	}

	// allowed env
	secrets, err := client.GetSecrets("org/repo", "dev", secretsPath, ".ejson")
	if err != nil {
		t.Fatal(err)
	}
	if secrets["DATABASE_URL"] != "postgres://x" || secrets["API_KEY"] != "s3cret" {
		t.Fatalf("unexpected secrets: %v", secrets)
	}
	if _, leaked := secrets["_ESEC_PUBLIC_KEY"]; leaked {
		t.Fatal("public key field leaked into env")
	}

	// denied env
	if _, err := client.GetSecrets("org/repo", "prod", secretsPath, ".ejson"); err == nil {
		t.Fatal("prod should be denied")
	}

	// unknown project
	if _, err := client.GetSecrets("org/other", "dev", secretsPath, ".ejson"); err == nil {
		t.Fatal("unknown project should fail")
	}

	// audit log recorded decisions
	auditEntries := readAudit(t, auditPath)
	var allows, denies int
	for _, e := range auditEntries {
		if e.Op != OpGetSecrets {
			continue
		}
		if e.UID == 0 && runtime.GOOS == "linux" {
			t.Error("uid not recorded")
		}
		switch e.Decision {
		case "allow":
			allows++
		case "deny":
			denies++
		}
	}
	if allows == 0 || denies == 0 {
		t.Fatalf("expected allow and deny audit entries, got %+v", auditEntries)
	}
}

func TestBrokerAskApprove(t *testing.T) {
	skipUnlessUnix(t)
	dir := t.TempDir()
	secretsPath, entries := encryptedFixture(t, dir)
	keys := map[string]map[string]string{"org/repo": entries}

	pol := &policy.Policy{
		Default: policy.Deny,
		Rules:   []policy.Rule{{Project: "*", Env: []string{"dev"}, Action: policy.Ask}},
	}
	client, _, srv := startTestBroker(t, keys, pol)

	type result struct {
		secrets map[string]string
		err     error
	}
	done := make(chan result, 1)
	go func() {
		s, err := client.GetSecrets("org/repo", "dev", secretsPath, ".ejson")
		done <- result{s, err}
	}()

	// Wait for the pending approval to appear, then approve it.
	var id string
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		srv.mu.Lock()
		for k := range srv.pending {
			id = k
		}
		srv.mu.Unlock()
		if id != "" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if id == "" {
		t.Fatal("no pending approval appeared")
	}
	if err := client.Approve(id); err != nil {
		t.Fatal(err)
	}

	select {
	case r := <-done:
		if r.err != nil {
			t.Fatal(r.err)
		}
		if r.secrets["DATABASE_URL"] != "postgres://x" {
			t.Fatalf("unexpected secrets: %v", r.secrets)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("approved request did not complete")
	}
}

func TestBrokerAskTimeout(t *testing.T) {
	skipUnlessUnix(t)
	dir := t.TempDir()
	secretsPath, entries := encryptedFixture(t, dir)
	keys := map[string]map[string]string{"org/repo": entries}

	pol := &policy.Policy{
		Default: policy.Deny,
		Rules:   []policy.Rule{{Project: "*", Env: []string{"dev"}, Action: policy.Ask}},
	}
	client, _, _ := startTestBroker(t, keys, pol)
	client.Timeout = 10 * time.Second

	if _, err := client.GetSecrets("org/repo", "dev", secretsPath, ".ejson"); err == nil {
		t.Fatal("expected denial after approval timeout")
	}
}

func TestBrokerSocketPermissions(t *testing.T) {
	skipUnlessUnix(t)
	client, _, _ := startTestBroker(t, map[string]map[string]string{}, &policy.Policy{Default: policy.Deny})
	fi, err := os.Stat(client.SockPath)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0600 {
		t.Fatalf("socket must be 0600, got %o", fi.Mode().Perm())
	}
}

func TestKeyFor(t *testing.T) {
	s := NewServer(map[string]map[string]string{
		"org/repo": {"ESEC_PRIVATE_KEY": "k0", "ESEC_PRIVATE_KEY_DEV": "k1"},
	}, &policy.Policy{}, nil, nil)
	if k, err := s.keyFor("org/repo", "dev"); err != nil || k != "k1" {
		t.Fatalf("got %q %v", k, err)
	}
	if k, err := s.keyFor("org/repo", ""); err != nil || k != "k0" {
		t.Fatalf("got %q %v", k, err)
	}
	if _, err := s.keyFor("org/repo", "prod"); err == nil {
		t.Fatal("expected missing key error")
	}
	if _, err := s.keyFor("org/nope", "dev"); err == nil {
		t.Fatal("expected unknown project error")
	}
}
