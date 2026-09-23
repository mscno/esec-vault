package runcmd

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/mscno/esec"
	"github.com/mscno/esec/pkg/projectfile"

	"github.com/mscno/esec-vault/internal/broker"
	"github.com/mscno/esec-vault/internal/policy"
)

func TestResolveSecretsFile(t *testing.T) {
	dir := t.TempDir()
	// Only an .env.dev exists.
	if err := os.WriteFile(filepath.Join(dir, ".env.dev"), []byte("A=B\n"), 0600); err != nil {
		t.Fatal(err)
	}

	path, format, err := resolveSecretsFile(dir, "dev", "")
	if err != nil {
		t.Fatal(err)
	}
	if format != ".env" || !strings.HasSuffix(path, ".env.dev") {
		t.Fatalf("got %s %s", path, format)
	}
	if !filepath.IsAbs(path) {
		t.Fatal("path must be absolute")
	}

	// Explicit format that does not exist errors.
	if _, _, err := resolveSecretsFile(dir, "dev", ".ejson"); err == nil {
		t.Fatal("expected error for missing .ejson.dev")
	}
	// Unknown environment errors.
	if _, _, err := resolveSecretsFile(dir, "prod", ""); err == nil {
		t.Fatal("expected error for missing environment")
	}
	// Explicit file path wins.
	p, f, err := resolveSecretsFile(dir, filepath.Join(dir, ".env.dev"), "")
	if err != nil || f != ".env" || p == "" {
		t.Fatalf("explicit path: %s %s %v", p, f, err)
	}
}

func TestRunInjectsSecretsFromBroker(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("broker requires unix sockets")
	}
	dir := t.TempDir()

	// Real encrypted secrets file in the repo.
	pub, priv, err := esec.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	var enc strings.Builder
	if _, err := esec.Encrypt(strings.NewReader(`{"_ESEC_PUBLIC_KEY": "`+pub+`", "GREETING": "hello-vault"}`), &enc, esec.FileFormatEjson); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".ejson.dev"), []byte(enc.String()), 0600); err != nil {
		t.Fatal(err)
	}
	if err := projectfile.WriteProjectFile(dir, "org/repo"); err != nil {
		t.Fatal(err)
	}

	// Live broker holding the project key, policy allowing dev. The socket
	// path must stay short (104-char unix socket limit on darwin), so
	// t.TempDir() is too long for it.
	sockDir, err := os.MkdirTemp("", "ev") //nolint:usetesting // see above
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(sockDir)
	sock := filepath.Join(sockDir, "b.sock")
	audit, err := broker.NewAuditLogger(filepath.Join(t.TempDir(), "audit.log"))
	if err != nil {
		t.Fatal(err)
	}
	srv := broker.NewServer(
		map[string]map[string]string{"org/repo": {"ESEC_PRIVATE_KEY_DEV": priv}},
		&policy.Policy{Default: policy.Deny, Rules: []policy.Rule{{Project: "*", Env: []string{"dev"}, Action: policy.Allow}}},
		audit, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Serve(ctx, sock) }()
	client := broker.NewClient(sock)
	deadline := time.Now().Add(5 * time.Second)
	for client.Ping() != nil {
		if time.Now().After(deadline) {
			t.Fatal("broker did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Run from the repo dir; child prints the secret.
	t.Chdir(dir)

	marker := filepath.Join(t.TempDir(), "out")
	cmd := []string{"sh", "-c", "printf '%s' \"$GREETING\" > " + marker}
	if err := Run(client, "dev", "", cmd); err != nil {
		t.Fatal(err)
	}
	out, err := os.ReadFile(marker) //nolint:gosec // test fixture path
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != "hello-vault" {
		t.Fatalf("child did not receive injected secret: %q", out)
	}

	// Denied environment must fail.
	if err := Run(client, "prod", "", []string{"true"}); err == nil {
		t.Fatal("prod should be denied")
	}
}
