package cli

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/mscno/esec"
	"github.com/mscno/esec-vault/internal/identity"
	"github.com/mscno/esec-vault/internal/keyring"
	"github.com/mscno/esec-vault/internal/keystore"
	"github.com/mscno/esec-vault/internal/paths"
	"github.com/mscno/esec-vault/internal/remote"
	"github.com/mscno/esec-vault/internal/service"
)

func TestCLIBackupAndFreshRecover(t *testing.T) {
	t.Setenv("ESEC_VAULT_HOME", t.TempDir())
	t.Setenv("ESEC_KEYRING_DIR", "")
	ctx := &cliCtx{Logger: slog.Default(), Keyring: keyring.NewMemory(), Quiet: true}
	phrase, err := identity.Init(ctx.Keyring, " spaced password ", nil)
	if err != nil {
		t.Fatal(err)
	}
	repo := t.TempDir()
	c := ProjectInitCmd{Project: "org/app", Dir: repo, Env: []string{"dev", "api.prod"}, Format: "env", Template: true}
	if err := c.Run(ctx); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(repo, ".env.api.prod")) //nolint:gosec // isolated test directory
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, []byte("ANSWER=secret-value\n")...)
	var encrypted bytes.Buffer
	if _, err := esec.Encrypt(bytes.NewReader(data), &encrypted, esec.FileFormatEnv); err != nil {
		t.Fatal(err)
	}
	old, err := keystore.New().Read("org/app")
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "backup.esec")
	if err := (&BackupCmd{Out: out, Verify: true}).Run(ctx); err != nil {
		t.Fatal(err)
	}
	if err := c.Run(ctx); err != nil {
		t.Fatal("repeat init must preserve keys:", err)
	}
	// Fresh home and empty keychain. Feed two lines through the actual prompts.
	t.Setenv("ESEC_VAULT_HOME", t.TempDir())
	ctx.Keyring = keyring.NewMemory()
	in, err := os.CreateTemp(t.TempDir(), "stdin")
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	if _, err := fmt.Fprintf(in, "%s\n spaced password \n", phrase); err != nil {
		t.Fatal(err)
	}
	if _, err := in.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	stdin := os.Stdin
	os.Stdin = in
	defer func() { os.Stdin = stdin }()
	if err := (&RecoverCmd{File: out}).Run(ctx); err != nil {
		t.Fatal(err)
	}
	got, err := keystore.New().Read("org/app")
	if err != nil {
		t.Fatal(err)
	}
	if got["ESEC_PRIVATE_KEY_API_PROD"] != old["ESEC_PRIVATE_KEY_API_PROD"] {
		t.Fatal("wrong private key restored")
	}
	var plain bytes.Buffer
	if _, err := esec.Decrypt(bytes.NewReader(encrypted.Bytes()), &plain, "api.prod", esec.FileFormatEnv, ".", got["ESEC_PRIVATE_KEY_API_PROD"]); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(plain.Bytes(), []byte("ANSWER=secret-value")) {
		t.Fatal("restored key cannot decrypt project secrets")
	}
	if _, err := os.Stat(paths.IdentityFile()); err != nil {
		t.Fatal(err)
	}
}

func TestRestartRefusesStaleManagedDaemon(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("managed daemon requires a unix service manager")
	}
	dir := t.TempDir()
	vault := filepath.Join(dir, "vault")
	noop := func(context.Context, string, ...string) ([]byte, error) { return nil, nil }
	m, err := service.NewAt(runtime.GOOS, os.Getuid(), dir, vault, "", noop)
	if err != nil {
		t.Fatal(err)
	}
	// Nothing is installed, so there is nothing stale to complain about.
	if err := requireCurrent(m); err != nil {
		t.Fatal("uninstalled manager rejected:", err)
	}
	older := writeExe(t, "old executable")
	if err := m.Install(context.Background(), older, false); err != nil {
		t.Fatal(err)
	}
	if err := requireCurrentWith(m, older); err != nil {
		t.Fatal("matching copy rejected:", err)
	}
	// A CLI newer than the managed copy must be refused, otherwise restart
	// would silently keep running the old code after an upgrade.
	newer := writeExe(t, "newer executable")
	err = requireCurrentWith(m, newer)
	if err == nil {
		t.Fatal("stale managed copy accepted")
	}
	if !strings.Contains(err.Error(), "daemon upgrade") {
		t.Fatalf("error does not point at the fix: %v", err)
	}
}

// writeExe creates a stand-in executable used as an install source.
func writeExe(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "exe")
	if err := os.WriteFile(p, []byte(content), 0700); err != nil { //nolint:gosec // test executable fixture
		t.Fatal(err)
	}
	return p
}

func TestNoninteractiveRemoteAddNeverPrompts(t *testing.T) {
	t.Setenv("ESEC_VAULT_HOME", t.TempDir())
	c := RemoteAddCmd{Name: "bad", Type: "rclone"}
	if err := c.Run(&cliCtx{}); err == nil {
		t.Fatal("missing fields accepted")
	}
	good := RemoteAddCmd{Name: "local", Type: "file", Dir: t.TempDir(), Prefix: "v2"}
	if err := good.Run(&cliCtx{}); err != nil {
		t.Fatal(err)
	}
	cfg, err := remote.Load()
	if err != nil || cfg.Default != "local" {
		t.Fatalf("config: %v", err)
	}
}
