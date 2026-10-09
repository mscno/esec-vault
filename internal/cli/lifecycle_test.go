package cli

import (
	"bytes"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/mscno/esec"
	"github.com/mscno/esec-vault/internal/identity"
	"github.com/mscno/esec-vault/internal/keyring"
	"github.com/mscno/esec-vault/internal/keystore"
	"github.com/mscno/esec-vault/internal/paths"
	"github.com/mscno/esec-vault/internal/remote"
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
