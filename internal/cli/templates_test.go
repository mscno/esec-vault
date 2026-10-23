package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mscno/esec"
	"github.com/mscno/esec-vault/internal/keystore"
)

func TestExampleTemplatesAreEncryptedBeforeWriting(t *testing.T) {
	for _, format := range []string{"etoml", "ejson", "env"} {
		t.Run(format, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("ESEC_VAULT_HOME", home)
			t.Setenv("ESEC_KEYRING_DIR", "")
			t.Setenv("ESEC_CONFIG", "")
			cfg := "default_format='" + format + "'\n[files]\ncreate='{env}.{format}'\n"
			if err := os.WriteFile(filepath.Join(home, "config.toml"), []byte(cfg), 0600); err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			name, content := "example."+format, "TOKEN=template-secret\n"
			if format == "env" {
				name = ".env.example"
			}
			if format == "etoml" {
				content = "[database]\npassword='template-secret'\nport=5432\n"
			}
			if format == "ejson" {
				content = `{"TOKEN":"template-secret","PORT":5432}`
			}
			if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0600); err != nil {
				t.Fatal(err)
			}
			c := ProjectInitCmd{Dir: dir, Env: []string{"dev"}, Template: true}
			if err := c.create("org/template"); err != nil {
				t.Fatal(err)
			}
			p := filepath.Join(dir, "dev."+format)
			enc, err := os.ReadFile(p) //nolint:gosec // test-owned template output
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(enc, []byte("template-secret")) {
				t.Fatal("template value written in plaintext")
			}
			entries, err := keystore.New().Read("org/template")
			if err != nil {
				t.Fatal(err)
			}
			plain, err := esec.DecryptFile(p, "", entries[environmentKey("dev")])
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Contains(plain, []byte("template-secret")) {
				t.Fatal("template default did not survive encryption")
			}
			// A second environment uses the same example but a distinct key.
			add := EnvAddCmd{Env: "prod", Project: "org/template", Dir: dir, Template: true}
			if err := add.Run(&cliCtx{}); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(filepath.Join(dir, "prod."+format)); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestAmbiguousTemplatesDoNotCreateKeys(t *testing.T) {
	t.Setenv("ESEC_VAULT_HOME", t.TempDir())
	t.Setenv("ESEC_KEYRING_DIR", "")
	t.Setenv("ESEC_CONFIG", "")
	dir := t.TempDir()
	for _, n := range []string{"example.etoml", ".etoml.example"} {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("A='value'"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	c := ProjectInitCmd{Dir: dir, Env: []string{"dev"}, Format: "etoml", Template: true}
	if err := c.create("org/ambiguous"); err == nil || !strings.Contains(err.Error(), "ambiguous") {
		t.Fatalf("expected ambiguity: %v", err)
	}
	if _, err := keystore.New().Read("org/ambiguous"); !os.IsNotExist(err) {
		t.Fatalf("failed template created keys: %v", err)
	}
}
