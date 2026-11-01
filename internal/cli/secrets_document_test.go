package cli

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mscno/esec"
	"github.com/mscno/esec-vault/internal/broker"
	"github.com/mscno/esec-vault/internal/keystore"
	"github.com/mscno/esec-vault/internal/paths"
	"github.com/mscno/esec-vault/internal/seal"
	"github.com/mscno/esec-vault/internal/secretfile"
	"github.com/mscno/esec/pkg/fileutils"
	coreseal "github.com/mscno/esec/pkg/seal"
)

func localDocumentFixture(t *testing.T) (path, pub string) {
	t.Helper()
	t.Setenv("ESEC_VAULT_HOME", t.TempDir())
	t.Setenv("ESEC_KEYRING_DIR", "")
	t.Setenv("ESEC_KEYRING_PATH", "")
	t.Setenv("ESEC_SECRET_STORE", "file")
	for _, entry := range os.Environ() {
		name, _, _ := strings.Cut(entry, "=")
		if strings.HasPrefix(name, "ESEC_PRIVATE_KEY") {
			t.Setenv(name, "")
		}
	}
	pub, priv, err := esec.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	writeDocumentTestFile(t, filepath.Join(root, "esec.toml"), []byte("project = 'acme/viewer'\n[files]\nformat = 'env'\nname = 'backend/.env.{env}'\n[env.dev]\nkey = '"+pub+"'\nguard = 'none'\n"))
	if err := os.Mkdir(filepath.Join(root, "backend"), 0700); err != nil {
		t.Fatal(err)
	}
	path = filepath.Join(root, "backend", ".env.dev")
	var encrypted bytes.Buffer
	if _, err := esec.Encrypt(strings.NewReader("ESEC_PUBLIC_KEY="+pub+"\nTOKEN=synthetic-viewer-secret\nEMPTY=\n"), &encrypted, esec.FileFormat(fileutils.Env)); err != nil {
		t.Fatal(err)
	}
	writeDocumentTestFile(t, path, encrypted.Bytes())
	if err := keystore.New().Write("acme/viewer", map[string]string{keystore.PubEntry(pub): priv}, false); err != nil {
		t.Fatal(err)
	}
	return path, pub
}

func writeDocumentTestFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestSecretDocumentLocalReadNeedsNoBrokerOrPolicy(t *testing.T) {
	path, _ := localDocumentFixture(t)
	before, _ := os.ReadFile(path) //nolint:gosec // test fixture
	info, _ := os.Stat(path)
	cmd := &SecretsShowCmd{File: path, Sock: filepath.Join(t.TempDir(), "absent.sock"), Session: "EsecVault app"}
	if _, err := os.Stat(paths.PolicyPath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("fixture unexpectedly has a policy")
	}
	for _, policy := range []string{"", "default = 'deny'\n"} {
		if policy != "" {
			writeDocumentTestFile(t, paths.PolicyPath(), []byte(policy))
		}
		var doc secretDocumentView
		output := stdoutOfRun(t, func() error { return cmd.Run(nil) })
		if err := json.Unmarshal([]byte(output), &doc); err != nil {
			t.Fatal(err)
		}
		if doc.File.Env != "dev" || doc.Revision != secretfile.Revision(before) || len(doc.Values) != 2 {
			t.Fatal("incorrect document metadata")
		}
		if doc.Values[0].Key != "EMPTY" || doc.Values[0].Value != "" || doc.Values[1].Value != "synthetic-viewer-secret" {
			t.Fatal("incorrect decrypted values")
		}
	}
	after, _ := os.ReadFile(path) //nolint:gosec // test fixture
	afterInfo, _ := os.Stat(path)
	if !bytes.Equal(before, after) || !info.ModTime().Equal(afterInfo.ModTime()) {
		t.Fatal("viewing changed the file")
	}
	audit, err := os.ReadFile(paths.AuditPath())
	if err != nil || bytes.Contains(audit, []byte("synthetic-viewer-secret")) {
		t.Fatal("audit missing or contains plaintext")
	}
	var entry broker.AuditEntry
	if err := json.Unmarshal(bytes.Split(bytes.TrimSpace(audit), []byte("\n"))[0], &entry); err != nil || entry.Decision != "allow" || entry.Session != cmd.Session || entry.Project != "acme/viewer" || entry.Env != "dev" {
		t.Fatal("local read missing audit attribution")
	}
}

func TestSecretDocumentGuardedReadNeverFallsBackToCachedKey(t *testing.T) {
	for _, source := range []string{"project", "seal"} {
		t.Run(source, func(t *testing.T) {
			path, pub := localDocumentFixture(t)
			root := filepath.Dir(filepath.Dir(path))
			if source == "project" {
				writeDocumentTestFile(t, filepath.Join(root, "esec.toml"), []byte("project = 'acme/viewer'\n[env.dev]\nkey = '"+pub+"'\nguard = 'touch'\n"))
			} else {
				sealed := []byte("synthetic sealed key; fake broker denies before opening it")
				if err := os.Mkdir(filepath.Join(root, ".esec"), 0700); err != nil {
					t.Fatal(err)
				}
				writeDocumentTestFile(t, filepath.Join(root, ".esec", "dev.age"), sealed)
				_, signer, err := ed25519.GenerateKey(nil)
				if err != nil {
					t.Fatal(err)
				}
				rec := &seal.Record{Key: pub, Guard: "session", Sealed: coreseal.Hash(sealed)}
				rec.Sign("acme/viewer", "dev", "synthetic-test", signer)
				if err := (seal.Records{"dev": rec}).Save(root); err != nil {
					t.Fatal(err)
				}
			}
			// A short socket path also works on macOS. The fake broker denies
			// the read despite the valid clear key still present in the fixture.
			socketDir, err := os.MkdirTemp("", "view-") //nolint:usetesting // t.TempDir includes the long test name, exceeding macOS's socket path limit
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.RemoveAll(socketDir) })
			listener, err := net.Listen("unix", filepath.Join(socketDir, "a.sock"))
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			requests := make(chan broker.Request, 1)
			go func() {
				conn, err := listener.Accept()
				if err != nil {
					return
				}
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				var req broker.Request
				if json.NewDecoder(conn).Decode(&req) == nil {
					requests <- req
					_ = json.NewEncoder(conn).Encode(broker.Response{Error: "denied by policy: synthetic guarded file"})
				}
			}()
			cmd := &SecretsShowCmd{File: path, Sock: listener.Addr().String()}
			out := stdoutOfRun(t, func() error {
				err := cmd.Run(nil)
				if err == nil || !strings.Contains(err.Error(), "denied by policy") {
					t.Error("guarded read did not honor the broker denial")
				}
				return nil
			})
			if out != "" {
				t.Fatal("guarded denial returned data")
			}
			select {
			case req := <-requests:
				if req.Op != broker.OpReadDocument || req.Digest == "" || req.Env != "dev" {
					t.Fatal("incorrect guarded request")
				}
			case <-time.After(time.Second):
				t.Fatal("guarded read bypassed broker")
			}
		})
	}
}

func TestSecretDocumentLocalReadFailsClosed(t *testing.T) {
	for _, failure := range []string{"bad config", "bad records", "renamed guarded file", "no local key", "audit unavailable"} {
		t.Run(failure, func(t *testing.T) {
			path, pub := localDocumentFixture(t)
			root := filepath.Dir(filepath.Dir(path))
			switch failure {
			case "bad config":
				writeDocumentTestFile(t, filepath.Join(root, "esec.toml"), []byte("project = ["))
			case "bad records":
				if err := os.Mkdir(filepath.Join(root, ".esec"), 0700); err != nil {
					t.Fatal(err)
				}
				writeDocumentTestFile(t, filepath.Join(root, ".esec", "seals.toml"), []byte("invalid = ["))
			case "renamed guarded file":
				writeDocumentTestFile(t, filepath.Join(root, "esec.toml"), []byte("project = 'acme/viewer'\n[env.prod]\nkey = '"+pub+"'\nguard = 'session'\n"))
			case "no local key":
				t.Setenv("ESEC_KEYRING_PATH", filepath.Join(root, "missing.keyring"))
			case "audit unavailable":
				if err := os.Mkdir(paths.AuditPath(), 0700); err != nil {
					t.Fatal(err)
				}
			}
			doc, err := (&SecretsShowCmd{File: path}).document()
			if err == nil || doc != nil {
				t.Fatal("failed read returned a document")
			}
		})
	}
}

func TestSecretDocumentUpdate(t *testing.T) {
	t.Setenv("ESEC_VAULT_HOME", t.TempDir())
	t.Setenv("ESEC_KEYRING_DIR", "")
	pub, priv, err := esec.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		format    fileutils.FileFormat
		text, key string
	}{
		{fileutils.Env, "ESEC_PUBLIC_KEY=" + pub + "\nTOKEN=old\nOTHER=untouched\n", "TOKEN"},
		{fileutils.Ejson, `{"_ESEC_PUBLIC_KEY":"` + pub + `","db":{"password":"old"},"OTHER":"untouched"}`, "db.password"},
		{fileutils.Etoml, "_ESEC_PUBLIC_KEY='" + pub + "'\nOTHER='untouched'\n[db]\npassword='old'\n", "db.password"},
		{fileutils.Eyaml, "_ESEC_PUBLIC_KEY: " + pub + "\nOTHER: untouched\ndb:\n  password: old\n", "db.password"},
	}
	for _, c := range cases {
		t.Run(string(c.format), func(t *testing.T) {
			var buf bytes.Buffer
			if _, err := esec.Encrypt(strings.NewReader(c.text), &buf, esec.FileFormat(c.format)); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), string(c.format)+".prod")
			if err := os.WriteFile(path, buf.Bytes(), 0640); err != nil { //nolint:gosec // verifies existing file permissions are preserved
				t.Fatal(err)
			}
			revision := secretfile.Revision(buf.Bytes())
			for _, value := range []string{"line one\nline two\n\"quotes\" $dollar \\ slash\tæ 🔐\n", "", "  spaces  "} {
				previous := revision
				var err error
				revision, err = updateSecretDocument(path, secretUpdate{Revision: revision, Key: c.key, Value: &value})
				if err != nil {
					t.Fatal(err)
				}
				data, err := os.ReadFile(path) //nolint:gosec // test fixture
				if err != nil {
					t.Fatal(err)
				}
				if revision != secretfile.Revision(data) || revision == previous {
					t.Fatal("incorrect saved revision")
				}
				got, err := secretfile.Check(data, c.format, c.key, priv)
				if err != nil || got != value {
					t.Fatalf("round trip failed: %v", err)
				}
				if plain, err := secretfile.Plain(data, c.format); err != nil || len(plain) != 0 {
					t.Fatalf("plaintext left on disk: %v", err)
				}
				other, err := secretfile.Check(data, c.format, "OTHER", priv)
				if err != nil || other != "untouched" {
					t.Fatal("changed another value")
				}
				if _, err := updateSecretDocument(path, secretUpdate{Revision: previous, Key: c.key, Value: &value}); err == nil {
					t.Fatal("stale edit accepted")
				}
				unchanged, _ := os.ReadFile(path) //nolint:gosec // test fixture
				if !bytes.Equal(data, unchanged) {
					t.Fatal("failed edit modified file")
				}
			}
			info, _ := os.Stat(path)
			if info.Mode().Perm() != 0640 {
				t.Fatal("permissions changed")
			}
			files, _ := os.ReadDir(filepath.Dir(path))
			if len(files) != 1 {
				t.Fatal("temporary file left behind")
			}
		})
	}
}

func TestSecretDocumentCreateAndReadOnly(t *testing.T) {
	t.Setenv("ESEC_VAULT_HOME", t.TempDir())
	t.Setenv("ESEC_KEYRING_DIR", "")
	pub, _, _ := esec.GenerateKeypair()
	for _, format := range []fileutils.FileFormat{fileutils.Env, fileutils.Eyaml} {
		text := "ESEC_PUBLIC_KEY=" + pub + "\n"
		if format == fileutils.Eyaml {
			text = "_ESEC_PUBLIC_KEY: " + pub + "\n_note: keep\n"
		}
		var out bytes.Buffer
		if _, err := esec.Encrypt(strings.NewReader(text), &out, esec.FileFormat(format)); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(t.TempDir(), string(format))
		if err := os.WriteFile(path, out.Bytes(), 0600); err != nil {
			t.Fatal(err)
		}
		value := "new value"
		revision, err := updateSecretDocument(path, secretUpdate{Revision: secretfile.Revision(out.Bytes()), Key: "NEW_KEY", Value: &value, Create: true})
		if err != nil {
			t.Fatal(err)
		}
		for _, key := range []string{"NEW_KEY", "bad\nINJECTED", "_note", "ESEC_PUBLIC_KEY"} {
			if _, err := updateSecretDocument(path, secretUpdate{Revision: revision, Key: key, Value: &value, Create: true}); err == nil {
				t.Fatalf("accepted invalid addition %s", key)
			}
		}
	}
}
