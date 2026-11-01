package cli

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/joho/godotenv"
	"github.com/mscno/esec"
	"github.com/mscno/esec-vault/internal/keystore"
	"github.com/mscno/esec-vault/internal/secretfile"
	"github.com/mscno/esec/pkg/fileutils"
	"github.com/mscno/esec/pkg/projectfile"
)

func initAnswer(t *testing.T, answer string) {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "input")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(answer); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	previous := os.Stdin
	os.Stdin = f
	t.Cleanup(func() { os.Stdin = previous; _ = f.Close() })
}

func TestInitPlaintextNeedsConsent(t *testing.T) {
	for _, tc := range []struct {
		name, answer string
		yes, success bool
	}{
		{name: "confirmed", answer: "y\n", success: true},
		{name: "declined", answer: "n\n"},
		{name: "empty answer", answer: "\n"},
		{name: "EOF"},
		{name: "script consent", yes: true, success: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, ctx := initFixture(t, "env")
			c.Yes = tc.yes
			initAnswer(t, tc.answer)
			path := filepath.Join(c.Dir, ".env.dev")
			original := "# keep this comment\nTOKEN=synthetic-token\nEMPTY=\nQUOTED=\"a=b # literal\"\n"
			writeInitFixture(t, path, original)
			err := c.Run(ctx)
			if (err == nil) != tc.success {
				t.Fatalf("success=%v error=%v", tc.success, err)
			}
			data, readErr := os.ReadFile(path) //nolint:gosec // test-owned file
			if readErr != nil {
				t.Fatal(readErr)
			}
			if !tc.success {
				assertInitCancelled(t, c, path, original)
				return
			}
			assertInitValues(t, c, path, original)
			info, _ := os.Stat(path)
			if info.Mode().Perm() != 0640 || !bytes.Contains(data, []byte("# keep this comment")) {
				t.Fatal("mode or comments lost")
			}
			if len(c.created) != 0 || len(c.encrypted) != 1 {
				t.Fatal("incorrect changed-file reporting")
			}
			if err := c.Run(ctx); err != nil {
				t.Fatal("repeat init failed:", err)
			}
			again, _ := os.ReadFile(path) //nolint:gosec // test-owned file
			if !bytes.Equal(data, again) || len(c.created) != 0 || len(c.encrypted) != 0 {
				t.Fatal("repeat init changed encrypted file")
			}
		})
	}
}

func assertInitCancelled(t *testing.T, c *ProjectInitCmd, path, original string) {
	t.Helper()
	data, err := os.ReadFile(path) //nolint:gosec // test-owned file
	if err != nil || string(data) != original {
		t.Fatal("failed init modified original")
	}
	if _, err := projectfile.Load(c.Dir); err == nil {
		t.Fatal("failed init created a project")
	}
	if _, err := keystore.New().Read(c.Project); !os.IsNotExist(err) {
		t.Fatal("failed init created keys")
	}
}

func assertInitValues(t *testing.T, c *ProjectInitCmd, path, original string) {
	t.Helper()
	entries, err := keystore.New().Read(c.Project)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := esec.DecryptFile(path, "", entries[keystore.EnvEntry("dev")])
	if err != nil {
		t.Fatal(err)
	}
	want, err := godotenv.Unmarshal(original)
	if err != nil {
		t.Fatal(err)
	}
	got, err := godotenv.Unmarshal(string(plain))
	if err != nil {
		t.Fatal(err)
	}
	delete(want, "ESEC_PUBLIC_KEY")
	delete(want, "_ESEC_PUBLIC_KEY")
	delete(got, "ESEC_PUBLIC_KEY")
	delete(got, "_ESEC_PUBLIC_KEY")
	if !reflect.DeepEqual(want, got) {
		t.Fatal("dotenv values changed during encryption")
	}
	data, _ := os.ReadFile(path) //nolint:gosec // test-owned file
	for _, value := range []string{"synthetic-token", "continuation-secret", "colon-secret"} {
		if bytes.Contains(data, []byte(value)) {
			t.Fatal("plaintext secret was written")
		}
	}
}

func TestInitPreservesDotenvValuesAndExistingPublicKey(t *testing.T) {
	for _, body := range []string{
		"TOKEN=synthetic-token\n",
		"MULTILINE=\"first\nOTHER=continuation-secret\"\nZERO=000123\nDOLLAR='literal $VALUE'\n",
		"TOKEN: colon-secret\n",
		"export TOKEN=synthetic-token\n",
	} {
		t.Run(strings.SplitN(body, "=", 2)[0], func(t *testing.T) {
			c, ctx := initFixture(t, "env")
			c.Yes = true
			pub, priv, err := esec.GenerateKeypair()
			if err != nil {
				t.Fatal(err)
			}
			if err := keystore.New().Write(c.Project, map[string]string{keystore.EnvEntry("dev"): priv}, false); err != nil {
				t.Fatal(err)
			}
			original := "export ESEC_PUBLIC_KEY=" + pub + "\n" + body
			path := filepath.Join(c.Dir, ".env.dev")
			writeInitFixture(t, path, original)
			if err := c.Run(ctx); err != nil {
				t.Fatal(err)
			}
			assertInitValues(t, c, path, original)
			data, _ := os.ReadFile(path) //nolint:gosec // test-owned file
			got, err := esec.ExtractPublicKey(data, esec.FileFormatEnv)
			if err != nil || hex.EncodeToString(got[:]) != pub {
				t.Fatal("existing public key changed")
			}
		})
	}
}

func TestInitRejectsUnsafeExistingFilesBeforeWriting(t *testing.T) {
	for _, tc := range []struct{ name, content, diagnostic string }{
		{"invalid header", "ESEC_PUBLIC_KEY=not-a-key\nTOKEN=synthetic-token\n", "invalid"},
		{"ciphertext without key", "TOKEN=ESEC[1:synthetic:ciphertext]\n", "encrypted values but has no"},
		{"invalid dotenv", "TOKEN=\"unterminated\n", "syntax"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, ctx := initFixture(t, "env")
			c.Yes = true
			c.Env = []string{"prod", "dev"}
			path := filepath.Join(c.Dir, ".env.dev")
			writeInitFixture(t, path, tc.content)
			err := c.Run(ctx)
			if err == nil || !strings.Contains(err.Error(), tc.diagnostic) || strings.Contains(err.Error(), "synthetic-token") {
				t.Fatalf("unexpected diagnostic: %v", err)
			}
			assertInitCancelled(t, c, path, tc.content)
			if _, err := os.Stat(filepath.Join(c.Dir, ".env.prod")); !os.IsNotExist(err) {
				t.Fatal("failed init published earlier file")
			}
		})
	}
}

func TestInitRefusesChangedFilesAndSymlinks(t *testing.T) {
	c, _ := initFixture(t, "env")
	c.Yes = true
	path := filepath.Join(c.Dir, ".env.dev")
	writeInitFixture(t, path, "TOKEN=synthetic-token\n")
	p, err := inspectInitFile(c.Dir, ".env", "dev")
	if err != nil {
		t.Fatal(err)
	}
	pub, _, _ := esec.GenerateKeypair()
	if err := p.prepare(c, "dev", pub); err != nil {
		t.Fatal(err)
	}
	writeInitFixture(t, path, "TOKEN=concurrent-edit\n")
	if err := p.publish(); err == nil {
		t.Fatal("overwrote concurrent edit")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(t.TempDir(), "target")
	writeInitFixture(t, other, "TOKEN=external\n")
	if err := os.Symlink(other, path); err != nil {
		t.Fatal(err)
	}
	if _, err := inspectInitFile(c.Dir, ".env", "dev"); err == nil {
		t.Fatal("accepted symlink")
	}
}

func TestInitEncryptsExistingStructuredFiles(t *testing.T) {
	for _, tc := range []struct{ format, content string }{
		{"ejson", `{"TOKEN":"synthetic-token","nested":{"password":"another-value"},"PORT":5432}`},
		{"eyaml", "---\nTOKEN: synthetic-token\nnested:\n  password: another-value\nPORT: 5432\n"},
		{"etoml", "TOKEN='synthetic-token'\nPORT=5432\n[nested]\npassword='another-value'\n"},
	} {
		t.Run(tc.format, func(t *testing.T) {
			c, ctx := initFixture(t, tc.format)
			c.Yes = true
			f := "." + tc.format
			path, _, err := secretsTemplate(c.Dir, f, "dev", "")
			if err != nil {
				t.Fatal(err)
			}
			writeInitFixture(t, path, tc.content)
			if err := c.Run(ctx); err != nil {
				t.Fatal(err)
			}
			keys, err := keystore.New().Read(c.Project)
			if err != nil {
				t.Fatal(err)
			}
			plain, err := esec.DecryptFile(path, "", keys[keystore.EnvEntry("dev")])
			if err != nil {
				t.Fatal(err)
			}
			want, err := secretfile.DocumentValues([]byte(tc.content), fileutils.FileFormat(f))
			if err != nil {
				t.Fatal(err)
			}
			got, err := secretfile.DocumentValues(plain, fileutils.FileFormat(f))
			if err != nil || !reflect.DeepEqual(want, got) {
				t.Fatal("structured values changed")
			}
		})
	}
}

func TestInitMismatchedKeysHaveAccurateErrors(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		t.Run(fmt.Sprint(encrypted), func(t *testing.T) {
			c, ctx := initFixture(t, "env")
			c.Yes = true
			if err := c.Run(ctx); err != nil {
				t.Fatal(err)
			}
			pub, _, _ := esec.GenerateKeypair()
			data := []byte("ESEC_PUBLIC_KEY=" + pub + "\nTOKEN=synthetic-token\n")
			want := "is plaintext but has a different public key"
			if encrypted {
				var out bytes.Buffer
				if _, err := esec.Encrypt(bytes.NewReader(data), &out, esec.FileFormatEnv); err != nil {
					t.Fatal(err)
				}
				data = out.Bytes()
				want = "contains values encrypted to a different public key"
			}
			path := filepath.Join(c.Dir, ".env.dev")
			writeInitFixture(t, path, string(data))
			err := c.Run(ctx)
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("incorrect error: %v", err)
			}
			after, _ := os.ReadFile(path) //nolint:gosec // test-owned file
			if !bytes.Equal(data, after) {
				t.Fatal("mismatched file was modified")
			}
		})
	}
}

func TestInitEncryptsRemainingPlaintextWithoutReplacingCiphertext(t *testing.T) {
	c, ctx := initFixture(t, "env")
	c.Yes = true
	path := filepath.Join(c.Dir, ".env.dev")
	writeInitFixture(t, path, "TOKEN=synthetic-token\n")
	if err := c.Run(ctx); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(path) //nolint:gosec // test-owned file
	writeInitFixture(t, path, string(before)+"NEW=second-secret\n")
	if err := c.Run(ctx); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(path) //nolint:gosec // test-owned file
	oldValues, _ := godotenv.Unmarshal(string(before))
	newValues, _ := godotenv.Unmarshal(string(after))
	if oldValues["TOKEN"] != newValues["TOKEN"] || bytes.Contains(after, []byte("second-secret")) {
		t.Fatal("existing ciphertext changed or plaintext left")
	}
	assertInitValues(t, c, path, "TOKEN=synthetic-token\nNEW=second-secret\n")
}

func TestProjectInitPlaintextCLI(t *testing.T) {
	r := newGuardRig(t)
	repo := initTestRepo(t)
	path := filepath.Join(repo, ".env.dev")
	original := "TOKEN=synthetic-token\n"
	writeInitFixture(t, path, original)
	args := []string{"project", "init", "--project", "acme/plain-init", "--format", "env", "--json"}
	out, code := r.run(repo, "", args...)
	if code == 0 || !strings.Contains(out, "[y/N]") || !strings.Contains(out, "encryption cancelled") {
		t.Fatalf("EOF must decline: %s", out)
	}
	before, _ := os.ReadFile(path) //nolint:gosec // test-owned file
	if string(before) != original {
		t.Fatal("CLI changed file without consent")
	}
	if _, err := projectfile.Load(repo); err == nil {
		t.Fatal("CLI created project without consent")
	}
	cmd := exec.Command(r.bin, args...)
	cmd.Dir, cmd.Env, cmd.Stdin = repo, r.env, strings.NewReader("y\n")
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("confirmed init: %v %s", err, stderr.String())
	}
	if strings.Contains(stdout.String()+stderr.String(), "synthetic-token") {
		t.Fatal("CLI leaked plaintext")
	}
	if !strings.Contains(stderr.String(), "[y/N]") {
		t.Fatal("missing confirmation on stderr")
	}
	var result initResult
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if len(result.Created) != 0 || len(result.Encrypted) != 1 || result.Encrypted[0] != ".env.dev" {
		t.Fatal("CLI did not report existing-file encryption")
	}
	after, _ := os.ReadFile(path) //nolint:gosec // test-owned file
	if !bytes.Contains(after, []byte("ESEC_PUBLIC_KEY=")) || !bytes.Contains(after, []byte("ESEC[")) || bytes.Contains(after, []byte("synthetic-token")) {
		t.Fatal("CLI did not encrypt file")
	}
}

func TestInitNeverReactivatesHistoricalKey(t *testing.T) {
	for _, metadata := range []bool{false, true} {
		t.Run(fmt.Sprint(metadata), func(t *testing.T) {
			c, ctx := initFixture(t, "env")
			c.Yes = true
			oldPub, oldPriv, err := esec.GenerateKeypair()
			if err != nil {
				t.Fatal(err)
			}
			_, activePriv, err := esec.GenerateKeypair()
			if err != nil {
				t.Fatal(err)
			}
			entries := map[string]string{keystore.EnvEntry("dev"): activePriv, keystore.PubEntry(oldPub): oldPriv}
			if err := keystore.New().Write(c.Project, entries, false); err != nil {
				t.Fatal(err)
			}
			if metadata {
				pf := &projectfile.File{Project: c.Project}
				pf.SetEnv("dev", oldPub)
				if err := pf.Save(c.Dir); err != nil {
					t.Fatal(err)
				}
			}
			path := filepath.Join(c.Dir, ".env.dev")
			original := "ESEC_PUBLIC_KEY=" + oldPub + "\nTOKEN=synthetic-token\n"
			writeInitFixture(t, path, original)
			err = c.Run(ctx)
			if err == nil || !strings.Contains(err.Error(), "different public key") {
				t.Fatalf("historical key was accepted: %v", err)
			}
			after, _ := os.ReadFile(path) //nolint:gosec // test-owned file
			if string(after) != original {
				t.Fatal("mismatched file changed")
			}
			stored, err := keystore.New().Read(c.Project)
			if err != nil || stored[keystore.EnvEntry("dev")] != activePriv || stored[keystore.PubEntry(oldPub)] != oldPriv {
				t.Fatal("active or historical key changed")
			}
			pf, err := projectfile.Load(c.Dir)
			if metadata {
				if err != nil || pf.Env["dev"].Key != oldPub {
					t.Fatal("existing metadata changed")
				}
			} else if err == nil {
				t.Fatal("project published despite mismatch")
			}
		})
	}
}
