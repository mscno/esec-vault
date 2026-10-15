package envrotate

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mscno/esec"

	"github.com/mscno/esec-vault/internal/keystore"
)

func setup(t *testing.T) (*keystore.Store, string, string) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("ESEC_VAULT_HOME", home)
	t.Setenv("ESEC_KEYRING_DIR", filepath.Join(home, "keyrings"))
	ks := keystore.New()
	pub, priv, err := esec.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if err := ks.Write("acme/store", map[string]string{EnvKey("dev"): priv, pubKeyEntry(pub): priv}, false); err != nil {
		t.Fatal(err)
	}
	return ks, pub, priv
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o640); err != nil { //nolint:gosec // checks that rotation keeps the mode
		t.Fatal(err)
	}
	if _, err := esec.EncryptFileInPlace(path); err != nil {
		t.Fatal(err)
	}
}

func TestRotateReencryptsAllFormatsAndKeepsOldKey(t *testing.T) {
	ks, pub, oldPriv := setup(t)
	repo := t.TempDir()
	envFile := filepath.Join(repo, ".env.dev")
	write(t, envFile, "ESEC_PUBLIC_KEY="+pub+"\nDATABASE_URL=postgres://db\nTOKEN=s3cret\n")
	jsonFile := filepath.Join(repo, "services", "api", ".ejson.dev")
	write(t, jsonFile, `{"_ESEC_PUBLIC_KEY": "`+pub+`", "token": "abc"}`)
	// A file with another key must be left alone.
	otherPub, _, _ := esec.GenerateKeypair()
	other := filepath.Join(repo, ".env.prod")
	write(t, other, "ESEC_PUBLIC_KEY="+otherPub+"\nTOKEN=prod\n")
	otherBefore, _ := os.ReadFile(other) //nolint:gosec // test temp dir
	// Files inside .git and node_modules are ignored.
	ignored := filepath.Join(repo, ".git", ".env.dev")
	write(t, ignored, "ESEC_PUBLIC_KEY="+pub+"\nTOKEN=x\n")

	res, err := Rotate(ks, "acme/store", "dev", repo)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Files) != 2 || res.OldPublic != pub || res.NewPublic == pub {
		t.Fatalf("unexpected result: %+v", res)
	}
	entries, err := ks.Read("acme/store")
	if err != nil {
		t.Fatal(err)
	}
	newPriv := entries[EnvKey("dev")]
	if newPriv == oldPriv || entries[pubKeyEntry(res.NewPublic)] != newPriv || entries[pubKeyEntry(pub)] != oldPriv {
		t.Fatal("keyring not updated with the new key and the retained old key")
	}
	plain, err := esec.DecryptFile(envFile, "", newPriv)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(plain), "TOKEN=s3cret") || !strings.Contains(string(plain), res.NewPublic) {
		t.Fatalf("rotated env file content: %s", plain)
	}
	if _, err := esec.DecryptFile(envFile, "", oldPriv); err == nil {
		t.Fatal("old key still decrypts the rotated file")
	}
	jplain, err := esec.DecryptFile(jsonFile, "", newPriv)
	if err != nil || !strings.Contains(string(jplain), `"abc"`) {
		t.Fatalf("rotated json: %s %v", jplain, err)
	}
	info, _ := os.Stat(envFile)
	if info.Mode().Perm() != 0o640 {
		t.Fatalf("file mode changed to %o", info.Mode().Perm())
	}
	otherAfter, _ := os.ReadFile(other) //nolint:gosec // test temp dir
	if !bytes.Equal(otherBefore, otherAfter) {
		t.Fatal("a file using another key was modified")
	}
	ign, _ := os.ReadFile(ignored) //nolint:gosec // test temp dir
	if !strings.Contains(string(ign), pub) {
		t.Fatal("file under .git was rewritten")
	}
	leftovers, _ := filepath.Glob(filepath.Join(repo, ".esec-rotate-*"))
	if len(leftovers) != 0 {
		t.Fatal("temporary files left behind")
	}
}

func TestRotateAbortsWithoutChangesOnAmbiguousFile(t *testing.T) {
	ks, pub, oldPriv := setup(t)
	repo := t.TempDir()
	good := filepath.Join(repo, ".env.dev")
	write(t, good, "ESEC_PUBLIC_KEY="+pub+"\nA=1\n")
	// The public key also appears as a value: rotation cannot tell which
	// occurrence to replace, so it must refuse before changing anything.
	bad := filepath.Join(repo, "app", ".env.dev")
	write(t, bad, "ESEC_PUBLIC_KEY="+pub+"\nCOPY="+pub+"\n")
	before, _ := os.ReadFile(good) //nolint:gosec // test temp dir

	if _, err := Rotate(ks, "acme/store", "dev", repo); err == nil {
		t.Fatal("ambiguous file accepted")
	}
	after, _ := os.ReadFile(good) //nolint:gosec // test temp dir
	if !bytes.Equal(before, after) {
		t.Fatal("a file changed although rotation failed")
	}
	entries, _ := ks.Read("acme/store")
	if entries[EnvKey("dev")] != oldPriv {
		t.Fatal("keyring changed although rotation failed")
	}
	leftovers, _ := filepath.Glob(filepath.Join(repo, "*", ".esec-rotate-*"))
	leftovers2, _ := filepath.Glob(filepath.Join(repo, ".esec-rotate-*"))
	if len(leftovers)+len(leftovers2) != 0 {
		t.Fatal("temporary files left behind")
	}
}

func TestRotateUnknownEnvironment(t *testing.T) {
	ks, _, _ := setup(t)
	if _, err := Rotate(ks, "acme/store", "prod", t.TempDir()); err == nil {
		t.Fatal("missing environment accepted")
	}
}
