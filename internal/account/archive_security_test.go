package account

import (
	"os"
	"path/filepath"
	"testing"
)

func TestArchivePathConfinement(t *testing.T) {
	for _, path := range []string{"../.env", "/tmp/.env", ".git/.env", ".esec-keyring/.env", "a/../../.env", "a\\.env", ".esec/../../key.age"} {
		if safeArchivePath(path, "secrets") || safeArchivePath(path, "seal") {
			t.Errorf("unsafe path accepted: %s", path)
		}
	}
	rootPath := t.TempDir()
	outside := filepath.Join(t.TempDir(), ".env.dev")
	if err := os.WriteFile(outside, []byte("not-an-archive"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(rootPath, ".env.dev")); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if _, err := readArchiveFile(root, ".env.dev"); err == nil {
		t.Fatal("archive followed a symlink outside its checkout")
	}
}
