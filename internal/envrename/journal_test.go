package envrename

import (
	"os"
	"path/filepath"
	"testing"
)

func TestJournalResumeAndNoClobber(t *testing.T) {
	root := t.TempDir()
	from, to := filepath.Join(root, ".env.prod"), filepath.Join(root, ".env.production")
	if err := os.WriteFile(from, []byte("ciphertext"), 0600); err != nil {
		t.Fatal(err)
	}
	j := &Journal{Old: "prod", New: "production"}
	if err := j.Add(root, from, to, nil); err != nil {
		t.Fatal(err)
	}
	if err := j.Save(root); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(to, []byte("occupied"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := j.Apply(root); err == nil {
		t.Fatal("overwrote destination")
	}
	if err := os.Remove(to); err != nil {
		t.Fatal(err)
	}
	// Simulate a crash between linking the new filename and removing the old.
	if err := os.Link(from, to); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := loaded.Apply(root); err != nil {
		t.Fatal(err)
	}
	if err := loaded.Apply(root); err != nil {
		t.Fatalf("replay failed: %v", err)
	}
	if _, err := os.Stat(from); !os.IsNotExist(err) {
		t.Fatal("source still exists")
	}
	data, err := os.ReadFile(to) //nolint:gosec // test TempDir
	if err != nil || string(data) != "ciphertext" {
		t.Fatal("renamed file changed")
	}
}

func TestFindExactPatternsAndNestedProjects(t *testing.T) {
	root := t.TempDir()
	for _, dir := range []string{"sub", "nested", "node_modules"} {
		if err := os.Mkdir(filepath.Join(root, dir), 0700); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{".env.eu.prod", "sub/eu.prod.ejson", ".env.prod", "nested/.env.eu.prod", "node_modules/.env.eu.prod", "nested/esec.toml"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("data"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	pairs, err := Find(root, "eu.prod", "eu.production")
	if err != nil {
		t.Fatal(err)
	}
	if len(pairs) != 2 {
		t.Fatalf("matched wrong files: %v", pairs)
	}
	for _, p := range pairs {
		if err := safePath(root, p[1]); err != nil {
			t.Fatal(err)
		}
	}
}
