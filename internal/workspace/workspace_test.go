package workspace

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/mscno/esec/pkg/projectfile"
)

func TestRegistry(t *testing.T) { //nolint:gocyclo // one story, step by step
	t.Setenv("ESEC_VAULT_HOME", t.TempDir())
	src := t.TempDir()
	store := filepath.Join(src, "store")
	api := filepath.Join(src, "mono", "services", "api")
	deep := filepath.Join(src, "node_modules", "pkg")
	for dir, id := range map[string]string{store: "acme/store", api: "acme/mono/services/api", deep: "acme/ignored"} {
		if err := os.MkdirAll(dir, 0750); err != nil {
			t.Fatal(err)
		}
		if err := projectfile.WriteProjectFile(dir, id); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now().UTC().Truncate(time.Second)
	r, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	found, err := r.Scan(src, 4, now)
	if err != nil || len(found) != 2 {
		t.Fatalf("scan found %v %v", found, err)
	}
	if err := r.Save(); err != nil {
		t.Fatal(err)
	}
	r, _ = Load()
	if len(r.Projects()["acme/store"]) != 1 || len(r.Projects()["acme/mono/services/api"]) != 1 {
		t.Fatalf("projects: %v", r.Projects())
	}
	// Adding again refreshes; a second clone is a second checkout.
	if _, isNew, _ := r.Add(store, now); isNew {
		t.Fatal("re-added a known checkout")
	}
	clone := filepath.Join(src, "store-2")
	if err := os.MkdirAll(clone, 0750); err != nil {
		t.Fatal(err)
	}
	if err := projectfile.WriteProjectFile(clone, "acme/store"); err != nil {
		t.Fatal(err)
	}
	if _, isNew, err := r.Add(clone, now); !isNew || err != nil {
		t.Fatalf("second checkout: %v", err)
	}
	if len(r.Projects()["acme/store"]) != 2 {
		t.Fatal("two checkouts of one project")
	}
	// A removed directory is pruned; a renamed project shows as moved.
	if err := os.RemoveAll(clone); err != nil {
		t.Fatal(err)
	}
	if err := projectfile.WriteProjectFile(store, "acme/shop"); err != nil {
		t.Fatal(err)
	}
	for _, c := range r.Checkouts {
		if c.Path == store || filepath.Base(c.Path) == "store" {
			if Check(c) != StatusMoved {
				t.Fatalf("renamed project: %s", Check(c))
			}
		}
	}
	if gone := r.Prune(); len(gone) != 1 {
		t.Fatalf("pruned %v", gone)
	}
	if !r.Remove(api) || r.Remove(api) {
		t.Fatal("remove")
	}
}
