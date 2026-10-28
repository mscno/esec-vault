package keystore

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mscno/esec"
)

func TestKeysAreOnlyAdded(t *testing.T) {
	s := &Store{Dir: filepath.Join(t.TempDir(), "keyrings")}
	pub, priv, err := esec.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	// A key written only under its name is filed under its public key too.
	if err := s.Write("acme/store", map[string]string{EnvEntry("prod"): priv}, false); err != nil {
		t.Fatal(err)
	}
	got, err := s.Read("acme/store")
	if err != nil || got[PubEntry(pub)] != priv {
		t.Fatalf("named key not filed under its public key: %v %v", got, err)
	}
	// Repointing the name is fine; the old key stays filed.
	pub2, priv2, _ := esec.GenerateKeypair()
	got[EnvEntry("prod")] = priv2
	if err := s.Write("acme/store", got, true); err != nil {
		t.Fatal(err)
	}
	got, _ = s.Read("acme/store")
	if got[PubEntry(pub)] != priv || got[PubEntry(pub2)] != priv2 {
		t.Fatalf("rotation lost a key: %v", got)
	}
	// Removing a filed key is refused.
	delete(got, PubEntry(pub))
	delete(got, EnvEntry("prod"))
	if err := s.Write("acme/store", got, true); err == nil || !strings.Contains(err.Error(), "only ever added") {
		t.Fatalf("removal accepted: %v", err)
	}
	// Guarding replaces the clear copy, and only through WriteGuarded.
	got, _ = s.Read("acme/store")
	delete(got, PubEntry(pub))
	got[GuardEntry(pub)] = "wrapped"
	if err := s.Write("acme/store", got, true); err == nil {
		t.Fatal("plain Write dropped a key for its guarded form")
	}
	if err := s.WriteGuarded("acme/store", got); err != nil {
		t.Fatal(err)
	}
	got, _ = s.Read("acme/store")
	if _, isClear := got[PubEntry(pub)]; isClear || got[GuardEntry(pub)] != "wrapped" {
		t.Fatalf("guarding: %v", got)
	}
	// A guarded key is never changed or dropped.
	got[GuardEntry(pub)] = "other"
	if err := s.WriteGuarded("acme/store", got); err == nil {
		t.Fatal("changed a guarded key")
	}
}

func TestEnvName(t *testing.T) {
	for name, want := range map[string]string{
		EnvEntry("api.dev"):                "api.dev",
		GuardEnvEntry("prod"):              "prod",
		PubEntry(strings.Repeat("ab", 32)): "",
		"ESEC_GUARD_IDENTITY":              "",
	} {
		got, ok := EnvName(name)
		if got != want || ok != (want != "") {
			t.Errorf("EnvName(%s) = %q %v", name, got, ok)
		}
	}
}

func TestRepairFilesNamedKeys(t *testing.T) {
	s := &Store{Dir: filepath.Join(t.TempDir(), "keyrings")}
	pub, priv, _ := esec.GenerateKeypair()
	// An old keyring, written before keys were filed by public key.
	if err := os.MkdirAll(s.Dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(s.Dir, "acme_old.keyring"), []byte("# ESEC_PROJECT=acme/old\n"+EnvEntry("dev")+"="+priv+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	added, err := s.Repair("acme/old")
	if err != nil || len(added) != 1 || added[0] != PubEntry(pub) {
		t.Fatalf("repair: %v %v", added, err)
	}
	got, _ := s.Read("acme/old")
	if got[PubEntry(pub)] != priv {
		t.Fatalf("not filed: %v", got)
	}
}
