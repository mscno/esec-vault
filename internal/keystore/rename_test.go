package keystore

import (
	"strings"
	"testing"
)

func TestRenameEnvNamesAndKeyringCollisions(t *testing.T) {
	s := &Store{Dir: t.TempDir()}
	private := strings.Repeat("01", 32)
	pub, err := PublicHex(private)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Write("acme/store", map[string]string{EnvEntry("prod"): private}, false); err != nil {
		t.Fatal(err)
	}
	if err := s.RenameEnv("acme/store", "prod", "production", pub, true); err != nil {
		t.Fatal(err)
	}
	if err := s.RenameEnv("acme/store", "prod", "production", pub, false); err != nil {
		t.Fatal(err)
	}
	if err := s.RenameEnv("acme/store", "prod", "production", pub, false); err != nil {
		t.Fatalf("retry: %v", err)
	}
	entries, err := s.Read("acme/store")
	if err != nil {
		t.Fatal(err)
	}
	if entries[EnvEntry("prod")] != "" || entries[EnvEntry("production")] != private || entries[PubEntry(pub)] != private {
		t.Fatal("mutable or immutable entries lost")
	}
	if err := s.RenameEnv("acme/store", "absent", "production", pub, true); err == nil {
		t.Fatal("accepted destination with no old named entry")
	}
	if err := s.RenameEnv("acme/store", "production", "next", strings.Repeat("ff", 32), true); err == nil {
		t.Fatal("moved a stale named key")
	}
}
