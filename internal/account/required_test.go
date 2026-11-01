package account

import (
	"errors"
	"testing"

	"github.com/mscno/esec-vault/internal/devicekey"
	"github.com/mscno/esec-vault/internal/keyring"
)

func TestRequireLoginRejectsIncompleteEnrollmentAndLogout(t *testing.T) {
	t.Setenv("ESEC_VAULT_HOME", t.TempDir())
	kr := keyring.NewMemory()
	if err := RequireLogin(kr); !errors.Is(err, ErrNotLoggedIn) {
		t.Fatalf("missing account: %v", err)
	}
	st := &State{Server: "https://vault.example.com", User: "gh:53101343", DeviceID: "d_test"}
	if err := st.Save(); err != nil {
		t.Fatal(err)
	}
	if err := RequireLogin(kr); !errors.Is(err, ErrUnconfirmed) {
		t.Fatalf("pending enrollment: %v", err)
	}
	st.Chain.Root = "pinned-root"
	if err := st.Save(); err != nil {
		t.Fatal(err)
	}
	if err := RequireLogin(kr); err == nil {
		t.Fatal("missing device keys accepted")
	}
	dev, err := devicekey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if err := dev.Save(kr); err != nil {
		t.Fatal(err)
	}
	if err := RequireLogin(kr); !errors.Is(err, ErrNotLoggedIn) {
		t.Fatalf("missing session accepted: %v", err)
	}
	if err := kr.Set(SessionTokenName, "stored-session"); err != nil {
		t.Fatal(err)
	}
	if err := RequireLogin(kr); err != nil {
		t.Fatal(err)
	}
	if err := kr.Delete(SessionTokenName); err != nil {
		t.Fatal(err)
	}
	if err := RequireLogin(kr); !errors.Is(err, ErrNotLoggedIn) {
		t.Fatalf("logout accepted: %v", err)
	}
}
