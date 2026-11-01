package cli

import (
	"context"
	"fmt"
	"regexp"
	"testing"
	"time"

	"github.com/mscno/esec-vault/internal/account"
	"github.com/mscno/esec-vault/internal/identity"
	"github.com/mscno/esec-vault/internal/keyring"
	"github.com/mscno/esec-vault/internal/servertest"
)

type enrollmentUI struct {
	t *testing.T
	h *servertest.Harness
}

func (u enrollmentUI) Printf(f string, args ...any) {
	if code := regexp.MustCompile(`enter ([0-9A-Z]{4}-[0-9A-Z]{4})`).FindStringSubmatch(fmt.Sprintf(f, args...)); code != nil {
		if err := u.h.Browser("mscno").Confirm(code[1], true); err != nil {
			u.t.Error(err)
		}
	}
}
func (enrollmentUI) Confirm(string) bool { return true }
func (enrollmentUI) Secret(string) (string, error) {
	return "", fmt.Errorf("unexpected enrollment prompt")
}
func enrollTestAccount(t *testing.T, kr keyring.Keyring) {
	t.Helper()
	h := servertest.Start(t, 53101343)
	h.GitHub.AddUser(53101343, "mscno")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	a, err := account.Login(ctx, kr, enrollmentUI{t, h}, account.LoginOptions{Server: h.URL, Name: "test", Poll: time.Millisecond, BootstrapToken: servertest.BootstrapToken})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Sync(ctx, account.SyncOptions{}); err != nil {
		t.Fatal(err)
	}
}
func (r *guardRig) connect() {
	r.t.Helper()
	r.t.Setenv("ESEC_VAULT_HOME", r.home)
	r.t.Setenv("ESEC_KEYRING_DIR", "")
	r.t.Setenv("ESEC_SECRET_STORE", "file")
	enrollTestAccount(r.t, keyring.NewOS())
}

func enrollFileAccount(t *testing.T, home string) {
	t.Helper()
	t.Setenv("ESEC_VAULT_HOME", home)
	t.Setenv("ESEC_KEYRING_DIR", "")
	t.Setenv("ESEC_SECRET_STORE", "file")
	kr := keyring.NewOS()
	if _, err := identity.Init(kr, "", nil); err != nil {
		t.Fatal(err)
	}
	enrollTestAccount(t, kr)
}

func TestLoginBootstrapsIdentityOnlyForNewAccount(t *testing.T) {
	t.Setenv("ESEC_VAULT_HOME", t.TempDir())
	t.Setenv("ESEC_KEYRING_DIR", "")
	kr := keyring.NewMemory()
	h := servertest.Start(t, 53101343)
	h.GitHub.AddUser(53101343, "mscno")
	calls := 0
	opts := account.LoginOptions{Server: h.URL, Name: "first", Poll: time.Millisecond, BootstrapToken: servertest.BootstrapToken, CreateIdentity: func() error {
		calls++
		_, err := identity.Init(kr, "", nil)
		return err
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := account.Login(ctx, kr, enrollmentUI{t, h}, opts); err != nil {
		t.Fatal(err)
	}
	if err := account.RequireLogin(kr); err != nil {
		t.Fatal(err)
	}
	if _, err := account.Login(ctx, kr, enrollmentUI{t, h}, opts); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("identity creation called %d times", calls)
	}
}

func (r *guardRig) initIdentity() {
	r.t.Helper()
	r.t.Setenv("ESEC_VAULT_HOME", r.home)
	r.t.Setenv("ESEC_KEYRING_DIR", "")
	r.t.Setenv("ESEC_SECRET_STORE", "file")
	if _, err := identity.Init(keyring.NewOS(), "", nil); err != nil {
		r.t.Fatal(err)
	}
}
