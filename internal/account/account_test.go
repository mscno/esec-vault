package account_test

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mscno/esec/pkg/secretstore"

	"github.com/mscno/esec-vault/internal/account"
	"github.com/mscno/esec-vault/internal/chain"
	"github.com/mscno/esec-vault/internal/identity"
	"github.com/mscno/esec-vault/internal/keyring"
	"github.com/mscno/esec-vault/internal/keystore"
	"github.com/mscno/esec-vault/internal/servertest"
	"github.com/mscno/esec-vault/internal/vaultfile"
	"github.com/mscno/esec-vault/internal/wire"
)

// testUI records output and confirms device codes in the fake browser.
type testUI struct {
	t      *testing.T
	h      *servertest.Harness
	mu     sync.Mutex
	out    strings.Builder
	answer bool
}

var codeRe = regexp.MustCompile(`enter ([0-9A-Z]{4}-[0-9A-Z]{4})`)

func (u *testUI) Printf(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	u.mu.Lock()
	u.out.WriteString(msg)
	u.mu.Unlock()
	if m := codeRe.FindStringSubmatch(msg); m != nil {
		go func() {
			if err := u.h.Browser("mscno").Confirm(m[1], true); err != nil {
				u.t.Error(err)
			}
		}()
	}
}
func (u *testUI) Confirm(string) bool           { return u.answer }
func (u *testUI) Secret(string) (string, error) { return "", errors.New("no secrets in tests") }

func setup(t *testing.T) (*servertest.Harness, *account.Account) {
	t.Helper()
	h := servertest.Start(t, 53101343)
	h.GitHub.AddUser(53101343, "mscno")
	home := t.TempDir()
	t.Setenv("ESEC_VAULT_HOME", home)
	t.Setenv("ESEC_KEYRING_DIR", "")
	t.Setenv(secretstore.EnvBackend, secretstore.BackendFile)
	kr := keyring.NewOS()
	if _, err := identity.Init(kr, "", nil); err != nil {
		t.Fatal(err)
	}
	if err := keystore.New().Write("acme/store", map[string]string{"ESEC_PRIVATE_KEY_DEV": strings.Repeat("ab", 32)}, false); err != nil {
		t.Fatal(err)
	}
	ui := &testUI{t: t, h: h}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	a, err := account.Login(ctx, kr, ui, account.LoginOptions{Server: h.URL, Name: "laptop", Poll: 50 * time.Millisecond})
	if err != nil {
		t.Fatalf("login: %v\n%s", err, ui.out.String())
	}
	if !strings.Contains(ui.out.String(), "Created the vault account") {
		t.Fatalf("login output:\n%s", ui.out.String())
	}
	return h, a
}

func exec(t *testing.T, h *servertest.Harness, q string, args ...any) {
	t.Helper()
	if _, err := h.DB.SQL().Exec(q, args...); err != nil {
		t.Fatal(err)
	}
}

func TestSyncRejectsVaultRollback(t *testing.T) {
	h, a := setup(t)
	ctx := context.Background()
	if err := keystore.New().Write("acme/api", map[string]string{"ESEC_PRIVATE_KEY_PROD": strings.Repeat("cd", 32)}, false); err != nil {
		t.Fatal(err)
	}
	res, err := a.Sync(ctx, account.SyncOptions{})
	if err != nil || !res.Pushed || res.Generation != 2 {
		t.Fatalf("push: %+v %v", res, err)
	}
	// The server "loses" the newest version and serves generation 1 again.
	exec(t, h, `DELETE FROM vault_versions WHERE version = 2`)
	if _, err := a.Sync(ctx, account.SyncOptions{}); err == nil || !strings.Contains(err.Error(), "rollback") {
		t.Fatalf("vault rollback not detected: %v", err)
	}
}

func TestSyncRejectsChainRollbackAndFork(t *testing.T) {
	h, a := setup(t)
	ctx := context.Background()
	if _, err := a.Sync(ctx, account.SyncOptions{}); err != nil {
		t.Fatal(err)
	}
	exec(t, h, `DELETE FROM chain_links WHERE seq = 2`)
	if _, err := a.Sync(ctx, account.SyncOptions{}); !errors.Is(err, chain.ErrRollback) {
		t.Fatalf("chain rollback not detected: %v", err)
	}
	// A server that swaps in a whole new account (fork from link 1).
	exec(t, h, `DELETE FROM chain_links`)
	fake, _ := identity.NewRandom()
	st := chain.New(a.State.User)
	e, err := st.NewLink(chain.TypeInit, chain.InitBody{EncPub: strings.Repeat("11", 32), SignPub: fmt.Sprintf("%x", fake.SignPublic()), MasterPub: strings.Repeat("22", 32)}, time.Now(), fake.Sign)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	exec(t, h, `INSERT INTO chain_links (user_id, seq, hash, envelope, created_at) VALUES (?, 1, ?, ?, 0)`, a.State.User, e.Hash(), raw)
	if _, err := a.Sync(ctx, account.SyncOptions{}); !errors.Is(err, chain.ErrRollback) {
		t.Fatalf("forked chain not detected: %v", err)
	}
}

func TestSyncRejectsForgedVault(t *testing.T) {
	h, a := setup(t)
	ctx := context.Background()
	id, err := identity.Load(a.KR)
	if err != nil {
		t.Fatal(err)
	}
	// Anyone can seal a blob to the public user key; the server tries to
	// plant its own environment key that way.
	wrapped, _ := identity.WrappedFile()
	hdr, _ := identity.ReadHeader(wrapped)
	master := hdr.MasterPublic
	blob, err := vaultfile.Seal(&vaultfile.Vault{Projects: map[string]map[string]string{"acme/evil": {"ESEC_PRIVATE_KEY_DEV": strings.Repeat("ee", 32)}}, Generation: 99}, &id.Public, &master)
	if err != nil {
		t.Fatal(err)
	}
	_, attacker, _ := ed25519.GenerateKey(nil)
	exec(t, h, `INSERT INTO vault_versions (user_id, version, blob, sig, sha256, pushed_by, created_at) VALUES (?, 99, ?, ?, 'x', 'd_x', 0)`, a.State.User, blob, ed25519.Sign(attacker, wire.VaultMessage(a.State.User, blob)))
	if _, err := a.Sync(ctx, account.SyncOptions{}); err == nil || !strings.Contains(err.Error(), "not signed by the current user key") {
		t.Fatalf("forged vault accepted: %v", err)
	}
	if _, err := keystore.New().Read("acme/evil"); err == nil {
		t.Fatal("forged vault wrote a keyring")
	}
}

func TestThreeWayMerge(t *testing.T) {
	h, a := setup(t)
	ctx := context.Background()
	if _, err := a.Sync(ctx, account.SyncOptions{}); err != nil {
		t.Fatal(err)
	}
	id, _ := identity.Load(a.KR)
	wrapped, _ := identity.WrappedFile()
	hdr, _ := identity.ReadHeader(wrapped)
	master := hdr.MasterPublic
	push := func(version uint64, gen uint64, projects map[string]map[string]string) {
		t.Helper()
		blob, err := vaultfile.Seal(&vaultfile.Vault{Projects: projects, Identity: wrapped, Generation: gen}, &id.Public, &master)
		if err != nil {
			t.Fatal(err)
		}
		exec(t, h, `INSERT INTO vault_versions (user_id, version, blob, sig, sha256, pushed_by, created_at) VALUES (?, ?, ?, ?, 'x', 'd_other', 0)`, a.State.User, version, blob, ed25519.Sign(id.Sign, wire.VaultMessage(a.State.User, blob)))
	}
	ks := keystore.New()
	// Another device rotated DEV: taken automatically, no conflict.
	push(2, 2, map[string]map[string]string{"acme/store": {"ESEC_PRIVATE_KEY_DEV": strings.Repeat("ac", 32)}})
	if _, err := a.Sync(ctx, account.SyncOptions{}); err != nil {
		t.Fatal(err)
	}
	if e, _ := ks.Read("acme/store"); e["ESEC_PRIVATE_KEY_DEV"] != strings.Repeat("ac", 32) {
		t.Fatal("a change made only on the server was not applied")
	}
	// Both sides change DEV: a non-interactive sync reports a conflict and
	// pushes nothing.
	if err := ks.Write("acme/store", map[string]string{"ESEC_PRIVATE_KEY_DEV": strings.Repeat("aa", 32)}, true); err != nil {
		t.Fatal(err)
	}
	push(3, 3, map[string]map[string]string{"acme/store": {"ESEC_PRIVATE_KEY_DEV": strings.Repeat("bb", 32)}})
	_, err := a.Sync(ctx, account.SyncOptions{})
	if !errors.Is(err, account.ErrConflicts) {
		t.Fatalf("conflict not reported: %v", err)
	}
	var n int
	_ = h.DB.SQL().QueryRow(`SELECT COUNT(*) FROM vault_versions WHERE user_id = ?`, a.State.User).Scan(&n)
	if n != 3 {
		t.Fatalf("a conflicting sync pushed a version (%d versions)", n)
	}
}
