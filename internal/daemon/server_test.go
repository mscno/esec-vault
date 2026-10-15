package daemon

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mscno/esec/pkg/secretstore"

	"github.com/mscno/esec-vault/internal/account"
	"github.com/mscno/esec-vault/internal/chain"
	"github.com/mscno/esec-vault/internal/client"
	"github.com/mscno/esec-vault/internal/devicekey"
	"github.com/mscno/esec-vault/internal/identity"
	"github.com/mscno/esec-vault/internal/keyring"
	"github.com/mscno/esec-vault/internal/keystore"
	"github.com/mscno/esec-vault/internal/servertest"
	"github.com/mscno/esec-vault/internal/vaultfile"
	"github.com/mscno/esec-vault/internal/wire"
)

type confirmUI struct {
	t *testing.T
	h *servertest.Harness
}

var codeRe = regexp.MustCompile(`enter ([0-9A-Z]{4}-[0-9A-Z]{4})`)

func (u confirmUI) Printf(format string, args ...any) {
	if m := codeRe.FindStringSubmatch(fmt.Sprintf(format, args...)); m != nil {
		go func() {
			if err := u.h.Browser("mscno").Confirm(m[1], true); err != nil {
				u.t.Error(err)
			}
		}()
	}
}
func (confirmUI) Confirm(string) bool           { return false }
func (confirmUI) Secret(string) (string, error) { return "", errors.New("no prompts") }

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// TestServerLoopSyncsAndNotifies runs the daemon's vault-server loop against
// a test server: it must pull a vault change pushed elsewhere and announce a
// device waiting for approval.
func TestServerLoopSyncsAndNotifies(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("daemon platforms only")
	}
	h := servertest.Start(t, 53101343)
	h.GitHub.AddUser(53101343, "mscno")
	dir, err := os.MkdirTemp("", "evs-") //nolint:usetesting // short paths for daemon sockets
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	t.Setenv("ESEC_VAULT_HOME", dir)
	t.Setenv("ESEC_KEYRING_DIR", "")
	t.Setenv(secretstore.EnvBackend, secretstore.BackendFile)
	kr := keyring.NewOS()
	if _, err := identity.Init(kr, "", nil); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a, err := account.Login(ctx, kr, confirmUI{t: t, h: h}, account.LoginOptions{Server: h.URL, Name: "laptop", Poll: 20 * time.Millisecond, BootstrapToken: servertest.BootstrapToken})
	if err != nil {
		t.Fatal(err)
	}

	var mu sync.Mutex
	var notes []string
	Notifier = func(title, body string) {
		mu.Lock()
		notes = append(notes, title+": "+body)
		mu.Unlock()
	}
	t.Cleanup(func() { Notifier = func(string, string) {} })

	s, err := New(kr, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	s.Interval = 50 * time.Millisecond
	done := make(chan struct{})
	go func() { s.serverLoop(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	eventually(t, "first sync", func() bool {
		st, err := account.LoadState()
		return err == nil && st.Events.Last > 0
	})

	// A vault change from another device is pulled into the keyrings.
	id, err := identity.Load(kr)
	if err != nil {
		t.Fatal(err)
	}
	wrapped, _ := identity.WrappedFile()
	hdr, _ := identity.ReadHeader(wrapped)
	master := hdr.MasterPublic
	blob, err := vaultfile.Seal(&vaultfile.Vault{Projects: map[string]map[string]string{"acme/new": {"ESEC_PRIVATE_KEY_DEV": strings.Repeat("ab", 32)}}, Identity: wrapped, Generation: 5}, &id.Public, &master)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.DB.SQL().Exec(`INSERT INTO vault_versions (user_id, version, blob, sig, sha256, pushed_by, created_at) VALUES (?, 2, ?, ?, 'x', 'd_other', 0)`, a.State.User, blob, ed25519.Sign(id.Sign, wire.VaultMessage(a.State.User, blob))); err != nil {
		t.Fatal(err)
	}
	s.wakeServer()
	eventually(t, "pulled project", func() bool {
		_, err := keystore.New().Read("acme/new")
		return err == nil
	})

	// A new device waiting for approval is announced.
	key, _ := devicekey.Generate()
	c, err := client.New(h.URL)
	if err != nil {
		t.Fatal(err)
	}
	reg, err := c.RegisterDevice(ctx, key.Registration("vm-new", "linux/amd64", time.Now()))
	if err != nil {
		t.Fatal(err)
	}
	c.DeviceID, c.Key = reg.DeviceID, key.Sign
	if err := h.Browser("mscno").Confirm(reg.UserCode, true); err != nil {
		t.Fatal(err)
	}
	tok, err := c.PollToken(ctx, reg.DeviceCode)
	if err != nil {
		t.Fatal(err)
	}
	c.DeviceID, c.Token = tok.Device.ID, tok.SessionToken
	d := tok.Device
	proof, err := key.Proof(a.State.User, chainDevice(d, key))
	if err != nil {
		t.Fatal(err)
	}
	if err := c.UploadProof(ctx, proof); err != nil {
		t.Fatal(err)
	}
	eventually(t, "pending device notification", func() bool {
		mu.Lock()
		defer mu.Unlock()
		for _, n := range notes {
			if strings.Contains(n, "vm-new") && strings.Contains(n, key.Words()) {
				return true
			}
		}
		return false
	})
}

func chainDevice(d wire.DeviceInfo, k *devicekey.Key) chain.Device {
	return chain.Device{ID: d.ID, Name: d.Name, Platform: d.Platform, EncPub: k.EncPubHex(), SignPub: k.SignPubHex(), Created: d.Created.UTC()}
}
