package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"testing"
	"time"

	"github.com/mscno/esec-vault/internal/account"
	"github.com/mscno/esec-vault/internal/broker"
	"github.com/mscno/esec-vault/internal/identity"
	"github.com/mscno/esec-vault/internal/keyring"
	"github.com/mscno/esec-vault/internal/keystore"
	"github.com/mscno/esec-vault/internal/paths"
	"github.com/mscno/esec-vault/internal/servertest"
)

func server(t *testing.T, intervals ...time.Duration) (*Server, context.Context) {
	t.Helper()
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("requires Unix credentials")
	}
	// Keep Unix socket paths within macOS's sockaddr_un length limit.
	dir, err := os.MkdirTemp("", "evd-") //nolint:usetesting // test names make t.TempDir exceed macOS Unix socket path limits
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	t.Setenv("ESEC_VAULT_HOME", dir)
	t.Setenv("ESEC_KEYRING_DIR", "")
	t.Setenv("ESEC_VAULT_SOCK", "")
	kr := keyring.NewMemory()
	if _, err := identity.Init(kr, "", nil); err != nil {
		t.Fatal(err)
	}
	h := servertest.Start(t, 53101343)
	h.GitHub.AddUser(53101343, "mscno")
	enrollCtx, enrollCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer enrollCancel()
	a, err := account.Login(enrollCtx, kr, testLoginUI{t, h}, account.LoginOptions{Server: h.URL, Name: "daemon-test", Poll: time.Millisecond, BootstrapToken: servertest.BootstrapToken})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Sync(enrollCtx, account.SyncOptions{}); err != nil {
		t.Fatal(err)
	}
	// Obsolete external configuration cannot affect daemon startup or uploads.
	if err := os.WriteFile(filepath.Join(dir, "remote.toml"), []byte("invalid legacy config"), 0600); err != nil {
		t.Fatal(err)
	}
	s, err := New(kr, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	s.Interval = 20 * time.Millisecond
	if len(intervals) > 0 {
		s.Interval = intervals[0]
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(10 * time.Second):
			t.Error("daemon did not stop")
		}
	})
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := Call(ctx, Request{Op: "status"}); err == nil {
			return s, ctx
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("daemon did not start")
	return nil, nil
}

func TestFilesystemEditBackedUpWithoutCLINotification(t *testing.T) {
	s, ctx := server(t, time.Hour)
	// Establish a persisted initial generation before the external edit.
	if _, err := Call(ctx, Request{Op: "snapshot"}); err != nil {
		t.Fatal(err)
	}
	if err := keystore.New().Write("org/external", map[string]string{"ESEC_PRIVATE_KEY_DEV": "test-key"}, true); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		a, err := account.Open(s.Keyring, nil)
		if err != nil {
			t.Fatal(err)
		}
		state, err := a.ReadVault(ctx)
		if err == nil && state.Projects["org/external"]["ESEC_PRIVATE_KEY_DEV"] == "test-key" {
			if _, err := os.Stat(paths.VaultFile()); !os.IsNotExist(err) {
				t.Fatal("automatic sync created a legacy local snapshot")
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("external edit was not acknowledged by the server")
}

func TestLockedStartTTLAndBackupJobs(t *testing.T) {
	s, ctx := server(t)
	r, err := Call(ctx, Request{Op: "status"})
	if err != nil {
		t.Fatal(err)
	}
	if r.Unlocked {
		t.Fatal("starts unlocked")
	}
	r, err = Call(ctx, Request{Op: "unlock", TTL: 100 * time.Millisecond})
	if err != nil || !r.Unlocked {
		t.Fatalf("unlock: %+v %v", r, err)
	}
	time.Sleep(150 * time.Millisecond)
	r, err = Call(ctx, Request{Op: "status"})
	if err != nil || r.Unlocked {
		t.Fatal("TTL did not lock broker")
	}
	if unlocked, _ := s.Broker.Session(); unlocked {
		t.Fatal("broker kept session")
	}
	r, err = Call(ctx, Request{Op: "snapshot"})
	if err != nil {
		t.Fatal(err)
	}
	if r.Job == nil || r.Job.State != "complete" || r.Job.Generation == 0 {
		t.Fatalf("false backup success: %+v", r)
	}
	r, err = Call(ctx, Request{Op: "snapshot", Async: true})
	if err != nil {
		t.Fatal(err)
	}
	id := r.Job.ID
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		r, err = Call(ctx, Request{Op: "job", ID: id})
		if err != nil {
			t.Fatal(err)
		}
		if r.Job.State == "complete" {
			return
		}
		if r.Job.State == "failed" {
			t.Fatal(r.Job.Error)
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("job never completed")
}

func TestControlRejectsOtherUIDAndBrokerCannotApprove(t *testing.T) {
	s, ctx := server(t)
	if r := s.dispatch(ctx, s.UID+1, 0, Request{Version: 1, Op: "unlock", TTL: time.Hour}); r.OK {
		t.Fatal("non-owner accepted")
	}
	if r := s.dispatch(ctx, s.UID, 0, Request{Version: 2, Op: "status"}); r.OK {
		t.Fatal("protocol mismatch accepted")
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if err := broker.NewClient(paths.SocketPath()).Ping(); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	r, err := broker.NewClient(paths.SocketPath()).Call(&broker.Request{Op: broker.OpApprove, ID: "x"})
	if err != nil {
		t.Fatal(err)
	}
	if r.OK || r.Error != "approval requires the owner control socket" {
		t.Fatalf("broker exposes control: %+v", r)
	}
}

func TestStatusReportsBuildVersion(t *testing.T) {
	_, ctx := server(t)
	t.Cleanup(func() { BuildVersion = "dev" })
	BuildVersion = "9.9.9-test"
	r, err := Call(ctx, Request{Op: "status"})
	if err != nil {
		t.Fatal(err)
	}
	if r.Version != "9.9.9-test" {
		t.Fatalf("status did not report the running build: %q", r.Version)
	}
	p, err := Call(ctx, Request{Op: "ping"})
	if err != nil {
		t.Fatal(err)
	}
	if p.Version != "9.9.9-test" {
		t.Fatalf("ping did not report the running build: %q", p.Version)
	}
}

func TestStaleNonSocketIsPreserved(t *testing.T) {
	p := filepath.Join(t.TempDir(), "control.sock")
	if err := os.WriteFile(p, []byte("unrelated"), 0600); err != nil {
		t.Fatal(err)
	}
	if ln, err := listen(p); err == nil {
		ln.Close()
		t.Fatal("removed non-socket")
	}
	data, err := os.ReadFile(p) //nolint:gosec // test-owned file
	if err != nil || string(data) != "unrelated" {
		t.Fatal("clobbered file")
	}
}

func TestControlSocketPermissionsAndShutdown(t *testing.T) {
	_, ctx := server(t)
	info, err := os.Stat(paths.ControlSocket())
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatal("socket permissions")
	}
	conn, err := net.Dial("unix", paths.ControlSocket())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := json.NewEncoder(conn).Encode(Request{Version: 1, Op: "shutdown"}); err != nil {
		t.Fatal(err)
	}
	var resp Response
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if !resp.OK {
		t.Fatal(resp.Error)
	}
	select {
	case <-ctx.Done():
	default:
	} // the server cancels its child, not the caller
}

type testLoginUI struct {
	t *testing.T
	h *servertest.Harness
}

func (u testLoginUI) Printf(f string, args ...any) {
	if code := regexp.MustCompile(`enter ([0-9A-Z]{4}-[0-9A-Z]{4})`).FindStringSubmatch(fmt.Sprintf(f, args...)); code != nil {
		if err := u.h.Browser("mscno").Confirm(code[1], true); err != nil {
			u.t.Error(err)
		}
	}
}
func (testLoginUI) Confirm(string) bool           { return true }
func (testLoginUI) Secret(string) (string, error) { return "", fmt.Errorf("unexpected prompt") }
