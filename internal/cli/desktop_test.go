package cli

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/mscno/esec-vault/internal/daemon"
	"github.com/mscno/esec-vault/internal/keyring"
	"github.com/mscno/esec-vault/internal/paths"
)

func TestAppOwnedHelperProcess(t *testing.T) { //nolint:gocyclo // integration assertions follow one real process lifecycle
	if os.Getenv("ESEC_TEST_APP_HELPER") == "1" {
		app := &cliCtx{Keyring: keyring.NewMemory(), Logger: slog.New(slog.DiscardHandler)}
		if err := (&DaemonRunCmd{AppOwned: true}).Run(app); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	if runtime.GOOS != "darwin" {
		t.Skip("Mac app lifecycle")
	}
	// Short path for macOS Unix sockets; no real credentials or service unit.
	dir, err := os.MkdirTemp("", "evapp-") //nolint:usetesting // Unix socket path length
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	t.Setenv("ESEC_VAULT_HOME", dir)
	t.Setenv("ESEC_KEYRING_DIR", filepath.Join(dir, "keyrings"))
	t.Setenv("ESEC_VAULT_SOCK", "")
	t.Setenv("ESEC_TEST_APP_HELPER", "1")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	start := func() (*exec.Cmd, io.WriteCloser, *bytes.Buffer) {
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestAppOwnedHelperProcess$") //nolint:gosec // run this test binary, never user input
		out := &bytes.Buffer{}
		cmd.Stdout, cmd.Stderr = out, out
		pipe, err := cmd.StdinPipe()
		if err != nil {
			t.Fatal(err)
		}
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		return cmd, pipe, out
	}
	cmd, parent, output := start()
	defer parent.Close()
	ready, readyCancel := context.WithTimeout(ctx, 5*time.Second)
	defer readyCancel()
	if err := waitDaemon(ready); err != nil {
		t.Fatal(err)
	}
	status, err := daemon.Call(ctx, daemon.Request{Op: "status"})
	if err != nil || status.Owner != "app" || status.Unlocked {
		t.Fatalf("helper did not start locked and app-owned: %v, %v", status, err)
	}
	if err := refuseAppServiceControl(); err == nil {
		t.Fatal("OS service control allowed while app owns helper")
	}
	other, otherParent, otherOutput := start()
	defer otherParent.Close()
	if err := other.Wait(); err == nil || !strings.Contains(otherOutput.String(), "another EsecVault app") {
		t.Fatalf("duplicate helper not refused: %v, %s", err, otherOutput)
	}
	after, err := daemon.Call(ctx, daemon.Request{Op: "status"})
	if err != nil || after.PID != status.PID {
		t.Fatal("duplicate disrupted the first helper")
	}
	if err := parent.Close(); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("parent EOF: %v: %s", err, output)
	}
	if _, err := daemon.Call(ctx, daemon.Request{Op: "status"}); err == nil {
		t.Fatal("orphan helper still serving")
	}
	r := &setupRun{ctx: &cliCtx{Version: "dev"}, c: &SetupCmd{JSON: true}}
	r.daemon()
	if len(r.steps) != 1 || r.steps[0].Command != "open -a EsecVault" {
		t.Fatalf("setup did not respect app ownership: %+v", r.steps)
	}
	if _, err := os.Stat(filepath.Join(paths.Home(), "daemon-install.json")); !os.IsNotExist(err) {
		t.Fatal("setup reinstalled a service")
	}
}
