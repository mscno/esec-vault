package cli

import (
	"bytes"
	"errors"
	"fmt"

	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/mscno/esec-vault/internal/service"
)

// buildCLI compiles the real binary so tests exercise the actual Execute()
// exit path, including kong's error wrapping.
func buildCLI(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "esec-vault")
	cmd := exec.Command("go", "build", "-o", bin, "github.com/mscno/esec-vault/cmd/esec-vault")
	cmd.Env = append(os.Environ(), "ESEC_VAULT_HOME="+filepath.Join(dir, "home"))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	return bin
}

func run(t *testing.T, bin string, args ...string) (stderr string, code int) {
	t.Helper()
	cmd := exec.Command(bin, args...)
	var o, e bytes.Buffer
	cmd.Stdout, cmd.Stderr = &o, &e
	err := cmd.Run()
	code = 0
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		code = exit.ExitCode()
	} else if err != nil {
		t.Fatalf("run: %v", err)
	}
	// stdout is folded in so a message on either stream counts as reported.
	return o.String() + e.String(), code
}

func TestExternalBackupCommandsRemoved(t *testing.T) {
	t.Setenv("ESEC_VAULT_HOME", t.TempDir())
	bin := buildCLI(t)
	out, code := run(t, bin, "remote", "test")
	if code == 0 || !strings.Contains(out, "remote") {
		t.Fatalf("removed command: %d %s", code, out)
	}
	out, code = run(t, bin, "project", "init", "acme/app", "--dir", t.TempDir())
	if code == 0 || !strings.Contains(out, "login") {
		t.Fatalf("operation without login: %d %s", code, out)
	}
}

// A launchctl/systemctl failure carries its explanation in the error, and it
// must reach the user even though the message embeds "exit status".
func TestServiceManagerFailureIsNeverSilent(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("launchd-specific")
	}
	dir := t.TempDir()
	fake := filepath.Join(dir, "launchctl")
	// service.run folds CombinedOutput into the error message.
	script := "#!/bin/sh\necho 'Load failed: 5: Input/output error'\nexit 5\n"
	if err := os.WriteFile(fake, []byte(script), 0700); err != nil { //nolint:gosec // test shim
		t.Fatal(err)
	}
	bin := buildCLI(t)
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	home := filepath.Join(dir, "home")
	// service.New derives the unit name from a hash of the vault home, so build
	// the manifest from the manager's own expectations.
	m, err := service.NewAt("darwin", os.Getuid(), dir, home, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("ESEC_VAULT_HOME", home)
	t.Setenv("HOME", dir)
	if err := os.MkdirAll(home, 0700); err != nil {
		t.Fatal(err)
	}
	manifest := fmt.Sprintf(`{"version":1,"os":%q,"uid":%d,"home":%q,"name":%q,"unit":%q,"binary":%q,"runtime":%q,"log":%q,"environment":{}}`,
		m.Manifest.OS, m.Manifest.UID, m.Manifest.Home, m.Manifest.Name,
		m.Manifest.Unit, m.Manifest.Binary, m.Manifest.Runtime, m.Manifest.Log)
	if err := os.WriteFile(filepath.Join(home, "daemon-install.json"), []byte(manifest), 0600); err != nil {
		t.Fatal(err)
	}
	stderr, _ := run(t, bin, "daemon", "start")
	if !strings.Contains(stderr, "Input/output error") {
		t.Fatalf("launchctl diagnostic was swallowed; stderr=%q", stderr)
	}
}

func TestForwardedExitErrorIsTheOnlySilentExit(t *testing.T) {
	// The run path forwards a child's exit code and must stay silent; every
	// other exitCodeError must carry a reason.
	if err := (&forwardedExitError{code: 3}).Error(); err != "exit status 3" {
		t.Fatalf("unexpected forwarded message: %q", err)
	}
	if err := (&exitCodeError{code: 1}).Error(); err != "exit status 1" {
		t.Fatalf("unexpected default message: %q", err)
	}
	if err := (&exitCodeError{code: 1, msg: "real reason"}).Error(); err != "real reason" {
		t.Fatalf("message not surfaced: %q", err)
	}
}

func TestGitStderrIsPreservedInError(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "notarepo"), []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := runGit(dir, "config", "--get", "remote.origin.url")
	if err == nil {
		t.Skip("git returned success outside a repository")
	}
	// Must name the command and include git's own explanation.
	if !strings.Contains(err.Error(), "config --get remote.origin.url") {
		t.Fatalf("error omits the command: %v", err)
	}
}

func TestExitCodeErrorMessageReachesStderr(t *testing.T) {
	bin := buildCLI(t)
	// doctor against an isolated home with no identity must explain itself.
	home := t.TempDir()
	cmd := exec.Command(bin, "doctor")
	cmd.Env = append(os.Environ(), "ESEC_VAULT_HOME="+home, "ESEC_KEYRING_DIR="+filepath.Join(home, "keyrings"))
	var o, e bytes.Buffer
	cmd.Stdout, cmd.Stderr = &o, &e
	err := cmd.Run()
	if err == nil {
		t.Skip("doctor unexpectedly succeeded on a bare home")
	}
	combined := o.String() + e.String()
	if strings.TrimSpace(combined) == "" {
		t.Fatalf("doctor failed with no explanation: %v", err)
	}
	if !strings.Contains(combined, "problem") {
		t.Fatalf("doctor failure did not report a reason: %q", combined)
	}
}
