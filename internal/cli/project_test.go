package cli

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mscno/esec-vault/internal/identity"
	"github.com/mscno/esec-vault/internal/keyring"

	"github.com/mscno/esec"
	"github.com/mscno/esec-vault/internal/keystore"
	"github.com/mscno/esec/pkg/projectfile"
)

func initTestRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if _, err := runGit(dir, "init"); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestProjectInitReportsDirectoryAndSource(t *testing.T) {
	t.Setenv("ESEC_VAULT_HOME", t.TempDir())
	t.Setenv("ESEC_KEYRING_DIR", "")
	for _, source := range []string{"--project flag", "project ID argument", "Git origin"} {
		t.Run(source, func(t *testing.T) {
			t.Setenv("ESEC_VAULT_HOME", t.TempDir())
			repo := initTestRepo(t)
			c := ProjectInitCmd{Dir: filepath.Join(repo, "app"), Env: []string{"dev"}, Format: "env", Template: true}
			switch source {
			case "--project flag":
				c.Project = "org/flag"
			case "project ID argument":
				c.ID = "org/argument"
			case "Git origin":
				if _, err := runGit(repo, "remote", "add", "origin", "git@github.com:org/origin.git"); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Mkdir(c.Dir, 0750); err != nil {
				t.Fatal(err)
			}
			output, err := os.CreateTemp(t.TempDir(), "stderr")
			if err != nil {
				t.Fatal(err)
			}
			defer output.Close()
			stderr := os.Stderr
			os.Stderr = output
			defer func() { os.Stderr = stderr }()
			if err := c.Run(testCtx(t)); err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(output.Name())
			if err != nil {
				t.Fatal(err)
			}
			project, err := projectfile.ReadProjectFile(c.Dir)
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{project, c.Dir, source} {
				if !strings.Contains(string(data), want) {
					t.Fatalf("initialization output omits %q: %s", want, data)
				}
			}
		})
	}
}

func TestProjectInitMissingOriginReportsError(t *testing.T) {
	t.Setenv("ESEC_VAULT_HOME", t.TempDir())
	t.Setenv("ESEC_KEYRING_DIR", "")
	bin := buildCLI(t)
	for _, empty := range []bool{false, true} {
		repo := initTestRepo(t)
		if empty {
			if _, err := runGit(repo, "config", "remote.origin.url", ""); err != nil {
				t.Fatal(err)
			}
		}
		output, code := run(t, bin, "project", "init", "--dir", repo)
		if code == 0 || !strings.Contains(output, "Git origin") || !strings.Contains(output, "--project org/repo") {
			t.Fatalf("missing origin must produce an actionable error: exit=%d output=%q", code, output)
		}
		if _, err := projectfile.ReadProjectFile(repo); err == nil {
			t.Fatal("failed initialization created a project marker")
		}
	}
}

func TestEnvShowKeyRequiresConfirmation(t *testing.T) {
	t.Setenv("ESEC_VAULT_HOME", t.TempDir())
	t.Setenv("ESEC_KEYRING_DIR", "")
	repo := t.TempDir()
	if err := projectfile.WriteProjectFile(repo, "org/app"); err != nil {
		t.Fatal(err)
	}
	subdir := filepath.Join(repo, "src")
	if err := os.Mkdir(subdir, 0750); err != nil {
		t.Fatal(err)
	}
	_, priv, err := esec.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if err := keystore.New().Write("org/app", map[string]string{environmentKey("api.prod"): priv, environmentKey("invalid"): "bad-key"}, false); err != nil {
		t.Fatal(err)
	}
	bin := buildCLI(t)
	for _, tc := range []struct {
		name, input string
		env         string
		args        []string
		success     bool
		prompt      bool
	}{
		{name: "confirmed", input: "y\n", success: true, prompt: true},
		{name: "declined", input: "n\n", prompt: true},
		{name: "default", input: "\n", prompt: true},
		{name: "EOF", prompt: true},
		{name: "quiet still prompts", args: []string{"--quiet"}, prompt: true},
		{name: "explicit project", input: "y\n", args: []string{"--project", "org/app"}, success: true, prompt: true},
		{name: "missing project", input: "y\n", args: []string{"--project", "org/missing"}},
		{name: "missing environment", env: "staging", input: "y\n"},
		{name: "invalid environment name", env: "../dev", input: "y\n"},
		{name: "invalid stored key", env: "invalid", input: "y\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := tc.env
			if env == "" {
				env = "api.prod"
			}
			cmd := exec.Command(bin, append([]string{"env", "show-key", env}, tc.args...)...)
			cmd.Dir = subdir
			cmd.Stdin = strings.NewReader(tc.input)
			var stdout, stderr bytes.Buffer
			cmd.Stdout, cmd.Stderr = &stdout, &stderr
			err := cmd.Run()
			if (err == nil) != tc.success {
				t.Fatalf("success=%v, error=%v stderr=%q", tc.success, err, stderr.String())
			}
			want := ""
			if tc.success {
				want = priv + "\n"
			}
			if stdout.String() != want {
				t.Fatal("stdout must contain only the confirmed key, or be empty on cancellation")
			}
			if strings.Contains(stderr.String(), priv) {
				t.Fatal("private key leaked to stderr")
			}
			if tc.prompt && (!strings.Contains(stderr.String(), "[y/N]") || !strings.Contains(stderr.String(), "org/app") || !strings.Contains(stderr.String(), "api.prod")) {
				t.Fatalf("confirmation must identify project and environment: %q", stderr.String())
			}
		})
	}
}

// testCtx is a command context with an identity in a memory keyring, so
// commands can seal keys. It makes the identity in the current
// ESEC_VAULT_HOME, which must have none yet.
func testCtx(t *testing.T) *cliCtx {
	t.Helper()
	kr := keyring.NewMemory()
	if _, err := identity.Init(kr, "", nil); err != nil {
		t.Fatal(err)
	}
	return &cliCtx{Keyring: kr}
}
