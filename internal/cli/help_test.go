package cli

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/alecthomas/kong"
	"github.com/mscno/esec/pkg/projectfile"
)

func parserForTest(t *testing.T) *kong.Kong {
	t.Helper()
	var c cli
	p, err := kong.New(&c, kong.Name("esec-vault"), kong.ExplicitGroups(commandGroups), kong.Vars{"version": "test"})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// Every documented command exists, so a renamed command cannot leave its
// examples behind unseen.
func TestCommandDetailsNameRealCommands(t *testing.T) {
	p := parserForTest(t)
	paths := map[string]bool{}
	var walk func(n *kong.Node)
	walk = func(n *kong.Node) {
		paths[commandPath(n)] = true
		for _, c := range n.Children {
			walk(c)
		}
	}
	walk(p.Model.Node)
	for path, detail := range commandDetails {
		if !paths[path] {
			t.Errorf("commandDetails names %q, which is no command", path)
		}
		if strings.Contains(detail, "esec-vault ") {
			t.Errorf("%q: write commands as 'esec vault ...' like the rest", path)
		}
	}
}

// Every top-level command sits in a titled section of the help.
func TestTopLevelCommandsAreGrouped(t *testing.T) {
	p := parserForTest(t)
	keys := map[string]bool{}
	for _, g := range commandGroups {
		keys[g.Key] = true
	}
	for _, n := range p.Model.Children {
		if n.Hidden {
			continue
		}
		if n.Group == nil || !keys[n.Group.Key] {
			t.Errorf("command %q has no help section", n.Name)
		}
	}
}

func TestHelpArgs(t *testing.T) {
	for _, tc := range []struct{ in, want []string }{
		{nil, []string{"--help"}},
		{[]string{"help"}, []string{"--help"}},
		{[]string{"help", "team", "add"}, []string{"team", "add", "--help"}},
		{[]string{"team", "help"}, []string{"team", "help"}},
		{[]string{"status"}, []string{"status"}},
	} {
		if got := helpArgs(tc.in); !slices.Equal(got, tc.want) {
			t.Errorf("helpArgs(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestHints(t *testing.T) {
	unanswered = false
	got := hints(fmt.Errorf("listing: %w", projectfile.ErrNotFound), nil)
	if len(got) != 1 || !strings.Contains(got[0], "esec vault project init") {
		t.Fatalf("project hint: %q", got)
	}
	if got := hints(errors.New("other"), nil); len(got) != 0 {
		t.Fatalf("unexpected hints: %q", got)
	}
	unanswered = true
	defer func() { unanswered = false }()
	p := parserForTest(t)
	ctx, err := p.Parse([]string{"team", "remove", "alice"})
	if err != nil {
		t.Fatal(err)
	}
	got = hints(errors.New("cancelled"), ctx.Selected())
	if len(got) != 1 || !strings.Contains(got[0], "--yes") {
		t.Fatalf("question hint: %q", got)
	}
}

// The binary: no arguments and "help" show help on stdout and succeed;
// usage errors go to stderr only, with kong's usage exit code.
func TestHelpAndUsageStreams(t *testing.T) {
	bin := buildCLI(t)
	home := t.TempDir()
	runIn := func(dir string, stdin string, args ...string) (stdout, stderr string, code int) {
		t.Helper()
		cmd := exec.Command(bin, args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "ESEC_VAULT_HOME="+home)
		cmd.Stdin = strings.NewReader(stdin)
		var o, e bytes.Buffer
		cmd.Stdout, cmd.Stderr = &o, &e
		err := cmd.Run()
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			code = exit.ExitCode()
		} else if err != nil {
			t.Fatal(err)
		}
		return o.String(), e.String(), code
	}
	dir := t.TempDir()

	out, _, code := runIn(dir, "")
	if code != 0 || !strings.Contains(out, "Get started:") || !strings.Contains(out, "On machines, CI jobs and servers:") {
		t.Fatalf("no-argument help (exit %d):\n%s", code, out)
	}
	if strings.Contains(out, "daemon run") {
		t.Fatal("the service entry point is listed")
	}
	out, _, code = runIn(dir, "", "help", "group", "token")
	if code != 0 || !strings.Contains(out, "Examples:") || !strings.Contains(out, "esec vault group token acme/production") {
		t.Fatalf("help group token (exit %d):\n%s", code, out)
	}
	out, errOut, code := runIn(dir, "", "nosuchcommand")
	if code != 80 || out != "" || !strings.Contains(errOut, "Usage:") {
		t.Fatalf("usage error: exit %d, stdout %q, stderr %q", code, out, errOut)
	}

	_, errOut, code = runIn(dir, "", "env", "list")
	if code != 1 || !strings.Contains(errOut, "hint: no .esec-project") {
		t.Fatalf("env list outside a project: exit %d\n%s", code, errOut)
	}
	if err := os.WriteFile(filepath.Join(dir, ".esec-project"), []byte("ESEC_PROJECT=acme/api\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, _, code = runIn(dir, "", "env", "list", "--json")
	if code != 0 || strings.TrimSpace(out) != "[]" {
		t.Fatalf("env list --json without keys: exit %d, %q", code, out)
	}
	out, _, code = runIn(dir, "", "keyring", "list", "--json")
	if code != 0 || strings.TrimSpace(out) != "[]" {
		t.Fatalf("keyring list --json without keys: exit %d, %q", code, out)
	}
}
