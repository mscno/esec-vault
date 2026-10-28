package cli

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// HookCmd manages the git pre-commit hook that runs secrets lint.
type HookCmd struct {
	Install   HookInstallCmd   `cmd:"" help:"Refuse commits with a secret in the clear or a file encrypted to another key than esec.toml names."`
	Uninstall HookUninstallCmd `cmd:"" help:"Remove the esec vault pre-commit hook (or its lines from a shared hook)."`
}

// The hook's lines, between markers so they can sit in a hook shared with
// other tools and be found again.
const (
	hookBegin = "# >>> esec vault: secrets lint >>>"
	hookEnd   = "# <<< esec vault: secrets lint <<<"
	hookBody  = hookBegin + `
# Refuses a commit with a secret in the clear, or a secrets file encrypted to
# another key than esec.toml names. Checks what is staged; needs no network.
# Skip once with: git commit --no-verify
if command -v esec-vault >/dev/null 2>&1; then
  esec-vault secrets lint --staged --offline || exit 1
else
  echo "esec vault: esec-vault is not installed; secrets not checked" >&2
fi
` + hookEnd + "\n"
)

// HookInstallCmd installs the hook.
type HookInstallCmd struct {
	Dir    string `default:"." type:"path" help:"A directory in the repository"`
	Append bool   `help:"Add the check to a pre-commit hook another tool installed, instead of refusing"`
	Print  bool   `help:"Only print the lines, for hook managers (lefthook, pre-commit, husky)"`
}

// Run implements hook install.
func (c *HookInstallCmd) Run(_ *cliCtx) error {
	if c.Print {
		fmt.Print(hookBody)
		fmt.Println(`
# lefthook.yml:
#   pre-commit:
#     commands:
#       esec-secrets:
#         run: esec-vault secrets lint --staged --offline
#
# .pre-commit-config.yaml:
#   - repo: local
#     hooks:
#       - id: esec-secrets
#         name: esec vault secrets lint
#         entry: esec-vault secrets lint --staged --offline
#         language: system
#         pass_filenames: false`)
		return nil
	}
	path, err := preCommitPath(c.Dir)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(path) //nolint:gosec // the repository's own hook
	switch {
	case errors.Is(err, fs.ErrNotExist):
		data = []byte("#!/bin/sh\n" + hookBody)
	case err != nil:
		return err
	case strings.Contains(string(data), hookBegin):
		fmt.Printf("The pre-commit hook in %s checks secrets already.\n", tildePath(path))
		return nil
	case !c.Append:
		return fmt.Errorf("%s exists (another tool's hook?): pass --append to add the check to it, or --print for the lines to give a hook manager", tildePath(path))
	default:
		if !strings.HasPrefix(string(data), "#!") {
			return fmt.Errorf("%s is not a shell script: add the check with your hook manager (esec vault hook install --print)", tildePath(path))
		}
		if !strings.HasSuffix(string(data), "\n") {
			data = append(data, '\n')
		}
		data = append(data, "\n"+hookBody...)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	if err := os.WriteFile(path, data, 0o755); err != nil { //nolint:gosec // a hook must be executable
		return err
	}
	if err := os.Chmod(path, 0o755); err != nil { //nolint:gosec // a hook must be executable
		return err
	}
	fmt.Printf("✓ Commits in this repository now run esec vault secrets lint (%s).\n", tildePath(path))
	return nil
}

// HookUninstallCmd removes the hook.
type HookUninstallCmd struct {
	Dir string `default:"." type:"path" help:"A directory in the repository"`
}

// Run implements hook uninstall.
func (c *HookUninstallCmd) Run(_ *cliCtx) error {
	path, err := preCommitPath(c.Dir)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(path) //nolint:gosec // the repository's own hook
	if errors.Is(err, fs.ErrNotExist) {
		return errors.New("no pre-commit hook here")
	}
	if err != nil {
		return err
	}
	text := string(data)
	begin, end := strings.Index(text, hookBegin), strings.Index(text, hookEnd)
	if begin < 0 || end < begin {
		return errors.New("the pre-commit hook does not run esec vault")
	}
	rest := strings.TrimRight(text[:begin], "\n") + "\n" + strings.TrimLeft(text[end+len(hookEnd):], "\n")
	if strings.TrimSpace(rest) == "#!/bin/sh" {
		if err := os.Remove(path); err != nil {
			return err
		}
	} else if err := os.WriteFile(path, []byte(rest), 0o755); err != nil { //nolint:gosec // a hook must be executable
		return err
	}
	fmt.Println("Removed the esec vault check from", tildePath(path))
	return nil
}

// preCommitPath is where git runs the repository's pre-commit hook from,
// honouring core.hooksPath.
func preCommitPath(dir string) (string, error) {
	out, err := gitOutput(dir, "rev-parse", "--path-format=absolute", "--git-path", "hooks/pre-commit")
	if err != nil {
		return "", fmt.Errorf("not in a git repository: %w", err)
	}
	return strings.TrimSpace(out), nil
}
