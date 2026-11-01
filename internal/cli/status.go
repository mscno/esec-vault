package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/mscno/esec-vault/internal/account"
	"github.com/mscno/esec-vault/internal/daemon"
	"github.com/mscno/esec-vault/internal/identity"
	"github.com/mscno/esec-vault/internal/keystore"
	"github.com/mscno/esec-vault/internal/paths"
	"github.com/mscno/esec-vault/internal/service"
	"github.com/mscno/esec-vault/internal/verify"
	"github.com/mscno/esec/pkg/projectfile"
)

// InitCmd is the legacy alias for signing in to a vault server.
type InitCmd struct {
	Server string `arg:"" optional:"" help:"Vault server (or ESEC_VAULT_SERVER)"`
}

// Run starts server enrollment rather than creating a standalone vault.
func (c *InitCmd) Run(ctx *cliCtx) error { return (&LoginCmd{Server: c.Server}).Run(ctx) }

// StatusCmd reports pending changes and vault-server health without exposing secrets.
type StatusCmd struct {
	JSON bool `help:"Machine-readable output"`
}
type status struct {
	Daemon      *daemon.Response `json:"daemon,omitempty"`
	Identity    string           `json:"identity,omitempty"`
	Passphrase  bool             `json:"passphrase_protected"`
	Generation  uint64           `json:"generation"`
	CreatedAt   time.Time        `json:"created_at"`
	Projects    int              `json:"projects"`
	Recoverable bool             `json:"recoverable"`
	Stale       bool             `json:"stale"`
	VaultServer *serverStatus    `json:"vault_server,omitempty"`
	SecretStore *storeStatus     `json:"secret_store,omitempty"`
	Problems    []string         `json:"problems,omitempty"`
}

// Run displays last verified upload and current pending state.
func (c *StatusCmd) Run(ctx *cliCtx) error {
	s := inspect(ctx)
	s.SecretStore = inspectStore(ctx, &s.Problems)
	s.VaultServer = inspectServer(ctx, &s.Problems)
	cctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if resp, err := daemon.Call(cctx, daemon.Request{Op: "status"}); err == nil {
		s.Daemon = resp
		resp.CLI = ctx.Version
		resp.UpToDate = resp.Version != "" && resp.Version == ctx.Version
		if resp.Version != "" && !resp.UpToDate {
			s.Problems = append(s.Problems, fmt.Sprintf("daemon runs %s but this CLI is %s; run: esec vault daemon upgrade", resp.Version, ctx.Version))
		}
	}
	if c.JSON {
		return printJSON(s)
	}
	fmt.Printf("Identity: %s\nServer vault: generation %d, %d local projects, recovery uploaded: %t\nUpload pending: %t\n", s.Identity, s.Generation, s.Projects, s.Recoverable, s.Stale)
	printServerStatus(s.VaultServer, s.SecretStore)
	if s.Daemon != nil {
		fmt.Printf("Daemon: running (pid %d), broker unlocked: %t\n", s.Daemon.PID, s.Daemon.Unlocked)
	}
	for _, p := range s.Problems {
		fmt.Println("!", p)
	}
	return nil
}

func inspect(ctx *cliCtx) status {
	s := status{}
	id, err := identity.Load(ctx.Keyring)
	if err != nil {
		s.Problems = append(s.Problems, err.Error())
		return s
	}
	s.Identity = id.Fingerprint()
	s.Passphrase = id.PassphraseProtected
	st, err := account.LoadState()
	if err != nil {
		s.Problems = append(s.Problems, err.Error())
		return s
	}
	s.Generation = st.Vault.Generation
	s.CreatedAt = st.Vault.SyncedAt
	s.Recoverable = st.Vault.Version > 0
	if projects, err := keystore.New().List(); err == nil {
		s.Projects = len(projects)
	} else {
		s.Problems = append(s.Problems, err.Error())
	}
	_, err = os.Stat(account.PendingPath())
	s.Stale = err == nil
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		s.Problems = append(s.Problems, err.Error())
	}
	if s.Stale {
		s.Problems = append(s.Problems, "saved locally; server upload pending")
	}
	if account.StagingIssue() {
		s.Stale = true
		s.Problems = append(s.Problems, "local backup preparation failed; run sync --server to inspect the error")
	}
	if !s.Recoverable {
		s.Problems = append(s.Problems, "no acknowledged server recovery revision yet")
	}
	return s
}

// DoctorCmd checks identity, coverage, paths and backup permissions.
type DoctorCmd struct {
	Dirs []string `name:"dir" type:"path" help:"Repository roots to scan"`
}

// Run reports actionable problems and fails when protection is incomplete.
func (c *DoctorCmd) Run(ctx *cliCtx) error {
	s := inspect(ctx)
	inspectStore(ctx, &s.Problems)
	inspectServer(ctx, &s.Problems)
	issues := s.Problems
	issues = append(issues, permissionIssues()...)
	issues = append(issues, daemonVersionIssues(ctx)...)
	safety, advice := keySafetyIssues()
	issues = append(issues, safety...)
	dirs := c.Dirs
	if len(dirs) == 0 {
		dirs = []string{"."}
	}
	for _, dir := range dirs {
		issues = append(issues, scanRepos(dir)...)
	}
	for _, a := range advice {
		fmt.Println("-", a)
	}
	if len(issues) == 0 {
		fmt.Println("No problems found")
		return nil
	}
	for _, issue := range issues {
		fmt.Println("!", issue)
	}
	// The findings above are the report; the message only prevents a silent
	// exit for anyone invoking this programmatically.
	return &exitCodeError{code: 1, msg: fmt.Sprintf("%d problem(s) found", len(issues))}
}

// keySafetyIssues reports what verify and the guard last found: keys lost,
// in one place or shared between projects, and guarded keys still in the
// clear on this device. advice is what is worth doing but not a fault: a
// check or a drill long ago, a guard with one security key.
func keySafetyIssues() (issues, advice []string) {
	last, err := verify.LoadLast()
	switch {
	case err != nil:
		issues = append(issues, "last key check unreadable: "+err.Error())
	case last.At.IsZero():
		advice = append(advice, "keys never checked: esec vault verify --root ~/src")
	case last.Report != nil && !last.Report.OK():
		issues = append(issues, fmt.Sprintf("%d key(s) need attention (%d current keys not found, %d historical keys not found): esec vault verify", last.Report.Problems, last.Report.Lost, last.Report.HistoryMissing))
	case time.Since(last.At) > 7*24*time.Hour:
		advice = append(advice, fmt.Sprintf("keys last checked %s ago: esec vault verify", time.Since(last.At).Round(time.Hour)))
	}
	if last != nil && !last.At.IsZero() && (last.Drill.IsZero() || time.Since(last.Drill) > 180*24*time.Hour) {
		advice = append(advice, "no recovery drill in six months: esec vault drill")
	}
	if st, err := readGuardStatus(); err == nil {
		for _, p := range st.Projects {
			if len(p.Clear) > 0 {
				issues = append(issues, fmt.Sprintf("%s: %d guarded key(s) still in the clear here: esec vault guard enable --project %s", p.Project, len(p.Clear), p.Project))
			}
		}
		if st.SetUp && len(st.Holders) < 2 {
			advice = append(advice, "one security key: add a spare YubiKey (esec vault security-keys add), or losing it means recovering with the phrase")
		}
	}
	return issues, advice
}

// daemonVersionIssues reports a managed daemon that is not running this build.
// Upgrading the CLI replaces only the binary on PATH, so the daemon keeps
// executing its own copy until daemon upgrade is run.
func daemonVersionIssues(ctx *cliCtx) []string {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		return nil
	}
	m, err := service.New()
	if err != nil {
		return []string{"could not inspect the managed daemon: " + err.Error()}
	}
	if !m.Installed() {
		return nil
	}
	exe, err := os.Executable()
	if err != nil {
		return []string{"could not locate this executable to compare builds: " + err.Error()}
	}
	same, err := m.BinaryCurrent(exe)
	if err != nil {
		return []string{"could not compare the managed daemon build: " + err.Error()}
	}
	if same {
		return nil
	}
	issue := "managed daemon runs an older copy of esec-vault; run: esec-vault daemon upgrade"
	cctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if resp, err := daemon.Call(cctx, daemon.Request{Op: "status"}); err == nil && resp.Version != "" && resp.Version != ctx.Version {
		issue += fmt.Sprintf(" (daemon %s, cli %s)", resp.Version, ctx.Version)
	}
	return []string{issue}
}

func permissionIssues() []string {
	if runtime.GOOS == "windows" {
		return nil
	}
	var issues []string
	for _, dir := range []string{paths.Home(), paths.KeyringDir()} {
		err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			info, err := d.Info()
			if err != nil {
				return err
			}
			if info.Mode().Perm()&0077 != 0 {
				issues = append(issues, "permissions too broad: "+p)
			}
			return nil
		})
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			issues = append(issues, err.Error())
		}
	}
	return issues
}

func scanRepos(root string) []string {
	var issues []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == ".git" || d.Name() == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Name() != ".esec-keyring" {
			return nil
		}
		project, _, err := projectfile.FindProjectFile(filepath.Dir(p))
		if err != nil {
			issues = append(issues, "keyring needs project marker: "+p)
			return nil //nolint:nilerr // accumulate diagnostic and continue scan
		}
		issues = append(issues, "repo-local keyring found; verify/import coverage for "+project+": "+p)
		return nil
	})
	if err != nil {
		issues = append(issues, err.Error())
	}
	return issues
}

func printJSON(v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(data))
	return nil
}
