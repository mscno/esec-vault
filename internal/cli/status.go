package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"time"

	"github.com/mscno/esec-vault/internal/daemon"
	"github.com/mscno/esec-vault/internal/identity"
	"github.com/mscno/esec-vault/internal/keystore"
	"github.com/mscno/esec-vault/internal/paths"
	"github.com/mscno/esec-vault/internal/remote"
	"github.com/mscno/esec-vault/internal/service"
	"github.com/mscno/esec-vault/internal/vaultfile"
	"github.com/mscno/esec/pkg/projectfile"
)

// InitCmd performs first-time identity setup and a verified local backup.
type InitCmd struct {
	Passphrase   bool `help:"Prompt for optional recovery passphrase"`
	NoPassphrase bool `help:"Use only the generated recovery phrase"`
	SkipBackup   bool `help:"Skip first snapshot"`
}

// Run initializes an identity and verifies its first snapshot.
func (c *InitCmd) Run(ctx *cliCtx) error {
	if err := (&IdentityInitCmd{Passphrase: c.Passphrase, NoPassphrase: c.NoPassphrase}).Run(ctx); err != nil {
		return err
	}
	if c.SkipBackup {
		return nil
	}
	return (&BackupCmd{Verify: true}).Run(ctx)
}

// StatusCmd reports local and remote backup health without exposing secrets.
type StatusCmd struct {
	JSON bool `help:"Machine-readable output"`
}
type status struct {
	Daemon       *daemon.Response `json:"daemon,omitempty"`
	Identity     string           `json:"identity,omitempty"`
	Passphrase   bool             `json:"passphrase_protected"`
	Generation   uint64           `json:"generation"`
	CreatedAt    time.Time        `json:"created_at"`
	Projects     int              `json:"projects"`
	Recoverable  bool             `json:"recoverable"`
	Stale        bool             `json:"stale"`
	Pending      bool             `json:"push_pending"`
	Destinations *remote.State    `json:"destinations,omitempty"`
	Problems     []string         `json:"problems,omitempty"`
}

// Run displays last verified upload and current snapshot state.
func (c *StatusCmd) Run(ctx *cliCtx) error {
	s := inspect(ctx)
	cctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if resp, err := daemon.Call(cctx, daemon.Request{Op: "status"}); err == nil {
		s.Daemon = resp
	}
	if c.JSON {
		return printJSON(s)
	}
	fmt.Printf("Identity: %s\nSnapshot: generation %d, %d projects, recovery material: %t\nStale: %t; upload pending: %t\n", s.Identity, s.Generation, s.Projects, s.Recoverable, s.Stale, s.Pending)
	if s.Daemon != nil {
		fmt.Printf("Daemon: running (pid %d), broker unlocked: %t\n", s.Daemon.PID, s.Daemon.Unlocked)
		if s.Daemon.Version != "" && s.Daemon.Version != ctx.Version {
			s.Problems = append(s.Problems, fmt.Sprintf("daemon runs %s but this CLI is %s; run: esec-vault daemon upgrade", s.Daemon.Version, ctx.Version))
		}
	}
	for _, p := range s.Problems {
		fmt.Println("!", p)
	}
	return (&RemoteListCmd{}).Run(ctx)
}

func inspect(ctx *cliCtx) status {
	s := status{Pending: remote.IsDirty()}
	id, err := identity.Load(ctx.Keyring)
	if err != nil {
		s.Problems = append(s.Problems, err.Error())
		return s
	}
	s.Identity = id.Fingerprint()
	s.Passphrase = id.PassphraseProtected
	raw, err := os.ReadFile(paths.VaultFile())
	if err != nil {
		s.Problems = append(s.Problems, "no readable local snapshot: "+err.Error())
		return s
	}
	v, err := vaultfile.Open(raw, &id.Public, &id.Private)
	if err != nil {
		s.Problems = append(s.Problems, err.Error())
		return s
	}
	s.Generation = v.Generation
	s.CreatedAt = v.CreatedAt
	s.Projects = len(v.Projects)
	s.Recoverable = len(v.Identity) > 0 && vaultfile.HasMasterCopy(raw) && v.IdentityFingerprint == id.Fingerprint()
	if !s.Recoverable {
		s.Problems = append(s.Problems, "snapshot lacks matching recovery material")
	}
	s.Stale, err = stale(v, id)
	if err != nil {
		s.Problems = append(s.Problems, err.Error())
	}
	if s.Stale {
		s.Problems = append(s.Problems, "local snapshot is stale; run backup or remote watch")
	}
	s.Destinations, err = remote.LoadState()
	if err != nil {
		s.Problems = append(s.Problems, err.Error())
	}
	return s
}

func stale(v *vaultfile.Vault, id *identity.Identity) (bool, error) {
	ks := keystore.New()
	projects, err := ks.List()
	if err != nil {
		return true, err
	}
	if len(projects) != len(v.Projects) {
		return true, nil
	}
	for _, p := range projects {
		e, err := ks.Read(p)
		if err != nil {
			return true, err
		}
		if !reflect.DeepEqual(e, v.Projects[p]) {
			return true, nil
		}
	}
	wrapped, _, err := identity.BackupMaterial(id)
	if err != nil {
		return true, err
	}
	return !reflect.DeepEqual(wrapped, v.Identity), nil
}

// DoctorCmd checks identity, coverage, paths and backup permissions.
type DoctorCmd struct {
	Dirs []string `name:"dir" type:"path" help:"Repository roots to scan"`
}

// Run reports actionable problems and fails when protection is incomplete.
func (c *DoctorCmd) Run(ctx *cliCtx) error {
	s := inspect(ctx)
	issues := s.Problems
	if cfg, err := remote.Load(); err != nil {
		issues = append(issues, err.Error())
	} else if cfg.Default == "" {
		issues = append(issues, "no default remote; run remote add or remote set-default")
	}
	issues = append(issues, permissionIssues()...)
	issues = append(issues, daemonVersionIssues(ctx)...)
	dirs := c.Dirs
	if len(dirs) == 0 {
		dirs = []string{"."}
	}
	for _, dir := range dirs {
		issues = append(issues, scanRepos(dir)...)
	}
	if len(issues) == 0 {
		fmt.Println("No problems found")
		return nil
	}
	for _, issue := range issues {
		fmt.Println("!", issue)
	}
	return &exitCodeError{code: 1}
}

// daemonVersionIssues reports a managed daemon that is not running this build.
// Upgrading the CLI replaces only the binary on PATH, so the daemon keeps
// executing its own copy until daemon upgrade is run.
func daemonVersionIssues(ctx *cliCtx) []string {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		return nil
	}
	m, err := service.New()
	if err != nil || !m.Installed() {
		return nil
	}
	exe, err := os.Executable()
	if err != nil {
		return nil
	}
	same, err := m.Current(exe)
	if err != nil || same {
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

func humanAge(d time.Duration) string { return d.Round(time.Second).String() }
func printJSON(v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(data))
	return nil
}
