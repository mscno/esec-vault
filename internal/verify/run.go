package verify

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/mscno/esec-vault/internal/account"
	"github.com/mscno/esec-vault/internal/identity"
	"github.com/mscno/esec-vault/internal/keyring"
	"github.com/mscno/esec-vault/internal/keystore"
	"github.com/mscno/esec-vault/internal/paths"
	"github.com/mscno/esec-vault/internal/remote"
	"github.com/mscno/esec-vault/internal/vaultfile"
	"github.com/mscno/esec-vault/internal/workspace"
)

// Source names.
const (
	SourceDevice = "this device"
	SourceServer = "vault server"
	SourceBackup = "backup"
)

// Options say what Run checks.
type Options struct {
	// Roots are scanned for checkouts, which are then remembered.
	Roots   []string
	History bool
	// Server and Backup check the vault server's copy and the newest
	// backup; each needs network.
	Server, Backup bool
	Keyring        keyring.Keyring
	// OpenAccount opens the signed-in account; nil skips the server.
	OpenAccount func() (*account.Account, error)
}

// Run checks every checkout this machine knows (and Roots) against this
// device, the vault server and the newest backup.
func Run(ctx context.Context, opts Options) (*Report, error) {
	reg, err := workspace.Load()
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC().Truncate(time.Second)
	for _, root := range opts.Roots {
		if _, err := reg.Scan(root, 5, now); err != nil {
			return nil, err
		}
	}
	if len(opts.Roots) > 0 {
		if err := reg.Save(); err != nil {
			return nil, err
		}
	}
	var checkouts []string
	for _, c := range reg.Checkouts {
		if workspace.Check(c) == workspace.StatusOK {
			checkouts = append(checkouts, c.Path)
		}
	}
	uses, files, collectErr := Collect(ctx, checkouts, opts.History)
	local, err := LocalProjects(keystore.New())
	if err != nil {
		return nil, err
	}
	sources := []Source{{Name: SourceDevice, Projects: local}}
	if opts.Server {
		sources = append(sources, serverSource(ctx, opts))
	}
	if opts.Backup {
		sources = append(sources, backupSource(ctx, opts))
	}
	rep := Build(uses, sources)
	rep.Checkouts, rep.Files = len(checkouts), files
	return rep, collectErr
}

func serverSource(ctx context.Context, opts Options) Source {
	s := Source{Name: SourceServer}
	if opts.OpenAccount == nil {
		s.Err = errors.New("not checked")
		return s
	}
	a, err := opts.OpenAccount()
	if err != nil {
		s.Err = err
		return s
	}
	cctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	s.Projects, s.Err = a.ServerProjects(cctx)
	return s
}

func backupSource(ctx context.Context, opts Options) Source {
	s := Source{Name: SourceBackup}
	cfg, err := remote.Load()
	if err != nil {
		s.Err = err
		return s
	}
	if cfg.Default == "" {
		s.Err = errors.New("no backup destination (esec vault remote add)")
		return s
	}
	id, err := identity.Load(opts.Keyring)
	if err != nil {
		s.Err = err
		return s
	}
	cctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	_, blob, err := remote.Latest(cctx, cfg, "")
	if err != nil {
		s.Err = err
		return s
	}
	v, err := vaultfile.Open(blob, &id.Public, &id.Private)
	if err != nil {
		s.Err = err
		return s
	}
	s.Name = SourceBackup + " (" + cfg.Default + ")"
	s.Projects = v.Projects
	return s
}

// Saved is the last check, kept for status, the daemon and the Mac app.
type Saved struct {
	At     time.Time `json:"at"`
	Report *Report   `json:"report,omitempty"`
	Error  string    `json:"error,omitempty"`
	// Drill is when the recovery phrase last opened the newest backup.
	Drill time.Time `json:"drill,omitzero"`
}

// LastFile is where the last check is kept.
func LastFile() string { return filepath.Join(paths.Home(), "verify.json") }

// LoadLast reads the last check; a missing file is a zero Saved.
func LoadLast() (*Saved, error) {
	data, err := os.ReadFile(LastFile())
	if errors.Is(err, os.ErrNotExist) {
		return &Saved{}, nil
	}
	if err != nil {
		return nil, err
	}
	var s Saved
	return &s, json.Unmarshal(data, &s)
}

// SaveLast records a check, keeping the last drill.
func SaveLast(rep *Report, runErr error, at time.Time) error {
	prev, _ := LoadLast()
	s := Saved{At: at, Report: rep}
	if prev != nil {
		s.Drill = prev.Drill
	}
	if runErr != nil {
		s.Error = runErr.Error()
	}
	return save(&s)
}

// SaveDrill records a passed drill.
func SaveDrill(at time.Time) error {
	s, err := LoadLast()
	if err != nil {
		s = &Saved{}
	}
	s.Drill = at
	return save(s)
}

func save(s *Saved) error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := LastFile() + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, LastFile())
}
