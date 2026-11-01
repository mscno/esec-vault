package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/joho/godotenv"
	"github.com/mscno/esec-vault/internal/account"
	"github.com/mscno/esec-vault/internal/daemon"
	"github.com/mscno/esec-vault/internal/identity"
	"github.com/mscno/esec-vault/internal/keystore"
	"github.com/mscno/esec-vault/internal/vaultfile"
	"github.com/mscno/esec-vault/internal/workspace"
	"github.com/mscno/esec/pkg/keyringfile"
	"github.com/mscno/esec/pkg/projectfile"
)

// VaultStorageCmd manages server inventory and local caches.
type VaultStorageCmd struct {
	List            VaultStorageListCmd     `cmd:"" default:"withargs" help:"List server-backed projects, file revisions, and device settings (metadata only)."`
	Add             VaultStorageAddCmd      `cmd:"" help:"Import a local keyring, verify server storage, and optionally remove its local copies."`
	Cache           VaultStorageCacheCmd    `cmd:"" help:"Keep a project available offline or remove its managed local keyring copy."`
	Export          VaultStorageExportCmd   `cmd:"" help:"Export independent unguarded keys as an ordinary esec keyring."`
	RestoreProject  VaultRestoreProjectCmd  `cmd:"" help:"Restore encrypted files and seals into a new directory."`
	RestoreSettings VaultRestoreSettingsCmd `cmd:"" help:"Restore a device's broker settings, explicitly mapping its local user."`
	Retire          VaultRetireCmd          `cmd:"" help:"Remove a key's environment aliases but retain its public-key entry for old files."`
	DeleteKey       VaultDeleteKeyCmd       `cmd:"" help:"Record a permanent key deletion so old devices cannot upload it again."`
}

// VaultStorageListCmd lists recovery metadata without secret values.
type VaultStorageListCmd struct {
	File string `type:"existingfile" help:"Inspect an explicit recovery export offline after identity recovery"`
	JSON bool   `help:"Print metadata as JSON"`
}
type storageProject struct {
	Project   string            `json:"project"`
	Keys      int               `json:"keys"`
	Cache     string            `json:"cache"`
	Revisions int               `json:"revisions"`
	Checkouts []string          `json:"checkouts"`
	Cached    bool              `json:"cached"`
	History   []storageRevision `json:"history"`
}
type storageRevision struct {
	ID       string    `json:"id"`
	Checkout string    `json:"checkout"`
	Label    string    `json:"label"`
	At       time.Time `json:"at"`
	Sequence uint64    `json:"sequence"`
	Files    int       `json:"files"`
}
type storageProfile struct {
	ID    string   `json:"id"`
	Name  string   `json:"name"`
	Files []string `json:"files"`
}
type storageView struct {
	Projects      []storageProject `json:"projects"`
	Profiles      []storageProfile `json:"profiles"`
	Pending       bool             `json:"pending"`
	Generation    uint64           `json:"generation"`
	Offline       bool             `json:"offline"`
	StagingFailed bool             `json:"staging_failed"`
}

// Run executes the storage command.
func (c *VaultStorageListCmd) Run(ctx *cliCtx) error {
	bg, cancel := timeout(30 * time.Second)
	defer cancel()
	v, offline, err := storageInventory(bg, ctx, c.File)
	if err != nil {
		return err
	}
	cache, err := account.LoadCachePolicy()
	if err != nil {
		return err
	}
	out := storageView{Projects: []storageProject{}, Profiles: []storageProfile{}, Generation: v.Generation, Offline: offline, StagingFailed: account.StagingIssue()}
	_, err = os.Stat(account.PendingPath())
	out.Pending = err == nil
	projects := map[string]bool{}
	for p := range v.Projects {
		projects[p] = true
	}
	if v.Catalog != nil {
		for _, r := range v.Catalog.Artifacts {
			projects[r.Project] = true
		}
	}
	for p := range projects {
		row := projectStorageRow(v, cache, p)
		out.Projects = append(out.Projects, row)
	}
	if v.Catalog != nil {
		for id, p := range v.Catalog.Profiles {
			row := storageProfile{ID: id, Name: p.Name, Files: []string{}}
			for f := range p.Settings {
				row.Files = append(row.Files, f)
			}
			sort.Strings(row.Files)
			out.Profiles = append(out.Profiles, row)
		}
	}
	sort.Slice(out.Projects, func(i, j int) bool { return out.Projects[i].Project < out.Projects[j].Project })
	sort.Slice(out.Profiles, func(i, j int) bool { return out.Profiles[i].ID < out.Profiles[j].ID })
	if c.JSON {
		return printJSON(out)
	}
	for _, p := range out.Projects {
		fmt.Printf("%s: %d keys, %d archived revisions, cache %s\n", p.Project, p.Keys, p.Revisions, p.Cache)
	}
	if out.Pending {
		fmt.Println("Saved locally — server upload pending")
	}
	return nil
}

func readStorageExport(ctx *cliCtx, path string) (*vaultfile.Vault, error) {
	id, err := identity.Load(ctx.Keyring)
	if err != nil {
		return nil, err
	}
	return vaultfile.Read(path, &id.Public, &id.Private)
}

func storageInventory(bg context.Context, ctx *cliCtx, file string) (*vaultfile.Vault, bool, error) {
	if file != "" {
		v, err := readStorageExport(ctx, file)
		return v, true, err
	}
	a, err := openAccount(ctx)
	if err != nil {
		return nil, false, err
	}
	v, err := a.ReadVault(bg)
	if err == nil {
		return v, false, nil
	}
	v, err = a.CachedVault()
	return v, true, err
}

// VaultStorageCacheCmd changes project offline availability.
type VaultStorageCacheCmd struct {
	Project string `required:"" help:"Project identifier"`
	Mode    string `required:"" enum:"offline,none" help:"offline retains a local keyring; none removes it after verified sync"`
}

// Run executes the storage command.
func (c *VaultStorageCacheCmd) Run(ctx *cliCtx) error {
	a, err := openAccount(ctx)
	if err != nil {
		return err
	}
	bg, cancel := timeout(2 * time.Minute)
	defer cancel()
	if err := a.CacheProject(bg, c.Project, c.Mode); err != nil {
		return err
	}
	// A broker must drop keys it opened before eviction.
	if c.Mode == "none" {
		if _, err := daemon.Call(bg, daemon.Request{Op: "lock"}); err != nil {
			fmt.Fprintln(os.Stderr, "Local keyring removed; lock any separately running foreground broker too.")
		}
	}
	fmt.Println("Project cache updated; server keys retained.")
	return nil
}

// VaultStorageExportCmd exports standalone unguarded keys.
type VaultStorageExportCmd struct {
	Project string `required:""`
	Out     string `required:"" type:"path" help:"New standalone keyring file (0600)"`
}

// Run executes the storage command.
func (c *VaultStorageExportCmd) Run(ctx *cliCtx) error {
	a, err := openAccount(ctx)
	if err != nil {
		return err
	}
	bg, cancel := timeout(30 * time.Second)
	defer cancel()
	entries, err := a.ExportProject(bg, c.Project)
	if err != nil {
		return err
	}
	text, err := godotenv.Marshal(entries)
	if err != nil {
		return err
	}
	if err := writeNewPrivate(c.Out, []byte(text+"\n")); err != nil {
		return err
	}
	fmt.Println("Independent keyring exported. Guarded keys remain sealed; exported keys are outside broker controls.")
	return nil
}

func writeNewPrivate(path string, b []byte) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600) //nolint:gosec // explicit user destination; exclusive creation never follows an existing final symlink
	if err != nil {
		return err
	}
	_, err = f.Write(b)
	if err == nil {
		err = f.Sync()
	}
	cerr := f.Close()
	if err != nil {
		return err
	}
	return cerr
}

// VaultStorageAddCmd imports and optionally moves a local keyring.
type VaultStorageAddCmd struct {
	Project string `required:""`
	File    string `required:"" type:"existingfile"`
	Move    bool   `help:"Remove the source and managed local keyring only after verified upload"`
}

// Run executes the storage command.
func (c *VaultStorageAddCmd) Run(ctx *cliCtx) error {
	if err := projectfile.ValidateOrgRepo(c.Project); err != nil {
		return err
	}
	path, err := filepath.Abs(c.File)
	if err != nil {
		return err
	}
	info, before, entries, err := readImportedKeyring(path)
	if err != nil {
		return err
	}
	a, err := openAccount(ctx)
	if err != nil {
		return err
	}
	bg, cancel := timeout(2 * time.Minute)
	defer cancel()
	if err := a.Locked(func() error {
		old, err := a.KS.Read(c.Project)
		if errors.Is(err, os.ErrNotExist) {
			old = map[string]string{}
		} else if err != nil {
			return err
		}
		for k, v := range entries {
			if previous, ok := old[k]; ok && previous != v {
				return errors.New("import conflicts with a local key; keep both files and resolve the conflict first")
			}
			old[k] = v
		}
		return a.KS.Write(c.Project, old, true)
	}); err != nil {
		return err
	}
	if _, err := a.Sync(bg, account.SyncOptions{}); err != nil {
		return fmt.Errorf("keys imported locally; server upload pending: %w", err)
	}
	v, err := a.ReadVault(bg)
	if err != nil {
		return err
	}
	for k, want := range entries {
		if v.Projects[c.Project][k] != want {
			return errors.New("server copy differs; local source retained")
		}
	}
	if c.Move {
		if err := moveImported(bg, a, c.Project, path, info, before); err != nil {
			return err
		}
	}
	fmt.Println("Keys verified in the server vault.")
	return nil
}

// VaultRestoreProjectCmd restores a complete project revision into a new directory.
type VaultRestoreProjectCmd struct {
	Revision string `help:"Complete project revision ID from storage list --json (default: latest)"`
	File     string `type:"existingfile" help:"Restore offline from an explicit recovery export"`
	Project  string `required:""`
	Checkout string `help:"Checkout ID shown by storage list --json"`
	To       string `required:"" type:"path" help:"New destination directory"`
}

// Run executes the storage command.
func (c *VaultRestoreProjectCmd) Run(ctx *cliCtx) error {
	if c.File != "" {
		id, err := identity.Load(ctx.Keyring)
		if err != nil {
			return err
		}
		v, err := vaultfile.Read(c.File, &id.Public, &id.Private)
		if err != nil {
			return err
		}
		if err := account.RestoreProjectArchive(v, c.Project, c.Checkout, c.To, c.Revision); err != nil {
			return err
		}
		return registerRestored(c.To)
	}
	a, err := openAccount(ctx)
	if err != nil {
		return err
	}
	bg, cancel := timeout(2 * time.Minute)
	defer cancel()
	if err := a.RestoreProject(bg, c.Project, c.Checkout, c.To, c.Revision); err != nil {
		return err
	}
	fmt.Println("Project restored with encrypted files and seals.")
	return registerRestored(c.To)
}

func registerRestored(path string) error {
	return workspace.Update(func(r *workspace.Registry) error { _, _, err := r.Add(path, time.Now()); return err })
}

// VaultRestoreSettingsCmd restores an explicitly selected device profile.
type VaultRestoreSettingsCmd struct {
	File    string `type:"existingfile" help:"Restore settings from an explicit recovery export offline"`
	Profile string `required:""`
	MapUser bool   `help:"Map the profile owner's uid to your current uid"`
	Replace bool   `help:"Replace existing policy and trust settings"`
}

// Run executes the storage command.
func (c *VaultRestoreSettingsCmd) Run(ctx *cliCtx) error {
	if c.File != "" {
		v, err := readStorageExport(ctx, c.File)
		if err != nil {
			return err
		}
		if err := account.RestoreProfileArchive(v, c.Profile, c.MapUser, c.Replace); err != nil {
			return err
		}
		bg, cancel := timeout(5 * time.Second)
		defer cancel()
		_, _ = daemon.Call(bg, daemon.Request{Op: "reload"})
		return nil
	}
	a, err := openAccount(ctx)
	if err != nil {
		return err
	}
	bg, cancel := timeout(30 * time.Second)
	defer cancel()
	if err := a.RestoreProfile(bg, c.Profile, c.MapUser, c.Replace); err != nil {
		return err
	}
	_, _ = daemon.Call(bg, daemon.Request{Op: "reload"})
	fmt.Println("Device settings restored.")
	return nil
}

// VaultRetireCmd retains a historical key without active aliases.
type VaultRetireCmd struct {
	Project string `required:""`
	Key     string `required:"" help:"Public key to retain for historical files"`
}

// Run executes the storage command.
func (c *VaultRetireCmd) Run(ctx *cliCtx) error { return changeStoredKey(ctx, c.Project, c.Key, false) }

// VaultDeleteKeyCmd permanently tombstones a key in the current inventory.
type VaultDeleteKeyCmd struct {
	Project string `required:""`
	Key     string `required:""`
	Yes     bool   `help:"Confirm permanent deletion from the current vault and managed caches"`
}

// Run executes the storage command.
func (c *VaultDeleteKeyCmd) Run(ctx *cliCtx) error {
	if !c.Yes {
		return errors.New("use --yes to confirm deletion; retire retains access to historical files")
	}
	return changeStoredKey(ctx, c.Project, c.Key, true)
}
func changeStoredKey(ctx *cliCtx, project, key string, deleted bool) error {
	a, err := openAccount(ctx)
	if err != nil {
		return err
	}
	bg, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := a.ChangeKey(bg, project, key, deleted); err != nil {
		return err
	}
	_, _ = daemon.Call(bg, daemon.Request{Op: "lock"})
	return nil
}

func moveImported(bg context.Context, a *account.Account, project, path string, info os.FileInfo, before []byte) error {
	if err := a.CacheProject(bg, project, "none"); err != nil {
		return err
	}
	currentInfo, err := os.Lstat(path)
	// The source may have been the managed keyring just evicted.
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !os.SameFile(info, currentInfo) || !currentInfo.Mode().IsRegular() {
		return errors.New("source replaced; local source retained")
	}
	current, err := os.ReadFile(path) //nolint:gosec // user-selected source, rechecked for identity and bytes before removal
	if err != nil {
		return err
	}
	if !bytes.Equal(current, before) {
		return errors.New("source changed; local source retained")
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	_, _ = daemon.Call(bg, daemon.Request{Op: "lock"})
	return nil
}

func projectStorageRow(v *vaultfile.Vault, cache *account.CachePolicy, p string) storageProject {
	row := storageProject{Project: p, Cache: cache.Projects[p], Checkouts: []string{}, History: []storageRevision{}}
	local, err := keystore.New().Read(p)
	row.Cached = err == nil && len(local) > 0
	if row.Cache == "" {
		row.Cache = "offline"
	}
	seen := map[string]bool{}
	for name := range v.Projects[p] {
		if keystore.IsPubEntry(name) || keystore.IsGuardEntry(name) {
			row.Keys++
		}
	}
	if v.Catalog != nil {
		for id, r := range v.Catalog.Captures {
			if r.Project == p {
				row.History = append(row.History, storageRevision{ID: id, Checkout: r.Checkout, Label: r.Device + " / " + r.Label, At: r.At, Sequence: r.Sequence, Files: len(r.Files)})
			}
		}
		for _, r := range v.Catalog.Artifacts {
			if r.Project == p {
				row.Revisions++
				seen[r.Checkout] = true
			}
		}
	}
	for origin := range seen {
		row.Checkouts = append(row.Checkouts, origin)
	}
	sort.Strings(row.Checkouts)
	sort.Slice(row.History, func(i, j int) bool {
		if row.History[i].Checkout == row.History[j].Checkout {
			return row.History[i].Sequence > row.History[j].Sequence
		}
		return row.History[i].At.After(row.History[j].At)
	})
	return row
}

func readImportedKeyring(path string) (os.FileInfo, []byte, map[string]string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, nil, nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, nil, nil, errors.New("choose a regular keyring file")
	}
	before, err := os.ReadFile(path) //nolint:gosec // explicitly selected regular keyring import
	if err != nil {
		return nil, nil, nil, err
	}
	entries, err := keyringfile.Parse(path, before)
	if err != nil {
		return nil, nil, nil, errors.New("could not read the keyring")
	}
	for name := range entries {
		if !strings.HasPrefix(name, "ESEC_PRIVATE_KEY") && !strings.HasPrefix(name, "ESEC_GUARD_") && name != "ESEC_ACTIVE_KEY" && name != "ESEC_ACTIVE_ENVIRONMENT" {
			return nil, nil, nil, errors.New("file contains entries that are not esec keys")
		}
	}
	return info, before, entries, nil
}
