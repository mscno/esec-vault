package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"

	"github.com/mscno/esec"
	"github.com/mscno/esec-vault/internal/daemon"
	"github.com/mscno/esec-vault/internal/identity"
	"github.com/mscno/esec-vault/internal/keystore"
	"github.com/mscno/esec-vault/internal/paths"
	"github.com/mscno/esec-vault/internal/remote"
	"github.com/mscno/esec-vault/internal/storage"
	"github.com/mscno/esec-vault/internal/vaultfile"
	"github.com/mscno/esec/pkg/projectfile"
)

// KeyringCmd manages existing and new project keyrings.
type KeyringCmd struct {
	Migrate KeyringMigrateCmd `cmd:"" help:"Import repo-local keyrings into the global store."`
	List    KeyringListCmd    `cmd:"" help:"List stored projects and key counts."`
	Add     KeyringAddCmd     `cmd:"" help:"Generate a public-key-addressed project key."`
}

// KeyringMigrateCmd imports keys from repositories.
type KeyringMigrateCmd struct {
	Dirs        []string `name:"dir" default:"." type:"path" help:"Repository roots to import"`
	DeleteLocal bool     `help:"Delete local keyrings after verified import"`
}

// Run imports keys, reporting partial failures.
func (c *KeyringMigrateCmd) Run(ctx *cliCtx) error {
	var errs []error
	for _, dir := range c.Dirs {
		projects, err := keystore.New().Migrate(dir, c.DeleteLocal, confirm)
		for _, p := range projects {
			fmt.Fprintln(os.Stderr, "Imported", p)
		}
		if len(projects) > 0 {
			markDirty("keyring import")
		}
		if err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// KeyringAddCmd generates one unnamed project key.
type KeyringAddCmd struct {
	Project string `help:"Project id (default: nearest .esec-project)"`
}

// Run generates and stores a key without printing its private half.
func (c *KeyringAddCmd) Run(ctx *cliCtx) error {
	project, err := resolveProject(c.Project)
	if err != nil {
		return err
	}
	ks := keystore.New()
	entries, err := readOrNew(ks, project)
	if err != nil {
		return err
	}
	pub, priv, err := esec.GenerateKeypair()
	if err != nil {
		return err
	}
	entries[esec.EsecPrivateKey+"_"+strings.ToUpper(pub)] = priv
	if err := ks.Write(project, entries, true); err != nil {
		return err
	}
	markDirty("keyring add")
	fmt.Printf("ESEC_PUBLIC_KEY=%s\n", pub)
	return nil
}

// KeyringListCmd prints metadata only.
type KeyringListCmd struct{}

// Run lists all keyrings including the default store.
func (c *KeyringListCmd) Run(ctx *cliCtx) error {
	ks := keystore.New()
	projects, err := ks.List()
	if err != nil {
		return err
	}
	for _, p := range projects {
		entries, err := ks.Read(p)
		if err != nil {
			return err
		}
		fmt.Printf("%s: %d entries\n", p, len(entries))
	}
	return nil
}

// BackupCmd persists a self-contained snapshot and optionally uploads it.
type BackupCmd struct {
	Out    string `type:"path" help:"Also export this encrypted snapshot"`
	Verify bool   `help:"Compare the snapshot against the live keyring store"`
	Push   bool   `help:"Upload and verify a remote copy"`
	Remote string `help:"Remote name (otherwise env/config default)"`
	Prune  bool   `help:"With --push, prune older generations"`
	Async  bool   `help:"With --push, queue the upload in the daemon"`
}

// Run backs up without requiring the recovery phrase.
func (c *BackupCmd) Run(ctx *cliCtx) error {
	if c.Async && !c.Push {
		return fmt.Errorf("--async requires --push")
	}
	if c.Prune && !c.Push {
		return fmt.Errorf("--prune requires --push")
	}
	if c.Out == "" {
		if c.Push {
			return (&RemotePushCmd{Prune: c.Prune, Name: c.Remote, Async: c.Async}).Run(ctx)
		}
		if handled, err := snapshotThroughDaemon(); handled {
			return err
		}
	}
	id, err := identity.Load(ctx.Keyring)
	if err != nil {
		return err
	}
	snap, err := remote.BuildSnapshot(id, keystore.New())
	if err != nil {
		return err
	}
	if c.Out != "" {
		if err := storage.Write(c.Out, snap.Blob); err != nil {
			return err
		}
	}
	if c.Verify {
		v, err := vaultfile.Open(snap.Blob, &id.Public, &id.Private)
		if err != nil {
			return err
		}
		if !vaultfile.HasMasterCopy(snap.Blob) || len(v.Identity) == 0 {
			return fmt.Errorf("snapshot has no recovery material")
		}
		if err := verifyRestored(keystore.New(), v); err != nil {
			return err
		}
	}
	if !ctx.Quiet {
		fmt.Fprintf(os.Stderr, "Snapshot generation %d: %d projects, identity included (%s)\n", snap.Generation, snap.Projects, paths.VaultFile())
	}
	if c.Push {
		return (&RemotePushCmd{Name: c.Remote, Prune: c.Prune, Async: c.Async}).Run(ctx)
	}
	return nil
}

func snapshotThroughDaemon() (bool, error) {
	resp, err := daemon.Call(context.Background(), daemon.Request{Op: "ping"})
	if err != nil {
		return resp != nil, err
	}
	resp, err = daemon.Call(context.Background(), daemon.Request{Op: "snapshot"})
	if err != nil {
		return true, err
	}
	return true, printJSON(resp.Job)
}

// RestoreCmd restores keys, with explicit optional settings restoration.
type RestoreCmd struct {
	File     string `type:"path" help:"Encrypted snapshot (default: local vault)"`
	Force    bool   `help:"Overwrite conflicting keyrings"`
	DryRun   bool   `help:"List projects without writing"`
	Settings bool   `help:"Also restore policy, trust pins and remote config"`
}

// Run validates the entire restore before writing any keys.
func (c *RestoreCmd) Run(ctx *cliCtx) error {
	id, err := identity.Load(ctx.Keyring)
	if err != nil {
		return err
	}
	file := c.File
	if file == "" {
		file = paths.VaultFile()
	}
	v, err := vaultfile.Read(file, &id.Public, &id.Private)
	if err != nil {
		return err
	}
	ks := keystore.New()
	if err := validateRestore(v); err != nil {
		return err
	}
	for _, project := range sortedKeys(v.Projects) {
		if c.DryRun {
			fmt.Printf("%s: %d entries\n", project, len(v.Projects[project]))
			continue
		}
		old, err := ks.Read(project)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if err == nil && !reflect.DeepEqual(old, v.Projects[project]) && !c.Force && !confirm("Overwrite keyring for "+project+"?") {
			return fmt.Errorf("restore cancelled before writing")
		}
	}
	if c.DryRun {
		return nil
	}
	if c.Settings {
		if err := checkSettings(v.Files, c.Force); err != nil {
			return err
		}
	}
	for _, project := range sortedKeys(v.Projects) {
		if err := ks.Write(project, v.Projects[project], true); err != nil {
			return err
		}
	}
	if c.Settings {
		if err := restoreSettings(v.Files); err != nil {
			return err
		}
	}
	markDirty("restore")
	return verifyRestored(ks, v)
}

func restoreSettings(files map[string][]byte) error {
	for name, data := range files {
		if err := storage.Write(filepath.Join(paths.Home(), name), data); err != nil {
			return err
		}
	}
	return nil
}

func checkSettings(files map[string][]byte, force bool) error {
	for name, data := range files {
		p := filepath.Join(paths.Home(), name)
		old, err := os.ReadFile(p) //nolint:gosec // filenames are allowlisted by validateRestore before calling
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if err == nil && !reflect.DeepEqual(old, data) && !force {
			return fmt.Errorf("settings file %s exists; use --force", name)
		}
	}
	return nil
}

func validateRestore(v *vaultfile.Vault) error {
	seen := map[string]bool{}
	for project, entries := range v.Projects {
		if project != "default" {
			if err := projectfile.ValidateOrgRepo(project); err != nil {
				return err
			}
		}
		name := projectfile.KeyringName(project)
		if seen[name] {
			return fmt.Errorf("colliding project ids in backup")
		}
		seen[name] = true
		for k, val := range entries {
			if strings.ContainsAny(k+val, "\r\n") || strings.ContainsAny(k, "=\x00") {
				return fmt.Errorf("invalid keyring entry in %s", project)
			}
		}
	}
	for name, data := range v.Files {
		switch name {
		case "policy.toml", "trusted.toml":
		case "remote.toml":
			if err := remote.CheckNoSecrets(data); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unsupported settings file in backup: %s", name)
		}
	}
	return nil
}

func verifyRestored(ks *keystore.Store, v *vaultfile.Vault) error {
	for project, want := range v.Projects {
		got, err := ks.Read(project)
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(want, got) {
			return fmt.Errorf("keyring %s does not match backup", project)
		}
	}
	return nil
}

func sortedKeys(m map[string]map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func readOrNew(ks *keystore.Store, project string) (map[string]string, error) {
	entries, err := ks.Read(project)
	if errors.Is(err, os.ErrNotExist) {
		return map[string]string{}, nil
	}
	return entries, err
}

// RecoverCmd restores identity and keys from one self-contained backup.
type RecoverCmd struct {
	File     string `type:"path" help:"Encrypted backup file"`
	Force    bool   `help:"Overwrite identity and conflicting keys"`
	Settings bool   `help:"Restore backed-up settings too"`
}

// Run performs cold recovery before restoring keys.
func (c *RecoverCmd) Run(ctx *cliCtx) error {
	if err := (&IdentityRecoverCmd{File: c.File, Force: c.Force}).Run(ctx); err != nil {
		return err
	}
	return (&RestoreCmd{File: c.File, Force: c.Force, Settings: c.Settings}).Run(ctx)
}
