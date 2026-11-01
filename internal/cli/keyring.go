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
	"time"

	"github.com/mscno/esec"
	"github.com/mscno/esec-vault/internal/identity"
	"github.com/mscno/esec-vault/internal/keystore"
	"github.com/mscno/esec-vault/internal/paths"
	"github.com/mscno/esec-vault/internal/storage"
	"github.com/mscno/esec-vault/internal/vaultfile"
	"github.com/mscno/esec/pkg/keyringfile"
	"github.com/mscno/esec/pkg/projectfile"
)

// KeyringCmd manages existing and new project keyrings.
type KeyringCmd struct {
	Migrate KeyringMigrateCmd `cmd:"" help:"Import repo-local keyrings into the global store."`
	List    KeyringListCmd    `cmd:"" help:"List stored projects and key counts."`
	Add     KeyringAddCmd     `cmd:"" help:"Generate a public-key-addressed project key."`
	Seal    KeyringSealCmd    `cmd:"" help:"Encrypt keyring files with this machine's cache key."`
	Unseal  KeyringUnsealCmd  `cmd:"" help:"Store keyring files as plain text again."`
	Repair  KeyringRepairCmd  `cmd:"" help:"File every key also under its public key, so no later change can drop it."`
}

// KeyringRepairCmd files named keys under their public keys. Every write
// does this by itself; repair brings keyrings written before up to date.
type KeyringRepairCmd struct{}

// Run implements keyring repair.
func (c *KeyringRepairCmd) Run(_ *cliCtx) error {
	ks := keystore.New()
	projects, err := ks.List()
	if err != nil {
		return err
	}
	total := 0
	for _, p := range projects {
		added, err := ks.Repair(p)
		if err != nil {
			return fmt.Errorf("%s: %w", p, err)
		}
		if len(added) > 0 {
			fmt.Printf("%s: filed %d key(s) under their public key\n", p, len(added))
			total += len(added)
		}
	}
	if total == 0 {
		fmt.Println("Every key is filed under its public key.")
		return nil
	}
	return nil
}

// KeyringSealCmd seals keyrings.
type KeyringSealCmd struct {
	All              bool   `help:"Seal every keyring and seal new keyrings by default"`
	Project          string `help:"Seal one project (default: nearest esec.toml)"`
	SkipVersionCheck bool   `help:"Seal even if the esec on PATH cannot read sealed keyrings"`
}

// Run implements keyring seal.
func (c *KeyringSealCmd) Run(ctx *cliCtx) error {
	if !c.SkipVersionCheck {
		if err := esecSupportsSealed(); err != nil {
			return fmt.Errorf("%w (or pass --skip-version-check)", err)
		}
	}
	if c.All {
		n, err := sealAll(ctx, true)
		if err != nil {
			return err
		}
		fmt.Printf("Sealed %d keyring(s); new keyrings will be sealed too.\n", n)
		return nil
	}
	return sealOne(ctx, c.Project, true)
}

// KeyringUnsealCmd unseals keyrings.
type KeyringUnsealCmd struct {
	All     bool   `help:"Unseal every keyring and stop sealing new ones"`
	Project string `help:"Unseal one project (default: nearest esec.toml)"`
	Yes     bool   `help:"Do not ask for confirmation"`
}

// Run implements keyring unseal.
func (c *KeyringUnsealCmd) Run(ctx *cliCtx) error {
	what := "this project's keyring"
	if c.All {
		what = "every keyring"
	}
	if !c.Yes && !confirm(fmt.Sprintf("Write %s as plain text on this disk?", what)) {
		return errors.New("unseal cancelled")
	}
	if c.All {
		n, err := sealAll(ctx, false)
		if err != nil {
			return err
		}
		fmt.Printf("Unsealed %d keyring(s); new keyrings will be plain.\n", n)
		return nil
	}
	return sealOne(ctx, c.Project, false)
}

func sealOne(ctx *cliCtx, explicit string, seal bool) error {
	project, err := resolveProject(explicit)
	if err != nil {
		return err
	}
	store, err := secretStoreFor(ctx)
	if err != nil {
		return err
	}
	if seal {
		if _, err := keyringfile.EnsureCacheKey(store); err != nil {
			return err
		}
	}
	if err := keystore.New().SetSealed(project, seal); err != nil {
		return err
	}
	state := "plain"
	if seal {
		state = "sealed"
	}
	fmt.Printf("%s is now %s.\n", project, state)
	return nil
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
		}
		if err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// KeyringAddCmd generates one unnamed project key.
type KeyringAddCmd struct {
	Project string `help:"Project id (default: nearest esec.toml)"`
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
	fmt.Printf("ESEC_PUBLIC_KEY=%s\n", pub)
	return nil
}

// KeyringListCmd prints metadata only.
type KeyringListCmd struct {
	JSON bool `help:"Print JSON, for scripts and agents"`
}

// Run lists all keyrings including the default store.
func (c *KeyringListCmd) Run(ctx *cliCtx) error {
	ks := keystore.New()
	projects, err := ks.List()
	if err != nil {
		return err
	}
	type project struct {
		Project string `json:"project"`
		Entries int    `json:"entries"`
	}
	out := []project{}
	for _, p := range projects {
		entries, err := ks.Read(p)
		if err != nil {
			return err
		}
		out = append(out, project{p, len(entries)})
	}
	if c.JSON {
		return printJSON(out)
	}
	if len(out) == 0 {
		fmt.Fprintln(os.Stderr, "No keyrings on this machine yet. Create keys in a repository with: esec vault project init ORG/REPO")
	}
	for _, p := range out {
		fmt.Printf("%s: %d entries\n", p.Project, p.Entries)
	}
	return nil
}

// BackupCmd syncs the server and optionally creates a portable recovery export.
type BackupCmd struct {
	Out    string `type:"path" help:"Create a new encrypted portable recovery file"`
	Verify bool   `help:"Verify the export's encryption and embedded recovery identity"`
	Push   bool   `hidden:"" help:"Removed: use sync --server"`
	Remote string `hidden:"" help:"Removed external backup destination"`
	Prune  bool   `hidden:"" help:"Removed external backup retention"`
	Async  bool   `hidden:"" help:"Removed external upload queue"`
}

// Run backs up without requiring the recovery phrase.
func (c *BackupCmd) Run(ctx *cliCtx) error {
	if c.Push || c.Remote != "" || c.Prune || c.Async {
		return fmt.Errorf("external backup sync was removed; run esec vault sync --server; use backup --out FILE for a local export")
	}
	if err := serverSync(ctx, false); err != nil {
		return fmt.Errorf("vault server backup failed: %w", err)
	}
	if c.Out == "" {
		fmt.Println("Vault synced to the server. Use --out FILE for an explicit portable recovery export.")
		return nil
	}
	a, err := openAccount(ctx)
	if err != nil {
		return err
	}
	bg, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	blob, err := a.RecoveryExport(bg)
	if err != nil {
		return err
	}
	if err := writeNewPrivate(c.Out, blob); err != nil {
		return err
	}
	if c.Verify {
		id, err := identity.Load(ctx.Keyring)
		if err != nil {
			return err
		}
		v, err := vaultfile.Open(blob, &id.Public, &id.Private)
		if err != nil {
			return err
		}
		if !vaultfile.HasMasterCopy(blob) || len(v.Identity) == 0 {
			return errors.New("export has no recovery copy")
		}
	}
	if !ctx.Quiet {
		fmt.Fprintln(os.Stderr, "Portable encrypted recovery export saved:", c.Out)
	}
	return nil
}

// RestoreCmd restores keys, with explicit optional settings restoration.
type RestoreCmd struct {
	File     string `type:"path" help:"Encrypted recovery export (omit to restore server keyrings)"`
	Force    bool   `help:"Overwrite conflicting keyrings"`
	DryRun   bool   `help:"List projects without writing"`
	Settings bool   `help:"Also restore policy and trust pins"`
}

// Run validates the entire restore before writing any keys.
func (c *RestoreCmd) Run(ctx *cliCtx) error {
	v, err := c.readVault(ctx)
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
	for name := range v.Files {
		switch name {
		case "policy.toml", "trusted.toml":
		case "remote.toml":
			// Legacy backups remain readable, but external sync configuration is obsolete.
			delete(v.Files, name)
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

func (c *RestoreCmd) readVault(ctx *cliCtx) (*vaultfile.Vault, error) {
	id, err := identity.Load(ctx.Keyring)
	if err != nil {
		return nil, err
	}
	file := c.File
	var v *vaultfile.Vault
	if file == "" {
		a, err := openAccount(ctx)
		if err != nil {
			return nil, err
		}
		bg, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		v, err = a.ReadVault(bg)
		if err != nil {
			return nil, err
		}
	} else {
		v, err = vaultfile.Read(file, &id.Public, &id.Private)
	}
	if err != nil {
		return nil, err
	}
	return v, nil
}
