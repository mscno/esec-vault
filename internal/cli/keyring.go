package cli

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/mscno/esec"
	"github.com/mscno/esec/pkg/projectfile"

	"github.com/mscno/esec-vault/internal/identity"
	"github.com/mscno/esec-vault/internal/keystore"
	"github.com/mscno/esec-vault/internal/paths"
	"github.com/mscno/esec-vault/internal/vaultfile"
)

// KeyringCmd groups global keyring store management.
type KeyringCmd struct {
	Migrate KeyringMigrateCmd `cmd:"" help:"Move repo-local .esec-keyring files into the global store."`
	List    KeyringListCmd    `cmd:"" help:"List projects and environments in the global store."`
	Add     KeyringAddCmd     `cmd:"" help:"Generate a component keypair and add it to a project's keyring."`
}

// KeyringMigrateCmd moves repo-local keyrings into the global store.
type KeyringMigrateCmd struct {
	Dirs        []string `help:"Repositories to migrate" name:"dir" default:"." type:"path"`
	DeleteLocal bool     `help:"Delete the repo-local keyring after a verified copy is in place"`
}

// Run implements keyring migrate.
func (c *KeyringMigrateCmd) Run(ctx *cliCtx) error {
	ks := keystore.New()
	failed := false
	for _, dir := range c.Dirs {
		projects, err := ks.Migrate(dir, c.DeleteLocal, confirm)
		for _, p := range projects {
			fmt.Printf("Migrated %s (from %s)\n", p, dir)
		}
		if err != nil {
			failed = true
			ctx.Logger.Error("migration had errors", "dir", dir, "error", err)
		}
	}
	if failed {
		return fmt.Errorf("migration completed with errors")
	}
	return nil
}

// KeyringAddCmd generates a component keypair and appends a pubkey-keyed
// entry to the project's global keyring.
type KeyringAddCmd struct {
	Project string `help:"Project id (default: nearest .esec-project)" name:"project"`
}

// Run implements keyring add.
func (c *KeyringAddCmd) Run(ctx *cliCtx) error {
	project := c.Project
	if project == "" {
		cwd, err := os.Getwd()
		if err != nil {
			return err
		}
		p, _, err := projectfile.FindProjectFile(cwd)
		if err != nil {
			return fmt.Errorf("no .esec-project found; pass --project explicitly")
		}
		project = p
	}

	pub, priv, err := esec.GenerateKeypair()
	if err != nil {
		return err
	}

	ks := keystore.New()
	entries, err := ks.Read(project)
	if err != nil {
		entries = map[string]string{}
	}
	name := fmt.Sprintf("%s_%s", esec.EsecPrivateKey, strings.ToUpper(pub))
	if _, exists := entries[name]; exists {
		return fmt.Errorf("entry %s already exists (collision — regenerate)", name)
	}
	entries[name] = priv
	if err := ks.Write(project, entries, true); err != nil {
		return err
	}

	fmt.Printf("Added keypair to keyring for %s\n", project)
	fmt.Printf("\nPublic key — put it in the new secrets file:\n\n  ESEC_PUBLIC_KEY=%s\n\n", pub)
	fmt.Println("The file will be decryptable via its public key regardless of its name.")
	return nil
}

// KeyringListCmd lists stored keyrings (metadata only).
type KeyringListCmd struct{}

// Run implements keyring list.
func (c *KeyringListCmd) Run(ctx *cliCtx) error {
	ks := keystore.New()
	projects, err := ks.List()
	if err != nil {
		return err
	}
	if len(projects) == 0 {
		fmt.Println("No keyrings in", ks.Dir)
		return nil
	}
	fmt.Println("Keyrings in", ks.Dir)
	for _, p := range projects {
		entries, err := ks.Read(p)
		if err != nil {
			fmt.Printf("  %s (unreadable: %v)\n", p, err)
			continue
		}
		var envs []string
		for k := range entries {
			if rest, ok := strings.CutPrefix(k, esec.EsecPrivateKey+"_"); ok {
				envs = append(envs, strings.ToLower(rest))
			} else if k == esec.EsecPrivateKey {
				envs = append(envs, "(default)")
			}
		}
		sort.Strings(envs)
		fmt.Printf("  %s: %s\n", p, strings.Join(envs, ", "))
	}
	return nil
}

// BackupCmd seals all keyrings into the vault blob.
type BackupCmd struct {
	Out string `help:"Also copy the sealed blob to this path" type:"path"`
}

// Run implements backup.
func (c *BackupCmd) Run(ctx *cliCtx) error {
	id, err := identity.Load(ctx.Keyring)
	if err != nil {
		return err
	}
	ks := keystore.New()
	projects, err := ks.List()
	if err != nil {
		return err
	}
	v := &vaultfile.Vault{Projects: map[string]map[string]string{}}
	for _, p := range projects {
		entries, err := ks.Read(p)
		if err != nil {
			return fmt.Errorf("failed to read keyring for %s: %w", p, err)
		}
		v.Projects[p] = entries
	}
	if err := vaultfile.Write(paths.VaultFile(), v, time.Now(), &id.Public); err != nil {
		return err
	}
	if c.Out != "" {
		data, err := os.ReadFile(paths.VaultFile())
		if err != nil {
			return err
		}
		if err := os.WriteFile(c.Out, data, 0600); err != nil { //nolint:gosec // c.Out is a user-provided CLI flag
			return err
		}
	}
	fmt.Printf("Vault sealed: %s (%d projects)\n", paths.VaultFile(), len(v.Projects))
	return nil
}

// RestoreCmd restores keyrings from the vault blob.
type RestoreCmd struct {
	File  string `help:"Vault blob to restore from" default:"" type:"path"`
	Force bool   `help:"Overwrite existing keyrings without prompting"`
}

// Run implements restore.
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
	restored := 0
	for project, entries := range v.Projects {
		if _, err := ks.Read(project); err == nil && !c.Force {
			if !confirm(fmt.Sprintf("keyring for %s already exists; overwrite?", project)) {
				continue
			}
		}
		if err := ks.Write(project, entries, true); err != nil {
			return err
		}
		restored++
	}
	fmt.Printf("Restored %d keyrings into %s\n", restored, ks.Dir)
	return nil
}

// RecoverCmd is the full cold-recovery path.
type RecoverCmd struct {
	File string `help:"Vault blob to restore from" type:"path"`
}

// Run implements recover: identity from mnemonic, then restore keyrings.
func (c *RecoverCmd) Run(ctx *cliCtx) error {
	rc := IdentityRecoverCmd{}
	if err := rc.Run(ctx); err != nil {
		return err
	}
	rs := RestoreCmd{File: c.File, Force: false}
	return rs.Run(ctx)
}

// SyncCmd and ShareCmd live in share.go; MembersCmd in members.go.
