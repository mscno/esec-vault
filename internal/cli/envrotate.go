package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/mscno/esec/pkg/projectfile"

	"github.com/mscno/esec-vault/internal/envrotate"
	"github.com/mscno/esec-vault/internal/keystore"
)

// EnvRotateCmd replaces an environment key and re-encrypts its files.
type EnvRotateCmd struct {
	Env     string `arg:"" help:"Environment name"`
	Project string `help:"Project id (default: nearest esec.toml)"`
	Dir     string `type:"path" help:"Directory to search for secrets files (default: the directory of the project marker)"`
	Yes     bool   `help:"Do not ask for confirmation"`
	Offline bool   `help:"Do not wait for the new key to reach the vault server or backup before re-encrypting"`
}

// rotator rotates environments, opening the guard once, when the first
// guarded one needs it, and storing each new key before files change.
type rotator struct {
	ctx     *cliCtx
	offline bool
	guard   *envrotate.Guard
}

func (r *rotator) rotate(project, env, root string) (*envrotate.Result, error) {
	opts := envrotate.Options{Guard: r.guard, Store: func() error { return requireStored(r.ctx, r.offline, "env rotate") }}
	res, err := envrotate.Rotate(keystore.New(), project, env, root, opts)
	if !errors.Is(err, envrotate.ErrGuarded) {
		return res, err
	}
	id, err := openGuard(fmt.Sprintf("Rotate the guarded %s key of %s (read the old key once, guard the new one)", env, project))
	if err != nil {
		return nil, err
	}
	r.guard = &envrotate.Guard{ID: id}
	opts.Guard = r.guard
	return envrotate.Rotate(keystore.New(), project, env, root, opts)
}

// Run implements env rotate.
func (c *EnvRotateCmd) Run(ctx *cliCtx) error {
	if err := validateEnvName(c.Env); err != nil {
		return err
	}
	project, root, err := c.resolve()
	if err != nil {
		return err
	}
	shared, err := sharedProject(ctx, project)
	if err != nil {
		return err
	}
	if !c.Yes && !confirm(fmt.Sprintf("Replace the %s key of %s and re-encrypt its files under %s?", c.Env, project, root)) {
		return errors.New("rotation cancelled")
	}
	rot := &rotator{ctx: ctx, offline: c.Offline}
	res, err := rot.rotate(project, c.Env, root)
	if res == nil && err != nil {
		return err
	}
	markDirty("env rotate")
	if pf, ferr := projectfile.Load(root); ferr == nil && pf.Project == project {
		pf.SetEnv(c.Env, res.NewPublic)
		if serr := pf.Save(root); serr != nil {
			fmt.Fprintln(os.Stderr, "! esec.toml: "+serr.Error())
		}
	}
	if shared {
		publishShared(ctx, project, c.Env, "rotated")
	}
	fmt.Printf("✓ Rotated %s %s: new public key %s\n", project, c.Env, res.NewPublic)
	if len(res.Files) == 0 {
		fmt.Println("! No file under", root, "used the old key. Rotate files elsewhere with the new key yourself.")
	}
	for _, f := range res.Files {
		rel, relErr := filepath.Rel(root, f)
		if relErr != nil {
			rel = f
		}
		fmt.Println("  re-encrypted", rel)
	}
	fmt.Println("The old key stays in the keyring under its public-key entry, so files in git history still decrypt.")
	fmt.Println("Next: commit the re-encrypted files. If the key was exposed, also change the secret values at their providers;")
	fmt.Println("a new key does not change values someone may already have read.")
	return err
}

func (c *EnvRotateCmd) resolve() (string, string, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return "", "", err
	}
	project, marker, findErr := projectfile.FindProjectFile(cwd)
	if c.Project != "" {
		if err := projectfile.ValidateOrgRepo(c.Project); err != nil {
			return "", "", err
		}
		if findErr != nil || project != c.Project {
			marker = ""
		}
		project = c.Project
	} else if findErr != nil {
		return "", "", findErr
	}
	root := c.Dir
	if root == "" {
		if marker == "" {
			return "", "", errors.New("pass --dir to say where the project's secrets files are")
		}
		root = filepath.Dir(marker)
	}
	return project, root, nil
}
