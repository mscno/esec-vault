package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/mscno/esec/pkg/projectfile"

	"github.com/mscno/esec-vault/internal/envrotate"
	"github.com/mscno/esec-vault/internal/seal"
)

// EnvRotateCmd replaces an environment key and re-encrypts its files.
type EnvRotateCmd struct {
	Env     string `arg:"" help:"Environment name"`
	Project string `help:"Project id (default: nearest esec.toml)"`
	Dir     string `type:"path" help:"Directory to search for secrets files (default: the directory of the project marker)"`
	Yes     bool   `help:"Do not ask for confirmation"`
}

// rotator rotates environments: it opens each old key (from this device,
// its seal, or with a touch), and seals each new key for the same readers
// before any file is encrypted to it.
type rotator struct {
	ctx *cliCtx
	s   *sealing
}

func (r *rotator) rotate(project, env, root string) (*envrotate.Result, error) {
	if r.s == nil {
		s, err := newSealing(r.ctx)
		if err != nil {
			return nil, err
		}
		r.s = s
	}
	pf, proot, err := projectRoot(root)
	if err != nil {
		return nil, fmt.Errorf("rotating needs the project's checkout: %w", err)
	}
	if pf.Project != project {
		return nil, fmt.Errorf("%s is a checkout of %s, not %s", proot, pf.Project, project)
	}
	old, err := r.s.open(proot, pf, env, "rotate its key (the old key is read once, the new one sealed)")
	if err != nil {
		return nil, err
	}
	readers, err := readersOf(pf, env)
	if err != nil {
		return nil, err
	}
	level := old.Guard
	return envrotate.Rotate(r.s.ks, project, env, root, envrotate.Options{
		Old:   old.Private,
		Cache: !seal.Guarded(level),
		Seal:  func(priv string) error { return r.s.seal(proot, pf, env, priv, level, readers) },
	})
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
	rot := &rotator{ctx: ctx}
	res, err := rot.rotate(project, c.Env, root)
	if res == nil && err != nil {
		return err
	}
	markDirty("env rotate")
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
	fmt.Println("The new key is sealed in .esec/; the old one stays sealed in git history, so old commits still decrypt.")
	fmt.Println("Next: commit .esec/, esec.toml and the re-encrypted files. If the key was exposed, also change the secret values at their providers;")
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
