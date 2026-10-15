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
	Project string `help:"Project id (default: nearest .esec-project)"`
	Dir     string `type:"path" help:"Directory to search for secrets files (default: the directory of the project marker)"`
	Yes     bool   `help:"Do not ask for confirmation"`
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
	if !c.Yes && !confirm(fmt.Sprintf("Replace the %s key of %s and re-encrypt its files under %s?", c.Env, project, root)) {
		return errors.New("rotation cancelled")
	}
	res, err := envrotate.Rotate(keystore.New(), project, c.Env, root)
	if res == nil && err != nil {
		return err
	}
	markDirty("env rotate")
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
