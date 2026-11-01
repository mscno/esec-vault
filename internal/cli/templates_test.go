package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/mscno/esec"
	"github.com/mscno/esec-vault/internal/secretfile"
	"github.com/mscno/esec/pkg/fileutils"
)

func initFixture(t *testing.T, f string) (*ProjectInitCmd, *cliCtx) {
	t.Helper()
	t.Setenv("ESEC_VAULT_HOME", t.TempDir())
	t.Setenv("ESEC_KEYRING_DIR", "")
	t.Setenv("ESEC_CONFIG", "")
	t.Setenv("ESEC_VAULT_NO_REGISTER", "1")
	ctx := testCtx(t)
	return &ProjectInitCmd{Project: "org/init", Dir: t.TempDir(), Env: []string{"dev"}, Format: f, Template: true, ctx: ctx}, ctx
}

func writeInitFixture(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0640); err != nil { //nolint:gosec // verify preservation of existing repository file permissions
		t.Fatal(err)
	}
}

func TestInitAndEnvAddNeverCopyExamples(t *testing.T) {
	for _, f := range []string{"env", "ejson", "eyaml", "eyml", "etoml"} {
		t.Run(f, func(t *testing.T) {
			c, ctx := initFixture(t, f)
			for _, name := range []string{"." + f + ".example", "example." + f} {
				writeInitFixture(t, filepath.Join(c.Dir, name), "TOKEN=must-never-be-copied\ninvalid [")
			}
			if err := c.Run(ctx); err != nil {
				t.Fatal(err)
			}
			if err := (&EnvAddCmd{Env: "prod", Project: c.Project, Dir: c.Dir, Template: true}).Run(ctx); err != nil {
				t.Fatal(err)
			}
			for _, env := range []string{"dev", "prod"} {
				path, _, err := secretsTemplate(c.Dir, "."+f, env, "")
				if err != nil {
					t.Fatal(err)
				}
				data, err := os.ReadFile(path) //nolint:gosec // test-owned file
				if err != nil {
					t.Fatal(err)
				}
				if _, err := esec.ExtractPublicKey(data, esec.FileFormat("."+f)); err != nil {
					t.Fatal(err)
				}
				keys, err := secretfile.Keys(data, fileutils.FileFormat("."+f))
				if err != nil || len(keys) != 0 {
					t.Fatalf("new file contains values: %v", err)
				}
			}
		})
	}
}
