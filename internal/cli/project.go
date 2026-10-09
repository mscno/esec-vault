package cli

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/mscno/esec"
	"github.com/mscno/esec-vault/internal/keystore"
	"github.com/mscno/esec-vault/internal/storage"
	"github.com/mscno/esec/pkg/crypto"
	"github.com/mscno/esec/pkg/projectfile"
)

// ProjectCmd scaffolds projects.
type ProjectCmd struct {
	Init ProjectInitCmd `cmd:"" help:"Create project marker, environment keys and secrets templates."`
}

// ProjectInitCmd creates a project without exposing private keys.
type ProjectInitCmd struct {
	ID       string   `arg:"" optional:"" help:"Project id (org/repo)"`
	Project  string   `help:"Project id; otherwise infer from origin"`
	Dir      string   `default:"." type:"path" help:"Project directory"`
	Env      []string `name:"env" sep:"," default:"dev" help:"Environment names"`
	Format   string   `short:"f" default:".env" help:"env, ejson, eyaml, eyml or etoml"`
	Template bool     `default:"true" negatable:"" help:"Create secrets templates"`
	Force    bool     `help:"Replace a different existing project marker"`
}

// Run validates all requested files before storing keys, then publishes templates.
func (c *ProjectInitCmd) Run(ctx *cliCtx) error {
	project, err := c.projectID()
	if err != nil {
		return err
	}
	if old, err := projectfile.ReadProjectFile(c.Dir); err == nil && old != project && !c.Force {
		return fmt.Errorf("project marker already identifies %s", old)
	} else if err != nil && !errors.Is(err, projectfile.ErrNotFound) {
		return err
	}
	return c.create(project)
}

func (c *ProjectInitCmd) projectID() (string, error) {
	project := c.Project
	if c.ID != "" {
		if project != "" && project != c.ID {
			return "", fmt.Errorf("conflicting project ids")
		}
		project = c.ID
	}
	if project == "" {
		var err error
		project, err = deriveProjectFromGit(c.Dir)
		if err != nil {
			return "", err
		}
	}
	return project, projectfile.ValidateOrgRepo(project)
}

func (c *ProjectInitCmd) create(project string) error {
	format := "." + strings.TrimPrefix(c.Format, ".")
	if _, err := templateContent(format, "", ""); err != nil {
		return err
	}
	ks := keystore.New()
	entries, err := readOrNew(ks, project)
	if err != nil {
		return err
	}
	files, err := prepareEnvironments(c, format, entries)
	if err != nil {
		return err
	}
	if err := ks.Write(project, entries, true); err != nil {
		return err
	}
	markDirty("project init")
	if err := os.MkdirAll(c.Dir, 0750); err != nil {
		return err
	}
	if err := projectfile.WriteProjectFile(c.Dir, project); err != nil {
		return err
	}
	for file, content := range files {
		if err := storage.Write(file, []byte(content)); err != nil {
			return err
		}
	}
	if err := ensureGitignoreEntry(c.Dir, esec.DefaultKeyringFilename); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "Project %s ready: %d environments, %d templates. Keys stored outside the repository.\n", project, len(c.Env), len(files))
	return nil
}

func prepareEnvironments(c *ProjectInitCmd, format string, entries map[string]string) (map[string]string, error) {
	files := map[string]string{}
	for _, env := range c.Env {
		if err := validateEnvName(env); err != nil {
			return nil, err
		}
		name := environmentKey(env)
		priv, exists := entries[name]
		var pub string
		var err error
		if exists {
			pub, err = publicHex(priv)
		} else {
			pub, priv, err = esec.GenerateKeypair()
		}
		if err != nil {
			return nil, err
		}
		file := filepath.Join(c.Dir, format+"."+env)
		if c.Template {
			data, readErr := os.ReadFile(file) //nolint:gosec // user-selected project directory and validated environment
			switch {
			case readErr == nil:
				p, err := esec.ExtractPublicKey(data, esec.FileFormat(format))
				if err != nil || hex.EncodeToString(p[:]) != pub {
					return nil, fmt.Errorf("existing %s does not match stored key; import its key first", file)
				}
			case !errors.Is(readErr, os.ErrNotExist):
				return nil, readErr
			default:
				content, err := templateContent(format, env, pub)
				if err != nil {
					return nil, err
				}
				files[file] = content
			}
		}
		entries[name] = priv
		entries[esec.EsecPrivateKey+"_"+strings.ToUpper(pub)] = priv
	}
	return files, nil
}

func templateContent(format, env, pub string) (string, error) {
	switch format {
	case ".env":
		return fmt.Sprintf("# %s secrets\nESEC_PUBLIC_KEY=%s\n", env, pub), nil
	case ".ejson":
		return fmt.Sprintf("{\n  \"_ESEC_PUBLIC_KEY\": %q\n}\n", pub), nil
	case ".eyaml", ".eyml":
		return fmt.Sprintf("_ESEC_PUBLIC_KEY: %q\n", pub), nil
	case ".etoml":
		return fmt.Sprintf("ESEC_PUBLIC_KEY = %q\n", pub), nil
	default:
		return "", fmt.Errorf("unsupported format %q", format)
	}
}

func deriveProjectFromGit(dir string) (string, error) {
	out, err := runGit(dir, "config", "--get", "remote.origin.url")
	if err != nil {
		return "", fmt.Errorf("pass --project org/repo: %w", err)
	}
	raw := strings.TrimSpace(out)
	var p string
	if strings.Contains(raw, "://") {
		u, err := url.Parse(raw)
		if err != nil {
			return "", err
		}
		p = u.Path
	} else if _, tail, ok := strings.Cut(raw, ":"); ok {
		p = tail
	} else {
		return "", fmt.Errorf("cannot infer project from local remote; pass --project")
	}
	parts := strings.Split(strings.Trim(strings.TrimSuffix(p, ".git"), "/"), "/")
	if len(parts) < 2 {
		return "", fmt.Errorf("cannot infer org/repo from remote")
	}
	p = strings.Join(parts[len(parts)-2:], "/")
	return p, projectfile.ValidateOrgRepo(p)
}

func validateEnvName(env string) error {
	for _, s := range strings.Split(env, ".") {
		if s == "" {
			return fmt.Errorf("empty environment segment")
		}
		for _, r := range s {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') {
				return fmt.Errorf("invalid environment %q: use dot-separated lowercase letters and digits", env)
			}
		}
	}
	return nil
}

// EnvCmd manages human-named environments.
type EnvCmd struct {
	Add  EnvAddCmd  `cmd:"" help:"Create an environment key."`
	List EnvListCmd `cmd:"" help:"List environment public keys."`
}

// EnvAddCmd stores a new key and prints only its public half.
type EnvAddCmd struct {
	Env     string `arg:"" help:"Environment name"`
	Project string `help:"Project id"`
}

// Run stores a new key pair atomically.
func (c *EnvAddCmd) Run(ctx *cliCtx) error {
	if err := validateEnvName(c.Env); err != nil {
		return err
	}
	project, err := resolveProject(c.Project)
	if err != nil {
		return err
	}
	ks := keystore.New()
	entries, err := readOrNew(ks, project)
	if err != nil {
		return err
	}
	name := environmentKey(c.Env)
	if _, ok := entries[name]; ok {
		return fmt.Errorf("environment %s already exists", c.Env)
	}
	pub, priv, err := esec.GenerateKeypair()
	if err != nil {
		return err
	}
	entries[name] = priv
	entries[esec.EsecPrivateKey+"_"+strings.ToUpper(pub)] = priv
	if err := ks.Write(project, entries, true); err != nil {
		return err
	}
	markDirty("env add")
	fmt.Printf("ESEC_PUBLIC_KEY=%s\n", pub)
	return nil
}

// EnvListCmd lists public metadata.
type EnvListCmd struct {
	Project string `help:"Project id"`
}

// Run prints environment names and their public keys.
func (c *EnvListCmd) Run(ctx *cliCtx) error {
	project, err := resolveProject(c.Project)
	if err != nil {
		return err
	}
	entries, err := keystore.New().Read(project)
	if err != nil {
		return err
	}
	var names []string
	for k := range entries {
		if rest, ok := strings.CutPrefix(k, esec.EsecPrivateKey+"_"); ok && (len(rest) != 64 || !isHex(rest)) {
			names = append(names, k)
		}
	}
	sort.Strings(names)
	for _, name := range names {
		pub, err := publicHex(entries[name])
		if err != nil {
			return err
		}
		env := strings.ToLower(strings.ReplaceAll(strings.TrimPrefix(name, esec.EsecPrivateKey+"_"), "_", "."))
		fmt.Printf("%s %s\n", env, pub)
	}
	return nil
}

func environmentKey(env string) string {
	return esec.EsecPrivateKey + "_" + strings.ToUpper(strings.ReplaceAll(env, ".", "_"))
}
func publicHex(priv string) (string, error) {
	raw, err := hex.DecodeString(priv)
	if err != nil || len(raw) != 32 {
		return "", fmt.Errorf("invalid stored private key")
	}
	var key [32]byte
	copy(key[:], raw)
	pub, err := crypto.PublicFromPrivate(key)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(pub[:]), nil
}

func resolveProject(explicit string) (string, error) {
	if explicit != "" {
		return explicit, projectfile.ValidateOrgRepo(explicit)
	}
	cwd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	p, _, err := projectfile.FindProjectFile(cwd)
	return p, err
}
func ensureGitignoreEntry(dir, entry string) error {
	p := filepath.Join(dir, ".gitignore")
	data, err := os.ReadFile(p) //nolint:gosec // user-selected project directory
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(line) == entry {
			return nil
		}
	}
	if len(data) > 0 && data[len(data)-1] != '\n' {
		data = append(data, '\n')
	}
	return storage.Write(p, append(data, []byte(entry+"\n")...))
}
func isHex(s string) bool { _, err := hex.DecodeString(s); return err == nil }
