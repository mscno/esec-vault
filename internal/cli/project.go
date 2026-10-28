package cli

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/mscno/esec"
	"github.com/mscno/esec-vault/internal/keystore"
	"github.com/mscno/esec-vault/internal/safetext"
	"github.com/mscno/esec-vault/internal/storage"
	"github.com/mscno/esec/pkg/config"
	"github.com/mscno/esec/pkg/crypto"
	"github.com/mscno/esec/pkg/fileutils"
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
	Format   string   `short:"f" default:"" help:"env, ejson, eyaml, eyml or etoml"`
	Template bool     `default:"true" negatable:"" help:"Create secrets templates"`
	Force    bool     `help:"Replace a different existing project id in esec.toml"`
	Guard    []string `name:"guard" sep:"," help:"Environments whose keys are born guarded (every read needs a touch), such as prod"`
	Offline  bool     `help:"Do not wait for the new keys to reach the vault server or backup before writing files"`

	ctx *cliCtx
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
	dir, err := filepath.Abs(c.Dir)
	if err != nil {
		return err
	}
	c.ctx = ctx
	if err := c.create(project); err != nil {
		return err
	}
	registerCheckout(dir)
	source := "Git origin"
	if c.Project != "" {
		source = "--project flag"
	} else if c.ID != "" {
		source = "project ID argument"
	}
	fmt.Fprintf(os.Stderr, "Project %s ready in %s (project ID from %s). Keys stored outside the repository.\n", project, dir, source)
	c.nextSteps()
	return nil
}

// nextSteps says what to do now. Running init again is safe: it keeps
// existing keys and files.
func (c *ProjectInitCmd) nextSteps() {
	if c.ctx != nil && c.ctx.Quiet {
		return
	}
	env := c.Env[0]
	steps := []string{
		"git add esec.toml and the secrets files (they hold no secret in the clear)",
		"esec vault secrets set NAME --env " + env + " --create   # add a value (--generate makes one)",
		"esec vault run " + env + " -- COMMAND                      # run with the values",
	}
	if slices.Contains(c.Env, "prod") && !slices.Contains(c.Guard, "prod") {
		if st, err := readGuardStatus(); err == nil && st.SetUp {
			steps = append(steps, "esec vault guard enable --env prod                 # every prod read needs your touch")
		}
	}
	fmt.Fprintln(os.Stderr, "Next:")
	for _, s := range steps {
		fmt.Fprintln(os.Stderr, "  "+s)
	}
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
	format, err := creationFormat(c.Dir, c.Format)
	if err != nil {
		return err
	}
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
	if err := c.guardNew(project, entries); err != nil {
		return err
	}
	if err := ks.WriteGuarded(project, entries); err != nil {
		return err
	}
	markDirty("project init")
	if err := requireStored(c.ctx, c.Offline, "project init"); err != nil {
		return err
	}
	if err := os.MkdirAll(c.Dir, 0750); err != nil {
		return err
	}
	if err := c.writeProjectFile(project, format, entries); err != nil {
		return err
	}
	for file, content := range files {
		if err := writeNewTemplate(file, []byte(content)); err != nil {
			return err
		}
	}
	if err := ensureGitignoreEntry(c.Dir, esec.DefaultKeyringFilename); err != nil {
		return err
	}
	return nil
}

// writeProjectFile records the project, its file format and each
// environment's public key in esec.toml, keeping what else it says.
func (c *ProjectInitCmd) writeProjectFile(project, format string, entries map[string]string) error {
	f, err := projectfile.Load(c.Dir)
	if errors.Is(err, projectfile.ErrNotFound) {
		f, err = &projectfile.File{}, nil
	}
	if err != nil {
		return err
	}
	if f.Project != project {
		// Another project's keys do not belong to this one.
		f.Env = nil
	}
	f.Project = project
	if f.FilesFormat() == "" {
		f.Files.Format = strings.TrimPrefix(format, ".")
	}
	for _, env := range c.Env {
		pub, level := envPublic(entries, env)
		if pub == "" {
			continue
		}
		f.SetEnv(env, pub)
		if e := f.Env[env]; level != projectfile.GuardNone && e.Guard == "" {
			e.Guard = level
			f.Env[env] = e
		}
	}
	return f.Save(c.Dir)
}

// guardNew guards the keys of the --guard environments: they are wrapped
// before the keyring is written, so they never exist in the clear on disk.
func (c *ProjectInitCmd) guardNew(project string, entries map[string]string) error {
	if len(c.Guard) == 0 {
		return nil
	}
	var todo []string
	for _, env := range c.Guard {
		if !slices.Contains(c.Env, env) {
			return fmt.Errorf("--guard %s: not one of --env", env)
		}
		if entries[keystore.GuardEnvEntry(env)] == "" {
			todo = append(todo, env)
		}
	}
	if len(todo) == 0 {
		return nil
	}
	id, err := openGuard(fmt.Sprintf("Create guarded keys for %s: %s", project, strings.Join(todo, ", ")))
	if err != nil {
		return err
	}
	for _, env := range todo {
		if _, err := guardEnv(entries, id, project, env, projectfile.GuardTouch); err != nil {
			return err
		}
	}
	return nil
}

// envPublic returns an environment's public key and guard level from
// keyring entries, "" when it has no key.
func envPublic(entries map[string]string, env string) (pub, level string) {
	if p := entries[keystore.GuardEnvEntry(env)]; p != "" {
		// The level is inside the encryption; esec.toml records it.
		return strings.ToLower(p), projectfile.GuardTouch
	}
	if priv, ok := entries[environmentKey(env)]; ok {
		if pub, err := publicHex(priv); err == nil {
			return pub, projectfile.GuardNone
		}
	}
	return "", ""
}

func prepareEnvironments(c *ProjectInitCmd, format string, entries map[string]string) (map[string]string, error) {
	files := map[string]string{}
	cfg, err := config.LoadDir(c.Dir)
	if err != nil {
		return nil, err
	}
	for _, env := range c.Env {
		if err := validateEnvName(env); err != nil {
			return nil, err
		}
		name := environmentKey(env)
		// A guarded environment keeps its key: never make a clear one
		// beside it.
		guardedPub := strings.ToLower(entries[keystore.GuardEnvEntry(env)])
		priv, exists := entries[name]
		var pub string
		var err error
		switch {
		case guardedPub != "":
			pub = guardedPub
		case exists:
			pub, err = publicHex(priv)
		default:
			pub, priv, err = esec.GenerateKeypair()
		}
		if err != nil {
			return nil, err
		}
		filename, err := config.Expand(cfg.Files.Create, env, format)
		if err != nil {
			return nil, err
		}
		file := filepath.Join(c.Dir, filename)
		if c.Template {
			if existing, _, err := fileutils.Resolve(c.Dir, env, format); err == nil {
				file = existing
			} else if !errors.Is(err, fileutils.ErrNotFound) {
				return nil, err
			}
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
				_, content, err := secretsTemplate(c.Dir, format, env, pub)
				if err != nil {
					return nil, err
				}
				files[file] = string(content)
			}
		}
		if guardedPub == "" {
			entries[name] = priv
			entries[esec.EsecPrivateKey+"_"+strings.ToUpper(pub)] = priv
		}
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
		var exit *exec.ExitError
		if errors.As(err, &exit) && exit.ExitCode() == 1 {
			return "", fmt.Errorf("cannot infer project: Git origin is missing or unset in %s; pass --project org/repo: %w", dir, err)
		}
		return "", fmt.Errorf("pass --project org/repo: %w", err)
	}
	raw := strings.TrimSpace(out)
	if raw == "" {
		return "", fmt.Errorf("cannot infer project: Git origin is empty in %s; pass --project org/repo", dir)
	}
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
	Add           EnvAddCmd           `cmd:"" help:"Create an environment key and encrypted secrets template."`
	List          EnvListCmd          `cmd:"" help:"List environment public keys."`
	ShowKey       EnvShowKeyCmd       `cmd:"" help:"Print an environment private key after confirmation."`
	Rotate        EnvRotateCmd        `cmd:"" help:"Replace an environment key and re-encrypt its files."`
	RotateExposed EnvRotateExposedCmd `cmd:"" name:"rotate-exposed" help:"Rotate, across checkouts, every environment whose key someone who left may hold."`
	Status        EnvStatusCmd        `cmd:"" help:"What of an environment picked up its key or a change: people, machines, workloads."`
}

// EnvShowKeyCmd reveals one named environment's private key after confirmation.
type EnvShowKeyCmd struct {
	Env     string `arg:"" help:"Environment name"`
	Project string `help:"Project id (default: nearest esec.toml)"`
}

// Run requires explicit confirmation before writing the private key to stdout.
func (c *EnvShowKeyCmd) Run(ctx *cliCtx) error {
	if err := validateEnvName(c.Env); err != nil {
		return err
	}
	project, err := resolveProject(c.Project)
	if err != nil {
		return err
	}
	entries, err := keystore.New().Read(project)
	if err != nil {
		return err
	}
	priv, ok := entries[environmentKey(c.Env)]
	if !ok {
		return fmt.Errorf("environment %s has no stored private key in project %s", c.Env, project)
	}
	if _, err := publicHex(priv); err != nil {
		return err
	}
	if !confirm(fmt.Sprintf("Print the private key for %s environment %s to the console?", project, c.Env)) {
		return fmt.Errorf("private key display cancelled")
	}
	_, err = fmt.Fprintln(os.Stdout, priv)
	return err
}

// EnvAddCmd stores a new key and prints only its public half.
type EnvAddCmd struct {
	Env      string `arg:"" help:"Environment name"`
	Project  string `help:"Project id"`
	Format   string `short:"f" help:"Template format (default: esec config)"`
	Dir      string `type:"path" help:"Secrets directory (default: project marker directory)"`
	Template bool   `default:"true" negatable:"" help:"Create an encrypted secrets file from an example or empty template"`
	Guard    string `enum:"none,touch,session" default:"none" help:"Guard the new key: touch (every read needs a touch) or session"`
	Offline  bool   `help:"Do not wait for the new key to reach the vault server or backup before writing its file"`
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
	file, content, err := c.prepareTemplate(project, pub)
	if err != nil {
		return err
	}
	if entries[keystore.GuardEnvEntry(c.Env)] != "" {
		return fmt.Errorf("environment %s already exists (guarded)", c.Env)
	}
	entries[name] = priv
	entries[keystore.PubEntry(pub)] = priv
	if c.Guard != "" && c.Guard != projectfile.GuardNone {
		id, err := openGuard(fmt.Sprintf("Create a guarded %s key for %s", c.Env, project))
		if err != nil {
			return err
		}
		if _, err := guardEnv(entries, id, project, c.Env, c.Guard); err != nil {
			return err
		}
	}
	if err := ks.WriteGuarded(project, entries); err != nil {
		return err
	}
	markDirty("env add")
	if err := requireStored(ctx, c.Offline, "env add"); err != nil {
		return err
	}
	if file != "" {
		if err := writeNewTemplate(file, content); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "Created encrypted secrets file %s\n", file)
	}
	c.recordEnv(project, pub)
	fmt.Printf("ESEC_PUBLIC_KEY=%s\n", pub)
	if shared, err := sharedProject(ctx, project); err != nil {
		fmt.Fprintln(os.Stderr, "! "+err.Error())
	} else if shared {
		publishShared(ctx, project, c.Env, "added")
	}
	return nil
}

// recordEnv adds the environment to the project's esec.toml, when the
// command runs in the project.
func (c *EnvAddCmd) recordEnv(project, pub string) {
	cwd, err := os.Getwd()
	if err != nil {
		return
	}
	f, path, err := projectfile.Find(cwd)
	if err != nil || f.Project != project {
		return
	}
	f.SetEnv(c.Env, pub)
	if c.Guard != "" && c.Guard != projectfile.GuardNone {
		e := f.Env[c.Env]
		e.Guard = c.Guard
		f.Env[c.Env] = e
	}
	if err := f.Save(filepath.Dir(path)); err != nil {
		fmt.Fprintln(os.Stderr, "! esec.toml: "+err.Error())
	}
}

// EnvListCmd lists public metadata.
type EnvListCmd struct {
	Project string `help:"Project id (default: nearest esec.toml)"`
	JSON    bool   `help:"Print JSON, for scripts and agents"`
}

// Run prints environment names and their public keys.
func (c *EnvListCmd) Run(ctx *cliCtx) error {
	project, err := resolveProject(c.Project)
	if err != nil {
		return err
	}
	entries, err := keystore.New().Read(project)
	if errors.Is(err, fs.ErrNotExist) {
		entries, err = nil, nil
	}
	if err != nil {
		return err
	}
	type envKey struct {
		Env       string `json:"env"`
		PublicKey string `json:"public_key"`
		Guarded   bool   `json:"guarded,omitempty"`
	}
	out := []envKey{}
	for k, v := range entries {
		env, ok := keystore.EnvName(k)
		if !ok {
			continue
		}
		if strings.HasPrefix(k, "ESEC_GUARD_ENV_") {
			out = append(out, envKey{env, strings.ToLower(v), true})
			continue
		}
		pub, err := publicHex(v)
		if err != nil {
			return err
		}
		out = append(out, envKey{Env: env, PublicKey: pub})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Env < out[j].Env })
	if c.JSON {
		return printJSON(out)
	}
	if len(out) == 0 {
		fmt.Fprintf(os.Stderr, "No environment keys for %s on this machine. Add one with: esec vault env add dev\n", project)
	}
	for _, e := range out {
		guarded := ""
		if e.Guarded {
			guarded = " (guarded)"
		}
		fmt.Printf("%s %s%s\n", e.Env, e.PublicKey, guarded)
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
	f, path, err := projectfile.Find(cwd)
	if err != nil {
		return "", err
	}
	if u := f.Unknown(); len(u) > 0 {
		fmt.Fprintf(os.Stderr, "! esec.toml: ignoring %s (from a newer esec, or a typo)\n", safetext.Clean(strings.Join(u, ", ")))
	}
	registerCheckout(filepath.Dir(path))
	return f.Project, nil
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
