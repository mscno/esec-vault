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
	"github.com/mscno/esec-vault/internal/seal"
	"github.com/mscno/esec-vault/internal/storage"
	"github.com/mscno/esec/pkg/config"
	"github.com/mscno/esec/pkg/crypto"
	"github.com/mscno/esec/pkg/fileutils"
	"github.com/mscno/esec/pkg/projectfile"
	coreseal "github.com/mscno/esec/pkg/seal"
)

// ProjectCmd scaffolds projects.
type ProjectCmd struct {
	Init     ProjectInitCmd     `cmd:"" help:"Create project marker, environment keys and secrets templates."`
	Transfer ProjectTransferCmd `cmd:"" help:"Transfer a project to a tenant you own, or request another owner's acceptance."`
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
	JSON     bool     `help:"Print what was set up as JSON (the project, its environments and keys, files created, next steps), for scripts and agents"`

	ctx     *cliCtx
	created []string
}

// initResult is project init's JSON.
type initResult struct {
	Project string `json:"project"`
	Dir     string `json:"dir"`
	// IDFrom says where the project id came from: argument, flag or git.
	IDFrom string    `json:"id_from"`
	Format string    `json:"format"`
	Envs   []initEnv `json:"envs"`
	// Created are the secrets files this run wrote; those that existed are
	// kept as they were.
	Created []string `json:"created"`
	Next    []string `json:"next"`
}

type initEnv struct {
	Name  string `json:"name"`
	Key   string `json:"public_key"`
	Guard string `json:"guard"`
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
	source, from := "Git origin", "git"
	if c.Project != "" {
		source, from = "--project flag", "flag"
	} else if c.ID != "" {
		source, from = "project ID argument", "argument"
	}
	next := c.nextSteps()
	if c.JSON {
		return c.printJSON(project, dir, from, next)
	}
	fmt.Fprintf(os.Stderr, "Project %s ready in %s (project ID from %s). Keys stored outside the repository.\n", project, dir, source)
	if !ctx.Quiet {
		fmt.Fprintln(os.Stderr, "Next:")
		for _, s := range next {
			fmt.Fprintln(os.Stderr, "  "+s)
		}
	}
	return nil
}

func (c *ProjectInitCmd) printJSON(project, dir, from string, next []string) error {
	pf, err := projectfile.Load(dir)
	if err != nil {
		return err
	}
	res := initResult{Project: project, Dir: dir, IDFrom: from, Format: pf.FilesFormat(), Envs: []initEnv{}, Created: []string{}, Next: next}
	for _, env := range c.Env {
		e := pf.Env[env]
		res.Envs = append(res.Envs, initEnv{Name: env, Key: e.Key, Guard: e.GuardLevel()})
	}
	for _, f := range c.created {
		res.Created = append(res.Created, relTo(dir, f))
	}
	sort.Strings(res.Created)
	return printJSON(res)
}

// nextSteps says what to do now. Running init again is safe: it keeps
// existing keys and files.
func (c *ProjectInitCmd) nextSteps() []string {
	env := c.Env[0]
	steps := []string{
		"git add esec.toml and the secrets files (they hold no secret in the clear)",
		"esec vault secrets set NAME --env " + env + " --create   # add a value (--generate makes one)",
		"esec vault run " + env + " -- COMMAND                      # run with the values",
	}
	if path, err := preCommitPath(c.Dir); err == nil {
		if data, err := os.ReadFile(path); err != nil || !strings.Contains(string(data), hookBegin) { //nolint:gosec // the repository's own hook
			steps = append(steps, "esec vault hook install                           # refuse commits with secrets in the clear")
		}
	}
	if slices.Contains(c.Env, "prod") && !slices.Contains(c.Guard, "prod") {
		if st, err := readGuardStatus(); err == nil && st.SetUp {
			steps = append(steps, "esec vault guard enable --env prod                 # every prod read needs your touch")
		}
	}
	return steps
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

// freshKey is a key project init made, to seal.
type freshKey struct{ env, priv, level string }

func (c *ProjectInitCmd) create(project string) error { //nolint:gocyclo // keys, files, seals, in order
	format, err := creationFormat(c.Dir, c.Format)
	if err != nil {
		return err
	}
	if _, err := templateContent(format, "", ""); err != nil {
		return err
	}
	for _, env := range c.Guard {
		if !slices.Contains(c.Env, env) {
			return fmt.Errorf("--guard %s: not one of --env", env)
		}
	}
	s, err := newSealing(c.ctx)
	if err != nil {
		return err
	}
	pf, err := projectfile.Load(c.Dir)
	if errors.Is(err, projectfile.ErrNotFound) {
		pf, err = &projectfile.File{}, nil
	}
	if err != nil {
		return err
	}
	if pf.Project != project {
		// Another project's keys do not belong to this one.
		pf.Env = nil
	}
	pf.Project = project
	if pf.FilesFormat() == "" {
		pf.Files.Format = strings.TrimPrefix(format, ".")
	}
	fresh, files, err := prepareEnvironments(c, s, pf, format)
	if err != nil {
		return err
	}
	for _, k := range fresh {
		if seal.Guarded(k.level) {
			if keys, err := mySecurityKeys(s.bg(), s.acct); err != nil || len(keys) == 0 {
				return fmt.Errorf("--guard %s: you have no security key yet to seal it to: plug in your YubiKey and run esec vault security-keys add (nothing was written)", k.env)
			}
		}
	}
	if err := os.MkdirAll(c.Dir, 0o750); err != nil {
		return err
	}
	for _, k := range fresh {
		if err := s.seal(c.Dir, pf, k.env, k.priv, k.level, nil); err != nil {
			return err
		}
		if !seal.Guarded(k.level) {
			if err := s.cache(project, k.env, k.priv); err != nil {
				return err
			}
		}
	}
	if err := pf.Save(c.Dir); err != nil {
		return err
	}
	markDirty("project init")
	for file, content := range files {
		if err := writeNewTemplate(file, []byte(content)); err != nil {
			return err
		}
		c.created = append(c.created, file)
	}
	return ensureGitignoreEntry(c.Dir, esec.DefaultKeyringFilename)
}

// prepareEnvironments works out each environment's key: the one sealed
// already (running init again changes nothing), one this device holds from
// before, or a new one. It returns the keys to seal and the secrets files to
// create.
func prepareEnvironments(c *ProjectInitCmd, s *sealing, pf *projectfile.File, format string) ([]freshKey, map[string]string, error) {
	files := map[string]string{}
	var fresh []freshKey
	cfg, err := config.LoadDir(c.Dir)
	if err != nil {
		return nil, nil, err
	}
	for _, env := range c.Env {
		if err := validateEnvName(env); err != nil {
			return nil, nil, err
		}
		pub := pf.Env[env].Key
		if _, serr := coreseal.Read(c.Dir, env); pub == "" || serr != nil {
			level := projectfile.GuardNone
			if slices.Contains(c.Guard, env) {
				level = projectfile.GuardTouch
			}
			priv, ok := s.cached(pf.Project, env, pub)
			if !ok {
				var err error
				if _, priv, err = esec.GenerateKeypair(); err != nil {
					return nil, nil, err
				}
			}
			if pub, err = publicHex(priv); err != nil {
				return nil, nil, err
			}
			fresh = append(fresh, freshKey{env: env, priv: priv, level: level})
		}
		filename, err := config.Expand(cfg.Files.Create, env, format)
		if err != nil {
			return nil, nil, err
		}
		file := filepath.Join(c.Dir, filename)
		if !c.Template {
			continue
		}
		if existing, _, err := fileutils.Resolve(c.Dir, env, format); err == nil {
			file = existing
		} else if !errors.Is(err, fileutils.ErrNotFound) {
			return nil, nil, err
		}
		data, readErr := os.ReadFile(file) //nolint:gosec // user-selected project directory and validated environment
		switch {
		case readErr == nil:
			p, err := esec.ExtractPublicKey(data, esec.FileFormat(format))
			if err != nil || hex.EncodeToString(p[:]) != pub {
				return nil, nil, fmt.Errorf("existing %s is not encrypted to %s's key: rotate it (esec vault env rotate %s), or move it aside", file, env, env)
			}
		case !errors.Is(readErr, os.ErrNotExist):
			return nil, nil, readErr
		default:
			_, content, err := secretsTemplate(c.Dir, format, env, pub)
			if err != nil {
				return nil, nil, err
			}
			files[file] = string(content)
		}
	}
	return fresh, files, nil
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
	Rename        EnvRenameCmd        `cmd:"" help:"Rename an environment and matching files, preserving its key, readers and guard."`
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
	Project  string `help:"Project id (default: the checkout here)"`
	Format   string `short:"f" help:"Template format (default: esec config)"`
	Dir      string `type:"path" help:"Secrets directory (default: project marker directory)"`
	Template bool   `default:"true" negatable:"" help:"Create an encrypted secrets file from an example or empty template"`
	Guard    string `enum:"none,touch,session" default:"none" help:"Guard the new key: touch (every read needs a touch) or session"`
}

// Run makes a key, seals it for the project's readers, and creates the
// environment's secrets file.
func (c *EnvAddCmd) Run(ctx *cliCtx) error {
	if err := validateEnvName(c.Env); err != nil {
		return err
	}
	root, pf, err := checkoutFor(c.Project)
	if c.Dir != "" {
		// The secrets directory is in the project's checkout.
		if dpf, droot, derr := projectRoot(c.Dir); derr == nil && (c.Project == "" || dpf.Project == c.Project) {
			root, pf, err = droot, dpf, nil
		}
	}
	if err != nil {
		return err
	}
	project := pf.Project
	if pf.Env[c.Env].Key != "" {
		return fmt.Errorf("environment %s already exists", c.Env)
	}
	s, err := newSealing(ctx)
	if err != nil {
		return err
	}
	pub, priv, err := esec.GenerateKeypair()
	if err != nil {
		return err
	}
	if c.Dir == "" {
		c.Dir = root
	}
	file, content, err := c.prepareTemplate(project, pub)
	if err != nil {
		return err
	}
	if err := s.seal(root, pf, c.Env, priv, c.Guard, projectReaders(pf)); err != nil {
		return err
	}
	if !seal.Guarded(c.Guard) {
		if err := s.cache(project, c.Env, priv); err != nil {
			return err
		}
	}
	markDirty("env add")
	if file != "" {
		if err := writeNewTemplate(file, content); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "Created encrypted secrets file %s\n", file)
	}
	fmt.Printf("ESEC_PUBLIC_KEY=%s\n", pub)
	if shared, err := sharedProject(ctx, project); err != nil {
		fmt.Fprintln(os.Stderr, "! "+err.Error())
	} else if shared {
		publishShared(ctx, project, c.Env, "added")
	}
	return nil
}

// projectReaders are everyone who reads one of the project's environments:
// a new environment is shared with them too.
func projectReaders(pf *projectfile.File) []seal.Reader {
	var all []string
	for _, env := range pf.Envs() {
		all = append(all, pf.Env[env].Readers...)
	}
	readers, err := seal.ParseReaders(all)
	if err != nil {
		return nil
	}
	return readers
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
