package cli

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/mscno/esec/pkg/fileutils"
	"github.com/mscno/esec/pkg/projectfile"

	"github.com/mscno/esec-vault/internal/account"
	"github.com/mscno/esec-vault/internal/caller"
	"github.com/mscno/esec-vault/internal/envrotate"
	"github.com/mscno/esec-vault/internal/keystore"
	"github.com/mscno/esec-vault/internal/notify"
	"github.com/mscno/esec-vault/internal/safetext"
	"github.com/mscno/esec-vault/internal/secretfile"
	"github.com/mscno/esec-vault/internal/storage"
)

// SecretsCmd finds, changes and checks the values in secrets files.
type SecretsCmd struct {
	List    SecretsListCmd    `cmd:"" default:"withargs" help:"List the secrets files under a directory: environment, project, keys, values in the clear (default)."`
	Where   SecretsWhereCmd   `cmd:"" help:"Find every secrets file that holds a key, across repositories."`
	Set     SecretsSetCmd     `cmd:"" help:"Set one value in a project's secrets files, encrypted, leaving the others as they are."`
	Request SecretsRequestCmd `cmd:"" help:"Ask a person for a value in a desktop dialog and encrypt it in: the agent that asks never sees it."`
	Rotate  SecretsRotateCmd  `cmd:"" help:"Give a credential a new value everywhere it is used, across repositories."`
	Lint    SecretsLintCmd    `cmd:"" help:"Check secrets files: no value in the clear, each encrypted to its environment's current key."`
}

// secretsRoot returns where to look: --root, else the current project's
// directory, else the current directory.
func secretsRoot(root string) (string, error) {
	if root != "" {
		return filepath.Abs(root)
	}
	cwd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	if _, marker, err := projectfile.FindProjectFile(cwd); err == nil {
		return filepath.Dir(marker), nil
	}
	return cwd, nil
}

func relTo(root, path string) string {
	if r, err := filepath.Rel(root, path); err == nil {
		return r
	}
	return path
}

// SecretsListCmd lists secrets files.
type SecretsListCmd struct {
	Root string `type:"path" help:"Where to look (default: the current repository): a directory of checkouts finds them all"`
	JSON bool   `help:"Print JSON, for scripts and agents"`
}

// Run implements secrets list.
func (c *SecretsListCmd) Run(_ *cliCtx) error {
	root, err := secretsRoot(c.Root)
	if err != nil {
		return err
	}
	files, err := secretfile.Scan(root)
	if err != nil {
		return err
	}
	if c.JSON {
		return printJSON(nonNil(files))
	}
	if len(files) == 0 {
		fmt.Println("No secrets files under " + root)
		return nil
	}
	for _, f := range files {
		env := f.Env
		if env == "" {
			env = "(default)"
		}
		extra := ""
		if len(f.Plain) > 0 {
			extra = "  ! in the clear: " + strings.Join(f.Plain, ", ")
		}
		fmt.Printf("%-40s %-12s %-24s %d key(s)%s\n", safetext.Clean(relTo(root, f.Path)), safetext.Clean(env), safetext.Clean(f.Project), len(f.Keys), safetext.Clean(extra))
	}
	return nil
}

// SecretsWhereCmd finds a key.
type SecretsWhereCmd struct {
	Key  string `arg:"" help:"The key, such as DATABASE_URL (nested keys with dots: db.password)"`
	Env  string `help:"Only this environment"`
	Root string `type:"path" help:"Where to look (default: the current repository), such as ~/src for every checkout"`
	JSON bool   `help:"Print JSON, for scripts and agents"`
}

// Run implements secrets where.
func (c *SecretsWhereCmd) Run(_ *cliCtx) error {
	root, err := secretsRoot(c.Root)
	if err != nil {
		return err
	}
	files, err := holding(root, c.Key, c.Env, false)
	if err != nil {
		return err
	}
	if c.JSON {
		return printJSON(nonNil(files))
	}
	if len(files) == 0 {
		fmt.Printf("No secrets file under %s holds %s.\n", root, c.Key)
		return nil
	}
	for _, f := range files {
		fmt.Printf("%-24s %-12s %s\n", safetext.Clean(f.Project), safetext.Clean(f.Env), safetext.Clean(relTo(root, f.Path)))
	}
	return nil
}

// holding lists the files under root that hold key (of env, when given).
// With exactEnv, env "" means the default environment only.
func holding(root, key, env string, exactEnv bool) ([]secretfile.File, error) {
	files, err := secretfile.Scan(root)
	if err != nil {
		return nil, err
	}
	var out []secretfile.File
	for _, f := range files {
		if (env != "" || exactEnv) && f.Env != env {
			continue
		}
		if f.Has(key) {
			out = append(out, f)
		}
	}
	return out, nil
}

// newValue reads a credential's new value: generated, or typed (twice on a
// terminal, never shown), or one line of stdin.
func newValue(key string, generate int) (string, error) {
	if generate > 0 {
		if generate < 16 || generate > 256 {
			return "", errors.New("--generate takes 16 to 256 bytes")
		}
		b := make([]byte, generate)
		if _, err := rand.Read(b); err != nil {
			return "", err
		}
		return base64.RawURLEncoding.EncodeToString(b), nil
	}
	v, err := promptSecret("New value for " + key + " (not shown): ")
	if err != nil {
		return "", err
	}
	if v == "" {
		return "", errors.New("no value given; nothing changed")
	}
	if stdinIsTerminal() {
		again, err := promptSecret("Again: ")
		if err != nil {
			return "", err
		}
		if again != v {
			return "", errors.New("the two values differ; nothing changed")
		}
	}
	return v, nil
}

// setIn sets key in each file, checks each against its private key where
// this device has it, and writes them only when all succeeded.
func setIn(files []secretfile.File, key, value string, create bool) ([]string, error) {
	type staged struct {
		path string
		data []byte
	}
	var out []staged
	var notes []string
	ks := keystore.New()
	for _, f := range files {
		data, err := os.ReadFile(f.Path)
		if err != nil {
			return nil, err
		}
		next, err := secretfile.Set(data, fileutils.FileFormat(f.Format), key, value, create)
		if err != nil {
			return nil, fmt.Errorf("%s: %w (nothing was changed)", f.Path, err)
		}
		// Where this device has the environment's key, read the value back.
		if f.Project != "" {
			if entries, err := ks.Read(f.Project); err == nil {
				if priv, ok := entries[envrotate.EnvKey(f.Env)]; ok && f.Env != "" {
					got, err := secretfile.Check(next, fileutils.FileFormat(f.Format), key, priv)
					if err != nil || got != value {
						return nil, fmt.Errorf("%s: the new value does not read back with this device's %s key (nothing was changed)", f.Path, f.Env)
					}
					notes = append(notes, f.Path+": checked with this device's "+f.Env+" key")
				}
			}
		}
		out = append(out, staged{f.Path, next})
	}
	for _, s := range out {
		if err := storage.WriteKeepMode(s.path, s.data); err != nil {
			return notes, err
		}
	}
	return notes, nil
}

// SecretsSetCmd sets one value.
type SecretsSetCmd struct {
	Key      string `arg:"" help:"The key, such as DATABASE_URL (nested keys with dots: db.password)"`
	Env      string `help:"The environment, such as prod (with --file: taken from its name)"`
	File     string `type:"existingfile" help:"The secrets file (default: the project's files of --env that hold the key)"`
	Create   bool   `help:"Add the key where it is missing (dotenv and YAML files)"`
	Generate int    `help:"Generate a random value of this many bytes (base64url) instead of reading one"`

	// ask, when set, gets the value instead of the terminal (secrets request).
	ask func() (string, error)
}

// Run implements secrets set.
func (c *SecretsSetCmd) Run(_ *cliCtx) error { //nolint:gocyclo // which files, the value, then writing
	var files []secretfile.File
	if c.File != "" {
		f, err := secretfile.Read(c.File)
		if err != nil {
			return err
		}
		if c.Env != "" && f.Env != c.Env {
			return fmt.Errorf("%s is the %q environment's file, not %s", c.File, f.Env, c.Env)
		}
		if !f.Has(c.Key) && !c.Create {
			return fmt.Errorf("%s has no %s (add it with --create)", c.File, c.Key)
		}
		files = []secretfile.File{*f}
	} else {
		if c.Env == "" {
			return errors.New("say which environment with --env (or name the file with --file)")
		}
		root, err := secretsRoot("")
		if err != nil {
			return err
		}
		all, err := secretfile.Scan(root)
		if err != nil {
			return err
		}
		var ofEnv []secretfile.File
		for _, f := range all {
			if f.Env == c.Env {
				ofEnv = append(ofEnv, f)
				if f.Has(c.Key) {
					files = append(files, f)
				}
			}
		}
		if len(files) == 0 {
			switch {
			case len(ofEnv) == 0:
				return fmt.Errorf("no secrets file of %s under %s", c.Env, root)
			case !c.Create:
				return fmt.Errorf("no %s file holds %s; add it with --create", c.Env, c.Key)
			case len(ofEnv) > 1:
				return fmt.Errorf("several %s files: name one with --file", c.Env)
			}
			files = ofEnv
		}
	}
	var value string
	var err error
	if c.ask != nil {
		value, err = c.ask()
	} else {
		value, err = newValue(c.Key, c.Generate)
	}
	if err != nil {
		return err
	}
	notes, err := setIn(files, c.Key, value, c.Create)
	if err != nil {
		return err
	}
	for _, f := range files {
		fmt.Printf("✓ Set %s in %s (encrypted; the other values are as they were).\n", c.Key, safetext.Clean(f.Path))
	}
	for _, n := range notes {
		fmt.Println("  " + safetext.Clean(n))
	}
	printRolloutSteps(files)
	return nil
}

// SecretsRequestCmd asks a person for a value in a desktop dialog and
// encrypts it into the secrets files: the program that asked, such as an
// agent, never sees it.
type SecretsRequestCmd struct {
	Key    string `arg:"" help:"The key, such as STRIPE_KEY"`
	Env    string `help:"The environment, such as prod (with --file: taken from its name)"`
	File   string `type:"existingfile" help:"The secrets file (default: the project's files of --env that hold the key)"`
	Create bool   `help:"Add the key where it is missing (dotenv and YAML files)"`
	Reason string `help:"Why the value is needed, shown in the dialog"`
}

// requestDialog is the dialog secrets request shows; tests replace it.
var requestDialog = func(title, prompt string) (string, bool, error) {
	return notify.Secret(title, prompt, 10*time.Minute)
}

// Run implements secrets request.
func (c *SecretsRequestCmd) Run(ctx *cliCtx) error {
	where := c.Env
	if c.File != "" {
		where = c.File
	}
	project := "this project"
	if p, err := resolveProject(""); err == nil {
		project = p
	}
	prompt := fmt.Sprintf("Paste the value of %s for %s %s.\n\nAsked by: %s", c.Key, project, where, caller.Describe(caller.Chain(os.Getpid())))
	if c.Reason != "" {
		prompt += "\nReason: " + c.Reason
	}
	prompt += "\n\nIt is encrypted into the secrets file; the program that asked never sees it."
	set := &SecretsSetCmd{Key: c.Key, Env: c.Env, File: c.File, Create: c.Create, ask: func() (string, error) {
		v, ok, err := requestDialog("esec: a secret value is requested", prompt)
		switch {
		case errors.Is(err, notify.ErrNoDialogs):
			return "", errors.New("no desktop to ask in: run esec vault secrets set yourself")
		case err != nil:
			return "", err
		case !ok:
			return "", errors.New("the request was turned down")
		case v == "":
			return "", errors.New("no value given")
		}
		return v, nil
	}}
	return set.Run(ctx)
}

// printRolloutSteps says what to do after a value changed.
func printRolloutSteps(files []secretfile.File) {
	roots := map[string]bool{}
	envs := map[string]bool{}
	for _, f := range files {
		roots[f.Root] = true
		if f.Project != "" {
			envs[f.Project+" "+f.Env] = true
		}
	}
	fmt.Println("Next:")
	fmt.Printf("  1. commit the change%s and deploy\n", map[bool]string{true: "s in each repository", false: ""}[len(roots) > 1])
	since := time.Now().UTC().Format(time.RFC3339)
	for _, pe := range slices.Sorted(mapKeysOf(envs)) {
		p, e, _ := strings.Cut(pe, " ")
		fmt.Printf("  2. see that every deployment restarted: esec vault env status %s --project %s --since %s\n", e, p, since)
	}
	fmt.Println("  3. then revoke the old value where it was issued (the database, the API provider)")
}

func mapKeysOf(m map[string]bool) func(func(string) bool) {
	return func(yield func(string) bool) {
		for k := range m {
			if !yield(k) {
				return
			}
		}
	}
}

// SecretsRotateCmd gives a credential a new value everywhere.
type SecretsRotateCmd struct {
	Key      string `arg:"" help:"The key, such as DATABASE_URL"`
	Env      string `required:"" help:"The environment, such as prod"`
	Root     string `type:"path" help:"Where to look (default: the current repository), such as ~/src for every checkout that uses it"`
	Generate int    `help:"Generate a random value of this many bytes (base64url) instead of reading one"`
	DryRun   bool   `name:"dry-run" help:"Only list where it would change"`
	Yes      bool   `help:"Do not ask"`
	JSON     bool   `help:"Print JSON: the files changed (never the value)"`
}

// Run implements secrets rotate.
func (c *SecretsRotateCmd) Run(_ *cliCtx) error {
	root, err := secretsRoot(c.Root)
	if err != nil {
		return err
	}
	files, err := holding(root, c.Key, c.Env, true)
	if err != nil {
		return err
	}
	if len(files) == 0 {
		return fmt.Errorf("no %s file under %s holds %s", c.Env, root, c.Key)
	}
	if c.DryRun {
		if c.JSON {
			return printJSON(files)
		}
		for _, f := range files {
			fmt.Printf("  %-24s %s\n", safetext.Clean(f.Project), safetext.Clean(relTo(root, f.Path)))
		}
		return nil
	}
	if !c.JSON {
		fmt.Printf("%s of %s is in %d file(s):\n", c.Key, c.Env, len(files))
		for _, f := range files {
			fmt.Printf("  %-24s %s\n", safetext.Clean(f.Project), safetext.Clean(relTo(root, f.Path)))
		}
	}
	if !c.Yes && !confirm("Give it a new value in all of them?") {
		return errors.New("nothing changed")
	}
	value, err := newValue(c.Key, c.Generate)
	if err != nil {
		return err
	}
	if _, err := setIn(files, c.Key, value, false); err != nil {
		return err
	}
	if c.JSON {
		return printJSON(files)
	}
	fmt.Printf("✓ %s has its new value in %d file(s), encrypted.\n", c.Key, len(files))
	printRolloutSteps(files)
	return nil
}

// SecretsLintCmd checks secrets files.
type SecretsLintCmd struct {
	Root    string `type:"path" help:"Where to look (default: the current repository)"`
	Staged  bool   `help:"Check what is staged for the next commit, not the files on disk (the pre-commit hook)"`
	Offline bool   `help:"Do not ask the vault server; check values in the clear and esec.toml only"`
	JSON    bool   `help:"Print JSON, for scripts and agents"`
}

// lintFinding is a problem with a secrets file.
type lintFinding struct {
	Path   string `json:"path"`
	Level  string `json:"level"`
	Detail string `json:"detail"`
	Fix    string `json:"fix,omitempty"`
}

// Run implements secrets lint. It fails on a value in the clear, or a file
// encrypted to a key that is not its environment's current one.
func (c *SecretsLintCmd) Run(ctx *cliCtx) error { //nolint:gocyclo // each kind of finding
	root, err := secretsRoot(c.Root)
	if err != nil {
		return err
	}
	var out []lintFinding
	add := func(path, level, detail, fix string) {
		out = append(out, lintFinding{Path: relTo(root, path), Level: level, Detail: detail, Fix: fix})
	}
	var files []secretfile.File
	if c.Staged {
		files, err = stagedSecrets(root, add)
	} else {
		files, err = secretfile.Scan(root)
	}
	if err != nil {
		return err
	}
	views := map[string]*account.TeamView{}
	projectFiles := map[string]*projectfile.File{}
	a, aerr := openAccount(ctx)
	if c.Offline {
		a, aerr = nil, errors.New("offline")
	}
	bg, cancel := timeout(5 * time.Minute)
	defer cancel()
	for _, f := range files {
		if len(f.Plain) > 0 {
			add(f.Path, account.CheckFail, "in the clear: "+strings.Join(f.Plain, ", "), "esec encrypt "+relTo(root, f.Path))
		}
		if f.Project == "" {
			add(f.Path, account.CheckWarn, "no esec.toml above it, so no project's key to check it against", "esec vault project init ORG/REPO")
			continue
		}
		// esec.toml names each environment's current key: no network needed.
		pf, ok := projectFiles[f.Root]
		if !ok {
			pf, _ = projectfile.Load(f.Root)
			projectFiles[f.Root] = pf
		}
		if pf != nil && f.Env != "" {
			if want := pf.Env[f.Env].Key; want != "" && !strings.EqualFold(want, f.PublicKey) {
				add(f.Path, account.CheckFail, "encrypted to "+short(f.PublicKey)+", but esec.toml names "+short(want)+" as "+f.Env+"'s key",
					"esec vault env rotate "+f.Env+" (re-encrypts it), or fix [env."+f.Env+"] in esec.toml")
				continue
			}
		}
		if f.Env == "" || aerr != nil {
			continue
		}
		v, ok := views[f.Project]
		if !ok {
			v, err = a.Team(bg, f.Project)
			if err != nil {
				v = nil
			}
			views[f.Project] = v
		}
		if v == nil {
			// Not shared: the local keyring has the key.
			continue
		}
		e, ok := v.State.Envs[f.Env]
		switch {
		case !ok:
			add(f.Path, account.CheckWarn, f.Project+" has no environment "+f.Env, "esec vault env add "+f.Env)
		case e.PublicKey == f.PublicKey:
		case slices.Contains(e.Retired, f.PublicKey):
			add(f.Path, account.CheckFail, "encrypted to an earlier "+f.Env+" key of "+f.Project+": deployments cannot read it", "esec vault env rotate "+f.Env+" (in the repository)")
		default:
			add(f.Path, account.CheckFail, "encrypted to a key that is not "+f.Project+"'s "+f.Env+" key", "check the file name and esec.toml")
		}
		if len(e.Exposed) > 0 {
			add(f.Path, account.CheckWarn, "someone who lost access may still hold the "+f.Env+" key", "esec vault env rotate "+f.Env)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Level == account.CheckFail && out[j].Level != account.CheckFail })
	failed := 0
	for _, f := range out {
		if f.Level == account.CheckFail {
			failed++
		}
	}
	if c.JSON {
		if err := printJSON(nonNil(out)); err != nil {
			return err
		}
	} else {
		for _, f := range out {
			mark := "!"
			if f.Level == account.CheckFail {
				mark = "✗"
			}
			fmt.Printf("%s %s: %s\n", mark, safetext.Clean(f.Path), safetext.Clean(f.Detail))
			if f.Fix != "" {
				fmt.Println("    " + safetext.Clean(f.Fix))
			}
		}
		if len(out) == 0 {
			fmt.Printf("✓ %d secrets file(s): every value encrypted, each to its environment's current key.\n", len(files))
		}
		if aerr != nil && !c.Offline {
			fmt.Println("  (not signed in: checked for values in the clear and against esec.toml)")
		}
	}
	if failed > 0 {
		return fmt.Errorf("%d problem(s) in secrets files", failed)
	}
	return nil
}

// stagedSecrets reads the staged version of every secrets file staged for
// the next commit in the repository holding root. A staged file named for
// one of its project's environments that has no public key is a secrets
// file in the clear: it is reported through add.
func stagedSecrets(root string, add func(path, level, detail, fix string)) ([]secretfile.File, error) {
	top, err := gitOutput(root, "rev-parse", "--show-toplevel")
	if err != nil {
		return nil, fmt.Errorf("--staged needs a git repository: %w", err)
	}
	top = strings.TrimSpace(top)
	names, err := gitOutput(top, "diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z")
	if err != nil {
		return nil, err
	}
	var out []secretfile.File
	for _, name := range strings.Split(names, "\x00") {
		if name == "" {
			continue
		}
		env, _, err := secretfile.EnvOf(name)
		if err != nil {
			continue // not a secrets file name
		}
		path := filepath.Join(top, filepath.FromSlash(name))
		data, err := gitOutput(top, "show", ":"+name)
		if err != nil {
			return nil, err
		}
		f, err := secretfile.Parse(path, []byte(data))
		if err != nil {
			// No public key: harmless (a template), unless its project has
			// an environment of this name.
			if pf, _, ferr := projectfile.Find(filepath.Dir(path)); ferr == nil && env != "" && pf.Env[env].Key != "" {
				add(path, account.CheckFail, "a "+env+" secrets file with no public key: its values are in the clear",
					"git restore --staged "+name+"; put the values in with esec vault secrets set NAME --env "+env)
			}
			continue
		}
		out = append(out, *f)
	}
	return out, nil
}

func gitOutput(dir string, args ...string) (string, error) {
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("git %s: %w: %s", args[0], err, strings.TrimSpace(stderr.String()))
	}
	return string(out), nil
}

// EnvStatusCmd shows what of an environment picked up a change.
type EnvStatusCmd struct {
	Env     string `arg:"" help:"Environment name, such as prod"`
	Project string `help:"Project id (default: nearest esec.toml)"`
	Since   string `help:"Count starts after this time (RFC 3339, or a duration such as 30m or 2h ago); default: when its key last changed"`
	JSON    bool   `help:"Print JSON, for scripts and agents"`
}

// Run implements env status.
func (c *EnvStatusCmd) Run(ctx *cliCtx) error {
	project, err := projectFlag(c.Project)
	if err != nil {
		return err
	}
	var since time.Time
	if c.Since != "" {
		if t, err := time.Parse(time.RFC3339, c.Since); err == nil {
			since = t
		} else if d, err := time.ParseDuration(c.Since); err == nil {
			since = time.Now().Add(-d)
		} else {
			return errors.New("--since is a time (2026-10-25T10:00:00Z) or a duration (30m, 2h)")
		}
	}
	a, err := openAccount(ctx)
	if err != nil {
		return err
	}
	bg, cancel := timeout(2 * time.Minute)
	defer cancel()
	r, err := a.Rollout(bg, project, c.Env, since)
	if err != nil {
		return err
	}
	if c.JSON {
		return printJSON(r)
	}
	fmt.Printf("%s %s: key %s since %s; counting starts after %s\n", project, c.Env, r.PublicKey[:12], r.KeySince.Local().Format(time.DateTime), r.Since.Local().Format(time.DateTime)) //nolint:gosmopolitan // shown to the local user
	for _, h := range r.Holders {
		name := h.Name
		if h.Via != "" {
			name = h.Via + " " + h.Name
		}
		state := "✓"
		detail := ""
		switch h.Kind {
		case "member", "group":
			if !h.Current {
				state, detail = "…", "key "+h.Key
			}
		default:
			switch {
			case h.Unknown:
				state, detail = "?", "an admin of "+h.Via+" sees when it started"
			case h.LastStart.IsZero():
				state, detail = "✗", "never started"
			case !h.Current:
				state, detail = "✗", "last started "+h.LastStart.Local().Format(time.DateTime)+": restart it" //nolint:gosmopolitan // shown to the local user
			default:
				detail = "started " + h.LastStart.Local().Format(time.DateTime) //nolint:gosmopolitan // shown to the local user
			}
		}
		fmt.Printf("  %s %-9s %-36s %s\n", state, h.Kind, safetext.Clean(name), safetext.Clean(detail))
	}
	switch {
	case r.Behind > 0:
		fmt.Printf("%d deployment(s) have not started since: they run with what they had.\n", r.Behind)
		return fmt.Errorf("%d deployment(s) behind", r.Behind)
	case r.Members > 0:
		fmt.Printf("Every deployment started since; %d person(s)' devices still take in the key.\n", r.Members)
	default:
		fmt.Println("✓ Everything that reads it has picked it up.")
	}
	return nil
}

// EnvRotateExposedCmd rotates, across checkouts, every environment whose
// key someone who left may hold.
type EnvRotateExposedCmd struct {
	Root   string `type:"path" help:"Only checkouts under this directory, such as ~/src (found and remembered); default: every checkout this machine knows"`
	Org    string `help:"Only projects of this organisation"`
	DryRun bool   `name:"dry-run" help:"Only list what would be rotated"`
	Yes    bool   `help:"Do not ask"`
	JSON   bool   `help:"Print JSON, for scripts and agents"`
}

// rotatedRepo is what env rotate-exposed did in one checkout.
type rotatedRepo struct {
	Project string   `json:"project"`
	Dir     string   `json:"dir"`
	Env     string   `json:"env"`
	Files   []string `json:"files"`
	Error   string   `json:"error,omitempty"`
	Skipped string   `json:"skipped,omitempty"`
}

// Run implements env rotate-exposed.
func (c *EnvRotateExposedCmd) Run(ctx *cliCtx) error { //nolint:gocyclo // plan, ask, then each checkout
	a, err := openAccount(ctx)
	if err != nil {
		return err
	}
	bg, cancel := timeout(30 * time.Minute)
	defer cancel()
	needs, err := a.Rotations(bg, strings.ToLower(c.Org))
	if err != nil {
		return err
	}
	dirs, root, err := checkoutsByProject(c.Root)
	if err != nil {
		return err
	}
	var plan []rotatedRepo
	for _, n := range needs {
		r := rotatedRepo{Project: n.Project, Env: n.Env}
		switch {
		case !n.Admin:
			r.Skipped = "you are not an admin of it"
		case len(dirs[n.Project]) == 0:
			r.Skipped = "no checkout " + root
		case len(dirs[n.Project]) > 1:
			r.Skipped = "checked out in several repositories, rotate in one: " + strings.Join(dirs[n.Project], ", ")
		default:
			r.Dir = dirs[n.Project][0]
		}
		plan = append(plan, r)
	}
	if len(plan) == 0 {
		if c.JSON {
			return printJSON([]rotatedRepo{})
		}
		fmt.Println("✓ No key needs rotating.")
		return nil
	}
	if !c.JSON || c.DryRun {
		for _, r := range plan {
			if r.Skipped != "" {
				fmt.Printf("  - %s %s: %s\n", r.Project, r.Env, r.Skipped)
			} else {
				fmt.Printf("  %s %s in %s\n", r.Project, r.Env, r.Dir)
			}
		}
	}
	if c.DryRun {
		return nil
	}
	if !c.Yes && !confirm("Rotate these, and re-encrypt their files?") {
		return errors.New("nothing changed")
	}
	failed := 0
	rot := &rotator{ctx: ctx}
	for i := range plan {
		r := &plan[i]
		if r.Skipped != "" {
			continue
		}
		res, err := rot.rotate(r.Project, r.Env, r.Dir)
		if err != nil && res == nil {
			r.Error, failed = err.Error(), failed+1
			continue
		}
		recordEnvKey(r.Dir, r.Project, r.Env, res.NewPublic)
		for _, f := range res.Files {
			r.Files = append(r.Files, relTo(r.Dir, f))
		}
		if err != nil {
			// Rotated, but a file could not be rewritten.
			r.Error, failed = err.Error(), failed+1
			continue
		}
		if _, err := a.PublishEnv(bg, r.Project, r.Env, "rotated"); err != nil {
			r.Error, failed = "rotated here, but not published: "+err.Error()+" (esec vault access publish "+r.Env+" --project "+r.Project+")", failed+1
		}
	}
	markDirty("env rotate")
	if c.JSON {
		if err := printJSON(plan); err != nil {
			return err
		}
	} else {
		for _, r := range plan {
			switch {
			case r.Error != "":
				fmt.Printf("✗ %s %s: %s\n", r.Project, r.Env, safetext.Clean(r.Error))
			case r.Skipped == "":
				fmt.Printf("✓ %s %s: re-encrypted %s; commit them in %s and deploy\n", r.Project, r.Env, strings.Join(r.Files, ", "), r.Dir)
			}
		}
		fmt.Println("Then check each with: esec vault env status ENV --project PROJECT")
	}
	if failed > 0 {
		return fmt.Errorf("%d rotation(s) failed", failed)
	}
	return nil
}
