package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/mscno/esec/pkg/projectfile"
	"github.com/pelletier/go-toml/v2"

	"github.com/mscno/esec-vault/internal/account"
	"github.com/mscno/esec-vault/internal/safetext"
	"github.com/mscno/esec-vault/internal/secretfile"
	"github.com/mscno/esec-vault/internal/storage"
	"github.com/mscno/esec-vault/internal/team"
	"github.com/mscno/esec-vault/internal/wire"
)

// AppCmd sets up and checks an app that reads its secrets with no secret
// of its own.
type AppCmd struct {
	Init  AppInitCmd  `cmd:"" help:"Set up the app in this repository to read an environment: its group, workload and fly.toml, then check it."`
	Check AppCheckCmd `cmd:"" help:"Check, before a deploy, that the app will get its keys: files, fly.toml, Dockerfile, workload, group, keys sent."`
}

// appRepo is what an app's repository says about it.
type appRepo struct {
	Dir     string
	Project string
	FlyToml string
	FlyApp  string
	// Workload is fly.toml's [env] ESEC_VAULT_WORKLOAD.
	Workload   string
	Dockerfile string
	Files      []secretfile.File
}

func readAppRepo(dir string) (*appRepo, error) {
	if dir == "" {
		dir = "."
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	project, marker, err := projectfile.FindProjectFile(abs)
	if err != nil {
		return nil, fmt.Errorf("no .esec-project in %s or above: run esec vault project init ORG/REPO", abs)
	}
	r := &appRepo{Dir: filepath.Dir(marker), Project: project}
	if r.Files, err = secretfile.Scan(r.Dir); err != nil {
		return nil, err
	}
	if data, err := os.ReadFile(filepath.Join(abs, "fly.toml")); err == nil { //nolint:gosec // the app's own configuration
		r.FlyToml = filepath.Join(abs, "fly.toml")
		var cfg struct {
			App string            `toml:"app"`
			Env map[string]string `toml:"env"`
		}
		if err := toml.Unmarshal(data, &cfg); err != nil {
			return nil, fmt.Errorf("fly.toml: %w", err)
		}
		r.FlyApp, r.Workload = cfg.App, cfg.Env["ESEC_VAULT_WORKLOAD"]
	}
	if data, err := os.ReadFile(filepath.Join(abs, "Dockerfile")); err == nil { //nolint:gosec // the app's own Dockerfile
		r.Dockerfile = string(data)
	}
	return r, nil
}

// filesOf returns the secrets files of env of the repository's project.
func (r *appRepo) filesOf(env string) []secretfile.File {
	var out []secretfile.File
	for _, f := range r.Files {
		if f.Env == env && f.Project == r.Project {
			out = append(out, f)
		}
	}
	return out
}

// localChecks checks the repository itself.
func (r *appRepo) localChecks(env string) []account.Check {
	var out []account.Check
	add := func(name, level, detail, fix string) {
		out = append(out, account.Check{Name: name, Level: level, Detail: detail, Fix: fix})
	}
	files := r.filesOf(env)
	if len(files) == 0 {
		add("secrets file", account.CheckFail, "no secrets file of "+env+" in "+r.Dir, "esec vault env add "+env)
	}
	for _, f := range r.Files {
		if len(f.Plain) > 0 {
			add("in the clear", account.CheckFail, relTo(r.Dir, f.Path)+": "+strings.Join(f.Plain, ", ")+" not encrypted", "esec encrypt "+relTo(r.Dir, f.Path))
		}
	}
	for _, f := range files {
		if ignored, pattern := dockerIgnored(r.Dir, relTo(r.Dir, f.Path)); ignored {
			add("image", account.CheckFail, relTo(r.Dir, f.Path)+" is left out of the image by .dockerignore ("+pattern+"): the app could not read it", "let it in: add !"+relTo(r.Dir, f.Path)+" to .dockerignore (it is encrypted)")
		}
	}
	if r.FlyToml != "" && r.FlyApp == "" {
		add("fly.toml", account.CheckFail, "fly.toml names no app", "")
	}
	if r.Dockerfile != "" {
		if !strings.Contains(r.Dockerfile, "esec-vault") {
			add("image", account.CheckWarn, "the Dockerfile never mentions esec-vault: the image needs esec and esec-vault, and to start the app through them", `CMD ["esec-vault", "machine", "run", "--", "esec", "run", ".env.`+env+`", "--", "/app/server"]`)
		} else if !regexp.MustCompile(`esec-vault"?,?\s*"?machine"?,?\s*"?run`).MatchString(r.Dockerfile) {
			add("image", account.CheckWarn, "the Dockerfile does not seem to start the app with esec-vault machine run", `CMD ["esec-vault", "machine", "run", "--", "esec", "run", ".env.`+env+`", "--", "/app/server"]`)
		}
	}
	return out
}

// dockerIgnored reports whether .dockerignore leaves rel out of the image,
// and by which pattern.
func dockerIgnored(dir, rel string) (bool, string) {
	data, err := os.ReadFile(filepath.Join(dir, ".dockerignore")) //nolint:gosec // the app's own .dockerignore
	if err != nil {
		return false, ""
	}
	rel = filepath.ToSlash(rel)
	ignored, by := false, ""
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		neg := strings.HasPrefix(line, "!")
		pat := strings.TrimPrefix(strings.TrimPrefix(line, "!"), "/")
		pat = strings.TrimPrefix(pat, "**/")
		match := false
		for _, cand := range []string{rel, filepath.Base(rel)} {
			if ok, _ := filepath.Match(pat, cand); ok {
				match = true
			}
		}
		if strings.HasSuffix(pat, "/") || !strings.ContainsAny(pat, "*?[") {
			match = match || strings.HasPrefix(rel, strings.TrimSuffix(pat, "/")+"/")
		}
		if match {
			ignored, by = !neg, line
		}
	}
	return ignored, by
}

// printChecks prints checks and returns how many failed.
func printChecks(checks []account.Check) int {
	failed := 0
	for _, c := range checks {
		mark := "✓"
		switch c.Level {
		case account.CheckFail:
			mark = "✗"
			failed++
		case account.CheckWarn:
			mark = "!"
		}
		fmt.Printf("%s %-13s %s\n", mark, c.Name, safetext.Clean(c.Detail))
		if c.Fix != "" && c.Level != account.CheckOK {
			fmt.Printf("  %13s → %s\n", "", safetext.Clean(c.Fix))
		}
	}
	return failed
}

// AppCheckCmd checks an app before a deploy.
type AppCheckCmd struct {
	Env    string `help:"The environment the app reads (default: the only one with a secrets file, or prod)"`
	Dir    string `type:"path" help:"The app's directory (default: the current one)"`
	Strict bool   `help:"Fail on warnings too"`
	JSON   bool   `help:"Print JSON, for scripts and CI"`
}

// Run implements app check.
func (c *AppCheckCmd) Run(ctx *cliCtx) error {
	r, err := readAppRepo(c.Dir)
	if err != nil {
		return err
	}
	env := c.Env
	if env == "" {
		env = guessEnv(r)
	}
	checks := r.localChecks(env)
	a, err := openAccount(ctx)
	if err != nil {
		checks = append(checks, account.Check{Name: "vault", Level: account.CheckWarn, Detail: "not signed in: checked only the repository", Fix: "esec vault login SERVER"})
	} else {
		bg, cancel := timeout(2 * time.Minute)
		defer cancel()
		in := account.AppCheckInput{Project: r.Project, Env: env, FilePublicKeys: map[string]string{}, FlyApp: r.FlyApp, Workload: r.Workload}
		for _, f := range r.filesOf(env) {
			in.FilePublicKeys[relTo(r.Dir, f.Path)] = f.PublicKey
		}
		more, err := a.CheckApp(bg, in)
		if err != nil {
			return err
		}
		checks = append(checks, more...)
	}
	failed, warned := 0, 0
	for _, ch := range checks {
		switch ch.Level {
		case account.CheckFail:
			failed++
		case account.CheckWarn:
			warned++
		}
	}
	if c.JSON {
		if err := printJSON(nonNil(checks)); err != nil {
			return err
		}
	} else {
		fmt.Printf("%s, environment %s%s:\n", r.Project, env, map[bool]string{true: ", Fly.io app " + r.FlyApp, false: ""}[r.FlyApp != ""])
		printChecks(checks)
	}
	if failed > 0 || (c.Strict && warned > 0) {
		return fmt.Errorf("%d check(s) failed, %d warning(s): fix them before deploying", failed, warned)
	}
	if !c.JSON {
		fmt.Println("✓ Ready to deploy.")
	}
	return nil
}

// guessEnv picks the environment an app most likely reads.
func guessEnv(r *appRepo) string {
	var envs []string
	for _, f := range r.Files {
		if f.Project == r.Project && f.Env != "" && !slices.Contains(envs, f.Env) {
			envs = append(envs, f.Env)
		}
	}
	if len(envs) == 1 {
		return envs[0]
	}
	return "prod"
}

// AppInitCmd sets up an app.
type AppInitCmd struct {
	Env     string `help:"The environment the app reads (default: the only one with a secrets file, or prod)"`
	App     string `help:"The Fly.io app (default: fly.toml's app)"`
	Dir     string `type:"path" help:"The app's directory (default: the current one)"`
	FlyOrg  string `name:"fly-org" help:"Its Fly.io organisation (default: the organisation's setting)"`
	KMS     string `name:"kms" help:"The approved KMS key (default: the app's own esec-APP, else the organisation's default)"`
	NoWrite bool   `name:"no-write" help:"Print the descriptor instead of writing it into fly.toml"`
	Yes     bool   `help:"Do not ask before writing fly.toml"`
}

// Run implements app init.
func (c *AppInitCmd) Run(ctx *cliCtx) error { //nolint:gocyclo // checks, setup, writing, then the checks again
	r, err := readAppRepo(c.Dir)
	if err != nil {
		return err
	}
	app := c.App
	if app == "" {
		app = r.FlyApp
	}
	if app == "" {
		return errors.New("name the Fly.io app with --app, or run this beside its fly.toml")
	}
	env := c.Env
	if env == "" {
		env = guessEnv(r)
	}
	// The repository first: a mistake here would be deployed.
	if failed := printChecks(r.localChecks(env)); failed > 0 {
		return errors.New("fix the repository first; nothing was set up")
	}
	a, err := openAccount(ctx)
	if err != nil {
		return err
	}
	bg, cancel := timeout(5 * time.Minute)
	defer cancel()
	org := team.OrgOf(r.Project)
	v, err := a.Org(bg, org)
	if err != nil {
		return err
	}
	if v.State == nil {
		return fmt.Errorf("%s is not set up as an organisation: esec vault org create %s", org, org)
	}
	flyOrg := c.FlyOrg
	if flyOrg == "" {
		flyOrg = v.State.Settings.FlyOrg
	}
	if flyOrg == "" {
		return fmt.Errorf("name the Fly.io organisation with --fly-org (or set a default: esec vault org set %s --fly-org SLUG)", org)
	}
	kmsName := c.KMS
	if kmsName == "" {
		if k, ok := v.State.KMSByName("esec-" + app); ok && slices.Contains(k.Groups, org+"/"+app) {
			kmsName = k.Name
		} else {
			kmsName = v.State.Settings.DefaultKMS
		}
	}
	if kmsName == "" {
		return fmt.Errorf("no KMS key to use: make one for the app (esec vault kms setup gcp --fly-org %s --fly-app %s --org %s --apply --approve), or name one with --kms", flyOrg, app, org)
	}
	res, err := a.FlyAppEnv(bg, r.Project, env, app, flyOrg, kmsName)
	if res != nil {
		for _, l := range res.Lines(wireApp(app, flyOrg, org, kmsName)) {
			fmt.Println(safetext.Clean(l))
		}
	}
	if err != nil {
		return err
	}
	desc := res.Ref.String()
	switch {
	case r.FlyToml == "" || c.NoWrite:
		fmt.Printf("\nPut this in fly.toml (not a secret):\n\n  [env]\n    ESEC_VAULT_WORKLOAD = %q\n\n", desc)
	case r.Workload == desc:
		fmt.Println("fly.toml has the descriptor already.")
	default:
		fmt.Printf("\nfly.toml gets, in [env] (not a secret):\n  ESEC_VAULT_WORKLOAD = %q\n", desc)
		if r.Workload != "" {
			fmt.Println("  (in place of the one it has, which names another workload)")
		}
		if !c.Yes && !confirm("Write it into fly.toml?") {
			fmt.Println("Not written; add it yourself.")
			break
		}
		if err := setFlyEnv(r.FlyToml, "ESEC_VAULT_WORKLOAD", desc); err != nil {
			return err
		}
		fmt.Println("✓ Wrote it into fly.toml; commit it.")
		r.Workload = desc
	}
	fmt.Println("\nChecking it:")
	check := AppCheckCmd{Env: env, Dir: c.Dir}
	return check.Run(ctx)
}

func wireApp(app, flyOrg, org, kms string) wire.FlyApp {
	return wire.FlyApp{App: app, FlyOrg: flyOrg, Group: org + "/" + app, KMS: kms}
}

var flyEnvLine = regexp.MustCompile(`^\s*ESEC_VAULT_WORKLOAD\s*=`)

// setFlyEnv sets key in fly.toml's [env] table, keeping the rest as it is.
func setFlyEnv(path, key, value string) error {
	data, err := os.ReadFile(path) //nolint:gosec // the app's own fly.toml
	if err != nil {
		return err
	}
	lines := strings.Split(string(data), "\n")
	line := fmt.Sprintf("  %s = %q", key, value)
	inEnv, envAt, done := false, -1, false
	for i, l := range lines {
		t := strings.TrimSpace(l)
		if strings.HasPrefix(t, "[") {
			inEnv = t == "[env]"
			if inEnv {
				envAt = i
			}
			continue
		}
		if inEnv && flyEnvLine.MatchString(l) {
			lines[i], done = line, true
		}
	}
	switch {
	case done:
	case envAt >= 0:
		lines = slices.Insert(lines, envAt+1, line)
	default:
		if len(lines) > 0 && lines[len(lines)-1] == "" {
			lines = lines[:len(lines)-1]
		}
		lines = append(lines, "", "[env]", line, "")
	}
	out := strings.Join(lines, "\n")
	var check struct {
		Env map[string]string `toml:"env"`
	}
	if err := toml.Unmarshal([]byte(out), &check); err != nil || check.Env[key] != value {
		return errors.New("could not write fly.toml cleanly; add the descriptor by hand")
	}
	return storage.WriteKeepMode(path, []byte(out))
}
