package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	coreseal "github.com/mscno/esec/pkg/seal"
	"golang.org/x/term"

	"github.com/mscno/esec-vault/internal/account"
	"github.com/mscno/esec-vault/internal/daemon"
	"github.com/mscno/esec-vault/internal/identity"
	"github.com/mscno/esec-vault/internal/remote"
	"github.com/mscno/esec-vault/internal/safetext"
	"github.com/mscno/esec-vault/internal/seal"
	"github.com/mscno/esec-vault/internal/service"
	"github.com/mscno/esec-vault/internal/verify"
	"github.com/mscno/esec-vault/internal/workspace"
)

// SetupCmd sets a machine up in one go, or reports what is left: identity
// (new, or joining your account), keys from the vault server, a second
// place for keys, the background service, your checkouts, guarded keys and
// a check that none can be lost. Every step can be run again.
type SetupCmd struct {
	Server   string   `help:"Vault server to sign in to, for a machine joining your account (default: the one signed in to, or ESEC_VAULT_SERVER)"`
	Root     []string `type:"path" help:"Where your checkouts are (default: whichever of ~/src, ~/code, ~/projects, ~/dev, ~/Developer, ~/work, ~/repos exist)"`
	NoDaemon bool     `help:"Do not install the background service"`
	Check    bool     `help:"Only report what is set up and what is left; change nothing"`
	Yes      bool     `help:"Do the steps that ask (guarding keys here, a backup destination) without asking; touches and phrases are still needed"`
	JSON     bool     `help:"Print the steps as JSON, for scripts, agents and the Mac app"`
}

// setupStep is one step of setup and what became of it.
type setupStep struct {
	Step string `json:"step"`
	// Status is ok (was set up), done (set up now), todo, skipped or failed.
	Status string `json:"status"`
	Detail string `json:"detail"`
	// Command does or fixes it.
	Command string `json:"command,omitempty"`
}

type setupRun struct {
	ctx         *cliCtx
	c           *SetupCmd
	interactive bool
	steps       []setupStep
}

func (r *setupRun) add(step, status, detail, command string) {
	r.steps = append(r.steps, setupStep{Step: step, Status: status, Detail: detail, Command: command})
	if r.c.JSON {
		return
	}
	mark := map[string]string{"ok": "✓", "done": "✓", "todo": "→", "skipped": "-", "failed": "✗"}[status]
	fmt.Printf("%s %s: %s\n", mark, step, safetext.Clean(detail))
	if command != "" {
		fmt.Printf("    %s\n", safetext.Clean(command))
	}
}

// may reports whether setup may do a step now: not --check, and asked when
// the step asks.
func (r *setupRun) may(question string) bool {
	switch {
	case r.c.Check:
		return false
	case r.c.Yes:
		return true
	case !r.interactive:
		return false
	}
	return confirm(question)
}

// Run implements setup.
func (c *SetupCmd) Run(ctx *cliCtx) error {
	r := &setupRun{ctx: ctx, c: c, interactive: term.IsTerminal(int(os.Stdin.Fd()))}
	stdout := os.Stdout
	if c.JSON {
		// The commands setup runs print as they go; keep stdout for the JSON.
		os.Stdout = os.Stderr
		defer func() { os.Stdout = stdout }()
	}
	haveID := r.identity()
	if haveID {
		r.server()
		r.secondPlace()
	}
	r.daemon()
	r.checkouts()
	if haveID {
		r.seals()
		r.keysHere()
		r.guard()
		r.verify()
	}
	os.Stdout = stdout
	return r.finish()
}

func (r *setupRun) finish() error {
	left, failed := 0, 0
	for _, s := range r.steps {
		switch s.Status {
		case "todo":
			left++
		case "failed":
			failed++
		}
	}
	if r.c.JSON {
		if err := printJSON(r.steps); err != nil {
			return err
		}
	} else {
		switch {
		case left == 0 && failed == 0:
			fmt.Println("\nThis machine is set up.")
		case r.c.Check:
			fmt.Printf("\n%d step(s) left: esec vault setup does what it can.\n", left+failed)
		default:
			fmt.Printf("\n%d step(s) left; run them, then esec vault setup again.\n", left+failed)
		}
	}
	if failed > 0 {
		return &exitCodeError{code: 1, msg: fmt.Sprintf("%d setup step(s) failed", failed)}
	}
	return nil
}

// serverURL is the vault server to join: --server, the one signed in to,
// or ESEC_VAULT_SERVER.
func (r *setupRun) serverURL() string {
	if r.c.Server != "" {
		return r.c.Server
	}
	if st, err := account.LoadState(); err == nil && st.Server != "" {
		return st.Server
	}
	return os.Getenv("ESEC_VAULT_SERVER")
}

// identity makes sure this machine has your identity: by signing in to
// your vault server (a machine joining), or, asked, from a backup and the
// phrase, or as your first machine. It never makes a second identity
// unasked: that would split your keys.
func (r *setupRun) identity() bool {
	id, err := identity.Load(r.ctx.Keyring)
	if err == nil {
		r.add("identity", "ok", "fingerprint "+id.Fingerprint()[:16]+"…", "")
		return true
	}
	if !errors.Is(err, identity.ErrNotFound) {
		r.add("identity", "failed", err.Error(), "esec vault doctor")
		return false
	}
	server := r.serverURL()
	join := "esec vault login SERVER (joining your account), esec vault recover --file BACKUP (from a backup), or esec vault identity init (your first machine)"
	if server != "" {
		join = "esec vault login " + server
	}
	if r.c.Check || !r.interactive && server == "" {
		r.add("identity", "todo", "none on this machine", join)
		return false
	}
	run := func(what string, cmd interface{ Run(ctx *cliCtx) error }) bool {
		if err := cmd.Run(r.ctx); err != nil {
			r.add("identity", "failed", what+": "+err.Error(), join)
			return false
		}
		id, err := identity.Load(r.ctx.Keyring)
		if err != nil {
			r.add("identity", "failed", what+": "+err.Error(), join)
			return false
		}
		r.add("identity", "done", what+": fingerprint "+id.Fingerprint()[:16]+"…", "")
		return true
	}
	if server != "" {
		return run("signed in to "+server, &LoginCmd{Server: server})
	}
	answer, err := promptLine("No identity here. Is this (1) another machine of yours with a vault server, (2) another machine with a backup, or (3) your first machine? [1/2/3]: ")
	if err != nil {
		r.add("identity", "todo", "none on this machine", join)
		return false
	}
	switch answer {
	case "1":
		url, err := promptLine("Vault server (https://…): ")
		if err != nil || url == "" {
			r.add("identity", "todo", "none on this machine", join)
			return false
		}
		return run("signed in to "+url, &LoginCmd{Server: url})
	case "2":
		if err := (&RemoteAddCmd{}).Run(r.ctx); err != nil {
			r.add("identity", "failed", "backup destination: "+err.Error(), join)
			return false
		}
		dir, err := os.MkdirTemp("", "esec-vault-setup-")
		if err != nil {
			r.add("identity", "failed", err.Error(), join)
			return false
		}
		defer os.RemoveAll(dir)
		file := filepath.Join(dir, "backup.esec")
		if err := (&RemotePullCmd{Out: file, Force: true}).Run(r.ctx); err != nil {
			r.add("identity", "failed", "download the newest backup: "+err.Error(), join)
			return false
		}
		return run("recovered from the newest backup", &RecoverCmd{File: file})
	case "3":
		return run("created; write the 24 words down", &InitCmd{})
	}
	r.add("identity", "todo", "none on this machine", join)
	return false
}

// server syncs keys with the vault server, when signed in.
func (r *setupRun) server() {
	if _, err := account.LoadState(); errors.Is(err, account.ErrNotLoggedIn) {
		r.add("vault server", "skipped", "not signed in; keys sync between your machines through one", "esec vault login SERVER")
		return
	}
	if r.c.Check {
		r.add("vault server", "ok", "signed in", "")
		return
	}
	if err := serverSync(r.ctx, r.interactive); err != nil {
		r.add("vault server", "failed", "sync: "+err.Error(), "esec vault sync")
		return
	}
	r.add("vault server", "done", "keys synced", "")
}

// secondPlace makes sure keys are stored somewhere besides this machine.
func (r *setupRun) secondPlace() {
	cfg, err := remote.Load()
	if err != nil {
		r.add("second place", "failed", err.Error(), "esec vault remote list")
		return
	}
	_, signedIn := account.LoadState()
	switch {
	case signedIn == nil && cfg.Default != "":
		r.add("second place", "ok", "the vault server, and backups to "+cfg.Default, "")
		return
	case signedIn == nil:
		r.add("second place", "ok", "the vault server", "")
		return
	case cfg.Default != "":
		r.add("second place", "ok", "backups to "+cfg.Default, "")
		return
	}
	if !r.interactive || !r.may("Keys are only on this machine. Add a backup destination now?") {
		r.add("second place", "todo", "keys are only on this machine", "esec vault remote add (or esec vault login SERVER)")
		return
	}
	if err := (&RemoteAddCmd{Prefix: "personal/v2"}).Run(r.ctx); err != nil {
		r.add("second place", "failed", err.Error(), "esec vault remote add")
		return
	}
	if err := (&BackupCmd{Verify: true, Push: true}).Run(r.ctx); err != nil {
		r.add("second place", "failed", "first backup: "+err.Error(), "esec vault backup --verify --push")
		return
	}
	r.add("second place", "done", "backed up", "")
}

// daemon installs the background service, or upgrades an old one.
func (r *setupRun) daemon() {
	if r.c.NoDaemon {
		r.add("background service", "skipped", "--no-daemon", "")
		return
	}
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		r.add("background service", "skipped", "not supported on "+runtime.GOOS, "")
		return
	}
	if !daemon.ManagedSocket() {
		r.add("background service", "skipped", "ESEC_VAULT_SOCK is set: run the broker yourself", "")
		return
	}
	m, err := service.New()
	if err != nil {
		r.add("background service", "failed", err.Error(), "esec vault daemon install --start")
		return
	}
	var cmd interface{ Run(ctx *cliCtx) error }
	var command string
	switch {
	case !m.Installed():
		cmd, command = &DaemonInstallCmd{Start: true}, "esec vault daemon install --start"
	case len(daemonVersionIssues(r.ctx)) > 0:
		cmd, command = &DaemonUpgradeCmd{Start: true}, "esec vault daemon upgrade"
	default:
		r.add("background service", "ok", "installed and current", "")
		return
	}
	if r.c.Check {
		r.add("background service", "todo", "it answers agents' requests, opens guarded keys and checks keys daily", command)
		return
	}
	if err := cmd.Run(r.ctx); err != nil {
		r.add("background service", "failed", err.Error(), command)
		return
	}
	r.add("background service", "done", "running", "")
}

// setupRoots are the usual places for checkouts that exist here.
func setupRoots() []string {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	var out []string
	for _, d := range []string{"src", "code", "projects", "dev", "Developer", "work", "repos"} {
		if info, err := os.Stat(filepath.Join(home, d)); err == nil && info.IsDir() {
			out = append(out, filepath.Join(home, d))
		}
	}
	return out
}

// checkouts finds the projects checked out on this machine.
func (r *setupRun) checkouts() {
	roots := r.c.Root
	if len(roots) == 0 {
		roots = setupRoots()
	}
	if !r.c.Check && len(roots) > 0 {
		now := time.Now().UTC().Truncate(time.Second)
		err := workspace.Update(func(reg *workspace.Registry) error {
			var errs []error
			for _, root := range roots {
				if _, err := reg.Scan(root, 4, now); err != nil {
					errs = append(errs, err)
				}
			}
			return errors.Join(errs...)
		})
		if err != nil {
			r.add("checkouts", "failed", err.Error(), "esec vault projects scan DIR")
			return
		}
	}
	reg, err := workspace.Load()
	if err != nil {
		r.add("checkouts", "failed", err.Error(), "")
		return
	}
	n := len(reg.Projects())
	switch {
	case n == 0 && len(roots) == 0:
		r.add("checkouts", "todo", "none found", "esec vault projects scan DIR (or esec vault setup --root DIR)")
	case n == 0:
		r.add("checkouts", "ok", "no esec.toml under "+strings.Join(tildePaths(roots), ", "), "")
	default:
		r.add("checkouts", "ok", fmt.Sprintf("%d checkout(s) of %d project(s)", len(reg.Checkouts), n), "")
	}
}

func tildePaths(paths []string) []string {
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		out = append(out, tildePath(p))
	}
	return out
}

// keysHere says which environments of the checkouts have no key here.
func (r *setupRun) keysHere() {
	// Open what this person can into the keyring first: a new machine then
	// has every unguarded key of every checkout, with no sync.
	if !r.c.Check {
		if s, err := newSealing(r.ctx); err == nil {
			if targets, err := sealTargets("", true); err == nil {
				for _, t := range targets {
					s.unsealAll(t.root, t.pf)
				}
			}
		}
	}
	views, err := projectViews()
	if err != nil {
		r.add("keys here", "failed", err.Error(), "esec vault projects")
		return
	}
	var missing []string
	for _, v := range views {
		for _, e := range v.Envs {
			if e.Here == "missing" || e.Mismatch {
				missing = append(missing, v.Project+" "+e.Name)
			}
		}
	}
	if len(missing) == 0 {
		r.add("keys here", "ok", fmt.Sprintf("every environment of %d project(s) opens here", len(views)), "")
		return
	}
	r.add("keys here", "todo", fmt.Sprintf("%d environment(s) not shared with you: %s", len(missing), strings.Join(firstN(missing, 5), ", ")),
		"esec vault projects (each says what to do)")
}

// sealState sorts the environments of every checkout: keys not sealed in
// their repository yet, seals to make again (unguarded ones: guarded ones
// need a touch, so they wait for seal sync), and seals that fail the check.
func sealState(s *sealing, targets []sealTarget) (unsealed, stale, broken []string) {
	for _, t := range targets {
		recs, _ := seal.LoadRecords(t.root)
		for _, p := range seal.Check(t.pf, recs, func(env string) ([]byte, error) { return coreseal.Read(t.root, env) }) {
			if p.Level == seal.Fail && !strings.Contains(p.Detail, "not sealed in the repository") {
				broken = append(broken, t.pf.Project+" "+p.Env+": "+p.Detail)
			}
		}
		for _, env := range t.pf.Envs() {
			e := t.pf.Env[env]
			if e.Key == "" {
				continue
			}
			if _, err := coreseal.Read(t.root, env); err != nil {
				unsealed = append(unsealed, t.pf.Project+" "+env)
				continue
			}
			if why, err := seal.Stale(s.bg(), s.dir, e, recs[env], s.sign); err == nil && len(why) > 0 && !seal.Guarded(e.Guard) {
				stale = append(stale, t.pf.Project+" "+env)
			}
		}
	}
	return unsealed, stale, broken
}

// seals makes sure every key of every checkout is sealed in its repository
// with a recovery key, and current: keys this device holds and no seal does
// yet are sealed; changed readers are sealed again.
func (r *setupRun) seals() {
	targets, err := sealTargets("", true)
	if err != nil || len(targets) == 0 {
		return
	}
	s, err := newSealing(r.ctx)
	if err != nil {
		r.add("seals", "failed", err.Error(), "esec vault seal --all")
		return
	}
	unsealed, stale, broken := sealState(s, targets)
	if len(broken) > 0 {
		r.add("seals", "failed", fmt.Sprintf("%d seal problem(s): %s", len(broken), strings.Join(firstN(broken, 3), "; ")), "esec vault seal --all")
		return
	}
	if len(unsealed)+len(stale) == 0 {
		r.add("seals", "ok", fmt.Sprintf("every key of %d project(s) is sealed in its repository, with your recovery key", len(targets)), "")
		return
	}
	if !r.may(fmt.Sprintf("%d key(s) to seal in their repositories (%s). Seal them now?", len(unsealed)+len(stale), strings.Join(firstN(append(unsealed, stale...), 3), ", "))) {
		r.add("seals", "todo", fmt.Sprintf("%d key(s) not sealed in their repository, %d to seal again", len(unsealed), len(stale)), "esec vault seal migrate --all && esec vault seal sync --all")
		return
	}
	failed := 0
	if len(unsealed) > 0 && (&SealMigrateCmd{All: true}).Run(r.ctx) != nil {
		failed++
	}
	if len(stale) > 0 && (&SealSyncCmd{All: true}).Run(r.ctx) != nil {
		failed++
	}
	if failed > 0 {
		r.add("seals", "failed", "some keys could not be sealed", "esec vault seal --all")
		return
	}
	r.add("seals", "done", "sealed; commit .esec/ and esec.toml in each repository", "")
}

func firstN(list []string, n int) []string {
	if len(list) <= n {
		return list
	}
	return append(append([]string(nil), list[:n]...), fmt.Sprintf("and %d more", len(list)-n))
}

// guard guards here the keys you guard elsewhere: sync brings the guarded
// copy, but a clear copy from before stays until guarded here.
func (r *setupRun) guard() {
	st, err := readGuardStatus()
	if err != nil {
		r.add("guard", "failed", err.Error(), "esec vault guard")
		return
	}
	if !st.SetUp {
		r.add("guard", "todo", "no security key yet: plug in your YubiKey to keep prod behind a touch", "esec vault security-keys add")
		return
	}
	var inClear []guardProject
	for _, p := range st.Projects {
		if len(p.Clear) > 0 {
			inClear = append(inClear, p)
		}
	}
	switch {
	case len(inClear) == 0:
		r.add("guard", "ok", fmt.Sprintf("held by %d; no guarded key in the clear here", len(st.Holders)), "")
	case !r.may(fmt.Sprintf("%d project(s) have guarded keys still in the clear here. Guard them now (one touch each)?", len(inClear))):
		r.add("guard", "todo", fmt.Sprintf("%d project(s) have guarded keys still in the clear here", len(inClear)), "esec vault guard enable --project "+inClear[0].Project)
	default:
		r.guardHere(inClear)
	}
	if len(st.Holders) < 2 {
		r.add("spare YubiKey", "todo", "one security key: losing it means recovering with the phrase", "esec vault security-keys add")
	}
}

func (r *setupRun) guardHere(inClear []guardProject) {
	var failed []string
	for _, p := range inClear {
		cmd := &GuardEnableCmd{Project: p.Project, Env: p.Envs}
		if dir := checkoutOf(p.Project); dir != "" {
			// In a checkout, esec.toml says each environment's level.
			cmd.Env = nil
			err := inDir(dir, func() error { return cmd.Run(r.ctx) })
			if err != nil {
				failed = append(failed, p.Project+": "+err.Error())
			}
			continue
		}
		if err := cmd.Run(r.ctx); err != nil {
			failed = append(failed, p.Project+": "+err.Error())
		}
	}
	if len(failed) > 0 {
		r.add("guard", "failed", strings.Join(failed, "; "), "esec vault guard enable --project PROJECT")
		return
	}
	r.add("guard", "done", fmt.Sprintf("guarded the keys of %d project(s) here", len(inClear)), "")
}

// checkoutOf returns a checkout of project on this machine, "" if none.
func checkoutOf(project string) string {
	reg, err := workspace.Load()
	if err != nil {
		return ""
	}
	for _, co := range reg.Checkouts {
		if co.Project == project && workspace.Check(co) == workspace.StatusOK {
			return co.Path
		}
	}
	return ""
}

// inDir runs fn with dir as the working directory.
func inDir(dir string, fn func() error) error {
	prev, err := os.Getwd()
	if err != nil {
		return err
	}
	if err := os.Chdir(dir); err != nil {
		return err
	}
	defer func() { _ = os.Chdir(prev) }()
	return fn()
}

// verify checks that no key can be lost, and when the drill was.
func (r *setupRun) verify() {
	var rep *verify.Report
	var runErr error
	if r.c.Check {
		last, err := verify.LoadLast()
		if err != nil || last.Report == nil {
			r.add("keys safe", "todo", "never checked", "esec vault verify")
			return
		}
		rep = last.Report
	} else {
		bg, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()
		rep, runErr = verify.Run(bg, verify.Options{History: true, Server: true, Backup: true, Keyring: r.ctx.Keyring,
			OpenAccount: func() (*account.Account, error) { return openAccount(r.ctx) }})
		if rep == nil {
			r.add("keys safe", "failed", runErr.Error(), "esec vault verify")
			return
		}
		_ = verify.SaveLast(rep, runErr, time.Now().UTC())
	}
	if rep.OK() {
		r.add("keys safe", "ok", fmt.Sprintf("all %d key(s) in two places, none shared between projects", len(rep.Keys)-rep.Unheld), "")
	} else {
		r.add("keys safe", "todo", fmt.Sprintf("%d key(s) need attention (%d lost)", rep.Problems, rep.Lost), "esec vault verify")
	}
	last, _ := verify.LoadLast()
	if last == nil || last.Drill.IsZero() || time.Since(last.Drill) > 180*24*time.Hour {
		r.add("recovery drill", "todo", "prove the newest backup opens with your phrase alone", "esec vault drill")
	} else {
		r.add("recovery drill", "ok", "last "+last.Drill.Format(time.DateOnly), "")
	}
}
