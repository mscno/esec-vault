package cli

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/mscno/esec/pkg/projectfile"

	"github.com/mscno/esec-vault/internal/account"
	"github.com/mscno/esec-vault/internal/keystore"
	"github.com/mscno/esec-vault/internal/safetext"
	"github.com/mscno/esec-vault/internal/seal"
	"github.com/mscno/esec-vault/internal/secretfile"
	"github.com/mscno/esec-vault/internal/workspace"
)

// ProjectsCmd lists the projects on this machine: where each is checked out,
// its environments and whether this device holds their keys.
type ProjectsCmd struct {
	List   ProjectsListCmd   `cmd:"" default:"withargs" help:"Every project on this machine: checkouts, environments, keys here (default)."`
	Show   ProjectsShowCmd   `cmd:"" help:"One project: its checkouts, environments and secrets files."`
	Add    ProjectsAddCmd    `cmd:"" help:"Remember a checkout (a directory with esec.toml)."`
	Remove ProjectsRemoveCmd `cmd:"" help:"Forget a checkout; nothing on disk changes."`
	Scan   ProjectsScanCmd   `cmd:"" help:"Find every checkout under a directory, such as ~/src, and remember them."`
	Prune  ProjectsPruneCmd  `cmd:"" help:"Forget checkouts whose directory or esec.toml is gone."`
}

// registerCheckout remembers the checkout at dir. Commands call it when
// they find a project, so the list fills itself; failures are ignored.
func registerCheckout(dir string) {
	if os.Getenv("ESEC_VAULT_NO_REGISTER") != "" {
		return
	}
	abs, _ := filepath.Abs(dir)
	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		abs = resolved
	}
	r, err := workspace.Load()
	if err != nil {
		return
	}
	for _, c := range r.Checkouts {
		// Refresh "seen" at most daily, so ordinary commands rarely write.
		if c.Path == abs && time.Since(c.Seen) < 24*time.Hour {
			return
		}
	}
	_ = workspace.Update(func(r *workspace.Registry) error {
		_, _, err := r.Add(abs, time.Now().UTC().Truncate(time.Second))
		return err
	})
}

// recordEnvKey records an environment's new public key in the esec.toml of
// root, when that is the project's. A failure only warns: the keys and
// files are right, the file is a record.
func recordEnvKey(root, project, env, pub string) {
	pf, err := projectfile.Load(root)
	if err != nil || pf.Project != project {
		return
	}
	pf.SetEnv(env, pub)
	if err := pf.Save(root); err != nil {
		fmt.Fprintln(os.Stderr, "! esec.toml: "+err.Error())
	}
}

// checkoutsByProject returns, by project, one checkout per repository: a
// repository's worktrees are one, its main worktree preferred. With under
// set, it first finds the checkouts there and keeps only those; where says
// which checkouts were looked at, for messages.
func checkoutsByProject(under string) (dirs map[string][]string, where string, err error) {
	where = "known on this machine (esec vault projects scan ~/src)"
	if under != "" {
		if under, err = filepath.Abs(under); err != nil {
			return nil, "", err
		}
		if resolved, rerr := filepath.EvalSymlinks(under); rerr == nil {
			under = resolved
		}
		where = "under " + under
		err = workspace.Update(func(r *workspace.Registry) error {
			_, scanErr := r.Scan(under, 6, time.Now().UTC().Truncate(time.Second))
			return scanErr
		})
		if err != nil {
			return nil, "", err
		}
	}
	reg, err := workspace.Load()
	if err != nil {
		return nil, "", err
	}
	type repo struct{ project, common string }
	chosen := map[repo]string{}
	var order []repo
	for _, co := range reg.Checkouts {
		if workspace.Check(co) != workspace.StatusOK {
			continue
		}
		if under != "" && co.Path != under && !strings.HasPrefix(co.Path, under+string(filepath.Separator)) {
			continue
		}
		common, main := workspace.GitRepo(co.Path)
		k := repo{co.Project, common}
		if common == "" {
			k.common = co.Path // not in git: each is its own
		}
		if prev, ok := chosen[k]; !ok {
			order = append(order, k)
			chosen[k] = co.Path
		} else if main && prev != co.Path {
			chosen[k] = co.Path
		}
	}
	dirs = map[string][]string{}
	for _, k := range order {
		dirs[k.project] = append(dirs[k.project], chosen[k])
	}
	return dirs, where, nil
}

// envView is one environment as the projects commands show it.
type envView struct {
	Name  string `json:"name"`
	Key   string `json:"key,omitempty"`
	Guard string `json:"guard"`
	// Here is guarded, clear or missing: the key on this device.
	Here string `json:"here"`
	// Mismatch is set when esec.toml names another key than this device
	// holds for the environment.
	Mismatch bool `json:"mismatch,omitempty"`
	// Readers are who it is sealed to, as esec.toml names them.
	Readers []string `json:"readers,omitempty"`
	// Pending are readers not sealed in yet (no account or security key).
	Pending []string `json:"pending,omitempty"`
	// Action is the command that fixes what is wrong, if anything.
	Action string `json:"action,omitempty"`
}

type checkoutView struct {
	Path   string           `json:"path"`
	Status workspace.Status `json:"status"`
	Seen   time.Time        `json:"seen"`
}

type projectView struct {
	Project   string         `json:"project"`
	Checkouts []checkoutView `json:"checkouts"`
	Envs      []envView      `json:"envs"`
	// KeysHere is whether this device has a keyring for it.
	KeysHere bool `json:"keys_here"`
	// Files is set by projects show.
	Files []secretfile.File `json:"files,omitempty"`
}

// projectViews merges the registry, the keyrings on this device and each
// checkout's esec.toml.
func projectViews() ([]projectView, error) {
	r, err := workspace.Load()
	if err != nil {
		return nil, err
	}
	ks := keystore.New()
	keyrings, err := ks.List()
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	byID := map[string]*projectView{}
	get := func(id string) *projectView {
		if v, ok := byID[id]; ok {
			return v
		}
		v := &projectView{Project: id, Checkouts: []checkoutView{}, Envs: []envView{}}
		byID[id] = v
		return v
	}
	for id, cs := range r.Projects() {
		v := get(id)
		for _, c := range cs {
			v.Checkouts = append(v.Checkouts, checkoutView{Path: c.Path, Status: workspace.Check(c), Seen: c.Seen})
		}
	}
	for _, id := range keyrings {
		if id != "default" {
			get(id).KeysHere = true
		}
	}
	me := ""
	if st, err := account.LoadState(); err == nil {
		me = st.User
	}
	out := make([]projectView, 0, len(byID))
	for _, v := range byID {
		var pf *projectfile.File
		var recs seal.Records
		for _, c := range v.Checkouts {
			if c.Status == workspace.StatusOK {
				if f, err := projectfile.Load(c.Path); err == nil {
					pf = f
					recs, _ = seal.LoadRecords(c.Path)
					break
				}
			}
		}
		var entries map[string]string
		if v.KeysHere {
			if entries, err = ks.Read(v.Project); err != nil {
				return nil, err
			}
		}
		v.Envs = envViews(pf, entries, recs, me)
		for i := range v.Envs {
			v.Envs[i].Action = envAction(v.Project, v.Envs[i])
		}
		out = append(out, *v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Project < out[j].Project })
	return out, nil
}

// envViews lists the environments esec.toml declares, and whether this
// device opens each: its key cached here ("clear"), sealed to this person
// and opened on first use ("sealed"), opened with a touch ("guarded"), or
// not at all ("missing").
func envViews(pf *projectfile.File, entries map[string]string, recs seal.Records, me string) []envView {
	if pf == nil {
		return []envView{}
	}
	out := make([]envView, 0, len(pf.Env))
	for _, name := range pf.Envs() {
		pe := pf.Env[name]
		e := envView{Name: name, Key: pe.Key, Guard: pe.GuardLevel(), Here: "missing", Readers: pe.Readers}
		switch {
		case pe.Key != "" && entries[keystore.PubEntry(pe.Key)] != "" && !seal.Guarded(pe.Guard):
			e.Here = "clear"
		case sealedFor(recs[name], me) && seal.Guarded(pe.Guard):
			e.Here = "guarded"
		case sealedFor(recs[name], me):
			e.Here = "sealed"
		}
		if priv := entries[keystore.EnvEntry(name)]; priv != "" && pe.Key != "" {
			if pub, err := keystore.PublicHex(priv); err == nil && pub != pe.Key && entries[keystore.PubEntry(pe.Key)] == "" {
				e.Mismatch = true
			}
		}
		if rec := recs[name]; rec != nil {
			for _, sf := range rec.Readers {
				if sf.Pending != "" {
					e.Pending = append(e.Pending, sf.Reader)
				}
			}
		}
		out = append(out, e)
	}
	return out
}

// sealedFor reports whether a seal was made for this person ("me", their
// GitHub id).
func sealedFor(rec *seal.Record, me string) bool {
	if rec == nil {
		return false
	}
	for _, sf := range rec.Readers {
		r, err := seal.ParseReader(sf.Reader)
		if err != nil || sf.Pending != "" {
			continue
		}
		if r.Kind == seal.KindMe || (me != "" && r.ID == me) {
			return true
		}
	}
	return false
}

// envAction is the one command that fixes an environment, "" when it is
// fine.
func envAction(project string, e envView) string {
	switch {
	case e.Here == "missing":
		// Not sealed to this person: someone who reads it shares it.
		return "ask a reader of " + e.Name + " to run: esec vault share " + e.Name + " --with YOUR-GITHUB-LOGIN"
	case e.Mismatch:
		return "esec vault seal sync --project " + project
	case len(e.Pending) > 0:
		return "esec vault seal sync --project " + project + " (" + strings.Join(e.Pending, ", ") + " not sealed in yet)"
	}
	return ""
}

// ProjectsListCmd lists projects.
type ProjectsListCmd struct {
	JSON bool `help:"Print JSON, for scripts, agents and the Mac app"`
}

// Run implements projects list.
func (c *ProjectsListCmd) Run(_ *cliCtx) error {
	views, err := projectViews()
	if err != nil {
		return err
	}
	if c.JSON {
		return printJSON(views)
	}
	if len(views) == 0 {
		fmt.Println("No projects on this machine yet. Find your checkouts: esec vault projects scan ~/src")
		return nil
	}
	for _, v := range views {
		var envs []string
		for _, e := range v.Envs {
			mark := map[string]string{"clear": "", "guarded": "🔒", "missing": "?"}[e.Here]
			if e.Mismatch {
				mark += "!"
			}
			envs = append(envs, e.Name+mark)
		}
		where := "no checkout"
		if len(v.Checkouts) > 0 {
			where = tildePath(v.Checkouts[0].Path)
			if v.Checkouts[0].Status != workspace.StatusOK {
				where += " (" + string(v.Checkouts[0].Status) + ")"
			}
			if len(v.Checkouts) > 1 {
				where += fmt.Sprintf(" +%d", len(v.Checkouts)-1)
			}
		}
		fmt.Printf("%-34s %-28s %s\n", safetext.Clean(v.Project), safetext.Clean(strings.Join(envs, " ")), safetext.Clean(where))
	}
	fmt.Println("\n🔒 guarded  ? no key on this device  ! esec.toml names another key")
	var todo []string
	for _, v := range views {
		for _, e := range v.Envs {
			if e.Action != "" {
				todo = append(todo, fmt.Sprintf("  %s %s: %s", safetext.Clean(v.Project), safetext.Clean(e.Name), safetext.Clean(e.Action)))
			}
		}
	}
	if len(todo) > 0 {
		fmt.Println("\nTo do:")
		fmt.Println(strings.Join(todo, "\n"))
	}
	return nil
}

func tildePath(p string) string {
	if home, err := os.UserHomeDir(); err == nil {
		if rest, ok := strings.CutPrefix(p, home+string(filepath.Separator)); ok {
			return "~/" + rest
		}
	}
	return p
}

// ProjectsShowCmd shows one project.
type ProjectsShowCmd struct {
	Project string `arg:"" optional:"" help:"Project id (default: nearest esec.toml)"`
	JSON    bool   `help:"Print JSON, for scripts, agents and the Mac app"`
}

// Run implements projects show.
func (c *ProjectsShowCmd) Run(_ *cliCtx) error {
	id, err := resolveProject(c.Project)
	if err != nil {
		return err
	}
	views, err := projectViews()
	if err != nil {
		return err
	}
	var v *projectView
	for i := range views {
		if views[i].Project == id {
			v = &views[i]
		}
	}
	if v == nil {
		return fmt.Errorf("%s is not on this machine: no checkout and no keys", id)
	}
	for _, co := range v.Checkouts {
		if co.Status != workspace.StatusOK {
			continue
		}
		files, err := secretfile.Scan(co.Path)
		if err != nil {
			return err
		}
		for _, f := range files {
			if f.Project == id {
				v.Files = append(v.Files, f)
			}
		}
	}
	if c.JSON {
		return printJSON(v)
	}
	fmt.Println(v.Project)
	for _, co := range v.Checkouts {
		fmt.Printf("  checkout %s (%s)\n", safetext.Clean(tildePath(co.Path)), co.Status)
	}
	for _, e := range v.Envs {
		note := ""
		if e.Mismatch {
			note = "  ! esec.toml names another key than this device holds"
		}
		fmt.Printf("  env %-14s %-8s key here: %-8s %s%s\n", safetext.Clean(e.Name), e.Guard, e.Here, short(e.Key), note)
	}
	for _, f := range v.Files {
		extra := ""
		if len(f.Plain) > 0 {
			extra = "  ! in the clear: " + strings.Join(f.Plain, ", ")
		}
		fmt.Printf("  file %-30s %-10s %d key(s)%s\n", safetext.Clean(tildePath(f.Path)), safetext.Clean(f.Env), len(f.Keys), safetext.Clean(extra))
	}
	return nil
}

func short(pub string) string {
	if len(pub) > 12 {
		return pub[:12] + "…"
	}
	return pub
}

// ProjectsAddCmd remembers a checkout.
type ProjectsAddCmd struct {
	Dir string `arg:"" default:"." type:"path" help:"The checkout's directory"`
}

// Run implements projects add.
func (c *ProjectsAddCmd) Run(_ *cliCtx) error {
	var co workspace.Checkout
	var isNew bool
	err := workspace.Update(func(r *workspace.Registry) (err error) {
		co, isNew, err = r.Add(c.Dir, time.Now().UTC().Truncate(time.Second))
		return err
	})
	if err != nil {
		return err
	}
	if isNew {
		fmt.Printf("Added %s at %s\n", co.Project, tildePath(co.Path))
	} else {
		fmt.Printf("%s at %s is known already\n", co.Project, tildePath(co.Path))
	}
	return nil
}

// ProjectsRemoveCmd forgets a checkout.
type ProjectsRemoveCmd struct {
	Dir string `arg:"" type:"path" help:"The checkout's directory"`
}

// Run implements projects remove.
func (c *ProjectsRemoveCmd) Run(_ *cliCtx) error {
	err := workspace.Update(func(r *workspace.Registry) error {
		if !r.Remove(c.Dir) {
			return fmt.Errorf("no checkout at %s", c.Dir)
		}
		return nil
	})
	if err != nil {
		return err
	}
	fmt.Printf("Forgot %s (nothing on disk changed)\n", tildePath(c.Dir))
	return nil
}

// ProjectsScanCmd finds checkouts.
type ProjectsScanCmd struct {
	Root  string `arg:"" type:"path" help:"Where to look, such as ~/src"`
	Depth int    `default:"5" help:"How many directories down to look"`
	JSON  bool   `help:"Print JSON, for scripts and agents"`
}

// Run implements projects scan.
func (c *ProjectsScanCmd) Run(_ *cliCtx) error {
	var found []workspace.Checkout
	var scanErr error
	err := workspace.Update(func(r *workspace.Registry) error {
		found, scanErr = r.Scan(c.Root, c.Depth, time.Now().UTC().Truncate(time.Second))
		return nil
	})
	if err != nil {
		return err
	}
	if c.JSON {
		if err := printJSON(nonNil(found)); err != nil {
			return err
		}
	} else {
		for _, co := range found {
			fmt.Printf("%-34s %s\n", safetext.Clean(co.Project), safetext.Clean(tildePath(co.Path)))
		}
		fmt.Printf("%d checkout(s) under %s\n", len(found), tildePath(c.Root))
	}
	return scanErr
}

// ProjectsPruneCmd forgets checkouts that are gone.
type ProjectsPruneCmd struct{}

// Run implements projects prune.
func (c *ProjectsPruneCmd) Run(_ *cliCtx) error {
	var gone []workspace.Checkout
	err := workspace.Update(func(r *workspace.Registry) error {
		gone = r.Prune()
		return nil
	})
	if err != nil {
		return err
	}
	for _, co := range gone {
		fmt.Printf("Forgot %s at %s\n", co.Project, tildePath(co.Path))
	}
	if len(gone) == 0 {
		fmt.Println("Every checkout is still there.")
	}
	return nil
}
