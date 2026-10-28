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

	"github.com/mscno/esec-vault/internal/keystore"
	"github.com/mscno/esec-vault/internal/safetext"
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
	r, err := workspace.Load()
	if err != nil {
		return
	}
	abs, _ := filepath.Abs(dir)
	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		abs = resolved
	}
	for _, c := range r.Checkouts {
		// Refresh "seen" at most daily, so ordinary commands rarely write.
		if c.Path == abs && time.Since(c.Seen) < 24*time.Hour {
			return
		}
	}
	if _, _, err := r.Add(abs, time.Now().UTC().Truncate(time.Second)); err != nil {
		return
	}
	_ = r.Save()
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
	out := make([]projectView, 0, len(byID))
	for _, v := range byID {
		var pf *projectfile.File
		for _, c := range v.Checkouts {
			if c.Status == workspace.StatusOK {
				if f, err := projectfile.Load(c.Path); err == nil {
					pf = f
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
		v.Envs = envViews(pf, entries)
		out = append(out, *v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Project < out[j].Project })
	return out, nil
}

// envViews lists the environments esec.toml declares and those this
// device holds keys for.
func envViews(pf *projectfile.File, entries map[string]string) []envView {
	names := map[string]bool{}
	if pf != nil {
		for name := range pf.Env {
			names[name] = true
		}
	}
	for k := range entries {
		if env, ok := keystore.EnvName(k); ok {
			names[env] = true
		}
	}
	out := make([]envView, 0, len(names))
	for name := range names {
		e := envView{Name: name, Guard: projectfile.GuardNone, Here: "missing"}
		if pf != nil {
			e.Key, e.Guard = pf.Env[name].Key, pf.Env[name].GuardLevel()
		}
		pub, level := envPublic(entries, name)
		switch level {
		case "":
		case projectfile.GuardNone:
			e.Here = "clear"
		default:
			e.Here = "guarded"
			if e.Guard == projectfile.GuardNone {
				e.Guard = level
			}
		}
		if pub != "" && e.Key != "" && pub != e.Key {
			e.Mismatch = true
		}
		if e.Key == "" {
			e.Key = pub
		}
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
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
	r, err := workspace.Load()
	if err != nil {
		return err
	}
	co, isNew, err := r.Add(c.Dir, time.Now().UTC().Truncate(time.Second))
	if err != nil {
		return err
	}
	if err := r.Save(); err != nil {
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
	r, err := workspace.Load()
	if err != nil {
		return err
	}
	if !r.Remove(c.Dir) {
		return fmt.Errorf("no checkout at %s", c.Dir)
	}
	if err := r.Save(); err != nil {
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
	r, err := workspace.Load()
	if err != nil {
		return err
	}
	found, scanErr := r.Scan(c.Root, c.Depth, time.Now().UTC().Truncate(time.Second))
	if err := r.Save(); err != nil {
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
	r, err := workspace.Load()
	if err != nil {
		return err
	}
	gone := r.Prune()
	if err := r.Save(); err != nil {
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
