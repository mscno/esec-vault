package account

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/mscno/esec-vault/internal/team"
	"github.com/mscno/esec-vault/internal/wire"
)

// Views across many projects and groups at once, for people who run a
// fleet of them. Each is worked out from the chains this device verifies,
// not from what the server says.

// RotationNeed is an environment whose current key someone who lost access
// may still hold.
type RotationNeed struct {
	Project string `json:"project"`
	Env     string `json:"env"`
	// Who names those who may hold it, and why.
	Who []string `json:"who"`
	// Admin says this account can rotate it.
	Admin bool `json:"admin"`
}

// orgContainsResource includes historical aliases in tenant-scoped reports.
func orgContainsResource(os *team.OrgState, org, id string) bool {
	if org == "" {
		return true
	}
	if os != nil {
		return os.ContainsProject(id)
	}
	return team.OrgOf(id) == org
}

// Rotations lists the environments to rotate across the shared projects
// this account is in (of org only, when given), that it can read.
func (a *Account) Rotations(ctx context.Context, org string) ([]RotationNeed, error) {
	var out []RotationNeed
	err := a.withTeam(ctx, func(t *teamCtx) error {
		var os *team.OrgState
		if org != "" {
			var err error
			os, err = t.org(org)
			if err != nil {
				return err
			}
		}
		list, err := t.a.Client.Projects(t.ctx)
		if err != nil {
			return err
		}
		for _, p := range list {
			if !orgContainsResource(os, org, p.ID) {
				continue
			}
			st, err := t.state(p.ID)
			if err != nil || st == nil || st.Archived {
				continue
			}
			who := map[string][]string{}
			for _, e := range st.Rotations() {
				for _, x := range e.Exposed {
					who[e.Name] = append(who[e.Name], x.Name+" ("+x.Reason+")")
				}
			}
			for _, pg := range st.ActiveGroups() {
				gs, err := t.group(pg.Group)
				if err != nil || gs == nil {
					continue
				}
				for env, xs := range team.GroupExposures(st, gs) {
					for _, x := range xs {
						who[env] = append(who[env], x.Name+" ("+x.Reason+")")
					}
				}
			}
			for _, env := range team.SortEnvs(mapKeys(who)) {
				if !st.HasAccess(a.State.User, env) {
					continue
				}
				out = append(out, RotationNeed{Project: p.ID, Env: env, Who: who[env], Admin: st.Admin(a.State.User)})
			}
		}
		return nil
	})
	return out, err
}

// WorkloadView is a workload of a group, for fleet listings.
type WorkloadView struct {
	Group string `json:"group"`
	ID    string `json:"id"`
	Name  string `json:"name"`
	Runs  string `json:"runs"`
	// KMS names the approved key it uses ("" when the organisation
	// approved none like it), KMSKey the key itself.
	KMS    string `json:"kms,omitempty"`
	KMSKey string `json:"kms_key,omitempty"`
	// KeyProblem says why its key is not one the organisation approves
	// for its group, when it is not.
	KeyProblem string    `json:"key_problem,omitempty"`
	Reads      []string  `json:"reads"`
	LastUsed   time.Time `json:"last_used,omitzero"`
	Uses       int       `json:"uses"`
	Suspended  bool      `json:"suspended,omitempty"`
	// Admin says this account administers its group.
	Admin      bool   `json:"admin"`
	Descriptor string `json:"descriptor"`
}

// Workloads lists the workloads of the groups of org this account can see.
func (a *Account) Workloads(ctx context.Context, org string) ([]WorkloadView, error) { //nolint:gocyclo // one pass over each group's workloads
	var out []WorkloadView
	err := a.withTeam(ctx, func(t *teamCtx) error {
		os, err := t.org(org)
		if err != nil {
			return err
		}
		list, err := t.a.Client.Groups(t.ctx)
		if err != nil {
			return err
		}
		for _, sum := range list {
			if !orgContainsResource(os, org, sum.ID) {
				continue
			}
			gs, err := t.group(sum.ID)
			if err != nil || gs == nil {
				continue
			}
			creds := gs.ActiveCreds(team.KindWorkload)
			if len(creds) == 0 {
				continue
			}
			used := map[string]wire.CredStatus{}
			if gs.Admin(a.State.User) {
				if status, err := t.a.Client.GroupStatus(t.ctx, gs.Group); err == nil {
					for _, c := range status.Creds {
						used[c.ID] = c
					}
				}
			}
			var reads []string
			for _, pr := range t.groupProjects(gs) {
				if len(pr.Envs) > 0 {
					reads = append(reads, pr.Project+" "+strings.Join(pr.Envs, ","))
				}
			}
			for _, c := range creds {
				v := WorkloadView{Group: gs.Group, ID: c.ID, Name: c.Name, Reads: nonNilStrings(reads), Admin: gs.Admin(a.State.User),
					Descriptor: (&team.WorkloadRef{Server: a.State.Server, Group: gs.Group, Root: gs.Root(), ID: c.ID}).String()}
				if c.OIDC != nil {
					v.Runs = c.OIDC.Describe()
				}
				if u, ok := used[c.ID]; ok {
					v.LastUsed, v.Uses, v.Suspended = u.LastUsed, u.Uses, u.Suspended
				}
				if c.KMS != nil {
					v.KMSKey = c.KMS.Provider + " " + c.KMS.Name
					if os != nil {
						if k := os.KMSFor(*c.KMS); k != nil {
							v.KMS = k.Name
						}
						if err := os.CheckKMS(*c.KMS, gs.Group); err != nil {
							v.KeyProblem = err.Error()
						}
					}
				}
				out = append(out, v)
			}
		}
		return nil
	})
	sort.Slice(out, func(i, j int) bool {
		if out[i].Group != out[j].Group {
			return out[i].Group < out[j].Group
		}
		return out[i].Name < out[j].Name
	})
	return out, err
}

// Rekeyed is a workload moved to another key, or one that could not be.
type Rekeyed struct {
	Group string `json:"group"`
	Name  string `json:"name"`
	Done  bool   `json:"done"`
	Error string `json:"error,omitempty"`
}

// RekeyOrg moves the workloads of org's groups that use the approved key
// from (all of them, with from "") to the approved key to, across the
// groups this account administers; with dryRun, it only lists them.
func (a *Account) RekeyOrg(ctx context.Context, org, from, to string, dryRun bool) ([]Rekeyed, error) {
	target, err := a.OrgKMSKey(ctx, org, to)
	if err != nil {
		return nil, err
	}
	var source *team.OrgKMSState
	if from != "" {
		if source, err = a.OrgKMSKey(ctx, org, from); err != nil {
			return nil, err
		}
	}
	list, err := a.Workloads(ctx, org)
	if err != nil {
		return nil, err
	}
	byGroup := map[string][]string{}
	var out []Rekeyed
	for _, w := range list {
		if !w.Admin || w.KMS == to || (source != nil && w.KMS != source.Name) {
			continue
		}
		if len(target.Groups) > 0 && !slices.Contains(target.Groups, w.Group) {
			out = append(out, Rekeyed{Group: w.Group, Name: w.Name, Error: fmt.Sprintf("%s is approved only for %s", to, strings.Join(target.Groups, ", "))})
			continue
		}
		byGroup[w.Group] = append(byGroup[w.Group], w.Name)
	}
	groups := mapKeys(byGroup)
	sort.Strings(groups)
	for _, g := range groups {
		if dryRun {
			for _, n := range byGroup[g] {
				out = append(out, Rekeyed{Group: g, Name: n})
			}
			continue
		}
		moved, err := a.RekeyWorkloads(ctx, g, byGroup[g], target.Key)
		for _, n := range byGroup[g] {
			r := Rekeyed{Group: g, Name: n, Done: slices.Contains(moved, n)}
			if err != nil {
				r.Error = err.Error()
			}
			out = append(out, r)
		}
	}
	return out, nil
}

// Todo is one thing waiting for this account.
type Todo struct {
	// Kind is rotate, changes, joins, org-confirm, org-left or
	// workload-key.
	Kind string `json:"kind"`
	// Target is the project, group or organisation.
	Target string `json:"target"`
	Text   string `json:"text"`
	// Command does it, when one does.
	Command string `json:"command,omitempty"`
}

// Todos lists what waits for this account across everything it can see,
// from the verified chains: keys to rotate, changes to sign, machines
// asking to join, organisations to confirm, people who left an
// organisation and are still in its projects, and workloads on keys their
// organisation does not approve.
func (a *Account) Todos(ctx context.Context) ([]Todo, error) { //nolint:gocyclo // one section per kind of to-do
	var out []Todo
	rot, err := a.Rotations(ctx, "")
	if err != nil {
		return nil, err
	}
	for _, r := range rot {
		td := Todo{Kind: "rotate", Target: r.Project, Text: fmt.Sprintf("%s %s needs a new key: %s may hold it", r.Project, r.Env, strings.Join(r.Who, "; "))}
		if r.Admin {
			td.Command = "esec vault env rotate " + r.Env + " --project " + r.Project
		}
		out = append(out, td)
	}
	if cs, err := a.Client.Changes(ctx); err == nil && len(cs) > 0 {
		out = append(out, Todo{Kind: "changes", Text: fmt.Sprintf("%d change(s) made on the web wait for your device to sign them", len(cs)), Command: "esec vault changes"})
	}
	orgs := map[string]bool{}
	err = a.withTeam(ctx, func(t *teamCtx) error {
		groups, err := t.a.Client.Groups(t.ctx)
		if err != nil {
			return err
		}
		for _, g := range groups {
			orgs[team.OrgOf(g.ID)] = true
			if !g.Admin {
				continue
			}
			if status, err := t.a.Client.GroupStatus(t.ctx, g.ID); err == nil && len(status.Joins) > 0 {
				out = append(out, Todo{Kind: "joins", Target: g.ID, Text: fmt.Sprintf("%d machine(s) ask to join %s", len(status.Joins), g.ID), Command: "esec vault group approve " + g.ID})
			}
		}
		projects, err := t.a.Client.Projects(t.ctx)
		if err != nil {
			return err
		}
		for _, p := range projects {
			orgs[team.OrgOf(p.ID)] = true
		}
		for _, org := range sortedKeys(orgs) {
			os, err := t.org(org)
			if err != nil || os == nil {
				continue
			}
			if !t.trusted(os) {
				out = append(out, Todo{Kind: "org-confirm", Target: org, Text: fmt.Sprintf("confirm the organisation %s (fingerprint %s) with an admin", org, os.Words()), Command: "esec vault org trust " + org})
				continue
			}
			plan, _ := t.orgRemovals(os, false, false)
			for _, r := range plan {
				if r.Login != "" {
					out = append(out, Todo{Kind: "org-left", Target: r.ID, Text: fmt.Sprintf("%s left %s but is still in %s", r.Login, org, r.ID), Command: "esec vault sync"})
				}
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	for _, org := range sortedKeys(orgs) {
		ws, err := a.Workloads(ctx, org)
		if err != nil {
			continue
		}
		for _, w := range ws {
			if w.KeyProblem != "" && w.Admin {
				out = append(out, Todo{Kind: "workload-key", Target: w.Group, Text: fmt.Sprintf("the workload %s of %s: %s", w.Name, w.Group, w.KeyProblem), Command: "esec vault org rekey " + org + " --to NAME"})
			}
		}
	}
	return out, nil
}

func sortedKeys(m map[string]bool) []string {
	out := mapKeys(m)
	sort.Strings(out)
	return out
}

func mapKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func nonNilStrings(v []string) []string {
	if v == nil {
		return []string{}
	}
	return v
}

// SeenProjects lists the shared projects this device verified before, as
// pinned in teams.toml: a server that leaves one out of a list cannot hide
// that it did.
func (a *Account) SeenProjects() ([]string, error) {
	pins, err := loadTeamPins()
	if err != nil {
		return nil, err
	}
	var out []string
	for p, pin := range pins.Projects {
		if !pin.Archived {
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out, nil
}
