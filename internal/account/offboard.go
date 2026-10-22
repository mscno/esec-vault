package account

import (
	"context"
	"sort"
	"strings"

	"github.com/mscno/esec-vault/internal/team"
)

// Offboarding: everything one person can read, across the shared projects
// and groups this account administers, so it can all be taken away at
// once.

// Holding kinds of an offboarding plan.
const (
	HoldsProject     = "project"
	HoldsGroupMember = "group-member"
	HoldsGroupAdmin  = "group-admin"
)

// OffboardItem is one place a person reads keys from.
type OffboardItem struct {
	// Kind is HoldsProject, HoldsGroupMember or HoldsGroupAdmin.
	Kind string `json:"kind"`
	// ID is the project or group.
	ID string `json:"id"`
	// Admin says they are an admin of the project.
	Admin bool `json:"admin,omitempty"`
	// Envs lists what they read there; for a group, what it reads of each
	// project, as "project env".
	Envs []string `json:"envs"`
	// CanRemove says this account can take it away (it is an admin there).
	CanRemove bool `json:"can_remove"`
}

// OffboardPlan lists where login reads keys, among the shared projects and
// groups this account can see.
func (a *Account) OffboardPlan(ctx context.Context, login string) ([]OffboardItem, error) {
	if err := team.ValidLogin(login); err != nil {
		return nil, err
	}
	var out []OffboardItem
	err := a.withTeam(ctx, func(t *teamCtx) error {
		projects, err := a.Client.Projects(ctx)
		if err != nil {
			return err
		}
		for _, p := range projects {
			st, err := t.state(p.ID)
			if err != nil || st == nil {
				continue
			}
			m, err := member(st, login)
			if err != nil {
				continue
			}
			out = append(out, OffboardItem{Kind: HoldsProject, ID: p.ID, Admin: m.Admin, Envs: st.Access(m.User), CanRemove: st.Admin(a.State.User) || m.User == a.State.User})
		}
		groups, err := a.Client.Groups(ctx)
		if err != nil {
			return err
		}
		for _, g := range groups {
			gs, err := t.group(g.ID)
			if err != nil || gs == nil {
				continue
			}
			var who *team.GroupAdminState
			kind := HoldsGroupMember
			for _, p := range gs.KeyHolders() {
				if strings.EqualFold(p.Login, login) {
					who = p
				}
			}
			if who == nil {
				continue
			}
			if gs.Admin(who.User) {
				kind = HoldsGroupAdmin
			}
			var envs []string
			for _, pr := range t.groupProjects(gs) {
				for _, e := range pr.Envs {
					envs = append(envs, pr.Project+" "+e)
				}
			}
			out = append(out, OffboardItem{Kind: kind, ID: g.ID, Envs: envs, CanRemove: gs.Admin(a.State.User)})
		}
		return nil
	})
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind > out[j].Kind
		}
		return out[i].ID < out[j].ID
	})
	return out, err
}
