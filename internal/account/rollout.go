package account

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/mscno/esec-vault/internal/team"
	"github.com/mscno/esec-vault/internal/wire"
)

// RolloutHolder is something that reads an environment, and whether it
// started (fetched its keys) since a change.
type RolloutHolder struct {
	// Kind is member, machine, group, or a group's machine, token or
	// workload.
	Kind string `json:"kind"`
	Name string `json:"name"`
	// Via is the group it reads through.
	Via string `json:"via,omitempty"`
	// Key says whether the current key reached it: held, missing (an
	// admin's device sends it) or waiting (its devices take it in).
	Key string `json:"key,omitempty"`
	// LastStart is when it last fetched its keys; Current says that was
	// after the change. Unknown says this account cannot see when (the
	// group's admins can).
	LastStart time.Time `json:"last_start,omitzero"`
	Current   bool      `json:"current"`
	Unknown   bool      `json:"unknown,omitempty"`
}

// Rollout says what of an environment has picked up a change.
type Rollout struct {
	Project   string          `json:"project"`
	Env       string          `json:"env"`
	PublicKey string          `json:"public_key"`
	KeySince  time.Time       `json:"key_since"`
	Since     time.Time       `json:"since"`
	Holders   []RolloutHolder `json:"holders"`
	// Behind counts deployments (machines, tokens, workloads) that have
	// not started since; Members those people whose devices lack the key.
	Behind  int `json:"behind"`
	Members int `json:"members_without_key"`
}

// Rollout reports, for env of project, which people and deployments have
// the environment's current key, and which deployments started after the
// time since (zero: since the key changed). Deployments fetch their keys when
// they start, so one that did not start since a change still runs with
// what it had.
func (a *Account) Rollout(ctx context.Context, project, env string, since time.Time) (*Rollout, error) { //nolint:gocyclo // members, machines, then each group's
	var out *Rollout
	err := a.withTeam(ctx, func(t *teamCtx) error {
		st, err := t.state(project)
		if err != nil {
			return err
		}
		if st == nil {
			return fmt.Errorf("%s is not a shared project", project)
		}
		e, ok := st.Envs[env]
		if !ok {
			return fmt.Errorf("%s has no environment %s (it has %s)", project, env, strings.Join(st.EnvNames(), ", "))
		}
		if since.IsZero() {
			since = e.Since
		}
		out = &Rollout{Project: project, Env: env, PublicKey: e.PublicKey, KeySince: e.Since, Since: since}
		status, err := t.a.Client.ProjectStatus(t.ctx, project)
		if err != nil {
			return err
		}
		held := map[string]wire.HolderStatus{}
		for _, h := range status.Holders {
			held[h.ID] = h
		}
		for _, m := range st.ActiveMembers() {
			if !st.HasAccess(m.User, env) {
				continue
			}
			h := RolloutHolder{Kind: "member", Name: m.Login, Key: held[m.User].Envs[env], Current: held[m.User].Envs[env] == wire.KeyHeld}
			if !h.Current {
				out.Members++
			}
			out.Holders = append(out.Holders, h)
		}
		for _, m := range st.ActiveMachines() {
			if !st.HasAccess(m.ID, env) {
				continue
			}
			hs := held[m.ID]
			h := RolloutHolder{Kind: "machine", Name: m.Name, Key: hs.Envs[env], LastStart: hs.LastUsed, Current: !hs.LastUsed.IsZero() && !hs.LastUsed.Before(since)}
			if !h.Current {
				out.Behind++
			}
			out.Holders = append(out.Holders, h)
		}
		for _, pg := range st.ActiveGroups() {
			if !st.HasAccess(team.GroupHolder(pg.Group), env) {
				continue
			}
			out.Holders = append(out.Holders, RolloutHolder{Kind: "group", Name: pg.Group, Key: held[team.GroupHolder(pg.Group)].Envs[env], Current: held[team.GroupHolder(pg.Group)].Envs[env] == wire.KeyHeld})
			gs, err := t.group(pg.Group)
			if err != nil || gs == nil || gs.Root() != pg.Root {
				continue
			}
			used := map[string]wire.CredStatus{}
			known := false
			if gs.Admin(a.State.User) {
				if s, err := t.a.Client.GroupStatus(t.ctx, gs.Group); err == nil {
					known = true
					for _, c := range s.Creds {
						used[c.ID] = c
					}
				}
			}
			for _, c := range gs.ActiveCreds("") {
				u := used[c.ID]
				h := RolloutHolder{Kind: c.Kind, Name: c.Name, Via: gs.Group, LastStart: u.LastUsed, Current: !u.LastUsed.IsZero() && !u.LastUsed.Before(since), Unknown: !known}
				if !h.Current && known {
					out.Behind++
				}
				out.Holders = append(out.Holders, h)
			}
		}
		sort.SliceStable(out.Holders, func(i, j int) bool {
			if out.Holders[i].Current != out.Holders[j].Current {
				return !out.Holders[i].Current
			}
			return false
		})
		return nil
	})
	return out, err
}
