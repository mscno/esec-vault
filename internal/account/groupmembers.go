package account

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/mscno/esec-vault/internal/chain"
	"github.com/mscno/esec-vault/internal/client"
	"github.com/mscno/esec-vault/internal/envelope"
	"github.com/mscno/esec-vault/internal/team"
	"github.com/mscno/esec-vault/internal/wire"
)

// People in groups. A member reads what the group reads: the group key is
// sealed to their user key like to a machine's key, and their devices open
// each project's keys sealed to the group, verified as a machine verifies
// them. Admins manage a group without reading through it; a project grants
// them access directly when they need it.

// AddGroupMember adds login to a group as a member, checked like a new
// project member, and seals the group key to them.
func (a *Account) AddGroupMember(ctx context.Context, id, login, accountKey string) (*AddResult, error) {
	if err := team.ValidLogin(login); err != nil {
		return nil, err
	}
	var out *AddResult
	err := a.withTeam(ctx, func(t *teamCtx) error {
		gs, err := t.requireGroupAdmin(id)
		if err != nil {
			return err
		}
		person, cs, proof, err := t.lookupPerson(login)
		if err != nil {
			return err
		}
		if gs.HoldsKey(person.User) {
			return fmt.Errorf("%s is already in %s", person.Login, id)
		}
		verified, err := checkPerson(person, proof, cs, accountKey)
		if err != nil {
			return err
		}
		key, err := t.groupKey(gs)
		if err != nil {
			return err
		}
		e, next, err := t.glink(gs, team.GroupMemberAdd, team.GroupMemberAddBody{Member: person, Verified: verified})
		if err != nil {
			return err
		}
		g, err := t.keyGrant(next, person.User, key)
		if err != nil {
			return err
		}
		out = &AddResult{Login: person.Login, AccountWords: cs.AccountWords(), Verified: verified}
		for _, pr := range t.groupProjects(next) {
			for _, env := range pr.Envs {
				out.Granted = append(out.Granted, pr.Project+" "+env)
			}
		}
		return t.gcommit(next, []*envelope.Envelope{e}, []*envelope.Envelope{g})
	})
	return out, err
}

// lookupPerson asks the server for login's account and verifies it: the
// server chose the account, so it must be the login asked for.
func (t *teamCtx) lookupPerson(login string) (team.Person, *chain.State, *wire.AccountProof, error) {
	p, err := t.a.Client.Person(t.ctx, login)
	if err != nil {
		return team.Person{}, nil, nil, err
	}
	if !strings.EqualFold(p.User.Login, login) || p.User.ID != fmt.Sprintf("gh:%d", p.User.GitHubID) {
		return team.Person{}, nil, nil, fmt.Errorf("the server returned the account of %q for %q; not adding it", p.User.Login, login)
	}
	cs, err := t.peer(p.User.ID, p.Links)
	if err != nil {
		return team.Person{}, nil, nil, err
	}
	return team.Person{User: p.User.ID, Login: p.User.Login, Root: cs.Root()}, cs, p.Proof, nil
}

// findMember finds an active member of a group by login.
func findMember(gs *team.GroupState, login string) (*team.GroupAdminState, bool) {
	for _, m := range gs.ActiveMembers() {
		if strings.EqualFold(m.Login, login) {
			return m, true
		}
	}
	return nil, false
}

// RemoveGroupMember removes a member from a group (this account's own
// login: leaves it). They held the group key, so an admin's removal gives
// the group a new one at once, sealed to everyone left; after a member
// leaves, an admin's device does that on its next sync.
func (a *Account) RemoveGroupMember(ctx context.Context, id, login, reason string) (*GroupRemoveResult, error) {
	out := &GroupRemoveResult{Exposed: map[string][]string{}}
	err := a.withTeam(ctx, func(t *teamCtx) error {
		gs, err := t.group(id)
		if client.IsCode(err, wire.ErrForbidden) {
			return fmt.Errorf("you are not in %s", id)
		}
		if err != nil {
			return err
		}
		if gs == nil {
			return fmt.Errorf("there is no group %s", id)
		}
		m, ok := findMember(gs, login)
		if !ok {
			return fmt.Errorf("%s is not a member of %s", login, id)
		}
		self := m.User == a.State.User
		if !self && !gs.Admin(a.State.User) {
			return fmt.Errorf("only an admin of %s can remove others", id)
		}
		e, next, err := t.glink(gs, team.GroupMemberRemove, team.GroupMemberRemoveBody{User: m.User, Reason: clipReason(reason)})
		if err != nil {
			return err
		}
		links := []*envelope.Envelope{e}
		var grants []*envelope.Envelope
		if !self {
			re, rotated, gr, err := t.rotateGroupKey(next, "after removing the member "+m.Login)
			if err != nil {
				return err
			}
			links, next, grants, out.Rotated = append(links, re), rotated, gr, true
		}
		if err := t.gcommit(next, links, grants); err != nil {
			return err
		}
		if out.Rotated {
			out.Resealed, out.Pending = t.resealGroup(next)
		}
		for _, pr := range t.groupProjects(next) {
			if len(pr.Rotate) > 0 {
				out.Exposed[pr.Project] = pr.Rotate
			}
		}
		out.Cred = &team.CredState{Credential: team.Credential{Name: m.Login}, Kind: "member"}
		return nil
	})
	return out, err
}

// importGroupKeys takes in, for every group this account is a member of,
// the keys of the projects the group reads: verified like a machine of the
// group verifies them, and taken in like keys granted directly, once the
// person accepted the project.
func (t *teamCtx) importGroupKeys(res *TeamSyncResult, opts TeamSyncOptions) {
	list, err := t.a.Client.Groups(t.ctx)
	if err != nil {
		res.Problems = append(res.Problems, "groups: "+err.Error())
		return
	}
	for _, sum := range list {
		if !sum.Member {
			continue
		}
		if err := t.importGroup(sum.ID, res, opts); err != nil {
			res.problem(sum.ID, err)
		}
	}
}

func (t *teamCtx) importGroup(id string, res *TeamSyncResult, opts TeamSyncOptions) error {
	gk, err := t.a.Client.GroupKeys(t.ctx, id)
	if client.IsCode(err, wire.ErrNotFound) {
		// The group key was not sealed to this account yet.
		res.Unsent = append(res.Unsent, fmt.Sprintf("%s: the group key (an admin's device sends it)", id))
		return nil
	}
	if err != nil {
		return err
	}
	gs, err := t.verifyGroup(id, gk.Links, gk.Chains)
	if err != nil {
		return err
	}
	if !gs.Member(t.a.State.User) {
		return nil
	}
	if gk.KeyGrant == nil {
		return errors.New("the server sent no group key")
	}
	gpriv, err := team.OpenKeyGrant(gk.KeyGrant, gs, t.chains, t.me(), t.id.Private)
	if errors.Is(err, team.ErrStale) {
		// Sealed to an earlier user key, or an earlier group key: an admin's
		// device sends it again.
		res.Unsent = append(res.Unsent, fmt.Sprintf("%s: the group key (an admin's device sends it again)", id))
		return nil
	}
	if err != nil {
		return fmt.Errorf("the group key does not verify: %w", err)
	}
	t.groupKeys[id] = gpriv
	gpub, err := chain.ParseKey32(gs.Key.EncPub)
	if err != nil {
		return err
	}
	me := team.Recipient{ID: team.GroupHolder(id), Version: gs.Key.Version, EncPub: gpub}
	sort.Slice(gk.Projects, func(i, j int) bool { return gk.Projects[i].Project < gk.Projects[j].Project })
	for _, p := range gk.Projects {
		if err := t.importGroupProject(gs, p, me, gpriv, res, opts); err != nil {
			res.problem(p.Project+" (through "+id+")", err)
		}
	}
	return nil
}

func (t *teamCtx) importGroupProject(gs *team.GroupState, p wire.GroupProjectKeys, me team.Recipient, gpriv [32]byte, res *TeamSyncResult, opts TeamSyncOptions) error {
	root, ok := gs.Access[p.Project]
	if !ok {
		return errors.New("the group does not take keys from it")
	}
	if len(p.Links) == 0 || p.Links[0].Hash() != root {
		return errors.New("its chain does not start where the group chain says")
	}
	st, err := t.verifyProject(p.Project, p.Links, nil)
	if err != nil {
		return err
	}
	pg, ok := st.Group(gs.Group)
	if !ok || pg.Root != gs.Root() {
		return nil
	}
	if p.Grant == nil {
		res.Unsent = append(res.Unsent, fmt.Sprintf("%s: %s through %s (an admin of the project seals them)", p.Project, strings.Join(pg.Envs, ","), gs.Group))
		return nil
	}
	_, keys, err := team.Open(p.Grant, st, t.chains, me, gpriv)
	if errors.Is(err, team.ErrStale) {
		res.Unsent = append(res.Unsent, fmt.Sprintf("%s: %s through %s (an admin of the project seals the current keys)", p.Project, strings.Join(pg.Envs, ","), gs.Group))
		return nil
	}
	if err != nil {
		return fmt.Errorf("its keys do not verify: %w", err)
	}
	if !t.acceptVia(st, gs.Group, pg.Envs, res, opts) {
		return nil
	}
	imported, conflicts, err := t.a.importKeys(st, keys, t.pins, opts.Interactive)
	if err != nil {
		return err
	}
	res.Imported = append(res.Imported, imported...)
	res.Conflicts = append(res.Conflicts, conflicts...)
	return nil
}

// acceptVia is accept for a project whose keys come through a group: like
// a project someone added this account to, its first keys wait until the
// person accepts them.
func (t *teamCtx) acceptVia(st *team.State, group string, envs []string, res *TeamSyncResult, opts TeamSyncOptions) bool {
	if t.pins.Accepted[st.Project] || t.followMoves(st) {
		return true
	}
	inv := Invite{Project: st.Project, AddedBy: "the group " + group, Envs: envs, Group: group}
	if opts.Accept != nil && opts.Accept(inv) {
		t.pins.Accepted[st.Project] = true
		return true
	}
	for _, seen := range res.Invites {
		if seen.Project == inv.Project {
			return false
		}
	}
	res.Invites = append(res.Invites, inv)
	return false
}
