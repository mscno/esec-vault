package account

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/mscno/esec-vault/internal/chain"
	"github.com/mscno/esec-vault/internal/client"
	"github.com/mscno/esec-vault/internal/envelope"
	"github.com/mscno/esec-vault/internal/team"
	"github.com/mscno/esec-vault/internal/wire"
)

// Machine groups, from an admin's device. Like project chains, every group
// chain is verified from its first link and pinned in teams.toml. The
// group's private key reaches admins the way it reaches machines: sealed to
// their user key in a key grant, which this device opens when it has to
// seal the key to someone else.

// group fetches and verifies a group chain and moves its pin. It returns
// nil, nil for a group that does not exist.
func (t *teamCtx) group(id string) (*team.GroupState, error) {
	if gs, ok := t.groups[id]; ok {
		return gs, nil
	}
	gc, err := t.a.Client.GroupChain(t.ctx, id)
	if client.IsCode(err, wire.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return t.verifyGroup(id, gc.Links, gc.Chains)
}

// verifyGroup verifies a group chain the server sent, with the user chains
// it sent along, against this device's pin, and moves the pin.
func (t *teamCtx) verifyGroup(id string, links []*envelope.Envelope, chains map[string][]*envelope.Envelope) (*team.GroupState, error) {
	t.give(chains)
	gs, err := team.VerifyGroup(id, links, t.chains)
	if err != nil {
		return nil, fmt.Errorf("the server's chain for the group %s does not verify: %w", id, err)
	}
	if err := t.moveGroupPin(gs); err != nil {
		return nil, err
	}
	return gs, nil
}

// moveGroupPin checks a verified group chain against this device's pin of
// it, and moves the pin.
func (t *teamCtx) moveGroupPin(gs *team.GroupState) error {
	pin, ok := t.pins.Groups[gs.Group]
	describe := func(i uint64) (string, string) { return gs.Links[i].Signer, describeGroupLink(gs, gs.Links[i]) }
	if err := t.checkPin(pin, ok, gs.Group, "group", gs, gs.Hashes, describe); err != nil {
		return err
	}
	t.gpin(gs)
	return nil
}

func (t *teamCtx) gpin(gs *team.GroupState) {
	t.pins.Groups[gs.Group] = Pin{Seq: gs.Seq, Head: gs.Head(), Root: gs.Root()}
	t.groups[gs.Group] = gs
}

// requireGroupAdmin loads a group this account administers.
func (t *teamCtx) requireGroupAdmin(id string) (*team.GroupState, error) {
	gs, err := t.group(id)
	if err != nil {
		return nil, err
	}
	if gs == nil {
		return nil, fmt.Errorf("there is no machine group %s; create it with 'esec vault group create %s'", id, id)
	}
	if !gs.Admin(t.a.State.User) {
		return nil, fmt.Errorf("only an admin of %s can do that", id)
	}
	return gs, nil
}

// groupRecipient returns the key a project's grant to a group is sealed to:
// the group's current key, from the group chain the project names.
func (t *teamCtx) groupRecipient(st *team.State, id string) (team.Recipient, error) {
	pg, ok := st.Group(id)
	if !ok {
		return team.Recipient{}, fmt.Errorf("the group %s reads nothing of %s", id, st.Project)
	}
	gs, err := t.group(id)
	if err != nil {
		return team.Recipient{}, err
	}
	if gs == nil || gs.Root() != pg.Root {
		return team.Recipient{}, fmt.Errorf("the group %s is not the one %s names", id, st.Project)
	}
	// Both sides agreed: the group's admins chose this project, too.
	if root, ok := gs.Access[st.Project]; !ok || root != st.Root() {
		return team.Recipient{}, fmt.Errorf("the group %s does not take keys from %s", id, st.Project)
	}
	pub, err := chain.ParseKey32(gs.Key.EncPub)
	return team.Recipient{ID: team.GroupHolder(id), Version: gs.Key.Version, EncPub: pub}, err
}

// rotations lists the environments of st whose current key someone may
// still hold: people and machines that lost access, and machines removed
// from groups that read them. A group this device cannot read is skipped.
func (t *teamCtx) rotations(st *team.State) []string {
	var out []string
	for _, e := range st.Rotations() {
		out = append(out, e.Name)
	}
	for _, pg := range st.ActiveGroups() {
		gs, err := t.group(pg.Group)
		if err != nil || gs == nil {
			continue
		}
		for env := range team.GroupExposures(st, gs) {
			out = append(out, env)
		}
	}
	return team.SortEnvs(out)
}

// me is this account as the recipient of a key grant.
func (t *teamCtx) me() team.Recipient {
	return team.Recipient{ID: t.a.State.User, Version: t.own.UKeyVersion, EncPub: t.id.Public}
}

// groupKey opens the group's current private key from this account's key
// grant.
func (t *teamCtx) groupKey(gs *team.GroupState) ([32]byte, error) {
	if k, ok := t.groupKeys[gs.Group]; ok {
		return k, nil
	}
	grants, err := t.a.Client.GroupKeyGrants(t.ctx, gs.Group)
	if err != nil {
		return [32]byte{}, err
	}
	last := fmt.Errorf("%w: no admin's device has sent you the key of %s yet", errNoGroupKey, gs.Group)
	for _, e := range grants {
		k, err := team.OpenKeyGrant(e, gs, t.chains, t.me(), t.id.Private)
		if err != nil {
			last = fmt.Errorf("%w: %w", errNoGroupKey, err)
			continue
		}
		t.groupKeys[gs.Group] = k
		return k, nil
	}
	return [32]byte{}, last
}

// errNoGroupKey is returned when this account cannot open a group's key.
var errNoGroupKey = errors.New("this account cannot open the group key")

// glink signs the next link of a group.
func (t *teamCtx) glink(gs *team.GroupState, typ string, body any) (*envelope.Envelope, *team.GroupState, error) {
	e, err := gs.NewLink(typ, body, t.a.Now(), t.a.State.User, t.own.UKeyVersion, t.own.Seq, t.id.Sign)
	if err != nil {
		return nil, nil, err
	}
	next, err := gs.Next(e, t.chains)
	if err != nil {
		return nil, nil, err
	}
	return e, next, nil
}

// gcommit sends group links and key grants, and pins the new state.
func (t *teamCtx) gcommit(next *team.GroupState, links, grants []*envelope.Envelope) error {
	for _, e := range links {
		t.pins.Signed[e.Hash()] = true
	}
	for len(links) > 0 || len(grants) > 0 {
		n := min(len(grants), 1000)
		if _, err := t.a.Client.GroupCommit(t.ctx, next.Group, &wire.GroupCommit{Links: links, KeyGrants: grants[:n]}); err != nil {
			return err
		}
		links, grants = nil, grants[n:]
	}
	t.gpin(next)
	return nil
}

// keyGrant seals the group key to a machine, token, admin or member of gs.
func (t *teamCtx) keyGrant(gs *team.GroupState, to string, key [32]byte) (*envelope.Envelope, error) {
	var r team.Recipient
	if c, ok := gs.Cred(to); ok {
		if c.Kind == team.KindWorkload {
			// Wrapped with the workload's KMS key, here: no KMS call.
			return team.NewWorkloadKeyGrant(gs, t.a.State.User, t.own.UKeyVersion, t.id.Sign, c, key, t.a.Now())
		}
		pub, err := chain.ParseKey32(c.EncPub)
		if err != nil {
			return nil, err
		}
		r = team.Recipient{ID: c.ID, EncPub: pub}
	} else {
		cs, err := t.chains(to)
		if err != nil {
			return nil, err
		}
		if p, ok := gs.Person(to); !ok || cs.Root() != p.Root {
			return nil, fmt.Errorf("the account of %s is not the one the group recorded", to)
		}
		r = team.Recipient{ID: to, Version: cs.UKeyVersion, EncPub: cs.EncPub}
	}
	return team.NewKeyGrant(gs, t.a.State.User, t.own.UKeyVersion, t.id.Sign, r, key, t.a.Now())
}

// keyGrantsAll seals key to every machine, token, admin and member of gs, but
// expired tokens and machines blocked on the web: a new key cuts them off.
func (t *teamCtx) keyGrantsAll(gs *team.GroupState, key [32]byte) ([]*envelope.Envelope, error) {
	blocked := map[string]bool{}
	if status, err := t.a.Client.GroupStatus(t.ctx, gs.Group); err == nil {
		for _, c := range status.Creds {
			blocked[c.ID] = c.Suspended
		}
		for _, u := range status.BlockedMembers {
			blocked[u] = true
		}
	}
	var out []*envelope.Envelope
	for _, c := range gs.ActiveCreds("") {
		if blocked[c.ID] || c.Expired(t.a.Now()) {
			continue
		}
		g, err := t.keyGrant(gs, c.ID, key)
		if err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	for _, a := range gs.KeyHolders() {
		if blocked[a.User] || t.uncheckedWebMember(gs, a.User) {
			continue
		}
		g, err := t.keyGrant(gs, a.User, key)
		if err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, nil
}

// uncheckedWebMember reports whether user is a member a passkey added whose
// GitHub SSH proof this device could not check: the group key is not sealed
// to them until it can.
func (t *teamCtx) uncheckedWebMember(gs *team.GroupState, user string) bool {
	m, ok := gs.Members[user]
	return ok && m.Active && m.Verified == team.VerifiedWeb && t.checkWebPerson(m.Person) != nil
}

// ---- operations ----

// Groups lists the machine groups this account administers, or whose
// machines read its projects.
func (a *Account) Groups(ctx context.Context) ([]wire.GroupSummary, error) {
	if err := a.requireConfirmed(); err != nil {
		return nil, err
	}
	return a.Client.Groups(ctx)
}

// ProjectRead is what a group reads of one project.
type ProjectRead struct {
	Project string
	// Envs is what the project grants the group; Trusted says the group
	// takes keys from it.
	Envs    []string
	Trusted bool
	// Delivered says the project's keys are sealed to the group's current
	// key.
	Delivered bool
	// Rotate lists environments whose keys a removed machine may hold.
	Rotate []string
	// Visible is false when this account is not a member of the project,
	// so only the group's side is known.
	Visible bool
}

// GroupView is a verified group, with what the server knows of it.
type GroupView struct {
	State    *team.GroupState
	Status   *wire.GroupStatus
	Projects []ProjectRead
}

// Group verifies a group and returns it with its status and projects.
func (a *Account) Group(ctx context.Context, id string) (*GroupView, error) {
	var out *GroupView
	err := a.withTeam(ctx, func(t *teamCtx) error {
		gs, err := t.group(id)
		if err != nil {
			return err
		}
		if gs == nil {
			return fmt.Errorf("there is no machine group %s", id)
		}
		out = &GroupView{State: gs}
		if gs.Admin(a.State.User) {
			if out.Status, err = a.Client.GroupStatus(ctx, id); err != nil {
				return err
			}
		}
		out.Projects = t.groupProjects(gs)
		return nil
	})
	return out, err
}

// groupProjects lists the projects a group trusts or is granted by, as far
// as this account can see them.
func (t *teamCtx) groupProjects(gs *team.GroupState) []ProjectRead {
	ids := map[string]bool{}
	for p := range gs.Access {
		ids[p] = true
	}
	if list, err := t.a.Client.Projects(t.ctx); err == nil {
		for _, p := range list {
			ids[p.ID] = true
		}
	}
	var out []ProjectRead
	for p := range ids {
		pr := ProjectRead{Project: p}
		root, trusted := gs.Access[p]
		st, err := t.state(p)
		if err == nil && st != nil {
			pr.Visible = true
			pr.Trusted = trusted && root == st.Root()
			pg, ok := st.Group(gs.Group)
			if ok && pg.Root == gs.Root() {
				pr.Envs = pg.Envs
				for env := range team.GroupExposures(st, gs) {
					pr.Rotate = append(pr.Rotate, env)
				}
				pr.Rotate = team.SortEnvs(pr.Rotate)
				if status, err := t.a.Client.ProjectStatus(t.ctx, p); err == nil {
					pr.Delivered = true
					for _, h := range status.Holders {
						if h.ID == team.GroupHolder(gs.Group) {
							for _, v := range h.Envs {
								if v != wire.KeyHeld {
									pr.Delivered = false
								}
							}
						}
					}
				}
			}
		} else {
			pr.Trusted = trusted
		}
		if !pr.Trusted && len(pr.Envs) == 0 {
			continue
		}
		out = append(out, pr)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Project < out[j].Project })
	return out
}

// CreateGroup creates a machine group with this account as its admin.
func (a *Account) CreateGroup(ctx context.Context, id string) (*team.GroupState, error) {
	if err := team.ValidGroup(id); err != nil {
		return nil, err
	}
	var out *team.GroupState
	err := a.withTeam(ctx, func(t *teamCtx) error {
		existing, err := t.group(id)
		if err != nil && !client.IsCode(err, wire.ErrForbidden) {
			return err
		}
		if existing != nil || err != nil {
			return fmt.Errorf("the group %s exists already; pick another name, or ask one of its admins to add you", id)
		}
		key, priv, err := team.NewGroupKey(1)
		if err != nil {
			return err
		}
		e, next, err := t.glink(team.NewGroup(id), team.GroupInit, team.GroupInitBody{Creator: team.Person{User: a.State.User, Login: a.State.Login, Root: t.own.Root()}, Key: key})
		if err != nil {
			return err
		}
		g, err := t.keyGrant(next, a.State.User, priv)
		if err != nil {
			return err
		}
		if err := t.gcommit(next, []*envelope.Envelope{e}, []*envelope.Envelope{g}); err != nil {
			return err
		}
		out = next
		return nil
	})
	return out, err
}

// AddGroupAdmin makes login an admin of a group, checked like a new
// project member, and seals the group key to them.
func (a *Account) AddGroupAdmin(ctx context.Context, id, login, accountKey string) (*AddResult, error) {
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
		if gs.Admin(person.User) {
			return fmt.Errorf("%s is already an admin of %s", person.Login, id)
		}
		verified, err := checkPerson(person, proof, cs, accountKey)
		if err != nil {
			return err
		}
		key, err := t.groupKey(gs)
		if err != nil {
			return err
		}
		e, next, err := t.glink(gs, team.GroupAdminAdd, team.GroupAdminAddBody{Admin: person, Verified: verified})
		if err != nil {
			return err
		}
		g, err := t.keyGrant(next, person.User, key)
		if err != nil {
			return err
		}
		out = &AddResult{Login: person.Login, AccountWords: cs.AccountWords(), Verified: verified}
		return t.gcommit(next, []*envelope.Envelope{e}, []*envelope.Envelope{g})
	})
	return out, err
}

// RemoveGroupAdmin removes an admin from a group (this account's own login:
// leaves it). They held the group key, so the group gets a new one, sealed
// to everyone left; when this account leaves, the new key is not sealed to
// it, and another admin's device reseals the projects.
func (a *Account) RemoveGroupAdmin(ctx context.Context, id, login string) (*GroupRemoveResult, error) {
	out := &GroupRemoveResult{Exposed: map[string][]string{}, Rotated: true}
	err := a.withTeam(ctx, func(t *teamCtx) error {
		gs, err := t.requireGroupAdmin(id)
		if err != nil {
			return err
		}
		var who *team.GroupAdminState
		for _, ad := range gs.ActiveAdmins() {
			if strings.EqualFold(ad.Login, login) {
				who = ad
			}
		}
		if who == nil {
			return fmt.Errorf("%s is not an admin of %s", login, id)
		}
		e, next, err := t.glink(gs, team.GroupAdminRemove, team.GroupAdminRemoveBody{User: who.User})
		if err != nil {
			return err
		}
		links := []*envelope.Envelope{e}
		var grants []*envelope.Envelope
		if who.User != a.State.User {
			re, rotated, gr, err := t.rotateGroupKey(next, "after removing the admin "+who.Login)
			if err != nil {
				return err
			}
			links, next, grants = append(links, re), rotated, gr
		} else {
			// Leaving: the others rotate, since this device's next sync no
			// longer administers the group.
			out.Rotated = false
		}
		if err := t.gcommit(next, links, grants); err != nil {
			return err
		}
		if out.Rotated {
			out.Resealed, out.Pending = t.resealGroup(next)
		}
		return nil
	})
	return out, err
}

// NewCred creates a machine (kind team.KindMachine) or token of a group and
// seals the group key to it. The returned key is its secret.
func (a *Account) NewCred(ctx context.Context, id, kind, name string, expires time.Time, policy *team.OIDCPolicy) (*team.CredKey, error) {
	var out *team.CredKey
	err := a.withTeam(ctx, func(t *teamCtx) error {
		gs, err := t.requireGroupAdmin(id)
		if err != nil {
			return err
		}
		for _, c := range gs.ActiveCreds(kind) {
			if c.Name == name {
				return fmt.Errorf("%s already has a %s named %s", id, kind, name)
			}
		}
		key, err := t.groupKey(gs)
		if err != nil {
			return err
		}
		ck, c, err := team.NewCredKey(a.State.Server, id, gs.Root(), kind, name, a.Now())
		if err != nil {
			return err
		}
		c.OIDC = policy
		var e *envelope.Envelope
		var next *team.GroupState
		if kind == team.KindToken {
			c.Expires = expires
			e, next, err = t.glink(gs, team.GroupTokenAdd, team.GroupTokenAddBody{Token: c})
		} else {
			e, next, err = t.glink(gs, team.GroupMachineAdd, team.GroupMachineAddBody{Machine: c})
		}
		if err != nil {
			return err
		}
		g, err := t.keyGrant(next, c.ID, key)
		if err != nil {
			return err
		}
		if err := t.gcommit(next, []*envelope.Envelope{e}, []*envelope.Envelope{g}); err != nil {
			return err
		}
		out = ck
		return nil
	})
	return out, err
}

// PendingJoins lists the machines waiting to join a group, with the root
// this device verified; the words each machine shows must match
// team.JoinWords of that root.
func (a *Account) PendingJoins(ctx context.Context, id string) (string, []wire.JoinRequest, error) {
	var root string
	var out []wire.JoinRequest
	err := a.withTeam(ctx, func(t *teamCtx) error {
		gs, err := t.requireGroupAdmin(id)
		if err != nil {
			return err
		}
		status, err := a.Client.GroupStatus(ctx, id)
		if err != nil {
			return err
		}
		root, out = gs.Root(), status.Joins
		return nil
	})
	return root, out, err
}

// ApproveJoin lets a waiting machine into a group and seals the group key
// to it. The caller has compared the words the machine shows.
func (a *Account) ApproveJoin(ctx context.Context, id string, j wire.JoinRequest) error {
	if err := team.ValidJoinID(j.ID); err != nil {
		return err
	}
	return a.withTeam(ctx, func(t *teamCtx) error {
		gs, err := t.requireGroupAdmin(id)
		if err != nil {
			return err
		}
		key, err := t.groupKey(gs)
		if err != nil {
			return err
		}
		c := team.Credential{ID: j.Machine, Name: j.Name, EncPub: j.EncPub, SignPub: j.SignPub, Created: a.Now().UTC().Truncate(time.Second)}
		e, next, err := t.glink(gs, team.GroupMachineAdd, team.GroupMachineAddBody{Machine: c, Join: j.ID})
		if err != nil {
			return err
		}
		g, err := t.keyGrant(next, c.ID, key)
		if err != nil {
			return err
		}
		return t.gcommit(next, []*envelope.Envelope{e}, []*envelope.Envelope{g})
	})
}

// RejectJoin turns a waiting machine away.
func (a *Account) RejectJoin(ctx context.Context, id, join string) error {
	return a.Client.RejectJoin(ctx, id, join)
}

// GroupRemoveResult describes a removed machine or token.
type GroupRemoveResult struct {
	Cred *team.CredState
	// Rotated says the group got a new key, sealed to everyone left.
	Rotated bool
	// Resealed lists projects whose keys this device sealed to the new
	// group key; Pending those whose admins' devices still have to.
	Resealed, Pending []string
	// Exposed maps projects to the environments whose keys need replacing.
	Exposed map[string][]string
}

// findCred finds an active machine or token by name or id.
func findCred(gs *team.GroupState, nameOrID string) (*team.CredState, error) {
	var found []*team.CredState
	for _, c := range gs.ActiveCreds("") {
		if c.ID == nameOrID || c.Name == nameOrID {
			found = append(found, c)
		}
	}
	switch len(found) {
	case 0:
		return nil, fmt.Errorf("%s has no machine or token %s", gs.Group, nameOrID)
	case 1:
		return found[0], nil
	}
	return nil, fmt.Errorf("several machines or tokens of %s are named %s; use its id", gs.Group, nameOrID)
}

// RemoveCred removes a machine or token from a group. Unless destroyed, the
// group gets a new key in the same commit, and this device seals the
// projects' keys it administers to it.
func (a *Account) RemoveCred(ctx context.Context, id, nameOrID, reason string, destroyed bool) (*GroupRemoveResult, error) {
	out := &GroupRemoveResult{Exposed: map[string][]string{}}
	err := a.withTeam(ctx, func(t *teamCtx) error {
		gs, err := t.requireGroupAdmin(id)
		if err != nil {
			return err
		}
		c, err := findCred(gs, nameOrID)
		if err != nil {
			return err
		}
		out.Cred = c
		e, next, err := t.glink(gs, team.GroupRemove, team.GroupRemoveBody{ID: c.ID, Reason: reason, Destroyed: destroyed})
		if err != nil {
			return err
		}
		links := []*envelope.Envelope{e}
		var grants []*envelope.Envelope
		if !destroyed {
			re, rotated, gr, err := t.rotateGroupKey(next, "after removing "+c.Name)
			if err != nil {
				return err
			}
			links, next, grants, out.Rotated = append(links, re), rotated, gr, true
		} else if c.Kind == team.KindToken {
			// The token signed the group key grants of the machines it
			// enrolled; those stop verifying with it gone, so seal anew.
			if grants, err = t.resealEnrolled(next, c.ID); err != nil {
				return err
			}
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
		return nil
	})
	return out, err
}

// RotateGroupKey gives a group a new key and seals it to everyone in it,
// and the projects' keys this device administers to the new key.
func (a *Account) RotateGroupKey(ctx context.Context, id, reason string) (*GroupRemoveResult, error) {
	out := &GroupRemoveResult{Exposed: map[string][]string{}, Rotated: true}
	err := a.withTeam(ctx, func(t *teamCtx) error {
		gs, err := t.requireGroupAdmin(id)
		if err != nil {
			return err
		}
		e, next, grants, err := t.rotateGroupKey(gs, reason)
		if err != nil {
			return err
		}
		if err := t.gcommit(next, []*envelope.Envelope{e}, grants); err != nil {
			return err
		}
		out.Resealed, out.Pending = t.resealGroup(next)
		return nil
	})
	return out, err
}

// resealEnrolled seals the group key again to the machines token enrolled.
func (t *teamCtx) resealEnrolled(gs *team.GroupState, token string) ([]*envelope.Envelope, error) {
	var mine []string
	for _, m := range gs.ActiveCreds(team.KindMachine) {
		if m.AddedBy == token {
			mine = append(mine, m.ID)
		}
	}
	if len(mine) == 0 {
		return nil, nil
	}
	key, err := t.groupKey(gs)
	if err != nil {
		return nil, err
	}
	out := make([]*envelope.Envelope, 0, len(mine))
	for _, id := range mine {
		g, err := t.keyGrant(gs, id, key)
		if err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, nil
}

// rotateGroupKey builds a key_rotate link and the key grants of the new key.
func (t *teamCtx) rotateGroupKey(gs *team.GroupState, reason string) (*envelope.Envelope, *team.GroupState, []*envelope.Envelope, error) {
	key, priv, err := team.NewGroupKey(gs.Key.Version + 1)
	if err != nil {
		return nil, nil, nil, err
	}
	e, next, err := t.glink(gs, team.GroupKeyRotate, team.GroupKeyRotateBody{Key: key, Reason: clipReason(reason)})
	if err != nil {
		return nil, nil, nil, err
	}
	grants, err := t.keyGrantsAll(next, priv)
	if err != nil {
		return nil, nil, nil, err
	}
	t.groupKeys[gs.Group] = priv
	return e, next, grants, nil
}

// clipReason keeps a generated reason within what a link allows.
func clipReason(r string) string {
	r = strings.Map(func(c rune) rune {
		if strings.ContainsRune(".,:;()'/_+- ", c) || (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
			return c
		}
		return ' '
	}, r)
	if len(r) > 200 {
		r = r[:200]
	}
	return r
}

// resealGroup seals the keys of every project granting gs that this
// account administers to the group's current key. It returns the projects
// sealed and those left to other admins.
func (t *teamCtx) resealGroup(gs *team.GroupState) (done, pending []string) {
	list, err := t.a.Client.Projects(t.ctx)
	if err != nil {
		return nil, nil
	}
	for _, p := range list {
		st, err := t.state(p.ID)
		if err != nil || st == nil {
			continue
		}
		pg, ok := st.Group(gs.Group)
		if !ok || pg.Root != gs.Root() {
			continue
		}
		if !st.Admin(t.a.State.User) {
			pending = append(pending, p.ID)
			continue
		}
		g, missing, err := t.grant(st, team.GroupHolder(gs.Group), pg.Envs)
		if err != nil || g == nil || len(missing) > 0 || t.commit(st, nil, []*envelope.Envelope{g}) != nil {
			pending = append(pending, p.ID)
			continue
		}
		done = append(done, p.ID)
	}
	return done, pending
}

// GrantResult describes a change of what a group reads of a project.
type GrantResult struct {
	// Trusted and Granted say which side this device changed: the group
	// now takes keys from the project, and the project grants the group.
	Trusted, Granted bool
	// Sent says the keys were sealed to the group.
	Sent bool
	// Missing lists environments this device had no current key for.
	Missing []string
	// Exposed lists environments the group can no longer read.
	Exposed []string
	// NeedProjectAdmin and NeedGroupAdmin say the other side still needs
	// an admin of it.
	NeedProjectAdmin, NeedGroupAdmin bool
}

// GrantGroup lets a group read envs of a project (none: nothing), changing
// both sides this account administers: the group's list of projects it takes
// keys from, and the project's grant to the group.
func (a *Account) GrantGroup(ctx context.Context, id, project string, envs []string) (*GrantResult, error) {
	return a.grantGroup(ctx, id, project, envs, false)
}

// grantGroup is GrantGroup; with narrow, it refuses anything but the group
// reading less of the project it reads now, from the group chain the
// project names: never another chain, a new project, or more environments.
func (a *Account) grantGroup(ctx context.Context, id, project string, envs []string, narrow bool) (*GrantResult, error) {
	envs = team.SortEnvs(envs)
	out := &GrantResult{}
	err := a.withTeam(ctx, func(t *teamCtx) error {
		gs, err := t.group(id)
		if client.IsCode(err, wire.ErrForbidden) {
			return fmt.Errorf("you are not an admin of %s, and it does not take keys from %s yet: an admin of the group runs 'esec vault group grant %s --project %s --env ...' first", id, project, id, project)
		}
		if err != nil {
			return err
		}
		if gs == nil {
			return fmt.Errorf("there is no machine group %s", id)
		}
		st, err := t.state(project)
		if err != nil {
			return err
		}
		if st == nil {
			return fmt.Errorf("%s is not a shared project; share it first with 'esec vault access create'", project)
		}
		for _, n := range envs {
			if _, ok := st.Envs[n]; !ok {
				return fmt.Errorf("%s has no environment %s (it has %s)", project, n, strings.Join(st.EnvNames(), ", "))
			}
		}
		if narrow {
			pg, ok := st.Group(id)
			root, trusted := gs.Access[project]
			if !ok || pg.Root != gs.Root() || !trusted || root != st.Root() || !subsetOf(envs, pg.Envs) {
				return fmt.Errorf("the change to what %s reads of %s is not only a narrowing of what it reads now; sign it after reading it", id, project)
			}
		}
		if err := t.groupSide(gs, st, len(envs) > 0, out); err != nil {
			return err
		}
		// groupSide may have moved the group on.
		return t.projectSide(t.groups[id], st, envs, out)
	})
	return out, err
}

// groupSide makes the group take keys from st (or, with trust false, stop).
func (t *teamCtx) groupSide(gs *team.GroupState, st *team.State, trust bool, out *GrantResult) error {
	root, has := gs.Access[st.Project]
	want := trust
	if has == want && (!has || root == st.Root()) {
		return nil
	}
	if !gs.Admin(t.a.State.User) {
		out.NeedGroupAdmin = true
		return nil
	}
	var links []*envelope.Envelope
	next := gs
	if has {
		e, n, err := t.glink(next, team.GroupAccessRemove, team.GroupAccessRemoveBody{Project: st.Project})
		if err != nil {
			return err
		}
		links, next = append(links, e), n
	}
	if want {
		e, n, err := t.glink(next, team.GroupAccessAdd, team.GroupAccessBody{Project: st.Project, Root: st.Root()})
		if err != nil {
			return err
		}
		links, next = append(links, e), n
	}
	if err := t.gcommit(next, links, nil); err != nil {
		return err
	}
	out.Trusted = true
	return nil
}

// projectSide makes st grant the group envs and seals them to it.
func (t *teamCtx) projectSide(gs *team.GroupState, st *team.State, envs []string, out *GrantResult) error {
	pg, has := st.Group(gs.Group)
	if has && pg.Root == gs.Root() && slices.Equal(pg.Envs, envs) {
		return nil
	}
	if !has && len(envs) == 0 {
		return nil
	}
	if !st.Admin(t.a.State.User) {
		out.NeedProjectAdmin = true
		return nil
	}
	if root, ok := gs.Access[st.Project]; len(envs) > 0 && (!ok || root != st.Root()) {
		// The group's admins choose the projects it reads first.
		out.NeedGroupAdmin = true
		return nil
	}
	links, next, err := t.groupSetLinks(st, pg, gs, envs)
	if err != nil {
		return err
	}
	if has {
		for _, n := range pg.Envs {
			if !slices.Contains(envs, n) {
				out.Exposed = append(out.Exposed, n)
			}
		}
	}
	var grants []*envelope.Envelope
	if len(envs) > 0 {
		g, missing, err := t.grant(next, team.GroupHolder(gs.Group), envs)
		if err != nil {
			return err
		}
		out.Missing = missing
		if g != nil && len(missing) == 0 {
			grants, out.Sent = append(grants, g), true
		}
	}
	if err := t.commit(next, links, grants); err != nil {
		return err
	}
	out.Granted = true
	return nil
}

// groupSetLinks builds the group_set links that make st grant gs envs:
// taking a recreated group's access away first. pg is the group as st has
// it, or nil.
func (t *teamCtx) groupSetLinks(st *team.State, pg *team.ProjectGroupState, gs *team.GroupState, envs []string) ([]*envelope.Envelope, *team.State, error) {
	var links []*envelope.Envelope
	next, current := st, pg != nil
	if pg != nil && pg.Root != gs.Root() {
		e, n, err := t.link(next, team.TypeGroupSet, team.GroupSetBody{Group: gs.Group, Root: pg.Root})
		if err != nil {
			return nil, nil, err
		}
		links, next, current = append(links, e), n, false
	}
	if current || len(envs) > 0 {
		e, n, err := t.link(next, team.TypeGroupSet, team.GroupSetBody{Group: gs.Group, Root: gs.Root(), Envs: envs})
		if err != nil {
			return nil, nil, err
		}
		links, next = append(links, e), n
	}
	return links, next, nil
}

// ---- sync ----

// GroupTodo is a group with machines waiting to join it.
type GroupTodo struct {
	Group string
	Joins int
}

// fulfilGroups, for every group this account administers, seals the group
// key to machines, tokens and admins that lack it, and reports join
// requests and web changes waiting for approval. When no admin can open
// the group key any more (their user keys changed), it rotates the key.
func (t *teamCtx) fulfilGroups(res *TeamSyncResult) {
	list, err := t.a.Client.Groups(t.ctx)
	if err != nil {
		res.Problems = append(res.Problems, "machine groups: "+err.Error())
		return
	}
	for _, sum := range list {
		if !sum.Admin {
			continue
		}
		if err := t.fulfilGroup(sum.ID, res); err != nil {
			res.problem(sum.ID, err)
		}
	}
}

func (t *teamCtx) fulfilGroup(id string, res *TeamSyncResult) error {
	gs, err := t.group(id)
	if err != nil || gs == nil || !gs.Admin(t.a.State.User) {
		return err
	}
	status, err := t.a.Client.GroupStatus(t.ctx, id)
	if err != nil {
		return err
	}
	if len(status.Joins) > 0 {
		res.GroupTodos = append(res.GroupTodos, GroupTodo{Group: id, Joins: len(status.Joins)})
	}
	if len(gs.KeyExposed) > 0 {
		// Someone who left still holds the key (an admin who left by
		// themselves): a new one is always safe to make.
		e, next, grants, err := t.rotateGroupKey(gs, "after "+gs.KeyExposed[0].Name+" left")
		if err == nil {
			err = t.gcommit(next, []*envelope.Envelope{e}, grants)
		}
		if err != nil {
			res.GroupRotations = append(res.GroupRotations, id)
			return err
		}
		done, _ := t.resealGroup(next)
		res.Sent = append(res.Sent, fmt.Sprintf("%s: a new group key, since %s left; sealed %s", id, gs.KeyExposed[0].Name, joinOrNone(done)))
		return nil
	}
	want := lackingKey(gs, status, t.a.Now())
	if len(want) == 0 {
		return nil
	}
	key, err := t.groupKey(gs)
	if errors.Is(err, errNoGroupKey) && len(status.AdminsWithKey) == 0 {
		// No admin can open the key: a new one fixes that for everyone.
		e, next, grants, err := t.rotateGroupKey(gs, "no admin could open the group key")
		if err != nil {
			return err
		}
		if err := t.gcommit(next, []*envelope.Envelope{e}, grants); err != nil {
			return err
		}
		done, _ := t.resealGroup(next)
		res.Sent = append(res.Sent, fmt.Sprintf("%s: a new group key (no admin could open the old one); sealed %s", id, joinOrNone(done)))
		return nil
	}
	if err != nil {
		// Another admin's device will send it.
		return nil //nolint:nilerr // see above
	}
	var grants []*envelope.Envelope
	for _, to := range want {
		if t.uncheckedWebMember(gs, to) {
			res.Unsent = append(res.Unsent, fmt.Sprintf("%s: the group key to %s (added on the web): %v", id, gs.Members[to].Login, t.checkWebPerson(gs.Members[to].Person)))
			continue
		}
		g, err := t.keyGrant(gs, to, key)
		if err != nil {
			res.problem(id, err)
			continue
		}
		grants = append(grants, g)
	}
	if len(grants) == 0 {
		return nil
	}
	if err := t.gcommit(gs, nil, grants); err != nil {
		return err
	}
	res.Sent = append(res.Sent, fmt.Sprintf("%s: the group key to %d machine(s), token(s) or admin(s)", id, len(grants)))
	return nil
}

// lackingKey lists the machines, tokens and people of gs that no grant of
// the current group key waits for. A machine blocked on the web is left
// out.
func lackingKey(gs *team.GroupState, status *wire.GroupStatus, now time.Time) []string {
	has := map[string]bool{}
	for _, c := range status.Creds {
		has[c.ID] = c.HasKey || c.Suspended
	}
	for _, u := range status.AdminsWithKey {
		has[u] = true
	}
	for _, u := range status.BlockedMembers {
		has[u] = true
	}
	var want []string
	for _, c := range gs.ActiveCreds("") {
		if !has[c.ID] && !c.Expired(now) {
			want = append(want, c.ID)
		}
	}
	for _, a := range gs.KeyHolders() {
		if !has[a.User] {
			want = append(want, a.User)
		}
	}
	return want
}

func joinOrNone(list []string) string {
	if len(list) == 0 {
		return "no projects yet"
	}
	return strings.Join(list, ", ")
}

// describeGroupLink says what a group link did, for people.
func describeGroupLink(gs *team.GroupState, l team.GroupLink) string {
	switch l.Type {
	case team.GroupWorkloadAdd:
		return "added a workload"
	case team.GroupWorkloadRekey:
		return "moved a workload to another KMS key"
	case team.GroupMachineAdd:
		return "added a machine"
	case team.GroupTokenAdd:
		return "created an enrollment token"
	case team.GroupRemove:
		return "removed a machine or token"
	case team.GroupKeyRotate:
		return "gave the group a new key"
	case team.GroupAdminAdd:
		return "added an admin"
	case team.GroupAdminRemove:
		return "removed an admin"
	case team.GroupAccessAdd, team.GroupAccessRemove:
		return "changed the projects " + gs.Group + " takes keys from"
	case team.GroupMemberAdd:
		return "added a member"
	case team.GroupMemberRemove:
		return "removed a member"
	}
	return l.Type
}
