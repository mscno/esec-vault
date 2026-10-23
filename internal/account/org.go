package account

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/mscno/esec-vault/internal/client"
	"github.com/mscno/esec-vault/internal/envelope"
	"github.com/mscno/esec-vault/internal/kms"
	"github.com/mscno/esec-vault/internal/team"
	"github.com/mscno/esec-vault/internal/wire"
)

// Organisations, from a device's side. Like groups, every organisation
// chain is verified from its first link and pinned in teams.toml, so the
// server can neither roll one back nor hide it once this device saw it.
// This device applies an organisation's chain wherever it signs in one of
// its projects or groups: it wraps group keys only with approved KMS keys,
// adds only the people the settings allow, and takes out of what it
// administers the people who left the organisation.
//
// A server can make up a chain for an organisation, signed by accounts of
// its own, and anyone can set one up for a name nothing is named after yet.
// So what a chain lets this device do by itself, rather than only refuse,
// waits until the chain is anchored: this account signed a link of it
// (created it, or acted in it as an admin), or its person compared its
// fingerprint with an admin's (esec vault org trust). Until then the chain
// only adds checks.

// org fetches and verifies an organisation chain and moves its pin. It
// returns nil, nil for an organisation without a chain.
func (t *teamCtx) org(org string) (*team.OrgState, error) {
	org = strings.ToLower(org)
	if os, ok := t.orgs[org]; ok {
		return os, nil
	}
	if err := team.ValidOrg(org); err != nil {
		return nil, err
	}
	oc, err := t.a.Client.OrgChain(t.ctx, org)
	if client.IsCode(err, wire.ErrNotFound) {
		if _, pinned := t.pins.Orgs[org]; pinned {
			return nil, fmt.Errorf("%w: the server no longer shows the organisation %s, which this device saw", team.ErrRollback, org)
		}
		t.orgs[org] = nil
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("the organisation %s: %w", org, err)
	}
	t.give(oc.Chains)
	os, err := team.VerifyOrg(org, oc.Links, t.chains)
	if err != nil {
		return nil, fmt.Errorf("the server's chain for the organisation %s does not verify: %w", org, err)
	}
	if os.LastTime.After(t.a.Now().Add(time.Hour)) {
		return nil, fmt.Errorf("the organisation %s has a link dated in the future (%s); check this machine's clock", org, os.LastTime.Format(time.RFC3339))
	}
	pin, ok := t.pins.Orgs[org]
	describe := func(i uint64) (string, string) { return os.Links[i].Signer, team.DescribeOrgLink(os, os.Links[i]) }
	if err := t.checkPin(pin, ok, org, "organisation", os, os.Hashes, describe); err != nil {
		return nil, err
	}
	t.opin(os)
	return os, nil
}

func (t *teamCtx) opin(os *team.OrgState) {
	t.pins.Orgs[os.Org] = Pin{Seq: os.Seq, Head: os.Head(), Root: os.Root()}
	t.orgs[os.Org] = os
	// A link this account signed with its user key was signed by one of
	// its devices, which signs in a chain only once it trusts it (below).
	if os.SignedWithUserKey(t.a.State.User) {
		t.pins.OrgTrust[os.Org] = os.Root()
	}
}

// trusted reports whether this device anchored os: it signed in it, or its
// person confirmed its fingerprint.
func (t *teamCtx) trusted(os *team.OrgState) bool {
	return os != nil && t.pins.OrgTrust[os.Org] == os.Root()
}

// errUntrusted says how to anchor an organisation.
func errUntrusted(os *team.OrgState) error {
	return fmt.Errorf("this device has not confirmed the organisation %s yet: compare its fingerprint (%s) with an admin's, then run: esec vault org trust %s", os.Org, os.Words(), os.Org)
}

// orgOf returns the verified organisation of a project or group id, or nil
// when it has no chain.
func (t *teamCtx) orgOf(id string) (*team.OrgState, error) { return t.org(team.OrgOf(id)) }

// requireOrgAdmin loads an organisation this account administers.
func (t *teamCtx) requireOrgAdmin(org string) (*team.OrgState, error) {
	os, err := t.org(org)
	if err != nil {
		return nil, err
	}
	if os == nil {
		return nil, fmt.Errorf("%s has no organisation chain yet; set it up with 'esec vault org create %s'", org, org)
	}
	if !os.Admin(t.a.State.User) {
		return nil, fmt.Errorf("only an admin of the organisation %s can do that", org)
	}
	return os, nil
}

// olink signs the next link of an organisation. Past its first link, only
// in a chain this device anchored: signing in one anchors it on this
// account's other devices.
func (t *teamCtx) olink(os *team.OrgState, typ string, body any) (*envelope.Envelope, *team.OrgState, error) {
	if os.Seq > 0 && !t.trusted(os) {
		return nil, nil, errUntrusted(os)
	}
	e, err := os.NewLink(typ, body, t.a.Now(), t.a.State.User, t.own.UKeyVersion, t.own.Seq, t.id.Sign)
	if err != nil {
		return nil, nil, err
	}
	next, err := os.Next(e, t.chains)
	return e, next, err
}

// ocommit sends organisation links and pins the new state.
func (t *teamCtx) ocommit(next *team.OrgState, links ...*envelope.Envelope) error {
	for _, e := range links {
		t.pins.Signed[e.Hash()] = true
	}
	if _, err := t.a.Client.OrgCommit(t.ctx, next.Org, &wire.OrgCommit{Links: links}); err != nil {
		return err
	}
	t.opin(next)
	return nil
}

// checkOrgPerson applies the rules of id's organisation to someone about to
// be added to the project or group id.
func (t *teamCtx) checkOrgPerson(id string, p team.Person, verified string) error {
	os, err := t.orgOf(id)
	if err != nil || os == nil {
		return err
	}
	return os.CheckPerson(p.User, p.Login, verified)
}

// checkOrgKMS refuses a KMS key the organisation of group did not approve
// for it.
func (t *teamCtx) checkOrgKMS(group string, k kms.Key) error {
	os, err := t.orgOf(group)
	if err != nil || os == nil {
		return err
	}
	return os.CheckKMS(k, group)
}

// checkNamespace refuses, early, a new project or group named after an
// organisation this account is not in; the server refuses it too.
func (t *teamCtx) checkNamespace(id string) error {
	org := team.OrgOf(id)
	notIn := fmt.Errorf("%s is an organisation, and you are not in it: an admin of %s adds you first (esec vault org add %s %s)", org, org, org, t.a.State.Login)
	os, err := t.org(org)
	if client.IsCode(err, wire.ErrForbidden) {
		// Only those outside it may not read its chain.
		return notIn
	}
	if err != nil || os == nil {
		return err
	}
	if !os.In(t.a.State.User) {
		return notIn
	}
	return nil
}

// orgNote says, for a project this account was added to, whether its
// creator belongs to the organisation it is named after: anyone can create
// a project under any name where an organisation has no chain.
func (t *teamCtx) orgNote(st *team.State) (note string, warn bool) {
	os, err := t.orgOf(st.Project)
	if err != nil || os == nil || len(st.Links) == 0 {
		return "", false
	}
	creator := st.Links[0].Signer
	login := loginOf(st, creator)
	if !t.trusted(os) {
		return fmt.Sprintf("%s has an organisation chain this device has not confirmed (fingerprint %s), so it cannot tell whether %s, who created it, belongs to it.", os.Org, os.Words(), login), !os.In(creator)
	}
	if os.In(creator) {
		return fmt.Sprintf("%s created it and belongs to the organisation %s (checked against its signed chain).", login, os.Org), false
	}
	if _, left := os.Left(creator); left {
		return fmt.Sprintf("%s created it, and has since left the organisation %s.", login, os.Org), false
	}
	return fmt.Sprintf("Careful: %s created it and is not in the organisation %s, so it may not be %s's project.", login, os.Org, os.Org), true
}

// ---- operations ----

// Orgs lists the organisations this account belongs to.
func (a *Account) Orgs(ctx context.Context) ([]wire.OrgSummary, error) {
	if err := a.requireConfirmed(); err != nil {
		return nil, err
	}
	return a.Client.Orgs(ctx)
}

// OrgView is a verified organisation with the policy the server enforces.
type OrgView struct {
	State  *team.OrgState
	Policy *wire.OrgPolicy
	// Left lists, for people who left, where they still read keys among
	// what this account can see.
	Left map[string][]string
	// Trusted says this device anchored the chain.
	Trusted bool
}

// Org verifies an organisation. Its state is nil when it has no chain.
func (a *Account) Org(ctx context.Context, org string) (*OrgView, error) {
	org = strings.ToLower(org)
	if err := team.ValidOrg(org); err != nil {
		return nil, err
	}
	out := &OrgView{Left: map[string][]string{}}
	err := a.withTeam(ctx, func(t *teamCtx) error {
		os, err := t.org(org)
		if err != nil {
			return err
		}
		out.State = os
		if os != nil {
			plan, _ := t.orgRemovals(os, false, false)
			out.Trusted = t.trusted(os)
			for _, r := range plan {
				if r.Login != "" {
					out.Left[r.Login] = append(out.Left[r.Login], r.ID)
				}
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if out.Policy, err = a.Client.OrgPolicy(ctx, org); err != nil {
		return nil, err
	}
	return out, nil
}

// CreateOrg starts an organisation's chain with this account as its admin.
// Once it has one, only its people create projects and groups named after
// it.
func (a *Account) CreateOrg(ctx context.Context, org string) (*team.OrgState, error) {
	org = strings.ToLower(org)
	if err := team.ValidOrg(org); err != nil {
		return nil, err
	}
	var out *team.OrgState
	err := a.withTeam(ctx, func(t *teamCtx) error {
		existing, err := t.org(org)
		if err != nil && !client.IsCode(err, wire.ErrForbidden) {
			return err
		}
		if existing != nil || err != nil {
			return fmt.Errorf("the organisation %s exists already; ask one of its admins to add you", org)
		}
		e, next, err := t.olink(team.NewOrg(org), team.OrgInit, team.OrgInitBody{Creator: team.Person{User: a.State.User, Login: a.State.Login, Root: t.own.Root()}})
		if err != nil {
			return err
		}
		if err := t.ocommit(next, e); err != nil {
			return err
		}
		out = next
		return nil
	})
	return out, err
}

// AddOrgPerson adds login to an organisation, as a member or an admin,
// checked like a new project member.
func (a *Account) AddOrgPerson(ctx context.Context, org, login string, admin bool, accountKey string) (*AddResult, error) {
	if err := team.ValidLogin(login); err != nil {
		return nil, err
	}
	var out *AddResult
	err := a.withTeam(ctx, func(t *teamCtx) error {
		os, err := t.requireOrgAdmin(org)
		if err != nil {
			return err
		}
		person, cs, proof, err := t.lookupPerson(login)
		if err != nil {
			return err
		}
		if os.Admin(person.User) || (!admin && os.Member(person.User)) {
			return fmt.Errorf("%s is already in %s", person.Login, os.Org)
		}
		verified, err := checkPerson(person, proof, cs, accountKey)
		if err != nil {
			return err
		}
		typ, body := team.OrgMemberAdd, any(team.OrgMemberAddBody{Member: person, Verified: verified})
		if admin {
			typ, body = team.OrgAdminAdd, team.OrgAdminAddBody{Admin: person, Verified: verified}
		}
		e, next, err := t.olink(os, typ, body)
		if err != nil {
			return err
		}
		out = &AddResult{Login: person.Login, AccountWords: cs.AccountWords(), Verified: verified}
		return t.ocommit(next, e)
	})
	return out, err
}

// OrgRemoval is one place someone who left an organisation was taken out
// of, or still has to be.
type OrgRemoval struct {
	Login string
	// Kind is HoldsProject, HoldsGroupMember or HoldsGroupAdmin; ID the
	// project or group.
	Kind string
	ID   string
	// Done says this device took them out; Err why it could not.
	Done bool
	Err  error
	// Rotate lists the environments ("project env") to rotate after.
	Rotate []string
}

// Line describes r for people.
func (r OrgRemoval) Line() string {
	switch {
	case r.Login == "":
		return fmt.Sprintf("could not check %s: %v", r.ID, r.Err)
	case r.Err != nil:
		return fmt.Sprintf("%s is still in %s: %v", r.Login, r.ID, r.Err)
	case !r.Done:
		return fmt.Sprintf("%s is still in %s", r.Login, r.ID)
	case len(r.Rotate) > 0:
		return fmt.Sprintf("Took %s out of %s; rotate %s: they may still hold the keys.", r.Login, r.ID, strings.Join(r.Rotate, ", "))
	}
	return fmt.Sprintf("Took %s out of %s.", r.Login, r.ID)
}

// errAdminRole explains an admin's role the cascade leaves alone.
var errAdminRole = errors.New("they are an admin there; remove them on a device (esec vault access revoke, or group remove-admin)")

// RemoveOrgPerson removes login from an organisation (this account's own
// login: leaves it), and takes them out of every project and group of it
// this account administers. The devices of the other admins do the same
// for theirs on their next sync.
func (a *Account) RemoveOrgPerson(ctx context.Context, org, login, reason string) ([]OrgRemoval, error) {
	return a.removeOrgPerson(ctx, org, login, reason, false)
}

// removeOrgPerson is RemoveOrgPerson; with narrow, as changes --yes signs
// it, it refuses an admin of the organisation and takes the person out of
// nothing they administer.
func (a *Account) removeOrgPerson(ctx context.Context, org, login, reason string, narrow bool) ([]OrgRemoval, error) {
	var out []OrgRemoval
	err := a.withTeam(ctx, func(t *teamCtx) error {
		os, err := t.org(org)
		if err != nil {
			return err
		}
		if os == nil {
			return fmt.Errorf("%s has no organisation chain", org)
		}
		p, ok := os.PersonByLogin(login)
		if !ok {
			return fmt.Errorf("%s is not in %s", login, os.Org)
		}
		self := p.User == a.State.User
		if !self && !os.Admin(a.State.User) {
			return fmt.Errorf("only an admin of %s can remove others", os.Org)
		}
		if narrow && os.Admin(p.User) {
			return fmt.Errorf("%s is an admin of %s; removing an admin is signed only after asking", p.Login, os.Org)
		}
		typ, body := team.OrgMemberRemove, any(team.OrgMemberRemoveBody{User: p.User, Reason: clipReason(reason), KeepAdminRoles: narrow})
		if os.Admin(p.User) {
			typ, body = team.OrgAdminRemove, team.OrgAdminRemoveBody{User: p.User, Reason: clipReason(reason)}
		}
		e, next, err := t.olink(os, typ, body)
		if err != nil {
			return err
		}
		if err := t.ocommit(next, e); err != nil {
			return err
		}
		if self {
			return nil
		}
		out, err = t.orgRemovals(next, true, narrow)
		return err
	})
	return out, err
}

// orgRemovals finds, among the projects and groups of os this account can
// see, the people who left os and still read keys there, added before they
// left (someone added again since was added on purpose). With apply, it
// takes them out of those this account administers, if this device
// anchored os. An admin's role there is taken away only by a removal its
// signer made on a device, and never with narrow.
func (t *teamCtx) orgRemovals(os *team.OrgState, apply, narrow bool) ([]OrgRemoval, error) { //nolint:gocyclo // projects, then groups
	former := os.Former()
	if len(former) == 0 {
		return nil, nil
	}
	apply = apply && t.trusted(os)
	leftAt := map[string]time.Time{}
	keepAdmin := map[string]bool{}
	for _, p := range former {
		if p.User == t.a.State.User {
			// Someone leaving keeps nothing by their own devices' doing:
			// the others' devices take them out.
			continue
		}
		at, _ := os.Left(p.User)
		leftAt[p.User] = at
		keepAdmin[p.User] = narrow || os.KeepsAdminRoles(p.User)
	}
	if len(leftAt) == 0 {
		return nil, nil
	}
	var out []OrgRemoval
	projects, err := t.a.Client.Projects(t.ctx)
	if err != nil {
		return nil, err
	}
	for _, sum := range projects {
		if team.OrgOf(sum.ID) != os.Org {
			continue
		}
		st, err := t.state(sum.ID)
		if err != nil {
			out = append(out, OrgRemoval{ID: sum.ID, Err: err})
			continue
		}
		if st == nil || st.Archived {
			continue
		}
		for _, m := range st.ActiveMembers() {
			at, left := leftAt[m.User]
			// Added after they left (links name seconds: not in the same
			// one) means added on purpose.
			if !left || m.AddedSeq == 0 || st.Links[m.AddedSeq-1].CTime.After(at) {
				continue
			}
			r := OrgRemoval{Login: m.Login, Kind: HoldsProject, ID: st.Project}
			mine := apply && st.Admin(t.a.State.User)
			switch {
			case m.Admin && keepAdmin[m.User]:
				if mine {
					r.Err = errAdminRole
				}
			case mine:
				envs := st.Access(m.User)
				e, next, err := t.link(st, team.TypeMemberRemove, team.MemberRemoveBody{User: m.User, Reason: "left the organisation " + os.Org})
				if err == nil {
					err = t.commit(next, []*envelope.Envelope{e}, nil)
				}
				if err == nil {
					st = next
					r.Done = true
					for _, env := range envs {
						r.Rotate = append(r.Rotate, st.Project+" "+env)
					}
				}
				r.Err = err
			}
			out = append(out, r)
		}
	}
	groups, err := t.a.Client.Groups(t.ctx)
	if err != nil {
		return nil, err
	}
	for _, sum := range groups {
		if team.OrgOf(sum.ID) != os.Org {
			continue
		}
		gs, err := t.group(sum.ID)
		if err != nil {
			out = append(out, OrgRemoval{ID: sum.ID, Err: err})
			continue
		}
		if gs == nil {
			continue
		}
		for _, p := range gs.KeyHolders() {
			at, left := leftAt[p.User]
			if !left || p.AddedSeq == 0 || gs.Links[p.AddedSeq-1].CTime.After(at) {
				continue
			}
			kind := HoldsGroupMember
			if gs.Admin(p.User) {
				kind = HoldsGroupAdmin
			}
			r := OrgRemoval{Login: p.Login, Kind: kind, ID: gs.Group}
			mine := apply && gs.Admin(t.a.State.User)
			switch {
			case kind == HoldsGroupAdmin && keepAdmin[p.User]:
				if mine {
					r.Err = errAdminRole
				}
			case mine:
				next, rotate, err := t.removeFromGroup(gs, p, "left the organisation "+os.Org)
				if err == nil {
					gs, r.Done, r.Rotate = next, true, rotate
				}
				r.Err = err
			}
			out = append(out, r)
		}
	}
	return out, nil
}

// removeFromGroup takes an admin or member out of a group, gives the group
// a new key, and returns the environments to rotate ("project env").
func (t *teamCtx) removeFromGroup(gs *team.GroupState, p *team.GroupAdminState, reason string) (*team.GroupState, []string, error) {
	typ, body := team.GroupMemberRemove, any(team.GroupMemberRemoveBody{User: p.User, Reason: clipReason(reason)})
	if gs.Admin(p.User) {
		typ, body = team.GroupAdminRemove, team.GroupAdminRemoveBody{User: p.User, Reason: clipReason(reason)}
	}
	e, next, err := t.glink(gs, typ, body)
	if err != nil {
		return nil, nil, err
	}
	re, rotated, grants, err := t.rotateGroupKey(next, "after "+p.Login+" "+reason)
	if err != nil {
		return nil, nil, err
	}
	if err := t.gcommit(rotated, []*envelope.Envelope{e, re}, grants); err != nil {
		return nil, nil, err
	}
	t.resealGroup(rotated)
	var out []string
	for _, pr := range t.groupProjects(rotated) {
		for _, env := range pr.Rotate {
			out = append(out, pr.Project+" "+env)
		}
	}
	return rotated, out, nil
}

// syncOrgs takes the people who left an organisation out of what this
// account administers in it, for every organisation it can see.
func (t *teamCtx) syncOrgs(res *TeamSyncResult) {
	seen := map[string]bool{}
	var ids []string
	if list, err := t.a.Client.Projects(t.ctx); err == nil {
		for _, p := range list {
			ids = append(ids, p.ID)
		}
	}
	if list, err := t.a.Client.Groups(t.ctx); err == nil {
		for _, g := range list {
			ids = append(ids, g.ID)
		}
	}
	for _, id := range ids {
		org := team.OrgOf(id)
		if seen[org] {
			continue
		}
		seen[org] = true
		os, err := t.org(org)
		if err != nil {
			res.problem("organisation "+org, err)
			continue
		}
		if os == nil {
			continue
		}
		if !t.trusted(os) {
			res.OrgUntrusted = append(res.OrgUntrusted, os.Org+" "+os.Words())
		}
		done, err := t.orgRemovals(os, true, false)
		if err != nil {
			res.problem("organisation "+org, err)
			continue
		}
		for _, r := range done {
			if r.Done || r.Err != nil {
				res.OrgRemovals = append(res.OrgRemovals, r.Line())
			}
		}
	}
}

// TrustOrg anchors an organisation's chain on this device, once its person
// compared its fingerprint (words, when given, must match).
func (a *Account) TrustOrg(ctx context.Context, org, words string) (*team.OrgState, error) {
	var out *team.OrgState
	err := a.withTeam(ctx, func(t *teamCtx) error {
		os, err := t.org(org)
		if err != nil {
			return err
		}
		if os == nil {
			return fmt.Errorf("%s has no organisation chain", org)
		}
		if words != "" && normalizeWords(words) != os.Words() {
			return fmt.Errorf("those are not the fingerprint words of the chain the server shows for %s: do not trust it, and tell its admins", os.Org)
		}
		t.pins.OrgTrust[os.Org] = os.Root()
		out = os
		return nil
	})
	return out, err
}

// ApproveKMS approves a KMS key for the workloads of an organisation's
// groups. The caller read its public half from the KMS itself.
func (a *Account) ApproveKMS(ctx context.Context, org string, k team.OrgKMSKey) error {
	return a.withTeam(ctx, func(t *teamCtx) error {
		os, err := t.requireOrgAdmin(org)
		if err != nil {
			return err
		}
		slices.Sort(k.Groups)
		k.Groups = slices.Compact(k.Groups)
		e, next, err := t.olink(os, team.OrgKMSAdd, team.OrgKMSAddBody{Key: k})
		if err != nil {
			return err
		}
		return t.ocommit(next, e)
	})
}

// WithdrawKMS withdraws an approved KMS key: no new workload uses it.
// Workloads that use it keep working until they are moved to another key.
func (a *Account) WithdrawKMS(ctx context.Context, org, name, reason string) ([]string, error) {
	var users []string
	err := a.withTeam(ctx, func(t *teamCtx) error {
		os, err := t.requireOrgAdmin(org)
		if err != nil {
			return err
		}
		k, ok := os.KMSByName(name)
		if !ok {
			return fmt.Errorf("%s has no key %s", os.Org, name)
		}
		e, next, err := t.olink(os, team.OrgKMSRemove, team.OrgKMSRemoveBody{Name: name, Reason: clipReason(reason)})
		if err != nil {
			return err
		}
		if err := t.ocommit(next, e); err != nil {
			return err
		}
		users = t.kmsUsers(os.Org, k.Key)
		return nil
	})
	return users, err
}

// kmsUsers lists the workloads ("group name") of org that use key, among
// the groups this account can see.
func (t *teamCtx) kmsUsers(org string, key kms.Key) []string {
	var out []string
	list, err := t.a.Client.Groups(t.ctx)
	if err != nil {
		return nil
	}
	for _, g := range list {
		if team.OrgOf(g.ID) != org {
			continue
		}
		gs, err := t.group(g.ID)
		if err != nil || gs == nil {
			continue
		}
		for _, c := range gs.ActiveCreds(team.KindWorkload) {
			if c.KMS != nil && c.KMS.Fingerprint() == key.Fingerprint() {
				out = append(out, g.ID+" "+c.Name)
			}
		}
	}
	return out
}

// SetOrgSettings replaces an organisation's settings.
func (a *Account) SetOrgSettings(ctx context.Context, org string, st team.OrgSettings) error {
	return a.withTeam(ctx, func(t *teamCtx) error {
		os, err := t.requireOrgAdmin(org)
		if err != nil {
			return err
		}
		if os.Settings == st {
			return nil
		}
		e, next, err := t.olink(os, team.OrgSettingsSet, team.OrgSettingsBody{Settings: st})
		if err != nil {
			return err
		}
		return t.ocommit(next, e)
	})
}

// OrgKMSKey returns an organisation's approved key by name, verified.
func (a *Account) OrgKMSKey(ctx context.Context, org, name string) (*team.OrgKMSState, error) {
	var out *team.OrgKMSState
	err := a.withTeam(ctx, func(t *teamCtx) error {
		os, err := t.org(org)
		if err != nil {
			return err
		}
		if os == nil {
			return fmt.Errorf("%s has no organisation chain, so no approved keys", org)
		}
		if !t.trusted(os) {
			return errUntrusted(os)
		}
		k, ok := os.KMSByName(name)
		if !ok {
			return fmt.Errorf("%s has no approved key %s (esec vault org kms %s)", os.Org, name, os.Org)
		}
		out = k
		return nil
	})
	return out, err
}

// FlyAppResult says what setting up a Fly.io app did.
type FlyAppResult struct {
	Ref *team.WorkloadRef
	// Key is the approved key its group key is wrapped with.
	Key          *team.OrgKMSState
	CreatedGroup bool
	// Granted lists "project envs" the group reads now; Pending what an
	// admin of the project still has to agree to.
	Granted []string
	Pending []string
}

// AddFlyApp sets up a Fly.io app to read keys with no secret: a group for
// it (created when missing, under the organisation), what the group reads,
// and a workload bound to the app, wrapped with an approved KMS key.
func (a *Account) AddFlyApp(ctx context.Context, org string, app wire.FlyApp) (*FlyAppResult, error) { //nolint:gocyclo // checks, then each step in turn
	org = strings.ToLower(org)
	if team.OrgOf(app.Group) != org {
		return nil, fmt.Errorf("the group %s is not in %s", app.Group, org)
	}
	if err := team.ValidGroup(app.Group); err != nil {
		return nil, err
	}
	policy := &team.OIDCPolicy{Provider: team.ProviderFly, FlyOrg: app.FlyOrg, FlyApps: []string{app.App}}
	if err := policy.Validate(); err != nil {
		return nil, err
	}
	out := &FlyAppResult{}
	key, err := a.OrgKMSKey(ctx, org, app.KMS)
	if err != nil {
		return nil, err
	}
	out.Key = key
	if len(key.Groups) > 0 && !slices.Contains(key.Groups, app.Group) {
		return nil, fmt.Errorf("%s approved the key %s only for %s", org, key.Name, strings.Join(key.Groups, ", "))
	}
	exists := false
	err = a.withTeam(ctx, func(t *teamCtx) error {
		gs, err := t.group(app.Group)
		if err != nil && !client.IsCode(err, wire.ErrForbidden) {
			return err
		}
		if err != nil {
			return fmt.Errorf("the group %s exists, and you are not its admin", app.Group)
		}
		exists = gs != nil
		return nil
	})
	if err != nil {
		return nil, err
	}
	if !exists {
		if _, err := a.CreateGroup(ctx, app.Group); err != nil {
			return nil, err
		}
		out.CreatedGroup = true
	}
	for _, rd := range app.Reads {
		res, err := a.GrantGroup(ctx, app.Group, rd.Project, rd.Envs)
		if err != nil {
			return out, fmt.Errorf("%s reading %s: %w", app.Group, rd.Project, err)
		}
		line := rd.Project + " " + strings.Join(rd.Envs, ",")
		if res.NeedProjectAdmin || res.NeedGroupAdmin {
			out.Pending = append(out.Pending, line)
		} else {
			out.Granted = append(out.Granted, line)
		}
	}
	var view *GroupView
	if view, err = a.Group(ctx, app.Group); err != nil {
		return out, err
	}
	for _, c := range view.State.ActiveCreds(team.KindWorkload) {
		if c.OIDC != nil && c.OIDC.FlyOrg == app.FlyOrg && slices.Equal(c.OIDC.FlyApps, []string{app.App}) {
			if c.EncPub != key.Key.Fingerprint() {
				if _, err := a.RekeyWorkloads(ctx, app.Group, []string{c.Name}, key.Key); err != nil {
					return out, err
				}
			}
			out.Ref = &team.WorkloadRef{Server: a.State.Server, Group: app.Group, Root: view.State.Root(), ID: c.ID}
			return out, nil
		}
	}
	out.Ref, err = a.AddWorkload(ctx, app.Group, app.App, key.Key, policy)
	return out, err
}
