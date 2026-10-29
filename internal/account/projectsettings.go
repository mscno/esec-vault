package account

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"os"
	"strings"

	"github.com/mscno/esec-vault/internal/envelope"
	"github.com/mscno/esec-vault/internal/team"
	"github.com/mscno/esec-vault/internal/wire"
)

// Project settings: archiving a project, moving it to a new id, deleting
// an archived one from the server.

// Archive archives a project (successor nil) or records where it moved.
func (a *Account) Archive(ctx context.Context, project, reason string) error {
	return a.withTeam(ctx, func(t *teamCtx) error {
		st, err := t.requireAdmin(project)
		if err != nil {
			return err
		}
		e, next, err := t.link(st, team.TypeArchive, team.ArchiveBody{Reason: clipReason(reason)})
		if err != nil {
			return err
		}
		return t.commit(next, []*envelope.Envelope{e}, nil)
	})
}

// Unarchive makes an archived project active again.
func (a *Account) Unarchive(ctx context.Context, project, reason string) error {
	return a.withTeam(ctx, func(t *teamCtx) error {
		st, err := t.requireAdmin(project)
		if err != nil {
			return err
		}
		e, next, err := t.link(st, team.TypeUnarchive, team.UnarchiveBody{Reason: clipReason(reason)})
		if err != nil {
			return err
		}
		return t.commit(next, []*envelope.Envelope{e}, nil)
	})
}

// DeleteProject deletes an archived project's data from the server.
func (a *Account) DeleteProject(ctx context.Context, project string) error {
	if err := a.requireConfirmed(); err != nil {
		return err
	}
	return a.Client.DeleteProject(ctx, project)
}

// MoveResult describes a project moved to a new id.
type MoveResult struct {
	Project     string
	CrossTenant bool
	// Members lists the people added to the new project; Skipped those who
	// were not, with why.
	Members, Skipped []string
	// Groups lists the groups that read the new project; GroupsLeft those
	// whose admins grant it again; Machines the machines to create again.
	Groups, GroupsLeft, Machines []string
	// Missing lists environments this device had no key for.
	Missing []string
}

// MoveProject atomically creates a new chain and archives the source, with
// reciprocal root references. Keys stay the same. Within a tenant people
// are retained; across tenants only the transferring admin is added, and
// no source group is reconnected. Old readers may still possess keys: a
// transfer is not a substitute for rotation and re-encryption.
func (a *Account) MoveProject(ctx context.Context, project, next string) (*MoveResult, error) { //nolint:gocyclo // one ordered preflight, signed atomic move and local key-delivery sequence
	if err := team.ValidProject(next); err != nil {
		return nil, err
	}
	out := &MoveResult{Project: next}
	out.CrossTenant = team.OrgOf(project) != team.OrgOf(next)
	err := a.withTeam(ctx, func(t *teamCtx) error {
		old, err := t.requireAdmin(project)
		if err != nil {
			return err
		}
		if old.Archived {
			return fmt.Errorf("%s is archived; unarchive it first", project)
		}
		from, err := a.Client.Namespace(ctx, team.OrgOf(project))
		if err != nil {
			return err
		}
		to, err := a.Client.Namespace(ctx, team.OrgOf(next))
		if err != nil {
			return err
		}
		out.CrossTenant = from.TenantID != to.TenantID
		if out.CrossTenant {
			os, err := t.org(team.OrgOf(project))
			if err != nil {
				return err
			}
			if (os != nil && !os.Owner(a.State.User)) || (os == nil && from.Owner != a.State.User) {
				return fmt.Errorf("source tenant owner authorization is required")
			}
		}
		if err := t.checkMoveDestination(next, out.CrossTenant); err != nil {
			return err
		}
		links, st, err := t.moveDestination(old, out)
		if err != nil {
			return err
		}
		archive, archived, err := t.link(old, team.TypeArchive, team.ArchiveBody{Reason: "moved to " + next, Successor: &team.ProjectRef{Project: next, Root: st.Root()}})
		if err != nil {
			return err
		}
		// Copy locally only after all preflight checks, before committing so a
		// failed network response cannot strand keys at an archived source.
		if err := a.copyKeyring(project, next); err != nil {
			return err
		}
		for _, l := range append(links, archive) {
			t.pins.Signed[l.Hash()] = true
		}
		if err := a.Client.TransferProject(ctx, project, &wire.ProjectTransfer{Destination: next, Links: links, Archive: archive}); err != nil {
			return err
		}
		t.pin(st)
		t.pin(archived)
		for _, m := range old.ActiveMachines() {
			out.Machines = append(out.Machines, m.Name+" ("+strings.Join(m.Envs, ",")+")")
		}
		t.pins.Accepted[next] = true
		for _, env := range st.Envs {
			t.pins.hold(next, env.Name, env.PublicKey)
		}
		if err := t.sendAll(st); err != nil {
			return err
		}
		if err := t.ackOwn(st); err != nil {
			return err
		}
		if out.CrossTenant {
			return nil
		}
		return t.moveGroups(old, next, out)
	})
	return out, err
}

func (t *teamCtx) checkMoveDestination(next string, cross bool) error {
	if err := t.checkNamespace(next); err != nil {
		return err
	}
	if cross {
		names, err := t.a.Client.Namespaces(t.ctx)
		if err != nil {
			return err
		}
		personal := false
		for _, n := range names {
			if n.Name == team.OrgOf(next) && n.Kind == "personal" && n.Owner == t.a.State.User {
				personal = true
			}
		}
		if !personal {
			os, err := t.requireOrgAdmin(team.OrgOf(next))
			if err != nil {
				return err
			}
			if !t.trusted(os) {
				return errUntrusted(os)
			}
			if !os.Owner(t.a.State.User) {
				return fmt.Errorf("destination tenant owner authorization is required; use project transfer --recipient OWNER to request acceptance")
			}
		}
	}
	existing, err := t.state(next)
	if err != nil && !errors.Is(err, errNotMember) {
		return err
	}
	if existing != nil || err != nil {
		return fmt.Errorf("%s exists already", next)
	}
	return nil
}

func (t *teamCtx) moveDestination(old *team.State, out *MoveResult) ([]*envelope.Envelope, *team.State, error) {
	have := t.localKeys(old)
	body := team.InitBody{Creator: team.Person{User: t.a.State.User, Login: t.a.State.Login, Root: t.own.Root()}, Predecessor: &team.ProjectRef{Project: old.Project, Root: old.Root()}}
	for _, n := range old.EnvNames() {
		if _, ok := have[n]; !ok {
			out.Missing = append(out.Missing, n)
		}
		body.Envs = append(body.Envs, old.Envs[n].Env)
	}
	if len(out.Missing) > 0 {
		return nil, nil, fmt.Errorf("this device has no current key for %s of %s; move it from a device that has them all", strings.Join(out.Missing, ", "), old.Project)
	}
	e, st, err := t.link(team.New(out.Project), team.TypeInit, body)
	if err != nil {
		return nil, nil, err
	}
	links := []*envelope.Envelope{e}
	if !out.CrossTenant {
		members, next, err := t.moveMembers(old, st, out)
		return append(links, members...), next, err
	}
	for _, m := range old.ActiveMembers() {
		if m.User != t.a.State.User {
			out.Skipped = append(out.Skipped, m.Login+": access is not copied across tenants")
		}
	}
	for _, g := range old.ActiveGroups() {
		out.GroupsLeft = append(out.GroupsLeft, g.Group)
	}
	return links, st, nil
}

// copyKeyring copies this device's keyring of a project to its new name,
// unless one is there.
func (a *Account) copyKeyring(project, next string) error {
	entries, err := a.KS.Read(project)
	if err != nil {
		return fmt.Errorf("this device has no keyring for %s: %w", project, err)
	}
	if existing, err := a.KS.Read(next); !errors.Is(err, os.ErrNotExist) {
		if err != nil {
			return err
		}
		if maps.Equal(existing, entries) {
			return nil
		}
		return fmt.Errorf("a different local keyring exists for %s; refusing to overwrite it", next)
	}
	return a.KS.Write(next, entries, false)
}

// moveMembers adds old's members to st, the new chain, each checked as
// before: a member checked on the web is checked by this device now.
func (t *teamCtx) moveMembers(old, st *team.State, out *MoveResult) ([]*envelope.Envelope, *team.State, error) {
	var links []*envelope.Envelope
	for _, m := range old.ActiveMembers() {
		if m.User == t.a.State.User {
			continue
		}
		verified := m.Verified
		if verified == team.VerifiedWeb || verified == "" {
			// Not checked by a device yet (or the creator): check now.
			if err := t.checkWebMember(m); err != nil {
				out.Skipped = append(out.Skipped, m.Login+": "+err.Error())
				continue
			}
			verified = team.VerifiedGitHubSSH
		}
		e, next, err := t.link(st, team.TypeMemberAdd, team.MemberAddBody{Member: m.Person, Admin: m.Admin, Envs: m.Envs, Verified: verified})
		if err != nil {
			return nil, nil, err
		}
		links, st = append(links, e), next
		out.Members = append(out.Members, m.Login)
	}
	return links, st, nil
}

// sendAll seals st's keys to every member but this account.
func (t *teamCtx) sendAll(st *team.State) error {
	var grants []*envelope.Envelope
	for _, m := range st.ActiveMembers() {
		if m.User == t.a.State.User {
			continue
		}
		g, _, err := t.grant(st, m.User, st.Access(m.User))
		if err != nil {
			return err
		}
		if g != nil {
			grants = append(grants, g)
		}
	}
	if len(grants) == 0 {
		return nil
	}
	return t.commit(st, nil, grants)
}

// moveGroups lets the groups that read old read next, where this account
// administers them.
func (t *teamCtx) moveGroups(old *team.State, next string, out *MoveResult) error {
	for _, pg := range old.ActiveGroups() {
		gs, err := t.group(pg.Group)
		if err != nil || gs == nil || !gs.Admin(t.a.State.User) {
			out.GroupsLeft = append(out.GroupsLeft, pg.Group+" ("+strings.Join(pg.Envs, ",")+")")
			continue
		}
		res := &GrantResult{}
		if err := t.groupSide(gs, t.states[next], true, res); err != nil {
			return err
		}
		if err := t.projectSide(t.groups[pg.Group], t.states[next], pg.Envs, res); err != nil {
			return err
		}
		out.Groups = append(out.Groups, pg.Group)
	}
	return nil
}

// followMoves accepts, for this device, a project that a project it
// accepted moved to: an admin of the accepted project named it, with the
// root of its chain.
func (t *teamCtx) followMoves(st *team.State) bool {
	// Not into a project this device has keys of already: the person says
	// whether those are the same project.
	if _, err := t.a.KS.Read(st.Project); err == nil {
		return false
	}
	for p := range t.pins.Accepted {
		if p == st.Project {
			continue
		}
		old, err := t.state(p)
		if err != nil || old == nil || old.Successor == nil {
			continue
		}
		if old.Successor.Project == st.Project && old.Successor.Root == st.Root() {
			t.pins.Accepted[st.Project] = true
			return true
		}
	}
	return false
}

// Lines says what a move did, one line each.
func (r *MoveResult) Lines(from string) []string {
	out := []string{fmt.Sprintf("Moved %s to %s, with %d member(s); %s is archived, pointing there.", from, r.Project, len(r.Members), from)}
	if r.CrossTenant {
		out = append(out, "Cross-tenant transfer: source people, groups and machines were not granted destination access. Existing readers may still hold the old environment keys; rotate them and re-encrypt files to revoke that access.")
	}
	for _, s := range r.Skipped {
		out = append(out, "Not added: "+s)
	}
	if len(r.Groups) > 0 {
		out = append(out, "These groups read it: "+strings.Join(r.Groups, ", ")+".")
	}
	if len(r.GroupsLeft) > 0 {
		out = append(out, "Their admins let these groups read it again (esec vault access grant GROUP --project "+r.Project+"): "+strings.Join(r.GroupsLeft, ", ")+".")
	}
	if len(r.Machines) > 0 {
		out = append(out, "Create these machines again for "+r.Project+" (esec vault machine create): "+strings.Join(r.Machines, ", ")+".")
	}
	out = append(out, "In the repository, set project = \""+r.Project+"\" in esec.toml and commit it.")
	return out
}
