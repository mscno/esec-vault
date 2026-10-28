package account

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/mscno/esec-vault/internal/envelope"
	"github.com/mscno/esec-vault/internal/team"
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
	Project string
	// Members lists the people added to the new project; Skipped those who
	// were not, with why.
	Members, Skipped []string
	// Groups lists the groups that read the new project; GroupsLeft those
	// whose admins grant it again; Machines the machines to create again.
	Groups, GroupsLeft, Machines []string
	// Missing lists environments this device had no key for.
	Missing []string
}

// MoveProject moves a project to a new id: a new chain with the same
// environment keys (the encrypted files stay as they are) and the same
// people, who get the keys sealed to them again, then the old chain
// archived, naming the new one. Members' devices follow the move on their
// own: an admin of a project they accepted named it. Machines are bound to
// the old project and are created again; groups whose admins this account
// is not grant the new project again.
func (a *Account) MoveProject(ctx context.Context, project, next string) (*MoveResult, error) {
	if err := team.ValidProject(next); err != nil {
		return nil, err
	}
	out := &MoveResult{Project: next}
	err := a.withTeam(ctx, func(t *teamCtx) error {
		old, err := t.requireAdmin(project)
		if err != nil {
			return err
		}
		if old.Archived {
			return fmt.Errorf("%s is archived; unarchive it first", project)
		}
		existing, err := t.state(next)
		if err != nil && !errors.Is(err, errNotMember) {
			return err
		}
		if existing != nil || err != nil {
			return fmt.Errorf("%s exists already", next)
		}
		if err := a.copyKeyring(project, next); err != nil {
			return err
		}
		have := t.localKeys(old)
		body := team.InitBody{Creator: team.Person{User: a.State.User, Login: a.State.Login, Root: t.own.Root()}}
		for _, n := range old.EnvNames() {
			if _, ok := have[n]; !ok {
				out.Missing = append(out.Missing, n)
			}
			body.Envs = append(body.Envs, old.Envs[n].Env)
		}
		if len(out.Missing) > 0 {
			return fmt.Errorf("this device has no current key for %s of %s; move it from a device that has them all", strings.Join(out.Missing, ", "), project)
		}
		e, st, err := t.link(team.New(next), team.TypeInit, body)
		if err != nil {
			return err
		}
		links, st, err := t.moveMembers(old, st, out)
		if err != nil {
			return err
		}
		if err := t.commit(st, append([]*envelope.Envelope{e}, links...), nil); err != nil {
			return err
		}
		t.pins.Accepted[next] = true
		for _, env := range body.Envs {
			t.pins.hold(next, env.Name, env.PublicKey)
		}
		if err := t.sendAll(st); err != nil {
			return err
		}
		if err := t.ackOwn(st); err != nil {
			return err
		}
		if err := t.archiveMoved(old, st, out); err != nil {
			return err
		}
		return t.moveGroups(old, next, out)
	})
	return out, err
}

// copyKeyring copies this device's keyring of a project to its new name,
// unless one is there.
func (a *Account) copyKeyring(project, next string) error {
	entries, err := a.KS.Read(project)
	if err != nil {
		return fmt.Errorf("this device has no keyring for %s: %w", project, err)
	}
	if _, err := a.KS.Read(next); !errors.Is(err, os.ErrNotExist) {
		return err
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

// archiveMoved archives old, naming st as where it moved, and lists its
// machines to create again.
func (t *teamCtx) archiveMoved(old, st *team.State, out *MoveResult) error {
	for _, m := range old.ActiveMachines() {
		out.Machines = append(out.Machines, m.Name+" ("+strings.Join(m.Envs, ",")+")")
	}
	e, archived, err := t.link(old, team.TypeArchive, team.ArchiveBody{Reason: "moved to " + st.Project, Successor: &team.ProjectRef{Project: st.Project, Root: st.Root()}})
	if err != nil {
		return err
	}
	return t.commit(archived, []*envelope.Envelope{e}, nil)
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
