package account

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/mscno/esec-vault/internal/envelope"
	"github.com/mscno/esec-vault/internal/kms"
	"github.com/mscno/esec-vault/internal/team"
)

// AddWorkload adds a workload to a group: an identity with no secret, bound
// to an OIDC policy (such as a Fly.io app), whose group key this device
// wraps with key, an external KMS key the workload's identity may decrypt
// with. It returns the workload's descriptor, which is plain configuration.
func (a *Account) AddWorkload(ctx context.Context, id, name string, key kms.Key, policy *team.OIDCPolicy) (*team.WorkloadRef, error) {
	if err := key.Validate(); err != nil {
		return nil, err
	}
	if policy == nil {
		return nil, fmt.Errorf("a workload needs an OIDC policy, such as --fly-org and --fly-app: it has no secret of its own")
	}
	var out *team.WorkloadRef
	err := a.withTeam(ctx, func(t *teamCtx) error {
		gs, err := t.requireGroupAdmin(id)
		if err != nil {
			return err
		}
		if err := t.checkOrgKMS(id, key); err != nil {
			return err
		}
		for _, c := range gs.ActiveCreds(team.KindWorkload) {
			if c.Name == name {
				return fmt.Errorf("%s already has a workload named %s", id, name)
			}
		}
		gkey, err := t.groupKey(gs)
		if err != nil {
			return err
		}
		wid, err := team.NewWorkloadID()
		if err != nil {
			return err
		}
		k := key
		c := team.Credential{ID: wid, Name: name, EncPub: k.Fingerprint(), KMS: &k, OIDC: policy, Created: a.Now().UTC().Truncate(time.Second)}
		e, next, err := t.glink(gs, team.GroupWorkloadAdd, team.GroupWorkloadAddBody{Workload: c})
		if err != nil {
			return err
		}
		cs, _ := next.Cred(wid)
		g, err := team.NewWorkloadKeyGrant(next, a.State.User, t.own.UKeyVersion, t.id.Sign, cs, gkey, a.Now())
		if err != nil {
			return err
		}
		if err := t.gcommit(next, []*envelope.Envelope{e}, []*envelope.Envelope{g}); err != nil {
			return err
		}
		out = &team.WorkloadRef{Server: a.State.Server, Group: id, Root: next.Root(), ID: wid}
		return nil
	})
	return out, err
}

// RekeyWorkloads moves a group's workloads (those named, or all) to
// another KMS key, and wraps the group key for them with it: their ids and
// descriptors stay. It returns the names of the workloads moved.
func (a *Account) RekeyWorkloads(ctx context.Context, id string, names []string, key kms.Key) ([]string, error) {
	if err := key.Validate(); err != nil {
		return nil, err
	}
	var out []string
	err := a.withTeam(ctx, func(t *teamCtx) error {
		gs, err := t.requireGroupAdmin(id)
		if err != nil {
			return err
		}
		if err := t.checkOrgKMS(id, key); err != nil {
			return err
		}
		gkey, err := t.groupKey(gs)
		if err != nil {
			return err
		}
		var links, grants []*envelope.Envelope
		next := gs
		for _, c := range gs.ActiveCreds(team.KindWorkload) {
			if len(names) > 0 && !slices.Contains(names, c.Name) {
				continue
			}
			if c.EncPub == key.Fingerprint() {
				continue
			}
			e, n, err := t.glink(next, team.GroupWorkloadRekey, team.GroupWorkloadRekeyBody{ID: c.ID, KMS: key})
			if err != nil {
				return err
			}
			links, next = append(links, e), n
			out = append(out, c.Name)
		}
		if len(links) == 0 {
			return nil
		}
		for _, name := range out {
			for _, c := range next.ActiveCreds(team.KindWorkload) {
				if c.Name != name {
					continue
				}
				g, err := team.NewWorkloadKeyGrant(next, a.State.User, t.own.UKeyVersion, t.id.Sign, c, gkey, a.Now())
				if err != nil {
					return err
				}
				grants = append(grants, g)
			}
		}
		return t.gcommit(next, links, grants)
	})
	return out, err
}
