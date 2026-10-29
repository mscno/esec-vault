package account

import (
	"context"
	"fmt"
	"strings"

	"github.com/mscno/esec-vault/internal/team"
)

// SetOrgOwner changes signed governance without changing daily admin rights.
func (a *Account) SetOrgOwner(ctx context.Context, org, login string, owner bool) error {
	return a.withTeam(ctx, func(t *teamCtx) error {
		os, err := t.requireOrgAdmin(org)
		if err != nil {
			return err
		}
		if !os.Owner(a.State.User) {
			return fmt.Errorf("only a tenant owner may change ownership")
		}
		p, ok := os.PersonByLogin(login)
		if !ok {
			return fmt.Errorf("%s is not in %s", login, org)
		}
		e, next, err := t.olink(os, team.OrgOwnerSet, team.OrgOwnerBody{User: p.User, Owner: owner})
		if err != nil {
			return err
		}
		return t.ocommit(next, e)
	})
}

// SetTenantProfile renames a handle, never the tenant or its signed history.
func (a *Account) SetTenantProfile(ctx context.Context, org, name, display string) error {
	return a.withTeam(ctx, func(t *teamCtx) error {
		os, err := t.requireOrgAdmin(org)
		if err != nil {
			return err
		}
		if !os.Owner(a.State.User) {
			return fmt.Errorf("only a tenant owner may rename it")
		}
		n, err := a.Client.Namespace(ctx, org)
		if err != nil {
			return err
		}
		if name == "" {
			name = n.Name
		}
		if display == "" {
			display = n.DisplayName
		}
		e, next, err := t.olink(os, team.OrgProfileSet, team.OrgProfileBody{TenantID: n.TenantID, Namespace: strings.ToLower(name), DisplayName: display})
		if err != nil {
			return err
		}
		return t.ocommit(next, e)
	})
}
