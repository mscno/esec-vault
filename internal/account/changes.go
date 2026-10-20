package account

import (
	"context"

	"github.com/mscno/esec-vault/internal/wire"
)

// ChangeView is a web change with the name of the machine or token it
// removes, from the verified group chain.
type ChangeView struct {
	wire.Change

	Name string
}

// Changes lists the changes made on the web pages that wait for this
// account's devices to sign them. A server can invent changes, so the
// caller shows each to its person before applying it.
func (a *Account) Changes(ctx context.Context) ([]ChangeView, error) {
	if err := a.requireConfirmed(); err != nil {
		return nil, err
	}
	list, err := a.Client.Changes(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]ChangeView, 0, len(list))
	err = a.withTeam(ctx, func(t *teamCtx) error {
		for _, c := range list {
			v := ChangeView{Change: c}
			if c.Scope == wire.ScopeGroup && c.Kind == wire.ChangeRemove {
				if gs, err := t.group(c.Target); err == nil && gs != nil {
					if cr := gs.Creds[c.Subject]; cr != nil {
						v.Name = cr.Name
					}
				}
			}
			out = append(out, v)
		}
		return nil
	})
	return out, err
}

// CloseChange marks a web change applied or dismissed.
func (a *Account) CloseChange(ctx context.Context, id int64, applied bool) error {
	return a.Client.CloseChange(ctx, id, applied)
}
