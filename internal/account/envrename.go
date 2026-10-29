package account

import (
	"context"
	"fmt"

	"github.com/mscno/esec-vault/internal/envelope"
	"github.com/mscno/esec-vault/internal/team"
)

// RenameEnv signs a name change; retries after a lost response are idempotent.
func (a *Account) RenameEnv(ctx context.Context, project, old, next, pub string) error {
	return a.withTeam(ctx, func(t *teamCtx) error {
		st, err := t.requireAdmin(project)
		if err != nil {
			return err
		}
		if st.CurrentEnv(old) == next {
			if e := st.Envs[next]; e != nil && e.PublicKey == pub {
				return nil
			}
			return fmt.Errorf("renamed environment key changed; sync before retrying")
		}
		e := st.Envs[old]
		if e == nil || e.PublicKey != pub {
			return fmt.Errorf("local environment does not match the vault; sync first")
		}
		link, state, err := t.link(st, team.TypeEnvRename, team.EnvRenameBody{Old: old, New: next})
		if err != nil {
			return err
		}
		if err := t.commit(state, []*envelope.Envelope{link}, nil); err != nil {
			return err
		}
		if held := t.pins.Held[project]; held != nil {
			if key, ok := held[old]; ok {
				held[next] = key
				delete(held, old)
			}
		}
		return nil
	})
}
