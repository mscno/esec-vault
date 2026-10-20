package cli

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/mscno/esec-vault/internal/account"
	"github.com/mscno/esec-vault/internal/safetext"
	"github.com/mscno/esec-vault/internal/wire"
)

// ChangesCmd signs the changes made on the web pages.
type ChangesCmd struct {
	Yes bool `help:"Sign removals without asking (anything that gives access is always asked)"`
}

// Run implements changes.
func (c *ChangesCmd) Run(ctx *cliCtx) error {
	a, err := openAccount(ctx)
	if err != nil {
		return err
	}
	bg, cancel := timeout(10 * time.Minute)
	defer cancel()
	list, err := a.Changes(bg)
	if err != nil {
		return err
	}
	if len(list) == 0 {
		fmt.Println("No changes made on the web wait to be signed.")
		return nil
	}
	return signChanges(bg, a, list, c.Yes)
}

// signChanges shows each change and, when the person agrees, applies and
// signs it on this device. The server stores the changes and could have
// invented any of them, so nothing that gives access is signed unasked.
func signChanges(ctx context.Context, a *account.Account, list []account.ChangeView, yesRemovals bool) error {
	for _, ch := range list {
		fmt.Printf("\n%s asked on the web, %s, in %s: %s.\n", safetext.Clean(ch.By), ch.Created.Local().Format("2006-01-02 15:04"), ch.Target, describeChange(ch)) //nolint:gosmopolitan // shown to the local user
		if (!yesRemovals || !removes(ch)) && !confirm("Sign it?") {
			if confirm("Dismiss it?") {
				if err := a.CloseChange(ctx, ch.ID, false); err != nil {
					return err
				}
				fmt.Println("  Dismissed.")
			}
			continue
		}
		if err := applyChange(ctx, a, ch); err != nil {
			fmt.Println("  ! " + err.Error())
			continue
		}
		if err := a.CloseChange(ctx, ch.ID, true); err != nil {
			return err
		}
	}
	return nil
}

// removes reports whether a change only takes access away.
func removes(ch account.ChangeView) bool {
	switch ch.Kind {
	case wire.ChangeRemove, wire.ChangeMemberRemove:
		return true
	case wire.ChangeAccess:
		return len(ch.Envs) == 0
	}
	return false
}

func describeChange(ch account.ChangeView) string {
	reads := "nothing"
	if len(ch.Envs) > 0 {
		reads = strings.Join(ch.Envs, ", ")
	}
	if ch.Admin {
		reads = "every environment, as an admin"
	}
	switch ch.Kind {
	case wire.ChangeAccess:
		if len(ch.Envs) == 0 {
			return "stop reading " + ch.Project
		}
		return "read " + reads + " of " + ch.Project
	case wire.ChangeRemove:
		name := ch.Name
		if name == "" {
			name = ch.Subject
		}
		return "remove " + safetext.Clean(name) + " (already blocked by the server)"
	case wire.ChangeMemberAdd:
		return "add " + safetext.Clean(ch.Subject) + ", who reads " + reads
	case wire.ChangeMemberSet:
		return "let " + safetext.Clean(ch.Subject) + " read " + reads
	case wire.ChangeMemberRemove:
		return "remove " + safetext.Clean(ch.Subject)
	}
	return ch.Kind
}

func applyChange(ctx context.Context, a *account.Account, ch account.ChangeView) error {
	switch {
	case ch.Scope == wire.ScopeGroup && ch.Kind == wire.ChangeAccess:
		res, err := a.GrantGroup(ctx, ch.Target, ch.Project, ch.Envs)
		if err != nil {
			return err
		}
		printGrant(ch.Target, ch.Project, ch.Envs, res)
	case ch.Scope == wire.ScopeGroup && ch.Kind == wire.ChangeRemove:
		res, err := a.RemoveCred(ctx, ch.Target, ch.Subject, "removed on the web", false)
		if err != nil {
			return err
		}
		printRemoved(ch.Target, res)
	case ch.Scope == wire.ScopeProject && ch.Kind == wire.ChangeMemberAdd:
		res, err := a.AddMember(ctx, ch.Target, ch.Subject, ch.Admin, ch.Envs, "")
		if errors.Is(err, account.ErrNoProof) {
			return fmt.Errorf("%w. Add them by hand with the account key words they read to you: esec vault team add %s --account-key '...' --project %s", err, ch.Subject, ch.Target)
		}
		if err != nil {
			return err
		}
		fmt.Printf("  ✓ Added %s to %s (checked with %s; account key %s).\n", safetext.Clean(res.Login), ch.Target, verifiedText(res.Verified), res.AccountWords)
		if len(res.Missing) > 0 {
			fmt.Printf("  This device has no current key for %s; an admin's device that has it sends it.\n", strings.Join(res.Missing, ", "))
		}
	case ch.Scope == wire.ScopeProject && ch.Kind == wire.ChangeMemberSet:
		res, err := a.UpdateMember(ctx, ch.Target, ch.Subject, ch.Admin, ch.Envs)
		if err != nil {
			return err
		}
		fmt.Printf("  ✓ %s now reads %s.\n", safetext.Clean(ch.Subject), describeReads(ch))
		printRotations(res.Exposed, ch.Subject+" can no longer read")
	case ch.Scope == wire.ScopeProject && ch.Kind == wire.ChangeMemberRemove:
		envs, err := a.RemoveMember(ctx, ch.Target, ch.Subject, "removed on the web")
		if err != nil {
			return err
		}
		fmt.Printf("  ✓ Removed %s from %s.\n", safetext.Clean(ch.Subject), ch.Target)
		printRotations(envs, ch.Subject+" could read")
	default:
		return fmt.Errorf("this version cannot sign a %s change; update esec-vault", ch.Kind)
	}
	return nil
}

func describeReads(ch account.ChangeView) string {
	if ch.Admin {
		return "every environment, as an admin"
	}
	if len(ch.Envs) == 0 {
		return "nothing"
	}
	return strings.Join(ch.Envs, ", ")
}
