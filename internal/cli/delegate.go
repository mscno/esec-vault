package cli

import (
	"fmt"
	"time"

	"github.com/mscno/esec-vault/internal/chain"
	"github.com/mscno/esec-vault/internal/safetext"
)

// DelegateCmd manages what may sign changes for you besides your devices.
type DelegateCmd struct {
	List   DelegateListCmd   `cmd:"" default:"withargs" help:"List your passkeys and whether the server signs removals (default)."`
	Server DelegateServerCmd `cmd:"" help:"Let the server sign removals made on the web pages for you (or --off)."`
	Remove DelegateRemoveCmd `cmd:"" help:"Remove a passkey."`
}

// DelegateListCmd lists delegates.
type DelegateListCmd struct{}

// Run implements delegate list.
func (c *DelegateListCmd) Run(ctx *cliCtx) error {
	a, err := openAccount(ctx)
	if err != nil {
		return err
	}
	bg, cancel := timeout(time.Minute)
	defer cancel()
	ds, err := a.Delegates(bg)
	if err != nil {
		return err
	}
	if len(ds) == 0 {
		fmt.Printf("Only your devices sign changes. Add a passkey, or let the server sign removals, on %s/account/signing\n", a.State.Server)
		return nil
	}
	for _, d := range ds {
		what := "members, access and removals"
		if d.Scope == chain.ScopeRemove {
			what = "removals only"
		}
		switch d.Kind {
		case chain.DelegateServer:
			fmt.Printf("%-18s the server          signs %s\n", d.ID, what)
		default:
			fmt.Printf("%-18s passkey %-20s signs %s; fingerprint %s\n", d.ID, safetext.Clean(d.Name), what, chain.DelegateWords(d.Delegate))
		}
	}
	return nil
}

// DelegateServerCmd lets the server sign removals.
type DelegateServerCmd struct {
	Off bool `help:"Stop the server signing removals"`
}

// Run implements delegate server.
func (c *DelegateServerCmd) Run(ctx *cliCtx) error {
	a, err := openAccount(ctx)
	if err != nil {
		return err
	}
	bg, cancel := timeout(time.Minute)
	defer cancel()
	if c.Off {
		if _, err := a.RemoveDelegate(bg, "server"); err != nil {
			return err
		}
		fmt.Println("✓ The server no longer signs anything for you.")
		return nil
	}
	if err := a.AllowServer(bg); err != nil {
		return err
	}
	fmt.Println("✓ The server now signs, for you, removals made on the web pages: taking access away from people who are not admins, and from machines. It can never add anyone or grant anything.")
	return nil
}

// DelegateRemoveCmd removes a delegate.
type DelegateRemoveCmd struct {
	Delegate string `arg:"" help:"Passkey name or delegate id"`
}

// Run implements delegate remove.
func (c *DelegateRemoveCmd) Run(ctx *cliCtx) error {
	a, err := openAccount(ctx)
	if err != nil {
		return err
	}
	bg, cancel := timeout(time.Minute)
	defer cancel()
	d, err := a.RemoveDelegate(bg, c.Delegate)
	if err != nil {
		return err
	}
	fmt.Printf("✓ Removed %s; it signs nothing for you any more.\n", safetext.Clean(d.Name))
	return nil
}
