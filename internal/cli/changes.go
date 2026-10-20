package cli

import (
	"context"
	"fmt"
	"time"

	"github.com/mscno/esec-vault/internal/account"
	"github.com/mscno/esec-vault/internal/safetext"
	"github.com/mscno/esec-vault/internal/wire"
)

// ChangesCmd signs the changes made on the web pages.
type ChangesCmd struct {
	Yes  bool `help:"Sign removals without asking (anything that gives access is always asked)"`
	List bool `help:"Only list the changes; sign nothing"`
	JSON bool `help:"List the changes as JSON (implies --list), for scripts and agents"`
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
	if c.JSON {
		return printJSON(changesJSON(list))
	}
	if len(list) == 0 {
		fmt.Println("No changes made on the web wait to be signed.")
		return nil
	}
	if c.List {
		for _, ch := range list {
			printChange(ch)
		}
		fmt.Println("\nSign them with: esec vault changes")
		return nil
	}
	return signChanges(bg, a, list, c.Yes)
}

// printChange shows one change made on the web.
func printChange(ch account.ChangeView) {
	fmt.Printf("\n#%d %s asked on the web, %s:\n", ch.ID, ch.AskedBy(), ch.Created.Local().Format("2006-01-02 15:04")) //nolint:gosmopolitan // shown to the local user
	for _, l := range ch.DescribeLines() {
		fmt.Println("  " + l)
	}
}

// signChanges shows each change and, when the person agrees, signs it on
// this device. The server stores the changes and could have invented any
// of them, so nothing that gives access is signed unasked.
func signChanges(ctx context.Context, a *account.Account, list []account.ChangeView, yesRemovals bool) error {
	unsigned := 0
	for _, ch := range list {
		printChange(ch)
		question := "Sign it?"
		if ch.Kind == wire.ChangeDelegateAdd {
			question = "Does the page that made it show the same fingerprint, and do you want it?"
		}
		if (!yesRemovals || !ch.Removes()) && !confirm(question) {
			if unanswered {
				// Nothing to ask: never sign, nor dismiss, on a guess.
				unsigned++
				continue
			}
			if confirm("Dismiss it?") {
				if err := a.CloseChange(ctx, ch.ID, false); err != nil {
					return err
				}
				fmt.Println("  Dismissed.")
			}
			continue
		}
		lines, err := a.ApplyChange(ctx, ch)
		if err != nil {
			fmt.Println("  ! " + err.Error())
			continue
		}
		for _, l := range lines {
			fmt.Println("  ✓ " + safetext.Clean(l))
		}
		if err := a.CloseChange(ctx, ch.ID, true); err != nil {
			return err
		}
	}
	if unsigned > 0 {
		unanswered = false // the message says it all
		return fmt.Errorf("%d change(s) not signed: nothing answered on stdin. Run 'esec vault changes' in a terminal, or pipe in the answers; --yes signs only removals", unsigned)
	}
	return nil
}
