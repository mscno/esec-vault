package cli

import (
	"encoding/hex"
	"fmt"
	"os"

	"github.com/mscno/esec-vault/internal/identity"
	"github.com/mscno/esec-vault/internal/keystore"
	"github.com/mscno/esec-vault/internal/share"
)

// ShareCmd seals project keys to team members.
type ShareCmd struct {
	To   []string `help:"GitHub logins to share with" name:"to" required:"" sep:","`
	Envs []string `help:"Environments to share (default: all)" name:"env" sep:","`
}

// Run implements share.
func (c *ShareCmd) Run(ctx *cliCtx) error {
	id, err := identity.Load(ctx.Keyring)
	if err != nil {
		return err
	}
	cwd, err := getwd()
	if err != nil {
		return err
	}
	written, err := share.Share(cwd, keystore.New(), id, c.To, c.Envs, nil, "")
	if err != nil {
		return err
	}
	for _, w := range written {
		fmt.Println("Wrote", w)
	}
	fmt.Println("Commit and push these files; recipients run 'esec vault sync'.")
	return nil
}

// SyncCmd opens committed share blobs into the global keyring store.
type SyncCmd struct{}

// Run implements sync.
func (c *SyncCmd) Run(ctx *cliCtx) error {
	id, err := identity.Load(ctx.Keyring)
	if err != nil {
		return err
	}
	cwd, err := getwd()
	if err != nil {
		return err
	}
	synced, err := share.Sync(cwd, keystore.New(), id, confirm)
	if err != nil {
		return err
	}
	for _, s := range synced {
		fmt.Println("Synced", s)
	}
	return nil
}

// helpers

func getwd() (string, error) { return os.Getwd() }

func hexDecode(s string) ([]byte, error) { return hex.DecodeString(s) }
