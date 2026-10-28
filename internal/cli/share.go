package cli

import (
	"encoding/hex"
	"fmt"
	"os"

	"github.com/mscno/esec-vault/internal/identity"
	"github.com/mscno/esec-vault/internal/keystore"
	"github.com/mscno/esec-vault/internal/share"
)

// SyncCmd opens committed share blobs into the global keyring store, or with
// --server syncs the vault with the vault server.
type SyncCmd struct {
	Server bool `help:"Sync your vault with the vault server instead of importing committed shares"`
}

// Run implements sync.
func (c *SyncCmd) Run(ctx *cliCtx) error {
	if c.Server {
		return serverSync(ctx, true)
	}
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
