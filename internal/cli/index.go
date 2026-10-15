package cli

import (
	"fmt"

	"github.com/mscno/esec-vault/internal/account"
)

// IndexCmd turns the published project index on or off.
type IndexCmd struct {
	State string `arg:"" optional:"" enum:"on,off," default:"" help:"on or off (default: show the current setting)"`
}

// Run implements index.
func (c *IndexCmd) Run(ctx *cliCtx) error {
	st, err := account.LoadState()
	if err != nil {
		return err
	}
	switch c.State {
	case "":
		state := "on"
		if st.NoIndex {
			state = "off"
		}
		fmt.Printf("Project index: %s. With it on, this device publishes project ids, environment names and public keys (never private keys or values) for the web UI.\n", state)
		return nil
	case "on":
		st.NoIndex = false
	case "off":
		st.NoIndex = true
	}
	if err := st.Save(); err != nil {
		return err
	}
	fmt.Printf("Project index %s; it takes effect with the next vault push from this device.\n", c.State)
	return nil
}
