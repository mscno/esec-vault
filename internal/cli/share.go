package cli

// SyncCmd brings this machine up to date with the vault server: its own keys
// (vault sync), then the shared projects' (invitations to accept, keys to
// take in, and as an admin keys others are missing). The background service
// does both by itself; this shows the result at once and asks what it may
// not decide alone.
type SyncCmd struct {
	Yes bool `help:"Accept every shared project you were added to without asking"`
	// Server is the old way to ask for the first half, which sync always does.
	Server bool `hidden:""`
}

// Run implements sync.
func (c *SyncCmd) Run(ctx *cliCtx) error {
	if c.Server {
		return serverSync(ctx, true)
	}
	if err := serverSync(ctx, true); err != nil {
		return err
	}
	return (&TeamSyncCmd{Yes: c.Yes}).Run(ctx)
}
