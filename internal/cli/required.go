package cli

import (
	"strings"

	"github.com/mscno/esec-vault/internal/account"
)

// Enrollment, recovery, diagnostics and stopping services must remain usable
// without a login. Workloads authenticate to the server with their own keys.
func requiresLogin(command string) bool {
	for _, path := range []string{
		"login", "logout", "setup", "init", "status", "doctor", "recover",
		"identity recover", "identity migrate",
		"daemon", "lock", "uninstall", "agent stop",
		"machine join", "machine run", "machine env", "machine whoami",
	} {
		if command == path || strings.HasPrefix(command, path+" ") {
			return false
		}
	}
	return true
}

func requireLogin(ctx *cliCtx, command string) error {
	if !requiresLogin(command) {
		return nil
	}
	return account.RequireLogin(ctx.Keyring)
}
