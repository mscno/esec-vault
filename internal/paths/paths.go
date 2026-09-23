// Package paths resolves esec-vault's filesystem locations.
//
// Everything lives under a single home directory, defaulting to
// $XDG_CONFIG_HOME/esec or ~/.config/esec. Override it with ESEC_VAULT_HOME.
package paths

import (
	"os"
	"path/filepath"

	"github.com/mscno/esec"
)

// Home returns the esec-vault home directory.
func Home() string {
	if h := os.Getenv("ESEC_VAULT_HOME"); h != "" {
		return h
	}
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		return filepath.Join(xdg, "esec")
	}
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".config", "esec")
	}
	return ".esec-vault"
}

// KeyringDir returns the global keyring store directory, mirroring esec's
// resolution: $ESEC_KEYRING_DIR, else <home>/keyrings.
func KeyringDir() string {
	if dir := os.Getenv(esec.EsecKeyringDir); dir != "" {
		return dir
	}
	return filepath.Join(Home(), "keyrings")
}

// IdentityFile is where the master-wrapped identity key lives.
func IdentityFile() string { return filepath.Join(Home(), "identity.esec") }

// VaultFile is the sealed backup of all keyrings.
func VaultFile() string { return filepath.Join(Home(), "vault.esec") }

// SocketPath is the broker's unix socket. Override with ESEC_VAULT_SOCK.
func SocketPath() string {
	if s := os.Getenv("ESEC_VAULT_SOCK"); s != "" {
		return s
	}
	return filepath.Join(Home(), "agent.sock")
}

// PIDFile records the broker's process id.
func PIDFile() string { return filepath.Join(Home(), "agent.pid") }

// AuditPath is the broker's append-only audit log.
func AuditPath() string { return filepath.Join(Home(), "audit.log") }

// PolicyPath is the broker's policy file.
func PolicyPath() string { return filepath.Join(Home(), "policy.toml") }

// TrustedPath stores TOFU-pinned member fingerprints.
func TrustedPath() string { return filepath.Join(Home(), "trusted.toml") }

// EnsureHome creates the home directory with private permissions.
func EnsureHome() error {
	return os.MkdirAll(Home(), 0700)
}
