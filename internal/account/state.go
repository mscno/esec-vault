// Package account connects this machine to an esec vault server: sign-in,
// device enrollment and approval, vault sync, revocation, key rotation and
// SSH-agent unlock slots. It verifies everything the server returns against
// the user's signed device chain.
package account

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/pelletier/go-toml/v2"

	"github.com/mscno/esec-vault/internal/chain"
	"github.com/mscno/esec-vault/internal/paths"
	"github.com/mscno/esec-vault/internal/storage"
)

// SessionTokenName is the secret store entry for the server session token.
const SessionTokenName = "session-token"

// State is this machine's account record, stored in account.toml. It holds
// no secrets: the session token and keys are in the secret store.
type State struct {
	Server     string `toml:"server"`
	User       string `toml:"user"`
	GitHubID   int64  `toml:"github_id"`
	Login      string `toml:"login"`
	DeviceID   string `toml:"device_id"`
	DeviceName string `toml:"device_name"`
	// IdentityFromAccount records that the local identity was created for or
	// installed from this account, so a newer user key may replace it.
	IdentityFromAccount bool `toml:"identity_from_account"`

	Chain  ChainPin  `toml:"chain"`
	Vault  VaultPin  `toml:"vault"`
	Events EventsPin `toml:"events"`
}

// ChainPin is the last verified chain head.
type ChainPin struct {
	Seq          uint64 `toml:"seq"`
	Head         string `toml:"head"`
	Root         string `toml:"root"`
	AccountWords string `toml:"account_words"`
	UKeyVersion  uint64 `toml:"ukey_version"`
}

// VaultPin is the last vault version this machine applied or pushed.
type VaultPin struct {
	Version    uint64    `toml:"version"`
	Generation uint64    `toml:"generation"`
	SHA256     string    `toml:"sha256"`
	SyncedAt   time.Time `toml:"synced_at"`
	// Conflicts lists entries left unmerged by a non-interactive sync.
	Conflicts []string `toml:"conflicts,omitempty"`
}

// EventsPin is the last server event the daemon handled.
type EventsPin struct {
	Last int64 `toml:"last"`
}

// Path returns the account.toml location.
func Path() string { return filepath.Join(paths.Home(), "account.toml") }

// ErrNotLoggedIn is returned when this machine has no account.
var ErrNotLoggedIn = errors.New("not signed in to a vault server; run 'esec vault login <server>'")

// LoadState reads account.toml. A missing file yields ErrNotLoggedIn.
func LoadState() (*State, error) {
	data, err := os.ReadFile(Path())
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotLoggedIn
	}
	if err != nil {
		return nil, err
	}
	var s State
	if err := toml.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("invalid %s: %w", Path(), err)
	}
	if s.Server == "" || s.User == "" || s.DeviceID == "" {
		return nil, ErrNotLoggedIn
	}
	return &s, nil
}

// Save writes account.toml (0600, atomic).
func (s *State) Save() error {
	if err := paths.EnsureHome(); err != nil {
		return err
	}
	data, err := toml.Marshal(s)
	if err != nil {
		return err
	}
	return storage.Write(Path(), data)
}

// Remove deletes account.toml.
func Remove() error {
	if err := os.Remove(Path()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// pin records a verified chain head.
func (s *State) pin(st *chain.State) {
	s.Chain = ChainPin{Seq: st.Seq, Head: st.Head(), Root: st.Root(), AccountWords: st.AccountWords(), UKeyVersion: st.UKeyVersion}
}

// checkPin rejects a chain that rolls back or forks from the pin.
func (s *State) checkPin(st *chain.State) error {
	if s.Chain.Root != "" && st.Root() != s.Chain.Root {
		return fmt.Errorf("%w: the account's first link changed", chain.ErrRollback)
	}
	return st.CheckPin(s.Chain.Seq, s.Chain.Head)
}
