// Package keyring abstracts the operating system's secret store so identity
// keys can be kept out of files, and so tests can run against an in-memory
// implementation.
package keyring

import (
	"errors"
	"fmt"
	"sync"

	"github.com/mscno/esec/pkg/secretstore"
)

// ServiceName is the OS keyring service esec-vault stores under.
const ServiceName = "esec-vault"

// Entry keys used within the service.
const (
	IdentityPrivateKey     = "identity-private"
	IdentityPublicKey      = "identity-public"
	IdentitySignPrivateKey = "identity-sign-private"
)

// ErrNotFound is returned by Get when the entry does not exist.
var ErrNotFound = errors.New("secret not found in keyring")

// Keyring stores and retrieves secrets.
type Keyring interface {
	Get(key string) (string, error)
	Set(key, value string) error
	Delete(key string) error
}

// OS is the production Keyring. It uses the secret store shared with esec
// (see esec's pkg/secretstore): the OS keychain where one exists, otherwise a
// TPM-sealed or 0600 file store on headless Linux. The backend is chosen on
// the first write and recorded, so later reads find the same store.
type OS struct {
	mu    sync.Mutex
	store secretstore.Store
}

// NewOS returns the secret-store-backed keyring.
func NewOS() *OS { return &OS{} }

// Store returns the underlying secret store, selecting one if necessary.
func (o *OS) Store() (secretstore.Store, error) { return o.resolve(true) }

// Backend reports the secret store backend in use.
func (o *OS) Backend() string {
	s, err := o.resolve(false)
	if err != nil {
		return "unavailable"
	}
	return s.Backend()
}

// HardwareBound reports whether the backend protects secrets beyond file
// permissions.
func (o *OS) HardwareBound() bool {
	s, err := o.resolve(false)
	return err == nil && s.HardwareBound()
}

// Get implements Keyring.
func (o *OS) Get(key string) (string, error) {
	s, err := o.resolve(false)
	if err != nil {
		return "", fmt.Errorf("keyring get: %w", err)
	}
	v, err := s.Get(key)
	if err != nil {
		if errors.Is(err, secretstore.ErrNotFound) {
			return "", ErrNotFound
		}
		return "", fmt.Errorf("keyring get: %w", err)
	}
	return v, nil
}

// Set implements Keyring.
func (o *OS) Set(key, value string) error {
	s, err := o.resolve(true)
	if err != nil {
		return fmt.Errorf("keyring set: %w", err)
	}
	if err := s.Set(key, value); err != nil {
		return fmt.Errorf("keyring set: %w", err)
	}
	return nil
}

// Delete implements Keyring; deleting a missing entry is not an error.
func (o *OS) Delete(key string) error {
	s, err := o.resolve(false)
	if err != nil {
		return fmt.Errorf("keyring delete: %w", err)
	}
	if err := s.Delete(key); err != nil && !errors.Is(err, secretstore.ErrNotFound) {
		return fmt.Errorf("keyring delete: %w", err)
	}
	return nil
}

// Memory is an in-memory Keyring for tests.
type Memory struct {
	mu   sync.Mutex
	data map[string]string
}

// NewMemory returns an empty in-memory keyring.
func NewMemory() *Memory { return &Memory{data: map[string]string{}} }

// Get implements Keyring.
func (m *Memory) Get(key string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.data[key]
	if !ok {
		return "", ErrNotFound
	}
	return v, nil
}

// Set implements Keyring.
func (m *Memory) Set(key, value string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data[key] = value
	return nil
}

// Delete implements Keyring.
func (m *Memory) Delete(key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.data, key)
	return nil
}

// Backend implements secretstore.Store.
func (m *Memory) Backend() string { return "memory" }

// HardwareBound implements secretstore.Store.
func (m *Memory) HardwareBound() bool { return false }

// SecretStore returns the secret store behind kr, for code that needs the
// esec-side interface (for example the keyring cache key).
func SecretStore(kr Keyring) (secretstore.Store, error) {
	switch k := kr.(type) {
	case *OS:
		return k.Store()
	case secretstore.Store:
		return k, nil
	}
	return nil, fmt.Errorf("keyring %T has no secret store", kr)
}

// Describe reports the backend name and whether it is hardware bound.
func Describe(kr Keyring) (string, bool) {
	if s, ok := kr.(interface {
		Backend() string
		HardwareBound() bool
	}); ok {
		return s.Backend(), s.HardwareBound()
	}
	return "unknown", false
}

func (o *OS) resolve(write bool) (secretstore.Store, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.store != nil {
		return o.store, nil
	}
	var (
		s   secretstore.Store
		err error
	)
	if write {
		s, err = secretstore.EnsureSelected()
	} else {
		s, err = secretstore.Default()
	}
	if err != nil {
		return nil, err
	}
	if write || secretstore.Configured() {
		o.store = s
	}
	return s, nil
}
