// Package keyring abstracts the operating system's secret store so identity
// keys can be kept out of files, and so tests can run against an in-memory
// implementation.
package keyring

import (
	"errors"
	"fmt"
	"sync"

	keyringlib "github.com/zalando/go-keyring"
)

// ServiceName is the OS keyring service esec-vault stores under.
const ServiceName = "esec-vault"

// Entry keys used within the service.
const (
	IdentityPrivateKey = "identity-private"
	IdentityPublicKey  = "identity-public"
)

// ErrNotFound is returned by Get when the entry does not exist.
var ErrNotFound = errors.New("secret not found in keyring")

// Keyring stores and retrieves secrets.
type Keyring interface {
	Get(key string) (string, error)
	Set(key, value string) error
	Delete(key string) error
}

// OS is the production Keyring backed by the operating system's secret store.
type OS struct{}

// NewOS returns the OS-backed keyring.
func NewOS() *OS { return &OS{} }

// Get implements Keyring.
func (OS) Get(key string) (string, error) {
	s, err := keyringlib.Get(ServiceName, key)
	if err != nil {
		if errors.Is(err, keyringlib.ErrNotFound) {
			return "", ErrNotFound
		}
		return "", fmt.Errorf("keyring get: %w", err)
	}
	return s, nil
}

// Set implements Keyring.
func (OS) Set(key, value string) error {
	if err := keyringlib.Set(ServiceName, key, value); err != nil {
		return fmt.Errorf("keyring set: %w", err)
	}
	return nil
}

// Delete implements Keyring; deleting a missing entry is not an error.
func (OS) Delete(key string) error {
	if err := keyringlib.Delete(ServiceName, key); err != nil && !errors.Is(err, keyringlib.ErrNotFound) {
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
