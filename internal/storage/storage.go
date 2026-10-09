// Package storage provides durable private-file writes and cross-process locks.
package storage

import (
	"os"
	"path/filepath"

	"github.com/mscno/esec/pkg/filelock"
)

// Write replaces a private file atomically and flushes it before publication.
func Write(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".esec-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if _, err = f.Write(data); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}

// Lock excludes concurrent mutations and is released by the kernel on exit.
func Lock(home string) (func(), error) {
	return filelock.Acquire(home)
}
