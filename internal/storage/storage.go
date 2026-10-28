// Package storage provides durable private-file writes and cross-process locks.
package storage

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

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

// WriteKeepMode replaces a file atomically, keeping its permissions: for
// files of a repository, such as secrets files.
func WriteKeepMode(path string, data []byte) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".esec-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if err := f.Chmod(info.Mode().Perm()); err != nil {
		return err
	}
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

// LockWait is Lock, waiting up to timeout for another process to finish.
// waiting is called once, when it starts to wait.
func LockWait(home string, timeout time.Duration, waiting func()) (func(), error) {
	deadline := time.Now().Add(timeout)
	told := false
	for {
		unlock, err := filelock.Acquire(home)
		if err == nil {
			return unlock, nil
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("another esec-vault command kept the keys busy for %s: %w", timeout, err)
		}
		if !told && waiting != nil {
			waiting()
			told = true
		}
		time.Sleep(100 * time.Millisecond)
	}
}
