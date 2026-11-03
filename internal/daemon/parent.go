package daemon

import (
	"context"
	"fmt"
	"io"
	"time"
)

// WithParent bounds an app helper's lifetime to its parent's private pipe.
// EOF (including a parent crash) cancels all work. The CLI must exit when this
// returns: a stuck keychain/plugin/network operation cannot keep an orphan alive.
func WithParent(parent context.Context, pipe io.ReadCloser, grace time.Duration, run func(context.Context) error) error {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	defer pipe.Close()
	go func() {
		_, _ = io.Copy(io.Discard, pipe)
		cancel()
	}()
	done := make(chan error, 1)
	go func() { done <- run(ctx) }()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
	}
	timer := time.NewTimer(grace)
	defer timer.Stop()
	select {
	case err := <-done:
		return err
	case <-timer.C:
		return fmt.Errorf("app helper shutdown exceeded %s", grace)
	}
}
