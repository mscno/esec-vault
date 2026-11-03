package daemon

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

func TestParentEOFStopsHelper(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	ready := make(chan struct{})
	stopped := make(chan error, 1)
	go func() {
		stopped <- WithParent(context.Background(), r, time.Second, func(ctx context.Context) error {
			close(ready)
			<-ctx.Done()
			return nil
		})
	}()
	<-ready
	select {
	case err := <-stopped:
		t.Fatal("helper exited while parent was alive:", err)
	default:
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-stopped:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("orphan helper survived EOF")
	}
}

func TestParentShutdownBoundsStuckWork(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	release := make(chan struct{})
	defer close(release)
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	err = WithParent(context.Background(), r, 20*time.Millisecond, func(context.Context) error {
		<-release
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "shutdown exceeded") {
		t.Fatalf("unbounded shutdown: %v", err)
	}
	if time.Since(start) > time.Second {
		t.Fatal("shutdown deadline not honored")
	}
}

func TestParentPreservesStartupFailure(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	want := errors.New("startup refused")
	err = WithParent(context.Background(), r, time.Second, func(context.Context) error { return want })
	if !errors.Is(err, want) {
		t.Fatalf("lost startup error: %v", err)
	}
}
