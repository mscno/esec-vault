package cli

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os/exec"
	"strings"
	"time"

	"github.com/mscno/esec-vault/internal/identity"
	"github.com/mscno/esec-vault/internal/keystore"
	"github.com/mscno/esec-vault/internal/remote"
)

// markDirty records that local state changed so the configured remote gets a
// push once the debounce window elapses. Failures are non-fatal: a missing
// dirty marker only means the next backup pushes.
func markDirty(reason string) {
	if err := remote.MarkDirty(reason, 0); err != nil {
		slog.Debug("could not mark push pending", "reason", reason, "error", err)
	}
}

// pushNow seals the current vault and pushes it to a remote, clearing the
// pending marker on success.
func pushNow(ctx *cliCtx, remoteName string, prune bool) (*remote.PushResult, error) {
	id, err := identity.Load(ctx.Keyring)
	if err != nil {
		return nil, err
	}
	cctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	return remote.PushNow(cctx, id, keystore.New(), remoteName, prune)
}

// maybeAutoPush performs a debounced push if one is due. It is called at the
// end of mutating commands and by the broker agent; a failure is logged but
// never blocks the user's actual request.
func maybeAutoPush(ctx *cliCtx) {
	maybeAutoPushContext(context.Background(), ctx)
}

func maybeAutoPushContext(parent context.Context, ctx *cliCtx) {
	id, err := identity.Load(ctx.Keyring)
	if err != nil {
		return
	}
	cctx, cancel := context.WithTimeout(parent, 2*time.Minute)
	defer cancel()
	res, err := remote.MaybePush(cctx, id, keystore.New(), "")
	if err != nil {
		ctx.Logger.Warn("auto-push failed; your local backup is unaffected", "error", err)
		return
	}
	if res != nil && !res.Skipped {
		ctx.Logger.Info("auto-pushed vault backup", "remote", res.Remote, "generation", res.Generation, "key", res.Key)
	}
}

// runGit runs a git command in dir and returns stdout. Git's own stderr is
// folded into the error: cmd.Output would otherwise discard it, leaving the
// user with a bare "exit status 128" and no explanation.
func runGit(dir string, args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			return "", fmt.Errorf("git %s: %w", strings.Join(args, " "), err)
		}
		return "", fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, msg)
	}
	return string(out), nil
}
