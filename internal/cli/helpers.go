package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/mscno/esec-vault/internal/account"
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
	ks := keystore.New()
	ks.Locked = ctx.keyringLocked
	return remote.PushNow(cctx, id, ks, remoteName, prune)
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

// errNoKeyStore is returned by storeKeysNow when keys have no second place
// to go: neither a vault server nor a backup destination.
var errNoKeyStore = errors.New("no vault server and no backup destination (esec vault login, or esec vault remote add)")

// storeKeysNow puts this device's keys in a second place before anything is
// encrypted to a new one: the vault server when signed in, else the default
// backup destination. It waits for the upload.
func storeKeysNow(ctx *cliCtx) error {
	if err := syncServerNow(ctx); !errors.Is(err, account.ErrNotLoggedIn) {
		return err
	}
	cfg, err := remote.Load()
	if err != nil {
		return err
	}
	if cfg.Default == "" {
		return errNoKeyStore
	}
	_, err = pushNow(ctx, "", false)
	return err
}

// syncServerNow syncs the vault with the server and waits. It returns
// account.ErrNotLoggedIn when this machine is not signed in.
func syncServerNow(ctx *cliCtx) error {
	if ctx == nil || ctx.Keyring == nil {
		return account.ErrNotLoggedIn
	}
	a, err := openAccount(ctx)
	if err != nil {
		return err
	}
	bg, cancel := timeout(2 * time.Minute)
	defer cancel()
	res, err := a.Sync(bg, account.SyncOptions{})
	if err != nil {
		return err
	}
	if len(res.Conflicts) > 0 {
		return account.ErrConflicts
	}
	return nil
}

// requireStored is storeKeysNow for commands about to encrypt files to new
// keys: a failed upload stops them, so no file is encrypted to a key that
// exists on this device alone. Having no second place at all only warns
// (doctor reports it); offline skips the upload on purpose.
func requireStored(ctx *cliCtx, offline bool, what string) error {
	if offline {
		fmt.Fprintf(os.Stderr, "! %s: --offline, so the new keys are on this device only until it syncs (esec vault sync --server, or esec vault backup --push)\n", what)
		return nil
	}
	err := storeKeysNow(ctx)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, errNoKeyStore):
		fmt.Fprintf(os.Stderr, "! %s: the new keys are on this device only: %v\n", what, err)
		return nil
	}
	return fmt.Errorf("%s: the new keys are stored here but could not be stored elsewhere, so nothing was encrypted to them yet: %w; fix that and run the command again (it keeps the keys), or pass --offline", what, err)
}
