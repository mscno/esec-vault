package daemon

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/mscno/esec-vault/internal/account"
	"github.com/mscno/esec-vault/internal/verify"
)

// verifyEvery is how often the daemon checks that no key can be lost.
const verifyEvery = 24 * time.Hour

// verifyLoop runs esec vault verify once a day, quietly, and notifies only
// when a key is in fewer than two places, lost, or serves two projects.
// ESEC_VAULT_VERIFY=off turns it off.
func (s *Server) verifyLoop(ctx context.Context) {
	if strings.EqualFold(os.Getenv("ESEC_VAULT_VERIFY"), "off") {
		return
	}
	// Let the first sync settle before the first check.
	first := time.NewTimer(10 * time.Minute)
	defer first.Stop()
	select {
	case <-ctx.Done():
		return
	case <-first.C:
	}
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		if last, err := verify.LoadLast(); err == nil && time.Since(last.At) >= verifyEvery {
			s.verifyOnce(ctx)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (s *Server) verifyOnce(ctx context.Context) {
	opts := verify.Options{History: true, Server: true, Backup: true, Keyring: s.Keyring,
		OpenAccount: func() (*account.Account, error) { return account.Open(s.Keyring, daemonUI{s}) }}
	rep, err := verify.Run(ctx, opts)
	if rep == nil {
		s.Logger.Warn("verify", "error", err)
		return
	}
	_ = verify.SaveLast(rep, err, time.Now().UTC())
	if rep.OK() {
		s.Logger.Info("verify: every key is in at least two places", "keys", len(rep.Keys))
		return
	}
	s.Logger.Warn("verify found keys that need attention", "problems", rep.Problems, "lost", rep.Lost)
	title := "esec: keys need attention"
	if rep.Lost > 0 {
		title = "esec: keys are lost"
	}
	Notifier(title, fmt.Sprintf("%d key(s) need attention: run esec vault verify", rep.Problems))
}
