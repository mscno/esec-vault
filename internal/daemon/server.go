package daemon

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/mscno/esec-vault/internal/account"
	"github.com/mscno/esec-vault/internal/chain"
	"github.com/mscno/esec-vault/internal/keystore"
	"github.com/mscno/esec-vault/internal/notify"
	"github.com/mscno/esec-vault/internal/wire"
)

// Notifier shows desktop notifications; tests replace it.
var Notifier = notify.Send

// daemonUI is the non-interactive account.UI of the daemon.
type daemonUI struct{ s *Server }

func (u daemonUI) Printf(format string, args ...any) {
	u.s.Logger.Info("vault server", "message", fmt.Sprintf(format, args...))
}
func (daemonUI) Confirm(string) bool { return false }
func (daemonUI) Secret(string) (string, error) {
	return "", errors.New("the daemon cannot prompt")
}

// serverLoop keeps the vault in sync with the vault server while this machine
// is signed in: it syncs on start, after local key changes, and whenever the
// server reports a change, and it notifies about devices joining the account.
func (s *Server) serverLoop(ctx context.Context) {
	retry := time.Minute
	seenPending := map[string]bool{}
	for ctx.Err() == nil {
		a, err := account.Open(s.Keyring, daemonUI{s})
		if errors.Is(err, account.ErrNotLoggedIn) {
			s.sleep(ctx, s.Interval)
			continue
		}
		if err != nil {
			s.Logger.Warn("vault server unavailable", "error", err)
			s.sleep(ctx, retry)
			continue
		}
		before := a.State.Chain.Seq
		if err := s.serverSync(ctx, a); err != nil && ctx.Err() == nil {
			s.Logger.Warn("vault server sync pending; will retry", "error", err)
			if errors.Is(err, account.ErrConflicts) {
				Notifier("esec vault", "Vault sync found conflicting keys. Run: esec vault sync --server")
			}
		}
		s.announceChain(ctx, a, before)
		if a.State.Events.Last == 0 {
			// Start from the newest event; old events were handled before.
			if ev, err := a.Client.Events(ctx, -1, 0); err == nil {
				a.State.Events.Last = ev.Next
				_ = a.Locked(func() error { a.State.Events.Last = ev.Next; return a.State.Save() })
			}
		}
		pollCtx, cancel := context.WithCancel(ctx)
		go func() {
			select {
			case <-s.serverWake:
				cancel()
			case <-pollCtx.Done():
			}
		}()
		ev, err := a.Client.Events(pollCtx, a.State.Events.Last, 25*time.Second)
		cancel()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			if pollCtx.Err() == nil {
				s.Logger.Warn("vault server events unavailable", "error", err)
				s.sleep(ctx, retry)
			}
			continue
		}
		for _, e := range ev.Events {
			switch {
			case e.Type == wire.EventDevicePending && !seenPending[e.Detail]:
				s.announcePending(ctx, a, e.Detail, seenPending)
			case e.Type == wire.EventDeviceStatus:
				s.announceSuspended(ctx, a, e.Detail)
			}
		}
		if ev.Next != a.State.Events.Last {
			next := ev.Next
			if err := a.Locked(func() error { a.State.Events.Last = next; return a.State.Save() }); err != nil {
				s.Logger.Warn("could not record vault server events", "error", err)
			}
		}
	}
}

// serverSync merges the server vault into local keyrings and pushes local
// changes, holding the keyring lock so CLI edits are never lost.
func (s *Server) serverSync(ctx context.Context, a *account.Account) error {
	sctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	res, err := a.Sync(sctx, account.SyncOptions{})
	if err != nil {
		return err
	}
	if len(res.Added) > 0 {
		s.Logger.Info("vault server: imported keys", "count", len(res.Added))
		s.refreshBroker()
	}
	if res.KeyChanged {
		s.Logger.Info("vault server: installed a rotated user key", "version", a.State.Chain.UKeyVersion)
	}
	return nil
}

// announceChain notifies about devices added since seq by recovery phrase or
// SSH agent, since nobody approved those on a screen.
func (s *Server) announceChain(ctx context.Context, a *account.Account, seq uint64) {
	if seq == 0 || a.State.Chain.Seq <= seq {
		return
	}
	st, err := a.VerifiedChain(ctx)
	if err != nil {
		return
	}
	for _, l := range st.Links[seq:] {
		switch l.Type {
		case chain.TypeDeviceAdd:
			for _, d := range st.Devices {
				if d.AddedSeq == l.Seq && d.ID != a.State.DeviceID {
					msg := fmt.Sprintf("Device %q joined your account via %s.", d.Name, d.Method)
					s.Logger.Warn("vault server: "+msg, "device", d.ID)
					if d.Method == chain.MethodSSHAgent || d.Method == chain.MethodRecovery {
						Notifier("esec vault: new device", msg+" If this was not you, run: esec vault devices revoke "+d.ID)
					}
				}
			}
		case chain.TypeUKeyRotate, chain.TypeDeviceRevoke:
			s.Logger.Info("vault server: device chain changed", "type", l.Type, "seq", l.Seq)
		}
	}
}

// maxPendingNotes bounds "device waiting" notifications per hour, so a flood
// of sign-ins cannot flood the desktop; the rest go to the log.
const maxPendingNotes = 5

func (s *Server) announcePending(ctx context.Context, a *account.Account, id string, seen map[string]bool) {
	pending, err := a.PendingDevices(ctx)
	if err != nil {
		return
	}
	for _, p := range pending {
		if p.Info.ID != id || seen[id] {
			continue
		}
		seen[id] = true
		msg := fmt.Sprintf("%q (%s) is waiting for approval.", p.Proof.Device.Name, p.Proof.Device.Platform)
		s.Logger.Info("vault server: "+msg, "device", id)
		now := time.Now()
		if now.Sub(s.noteWindow) > time.Hour {
			s.noteWindow, s.notes = now, 0
		}
		s.notes++
		switch {
		case s.notes <= maxPendingNotes:
			Notifier("esec vault: approve device?", msg+" Run: esec vault devices approve")
		case s.notes == maxPendingNotes+1:
			Notifier("esec vault: many sign-ins", "Many devices are waiting for approval. If you did not sign them in, someone may control your GitHub account.")
		}
	}
}

// announceSuspended asks the user to finish revoking a device that was
// suspended on the server (for example from the web page).
func (s *Server) announceSuspended(ctx context.Context, a *account.Account, id string) {
	devices, err := a.Devices(ctx)
	if err != nil {
		return
	}
	for _, d := range devices {
		if d.ID == id && d.ServerStatus == wire.DeviceSuspended && d.Status == chain.StatusActive {
			msg := fmt.Sprintf("Device %q was suspended. Finish revoking it: esec vault devices revoke %s", d.Name, d.ID)
			s.Logger.Warn("vault server: "+msg, "device", d.ID)
			Notifier("esec vault: device suspended", msg)
		}
	}
}

// refreshBroker reloads an unlocked broker's key cache, keeping its expiry.
func (s *Server) refreshBroker() {
	unlocked, expires := s.Broker.Session()
	if !unlocked {
		return
	}
	ttl := time.Until(expires)
	if ttl <= 0 {
		return
	}
	ks := keystore.New()
	projects, err := ks.List()
	if err != nil {
		return
	}
	keys := map[string]map[string]string{}
	for _, p := range projects {
		e, err := ks.Read(p)
		if err != nil {
			return
		}
		keys[p] = e
	}
	s.Broker.Unlock(keys, ttl)
}

func (s *Server) sleep(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	case <-s.serverWake:
	}
}
