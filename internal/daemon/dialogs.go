package daemon

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/mscno/esec-vault/internal/account"
	"github.com/mscno/esec-vault/internal/notify"
)

// Asker shows a Sign / Dismiss / Later dialog; tests replace it.
var Asker = notify.Ask

// dialogTimeout is how long a dialog waits for an answer.
const dialogTimeout = 10 * time.Minute

// changeDialogs asks, one dialog at a time, whether to sign each change made
// on the web pages, and signs the ones the person agrees to. The dialog text
// is the change itself, as this device will sign it: the web page cannot
// show one thing and have another signed. Set ESEC_VAULT_DIALOGS=off to
// turn them off.
type changeDialogs struct {
	mu      sync.Mutex
	running bool
	// asked is when each change was last shown; one left for later is shown
	// again after an hour.
	asked map[int64]time.Time
}

// askChanges starts asking about waiting changes, unless it is asking
// already.
func (s *Server) askChanges(ctx context.Context) {
	if strings.EqualFold(os.Getenv("ESEC_VAULT_DIALOGS"), "off") {
		return
	}
	d := &s.dialogs
	d.mu.Lock()
	if d.running {
		d.mu.Unlock()
		return
	}
	d.running = true
	if d.asked == nil {
		d.asked = map[int64]time.Time{}
	}
	d.mu.Unlock()
	// Read now, on the caller's goroutine: tests swap them.
	ask, note := Asker, Notifier
	go func() {
		defer func() {
			d.mu.Lock()
			d.running = false
			d.mu.Unlock()
		}()
		// Its own account: the server loop keeps using its own meanwhile.
		a, err := account.Open(s.Keyring, daemonUI{s})
		if err != nil {
			return
		}
		lctx, cancel := context.WithTimeout(ctx, time.Minute)
		list, err := a.Changes(lctx)
		cancel()
		if err != nil {
			s.Logger.Warn("web changes: cannot list them", "error", err)
			return
		}
		for _, ch := range list {
			if ctx.Err() != nil {
				return
			}
			d.mu.Lock()
			last, seen := d.asked[ch.ID]
			d.mu.Unlock()
			if seen && time.Since(last) < time.Hour {
				continue
			}
			if ch.NeedsWords() {
				// A yes in a dialog is not enough: the words are typed.
				d.mu.Lock()
				d.asked[ch.ID] = time.Now()
				d.mu.Unlock()
				note("esec vault: approve a new device", "A new device waits for your approval. Run esec vault changes and type the words it shows.")
				continue
			}
			// The change first, whole; who asked, from the server, last.
			text := strings.Join(ch.DescribeLines(), "\n") + "\n\nAsked on the web by " + ch.AskedBy() + ". Sign it with your user key on this device?"
			answer, err := ask("esec vault: sign a change?", text, dialogTimeout)
			d.mu.Lock()
			d.asked[ch.ID] = time.Now()
			d.mu.Unlock()
			if errors.Is(err, notify.ErrNoDialogs) {
				note("esec vault: changes to sign", "Changes made on the web wait for this device to sign them. Run: esec vault changes")
				return
			}
			if err != nil {
				s.Logger.Warn("web changes: dialog failed", "error", err)
				return
			}
			s.answer(ctx, a, ch, answer, note)
		}
	}()
}

// answer acts on the person's answer to a change's dialog.
func (s *Server) answer(ctx context.Context, a *account.Account, ch account.ChangeView, answer string, note func(title, body string)) {
	actx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	switch answer {
	case notify.AnswerSign:
		lines, err := a.ApplyChange(actx, ch)
		if err != nil {
			s.Logger.Warn("web changes: not signed", "change", ch.ID, "error", err)
			note("esec vault: not signed", err.Error())
			return
		}
		if err := a.CloseChange(actx, ch.ID, true); err != nil {
			s.Logger.Warn("web changes: signed, but not marked done", "error", err)
		}
		s.Logger.Info("web changes: signed", "change", ch.Describe())
		note("esec vault: signed", strings.Join(lines, " "))
	case notify.AnswerDismiss:
		if err := a.CloseChange(actx, ch.ID, false); err != nil {
			s.Logger.Warn("web changes: not dismissed", "error", err)
		}
	}
}
