package broker

import (
	"net"
	"time"

	"github.com/mscno/esec-vault/internal/policy"
)

// PeerCredentials authenticates a Unix connection using the kernel's credentials.
func PeerCredentials(conn *net.UnixConn) (uint32, uint32, error) { return peerCredentials(conn) }

// Unlock replaces the broker's key cache for a bounded session. Restarting the
// daemon does not call this; service startup always begins locked.
func (s *Server) Unlock(keys map[string]map[string]string, ttl time.Duration) {
	s.keysMu.Lock()
	defer s.keysMu.Unlock()
	if s.timer != nil {
		s.timer.Stop()
	}
	s.epoch++
	epoch := s.epoch
	s.Keys = keys
	s.locked = false
	s.expires = time.Now().Add(ttl)
	s.timer = time.AfterFunc(ttl, func() {
		s.keysMu.Lock()
		defer s.keysMu.Unlock()
		if epoch == s.epoch {
			s.clearKeys()
		}
	})
}

// Lock ends a session. It does not claim to erase Go runtime copies of strings
// or change the plaintext working keyring store.
func (s *Server) Lock() {
	s.keysMu.Lock()
	defer s.keysMu.Unlock()
	if s.timer != nil {
		s.timer.Stop()
	}
	s.epoch++
	s.clearKeys()
	s.mu.Lock()
	for id, ch := range s.pending {
		select {
		case ch <- false:
		default:
		}
		delete(s.pending, id)
	}
	s.mu.Unlock()
}

// Session reports whether the broker can currently serve secret requests.
func (s *Server) Session() (bool, time.Time) {
	s.keysMu.RLock()
	defer s.keysMu.RUnlock()
	return !s.locked && (s.expires.IsZero() || time.Now().Before(s.expires)), s.expires
}

// ReloadPolicy replaces the policy without restarting the service.
func (s *Server) ReloadPolicy(p *policy.Policy) {
	s.keysMu.Lock()
	defer s.keysMu.Unlock()
	s.Policy = p
}

// ApproveOwner is called only after the control endpoint authenticates its peer.
func (s *Server) ApproveOwner(uid, pid uint32, id string) *Response {
	return s.handleApprove(uid, pid, &Request{Op: OpApprove, ID: id})
}

func (s *Server) clearKeys() {
	for _, entries := range s.Keys {
		clear(entries)
	}
	s.Keys = nil
	s.locked = true
	s.expires = time.Time{}
}
