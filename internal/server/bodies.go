package server

import (
	"errors"
	"io"
	"net/http"
	"sync"
)

const maxSmallBody = 64 << 10

// maxLargeBody bounds commits and vault uploads.
const maxLargeBody = 16 << 20

// Request bodies held in memory at once. Only a request whose signature
// (over the declared body hash) verified, and that is within its device's
// rate limit, reserves memory, so a session token alone reserves nothing.
// Devices waiting for approval draw from their own pools: a phished or
// GitHub-takeover device holds a real device key, and must block neither
// trusted devices' uploads nor the owner's own new device.
const (
	// Trusted devices: per account and in total.
	maxBodyPerAccount = 2 * maxLargeBody
	maxBodyActive     = 8 * maxLargeBody
	// Pending devices' small requests (proofs, recovery, agent unlock): per
	// device, so other pending devices of the same account cannot use up a
	// new device's share.
	maxPendingPerDevice = 4 * maxSmallBody
	maxPendingSmall     = 4 * maxLargeBody
	// The one large request a pending device may send: the commit that
	// creates its account.
	maxPendingLarge = 4 * maxLargeBody
)

var errBodyTooLarge = errors.New("request body too large")

// bodyBudget accounts for the memory request bodies reserve while they are
// read and handled, per key (an account or a device) and in total.
type bodyBudget struct {
	mu       sync.Mutex
	total    int64
	perKey   map[string]int64
	maxTotal int64
	maxKey   int64
}

func newBodyBudget(maxTotal, maxKey int64) *bodyBudget {
	return &bodyBudget{perKey: map[string]int64{}, maxTotal: maxTotal, maxKey: maxKey}
}

// take reserves n bytes for a body under key, or reports that the key or
// the pool already holds as much as it may.
func (b *bodyBudget) take(key string, n int64) (release func(), ok bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.total+n > b.maxTotal || b.perKey[key]+n > b.maxKey {
		return nil, false
	}
	b.total += n
	b.perKey[key] += n
	return func() {
		b.mu.Lock()
		defer b.mu.Unlock()
		b.total -= n
		if b.perKey[key] -= n; b.perKey[key] <= 0 {
			delete(b.perKey, key)
		}
	}, true
}

// bodySize is what reading r's body may hold: its declared length, or the
// limit when the length is not declared.
func bodySize(r *http.Request, limit int64) (int64, error) {
	switch {
	case r.ContentLength > limit:
		return 0, errBodyTooLarge
	case r.ContentLength >= 0:
		return r.ContentLength, nil
	default:
		return limit, nil
	}
}

// readBody reads a body of at most limit bytes, growing its buffer as data
// arrives, so a caller that declares a length and sends nothing holds
// almost no memory.
func readBody(w http.ResponseWriter, r *http.Request, limit int64) ([]byte, error) {
	if r.ContentLength > limit {
		return nil, errBodyTooLarge
	}
	return io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
}

// readReserved reads a body whose declared length was reserved in a
// bodyBudget, allocating that length once instead of growing a buffer.
func readReserved(w http.ResponseWriter, r *http.Request, limit int64) ([]byte, error) {
	if r.ContentLength < 0 || r.ContentLength > limit {
		return readBody(w, r, limit)
	}
	b := make([]byte, r.ContentLength)
	if _, err := io.ReadFull(http.MaxBytesReader(w, r.Body, limit), b); err != nil {
		return nil, err
	}
	return b, nil
}
