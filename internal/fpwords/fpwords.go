// Package fpwords renders key fingerprints as short word sequences that people
// can compare between two screens.
//
// A fingerprint is SHA-256 over length-prefixed inputs, truncated to 44 bits
// and shown as four words from the BIP39 English list (11 bits each), joined
// by dashes: "tiger-lamp-orbit-maple". 44 bits is enough for a human
// comparison of two values displayed at the same moment; it is not meant as a
// long-term identifier.
package fpwords

import (
	"crypto/sha256"
	"encoding/binary"
	"strings"

	"github.com/tyler-smith/go-bip39"
)

// Words returns an n-word fingerprint (11 bits per word, up to 23 words) of
// the concatenated parts. Each part is length-prefixed so different splits
// never collide.
func Words(n int, domain string, parts ...[]byte) string {
	if n < 1 || n > 23 {
		panic("fpwords: word count out of range")
	}
	h := sha256.New()
	writePart(h, []byte(domain))
	for _, p := range parts {
		writePart(h, p)
	}
	sum := h.Sum(nil)
	list := bip39.GetWordList()
	words := make([]string, n)
	for i := range n {
		idx := 0
		for b := range 11 {
			bit := i*11 + b
			idx = idx<<1 | int(sum[bit/8]>>(7-bit%8)&1)
		}
		words[i] = list[idx]
	}
	return strings.Join(words, "-")
}

// Word counts. A device fingerprint is compared within the minutes a device
// waits for approval (66 bits); the account key never changes, so it must
// resist offline search for a matching chain root (88 bits).
const (
	DeviceWords  = 6
	AccountWords = 8
)

func writePart(h interface{ Write(p []byte) (int, error) }, p []byte) {
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(p))) //nolint:gosec // fingerprint inputs are small keys
	_, _ = h.Write(l[:])
	_, _ = h.Write(p)
}

// Domains used for fingerprints, so a device fingerprint can never equal an
// account fingerprint for the same bytes.
const (
	DomainDevice  = "esec-vault device v1"
	DomainAccount = "esec-vault account v1"
)
