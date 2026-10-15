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

// Words returns the four-word fingerprint of the concatenated parts. Each
// part is length-prefixed so different splits never collide.
func Words(domain string, parts ...[]byte) string {
	h := sha256.New()
	writePart(h, []byte(domain))
	for _, p := range parts {
		writePart(h, p)
	}
	sum := h.Sum(nil)
	bits := binary.BigEndian.Uint64(sum[:8]) >> 20 // top 44 bits
	list := bip39.GetWordList()
	words := make([]string, 4)
	for i := 3; i >= 0; i-- {
		words[i] = list[bits&0x7ff]
		bits >>= 11
	}
	return strings.Join(words, "-")
}

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
