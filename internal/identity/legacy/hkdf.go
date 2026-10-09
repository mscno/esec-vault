package legacy

import (
	"crypto/sha256"
	"io"

	"golang.org/x/crypto/hkdf"
)

// hkdfSHA256 mirrors esec's crypto.DeriveKey with an explicit salt, so the v1
// derivation can be reproduced without depending on that package's unexported
// constant.
func hkdfSHA256(secret, salt []byte, info string) ([]byte, error) {
	out := make([]byte, 32)
	r := hkdf.New(sha256.New, secret, salt, []byte(info))
	if _, err := io.ReadFull(r, out); err != nil {
		return nil, err
	}
	return out, nil
}
