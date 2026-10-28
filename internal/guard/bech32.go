package guard

import (
	"errors"
	"strings"
)

// bech32 encoding (BIP 173), for age's key strings: age1… recipients and
// AGE-SECRET-KEY-1… identities made from keys this program derives itself
// (the recovery key). age keeps its own encoder internal.

const charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

func polymod(values []byte) uint32 {
	gen := []uint32{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}
	chk := uint32(1)
	for _, v := range values {
		b := chk >> 25
		chk = (chk&0x1ffffff)<<5 ^ uint32(v)
		for i := 0; i < 5; i++ {
			if (b>>uint(i))&1 == 1 {
				chk ^= gen[i]
			}
		}
	}
	return chk
}

func hrpExpand(hrp string) []byte {
	out := make([]byte, 0, len(hrp)*2+1)
	for i := 0; i < len(hrp); i++ {
		out = append(out, hrp[i]>>5)
	}
	out = append(out, 0)
	for i := 0; i < len(hrp); i++ {
		out = append(out, hrp[i]&31)
	}
	return out
}

func convertBits(data []byte, from, to uint, pad bool) ([]byte, error) {
	var acc uint32
	var bits uint
	var out []byte
	maxv := uint32(1<<to) - 1
	for _, b := range data {
		acc = acc<<from | uint32(b)
		bits += from
		for bits >= to {
			bits -= to
			out = append(out, byte(acc>>bits&maxv)) //nolint:gosec // masked to at most 8 bits
		}
	}
	if pad {
		if bits > 0 {
			out = append(out, byte(acc<<(to-bits)&maxv)) //nolint:gosec // masked to at most 8 bits
		}
	} else if bits >= from || acc<<(to-bits)&maxv != 0 {
		return nil, errors.New("invalid padding")
	}
	return out, nil
}

// bech32Encode encodes data under the lowercase human-readable part hrp.
func bech32Encode(hrp string, data []byte) (string, error) {
	values, err := convertBits(data, 8, 5, true)
	if err != nil {
		return "", err
	}
	hrp = strings.ToLower(hrp)
	pm := polymod(append(append(hrpExpand(hrp), values...), 0, 0, 0, 0, 0, 0)) ^ 1
	var sb strings.Builder
	sb.WriteString(hrp)
	sb.WriteByte('1')
	for _, v := range values {
		sb.WriteByte(charset[v])
	}
	for i := 0; i < 6; i++ {
		sb.WriteByte(charset[(pm>>uint(5*(5-i)))&31])
	}
	return sb.String(), nil
}

// X25519Recipient returns the age1… recipient of an X25519 public key.
func X25519Recipient(pub [32]byte) (string, error) { return bech32Encode("age", pub[:]) }

// X25519IdentityString returns the AGE-SECRET-KEY-1… identity of an X25519
// private key.
func X25519IdentityString(priv [32]byte) (string, error) {
	s, err := bech32Encode("age-secret-key-", priv[:])
	return strings.ToUpper(s), err
}
