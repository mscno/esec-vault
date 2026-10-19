// Package apisig signs and verifies API requests with the device's Ed25519
// key. A session token alone is not enough to call the API: every request
// also carries a signature over the method, path, body hash, a timestamp and
// a single-use nonce, made with a key that never leaves the device's secret
// store. A token copied off the disk is useless without that key.
package apisig

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"time"
)

// Header names.
const (
	HeaderDevice    = "Esec-Device"
	HeaderTimestamp = "Esec-Timestamp"
	HeaderNonce     = "Esec-Nonce"
	HeaderSignature = "Esec-Signature"
	// HeaderBodyHash carries the hex SHA-256 of the body the signature
	// covers, so a server can check the signature before reading the body.
	HeaderBodyHash = "Esec-Body-Sha256"
)

// EmptyBodyHash is the hex SHA-256 of an empty body.
var EmptyBodyHash = BodyHash(nil)

// BodyHash returns the hex SHA-256 of body.
func BodyHash(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

// MaxSkew is the accepted clock difference between client and server.
const MaxSkew = 60 * time.Second

// ErrInvalid is returned for any missing or invalid signature header.
var ErrInvalid = errors.New("request signature missing or invalid")

var (
	noncePattern    = regexp.MustCompile(`^[A-Za-z0-9_-]{22,64}$`)
	bodyHashPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// Message returns the bytes a request signature covers.
func Message(method, requestURI string, body []byte, timestamp int64, nonce, deviceID string) []byte {
	return messageForHash(method, requestURI, BodyHash(body), timestamp, nonce, deviceID)
}

func messageForHash(method, requestURI, bodyHash string, timestamp int64, nonce, deviceID string) []byte {
	var b bytes.Buffer
	b.WriteString("esec-vault-request/v1\n")
	b.WriteString(method)
	b.WriteByte('\n')
	b.WriteString(requestURI)
	b.WriteByte('\n')
	b.WriteString(bodyHash)
	b.WriteByte('\n')
	b.WriteString(strconv.FormatInt(timestamp, 10))
	b.WriteByte('\n')
	b.WriteString(nonce)
	b.WriteByte('\n')
	b.WriteString(deviceID)
	return b.Bytes()
}

// Sign adds signature headers to req for body.
func Sign(req *http.Request, body []byte, deviceID string, key ed25519.PrivateKey, now time.Time) error {
	var n [18]byte
	if _, err := rand.Read(n[:]); err != nil {
		return err
	}
	nonce := base64.RawURLEncoding.EncodeToString(n[:])
	ts := now.Unix()
	sig := ed25519.Sign(key, Message(req.Method, req.URL.RequestURI(), body, ts, nonce, deviceID))
	req.Header.Set(HeaderDevice, deviceID)
	req.Header.Set(HeaderTimestamp, strconv.FormatInt(ts, 10))
	req.Header.Set(HeaderNonce, nonce)
	req.Header.Set(HeaderSignature, base64.StdEncoding.EncodeToString(sig))
	req.Header.Set(HeaderBodyHash, BodyHash(body))
	return nil
}

// Signed holds the parsed signature headers of a request.
type Signed struct {
	DeviceID  string
	Timestamp time.Time
	Nonce     string
	// BodyHash is the declared body hash, or "" when the client sent none
	// (clients before v0.4.2).
	BodyHash string
	sig      []byte
}

// Parse reads the signature headers without verifying them.
func Parse(r *http.Request) (*Signed, error) {
	dev := r.Header.Get(HeaderDevice)
	tsRaw := r.Header.Get(HeaderTimestamp)
	nonce := r.Header.Get(HeaderNonce)
	sigRaw := r.Header.Get(HeaderSignature)
	if dev == "" || tsRaw == "" || nonce == "" || sigRaw == "" {
		return nil, ErrInvalid
	}
	ts, err := strconv.ParseInt(tsRaw, 10, 64)
	if err != nil {
		return nil, ErrInvalid
	}
	if !noncePattern.MatchString(nonce) {
		return nil, ErrInvalid
	}
	sig, err := base64.StdEncoding.DecodeString(sigRaw)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return nil, ErrInvalid
	}
	bodyHash := r.Header.Get(HeaderBodyHash)
	if bodyHash != "" && !bodyHashPattern.MatchString(bodyHash) {
		return nil, ErrInvalid
	}
	return &Signed{DeviceID: dev, Timestamp: time.Unix(ts, 0), Nonce: nonce, BodyHash: bodyHash, sig: sig}, nil
}

// Verify checks the signature against pub, the body and the clock. Nonce
// uniqueness is the caller's job.
func (s *Signed) Verify(r *http.Request, body []byte, pub ed25519.PublicKey, now time.Time) error {
	return s.VerifyHash(r, BodyHash(body), pub, now)
}

// VerifyHash is Verify for a body known only by its hex SHA-256. The caller
// must check that the body it then reads has that hash.
func (s *Signed) VerifyHash(r *http.Request, bodyHash string, pub ed25519.PublicKey, now time.Time) error {
	if len(pub) != ed25519.PublicKeySize {
		return ErrInvalid
	}
	if d := now.Sub(s.Timestamp); d > MaxSkew || d < -MaxSkew {
		return fmt.Errorf("%w: clock skew of %s exceeds %s; check this machine's clock", ErrInvalid, d.Round(time.Second), MaxSkew)
	}
	msg := messageForHash(r.Method, r.URL.RequestURI(), bodyHash, s.Timestamp.Unix(), s.Nonce, s.DeviceID)
	if !ed25519.Verify(pub, msg, s.sig) {
		return ErrInvalid
	}
	return nil
}
