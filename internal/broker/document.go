package broker

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/mscno/esec"
)

func (s *Server) handleGetSecrets(uid, pid uint32, req *Request) *Response { //nolint:gocyclo // checks, then guarded or cached or sealed key, then decrypt
	if req.Project == "" || req.Path == "" {
		return &Response{OK: false, Error: "project and path are required"}
	}
	if !filepath.IsAbs(req.Path) {
		return &Response{OK: false, Error: "path must be absolute"}
	}
	if s.Forwarded && req.Op == OpInspectRead {
		return readFailure(&esec.ReadError{Code: "inspection_unavailable", Detail: "forwarded inspection never opens a key"})
	}
	if s.Forwarded && len(req.Content) == 0 {
		return &Response{OK: false, Error: "a forwarded request carries its file"}
	}
	// Local authorization uses the file's independently resolved identity, never
	// a client-supplied environment label. Keep the original request immutable.
	copyReq := *req
	copyReq.readEpoch = s.readGeneration()
	req = &copyReq
	if !s.Forwarded {
		target, err := esec.ResolveRead(filepath.Dir(req.Path), req.Path, req.Format)
		if err != nil {
			return s.rejectRead(uid, pid, req, err)
		}
		if target.Project != "" && target.Project != req.Project {
			return s.rejectRead(uid, pid, req, &esec.ReadError{Code: "project_mismatch", Detail: "file belongs to " + target.Project})
		}
		if req.Env != target.Environment && req.Env != filepath.Base(req.Path) && req.Env != req.Path {
			return s.rejectRead(uid, pid, req, &esec.ReadError{Code: "environment_mismatch", Detail: "file belongs to " + target.Environment})
		}
		if req.Digest != "" && req.Digest != target.Digest {
			return s.rejectRead(uid, pid, req, &esec.ReadError{Code: "file_changed", Detail: "the encrypted file changed; retry the read"})
		}
		req.Env = target.Environment
		req.Path = target.Path
		req.Format = string(target.Format)
		req.resolved = target
		req.readEpoch = s.readGeneration()
		if req.Op == OpInspectRead {
			if s.Inspect == nil {
				return s.rejectRead(uid, pid, req, &esec.ReadError{Code: "daemon_upgrade_required", Detail: "this broker has no read inspector"})
			}
			return &Response{OK: true, Inspection: s.Inspect(uid, target)}
		}
	}
	data := req.Content
	if req.resolved != nil {
		data = req.resolved.Content
	}

	format := esec.FileFormat(req.Format)
	// The file's embedded public key is the ground truth for key resolution
	// (monorepo components, rotated keys).
	var pubkey *[32]byte
	pubHex := ""
	if pub, err := esec.ExtractPublicKey(data, format); err == nil {
		pubkey = &pub
		pubHex = hex.EncodeToString(pub[:])
	}

	var key string
	guarded, denied := s.isGuarded(uid, pid, req, pubHex)
	if denied != nil {
		return denied
	}
	if guarded {
		k, denied := s.guardedKey(uid, pid, req, pubHex)
		if denied != nil {
			return denied
		}
		key = k
	} else {
		if s.Forwarded {
			// Only guarded keys are served to other machines: each read
			// is then one the person sees and touches.
			_ = s.auditEntry(AuditEntry{UID: uid, PID: pid, Op: req.Op, Project: req.Project, Env: req.Env, Decision: "deny", Detail: "forwarded read of an unguarded key", Session: req.Session})
			return &Response{OK: false, Error: fmt.Sprintf("%s %s is not guarded: a forwarded broker serves guarded keys only; give the machine its own key (esec vault group token)", req.Project, req.Env)}
		}
		if s.Consent != nil && s.OpenRead != nil && req.resolved != nil {
			if denied := s.authorizeScoped(uid, pid, req); denied != nil {
				return denied
			}
			var err error
			key, err = s.OpenRead(req.resolved)
			if err != nil {
				return readFailure(err)
			}
		} else {
			if denied := s.authorize(uid, pid, req); denied != nil {
				return denied
			}
			var err error
			if key, err = s.keyFor(req.Project, req.Env, pubkey); err != nil {
				// Not held yet (a new checkout, a key rotated elsewhere): the
				// key sealed in the repository, opened with this identity.
				k, uerr := s.unseal(req, pubHex)
				if uerr != nil {
					return &Response{OK: false, Error: err.Error()}
				}
				key = k
			}
		}
	}

	var plain bytes.Buffer
	if _, err := esec.Decrypt(bytes.NewReader(data), &plain, "", format, ".", key); err != nil {
		return &Response{OK: false, Error: fmt.Sprintf("decryption failed: %v", err)}
	}

	if (s.Consent != nil || s.ReadGeneration != nil) && req.readEpoch != s.readGeneration() {
		return readFailure(&esec.ReadError{Code: "access_revoked", Detail: "vault locked while read was in progress"})
	}
	if req.Op == OpReadDocument {
		return &Response{OK: true, Document: plain.Bytes()}
	}

	secrets, err := esec.EnvVars(plain.Bytes(), format)
	if err != nil {
		return &Response{OK: false, Error: err.Error()}
	}
	// Never inject public-key markers or underscore-prefixed metadata.
	for k := range secrets {
		if k == esec.EsecPublicKey || strings.HasPrefix(k, "_") {
			delete(secrets, k)
		}
	}
	return &Response{OK: true, Secrets: secrets}
}

// unseal opens a key sealed in the request's project when the broker is
// unlocked, and holds it for the session.
func (s *Server) unseal(req *Request, pub string) (string, error) {
	if s.Unseal == nil {
		return "", errors.New("no unsealer")
	}
	s.keysMu.RLock()
	locked := s.locked || (!s.expires.IsZero() && !time.Now().Before(s.expires))
	s.keysMu.RUnlock()
	if locked {
		return "", errors.New("vault is locked")
	}
	key, err := s.Unseal(req.Project, req.Env, pub, req.Path)
	if err != nil {
		return "", err
	}
	s.keysMu.Lock()
	if s.Keys == nil {
		s.Keys = map[string]map[string]string{}
	}
	if s.Keys[req.Project] == nil {
		s.Keys[req.Project] = map[string]string{}
	}
	s.Keys[req.Project]["ESEC_PRIVATE_KEY_"+strings.ToUpper(pub)] = key
	s.keysMu.Unlock()
	return key, nil
}
