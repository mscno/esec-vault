package broker

import (
	"errors"

	"github.com/mscno/esec"
	"github.com/mscno/esec-vault/internal/policy"
)

func readFailure(err error) *Response {
	var read *esec.ReadError
	if errors.As(err, &read) {
		return &Response{Code: read.Code, Error: read.Detail}
	}
	return &Response{Code: "broker_read_failed", Error: err.Error()}
}

func (s *Server) guardRequest(req *Request, pub string) GuardRequest {
	env := req.Env
	if req.resolved != nil {
		env = req.resolved.KeyEnvironment
	}
	protection := ""
	if req.resolved != nil {
		protection = req.resolved.Guard
	}
	return GuardRequest{Project: req.Project, Env: env, PublicKey: pub, Path: req.Path, Forwarded: s.Forwarded, Seal: req.Seal, Protection: protection}
}
func (s *Server) authorizeScoped(uid, pid uint32, req *Request) *Response {
	if req.resolved.Project == "" {
		return s.rejectRead(uid, pid, req, &esec.ReadError{Code: "project_missing", Detail: "a scoped broker read requires the file's own esec.toml"})
	}
	s.keysMu.RLock()
	action, matched := s.Policy.DecideRule(req.Project, req.Env, uid)
	configured := s.Policy.Configured
	s.keysMu.RUnlock()
	if action == policy.Deny && (matched || configured) {
		_ = s.auditReq(uid, pid, req, "deny", "policy")
		return readFailure(&esec.ReadError{Code: "policy_denied", Detail: "local policy denies this environment"})
	}
	if action == policy.Allow {
		if unlocked, _ := s.Session(); unlocked {
			if err := s.recordAllow(uid, pid, req, "policy"); err != nil {
				return auditFailed()
			}
			return nil
		}
	}
	how, err := s.Consent(uid, pid, req.resolved)
	if err != nil {
		_ = s.auditReq(uid, pid, req, "deny", err.Error())
		return readFailure(err)
	}
	if err := s.recordAllow(uid, pid, req, "consent "+how); err != nil {
		return auditFailed()
	}
	return nil
}

// Epoch changes on lock/unlock. Scoped consent cannot outlive revocation.
func (s *Server) Epoch() uint64 { s.keysMu.RLock(); defer s.keysMu.RUnlock(); return s.epoch }

// ReadPolicy returns the effective policy without exposing mutable state.
func (s *Server) ReadPolicy(uid uint32, project, env string) (policy.Action, bool) {
	s.keysMu.RLock()
	defer s.keysMu.RUnlock()
	action, matched := s.Policy.DecideRule(project, env, uid)
	return action, matched || s.Policy.Configured
}

func (s *Server) rejectRead(uid, pid uint32, req *Request, err error) *Response {
	_ = s.auditReq(uid, pid, req, "deny", err.Error())
	return readFailure(err)
}

func (s *Server) readGeneration() uint64 {
	if s.ReadGeneration != nil {
		return s.ReadGeneration()
	}
	return s.Epoch()
}
