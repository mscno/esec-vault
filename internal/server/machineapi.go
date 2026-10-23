package server

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"regexp"
	"time"

	"github.com/mscno/esec-vault/internal/chain"
	"github.com/mscno/esec-vault/internal/team"
	"github.com/mscno/esec-vault/internal/wire"
)

var machineNonce = regexp.MustCompile(`^[A-Za-z0-9_-]{16,64}$`)

// apiMachineKeys gives a machine its sealed environment keys. A machine has
// no session: it signs the request with its own key, and when its policy
// says so, proves the workload with an OIDC token. The keys stay sealed to
// the machine's key, so the server never sees them.
func (s *Server) apiMachineKeys(w http.ResponseWriter, r *http.Request) { //nolint:gocyclo // each check is a separate, ordered gate
	now := s.now()
	ip := s.clientIP(r)
	if !s.allowAnon("machine", ip, 600, 3000, time.Hour) {
		writeErr(w, http.StatusTooManyRequests, wire.ErrRateLimited, "too many machine requests from this address")
		return
	}
	body, err := readBody(w, r, maxSmallBody)
	if err != nil {
		writeErr(w, http.StatusRequestEntityTooLarge, wire.ErrInvalidRequest, "request body too large")
		return
	}
	var req wire.MachineKeysRequest
	if err := decodeStrict(body, &req); err != nil || team.ValidMachineID(req.Machine) != nil || team.ValidProject(req.Project) != nil || !machineNonce.MatchString(req.Nonce) {
		writeErr(w, http.StatusBadRequest, wire.ErrInvalidRequest, "invalid request")
		return
	}
	if err := s.proofClock(req.Timestamp); err != nil {
		s.fail(w, r, err)
		return
	}
	ctx := r.Context()
	// One answer for every kind of unknown or removed machine, so the
	// endpoint does not tell which machine ids exist.
	unknown := func() {
		writeErr(w, http.StatusUnauthorized, wire.ErrUnauthorized, "unknown or removed machine, or a bad signature")
	}
	var project, signPub string
	var active bool
	err = s.db.sql.QueryRowContext(ctx, `SELECT project, sign_pub, active FROM project_machines WHERE id = ?`, req.Machine).Scan(&project, &signPub, &active)
	if err != nil || !active || project != req.Project {
		unknown()
		return
	}
	pub, err := chain.ParseSignKey(signPub)
	if err != nil {
		unknown()
		return
	}
	sum := sha256.Sum256([]byte(req.OIDCToken))
	tokenHash := ""
	if req.OIDCToken != "" {
		tokenHash = hex.EncodeToString(sum[:])
	}
	if !ed25519.Verify(pub, team.KeysMessage(req.Machine, req.Project, req.Timestamp, req.Nonce, tokenHash), req.Sig) {
		unknown()
		return
	}
	// Counted once signed: machine ids are shown on the project's page.
	if !s.limits.allow("machine:"+req.Machine, 600, time.Hour, now) {
		writeErr(w, http.StatusTooManyRequests, wire.ErrRateLimited, "too many requests for this machine; try again later")
		return
	}
	if err := s.recordNonce(ctx, req.Machine, req.Nonce, now); err != nil {
		writeErr(w, http.StatusUnauthorized, wire.ErrUnauthorized, "request replayed")
		return
	}
	st, links, err := s.db.projectState(ctx, s.db.sql, req.Project)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if st == nil {
		unknown()
		return
	}
	m, ok := st.Machine(req.Machine)
	if !ok {
		unknown()
		return
	}
	if st.Archived {
		writeErr(w, http.StatusForbidden, wire.ErrForbidden, req.Project+" is archived: it gives its machines no keys")
		return
	}
	detail := m.Name
	if m.OIDC != nil {
		if req.OIDCToken == "" {
			writeErr(w, http.StatusForbidden, wire.ErrForbidden, "this machine needs an OIDC token from "+m.OIDC.Describe()+oidcHint(m.OIDC))
			return
		}
		claims, err := s.oidc.Verify(ctx, m.OIDC, req.OIDCToken, s.cfg.BaseURL, now)
		if err != nil {
			if errors.Is(err, errOIDC) {
				writeErr(w, http.StatusForbidden, wire.ErrForbidden, err.Error())
				return
			}
			s.internalError(w, r, err)
			return
		}
		if err := m.OIDC.Allows(claims); err != nil {
			_ = s.db.projectAudit(ctx, s.db.sql, req.Project, req.Machine, ip, "machine_refused", m.Name+": "+truncate(err.Error(), 200), now)
			writeErr(w, http.StatusForbidden, wire.ErrForbidden, "the OIDC token does not match this machine's policy: "+err.Error())
			return
		}
		detail += " " + truncate(claims.Detail(), 300)
	}
	grants, err := s.db.grants(ctx, s.db.sql, `project = ? AND to_id = ?`, req.Project, req.Machine)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if len(grants) == 0 {
		writeErr(w, http.StatusNotFound, wire.ErrNotFound, "no keys were sent to this machine yet; an admin's device sends them (esec vault access sync)")
		return
	}
	chains, err := s.db.signerChains(ctx, s.db.sql, st)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	// The grant's signer may be an admin who signed no link.
	g := grants[len(grants)-1]
	if gr, err := team.PeekGrant(g.Env); err == nil {
		if _, ok := chains[gr.From]; !ok {
			if chains[gr.From], err = s.db.chainLinks(ctx, s.db.sql, gr.From, 0); err != nil {
				s.internalError(w, r, err)
				return
			}
		}
	}
	if _, err := s.db.sql.ExecContext(ctx, `UPDATE project_machines SET last_used_at = ?, last_ip = ?, uses = uses + 1 WHERE id = ?`, now.Unix(), ip, req.Machine); err != nil {
		s.internalError(w, r, err)
		return
	}
	if err := s.db.projectAudit(ctx, s.db.sql, req.Project, req.Machine, ip, "machine_keys", detail, now); err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, wire.MachineKeys{Links: links, Chains: chains, Grant: g.Env})
}
