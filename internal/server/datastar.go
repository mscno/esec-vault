package server

// Live pages with Datastar (https://data-star.dev). Every page still works
// as plain HTML: forms post and redirect, and nothing needs scripts. With
// scripts, Datastar sends a form in place and the server answers with
// server-sent events that patch parts of the page; some parts refresh on
// their own.
//
// Security:
//   - Datastar evaluates the expressions in data-* attributes. It runs in
//     its nonce mode: it reads a per-response nonce from <html data-nonce>
//     and runs each expression as a script carrying it, so the content
//     security policy allows scripts only from this site and with that
//     nonce, never 'unsafe-eval'.
//   - Expressions are only ever built by dsPost and dsLive, from paths that
//     must match a strict pattern; nothing a person or machine named goes
//     into one. Templates escape everything else as usual, so no data-*
//     attribute can be injected.
//   - Datastar posts the form itself (urlencoded) with the page's CSRF
//     token; checkForm checks it and the Origin header as for any form.
//   - Requests carry no session token but the cookie; patches go only to the
//     page that asked.

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"html"
	"html/template"
	"net/http"
	"regexp"

	"github.com/starfederation/datastar-go/datastar"
)

const pageCSP = "default-src 'none'; script-src 'self' 'nonce-%s'; style-src 'self'; img-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"

// newNonce returns a fresh CSP nonce.
func newNonce() string {
	var b [18]byte
	_, _ = rand.Read(b[:])
	return base64.RawURLEncoding.EncodeToString(b[:])
}

// isDatastar reports whether Datastar sent the request.
func isDatastar(r *http.Request) bool { return r.Header.Get("Datastar-Request") == "true" }

// dsPath is what a path in an expression may contain: no quotes,
// backslashes, spaces or anything else that could end the string.
// It must be a path on this site: "//host" would leave it.
var dsPath = regexp.MustCompile(`^/(?:[A-Za-z0-9._@:-][A-Za-z0-9._/@:-]{0,199})?$`)

// dsPost makes a form send itself in place to path, after the question in
// its data-confirm attribute (read as text, never evaluated) if it has one.
func dsPost(path string) template.HTMLAttr {
	if !dsPath.MatchString(path) {
		return ""
	}
	expr := "(!el.dataset.confirm || confirm(el.dataset.confirm)) && @post('" + path + "', {contentType: 'form'})"
	return template.HTMLAttr(`data-on:submit="` + html.EscapeString(expr) + `"`) //nolint:gosec // built from a checked path only
}

// dsLive refreshes the page from path every seconds while it is visible.
func dsLive(path string, seconds int) template.HTMLAttr {
	if !dsPath.MatchString(path) || seconds < 5 || seconds > 600 {
		return ""
	}
	return template.HTMLAttr(fmt.Sprintf(`data-on-interval__duration.%ds="%s"`, seconds, html.EscapeString("@get('"+path+"')"))) //nolint:gosec // built from a checked path only
}

// dsPatch renders templates, each a fragment with an id, and patches them
// into the page.
func (s *Server) dsPatch(w http.ResponseWriter, r *http.Request, data map[string]any, names ...string) {
	var buf bytes.Buffer
	for _, n := range names {
		if err := s.tmpl.ExecuteTemplate(&buf, n, data); err != nil {
			s.log.Error("template failed", "template", n, "error", err)
			s.dsWarn(w, r, "The page could not be updated; reload it.")
			return
		}
	}
	sse := datastar.NewSSE(w, r)
	if err := sse.PatchElements(buf.String()); err != nil {
		s.log.Debug("patch not sent", "error", err)
	}
}

// dsWarn shows a warning at the top of the page.
func (s *Server) dsWarn(w http.ResponseWriter, r *http.Request, text string) {
	sse := datastar.NewSSE(w, r)
	el := `<div id="flash" class="flash flash-warn" role="status" aria-live="polite">` + html.EscapeString(text) + `</div>`
	if err := sse.PatchElements(el); err != nil {
		s.log.Debug("flash not sent", "error", err)
	}
}

// dsSession returns the web session of a Datastar request, or tells the
// page the person was signed out: a redirect to sign in would go nowhere.
func (s *Server) dsSession(w http.ResponseWriter, r *http.Request) *webSession {
	ws, err := s.webSession(r)
	if err != nil {
		s.internalError(w, r, err)
		return nil
	}
	if ws == nil {
		s.dsWarn(w, r, "You were signed out. Reload the page to sign in again.")
		return nil
	}
	return ws
}

// pageForm runs a CSRF-checked form. fn makes the change and says what it
// did. Without scripts the browser returns to back; sent by Datastar, the
// page is patched in place: patch returns its data and the parts to send.
func (s *Server) pageForm(w http.ResponseWriter, r *http.Request, back string, fn func(ctx context.Context, ws *webSession) (string, error), patch func(ctx context.Context, ws *webSession) (map[string]any, []string, error)) {
	ds := isDatastar(r)
	var ws *webSession
	if ds {
		ws = s.dsSession(w, r)
	} else {
		ws = s.requireWeb(w, r)
	}
	if ws == nil {
		return
	}
	if !s.checkForm(r, ws) {
		if ds {
			s.dsWarn(w, r, "The form expired. Reload the page and try again.")
			return
		}
		s.webError(w, http.StatusForbidden, "The form expired. Reload the page and try again.")
		return
	}
	ctx := r.Context()
	done, err := fn(ctx, ws)
	if err != nil {
		if ds {
			s.dsFail(w, r, err)
			return
		}
		s.webFail(w, r, err)
		return
	}
	if !ds {
		if !dsPath.MatchString(back) {
			back = "/account"
		}
		http.Redirect(w, r, back, http.StatusSeeOther)
		return
	}
	data, names, err := patch(ctx, ws)
	if err != nil {
		s.dsFail(w, r, err)
		return
	}
	data["Flash"] = done
	s.dsPatch(w, r, data, append(names, "flash")...)
}

// webFail shows an error page: a client error's own words, or a generic
// one.
func (s *Server) webFail(w http.ResponseWriter, r *http.Request, err error) {
	var ae *apiError
	if errors.As(err, &ae) {
		s.webError(w, ae.status, ae.desc)
		return
	}
	s.internalError(w, r, err)
}

// dsFail shows an error at the top of a page Datastar is updating.
func (s *Server) dsFail(w http.ResponseWriter, r *http.Request, err error) {
	var ae *apiError
	if errors.As(err, &ae) {
		s.dsWarn(w, r, ae.desc)
		return
	}
	s.log.Error("web request failed", "path", r.URL.Path, "error", err)
	s.dsWarn(w, r, "Something went wrong on the server. Try again, or reload the page.")
}
