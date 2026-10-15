package server

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// GitHubUser is the part of a GitHub profile the server uses. The numeric ID
// is the identity; the login is for display only.
type GitHubUser struct {
	ID    int64  `json:"id"`
	Login string `json:"login"`
}

// GitHub performs the OAuth web flow.
type GitHub interface {
	// AuthorizeURL returns the URL that starts the flow.
	AuthorizeURL(redirectURI, state, challenge string) string
	// Exchange trades the code for a token, reads the user, and discards the
	// token. GitHub tokens are never stored.
	Exchange(ctx context.Context, redirectURI, code, verifier string) (*GitHubUser, error)
}

type githubClient struct {
	cfg  GitHubConfig
	http *http.Client
}

func (g *githubClient) AuthorizeURL(redirectURI, state, challenge string) string {
	v := url.Values{}
	v.Set("client_id", g.cfg.ClientID)
	v.Set("redirect_uri", redirectURI)
	v.Set("state", state)
	// No scopes: the public profile (id and login) is all the server needs.
	v.Set("scope", "")
	v.Set("allow_signup", "false")
	v.Set("code_challenge", challenge)
	v.Set("code_challenge_method", "S256")
	return strings.TrimRight(g.cfg.WebURL, "/") + "/login/oauth/authorize?" + v.Encode()
}

func (g *githubClient) Exchange(ctx context.Context, redirectURI, code, verifier string) (*GitHubUser, error) {
	form := url.Values{}
	form.Set("client_id", g.cfg.ClientID)
	form.Set("client_secret", g.cfg.ClientSecret)
	form.Set("code", code)
	form.Set("redirect_uri", redirectURI)
	form.Set("code_verifier", verifier)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(g.cfg.WebURL, "/")+"/login/oauth/access_token", strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	var tok struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}
	if err := g.do(req, &tok); err != nil {
		return nil, err
	}
	if tok.AccessToken == "" {
		return nil, fmt.Errorf("github token exchange failed: %s %s", tok.Error, tok.Description)
	}
	req, err = http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(g.cfg.APIURL, "/")+"/user", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	var u GitHubUser
	if err := g.do(req, &u); err != nil {
		return nil, err
	}
	if u.ID <= 0 || u.Login == "" {
		return nil, errors.New("github returned an incomplete user")
	}
	return &u, nil
}

func (g *githubClient) do(req *http.Request, v any) error {
	resp, err := g.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("github %s: HTTP %d", req.URL.Path, resp.StatusCode)
	}
	return json.Unmarshal(body, v)
}

// PKCEChallenge derives the S256 code challenge for verifier.
func PKCEChallenge(verifier string) string { return pkceChallenge(verifier) }

// pkceChallenge derives the S256 code challenge for verifier.
func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
