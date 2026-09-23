// Package policy implements the broker's access policy: which peer may
// decrypt which project's environment.
package policy

import (
	"errors"
	"fmt"
	"os"
	"path"
	"strings"

	"github.com/pelletier/go-toml/v2"
)

// Action is a policy decision.
type Action string

// Policy actions.
const (
	Allow Action = "allow"
	Ask   Action = "ask"
	Deny  Action = "deny"
)

// Rule matches requests; the first matching rule decides.
type Rule struct {
	Project string   `toml:"project"`       // exact, "*" or "prefix/*"
	Env     []string `toml:"env"`           // empty means any
	UID     *uint32  `toml:"uid,omitempty"` // nil means any
	Action  Action   `toml:"action"`
}

// Policy is an ordered rule list with a default action.
type Policy struct {
	Default Action `toml:"default"`
	Rules   []Rule `toml:"rule"`
}

// Load reads a policy file. A missing file yields a deny-all policy; a policy
// file that exists but is invalid is an error.
func Load(path string) (*Policy, error) {
	data, err := os.ReadFile(path) //nolint:gosec // path is constructed from trusted home dir
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return &Policy{Default: Deny}, nil
		}
		return nil, err
	}
	var p Policy
	if err := toml.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("invalid policy file %s: %w", path, err)
	}
	if p.Default == "" {
		p.Default = Deny
	}
	for _, r := range p.Rules {
		switch r.Action {
		case Allow, Ask, Deny:
		default:
			return nil, fmt.Errorf("invalid policy action %q", r.Action)
		}
		if r.Project == "" {
			return nil, fmt.Errorf("policy rule missing project")
		}
	}
	return &p, nil
}

// Decide applies the first matching rule, or the default action.
func (p *Policy) Decide(project, env string, uid uint32) Action {
	for _, r := range p.Rules {
		if !matchProject(r.Project, project) {
			continue
		}
		if len(r.Env) > 0 && !containsString(r.Env, env) {
			continue
		}
		if r.UID != nil && *r.UID != uid {
			continue
		}
		return r.Action
	}
	if p.Default == "" {
		return Deny
	}
	return p.Default
}

// matchProject supports "org/repo", "*" and "prefix/*" patterns.
func matchProject(pattern, project string) bool {
	if pattern == "*" {
		return true
	}
	if strings.HasSuffix(pattern, "/*") {
		return strings.HasPrefix(project, strings.TrimSuffix(pattern, "*"))
	}
	matched, err := path.Match(pattern, project)
	return err == nil && matched
}

func containsString(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}
