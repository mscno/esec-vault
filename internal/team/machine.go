package team

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/nacl/box"

	"github.com/mscno/esec-vault/internal/envelope"
	"github.com/mscno/esec-vault/internal/identity"
)

// OIDC providers.
const (
	// ProviderGitHub is GitHub Actions' OIDC issuer.
	ProviderGitHub = "github"
	// ProviderFly is Fly.io's issuer of OIDC tokens for Machines, one per
	// organisation: https://oidc.fly.io/ORG.
	ProviderFly = "fly"
)

// FlyIssuerBase starts the issuer of a Fly.io organisation's tokens.
const FlyIssuerBase = "https://oidc.fly.io"

// Issuer returns the OIDC issuer a policy's tokens come from.
func (p *OIDCPolicy) Issuer() string {
	if p.Provider == ProviderFly {
		return FlyIssuerBase + "/" + p.FlyOrg
	}
	return "https://token.actions.githubusercontent.com"
}

// OIDCPolicy restricts a machine to workloads that prove who they are with
// an OIDC token, such as a GitHub Actions job: the server releases the
// machine's sealed keys only to requests whose token matches. The machine's
// secret is still needed to open them, so neither a leaked secret nor a
// workflow in another repository is enough on its own.
type OIDCPolicy struct {
	Provider string `json:"provider"`
	// Repository is the "owner/name" the job must run in, and RepositoryID
	// its numeric id, which survives renames (0: not checked).
	Repository   string `json:"repository"`
	RepositoryID int64  `json:"repository_id,omitempty"`
	// Refs, when set, are the git refs allowed, such as refs/heads/main;
	// a trailing * matches any suffix.
	Refs []string `json:"refs,omitempty"`
	// Environments, when set, are the GitHub deployment environments
	// allowed; a job outside every environment is refused.
	Environments []string `json:"environments,omitempty"`
	// FlyOrg is the Fly.io organisation (its slug) whose Machines may
	// fetch the keys; FlyApps, when set, the apps among them.
	FlyOrg  string   `json:"fly_org,omitempty"`
	FlyApps []string `json:"fly_apps,omitempty"`
}

var (
	refPattern      = regexp.MustCompile(`^refs/[A-Za-z0-9._/-]{1,200}\*?$`)
	flyNamePattern  = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	ghEnvPattern    = regexp.MustCompile(`^[A-Za-z0-9 _.-]{1,255}$`)
	repoNamePattern = regexp.MustCompile(`^[A-Za-z0-9-]{1,39}/[A-Za-z0-9._-]{1,100}$`)
)

// Validate checks a policy.
func (p *OIDCPolicy) Validate() error {
	switch p.Provider {
	case ProviderFly:
		return p.validateFly()
	case ProviderGitHub:
	default:
		return fmt.Errorf("unknown OIDC provider %q", p.Provider)
	}
	if p.FlyOrg != "" || len(p.FlyApps) > 0 {
		return errors.New("a GitHub policy names no Fly.io organisation or apps")
	}
	if !repoNamePattern.MatchString(p.Repository) {
		return fmt.Errorf("invalid repository %q: use owner/name", p.Repository)
	}
	if p.RepositoryID < 0 {
		return fmt.Errorf("invalid repository id")
	}
	if len(p.Refs) > 20 || len(p.Environments) > 20 {
		return fmt.Errorf("too many refs or environments")
	}
	for _, r := range p.Refs {
		if !refPattern.MatchString(r) {
			return fmt.Errorf("invalid ref %q: use refs/heads/NAME or refs/tags/NAME, optionally ending in *", r)
		}
	}
	for _, e := range p.Environments {
		if !ghEnvPattern.MatchString(e) {
			return fmt.Errorf("invalid environment %q", e)
		}
	}
	return nil
}

// Claims are the OIDC token claims a policy checks: GitHub Actions' and
// Fly.io's.
type Claims struct {
	Repository   string `json:"repository"`
	RepositoryID string `json:"repository_id"`
	Ref          string `json:"ref"`
	Environment  string `json:"environment"`
	// Recorded in the audit log, not checked.
	Workflow string `json:"workflow_ref"`
	RunID    string `json:"run_id"`
	Actor    string `json:"actor"`

	// Fly.io's.
	OrgName     string `json:"org_name"`
	AppName     string `json:"app_name"`
	MachineID   string `json:"machine_id"`
	MachineName string `json:"machine_name"`
	Region      string `json:"region"`
	ImageDigest string `json:"image_digest"`
}

// Detail describes the workload a token names, for the audit log.
func (c *Claims) Detail() string {
	if c.AppName != "" {
		return strings.Join([]string{"fly", c.OrgName + "/" + c.AppName, c.MachineName, c.MachineID, c.Region}, " ")
	}
	return strings.Join([]string{c.Repository, c.Ref, c.Environment, "run " + c.RunID, c.Actor}, " ")
}

// Allows reports why c does not match the policy, or nil.
func (p *OIDCPolicy) Allows(c *Claims) error {
	if p.Provider == ProviderFly {
		// The issuer, checked with the token's signature, names the
		// organisation already; its claim must agree.
		if c.OrgName != p.FlyOrg {
			return fmt.Errorf("the Machine is in the Fly.io organisation %q, not %q", c.OrgName, p.FlyOrg)
		}
		if len(p.FlyApps) > 0 && !slices.Contains(p.FlyApps, c.AppName) {
			return fmt.Errorf("the Fly.io app %q is not allowed", c.AppName)
		}
		return nil
	}
	if !strings.EqualFold(c.Repository, p.Repository) {
		return fmt.Errorf("the job runs in %q, not %q", c.Repository, p.Repository)
	}
	if p.RepositoryID != 0 && c.RepositoryID != strconv.FormatInt(p.RepositoryID, 10) {
		return fmt.Errorf("the repository id is %q, not %d (was the repository recreated?)", c.RepositoryID, p.RepositoryID)
	}
	if len(p.Refs) > 0 && !matchRef(p.Refs, c.Ref) {
		return fmt.Errorf("ref %q is not allowed", c.Ref)
	}
	if len(p.Environments) > 0 {
		ok := false
		for _, e := range p.Environments {
			if c.Environment == e {
				ok = true
			}
		}
		if !ok {
			return fmt.Errorf("environment %q is not allowed", c.Environment)
		}
	}
	return nil
}

func matchRef(patterns []string, ref string) bool {
	for _, p := range patterns {
		if prefix, ok := strings.CutSuffix(p, "*"); ok {
			if strings.HasPrefix(ref, prefix) {
				return true
			}
		} else if ref == p {
			return true
		}
	}
	return false
}

// Describe summarizes a policy for people.
func (p *OIDCPolicy) Describe() string {
	if p == nil {
		return ""
	}
	if p.Provider == ProviderFly {
		s := "Fly.io Machines of " + p.FlyOrg
		if len(p.FlyApps) > 0 {
			s += " (app " + strings.Join(p.FlyApps, ", ") + ")"
		}
		return s
	}
	parts := []string{"GitHub Actions in " + p.Repository}
	if len(p.Refs) > 0 {
		parts = append(parts, "on "+strings.Join(p.Refs, ", "))
	}
	if len(p.Environments) > 0 {
		parts = append(parts, "in environment "+strings.Join(p.Environments, ", "))
	}
	return strings.Join(parts, " ")
}

func (p *OIDCPolicy) validateFly() error {
	if p.Repository != "" || p.RepositoryID != 0 || len(p.Refs) > 0 || len(p.Environments) > 0 {
		return errors.New("a Fly.io policy names no GitHub repository, refs or environments")
	}
	if !flyNamePattern.MatchString(p.FlyOrg) {
		return fmt.Errorf("invalid Fly.io organisation %q: use its slug (fly orgs list)", p.FlyOrg)
	}
	if len(p.FlyApps) > 20 {
		return errors.New("too many Fly.io apps")
	}
	for _, a := range p.FlyApps {
		if !flyNamePattern.MatchString(a) {
			return fmt.Errorf("invalid Fly.io app name %q", a)
		}
	}
	return nil
}

// MachineKey is a machine's private identity. It is the one secret a CI
// job or app holds; the token form starts with TokenPrefix.
type MachineKey struct {
	Server  string `json:"server"`
	Project string `json:"project"`
	// Root is the hash of the project chain's first link: the machine
	// verifies the chain and its grants from it, trusting nothing else the
	// server says.
	Root     string `json:"root"`
	ID       string `json:"id"`
	EncPriv  []byte `json:"enc"`
	SignSeed []byte `json:"sign"`
}

// TokenPrefix starts every machine token, so secret scanners can find one.
const TokenPrefix = "esecm1_"

// NewMachineKey creates a machine's keys.
func NewMachineKey(server, project, root, name string, now time.Time) (*MachineKey, Machine, error) {
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, Machine{}, err
	}
	signPub, sign, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, Machine{}, err
	}
	idBytes := make([]byte, 15)
	if _, err := rand.Read(idBytes); err != nil {
		return nil, Machine{}, err
	}
	id := "m_" + base32Lower(idBytes)
	k := &MachineKey{Server: server, Project: project, Root: root, ID: id, EncPriv: priv[:], SignSeed: sign.Seed()}
	m := Machine{ID: id, Name: name, EncPub: hex.EncodeToString(pub[:]), SignPub: hex.EncodeToString(signPub), Created: now.UTC().Truncate(time.Second)}
	return k, m, nil
}

func base32Lower(b []byte) string {
	const alphabet = "abcdefghijklmnopqrstuvwxyz234567"
	var out strings.Builder
	var buf uint64
	bits := 0
	for _, c := range b {
		buf = buf<<8 | uint64(c)
		bits += 8
		for bits >= 5 {
			out.WriteByte(alphabet[(buf>>(bits-5))&31])
			bits -= 5
		}
	}
	if bits > 0 {
		out.WriteByte(alphabet[(buf<<(5-bits))&31])
	}
	return out.String()
}

// Token encodes k as one string.
func (k *MachineKey) Token() string {
	raw, err := json.Marshal(k)
	if err != nil {
		panic(err) // strings and byte slices always marshal
	}
	return TokenPrefix + base64.RawURLEncoding.EncodeToString(raw)
}

// ParseToken decodes a machine token.
func ParseToken(s string) (*MachineKey, error) {
	rest, ok := strings.CutPrefix(strings.TrimSpace(s), TokenPrefix)
	if !ok {
		return nil, errors.New("not an esec vault machine key (it starts with " + TokenPrefix + ")")
	}
	raw, err := base64.RawURLEncoding.DecodeString(rest)
	if err != nil {
		return nil, errors.New("the machine key is damaged")
	}
	var k MachineKey
	if err := envelope.DecodeStrict(raw, &k); err != nil {
		return nil, errors.New("the machine key is damaged")
	}
	if err := ValidProject(k.Project); err != nil {
		return nil, err
	}
	if err := ValidMachineID(k.ID); err != nil || !rootPattern.MatchString(k.Root) || len(k.EncPriv) != 32 || len(k.SignSeed) != ed25519.SeedSize || k.Server == "" {
		return nil, errors.New("the machine key is damaged")
	}
	return &k, nil
}

// Sign returns the machine's signing key.
func (k *MachineKey) Sign() ed25519.PrivateKey { return ed25519.NewKeyFromSeed(k.SignSeed) }

// Keys returns the machine's X25519 keypair.
func (k *MachineKey) Keys() (pub, priv [32]byte) {
	copy(priv[:], k.EncPriv)
	return identity.PublicFromPrivate(priv), priv
}

// Matches reports whether m describes this key.
func (k *MachineKey) Matches(m Machine) bool {
	pub, _ := k.Keys()
	signPub, _ := k.Sign().Public().(ed25519.PublicKey)
	return m.ID == k.ID && m.EncPub == hex.EncodeToString(pub[:]) && m.SignPub == hex.EncodeToString(signPub)
}

// KeysMessage is what a machine signs to fetch its keys. The OIDC token's
// hash is covered, so a captured request cannot carry another token.
func KeysMessage(machine, project string, timestamp int64, nonce, oidcTokenHash string) []byte {
	return []byte(fmt.Sprintf("esec-vault machine-keys v1\n%s\n%s\n%d\n%s\n%s", machine, project, timestamp, nonce, oidcTokenHash))
}
