package server

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/pelletier/go-toml/v2"
)

// Config configures the server. Secrets (the GitHub client secret) come only
// from the environment, never from the file.
type Config struct {
	BaseURL string `toml:"base_url"`
	Listen  string `toml:"listen"`
	DBPath  string `toml:"db_path"`
	// VaultHistory is how many vault versions are kept per user.
	VaultHistory int `toml:"vault_history"`
	// ClientIPHeader names a header set by a trusted reverse proxy that
	// carries the client address (for example Fly-Client-IP). Empty means
	// the TCP peer address.
	ClientIPHeader string `toml:"client_ip_header"`
	// NewDevices is "open" (default) or "closed". Closed is an emergency
	// switch for an attack: only devices the server already trusts, and
	// browsers that signed in before, can sign in; new ones are refused.
	NewDevices string `toml:"new_devices"`

	// BootstrapToken must accompany the creation of every account. It comes
	// from ESEC_SERVER_BOOTSTRAP_TOKEN only. Without it, whoever controls an
	// allowlisted GitHub account before its owner's first login could create
	// the vault account with their own keys.
	BootstrapToken string `toml:"-"`

	GitHub   GitHubConfig   `toml:"github"`
	Access   AccessConfig   `toml:"access"`
	Sessions SessionsConfig `toml:"sessions"`
}

// GitHubConfig configures the GitHub OAuth app.
type GitHubConfig struct {
	ClientID string `toml:"client_id"`
	// ClientSecret is read from ESEC_SERVER_GITHUB_CLIENT_SECRET only.
	ClientSecret string `toml:"-"`
	// WebURL and APIURL default to github.com; tests point them elsewhere.
	WebURL string `toml:"web_url"`
	APIURL string `toml:"api_url"`
}

// AccessConfig lists who may sign in.
type AccessConfig struct {
	// AllowedGitHubIDs are numeric GitHub user IDs. Usernames are never used
	// for access: they can be renamed and later claimed by someone else.
	AllowedGitHubIDs []int64 `toml:"allowed_github_ids"`
	// AdminGitHubIDs may open the read-only admin pages: every account's
	// devices, activity and storage, and the server's status. Each must also
	// be allowed.
	AdminGitHubIDs []int64 `toml:"admin_github_ids"`
}

// SessionsConfig sets CLI session lifetimes.
type SessionsConfig struct {
	Idle     Duration `toml:"idle"`
	Absolute Duration `toml:"absolute"`
}

// Duration is a TOML string duration such as "720h".
type Duration struct{ time.Duration }

// UnmarshalText implements encoding.TextUnmarshaler.
func (d *Duration) UnmarshalText(b []byte) error {
	v, err := time.ParseDuration(string(b))
	if err != nil {
		return err
	}
	d.Duration = v
	return nil
}

// MarshalText implements encoding.TextMarshaler.
func (d Duration) MarshalText() ([]byte, error) { return []byte(d.String()), nil }

// Defaults.
const (
	defaultListen       = ":8080"
	defaultVaultHistory = 50
	defaultIdle         = 30 * 24 * time.Hour
	defaultAbsolute     = 90 * 24 * time.Hour
)

// LoadConfig reads the TOML file at path (optional when empty) and applies
// ESEC_SERVER_* environment overrides.
func LoadConfig(path string) (*Config, error) {
	c := &Config{}
	if path != "" {
		data, err := os.ReadFile(path) //nolint:gosec // operator-supplied config path
		if err != nil {
			return nil, err
		}
		dec := toml.NewDecoder(strings.NewReader(string(data)))
		dec.DisallowUnknownFields()
		if err := dec.Decode(c); err != nil {
			return nil, fmt.Errorf("config %s: %w", path, err)
		}
	}
	if err := c.applyEnv(); err != nil {
		return nil, err
	}
	c.defaults()
	return c, c.Validate()
}

func parseIDs(s string) ([]int64, error) {
	var out []int64
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		n, err := strconv.ParseInt(part, 10, 64)
		if err != nil || n <= 0 {
			return nil, fmt.Errorf("invalid GitHub user id %q (use numeric ids, not usernames)", part)
		}
		out = append(out, n)
	}
	return out, nil
}

// Validate checks the configuration.
func (c *Config) Validate() error { //nolint:gocyclo // flat list of independent checks
	var errs []error
	u, err := url.Parse(c.BaseURL)
	switch {
	case c.BaseURL == "" || err != nil || u.Host == "" || u.Path != "" || u.RawQuery != "" || u.User != nil:
		errs = append(errs, errors.New("base_url must be an origin such as https://vault.example.com"))
	case u.Scheme != "https" && (u.Scheme != "http" || !isLoopback(u.Hostname())):
		errs = append(errs, errors.New("base_url must use https (http is allowed only for localhost)"))
	}
	if c.DBPath == "" {
		errs = append(errs, errors.New("db_path is required"))
	}
	if c.GitHub.ClientID == "" {
		errs = append(errs, errors.New("github.client_id is required"))
	}
	if c.GitHub.ClientSecret == "" {
		errs = append(errs, errors.New("ESEC_SERVER_GITHUB_CLIENT_SECRET is required"))
	}
	if len(c.BootstrapToken) < 16 {
		errs = append(errs, errors.New("ESEC_SERVER_BOOTSTRAP_TOKEN is required (at least 16 characters, e.g. openssl rand -base64 24): it authorizes creating accounts"))
	}
	if len(c.Access.AllowedGitHubIDs) == 0 {
		errs = append(errs, errors.New("access.allowed_github_ids must list at least one numeric GitHub user id"))
	}
	for _, id := range c.Access.AllowedGitHubIDs {
		if id <= 0 {
			errs = append(errs, fmt.Errorf("invalid GitHub user id %d", id))
		}
	}
	for _, id := range c.Access.AdminGitHubIDs {
		if !c.Allowed(id) {
			errs = append(errs, fmt.Errorf("admin GitHub user id %d is not in access.allowed_github_ids", id))
		}
	}
	if c.NewDevices != "" && c.NewDevices != NewDevicesOpen && c.NewDevices != NewDevicesClosed {
		errs = append(errs, fmt.Errorf("new_devices must be %q or %q", NewDevicesOpen, NewDevicesClosed))
	}
	if c.VaultHistory < 1 || c.VaultHistory > 1000 {
		errs = append(errs, errors.New("vault_history must be between 1 and 1000"))
	}
	if c.Sessions.Idle.Duration < time.Hour || c.Sessions.Absolute.Duration < c.Sessions.Idle.Duration || c.Sessions.Absolute.Duration > 366*24*time.Hour {
		errs = append(errs, errors.New("sessions: idle must be at least 1h and absolute between idle and 366 days"))
	}
	for _, raw := range []string{c.GitHub.WebURL, c.GitHub.APIURL} {
		if gu, err := url.Parse(raw); err != nil || gu.Host == "" || (gu.Scheme != "https" && (gu.Scheme != "http" || !isLoopback(gu.Hostname()))) {
			errs = append(errs, fmt.Errorf("invalid GitHub URL %q", raw))
		}
	}
	return errors.Join(errs...)
}

// UserBootstrapToken derives the account creation token of one GitHub user
// from the server's bootstrap secret. Each person gets their own token, so a
// token can only create its own account, and only once (an account is
// created once).
func UserBootstrapToken(secret string, githubID int64) string {
	mac := hmac.New(sha256.New, []byte(secret))
	fmt.Fprintf(mac, "esec-vault bootstrap v1\n%d", githubID)
	return "esb_" + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// Values of Config.NewDevices.
const (
	NewDevicesOpen   = "open"
	NewDevicesClosed = "closed"
)

// Secure reports whether the server is served over https.
func (c *Config) Secure() bool { return strings.HasPrefix(c.BaseURL, "https://") }

// Allowed reports whether a GitHub user id may sign in.
func (c *Config) Allowed(githubID int64) bool {
	for _, id := range c.Access.AllowedGitHubIDs {
		if id == githubID {
			return true
		}
	}
	return false
}

// Admin reports whether a GitHub user id may open the admin pages.
func (c *Config) Admin(githubID int64) bool {
	return c.Allowed(githubID) && slices.Contains(c.Access.AdminGitHubIDs, githubID)
}

func isLoopback(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

func (c *Config) applyEnv() error {
	set := func(env string, dst *string) {
		if v := os.Getenv(env); v != "" {
			*dst = v
		}
	}
	set("ESEC_SERVER_BASE_URL", &c.BaseURL)
	set("ESEC_SERVER_LISTEN", &c.Listen)
	set("ESEC_SERVER_DB_PATH", &c.DBPath)
	set("ESEC_SERVER_CLIENT_IP_HEADER", &c.ClientIPHeader)
	set("ESEC_SERVER_NEW_DEVICES", &c.NewDevices)
	set("ESEC_SERVER_GITHUB_CLIENT_ID", &c.GitHub.ClientID)
	set("ESEC_SERVER_GITHUB_WEB_URL", &c.GitHub.WebURL)
	set("ESEC_SERVER_GITHUB_API_URL", &c.GitHub.APIURL)
	c.GitHub.ClientSecret = os.Getenv("ESEC_SERVER_GITHUB_CLIENT_SECRET")
	c.BootstrapToken = os.Getenv("ESEC_SERVER_BOOTSTRAP_TOKEN")
	if v := os.Getenv("ESEC_SERVER_ALLOWED_GITHUB_IDS"); v != "" {
		ids, err := parseIDs(v)
		if err != nil {
			return fmt.Errorf("ESEC_SERVER_ALLOWED_GITHUB_IDS: %w", err)
		}
		c.Access.AllowedGitHubIDs = ids
	}
	if v := os.Getenv("ESEC_SERVER_ADMIN_GITHUB_IDS"); v != "" {
		ids, err := parseIDs(v)
		if err != nil {
			return fmt.Errorf("ESEC_SERVER_ADMIN_GITHUB_IDS: %w", err)
		}
		c.Access.AdminGitHubIDs = ids
	}
	if v := os.Getenv("ESEC_SERVER_VAULT_HISTORY"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return fmt.Errorf("ESEC_SERVER_VAULT_HISTORY: %w", err)
		}
		c.VaultHistory = n
	}
	return nil
}

func (c *Config) defaults() {
	if c.Listen == "" {
		c.Listen = defaultListen
	}
	if c.NewDevices == "" {
		c.NewDevices = NewDevicesOpen
	}
	if c.VaultHistory == 0 {
		c.VaultHistory = defaultVaultHistory
	}
	if c.Sessions.Idle.Duration == 0 {
		c.Sessions.Idle.Duration = defaultIdle
	}
	if c.Sessions.Absolute.Duration == 0 {
		c.Sessions.Absolute.Duration = defaultAbsolute
	}
	if c.GitHub.WebURL == "" {
		c.GitHub.WebURL = "https://github.com"
	}
	if c.GitHub.APIURL == "" {
		c.GitHub.APIURL = "https://api.github.com"
	}
	c.BaseURL = strings.TrimRight(c.BaseURL, "/")
}

// newDevicesClosed reports whether the emergency switch is on.
func (c *Config) newDevicesClosed() bool { return c.NewDevices == NewDevicesClosed }
