// Package service installs an OS-managed per-user daemon and tracks every
// owned artifact so removal does not depend on a healthy daemon process.
package service

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/mscno/esec-vault/internal/paths"
	"github.com/mscno/esec-vault/internal/storage"
)

// Manifest is installation intent, written before service artifacts. No secrets
// are recorded: environment entries are paths or profile names only.
type Manifest struct {
	Version     int               `json:"version"`
	OS          string            `json:"os"`
	UID         int               `json:"uid"`
	Home        string            `json:"home"`
	Name        string            `json:"name"`
	Unit        string            `json:"unit"`
	Binary      string            `json:"binary"`
	Runtime     string            `json:"runtime"`
	Log         string            `json:"log"`
	Environment map[string]string `json:"environment"`
}

// Runner executes service-manager commands. Tests substitute an OS simulation.
type Runner func(ctx context.Context, name string, args ...string) ([]byte, error)

// Manager encapsulates platform paths, ownership and the OS service manager.
type Manager struct {
	Manifest Manifest
	Run      Runner
}

// New selects the current user's service manager without using root services.
func New() (*Manager, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	return NewAt(runtime.GOOS, os.Getuid(), home, paths.Home(), os.Getenv("XDG_CONFIG_HOME"), run)
}

// NewAt constructs a manager with explicit paths for isolated tests.
func NewAt(platform string, uid int, userHome, vaultHome, xdg string, runner Runner) (*Manager, error) {
	if platform != "darwin" && platform != "linux" {
		return nil, fmt.Errorf("managed daemon requires macOS or Linux")
	}
	home, err := filepath.Abs(vaultHome)
	if err != nil {
		return nil, err
	}
	if home == string(filepath.Separator) || home == userHome {
		return nil, fmt.Errorf("vault home must be a dedicated directory")
	}
	hash := sha256.Sum256([]byte(home))
	name := "io.github.mscno.esec-vault." + hex.EncodeToString(hash[:6])
	base := filepath.Join(home, "daemon")
	m := Manifest{Version: 1, OS: platform, UID: uid, Home: home, Name: name, Binary: filepath.Join(base, "esec-vault"), Runtime: filepath.Join(home, "run"), Log: filepath.Join(base, "daemon.log"), Environment: map[string]string{"ESEC_VAULT_HOME": home}}
	if platform == "darwin" {
		m.Unit = filepath.Join(userHome, "Library", "LaunchAgents", name+".plist")
	} else {
		if xdg == "" {
			xdg = filepath.Join(userHome, ".config")
		}
		m.Unit = filepath.Join(xdg, "systemd", "user", name+".service")
	}
	return &Manager{Manifest: m, Run: runner}, nil
}

// Install records ownership, copies a stable executable and enables login startup.
func (m *Manager) Install(ctx context.Context, source string, start bool) error {
	if err := m.validateDirectories(); err != nil {
		return err
	}
	if err := m.existing(); err != nil {
		return err
	}
	if _, err := os.Stat(m.manifestPath()); err == nil {
		if err := m.Disable(ctx); err != nil {
			return err
		}
	}
	data, err := os.ReadFile(source) //nolint:gosec // caller-selected executable, normally os.Executable
	if err != nil {
		return err
	}
	if err := captureEnvironment(m.Manifest.Environment); err != nil {
		return err
	}
	manifest, err := json.MarshalIndent(m.Manifest, "", "  ")
	if err != nil {
		return err
	}
	if err := storage.Write(m.manifestPath(), manifest); err != nil {
		return err
	}
	if err := storage.Write(m.Manifest.Binary, data); err != nil {
		return err
	}
	if err := os.Chmod(m.Manifest.Binary, 0700); err != nil { //nolint:gosec // private executable must be executable by its owner
		return err
	}
	if _, err := os.Stat(m.Manifest.Log); errors.Is(err, os.ErrNotExist) {
		if err := storage.Write(m.Manifest.Log, nil); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	unit, err := m.UnitContents()
	if err != nil {
		return err
	}
	if err := storage.Write(m.Manifest.Unit, unit); err != nil {
		return err
	}
	if err := m.enable(ctx); err != nil {
		return err
	}
	if start {
		return m.Start(ctx)
	}
	return nil
}

func captureEnvironment(env map[string]string) error {
	for _, key := range []string{"PATH", "ESEC_KEYRING_DIR", "RCLONE_CONFIG", "RESTIC_PASSWORD_FILE", "RESTIC_REPOSITORY", "AWS_PROFILE", "AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE"} {
		value := os.Getenv(key)
		if value == "" {
			continue
		}
		switch key {
		case "PATH":
			parts := filepath.SplitList(value)
			for i, p := range parts {
				abs, err := filepath.Abs(p)
				if err != nil {
					return err
				}
				parts[i] = abs
			}
			value = strings.Join(parts, string(os.PathListSeparator))
		case "AWS_PROFILE":
		case "RESTIC_REPOSITORY":
			if !strings.Contains(value, ":") {
				abs, err := filepath.Abs(value)
				if err != nil {
					return err
				}
				value = abs
			}
		default:
			abs, err := filepath.Abs(value)
			if err != nil {
				return err
			}
			value = abs
		}
		env[key] = value
	}
	return nil
}

// Start enables and starts the installed user service.
func (m *Manager) Start(ctx context.Context) error {
	if err := m.load(); err != nil {
		return err
	}
	if err := m.enable(ctx); err != nil {
		return err
	}
	if m.Manifest.OS == "linux" {
		_, err := m.Run(ctx, "systemctl", "--user", "start", m.Manifest.Name)
		return err
	}
	loaded, err := m.Loaded(ctx)
	if err != nil {
		return err
	}
	if !loaded {
		_, err = m.Run(ctx, "launchctl", "bootstrap", m.domain(), m.Manifest.Unit)
		return err
	}
	_, err = m.Run(ctx, "launchctl", "kickstart", m.target())
	return err
}

// Stop unloads/stops the service without disabling login startup.
func (m *Manager) Stop(ctx context.Context) error {
	if err := m.load(); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	loaded, err := m.Loaded(ctx)
	if err != nil {
		return err
	}
	if !loaded {
		return nil
	}
	if m.Manifest.OS == "darwin" {
		_, err = m.Run(ctx, "launchctl", "bootout", m.target())
	} else {
		_, err = m.Run(ctx, "systemctl", "--user", "stop", m.Manifest.Name)
	}
	if err != nil {
		return err
	}
	return m.waitStopped(ctx)
}

// Disable stops the process and prevents automatic restart/login startup.
func (m *Manager) Disable(ctx context.Context) error {
	if err := m.load(); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	var err error
	if m.Manifest.OS == "darwin" {
		_, err = m.Run(ctx, "launchctl", "disable", m.target())
	} else {
		if _, statErr := os.Stat(m.Manifest.Unit); statErr == nil {
			_, err = m.Run(ctx, "systemctl", "--user", "disable", m.Manifest.Name)
		} else if !errors.Is(statErr, os.ErrNotExist) {
			return statErr
		}
	}
	if err != nil {
		return err
	}
	return m.Stop(ctx)
}

// Uninstall removes only installation-owned files after the OS confirms exit.
// It preserves identity, keys, snapshots, configuration and externally installed tools.
func (m *Manager) Uninstall(ctx context.Context) error {
	if err := m.load(); errors.Is(err, os.ErrNotExist) {
		return m.checkAbsent(ctx)
	} else if err != nil {
		return err
	}
	if err := m.Disable(ctx); err != nil {
		return err
	}
	if m.Manifest.OS == "linux" {
		if loaded, err := m.Loaded(ctx); err != nil {
			return err
		} else if loaded {
			if _, err := m.Run(ctx, "systemctl", "--user", "reset-failed", m.Manifest.Name); err != nil {
				return err
			}
		}
	}
	if err := remove(m.Manifest.Unit); err != nil {
		return err
	}
	if m.Manifest.OS == "linux" {
		if _, err := m.Run(ctx, "systemctl", "--user", "daemon-reload"); err != nil {
			return err
		}
	} else {
		// Remove the disabled override after the unloaded service file is gone.
		if _, err := m.Run(ctx, "launchctl", "enable", m.target()); err != nil {
			return err
		}
	}
	if loaded, err := m.Loaded(ctx); err != nil {
		return err
	} else if loaded {
		return fmt.Errorf("service remains registered; refusing artifact deletion")
	}
	for _, p := range m.artifacts() {
		if err := remove(p); err != nil {
			return err
		}
	}
	for _, p := range []string{m.Manifest.Runtime, filepath.Dir(m.Manifest.Binary)} {
		if err := removeEmpty(p); err != nil {
			return err
		}
	}
	if err := remove(m.manifestPath()); err != nil {
		return err
	}
	return removeIfEmpty(m.Manifest.Home)
}

// Loaded checks OS registration, not a potentially stale PID file.
func (m *Manager) Loaded(ctx context.Context) (bool, error) {
	if m.Manifest.OS == "darwin" {
		_, err := m.Run(ctx, "launchctl", "print", m.target())
		if err == nil {
			return true, nil
		}
		if exitCode(err) == 113 {
			return false, nil
		}
		return false, err
	}
	out, err := m.Run(ctx, "systemctl", "--user", "show", m.Manifest.Name, "--property=LoadState", "--value")
	if err != nil {
		return false, err
	}
	return strings.TrimSpace(string(out)) != "not-found", nil
}

// Running verifies process exit using service-manager state.
func (m *Manager) Running(ctx context.Context) (bool, error) {
	if m.Manifest.OS == "darwin" {
		return m.Loaded(ctx)
	}
	out, err := m.Run(ctx, "systemctl", "--user", "show", m.Manifest.Name, "--property=MainPID", "--value")
	if err != nil {
		return false, err
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(out)))
	if err != nil {
		return false, err
	}
	return pid != 0, nil
}

// UnitContents renders an escaped, deterministic launchd plist or systemd unit.
func (m *Manager) UnitContents() ([]byte, error) {
	if m.Manifest.OS == "linux" {
		return []byte(m.systemd()), nil
	}
	var b bytes.Buffer
	b.WriteString("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<plist version=\"1.0\"><dict>\n")
	item := func(key, value string) {
		b.WriteString("<key>" + key + "</key><string>")
		_ = xml.EscapeText(&b, []byte(value))
		b.WriteString("</string>\n")
	}
	item("Label", m.Manifest.Name)
	b.WriteString("<key>ProgramArguments</key><array>")
	for _, a := range []string{m.Manifest.Binary, "daemon", "run"} {
		b.WriteString("<string>")
		_ = xml.EscapeText(&b, []byte(a))
		b.WriteString("</string>")
	}
	b.WriteString("</array><key>RunAtLoad</key><true/><key>KeepAlive</key><true/><key>ThrottleInterval</key><integer>10</integer>\n")
	item("StandardOutPath", m.Manifest.Log)
	item("StandardErrorPath", m.Manifest.Log)
	b.WriteString("<key>EnvironmentVariables</key><dict>")
	for _, k := range sortedEnvironment(m.Manifest.Environment) {
		item(k, m.Manifest.Environment[k])
	}
	b.WriteString("</dict><key>Umask</key><integer>63</integer></dict></plist>\n")
	return b.Bytes(), nil
}

func (m *Manager) systemd() string {
	quote := func(s string) string { return strconv.Quote(strings.ReplaceAll(s, "%", "%%")) }
	var b strings.Builder
	b.WriteString("# Managed by esec-vault\n[Unit]\nDescription=esec-vault user daemon\n[Service]\nType=simple\n")
	fmt.Fprintf(&b, "ExecStart=%s daemon run\nRestart=on-failure\nRestartSec=10\nTimeoutStopSec=30\nUMask=0077\n", quote(strings.ReplaceAll(m.Manifest.Binary, "$", "$$")))
	for _, k := range sortedEnvironment(m.Manifest.Environment) {
		fmt.Fprintf(&b, "Environment=%s\n", quote(k+"="+m.Manifest.Environment[k]))
	}
	b.WriteString("[Install]\nWantedBy=default.target\n")
	return b.String()
}

func (m *Manager) enable(ctx context.Context) error {
	if m.Manifest.OS == "darwin" {
		_, err := m.Run(ctx, "launchctl", "enable", m.target())
		return err
	}
	if _, err := m.Run(ctx, "systemctl", "--user", "daemon-reload"); err != nil {
		return err
	}
	_, err := m.Run(ctx, "systemctl", "--user", "enable", m.Manifest.Name)
	return err
}
func (m *Manager) waitStopped(ctx context.Context) error {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		running, err := m.Running(ctx)
		if err != nil {
			return err
		}
		if !running {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}
func (m *Manager) load() error {
	data, err := os.ReadFile(m.manifestPath())
	if err != nil {
		return err
	}
	var got Manifest
	if err := json.Unmarshal(data, &got); err != nil {
		return err
	}
	want := m.Manifest
	if got.Version != 1 || got.OS != want.OS || got.UID != want.UID || got.Home != want.Home || got.Name != want.Name || got.Unit != want.Unit || got.Binary != want.Binary || got.Runtime != want.Runtime || got.Log != want.Log {
		return fmt.Errorf("installation manifest does not match this user's managed paths")
	}
	return nil
}
func (m *Manager) existing() error {
	if err := m.load(); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	for _, p := range append(m.artifacts(), m.Manifest.Unit) {
		if _, err := os.Lstat(p); err == nil {
			return fmt.Errorf("unowned installation artifact exists: %s", p)
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}
func (m *Manager) checkAbsent(ctx context.Context) error {
	if _, err := os.Lstat(m.Manifest.Unit); err == nil {
		return fmt.Errorf("service file exists without installation manifest")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if loaded, err := m.Loaded(ctx); err != nil {
		return err
	} else if loaded {
		return fmt.Errorf("service is registered without installation manifest")
	}
	for _, p := range m.artifacts() {
		if _, err := os.Lstat(p); err == nil {
			return fmt.Errorf("installation artifact exists without a manifest; stop any foreground daemon before removal: %s", p)
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	if err := removeEmpty(m.Manifest.Runtime); err != nil {
		return err
	}
	return removeIfEmpty(m.Manifest.Home)
}

func (m *Manager) validateDirectories() error {
	for _, p := range []string{m.Manifest.Home, filepath.Dir(m.Manifest.Binary), m.Manifest.Runtime} {
		if info, err := os.Lstat(p); err == nil && info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing managed symlink directory %s", p)
		} else if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

func removeIfEmpty(p string) error {
	entries, err := os.ReadDir(p)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if len(entries) == 0 {
		return os.Remove(p)
	}
	return nil
}
func (m *Manager) artifacts() []string {
	return []string{m.Manifest.Binary, m.Manifest.Log, m.Manifest.Log + ".1", filepath.Join(m.Manifest.Runtime, "control.sock"), filepath.Join(m.Manifest.Runtime, "agent.sock")}
}
func (m *Manager) manifestPath() string { return filepath.Join(m.Manifest.Home, "daemon-install.json") }
func (m *Manager) domain() string       { return "gui/" + strconv.Itoa(m.Manifest.UID) }
func (m *Manager) target() string       { return m.domain() + "/" + m.Manifest.Name }
func run(ctx context.Context, name string, args ...string) ([]byte, error) {
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("%s: %w: %s", name, err, strings.TrimSpace(string(out)))
	}
	return out, nil
}
func exitCode(err error) int {
	var e interface{ ExitCode() int }
	if errors.As(err, &e) {
		return e.ExitCode()
	}
	return -1
}
func remove(p string) error {
	if info, err := os.Lstat(p); err == nil && info.Mode()&os.ModeSocket != 0 {
		if conn, err := net.DialTimeout("unix", p, time.Second); err == nil {
			conn.Close()
			return fmt.Errorf("socket is still active; refusing removal: %s", p)
		}
	}
	err := os.Remove(p)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}
func removeEmpty(p string) error {
	entries, err := os.ReadDir(p)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if len(entries) > 0 {
		return fmt.Errorf("managed directory contains unexpected files: %s", p)
	}
	return os.Remove(p)
}
