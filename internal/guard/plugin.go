package guard

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

// pluginNames are the hardware plugins the guard knows.
var pluginNames = []string{"yubikey", "se"}

// CheckPlugin finds the age plugin of a hardware holder and checks that
// only its owner (the person, or root) can replace it: the program itself
// and its directory are neither group- nor world-writable, after symlinks.
// It returns the plugin's resolved path.
//
// This keeps another user from swapping the program that sees the guard's
// file key. It cannot stop a program running as the person: see "What it
// does not protect" in docs/design/guard.md.
func CheckPlugin(name string) (string, error) {
	path, err := exec.LookPath("age-plugin-" + name)
	if err != nil {
		return "", fmt.Errorf("age-plugin-%s is not installed: %w", name, err)
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", err
	}
	if !filepath.IsAbs(resolved) {
		if resolved, err = filepath.Abs(resolved); err != nil {
			return "", err
		}
	}
	for _, p := range []string{resolved, filepath.Dir(resolved)} {
		info, err := os.Stat(p)
		if err != nil {
			return "", err
		}
		if info.Mode().Perm()&0o022 != 0 {
			return "", fmt.Errorf("refusing age-plugin-%s: %s is writable by other users", name, p)
		}
		if st, ok := info.Sys().(*syscall.Stat_t); ok && st.Uid != 0 && int(st.Uid) != os.Getuid() {
			return "", fmt.Errorf("refusing age-plugin-%s: %s belongs to another user", name, p)
		}
	}
	return resolved, nil
}

// PinPlugins puts the checked directories of the installed hardware
// plugins first on this process's PATH, so later lookups find those very
// programs whatever else PATH holds. The background service calls it once
// at start.
func PinPlugins() {
	var dirs []string
	for _, name := range pluginNames {
		if p, err := CheckPlugin(name); err == nil {
			dirs = append(dirs, filepath.Dir(p))
		}
	}
	if len(dirs) > 0 {
		_ = os.Setenv("PATH", strings.Join(append(dirs, os.Getenv("PATH")), string(os.PathListSeparator)))
	}
}
