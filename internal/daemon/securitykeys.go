package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/mscno/esec-vault/internal/paths"
	"github.com/mscno/esec-vault/internal/securitykey"
)

// detectEvery is how often the daemon looks for plugged-in YubiKeys.
var detectEvery = time.Minute

// SeenKeys is what the daemon last found plugged in, for the Mac app, and
// which YubiKeys it has told the person about already.
type SeenKeys struct {
	Checked time.Time `json:"checked"`
	// PluggedIn are the age identities on the YubiKeys plugged in now.
	PluggedIn []SeenKey `json:"plugged_in"`
	// Unprovisioned are serials of plugged-in YubiKeys with no age identity.
	Unprovisioned []string `json:"unprovisioned"`
	// Notified are serials the person was told about, once each.
	Notified []string `json:"notified"`
}

// SeenKey is a plugged-in YubiKey slot.
type SeenKey struct {
	securitykey.Detected

	Registered bool `json:"registered"`
}

// SeenKeysFile is where SeenKeys is kept.
func SeenKeysFile() string { return filepath.Join(paths.Home(), "security-keys-seen.json") }

// LoadSeenKeys reads SeenKeys; a missing file is an empty one.
func LoadSeenKeys() (*SeenKeys, error) {
	data, err := os.ReadFile(SeenKeysFile())
	if errors.Is(err, os.ErrNotExist) {
		return &SeenKeys{}, nil
	}
	if err != nil {
		return nil, err
	}
	var s SeenKeys
	return &s, json.Unmarshal(data, &s)
}

func (s *SeenKeys) save() error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := SeenKeysFile() + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, SeenKeysFile())
}

// securityKeyLoop looks for YubiKeys now and then, and tells the person
// once about each one that is plugged in but not registered, or that has no
// age identity yet. ESEC_VAULT_DETECT=off turns it off; without
// age-plugin-yubikey it stays quiet.
func (s *Server) securityKeyLoop(ctx context.Context) {
	if strings.EqualFold(os.Getenv("ESEC_VAULT_DETECT"), "off") {
		return
	}
	t := time.NewTicker(detectEvery)
	defer t.Stop()
	for {
		s.detectOnce(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (s *Server) detectOnce(ctx context.Context) {
	plugged, err := securitykey.Detect(ctx)
	if errors.Is(err, securitykey.ErrNoPlugin) {
		return
	}
	if err != nil {
		s.Logger.Debug("detect security keys", "error", err)
		return
	}
	reg, err := securitykey.Load()
	if err != nil {
		s.Logger.Warn("security keys", "error", err)
		return
	}
	seen, err := LoadSeenKeys()
	if err != nil {
		seen = &SeenKeys{}
	}
	unprovisioned, _ := securitykey.DetectUnprovisioned(ctx)
	seen.Checked = time.Now().UTC().Truncate(time.Second)
	seen.PluggedIn = seen.PluggedIn[:0]
	seen.Unprovisioned = unprovisioned
	for _, d := range plugged {
		registered := reg.Has(d.Recipient)
		seen.PluggedIn = append(seen.PluggedIn, SeenKey{Detected: d, Registered: registered})
		if registered || slices.Contains(seen.Notified, d.Serial) {
			continue
		}
		seen.Notified = append(seen.Notified, d.Serial)
		Notifier("esec: new YubiKey", "YubiKey "+d.Serial+" is not one of your security keys yet. To open guarded environments with it: esec vault security-keys add")
	}
	for _, serial := range unprovisioned {
		if slices.Contains(seen.Notified, serial) {
			continue
		}
		seen.Notified = append(seen.Notified, serial)
		Notifier("esec: new YubiKey", "YubiKey "+serial+" has no age key yet. To use it for esec: esec vault security-keys setup --serial "+serial)
	}
	if err := seen.save(); err != nil {
		s.Logger.Warn("security keys", "error", err)
	}
}
