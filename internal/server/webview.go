package server

import (
	"fmt"
	"html/template"
	"strconv"
	"strings"
	"time"

	"github.com/mscno/esec-vault/internal/chain"
)

// Presentation helpers for the web pages.

// relTime describes t relative to now, such as "3 hours ago" or "in 5 days".
func relTime(now, t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	d := now.Sub(t)
	future := d < 0
	if future {
		d = -d
	}
	var s string
	switch {
	case d < time.Minute:
		if future {
			return "in under a minute"
		}
		return "just now"
	case d < time.Hour:
		s = plural(int(d/time.Minute), "minute")
	case d < 48*time.Hour:
		s = plural(int(d/time.Hour), "hour")
	case d < 60*24*time.Hour:
		s = plural(int(d/(24*time.Hour)), "day")
	case d < 730*24*time.Hour:
		s = plural(int(d/(30*24*time.Hour)), "month")
	default:
		s = plural(int(d/(365*24*time.Hour)), "year")
	}
	if future {
		return "in " + s
	}
	return s + " ago"
}

// durationText describes a duration in the largest fitting unit, such as
// "30 days".
func durationText(d time.Duration) string {
	if d < time.Minute {
		return "under a minute"
	}
	now := time.Unix(0, 0)
	return strings.TrimSuffix(relTime(now, now.Add(-d)), " ago")
}

func plural(n int, unit string) string {
	if n == 1 {
		return "1 " + unit
	}
	return strconv.Itoa(n) + " " + unit + "s"
}

// whenHTML renders a time as relative text with the exact time in a
// tooltip; the page script shows the tooltip in the viewer's time zone.
func whenHTML(now, t time.Time) template.HTML {
	if t.IsZero() {
		return `<span class="muted">—</span>`
	}
	return template.HTML(fmt.Sprintf(`<time datetime="%s" title="%s">%s</time>`, //nolint:gosec // every part is generated, not user input
		t.UTC().Format(time.RFC3339), t.UTC().Format("2006-01-02 15:04 UTC"), relTime(now, t)))
}

// byteSize formats a size in bytes.
func byteSize(n int64) string {
	switch {
	case n < 1024:
		return strconv.FormatInt(n, 10) + " B"
	case n < 1024*1024:
		return fmt.Sprintf("%.1f KiB", float64(n)/1024)
	case n < 1024*1024*1024:
		return fmt.Sprintf("%.1f MiB", float64(n)/(1024*1024))
	default:
		return fmt.Sprintf("%.1f GiB", float64(n)/(1024*1024*1024))
	}
}

// browserSummary names the browser and system of a user agent, such as
// "Firefox on macOS".
func browserSummary(ua string) string {
	browser := ""
	switch {
	case strings.Contains(ua, "Edg/"):
		browser = "Edge"
	case strings.Contains(ua, "OPR/"):
		browser = "Opera"
	case strings.Contains(ua, "Firefox/"), strings.Contains(ua, "FxiOS/"):
		browser = "Firefox"
	case strings.Contains(ua, "Chrome/"), strings.Contains(ua, "CriOS/"):
		browser = "Chrome"
	case strings.Contains(ua, "Safari/"):
		browser = "Safari"
	}
	system := ""
	switch {
	case strings.Contains(ua, "iPhone"):
		system = "iOS"
	case strings.Contains(ua, "iPad"):
		system = "iPadOS"
	case strings.Contains(ua, "Android"):
		system = "Android"
	case strings.Contains(ua, "Mac OS X"), strings.Contains(ua, "Macintosh"):
		system = "macOS"
	case strings.Contains(ua, "Windows"):
		system = "Windows"
	case strings.Contains(ua, "CrOS"):
		system = "ChromeOS"
	case strings.Contains(ua, "Linux"):
		system = "Linux"
	}
	switch {
	case browser != "" && system != "":
		return browser + " on " + system
	case browser != "":
		return browser
	case system != "":
		return "A browser on " + system
	}
	return "Unknown browser"
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return strings.ToValidUTF8(s[:n], "")
}

// auditKind is how the web pages describe an audit action.
type auditKind struct {
	label string
	// tone is "good", "bad" or "".
	tone string
}

var auditKinds = map[string]auditKind{
	"web_login":               {"Signed in on the web", ""},
	"web_sessions_ended":      {"Browsers signed out", ""},
	"login":                   {"Device signed in", ""},
	"logout":                  {"Device signed out", ""},
	"device_registered":       {"Device sign-in started", ""},
	"device_code_confirmed":   {"Sign-in code confirmed", ""},
	"device_code_denied":      {"Sign-in code denied", "bad"},
	"device_added":            {"Device approved", "good"},
	"device_suspended":        {"Device suspended", "bad"},
	"sessions_ended":          {"Device sessions ended", ""},
	"agent_slot_disabled":     {"SSH-agent slot disabled", ""},
	"vault_put":               {"Vault pushed", ""},
	"commit":                  {"Account change saved", ""},
	"chain_init":              {"Account created", "good"},
	"chain_device_add":        {"Device added to the account", ""},
	"chain_device_revoke":     {"Device revoked", "bad"},
	"chain_device_rename":     {"Device renamed", ""},
	"chain_ukey_rotate":       {"User key rotated", ""},
	"chain_agent_slot_add":    {"SSH-agent slot added", ""},
	"chain_agent_slot_remove": {"SSH-agent slot removed", ""},
	"login_denied":            {"Sign-in refused: not allowed", "bad"},
}

// auditCategory groups actions for the activity filter.
type auditCategory struct {
	Key     string
	Label   string
	actions []string
}

var auditCategories = []auditCategory{
	{"logins", "Sign-ins", []string{"web_login", "web_sessions_ended", "login", "logout", "device_registered", "device_code_confirmed", "device_code_denied", "sessions_ended"}},
	{"devices", "Devices", []string{"device_added", "device_suspended", "chain_device_add", "chain_device_revoke", "chain_device_rename"}},
	{"vault", "Vault and keys", []string{"vault_put", "commit", "chain_init", "chain_ukey_rotate"}},
	{"slots", "SSH-agent slots", []string{"agent_slot_disabled", "chain_agent_slot_add", "chain_agent_slot_remove"}},
}

// securityActions are the entries the admin page shows by default: refusals,
// suspensions, revocations, new accounts and new devices.
var securityActions = []string{
	"login_denied", "device_code_denied", "device_registered", "device_added", "device_suspended",
	"sessions_ended", "web_sessions_ended", "agent_slot_disabled", "chain_init", "chain_device_revoke", "chain_ukey_rotate",
}

func categoryActions(key string) []string {
	for _, c := range auditCategories {
		if c.Key == key {
			return c.actions
		}
	}
	return nil
}

// auditView is an audit entry as the pages show it.
type auditView struct {
	auditRow

	Label string
	Tone  string
	Text  string
	// DeviceName names the device that acted.
	DeviceName string
	// Subject is the device the entry is about, and SubjectName its name.
	Subject     string
	SubjectName string
	// Login is the account's GitHub login (admin pages).
	Login string
}

func auditViews(rows []auditRow, names, logins map[string]string) []auditView {
	out := make([]auditView, 0, len(rows))
	for _, e := range rows {
		v := auditView{auditRow: e, Label: e.Action, Text: e.Detail, DeviceName: names[e.DeviceID], Login: logins[e.UserID]}
		if k, ok := auditKinds[e.Action]; ok {
			v.Label, v.Tone = k.label, k.tone
		}
		switch e.Action {
		case "device_suspended", "sessions_ended":
			v.Subject, v.Text = e.Detail, ""
		case "device_added":
			id, method, _ := strings.Cut(e.Detail, " via ")
			v.Subject, v.Text = id, "via "+methodLabel(method)
		case "web_login":
			// The detail is the account's own login.
			v.Text = ""
		case "vault_put":
			v.Text = "version " + e.Detail
		case "web_sessions_ended":
			v.Text = plural(atoi(e.Detail), "browser")
		case "commit":
			v.Text = commitText(e.Detail)
		case "login_denied":
			id, login, _ := strings.Cut(e.Detail, " ")
			v.Text = login + " (GitHub " + strings.TrimPrefix(id, "gh:") + ")"
		default:
			if strings.HasPrefix(e.Action, "chain_") {
				v.Text = "chain link " + e.Detail
			}
		}
		if v.Subject != "" {
			v.SubjectName = names[v.Subject]
		}
		out = append(out, v)
	}
	return out
}

func atoi(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}

// methodLabel describes how a device was approved.
func methodLabel(m string) string {
	switch m {
	case chain.MethodFirst:
		return "account creation"
	case chain.MethodApproval:
		return "approval from another device"
	case chain.MethodRecovery:
		return "the recovery phrase"
	case chain.MethodSSHAgent:
		return "an SSH-agent slot"
	}
	return m
}

// commitText describes a commit audit entry ("links=1 boxes=2 ...").
func commitText(detail string) string {
	var parts []string
	for f := range strings.FieldsSeq(detail) {
		k, v, _ := strings.Cut(f, "=")
		n := atoi(v)
		switch {
		case k == "links" && n > 0:
			parts = append(parts, plural(n, "chain link"))
		case k == "boxes" && n > 0:
			parts = append(parts, plural(n, "device key"))
		case k == "slots" && n > 0:
			parts = append(parts, plural(n, "SSH-agent slot"))
		case k == "identity" && v == "true":
			parts = append(parts, "identity")
		case k == "vault" && v == "true":
			parts = append(parts, "vault")
		}
	}
	return strings.Join(parts, ", ")
}

// notice is an item on the overview's "needs attention" list.
type notice struct {
	// Level is "warn" or "info".
	Level   string
	Text    string
	Command string
	Link    string
	LinkTo  string
}
