package server

import (
	"cmp"
	"context"
	"database/sql"
	"errors"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/mscno/esec-vault/internal/chain"
	"github.com/mscno/esec-vault/internal/devicekey"
	"github.com/mscno/esec-vault/internal/wire"
)

const (
	// staleDevice is how long an active device can go unseen before the
	// overview suggests revoking it.
	staleDevice = 90 * 24 * time.Hour
	// slotWarning is how early the overview warns that a slot expires.
	slotWarning = 14 * 24 * time.Hour
	// activityPage is the number of entries per activity page.
	activityPage = 50
)

// page returns the template data every signed-in page needs.
func (s *Server) page(ws *webSession, nav string) map[string]any {
	return map[string]any{
		"User": ws.user, "CSRF": ws.csrf, "Nav": nav, "Now": s.now(),
		"IsAdmin": s.cfg.Admin(ws.user.GitHubID), "BaseURL": s.cfg.BaseURL,
	}
}

type deviceView struct {
	*deviceRow

	Sessions int
	Words    string
	Stale    bool
}

// accountDevices lists an account's devices as the pages show them: without
// registrations that were never confirmed or waiting devices that expired.
func (s *Server) accountDevices(ctx context.Context, userID string, now time.Time) ([]deviceView, error) {
	rows, err := s.db.devicesOf(ctx, s.db.sql, userID)
	if err != nil {
		return nil, err
	}
	sessions, err := s.db.liveSessionCounts(ctx, userID, now, s.cfg.Sessions.Idle.Duration)
	if err != nil {
		return nil, err
	}
	var out []deviceView
	for _, d := range rows {
		if d.Status == wire.DeviceRegistering || (d.Status == wire.DevicePending && !now.Before(d.PendingExpires)) {
			continue
		}
		out = append(out, deviceView{
			deviceRow: d,
			Sessions:  sessions[d.ID],
			Words:     deviceWords(d),
			Stale:     d.Status == wire.DeviceActive && !d.LastSeen.IsZero() && now.Sub(d.LastSeen) > staleDevice,
		})
	}
	return out, nil
}

// deviceWords returns a device's fingerprint words. The words of a device
// that was never approved are never shown on the web: approving it needs them
// typed from the device's own screen.
func deviceWords(d *deviceRow) string {
	if d.Status != wire.DeviceActive && d.Method == "" {
		// Waiting, or suspended while waiting: never approved.
		return ""
	}
	return devicekey.Words(d.EncPub, d.SignPub)
}

func (s *Server) webAccount(w http.ResponseWriter, r *http.Request) {
	ws := s.requireWeb(w, r)
	if ws == nil {
		return
	}
	ctx := r.Context()
	now := s.now()
	devices, err := s.accountDevices(ctx, ws.user.ID, now)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	slots, err := s.slots(ctx, ws.user.ID, now, true)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	browsers, err := s.db.browsers(ctx, ws.user.ID, now)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	idx, vault, err := s.latestIndex(ctx, ws.user.ID)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	names, err := s.db.deviceNames(ctx, ws.user.ID)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	recent, err := s.db.auditPage(ctx, auditFilter{UserID: ws.user.ID, Limit: 8})
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	links, err := s.db.chainLinks(ctx, s.db.sql, ws.user.ID, 0)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	accountWords := ""
	if st, err := chain.Verify(ws.user.ID, links); err == nil {
		accountWords = st.AccountWords()
	}

	counts := map[string]int{}
	for _, d := range devices {
		counts[d.Status]++
	}
	enabledSlots := 0
	for _, sl := range slots {
		if !sl.Disabled && now.Before(sl.Expires) {
			enabledSlots++
		}
	}
	var browserViews []map[string]any
	for _, b := range browsers {
		browserViews = append(browserViews, map[string]any{
			"ID": b.IDHash, "Summary": browserSummary(b.UserAgent), "IP": b.IP,
			"Created": b.Created, "Expires": b.Expires, "Current": b.IDHash == ws.idHash,
		})
	}
	projects, envs := 0, 0
	if idx != nil {
		projects = len(idx.Projects)
		for _, p := range idx.Projects {
			envs += len(p.Environments)
		}
	}

	data := s.page(ws, "account")
	data["Devices"] = devices
	data["Counts"] = counts
	data["Slots"] = slots
	data["EnabledSlots"] = enabledSlots
	data["Browsers"] = browserViews
	data["Recent"] = auditViews(recent, names, nil)
	data["AccountWords"] = accountWords
	data["Vault"] = vault
	data["Index"] = idx
	data["Projects"] = projects
	data["Environments"] = envs
	if vault != nil {
		data["PushedBy"] = names[vault.PushedBy]
	}
	alertNotice, err := s.alertData(ctx, data, ws.user.ID, now)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	teamNotices, err := s.sharedNotices(ctx, ws.user.ID)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	data["Notices"] = append(append(s.notices(devices, slots, len(links) > 0, enabledSlots, now), teamNotices...), alertNotice...)
	s.render(w, http.StatusOK, "account.html", data)
}

// alertData adds the overview's alert section, and returns a notice that
// suggests email alerts to an account without them.
func (s *Server) alertData(ctx context.Context, data map[string]any, userID string, now time.Time) ([]notice, error) {
	email, pending, err := s.db.alertAddresses(ctx, userID, now)
	if err != nil {
		return nil, err
	}
	data["EmailAlerts"] = s.cfg.Alerts.Email()
	data["OperatorAlerts"] = len(s.cfg.Alerts.EmailTo) > 0 || s.cfg.Alerts.Webhook()
	data["AlertEmail"] = email
	data["AlertPending"] = pending
	if !s.cfg.Alerts.Email() || email != "" || pending != "" {
		return nil, nil
	}
	return []notice{{Level: "info", Text: "Get an email when a device signs in to your account, is approved, suspended or revoked, or when someone signs in here from a new browser.", Link: "#alerts", LinkTo: "Set up email alerts"}}, nil
}

// notices lists what needs the account owner's attention, most urgent first.
func (s *Server) notices(devices []deviceView, slots []wire.AgentSlot, created bool, enabledSlots int, now time.Time) []notice {
	var out, later []notice
	active := 0
	for _, d := range devices {
		switch d.Status {
		case wire.DevicePending:
			out = append(out, notice{
				Level:   "warn",
				Text:    d.Name + " (" + d.Platform + ") is waiting for approval. Approve it from a trusted device, typing the words its own screen shows. If you did not start this sign-in, suspend it.",
				Command: "esec vault devices approve " + d.ID,
				Link:    "/devices/" + d.ID, LinkTo: "Review device",
			})
		case wire.DeviceSuspended:
			if d.Method == "" {
				// Suspended before it was approved: it never had access and
				// is not in the chain, so there is nothing to revoke.
				continue
			}
			later = append(later, notice{
				Level:   "warn",
				Text:    d.Name + " is suspended but not revoked. Revoke it from a trusted device: that rotates your user key, so it can never read new secrets.",
				Command: "esec vault devices revoke " + d.ID,
			})
		case wire.DeviceActive:
			active++
			if d.Stale {
				later = append(later, notice{
					Level:   "info",
					Text:    d.Name + " has not been seen for " + durationText(now.Sub(d.LastSeen)) + ". If you no longer use it, revoke it.",
					Command: "esec vault devices revoke " + d.ID,
				})
			}
		}
	}
	// Waiting devices come first: they may be a sign-in someone else started.
	out = append(out, later...)
	for _, sl := range slots {
		if !sl.Disabled && now.Before(sl.Expires) && sl.Expires.Sub(now) < slotWarning {
			out = append(out, notice{Level: "info", Text: "The SSH-agent unlock slot for " + sl.SSHKeyFP + " expires " + relTime(now, sl.Expires) + ". Add a new slot if you still want it.", Command: "esec vault agent-unlock enable"})
		}
	}
	switch {
	case !created:
		out = append(out, notice{Level: "info", Text: "Your account has not been created yet. Run this on the machine that holds your esec identity and keyrings; it asks for the account creation token the server operator gave you.", Command: "esec vault login " + s.cfg.BaseURL})
	case active == 1 && enabledSlots == 0:
		out = append(out, notice{Level: "info", Text: "Only one device can open your vault. If you lose it, only your recovery phrase brings your keys back. Connect a second machine, or let an SSH-agent key unlock new devices.", Command: "esec vault agent-unlock enable"})
	}
	if s.cfg.newDevicesClosed() {
		out = append(out, notice{Level: "info", Text: "The server is closed to new devices for now. Devices and browsers that signed in before keep working."})
	}
	return out
}

func (s *Server) webDevicePage(w http.ResponseWriter, r *http.Request) {
	ws := s.requireWeb(w, r)
	if ws == nil {
		return
	}
	ctx := r.Context()
	now := s.now()
	d, err := s.db.device(ctx, s.db.sql, r.PathValue("id"))
	if errors.Is(err, sql.ErrNoRows) || (err == nil && (d.UserID != ws.user.ID || d.Status == wire.DeviceRegistering)) {
		s.webError(w, http.StatusNotFound, "There is no such device on your account.")
		return
	}
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	sessions, err := s.db.liveSessions(ctx, d.ID, now, s.cfg.Sessions.Idle.Duration)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	names, err := s.db.deviceNames(ctx, ws.user.ID)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	activity, err := s.db.auditPage(ctx, auditFilter{UserID: ws.user.ID, Device: d.ID, Limit: activityPage})
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	data := s.page(ws, "account")
	data["Device"] = d
	data["Words"] = deviceWords(d)
	data["MethodLabel"] = methodLabel(d.Method)
	data["Expired"] = d.Status == wire.DevicePending && !now.Before(d.PendingExpires)
	data["CLISessions"] = sessions
	data["Activity"] = auditViews(activity, names, nil)
	s.render(w, http.StatusOK, "devicedetail.html", data)
}

func (s *Server) webActivity(w http.ResponseWriter, r *http.Request) {
	ws := s.requireWeb(w, r)
	if ws == nil {
		return
	}
	ctx := r.Context()
	q := r.URL.Query()
	category := q.Get("category")
	actions := categoryActions(category)
	if actions == nil {
		category = ""
	}
	before, _ := strconv.ParseInt(q.Get("before"), 10, 64)
	names, err := s.db.deviceNames(ctx, ws.user.ID)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	device := q.Get("device")
	if _, ok := names[device]; !ok {
		device = ""
	}
	rows, err := s.db.auditPage(ctx, auditFilter{UserID: ws.user.ID, Actions: actions, Device: device, Before: before, Limit: activityPage + 1})
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	data := s.page(ws, "activity")
	if len(rows) > activityPage {
		rows = rows[:activityPage]
		data["Older"] = activityLink(category, device, rows[len(rows)-1].ID)
	}
	if before > 0 {
		data["Newest"] = activityLink(category, device, 0)
	}
	data["Entries"] = auditViews(rows, names, nil)
	data["Categories"] = auditCategories
	data["Category"] = category
	data["DeviceID"] = device
	data["DeviceName"] = names[device]
	data["Paged"] = before > 0
	s.render(w, http.StatusOK, "activity.html", data)
}

func activityLink(category, device string, before int64) string {
	var parts []string
	if category != "" {
		parts = append(parts, "category="+category)
	}
	if device != "" {
		parts = append(parts, "device="+device)
	}
	if before > 0 {
		parts = append(parts, "before="+strconv.FormatInt(before, 10))
	}
	if len(parts) == 0 {
		return "/activity"
	}
	return "/activity?" + strings.Join(parts, "&")
}

func (s *Server) webVault(w http.ResponseWriter, r *http.Request) {
	ws := s.requireWeb(w, r)
	if ws == nil {
		return
	}
	ctx := r.Context()
	versions, err := s.db.vaultVersions(ctx, ws.user.ID)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	names, err := s.db.deviceNames(ctx, ws.user.ID)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	var total int64
	for _, v := range versions {
		total += v.Size
	}
	data := s.page(ws, "vault")
	data["Versions"] = versions
	data["Names"] = names
	data["Total"] = total
	data["Keep"] = s.cfg.VaultHistory
	s.render(w, http.StatusOK, "vault.html", data)
}

func (s *Server) webProjects(w http.ResponseWriter, r *http.Request) {
	ws := s.requireWeb(w, r)
	if ws == nil {
		return
	}
	ctx := r.Context()
	idx, v, err := s.latestIndex(ctx, ws.user.ID)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	query := strings.TrimSpace(r.URL.Query().Get("q"))
	data := s.page(ws, "projects")
	data["Vault"] = v
	data["Query"] = query
	if idx != nil {
		total := len(idx.Projects)
		idx = filterIndex(idx, query)
		data["Total"] = total
	}
	data["Index"] = idx
	if v != nil {
		if d, err := s.db.device(ctx, s.db.sql, v.PushedBy); err == nil {
			data["PushedBy"] = d.Name
		}
	}
	teams, err := s.teamSummaries(ctx, ws.user.ID)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	data["Teams"] = teams
	s.render(w, http.StatusOK, "projects.html", data)
}

// filterIndex keeps the projects whose id matches query, and in the others
// the environments whose name or public key matches. Matching ignores case.
func filterIndex(idx *wire.VaultIndex, query string) *wire.VaultIndex {
	if query == "" {
		return idx
	}
	q := strings.ToLower(query)
	out := &wire.VaultIndex{Generation: idx.Generation}
	for _, p := range idx.Projects {
		if strings.Contains(strings.ToLower(p.ID), q) {
			out.Projects = append(out.Projects, p)
			continue
		}
		var envs []wire.IndexEnv
		for _, e := range p.Environments {
			if strings.Contains(strings.ToLower(e.Name), q) || strings.Contains(strings.ToLower(e.PublicKey), q) {
				envs = append(envs, e)
			}
		}
		if len(envs) > 0 {
			out.Projects = append(out.Projects, wire.IndexProject{ID: p.ID, Environments: envs, OtherKeys: p.OtherKeys})
		}
	}
	return out
}

func (s *Server) webEndBrowser(w http.ResponseWriter, r *http.Request) {
	ws := s.requireWeb(w, r)
	if ws == nil {
		return
	}
	if !s.checkForm(r, ws) {
		s.webError(w, http.StatusForbidden, "The form expired. Reload the page and try again.")
		return
	}
	ctx := r.Context()
	now := s.now()
	target := r.PathValue("id")
	others := target == "others"
	err := s.db.tx(ctx, func(tx *sql.Tx) error {
		var res sql.Result
		var err error
		if others {
			res, err = tx.ExecContext(ctx, `DELETE FROM web_sessions WHERE user_id = ? AND id_hash != ?`, ws.user.ID, ws.idHash)
		} else {
			res, err = tx.ExecContext(ctx, `DELETE FROM web_sessions WHERE user_id = ? AND id_hash = ?`, ws.user.ID, target)
		}
		if err != nil {
			return err
		}
		n, _ := res.RowsAffected()
		if n == 0 {
			return nil
		}
		return s.db.audit(ctx, tx, ws.user.ID, "", s.clientIP(r), "web_sessions_ended", strconv.FormatInt(n, 10), now)
	})
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if target == ws.idHash {
		s.clearCookie(w, "esec_session")
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/account#browsers", http.StatusSeeOther)
}

// ---- admin ----

// requireAdmin returns the session of a signed-in admin. Everyone else gets
// a 404, so the pages do not reveal who administers the server.
func (s *Server) requireAdmin(w http.ResponseWriter, r *http.Request) *webSession {
	ws := s.requireWeb(w, r)
	if ws == nil {
		return nil
	}
	if !s.cfg.Admin(ws.user.GitHubID) {
		s.webError(w, http.StatusNotFound, "There is no such page.")
		return nil
	}
	return ws
}

func (s *Server) webAdmin(w http.ResponseWriter, r *http.Request) {
	ws := s.requireAdmin(w, r)
	if ws == nil {
		return
	}
	ctx := r.Context()
	now := s.now()
	stats, err := s.db.serverStats(ctx, now, s.cfg.Sessions.Idle.Duration)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	accounts, err := s.adminAccounts(ctx, now)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	q := r.URL.Query()
	all := q.Get("events") == "all"
	before, _ := strconv.ParseInt(q.Get("before"), 10, 64)
	filter := auditFilter{AllUsers: true, Before: before, Limit: activityPage + 1}
	if !all {
		filter.Actions = securityActions
	}
	rows, err := s.db.auditPage(ctx, filter)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	names, err := s.db.deviceNames(ctx, "")
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	logins := map[string]string{}
	for _, a := range accounts {
		if a.Known {
			logins[a.ID] = a.Login
		}
	}
	data := s.page(ws, "admin")
	base := "/admin?"
	if all {
		base = "/admin?events=all&"
	}
	if len(rows) > activityPage {
		rows = rows[:activityPage]
		data["Older"] = base + "before=" + strconv.FormatInt(rows[len(rows)-1].ID, 10) + "#events"
	}
	data["Paged"] = before > 0
	data["AllEvents"] = all
	data["Events"] = auditViews(rows, names, logins)
	data["Stats"] = stats
	data["Accounts"] = accounts
	data["Version"] = s.version
	data["Started"] = s.started
	// Only what the page shows: the configuration also holds secrets.
	data["Config"] = adminConfig{
		BaseURL: s.cfg.BaseURL, ClientIPHeader: s.cfg.ClientIPHeader, VaultHistory: s.cfg.VaultHistory,
		Allowed: len(s.cfg.Access.AllowedGitHubIDs), Idle: s.cfg.Sessions.Idle.Duration, Absolute: s.cfg.Sessions.Absolute.Duration,
		EmailAlerts: s.cfg.Alerts.Email(), EmailFrom: s.cfg.Alerts.EmailFrom, OperatorEmails: len(s.cfg.Alerts.EmailTo),
		Webhook: s.cfg.Alerts.Webhook(), WebhookSigned: s.cfg.Alerts.WebhookSecret != "",
	}
	data["NewDevicesClosed"] = s.cfg.newDevicesClosed()
	alerts, err := s.db.alertStats(ctx, now.Add(-7*24*time.Hour))
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	data["Alerts"] = alerts
	teams, err := s.teamSummaries(ctx, "")
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	data["Teams"] = teams
	groups, err := s.groupSummaries(ctx, "")
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	data["Groups"] = groups
	s.render(w, http.StatusOK, "admin.html", data)
}

// adminConfig is the part of the configuration the admin page shows.
type adminConfig struct {
	BaseURL        string
	ClientIPHeader string
	VaultHistory   int
	Allowed        int
	Idle, Absolute time.Duration
	// Alerts: whether each channel is on, never the token or webhook URL.
	EmailAlerts    bool
	EmailFrom      string
	OperatorEmails int
	Webhook        bool
	WebhookSigned  bool
}

// adminAccounts lists every allowed id and every account: allowed ones
// first, then by login, with ids that never signed in last.
func (s *Server) adminAccounts(ctx context.Context, now time.Time) ([]*accountSummary, error) {
	byID, err := s.db.accountSummaries(ctx, now)
	if err != nil {
		return nil, err
	}
	for _, gh := range s.cfg.Access.AllowedGitHubIDs {
		id := userID(gh)
		if _, ok := byID[id]; !ok {
			byID[id] = &accountSummary{ID: id, GitHubID: gh, Devices: map[string]int{}}
		}
	}
	var out []*accountSummary
	for _, a := range byID {
		if a.GitHubID == 0 {
			// Rows left behind by an account that no longer exists.
			continue
		}
		a.Allowed, a.Admin = s.cfg.Allowed(a.GitHubID), s.cfg.Admin(a.GitHubID)
		out = append(out, a)
	}
	slices.SortFunc(out, func(a, b *accountSummary) int {
		if a.Allowed != b.Allowed {
			if a.Allowed {
				return -1
			}
			return 1
		}
		if a.Known != b.Known {
			if a.Known {
				return -1
			}
			return 1
		}
		return cmp.Or(cmp.Compare(strings.ToLower(a.Login), strings.ToLower(b.Login)), cmp.Compare(a.GitHubID, b.GitHubID))
	})
	return out, nil
}

func (s *Server) webAdminUser(w http.ResponseWriter, r *http.Request) {
	ws := s.requireAdmin(w, r)
	if ws == nil {
		return
	}
	ctx := r.Context()
	now := s.now()
	u, err := s.db.userByID(ctx, r.PathValue("id"))
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if u == nil {
		s.webError(w, http.StatusNotFound, "There is no such account.")
		return
	}
	devices, err := s.accountDevices(ctx, u.ID, now)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	accounts, err := s.db.accountSummaries(ctx, now)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	names, err := s.db.deviceNames(ctx, u.ID)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	rows, err := s.db.auditPage(ctx, auditFilter{UserID: u.ID, Limit: 100})
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	data := s.page(ws, "admin")
	data["Account"] = u
	data["Summary"] = accounts[u.ID]
	data["Allowed"] = s.cfg.Allowed(u.GitHubID)
	data["Devices"] = devices
	data["Activity"] = auditViews(rows, names, nil)
	s.render(w, http.StatusOK, "adminuser.html", data)
}
