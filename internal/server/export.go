package server

// Exports: an account's activity, and a project's or group's history (its
// signed chain and what the server recorded), as CSV or JSON, for audits
// and for the scripts that keep them.

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/mscno/esec-vault/internal/team"
	"github.com/mscno/esec-vault/internal/wire"
)

// maxExport is the most entries one export holds.
const maxExport = 10000

// exportRow is one exported entry.
type exportRow struct {
	Time time.Time `json:"time"`
	// Source is "chain" for a signed link, "server" for what the server
	// recorded.
	Source string `json:"source"`
	Actor  string `json:"actor"`
	Action string `json:"action"`
	Detail string `json:"detail"`
	IP     string `json:"ip,omitempty"`
	Device string `json:"device,omitempty"`
}

// writeExport writes rows as CSV or JSON, as a download named name.
func writeExport(w http.ResponseWriter, format, name string, rows []exportRow) {
	w.Header().Set("Cache-Control", "no-store")
	if format == "json" {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", `attachment; filename="`+name+`.json"`)
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		if err := enc.Encode(rows); err != nil {
			return // the client went away
		}
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`.csv"`)
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"time", "source", "actor", "action", "detail", "ip", "device"})
	for _, r := range rows {
		// A leading = + - @ makes spreadsheets run a cell as a formula.
		_ = cw.Write([]string{r.Time.UTC().Format(time.RFC3339), r.Source, csvSafe(r.Actor), csvSafe(r.Action), csvSafe(r.Detail), csvSafe(r.IP), csvSafe(r.Device)})
	}
	cw.Flush()
}

// csvSafe keeps a spreadsheet from reading a cell as a formula.
func csvSafe(s string) string {
	if s != "" && (s[0] == '=' || s[0] == '+' || s[0] == '-' || s[0] == '@' || s[0] == '\t' || s[0] == '\r') {
		return "'" + s
	}
	return s
}

func exportFormat(r *http.Request) string {
	if r.URL.Query().Get("format") == "json" {
		return "json"
	}
	return "csv"
}

// webActivityExport exports the account's activity, filtered like the
// activity page.
func (s *Server) webActivityExport(w http.ResponseWriter, r *http.Request) {
	ws := s.requireWeb(w, r)
	if ws == nil {
		return
	}
	ctx := r.Context()
	q := r.URL.Query()
	names, err := s.db.deviceNames(ctx, ws.user.ID)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	device := q.Get("device")
	if _, ok := names[device]; !ok {
		device = ""
	}
	query := strings.TrimSpace(q.Get("q"))
	if len(query) > 100 {
		query = query[:100]
	}
	rows, err := s.db.auditPage(ctx, auditFilter{UserID: ws.user.ID, Actions: categoryActions(q.Get("category")), Device: device, Query: query, Limit: maxExport})
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	out := make([]exportRow, 0, len(rows))
	for _, v := range auditViews(rows, names, nil) {
		out = append(out, exportRow{Time: v.Time, Source: "server", Actor: ws.user.Login, Action: v.Label, Detail: joinText(v.Text, v.SubjectName), IP: v.IP, Device: v.DeviceName})
	}
	writeExport(w, exportFormat(r), "esec-vault-activity", out)
}

func joinText(a, b string) string {
	switch {
	case a == "":
		return b
	case b == "":
		return a
	}
	return a + " " + b
}

// webTeamExport exports a project's history: its signed chain, and what the
// server recorded (key deliveries, machines' fetches, web changes). Addresses
// are left out for anyone but the project's admins.
func (s *Server) webTeamExport(w http.ResponseWriter, r *http.Request) {
	ws := s.requireWeb(w, r)
	if ws == nil {
		return
	}
	project := r.PathValue("org") + "/" + r.PathValue("repo")
	ctx := r.Context()
	st, err := s.exportableProject(ctx, ws, project)
	if err != nil {
		s.webFail(w, r, err)
		return
	}
	var out []exportRow
	seen := map[string]bool{}
	for _, l := range st.Links {
		out = append(out, exportRow{Time: l.CTime, Source: "chain", Actor: loginOf(st, l.Signer), Action: l.Type, Detail: linkText(st, l, seen)})
	}
	audit, err := s.db.projectAuditPage(ctx, project, maxExport)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	logins, err := s.db.logins(ctx)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	showIP := st.Admin(ws.user.ID) || s.cfg.Admin(ws.user.GitHubID)
	for _, e := range audit {
		row := exportRow{Time: e.Time, Source: "server", Actor: actorName(logins, st.Machines, e.Actor), Action: e.Action, Detail: e.Detail}
		if showIP {
			row.IP = e.IP
		} else if e.Action == "machine_refused" || e.Action == "keys" {
			// Claims and refusal reasons are the admins' to see.
			row.Detail = ""
		}
		out = append(out, row)
	}
	sortExport(out)
	writeExport(w, exportFormat(r), "esec-vault-"+r.PathValue("org")+"-"+r.PathValue("repo"), out)
}

// exportableProject loads a project the viewer is a member of (or that a
// server admin looks at).
func (s *Server) exportableProject(ctx context.Context, ws *webSession, project string) (*team.State, error) {
	notFound := clientErr(http.StatusNotFound, wire.ErrNotFound, "There is no such project, or you are not a member of it.")
	if team.ValidProject(project) != nil {
		return nil, notFound
	}
	st, _, err := s.db.projectState(ctx, s.db.sql, project)
	if err != nil {
		return nil, err
	}
	if st == nil {
		return nil, notFound
	}
	if _, member := st.Member(ws.user.ID); !member && !s.cfg.Admin(ws.user.GitHubID) {
		return nil, notFound
	}
	return st, nil
}

func actorName(logins map[string]string, machines map[string]*team.MachineState, id string) string {
	if l, ok := logins[id]; ok {
		return l
	}
	if m, ok := machines[id]; ok {
		return "machine " + m.Name
	}
	return id
}

// webGroupExport exports a group's history, like a project's.
func (s *Server) webGroupExport(w http.ResponseWriter, r *http.Request) {
	ws := s.requireWeb(w, r)
	if ws == nil {
		return
	}
	id := r.PathValue("org") + "/" + r.PathValue("name")
	ctx := r.Context()
	notFound := clientErr(http.StatusNotFound, wire.ErrNotFound, "There is no such group, or it is not yours to see.")
	if team.ValidGroup(id) != nil {
		s.webFail(w, r, notFound)
		return
	}
	gs, _, err := s.db.groupState(ctx, s.db.sql, id)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	readable := false
	if gs != nil {
		if readable, err = s.db.canReadGroup(ctx, ws.user.ID, id); err != nil {
			s.internalError(w, r, err)
			return
		}
	}
	if gs == nil || (!readable && !s.cfg.Admin(ws.user.GitHubID)) {
		s.webFail(w, r, notFound)
		return
	}
	var out []exportRow
	for _, l := range gs.Links {
		out = append(out, exportRow{Time: l.CTime, Source: "chain", Actor: groupActor(gs, l.Signer), Action: l.Type, Detail: groupLinkText(gs, l)})
	}
	showOps := gs.Admin(ws.user.ID) || s.cfg.Admin(ws.user.GitHubID)
	if showOps {
		audit, err := s.db.groupAuditPage(ctx, id, maxExport)
		if err != nil {
			s.internalError(w, r, err)
			return
		}
		logins, err := s.db.logins(ctx)
		if err != nil {
			s.internalError(w, r, err)
			return
		}
		for _, e := range audit {
			actor := logins[e.Actor]
			if c := gs.Creds[e.Actor]; c != nil {
				actor = c.Kind + " " + c.Name
			}
			if actor == "" {
				actor = e.Actor
			}
			out = append(out, exportRow{Time: e.Time, Source: "server", Actor: actor, Action: e.Action, Detail: e.Detail, IP: e.IP})
		}
	}
	sortExport(out)
	writeExport(w, exportFormat(r), "esec-vault-"+r.PathValue("org")+"-"+r.PathValue("name"), out)
}

// sortExport puts rows oldest first.
func sortExport(rows []exportRow) {
	slices.SortStableFunc(rows, func(a, b exportRow) int { return a.Time.Compare(b.Time) })
}
