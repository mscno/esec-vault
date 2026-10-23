package cli

// JSON output of the list and show commands, for scripts and agents. It
// carries the same facts as the text, never a key: only names, public keys
// and fingerprints.

import (
	"sort"
	"strings"
	"time"

	"github.com/mscno/esec-vault/internal/account"
	"github.com/mscno/esec-vault/internal/chain"
	"github.com/mscno/esec-vault/internal/machine"
	"github.com/mscno/esec-vault/internal/team"
	"github.com/mscno/esec-vault/internal/wire"
)

// nonNil makes an empty list print as [] rather than null.
func nonNil[T any](list []T) []T {
	if list == nil {
		return []T{}
	}
	return list
}

type jsonExposure struct {
	Name   string `json:"name"`
	Reason string `json:"reason"`
}

type jsonRotation struct {
	Env     string         `json:"env"`
	Holders []jsonExposure `json:"may_hold_key"`
	Command string         `json:"command"`
}

type jsonKey = map[string]string

type jsonEnv struct {
	Name      string `json:"name"`
	PublicKey string `json:"public_key"`
}

type jsonMember struct {
	Login string   `json:"login"`
	User  string   `json:"user"`
	Admin bool     `json:"admin"`
	Envs  []string `json:"envs"`
	// Keys says, by environment, whether its key reached them.
	Keys jsonKey `json:"keys"`
}

type jsonTeamMachine struct {
	ID   string   `json:"id"`
	Name string   `json:"name"`
	Envs []string `json:"envs"`
	From string   `json:"from"`
	Keys jsonKey  `json:"keys"`
}

type jsonTeamGroup struct {
	Group string   `json:"group"`
	Envs  []string `json:"envs"`
	Keys  jsonKey  `json:"keys"`
}

func exposures(list []team.Exposure) []jsonExposure {
	out := make([]jsonExposure, 0, len(list))
	for _, x := range list {
		out = append(out, jsonExposure{x.Name, x.Reason})
	}
	return out
}

func teamJSON(project, server string, v *account.TeamView, keys map[string]map[string]string) any {
	st := v.State
	out := struct {
		Project  string            `json:"project"`
		URL      string            `json:"url"`
		Seq      uint64            `json:"seq"`
		Envs     []jsonEnv         `json:"envs"`
		Members  []jsonMember      `json:"members"`
		Machines []jsonTeamMachine `json:"machines"`
		Groups   []jsonTeamGroup   `json:"groups"`
		Rotate   []jsonRotation    `json:"rotate"`
	}{Project: project, URL: server + "/teams/" + project, Seq: st.Seq, Envs: []jsonEnv{}, Members: []jsonMember{}, Machines: []jsonTeamMachine{}, Groups: []jsonTeamGroup{}, Rotate: []jsonRotation{}}
	for _, n := range st.EnvNames() {
		out.Envs = append(out.Envs, jsonEnv{n, st.Envs[n].PublicKey})
	}
	for _, m := range st.ActiveMembers() {
		out.Members = append(out.Members, jsonMember{Login: m.Login, User: m.User, Admin: m.Admin, Envs: nonNil(m.Envs), Keys: nonNilMap(keys[m.User])})
	}
	for _, m := range st.ActiveMachines() {
		from := "anywhere with its key"
		if m.OIDC != nil {
			from = m.OIDC.Describe()
		}
		out.Machines = append(out.Machines, jsonTeamMachine{ID: m.ID, Name: m.Name, Envs: nonNil(m.Envs), From: from, Keys: nonNilMap(keys[m.ID])})
	}
	for _, g := range st.ActiveGroups() {
		out.Groups = append(out.Groups, jsonTeamGroup{Group: g.Group, Envs: nonNil(g.Envs), Keys: nonNilMap(keys[team.GroupHolder(g.Group)])})
	}
	for _, e := range st.Rotations() {
		out.Rotate = append(out.Rotate, jsonRotation{e.Name, exposures(e.Exposed), "esec vault env rotate " + e.Name})
	}
	for _, n := range team.SortEnvs(mapKeys(v.GroupExposed)) {
		out.Rotate = append(out.Rotate, jsonRotation{n, exposures(v.GroupExposed[n]), "esec vault env rotate " + n})
	}
	return out
}

func nonNilMap(m map[string]string) map[string]string {
	if m == nil {
		return map[string]string{}
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		if v == wire.KeyMissing {
			v = "not sent"
		}
		out[k] = v
	}
	return out
}

type jsonCred struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	LastUsed     time.Time `json:"last_used,omitzero"`
	LastIP       string    `json:"last_ip,omitempty"`
	Uses         int       `json:"uses"`
	Suspended    bool      `json:"suspended"`
	KeySent      *bool     `json:"key_sent,omitempty"`
	Expires      time.Time `json:"expires,omitzero"`
	Only         string    `json:"only,omitempty"`
	EnrolledWith string    `json:"enrolled_with,omitempty"`
}

type jsonGroupProject struct {
	Project string   `json:"project"`
	Envs    []string `json:"envs"`
	// Visible is false when you are not a member of the project.
	Visible bool `json:"visible"`
	// Trusted: the group takes the project's keys.
	Trusted bool `json:"trusted"`
	// Delivered: the keys are sealed to the group's current key.
	Delivered bool     `json:"delivered"`
	Rotate    []string `json:"rotate"`
}

func groupJSON(id, server string, v *account.GroupView, used map[string]wire.CredStatus) any {
	gs := v.State
	out := struct {
		Group       string             `json:"group"`
		URL         string             `json:"url"`
		KeyVersion  uint64             `json:"key_version"`
		Seq         uint64             `json:"seq"`
		Fingerprint string             `json:"fingerprint"`
		Admins      []string           `json:"admins"`
		Machines    []jsonCred         `json:"machines"`
		Tokens      []jsonCred         `json:"tokens"`
		Projects    []jsonGroupProject `json:"projects"`
		KeyExposed  bool               `json:"needs_new_key"`
		Waiting     int                `json:"waiting_for_approval"`
	}{Group: id, URL: server + "/groups/" + id, KeyVersion: gs.Key.Version, Seq: gs.Seq, Fingerprint: team.GroupWords(id, gs.Root()),
		Admins: []string{}, Machines: []jsonCred{}, Tokens: []jsonCred{}, Projects: []jsonGroupProject{}, KeyExposed: len(gs.KeyExposed) > 0}
	for _, ad := range gs.ActiveAdmins() {
		out.Admins = append(out.Admins, ad.Login)
	}
	for _, kind := range []string{team.KindMachine, team.KindToken} {
		for _, cr := range gs.ActiveCreds(kind) {
			u := used[cr.ID]
			j := jsonCred{ID: cr.ID, Name: cr.Name, LastUsed: u.LastUsed, LastIP: u.LastIP, Uses: u.Uses, Suspended: u.Suspended, Expires: cr.Expires}
			if v.Status != nil {
				sent := u.HasKey
				j.KeySent = &sent
			}
			if cr.OIDC != nil {
				j.Only = cr.OIDC.Describe()
			}
			if t := gs.Creds[cr.AddedBy]; strings.HasPrefix(cr.AddedBy, "t_") && t != nil {
				j.EnrolledWith = t.Name
			}
			if kind == team.KindMachine {
				out.Machines = append(out.Machines, j)
			} else {
				out.Tokens = append(out.Tokens, j)
			}
		}
	}
	for _, p := range v.Projects {
		out.Projects = append(out.Projects, jsonGroupProject{p.Project, nonNil(p.Envs), p.Visible, p.Trusted, p.Delivered, nonNil(p.Rotate)})
	}
	if v.Status != nil {
		out.Waiting = len(v.Status.Joins) + len(v.Status.Changes)
	}
	return out
}

func machinesJSON(ms []*team.MachineState, used map[string]time.Time) any {
	type jsonMachine struct {
		ID       string    `json:"id"`
		Name     string    `json:"name"`
		Envs     []string  `json:"envs"`
		LastUsed time.Time `json:"last_used,omitzero"`
		From     string    `json:"from"`
	}
	out := make([]jsonMachine, 0, len(ms))
	for _, m := range ms {
		from := "anywhere with its key"
		if m.OIDC != nil {
			from = m.OIDC.Describe()
		}
		out = append(out, jsonMachine{m.ID, m.Name, nonNil(m.Envs), used[m.ID], from})
	}
	return out
}

func whoamiJSON(cred *machine.Credential, keys *machine.Keys) any {
	kind := "project machine"
	switch {
	case cred.Workload != nil:
		kind = "workload"
	case keys.Group != "":
		kind = "machine"
		if cred.Group.Kind() == team.KindToken {
			kind = "token"
		}
	}
	reads := map[string][]string{}
	for _, p := range keys.ProjectIDs() {
		reads[p] = nonNil(keys.Names(p))
	}
	return struct {
		Name     string              `json:"name"`
		ID       string              `json:"id"`
		Kind     string              `json:"kind"`
		Project  string              `json:"project,omitempty"`
		Group    string              `json:"group,omitempty"`
		Server   string              `json:"server"`
		KeyFrom  string              `json:"key_from"`
		Reads    map[string][]string `json:"reads"`
		Problems []string            `json:"problems"`
	}{keys.Name, keys.Machine, kind, keys.Project, keys.Group, cred.Server(), cred.From, reads, nonNil(keys.Problems)}
}

func devicesJSON(a *account.Account, devices []account.DeviceView) any {
	type jsonDevice struct {
		ID           string    `json:"id"`
		Name         string    `json:"name"`
		Status       string    `json:"status"`
		ServerStatus string    `json:"server_status,omitempty"`
		Method       string    `json:"method,omitempty"`
		Fingerprint  string    `json:"fingerprint"`
		LastSeen     time.Time `json:"last_seen,omitzero"`
		LastIP       string    `json:"last_ip,omitempty"`
		ThisDevice   bool      `json:"this_device"`
	}
	out := struct {
		Account     string       `json:"account"`
		Fingerprint string       `json:"fingerprint"`
		Devices     []jsonDevice `json:"devices"`
	}{a.State.Login, a.State.Chain.AccountWords, []jsonDevice{}}
	for _, d := range devices {
		out.Devices = append(out.Devices, jsonDevice{d.ID, d.Name, d.Status, d.ServerStatus, d.Method, d.Words, d.LastSeen, d.LastIP, d.Self})
	}
	return out
}

func delegatesJSON(ds []*chain.DelegateState) any {
	type jsonDelegate struct {
		ID          string `json:"id"`
		Kind        string `json:"kind"`
		Name        string `json:"name"`
		Scope       string `json:"scope"`
		Fingerprint string `json:"fingerprint,omitempty"`
	}
	out := make([]jsonDelegate, 0, len(ds))
	for _, d := range ds {
		j := jsonDelegate{ID: d.ID, Kind: d.Kind, Name: d.Name, Scope: d.Scope}
		if d.Kind == chain.DelegatePasskey {
			j.Fingerprint = chain.DelegateWords(d.Delegate)
		}
		out = append(out, j)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func changesJSON(list []account.ChangeView) any {
	type jsonChange struct {
		ID      int64     `json:"id"`
		Scope   string    `json:"scope"`
		Target  string    `json:"target"`
		Kind    string    `json:"kind"`
		AskedBy string    `json:"asked_by"`
		Created time.Time `json:"created"`
		// Removes: only takes access away, so --yes may sign it.
		Removes     bool     `json:"removes"`
		Description []string `json:"description"`
	}
	out := make([]jsonChange, 0, len(list))
	for _, ch := range list {
		out = append(out, jsonChange{ch.ID, ch.Scope, ch.Target, ch.Kind, ch.AskedBy(), ch.Created, ch.Removes(), nonNil(ch.DescribeLines())})
	}
	return out
}
