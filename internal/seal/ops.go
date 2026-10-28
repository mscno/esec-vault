package seal

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"filippo.io/age"
	"github.com/mscno/esec/pkg/projectfile"
	coreseal "github.com/mscno/esec/pkg/seal"
)

// Signer is who seals: their id ("gh:<id>", or "key:<fingerprint>"), their
// signing key, and their recovery recipient, which every seal they make
// includes, so whoever seals can always recover.
type Signer struct {
	By       string
	Key      ed25519.PrivateKey
	Recovery string
}

// Env is one environment to seal.
type Env struct {
	Project string
	Name    string
	Root    string
	// Private is its private key (hex).
	Private string
	Guard   string
	Readers []Reader
}

// Result is a seal made: its bytes, its record, and the readers as they
// resolved ("me" becomes a GitHub id, logins are refreshed).
type Result struct {
	Data    []byte
	Record  *Record
	Readers []Reader
	Pending []SealedFor
}

// Make seals e for its readers and the signer's recovery key.
func Make(ctx context.Context, d Directory, e Env, s Signer) (*Result, error) {
	if s.Recovery == "" {
		return nil, errors.New("no recovery key to seal to: create your identity (esec vault setup)")
	}
	pub, err := coreseal.PublicHex(e.Private)
	if err != nil {
		return nil, err
	}
	guard := e.Guard
	if guard == "" {
		guard = projectfile.GuardNone
	}
	rec := &Record{Key: pub, Guard: guard, At: time.Now().UTC().Truncate(time.Second)}
	res := &Result{Record: rec}
	recovery := map[string]bool{s.Recovery: true}
	for _, r := range e.Readers {
		got, err := d.Resolve(ctx, r, Guarded(guard))
		if err != nil {
			return nil, err
		}
		res.Readers = append(res.Readers, got.Reader)
		sf := SealedFor{Reader: got.Reader.String(), Recipients: got.Recipients, Pending: got.Pending}
		rec.Readers = append(rec.Readers, sf)
		if got.Pending != "" {
			res.Pending = append(res.Pending, sf)
		}
		for _, x := range got.Recovery {
			recovery[x] = true
		}
	}
	for x := range recovery {
		rec.Recovery = append(rec.Recovery, x)
	}
	sort.Strings(rec.Recovery)
	recipients, err := parseRecipients(rec.Recipients())
	if err != nil {
		return nil, err
	}
	res.Data, err = coreseal.Seal(coreseal.Payload{Project: e.Project, Env: e.Name, Guard: guard, Private: e.Private}, recipients...)
	if err != nil {
		return nil, err
	}
	rec.Sealed = coreseal.Hash(res.Data)
	rec.Sign(e.Project, e.Name, s.By, s.Key)
	return res, nil
}

func parseRecipients(list []string) ([]age.Recipient, error) {
	out := make([]age.Recipient, 0, len(list))
	for _, s := range list {
		r, err := coreseal.ParseRecipient(s)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
}

// Write stores a seal, its record, and the readers and key in esec.toml.
func Write(root string, pf *projectfile.File, env string, res *Result) error {
	if err := coreseal.Write(root, env, res.Data); err != nil {
		return err
	}
	recs, err := LoadRecords(root)
	if err != nil {
		return err
	}
	recs[env] = res.Record
	if err := recs.Save(root); err != nil {
		return err
	}
	e := pf.Env[env]
	e.Key, e.Readers = res.Record.Key, Strings(res.Readers)
	if Guarded(res.Record.Guard) {
		e.Guard = res.Record.Guard
	} else {
		e.Guard = ""
	}
	if pf.Env == nil {
		pf.Env = map[string]projectfile.Env{}
	}
	pf.Env[env] = e
	return pf.Save(root)
}

// Open opens env's seal in root with ids, checking it is the key of the
// project's env with public key pub ("" skips that check).
func Open(root, project, env, pub string, ids ...age.Identity) (*coreseal.Payload, error) {
	data, err := coreseal.Read(root, env)
	if err != nil {
		return nil, err
	}
	return coreseal.Open(data, project, env, pub, ids...)
}

// Problem is something wrong with a project's seals.
type Problem struct {
	Env string `json:"env"`
	// Level is fail or warn.
	Level  string `json:"level"`
	Detail string `json:"detail"`
	Fix    string `json:"fix,omitempty"`
}

// Problem levels.
const (
	Fail = "fail"
	Warn = "warn"
)

// Check checks a project's seals without a network: every environment with
// a key has a seal, the seal is the one recorded, the record is signed and
// names esec.toml's key, guard and readers, and includes a recovery key.
// read returns a seal's bytes (from disk, or as staged for a commit).
func Check(pf *projectfile.File, recs Records, read func(env string) ([]byte, error)) []Problem {
	var out []Problem
	add := func(env, level, detail, fix string) {
		out = append(out, Problem{Env: env, Level: level, Detail: detail, Fix: fix})
	}
	for _, env := range pf.Envs() {
		e := pf.Env[env]
		if e.Key == "" {
			continue
		}
		data, err := read(env)
		if err != nil {
			add(env, Fail, "its key is not sealed in the repository, so it could be lost", "esec vault seal sync")
			continue
		}
		rec, ok := recs[env]
		if !ok {
			add(env, Fail, "its seal has no record of who it is sealed to", "esec vault seal sync")
			continue
		}
		checkRecord(pf.Project, env, e, rec, data, add)
	}
	for env := range recs {
		if _, ok := pf.Env[env]; !ok {
			add(env, Warn, "sealed, but esec.toml has no such environment", "")
		}
	}
	return out
}

func checkRecord(project, env string, e projectfile.Env, rec *Record, data []byte, add func(env, level, detail, fix string)) {
	switch {
	case rec.Verify(project, env) != nil:
		add(env, Fail, "the record of its seal is not validly signed", "esec vault seal sync")
	case coreseal.Hash(data) != rec.Sealed:
		add(env, Fail, "its seal is not the one recorded: it changed without being signed", "esec vault seal sync")
	case !strings.EqualFold(rec.Key, e.Key):
		add(env, Fail, fmt.Sprintf("esec.toml names key %s… but the seal holds %s…", short(e.Key), short(rec.Key)), "esec vault seal sync (or restore esec.toml)")
	case e.GuardLevel() != rec.Guard:
		add(env, Fail, fmt.Sprintf("esec.toml says guard %s but it is sealed as %s", e.GuardLevel(), rec.Guard), "esec vault guard "+env+" --level "+e.GuardLevel())
	case len(rec.Recovery) == 0:
		add(env, Fail, "its seal has no recovery key: losing every reader would lose it", "esec vault seal sync")
	}
	if want, have := readerIDs(e.Readers), recordIDs(rec); !slices.Equal(want, have) {
		add(env, Fail, "esec.toml's readers are not the ones it is sealed to", "esec vault seal sync")
	}
	for _, s := range rec.Readers {
		if s.Pending != "" {
			add(env, Warn, s.Reader+" "+s.Pending, "esec vault seal sync")
		}
	}
}

func readerIDs(list []string) []string {
	var out []string
	for _, s := range list {
		if r, err := ParseReader(s); err == nil {
			out = append(out, r.Kind+":"+r.ID)
		} else {
			out = append(out, "invalid:"+s)
		}
	}
	sort.Strings(out)
	return slices.Compact(out)
}

func recordIDs(rec *Record) []string {
	list := make([]string, 0, len(rec.Readers))
	for _, s := range rec.Readers {
		list = append(list, s.Reader)
	}
	return readerIDs(list)
}

// Stale says why an environment's seal should be made again: a reader's
// keys changed (a new security key, a rotated user key), a pending reader
// can now be sealed in, or the readers in esec.toml changed. It returns
// nothing when the seal is current.
func Stale(ctx context.Context, d Directory, e projectfile.Env, rec *Record, self Signer) ([]string, error) {
	if rec == nil {
		return []string{"not sealed yet"}, nil
	}
	readers, err := ParseReaders(e.Readers)
	if err != nil {
		return nil, err
	}
	var why []string
	if !slices.Equal(readerIDs(e.Readers), recordIDs(rec)) {
		why = append(why, "readers changed")
	}
	sealed := map[string][]string{}
	for _, s := range rec.Readers {
		if r, err := ParseReader(s.Reader); err == nil {
			sealed[r.Kind+":"+r.ID] = s.Recipients
		}
	}
	for _, r := range readers {
		got, err := d.Resolve(ctx, r, Guarded(rec.Guard))
		if err != nil {
			return nil, err
		}
		have := slices.Clone(sealed[got.Reader.Kind+":"+got.Reader.ID])
		if r.Kind == KindMe {
			have = slices.Clone(sealed[KindMe+":me"])
		}
		want := slices.Clone(got.Recipients)
		slices.Sort(have)
		slices.Sort(want)
		if !slices.Equal(have, want) {
			who := got.Reader.Display() + "'s"
			if r.Kind == KindMe || (got.Reader.Kind == KindPerson && strings.HasPrefix(self.By, "gh:") && got.Reader.ID == self.By) {
				who = "your"
			}
			why = append(why, who+" keys changed")
		}
	}
	if self.Recovery != "" && !slices.Contains(rec.Recovery, self.Recovery) {
		why = append(why, "your recovery key is not in it")
	}
	return why, nil
}

func short(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}
