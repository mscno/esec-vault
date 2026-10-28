package account

// Sealing environment keys in repositories: who a reader is, by GitHub id,
// resolved to keys from verified user chains. The server serves the chains;
// it cannot change them, since every link is signed by the person's keys,
// and the first by the key their recovery phrase derives.

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/mscno/esec-vault/internal/chain"
	"github.com/mscno/esec-vault/internal/client"
	"github.com/mscno/esec-vault/internal/seal"
	"github.com/mscno/esec-vault/internal/team"
	"github.com/mscno/esec-vault/internal/wire"
)

// SealPerson is a person as seals see them.
type SealPerson = seal.Person

func personFromChain(user, login string, st *chain.State) *seal.Person {
	p := &seal.Person{User: user, Login: login, EncPub: hex.EncodeToString(st.EncPub[:]), MasterPub: hex.EncodeToString(st.MasterPub[:])}
	for _, k := range st.ActiveSecurityKeys() {
		p.SecurityKeys = append(p.SecurityKeys, k.Recipient)
	}
	return p
}

// SealSelf returns this account's keys, from its verified chain.
func (a *Account) SealSelf(ctx context.Context) (*seal.Person, error) {
	st, err := a.VerifiedChain(ctx)
	if err != nil {
		return nil, err
	}
	return personFromChain(a.State.User, a.State.Login, st), nil
}

// SealPersonByID returns gh:<id>'s keys from their chain, checked against
// this device's pin of it. It returns seal.ErrNoAccount when they have none.
func (a *Account) SealPersonByID(ctx context.Context, user string) (*seal.Person, error) {
	var out *seal.Person
	err := a.withTeam(ctx, func(t *teamCtx) error {
		p, err := a.Client.PersonByID(ctx, user)
		if client.IsCode(err, wire.ErrNotFound) {
			return seal.ErrNoAccount
		}
		if err != nil {
			return err
		}
		if p.User.ID != user {
			return fmt.Errorf("the server returned the account of %s for %s", p.User.ID, user)
		}
		st, err := t.peer(user, p.Links)
		if err != nil {
			return err
		}
		out = personFromChain(user, p.User.Login, st)
		return nil
	})
	return out, err
}

// FoundPerson is a GitHub user looked up to share with.
type FoundPerson struct {
	User  string // gh:<id>
	Login string
	// Person is their keys; nil when they have no account yet.
	Person *seal.Person
	// Verified says how the account was tied to the GitHub login.
	Verified string
}

// FindPerson looks a GitHub login up to share with. With an account, it
// checks the account belongs to that login (their published GitHub SSH
// proof, or the account key words given); without one, it asks GitHub for
// the numeric id, so the person can be sealed in once they sign up and a
// later owner of the login never inherits the access.
func (a *Account) FindPerson(ctx context.Context, login, accountKey string) (*FoundPerson, error) {
	var out *FoundPerson
	err := a.withTeam(ctx, func(t *teamCtx) error {
		p, err := a.Client.Person(ctx, login)
		if client.IsCode(err, wire.ErrNotFound) {
			id, gotLogin, gerr := GitHubUser(ctx, login)
			if gerr != nil {
				return gerr
			}
			out = &FoundPerson{User: fmt.Sprintf("gh:%d", id), Login: gotLogin}
			return nil
		}
		if err != nil {
			return err
		}
		if !strings.EqualFold(p.User.Login, login) || p.User.ID != fmt.Sprintf("gh:%d", p.User.GitHubID) {
			return fmt.Errorf("the server returned the account of %q for %q; not sharing with it", p.User.Login, login)
		}
		st, err := t.peer(p.User.ID, p.Links)
		if err != nil {
			return err
		}
		person := team.Person{User: p.User.ID, Login: p.User.Login, Root: st.Root()}
		verified, err := checkPerson(person, p.Proof, st, accountKey)
		if err != nil {
			return err
		}
		out = &FoundPerson{User: p.User.ID, Login: p.User.Login, Person: personFromChain(p.User.ID, p.User.Login, st), Verified: verified}
		return nil
	})
	return out, err
}

// githubAPI is GitHub's API: ESEC_VAULT_GITHUB_API_URL, else that of
// ESEC_VAULT_GITHUB_URL (GitHub Enterprise, tests), else api.github.com.
func githubAPI() string {
	if u := strings.TrimRight(os.Getenv("ESEC_VAULT_GITHUB_API_URL"), "/"); u != "" {
		return u
	}
	if u := strings.TrimRight(os.Getenv("ESEC_VAULT_GITHUB_URL"), "/"); u != "" {
		return u + "/api/v3"
	}
	return "https://api.github.com"
}

// GitHubUser asks GitHub for a login's numeric id, the one thing that
// identifies a GitHub user for good.
func GitHubUser(ctx context.Context, login string) (int64, string, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, githubAPI()+"/users/"+url.PathEscape(login), nil)
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, "", fmt.Errorf("ask GitHub for %s: %w", login, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return 0, "", fmt.Errorf("GitHub has no user %q", login)
	}
	if resp.StatusCode != http.StatusOK {
		return 0, "", fmt.Errorf("ask GitHub for %s: %s", login, resp.Status)
	}
	var u struct {
		ID    int64  `json:"id"`
		Login string `json:"login"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&u); err != nil {
		return 0, "", err
	}
	if u.ID <= 0 || !strings.EqualFold(u.Login, login) {
		return 0, "", fmt.Errorf("GitHub answered for %q with %q", login, u.Login)
	}
	return u.ID, u.Login, nil
}

// SealGroupPublic returns a machine group's current public key (hex).
func (a *Account) SealGroupPublic(ctx context.Context, group string) (string, error) {
	var out string
	err := a.withTeam(ctx, func(t *teamCtx) error {
		gs, err := t.group(group)
		if err != nil {
			return err
		}
		if gs == nil {
			return fmt.Errorf("no group %s", group)
		}
		out = gs.Key.EncPub
		return nil
	})
	return out, err
}

// SealGroupPrivate opens a group's current private key, for a member
// opening a seal made for the group.
func (a *Account) SealGroupPrivate(ctx context.Context, group string) ([32]byte, error) {
	var out [32]byte
	err := a.withTeam(ctx, func(t *teamCtx) error {
		gs, err := t.group(group)
		if err != nil {
			return err
		}
		if gs == nil {
			return fmt.Errorf("no group %s", group)
		}
		out, err = t.groupKey(gs)
		return err
	})
	return out, err
}
