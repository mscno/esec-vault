package cli

import (
	"errors"
	"fmt"
	"time"

	"github.com/mscno/esec/pkg/secretstore"

	"github.com/mscno/esec-vault/internal/account"
	"github.com/mscno/esec-vault/internal/keyring"
	"github.com/mscno/esec-vault/internal/keystore"
	"github.com/mscno/esec-vault/internal/safetext"
)

// serverStatus is the vault-server part of status output.
type serverStatus struct {
	Server         string    `json:"server"`
	Login          string    `json:"login"`
	User           string    `json:"user"`
	DeviceID       string    `json:"device_id"`
	DeviceName     string    `json:"device_name"`
	DeviceStatus   string    `json:"device_status,omitempty"`
	DeviceWords    string    `json:"device_fingerprint,omitempty"`
	AccountWords   string    `json:"account_key"`
	ChainSeq       uint64    `json:"chain_seq"`
	UKeyVersion    uint64    `json:"user_key_version"`
	VaultVersion   uint64    `json:"vault_version"`
	VaultGen       uint64    `json:"vault_generation"`
	LastSync       time.Time `json:"last_sync,omitzero"`
	SessionExpires time.Time `json:"session_expires,omitzero"`
	Conflicts      []string  `json:"conflicts,omitempty"`
}

// storeStatus describes local key storage.
type storeStatus struct {
	Backend       string `json:"backend"`
	HardwareBound bool   `json:"hardware_bound"`
	Sealed        int    `json:"sealed_keyrings"`
	Plain         int    `json:"plain_keyrings"`
	SealNew       bool   `json:"seal_new_keyrings"`
}

func inspectServer(ctx *cliCtx, problems *[]string) *serverStatus {
	st, err := account.LoadState()
	if errors.Is(err, account.ErrNotLoggedIn) {
		return nil
	}
	if err != nil {
		*problems = append(*problems, err.Error())
		return nil
	}
	out := &serverStatus{Server: st.Server, Login: st.Login, User: st.User, DeviceID: st.DeviceID, DeviceName: st.DeviceName, AccountWords: st.Chain.AccountWords, ChainSeq: st.Chain.Seq, UKeyVersion: st.Chain.UKeyVersion, VaultVersion: st.Vault.Version, VaultGen: st.Vault.Generation, LastSync: st.Vault.SyncedAt, Conflicts: st.Vault.Conflicts}
	if len(st.Vault.Conflicts) > 0 {
		*problems = append(*problems, fmt.Sprintf("%d vault entries conflict with this machine's keyrings; run: esec vault sync", len(st.Vault.Conflicts)))
	}
	a, err := openAccount(ctx)
	if err != nil {
		*problems = append(*problems, "vault server: "+err.Error())
		return out
	}
	out.DeviceWords = a.Words()
	bg, cancel := timeout(5 * time.Second)
	defer cancel()
	me, err := a.Client.Me(bg)
	if err != nil {
		*problems = append(*problems, "vault server: "+err.Error())
		return out
	}
	out.DeviceStatus, out.SessionExpires = me.Device.Status, me.SessionExpires
	if me.Device.Status != "active" {
		*problems = append(*problems, "this device is "+safetext.Clean(me.Device.Status)+" on the vault server")
		return out
	}
	if devices, err := a.Devices(bg); err == nil {
		for _, d := range devices {
			if d.ServerStatus == "suspended" && d.Status == "active" {
				*problems = append(*problems, fmt.Sprintf("device %s (%s) is suspended on the server; finish revoking it: esec vault devices revoke %s", d.Name, d.ID, d.ID))
			}
		}
	}
	return out
}

func inspectStore(ctx *cliCtx, problems *[]string) *storeStatus {
	backend, hw := keyring.Describe(ctx.Keyring)
	out := &storeStatus{Backend: backend, HardwareBound: hw}
	if cfg, err := secretstore.LoadConfig(); err == nil {
		out.SealNew = cfg.SealKeyrings
	}
	ks := keystore.New()
	projects, err := ks.List()
	if err != nil {
		*problems = append(*problems, "keyrings: "+err.Error())
		return out
	}
	for _, p := range projects {
		sealed, err := ks.IsSealed(p)
		if err != nil {
			continue
		}
		if sealed {
			out.Sealed++
		} else {
			out.Plain++
		}
	}
	if out.Sealed > 0 && !hw {
		*problems = append(*problems, "keyrings are sealed, but the secret store ("+backend+") has no hardware binding: sealing only protects against copying the keyring files without the rest of the home directory")
	}
	return out
}

func printServerStatus(s *serverStatus, store *storeStatus) {
	if store != nil {
		hw := "no hardware binding"
		if store.HardwareBound {
			hw = "hardware bound"
		}
		fmt.Printf("Secret store: %s (%s); keyrings sealed: %d, plain: %d\n", store.Backend, hw, store.Sealed, store.Plain)
	}
	if s == nil {
		fmt.Println("Vault server: not signed in (esec vault login <server>)")
		return
	}
	fmt.Printf("Vault server: %s as %s (%s)\n", s.Server, safetext.Clean(s.Login), s.User)
	fmt.Printf("Device: %s %q, status %s, fingerprint %s\n", s.DeviceID, safetext.Clean(s.DeviceName), safetext.Clean(valueOr(s.DeviceStatus, "unknown")), s.DeviceWords)
	fmt.Printf("Account key: %s; chain %d links, user key version %d\n", s.AccountWords, s.ChainSeq, s.UKeyVersion)
	last := "never"
	if !s.LastSync.IsZero() {
		last = s.LastSync.Local().Format(time.RFC3339) //nolint:gosmopolitan // shown to the local user
	}
	fmt.Printf("Vault: version %d, generation %d, last sync %s\n", s.VaultVersion, s.VaultGen, last)
}

func valueOr(v, d string) string {
	if v == "" {
		return d
	}
	return v
}
