package identity

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/mscno/esec-vault/internal/chain"
	"github.com/mscno/esec-vault/internal/paths"
	"github.com/mscno/esec-vault/internal/storage"
)

// RootAuth is the recovery phrase's authorization of one user key as the
// root of a vault account. It is public data, kept so that creating an
// account later does not need the phrase again.
type RootAuth struct {
	EncPub        string `json:"enc_pub"`
	SignPub       string `json:"sign_pub"`
	MasterSignPub string `json:"master_sign_pub"`
	Sig           []byte `json:"sig"`
}

func rootAuthPath() string { return filepath.Join(paths.Home(), "root-auth.json") }

// MakeRootAuth signs id as an account root with the master signing key.
func MakeRootAuth(keys *MasterKeys, id *Identity) (*RootAuth, error) {
	if id.Sign == nil {
		return nil, errors.New("identity has no signing key")
	}
	return &RootAuth{
		EncPub:        hex.EncodeToString(id.Public[:]),
		SignPub:       hex.EncodeToString(id.SignPublic()),
		MasterSignPub: hex.EncodeToString(keys.SignPublic()),
		Sig:           ed25519.Sign(keys.Sign, chain.RootStatement(id.Public, id.SignPublic())),
	}, nil
}

// Matches reports whether ra authorizes exactly id.
func (ra *RootAuth) Matches(id *Identity) bool {
	if ra == nil || id.Sign == nil || ra.EncPub != hex.EncodeToString(id.Public[:]) || ra.SignPub != hex.EncodeToString(id.SignPublic()) {
		return false
	}
	pub, err := chain.ParseSignKey(ra.MasterSignPub)
	return err == nil && ed25519.Verify(pub, chain.RootStatement(id.Public, id.SignPublic()), ra.Sig)
}

// SaveRootAuth stores ra for later account creation.
func SaveRootAuth(ra *RootAuth) error {
	data, err := json.Marshal(ra)
	if err != nil {
		return err
	}
	return storage.Write(rootAuthPath(), data)
}

// LoadRootAuth reads the stored authorization; a missing file yields nil.
func LoadRootAuth() (*RootAuth, error) {
	data, err := os.ReadFile(rootAuthPath())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var ra RootAuth
	if err := json.Unmarshal(data, &ra); err != nil {
		return nil, fmt.Errorf("invalid %s: %w", rootAuthPath(), err)
	}
	return &ra, nil
}

// RememberRootAuth derives the master keys from the phrase and stores the
// authorization for id. Commands that already hold the phrase call it so the
// first vault login needs no phrase.
func RememberRootAuth(mnemonic, passphrase string, id *Identity) error {
	keys, err := DeriveMasterKeys(mnemonic, passphrase)
	if err != nil {
		return err
	}
	ra, err := MakeRootAuth(keys, id)
	if err != nil {
		return err
	}
	return SaveRootAuth(ra)
}
