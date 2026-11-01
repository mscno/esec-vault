package broker

import (
	"errors"
	"os"
	"testing"

	"github.com/mscno/esec-vault/internal/policy"
)

func TestLoggedOutBrokerRefusesCachedAndGuardedRequests(t *testing.T) {
	denied := errors.New("sign in to the vault server")
	s := &Server{RequireLogin: func() error { return denied }}
	for _, op := range []string{OpGetSecrets, OpListEnvs, OpApprove} {
		got := s.dispatch(0, 0, &Request{Op: op})
		if got.OK || got.Error != denied.Error() {
			t.Fatalf("%s bypassed sign-in: %+v", op, got)
		}
	}
	if got := s.dispatch(0, 0, &Request{Op: OpPing}); !got.OK {
		t.Fatal("diagnostic ping requires login")
	}
}

func TestLogoutDuringReadDoesNotDeliverDecryptedValues(t *testing.T) {
	skipUnlessUnix(t)
	path, entries := encryptedFixture(t, t.TempDir())
	s := NewServer(map[string]map[string]string{"org/app": entries}, &policy.Policy{Default: policy.Allow}, nil, nil)
	checks := 0
	s.RequireLogin = func() error {
		checks++
		if checks > 1 {
			return errors.New("signed out during read")
		}
		return nil
	}
	response := s.dispatch(uint32(os.Getuid()), 0, &Request{Op: OpGetSecrets, Project: "org/app", Env: "dev", Path: path, Format: ".ejson"}) //nolint:gosec // Unix user IDs fit in uint32.
	if response.OK || len(response.Secrets) != 0 || response.Error != "signed out during read" {
		t.Fatalf("read outlived login: %+v", response)
	}
}
