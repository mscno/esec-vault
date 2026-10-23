package machine

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/mscno/esec-vault/internal/chain"
	"github.com/mscno/esec-vault/internal/client"
	"github.com/mscno/esec-vault/internal/team"
	"github.com/mscno/esec-vault/internal/wire"
)

// WorkloadEnv names a workload's descriptor: plain configuration, no
// secret (team.WorkloadRef).
const WorkloadEnv = "ESEC_VAULT_WORKLOAD"

// FetchWorkload gets a workload's keys: it proves where it runs with its
// OIDC token, verifies the group chain from the descriptor's root, has the
// KMS key the chain names unwrap its group key (with an OIDC token for the
// KMS's identity federation), and opens each project's keys with it.
func FetchWorkload(ctx context.Context, ref *team.WorkloadRef) (*Keys, error) {
	c, err := client.New(ref.Server)
	if err != nil {
		return nil, err
	}
	token, err := WorkloadToken(ctx, ref.Server)
	if err != nil {
		return nil, err
	}
	if token == "" {
		return nil, errors.New("this workload has no OIDC token to prove where it runs: run it on a Fly.io Machine or in a GitHub Actions job")
	}
	resp, err := c.WorkloadKeys(ctx, wire.WorkloadKeysRequest{Group: ref.Group, ID: ref.ID, OIDCToken: token})
	if err != nil {
		return nil, err
	}
	return VerifyWorkload(ctx, ref, resp, WorkloadToken)
}

// VerifyWorkload checks a server response against a workload descriptor,
// like VerifyGroup for a machine, and unwraps its group key with the KMS
// key the verified chain names; token gives the KMS its OIDC token.
func VerifyWorkload(ctx context.Context, ref *team.WorkloadRef, resp *wire.GroupKeys, token func(ctx context.Context, audience string) (string, error)) (*Keys, error) {
	chains := chainsFrom(resp.Chains)
	if len(resp.Links) == 0 || resp.Links[0].Hash() != ref.Root {
		return nil, errors.New("the server's group chain does not start where this workload's does; refusing it")
	}
	gs, err := team.VerifyGroup(ref.Group, resp.Links, chains)
	if err != nil {
		return nil, fmt.Errorf("the group chain does not verify: %w", err)
	}
	cred, ok := gs.Cred(ref.ID)
	if !ok || cred.Kind != team.KindWorkload || cred.KMS == nil {
		return nil, fmt.Errorf("this workload is no longer part of %s", ref.Group)
	}
	if resp.KeyGrant == nil {
		return nil, errors.New("the server sent no group key")
	}
	// The KMS key comes from the verified chain, never from the server.
	unwrap := func(box []byte) ([]byte, error) { return cred.KMS.Unwrap(ctx, box, token) }
	gpriv, err := team.OpenWorkloadKeyGrant(resp.KeyGrant, gs, chains, ref.ID, unwrap)
	if err != nil {
		return nil, fmt.Errorf("the group key does not open: %w", err)
	}
	gpub, err := chain.ParseKey32(gs.Key.EncPub)
	if err != nil {
		return nil, err
	}
	me := team.Recipient{ID: team.GroupHolder(ref.Group), Version: gs.Key.Version, EncPub: gpub}
	out := &Keys{Group: ref.Group, Machine: ref.ID, Name: cred.Name, Projects: map[string]map[string]string{}}
	for _, p := range resp.Projects {
		keys, err := openProject(p, gs, chains, me, gpriv)
		if err != nil {
			out.Problems = append(out.Problems, p.Project+": "+err.Error())
			continue
		}
		out.Projects[p.Project] = keys
	}
	sort.Strings(out.Problems)
	return out, nil
}
