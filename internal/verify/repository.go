package verify

import "context"

// RepositorySource checks repository seals without opening their private keys.
func RepositorySource(ctx context.Context, checkouts []string, history bool) (Source, error) {
	return sealedSource(ctx, checkouts, history)
}
