package account

import (
	"context"
	"time"

	"github.com/mscno/esec-vault/internal/wire"
)

// Access requests and timed access live on the server alone: a request is
// only a message to a project's admins, and timed access only tells the
// server when to take access away (it can never grant any).

// AccessRequests lists the requests this account can decide, and its own.
func (a *Account) AccessRequests(ctx context.Context) (*wire.AccessRequests, error) {
	if err := a.requireConfirmed(); err != nil {
		return nil, err
	}
	return a.Client.Requests(ctx)
}

// RequestAccess asks a project's admins for environments.
func (a *Account) RequestAccess(ctx context.Context, project string, envs []string, reason string) (*wire.AccessRequest, error) {
	if err := a.requireConfirmed(); err != nil {
		return nil, err
	}
	return a.Client.RequestAccess(ctx, wire.AccessRequestNew{Project: project, Envs: envs, Reason: reason})
}

// CloseRequest answers a request, or withdraws this account's own.
func (a *Account) CloseRequest(ctx context.Context, id int64, granted bool) error {
	if err := a.requireConfirmed(); err != nil {
		return err
	}
	return a.Client.CloseRequest(ctx, id, granted)
}

// EndAccessAt tells the server to take envs of project away from subject (a
// login or a group) at t.
func (a *Account) EndAccessAt(ctx context.Context, project, subject string, envs []string, t time.Time) (*wire.AccessExpiry, error) {
	if err := a.requireConfirmed(); err != nil {
		return nil, err
	}
	return a.Client.SetExpiry(ctx, project, wire.AccessExpiry{Subject: subject, Envs: envs, Expires: t.UTC().Truncate(time.Second)})
}

// TimedAccess lists a project's timed access.
func (a *Account) TimedAccess(ctx context.Context, project string) ([]wire.AccessExpiry, error) {
	if err := a.requireConfirmed(); err != nil {
		return nil, err
	}
	return a.Client.Expiries(ctx, project)
}

// OrgPolicy returns the policy the server enforces for an organisation.
func (a *Account) OrgPolicy(ctx context.Context, org string) (*wire.OrgPolicy, error) {
	if err := a.requireConfirmed(); err != nil {
		return nil, err
	}
	return a.Client.OrgPolicy(ctx, org)
}

// ReviewStatus says whether a project's access review is due.
func (a *Account) ReviewStatus(ctx context.Context, project string) (*wire.ReviewStatus, error) {
	if err := a.requireConfirmed(); err != nil {
		return nil, err
	}
	return a.Client.Review(ctx, project)
}

// RecordReview records an access review of a project.
func (a *Account) RecordReview(ctx context.Context, project string, kept, removed []string) error {
	if err := a.requireConfirmed(); err != nil {
		return err
	}
	return a.Client.RecordReview(ctx, project, wire.AccessReview{Kept: kept, Removed: removed})
}
