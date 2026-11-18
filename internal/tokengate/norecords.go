package tokengate

import (
	"context"
	"time"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
)

// NoUserRecords is the explicit "there is no user database here" UserLookup:
// every user has no record and no deletion tombstone, so Gate.Check never
// refuses a token for SID-AUTH-06 reasons. It is for the registry-only
// process, which holds no user store; passing it instead of nil keeps that
// decision visible (TokenAuthMiddleware still panics on nil so a backend role
// cannot run without the gate). Never use it for a role serving user-scoped
// routes.
type NoUserRecords struct{}

var _ UserLookup = NoUserRecords{}

// GetAuthCutoff reports no user record.
func (NoUserRecords) GetAuthCutoff(context.Context, domain.UserID) (time.Time, error) {
	return time.Time{}, storage.ErrNotFound
}

// GetDeletionTombstone reports no tombstone.
func (NoUserRecords) GetDeletionTombstone(context.Context, string) (*domain.DeletionTombstone, error) {
	return nil, storage.ErrNotFound
}
