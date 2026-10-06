package tokengate

import (
	"context"
	"time"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
)

// NoUserRecords is the explicit "there is no user database here" UserLookup.
// It reports every user as having no record (storage.ErrNotFound) and no
// deletion tombstone, so Gate.Check never finds a cut-off and never refuses a
// token for SID-AUTH-06 reasons.
//
// It exists for the registry-only process (internal/registry): the registry
// validates tokens but never serves user-scoped writes, holds no user store
// and so has no per-user authorization cut-off to enforce. Passing this
// named implementation, instead of nil, keeps the "no lookup" decision
// visible at the call site; middleware.TokenAuthMiddleware still panics on a
// nil lookup so a backend role cannot silently run without the gate.
//
// It must NOT be used by any role that serves user-scoped routes: those wire
// the real storage user store.
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
