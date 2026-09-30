package service

import (
	"context"
	"time"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
)

// WIAChallengeStore is the interface for WIA challenge persistence.
// Implementations must support single-use consumption (get-and-delete atomically)
// and automatic expiry of stale challenges.
type WIAChallengeStore interface {
	// Put stores a challenge with an expiration time, scoped to tenantID.
	// Returns false if either the global or the per-tenant capacity is
	// exceeded (see issue #224 acceptance criteria: "bounded capacity per
	// tenant to prevent abuse" — a global-only bound lets a single tenant
	// exhaust the shared pool and deny challenge creation for everyone else).
	Put(ctx context.Context, tenantID domain.TenantID, challenge string, expiresAt time.Time) (bool, error)

	// Consume atomically retrieves and deletes a challenge.
	// Returns false if the challenge doesn't exist or is expired.
	Consume(ctx context.Context, challenge string) (bool, error)

	// Len returns the number of stored challenges (approximate for distributed stores).
	Len(ctx context.Context) (int, error)
}
