package service

import (
	"context"
	"time"
)

// WIAChallengeStore is the interface for WIA challenge persistence.
// Implementations must support single-use consumption (get-and-delete atomically)
// and automatic expiry of stale challenges.
type WIAChallengeStore interface {
	// Put stores a challenge with an expiration time.
	// Returns false if capacity is exceeded.
	Put(ctx context.Context, challenge string, expiresAt time.Time) (bool, error)

	// Consume atomically retrieves and deletes a challenge.
	// Returns false if the challenge doesn't exist or is expired.
	Consume(ctx context.Context, challenge string) (bool, error)

	// Len returns the number of stored challenges (approximate for distributed stores).
	Len(ctx context.Context) (int, error)
}
