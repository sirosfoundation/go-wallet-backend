package service

import (
	"context"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

// TokenBlacklist manages revoked JWT tokens.
// Tokens are stored until their expiry time, then automatically cleaned up.
//
// It also supports revoking every token for a user in one call (RevokeUser),
// for use on account deletion (#383): unlike Add, which blacklists one
// already-known jti, deletion has no way to enumerate every jti ever issued
// to the user, so it instead records "this user_id is permanently retired"
// and IsUserRevoked rejects any token for it from then on.
//
// A user-revocation entry is never time-expired (unlike the per-jti
// entries in tokens, which are only ever kept until the token's own exp):
// user_id values are UUIDs minted fresh by domain.NewUserID() and are never
// reissued to a different (or the same) user after deletion, so there is no
// "issued before/after the revocation" window to reason about - the
// revocation is simply permanent for that ID, and a time-based retention
// window (an earlier version of this used a fixed 30-day one) risks
// expiring the marker while a long-lived token for that same user_id is
// still otherwise valid. The tradeoff is that this map grows by one entry
// per account ever deleted and is never pruned - acceptable given how
// small and infrequent that is compared to the tokens map's own entries.
type TokenBlacklist struct {
	config config.TokenBlacklistConfig
	logger *zap.Logger

	mu              sync.RWMutex
	tokens          map[string]time.Time // jti -> expiry time
	userRevocations map[string]bool      // userID -> permanently revoked
	families        map[string]time.Time // sid (refresh-token family) -> revocation retention expiry
	stopChan        chan struct{}
	wg              sync.WaitGroup
}

// NewTokenBlacklist creates a new token blacklist
func NewTokenBlacklist(cfg config.TokenBlacklistConfig, logger *zap.Logger) *TokenBlacklist {
	cfg.SetDefaults()
	return &TokenBlacklist{
		config:          cfg,
		logger:          logger.Named("token-blacklist"),
		tokens:          make(map[string]time.Time),
		userRevocations: make(map[string]bool),
		families:        make(map[string]time.Time),
		stopChan:        make(chan struct{}),
	}
}

// Start begins the cleanup worker for expired blacklist entries.
//
// This always launches the cleanup goroutine, even when config.Enabled is
// false: ConsumeOnce (see its doc comment) writes entries unconditionally,
// independent of that flag, so a disabled blacklist can still accumulate
// consumed-refresh-token entries that need periodic sweeping - without
// this, every successful refresh would permanently grow the map for the
// life of the process whenever the general blacklist feature happens to be
// off (Copilot review on go-wallet-backend#400).
func (b *TokenBlacklist) Start() {
	b.wg.Add(1)
	go b.cleanupLoop()

	if !b.config.Enabled {
		b.logger.Info("Token blacklist (general revocation feature) disabled; cleanup worker still runs for ConsumeOnce-tracked entries")
		return
	}

	b.logger.Info("Token blacklist started",
		zap.Int("cleanup_interval_seconds", b.config.CleanupIntervalSeconds),
	)
}

// Stop gracefully stops the blacklist cleanup worker
func (b *TokenBlacklist) Stop() {
	close(b.stopChan)
	b.wg.Wait()
	b.logger.Info("Token blacklist stopped")
}

// cleanupLoop periodically removes expired entries
func (b *TokenBlacklist) cleanupLoop() {
	defer b.wg.Done()

	ticker := time.NewTicker(time.Duration(b.config.CleanupIntervalSeconds) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-b.stopChan:
			return
		case <-ticker.C:
			b.cleanup()
		}
	}
}

// cleanup removes expired entries from the blacklist
func (b *TokenBlacklist) cleanup() {
	b.mu.Lock()
	defer b.mu.Unlock()

	now := time.Now()
	removed := 0

	for jti, expiry := range b.tokens {
		if now.After(expiry) {
			delete(b.tokens, jti)
			removed++
		}
	}

	if removed > 0 {
		b.logger.Debug("Cleaned up expired blacklist entries",
			zap.Int("removed", removed),
			zap.Int("remaining", len(b.tokens)),
		)
	}

	// userRevocations is intentionally not swept here - see the type's doc
	// comment for why a user-level revocation is permanent, not time-bound.

	// families IS swept, unlike userRevocations: a session is logged out
	// far more often than an account is deleted, and RevokeFamily's own
	// expiry is sized so no token that could still reference that sid can
	// possibly still be valid past it (see RevokeFamily's doc comment) -
	// so, unlike a user revocation, there is never a reason to keep the
	// entry beyond that point.
	familiesRemoved := 0
	for sid, expiry := range b.families {
		if now.After(expiry) {
			delete(b.families, sid)
			familiesRemoved++
		}
	}

	if familiesRemoved > 0 {
		b.logger.Debug("Cleaned up expired family revocations",
			zap.Int("removed", familiesRemoved),
			zap.Int("remaining", len(b.families)),
		)
	}
}

// Add adds a token JTI to the blacklist
// The token will be automatically removed after its expiry time.
func (b *TokenBlacklist) Add(ctx context.Context, jti string, expiry time.Time) error {
	if !b.config.Enabled {
		return nil
	}

	if jti == "" {
		// Can't blacklist tokens without JTI
		return nil
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	b.tokens[jti] = expiry

	b.logger.Debug("Token added to blacklist",
		zap.String("jti", jti),
		zap.Time("expiry", expiry),
	)

	return nil
}

// ConsumeOnce atomically checks-and-marks jti as used, returning true only
// the first time it is called for a given jti (false on every subsequent
// call, including concurrent ones - the check and the insert happen under
// the same write lock, so two goroutines racing on the same jti cannot both
// observe "not yet consumed").
//
// Unlike Add/IsBlacklisted, this is NOT gated by config.Enabled: those two
// implement the general-purpose, operator-opt-in token revocation feature
// (Logout, DeleteUser - see their callers), but single-use enforcement for
// a refresh token (see WebAuthnService.RefreshAccessToken) is a correctness
// property of the refresh-token protocol itself, not an optional feature -
// making it conditional on a separate, independently-configured toggle
// would mean the "checked-in" default configuration (TokenBlacklist
// disabled) leaves refresh tokens replayable indefinitely despite
// RefreshAccessToken appearing to enforce single-use (Copilot review on
// #400: "wiring this object does not consume refresh tokens for standard
// configurations"). This still reuses the same underlying map/expiry
// cleanup machinery as Add/IsBlacklisted - only the Enabled gate is
// bypassed.
func (b *TokenBlacklist) ConsumeOnce(ctx context.Context, jti string, expiry time.Time) (firstUse bool, err error) {
	if jti == "" {
		// Can't track a jti-less token; treat as always "first use" so
		// callers don't spuriously reject a token this service issued
		// without one (shouldn't happen in practice).
		return true, nil
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	if existingExpiry, exists := b.tokens[jti]; exists && time.Now().Before(existingExpiry) {
		return false, nil
	}

	b.tokens[jti] = expiry
	return true, nil
}

// IsBlacklisted checks if a token JTI is on the blacklist
func (b *TokenBlacklist) IsBlacklisted(ctx context.Context, jti string) bool {
	if !b.config.Enabled {
		return false
	}

	if jti == "" {
		// Tokens without JTI can't be blacklisted
		return false
	}

	b.mu.RLock()
	defer b.mu.RUnlock()

	expiry, exists := b.tokens[jti]
	if !exists {
		return false
	}

	// Check if the blacklist entry has expired (token itself expired)
	if time.Now().After(expiry) {
		return false
	}

	return true
}

// RevokeUser permanently marks userID as revoked: every token for it,
// regardless of when issued, is rejected from now on. Used on account
// deletion (#383) so previously-issued tokens for that user - not just the
// one used to authenticate the deletion request - stop working immediately
// rather than lingering until they naturally expire. Combine with
// IsUserRevoked, which callers check alongside IsBlacklisted.
func (b *TokenBlacklist) RevokeUser(ctx context.Context, userID string) error {
	if !b.config.Enabled {
		return nil
	}

	if userID == "" {
		return nil
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	b.userRevocations[userID] = true

	b.logger.Debug("All tokens revoked for user", zap.String("user_id", userID))

	return nil
}

// IsUserRevoked reports whether userID has been permanently revoked (via
// RevokeUser) - i.e. whether any token for that user, however it validated,
// should be rejected even though its own jti was never individually
// blacklisted.
func (b *TokenBlacklist) IsUserRevoked(ctx context.Context, userID string) bool {
	if !b.config.Enabled {
		return false
	}

	if userID == "" {
		return false
	}

	b.mu.RLock()
	defer b.mu.RUnlock()

	return b.userRevocations[userID]
}

// RevokeFamily permanently revokes sid - a refresh-token family/session id
// minted into both an access token's and its paired refresh token's "sid"
// claim (see WebAuthnService.generateToken/generateRefreshToken) and carried
// forward unchanged across every rotation of that refresh token
// (WebAuthnService.RefreshAccessToken). From the moment this is called,
// every access or refresh token sharing that sid must be rejected -
// whichever of them is presented, however old, and regardless of whether
// its own jti was ever individually blacklisted.
//
// This closes the gap tracked as #402: Logout previously had no way to
// revoke anything beyond the single access token jti it was actually
// given, leaving any refresh token issued alongside it (or any token from
// a later rotation of it) fully valid until it naturally expired - a
// stolen refresh token, or one simply still held by another device,
// survived its own session's logout indefinitely.
//
// expiry must be no earlier than the latest possible expiry of any token
// that could still legitimately carry this sid - typically now +
// JWT.RefreshDays (the longer-lived of the pair) plus a safety margin;
// see Logout's own computation. Once expiry passes, the entry is swept by
// cleanup() exactly like a per-jti entry (unlike RevokeUser/
// userRevocations, which are permanent - see cleanup's doc comment for
// why a session revocation doesn't need to be).
//
// Unlike RevokeUser (an operator-opt-in feature gated by config.Enabled),
// this is NOT gated by it: revoking a session's own refresh-token family
// on logout is a correctness property of session termination itself, not
// a separate opt-in feature - exactly the same reasoning ConsumeOnce's own
// doc comment gives for bypassing the same gate, and for the same reason:
// making it conditional on a separately-configured toggle would leave the
// checked-in default configuration unable to revoke a session's refresh
// tokens on logout at all.
//
// Re-revoking an already revoked sid keeps the LATER of the existing and
// requested expiry, so the marker can only ever be extended.
//
// It returns ctx.Err() without recording anything if ctx is already done,
// so a caller (Logout) can never mistake an abandoned request for a
// completed revocation; callers must treat any error as "not revoked" and
// fail closed.
func (b *TokenBlacklist) RevokeFamily(ctx context.Context, sid string, expiry time.Time) error {
	if sid == "" {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	// Never shorten an existing marker: a re-revoke under a smaller
	// retention (e.g. config lowered to the floor) must not make tokens
	// from the original, longer window usable again.
	if existing, ok := b.families[sid]; ok && existing.After(expiry) {
		expiry = existing
	}
	b.families[sid] = expiry

	b.logger.Debug("Refresh-token family revoked", zap.String("sid", sid))

	return nil
}

// IsFamilyRevoked reports whether sid has been revoked via RevokeFamily and
// that revocation's own retention window hasn't yet elapsed. Checked
// alongside IsBlacklisted/IsUserRevoked by both the access-token validation
// path (pkg/middleware.AuthMiddlewareWithBlacklist) and
// WebAuthnService.RefreshAccessToken - see RevokeFamily's doc comment.
//
// Deliberately NOT gated by config.Enabled - see RevokeFamily.
func (b *TokenBlacklist) IsFamilyRevoked(ctx context.Context, sid string) bool {
	if sid == "" {
		return false
	}

	b.mu.RLock()
	defer b.mu.RUnlock()

	expiry, exists := b.families[sid]
	if !exists {
		return false
	}

	if time.Now().After(expiry) {
		return false
	}

	return true
}

// Remove removes a token from the blacklist (if needed for admin override)
func (b *TokenBlacklist) Remove(ctx context.Context, jti string) error {
	if !b.config.Enabled {
		return nil
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	delete(b.tokens, jti)

	b.logger.Debug("Token removed from blacklist",
		zap.String("jti", jti),
	)

	return nil
}

// Count returns the number of tokens currently on the blacklist
func (b *TokenBlacklist) Count() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.tokens)
}
