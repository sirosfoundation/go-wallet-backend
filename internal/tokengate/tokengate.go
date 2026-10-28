// Package tokengate refuses bearer tokens issued before a user's authorization
// was cut off by a wallet lifecycle event (SID-AUTH-06).
//
// The lifecycle service records User.AuthInvalidBefore; every place that
// accepts a token consults Gate.Check with the token's iat.
package tokengate

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
)

// ErrRevoked is returned for a token issued before the user's authorization was cut off.
var ErrRevoked = errors.New("token issued before the user's authorization was revoked")

// UserLookup reads the user's auth cut-off and the deletion tombstone.
type UserLookup interface {
	GetAuthCutoff(ctx context.Context, id domain.UserID) (time.Time, error)
	GetDeletionTombstone(ctx context.Context, userID string) (*domain.DeletionTombstone, error)
}

// ErrAccountDeleted refuses a token for a deleted account; it wraps ErrRevoked.
var ErrAccountDeleted = fmt.Errorf("%w: the account was deleted", ErrRevoked)

// RefuseIfDeleted refuses a user with a deletion tombstone; no tombstone means
// an external identity, not judged. A failed tombstone read fails closed.
func RefuseIfDeleted(ctx context.Context, users UserLookup, userID string) error {
	_, err := users.GetDeletionTombstone(ctx, userID)
	switch {
	case err == nil:
		return ErrAccountDeleted
	case errors.Is(err, storage.ErrNotFound):
		return nil
	default:
		return fmt.Errorf("check deletion tombstone: %w", err)
	}
}

// Gate checks tokens against User.AuthInvalidBefore.
type Gate struct {
	users UserLookup
}

// New creates a Gate; a nil lookup yields a nil Gate, on which Check is a no-op.
func New(users UserLookup) *Gate {
	if users == nil {
		return nil
	}
	return &Gate{users: users}
}

// Check refuses a token for userID issued at or before the user's
// AuthInvalidBefore; no token is exempt. A user with no record is refused only
// if DeleteUser left a tombstone: the AS also issues tokens for external
// identities (an OIDC-authenticated admin) with no wallet user record. An empty
// userID is not judged (pkg/middleware's RequireUser handles it). A token
// without a readable iat is refused once a cut-off exists.
func (g *Gate) Check(ctx context.Context, userID string, issuedAt time.Time) error {
	if g == nil || userID == "" {
		return nil
	}
	cutoff, err := g.users.GetAuthCutoff(ctx, domain.UserIDFromString(userID))
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return RefuseIfDeleted(ctx, g.users, userID)
		}
		return fmt.Errorf("check token authorization: %w", err)
	}
	if IssuedBeforeCutoff(issuedAt, cutoff) {
		return ErrRevoked
	}
	return nil
}

// IssuedBeforeCutoff is the single cut-off comparison. Both sides are in whole
// seconds (JWT iat precision), so a token minted in the cut-off's own second is
// refused; issuers mint in the next second. A zero cut-off refuses nothing.
func IssuedBeforeCutoff(issuedAt, cutoff time.Time) bool {
	if cutoff.IsZero() {
		return false
	}
	return issuedAt.Unix() <= cutoff.Unix()
}

type issuedAtKey struct{}
type subjectKey struct{}

// WithSubject is WithIssuedAt plus the token's user id, for RefuseNow.
func WithSubject(ctx context.Context, userID string, issuedAt time.Time) context.Context {
	return context.WithValue(WithIssuedAt(ctx, issuedAt), subjectKey{}, userID)
}

// SubjectFrom returns the user id recorded by WithSubject, or "".
func SubjectFrom(ctx context.Context) string {
	userID, _ := ctx.Value(subjectKey{}).(string)
	return userID
}

// RefuseNow judges the request's token against the user's current cut-off just
// before persisting, for a write that loads no user. It is not atomic with a
// revocation. A context without a token is not judged.
func RefuseNow(ctx context.Context, users UserLookup) error {
	userID, _ := ctx.Value(subjectKey{}).(string)
	if userID == "" || users == nil {
		return nil
	}
	cutoff, err := users.GetAuthCutoff(ctx, domain.UserIDFromString(userID))
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return RefuseIfDeleted(ctx, users, userID)
		}
		return fmt.Errorf("recheck token authorization: %w", err)
	}
	return RefuseLoaded(ctx, cutoff)
}

// IssuedAtFrom returns the iat recorded by WithIssuedAt or WithSubject; ok is
// false for a context without a token (an internal caller), which is not judged.
func IssuedAtFrom(ctx context.Context) (time.Time, bool) {
	t, ok := ctx.Value(issuedAtKey{}).(time.Time)
	return t, ok
}

// ErrWriteNotRolledBack is joined onto ErrRevoked by ConfirmWrite when the
// compensating delete failed too: the record remains until the next erasure or
// operator removal. The caller must treat the operation as failed.
var ErrWriteNotRolledBack = errors.New("write landed after authorization was revoked and could not be rolled back")

// rollbackTimeout bounds the compensating delete, which is detached from request
// cancellation so a hung-up client cannot leave the record behind.
const rollbackTimeout = 10 * time.Second

// ConfirmWrite is the post-write fence for a holder write in a store that cannot
// make the write conditional on the cut-off. Call it right after the write with
// a rollback that deletes exactly that record (by immutable id and write token,
// never the business key, which an erasure plus a fresh request can recreate).
// If the re-read shows the token refused, the record is rolled back and
// ErrRevoked returned; a failed re-read also rolls back (fail closed); a failed
// rollback adds ErrWriteNotRolledBack. A context without a token is not judged.
//
// Because every erasure advances the cut-off BEFORE it sweeps, no transaction is
// needed: for write W, re-read R, advance A and sweep S (A < S), either R sees A
// and W is rolled back, or W < R < A < S and S deletes W.
func ConfirmWrite(ctx context.Context, users UserLookup, rollback func(ctx context.Context) error) error {
	err := RefuseNow(ctx, users)
	if err == nil {
		return nil
	}
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), rollbackTimeout)
	defer cancel()
	if rerr := rollback(rctx); rerr != nil && !errors.Is(rerr, storage.ErrNotFound) {
		// Already gone (the erasure's sweep got it): the wanted outcome.
		return errors.Join(err, fmt.Errorf("%w: %w", ErrWriteNotRolledBack, rerr))
	}
	return err
}

// WithIssuedAt records the bearer token's iat on the context for RefuseLoaded.
func WithIssuedAt(ctx context.Context, issuedAt time.Time) context.Context {
	return context.WithValue(ctx, issuedAtKey{}, issuedAt)
}

// RefuseLoaded is the write-side gate. Check runs before the handler, so a
// request admitted just before a revocation could load the advanced cut-off and
// still put erased data back; a write that loads a user calls this with that
// cut-off. A context without a token iat is not judged.
func RefuseLoaded(ctx context.Context, cutoff time.Time) error {
	issuedAt, ok := ctx.Value(issuedAtKey{}).(time.Time)
	if !ok {
		return nil
	}
	if IssuedBeforeCutoff(issuedAt, cutoff) {
		return ErrRevoked
	}
	return nil
}

// payloadOf decodes the payload segment of a compact JWS.
func payloadOf(raw string) ([]byte, bool) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, false
	}
	return payload, true
}

// IssuedAt reads the iat claim out of a compact JWS without verifying it:
// callers must have verified the token already. The zero time means "no iat".
func IssuedAt(raw string) time.Time {
	payload, ok := payloadOf(raw)
	if !ok {
		return time.Time{}
	}
	var claims struct {
		IAT json.Number `json:"iat"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil || claims.IAT == "" {
		return time.Time{}
	}
	f, err := claims.IAT.Float64()
	if err != nil {
		return time.Time{}
	}
	return time.Unix(int64(f), 0)
}

// IssuedAtFromClaims reads iat from already-parsed map claims.
func IssuedAtFromClaims(claims jwt.MapClaims) time.Time {
	switch v := claims["iat"].(type) {
	case float64:
		return time.Unix(int64(v), 0)
	case int64:
		return time.Unix(v, 0)
	}
	return time.Time{}
}
