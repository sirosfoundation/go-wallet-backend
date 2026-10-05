// Package tokengate refuses bearer tokens that were issued before a user's
// authorization was cut off by a wallet lifecycle event (SID-AUTH-06).
//
// Revoking a wallet instance drops the user's live sessions,
// but a stateless bearer token that was already issued stays valid until it
// expires - up to a day for legacy HMAC tokens, longer for refresh tokens.
// The lifecycle service therefore records User.AuthInvalidBefore, and every
// place that accepts a token for a user consults Gate.Check with the token's
// iat: a token issued at or before that instant is refused.
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

// ErrRevoked is returned for a token issued before the user's authorization
// was cut off.
var ErrRevoked = errors.New("token issued before the user's authorization was revoked")

// UserLookup is the subset of storage.UserStore the gate needs: a narrow
// read of the one auth field, not the whole user record, and the deletion
// tombstone that stands in for the record once the account is gone.
type UserLookup interface {
	GetAuthCutoff(ctx context.Context, id domain.UserID) (time.Time, error)
	GetDeletionTombstone(ctx context.Context, userID string) (*domain.DeletionTombstone, error)
}

// ErrAccountDeleted is what a token for a deleted account is refused with. It
// wraps ErrRevoked, so every caller that already maps ErrRevoked to a refusal
// treats it the same way.
var ErrAccountDeleted = fmt.Errorf("%w: the account was deleted", ErrRevoked)

// RefuseIfDeleted decides what a user the store has no record of is. A
// deleted account leaves a tombstone (UserService.DeleteUser writes it before
// it removes the record) and its tokens are refused, whenever issued. A user
// with neither record nor tombstone is an external identity (see Check) and is
// not judged. A failed tombstone read fails closed.
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

// New creates a Gate over the given user lookup. A nil lookup yields a nil
// Gate, on which Check is a no-op, so callers can wire it optionally.
func New(users UserLookup) *Gate {
	if users == nil {
		return nil
	}
	return &Gate{users: users}
}

// Check refuses a token for userID that was issued at or before the user's
// AuthInvalidBefore. No token is exempt: a lifecycle change is a provider
// action and logging out everywhere is meant to include the session that
// asked for it.
//
// A user the store has no record of is refused when DeleteUser left a
// deletion tombstone for it (ErrAccountDeleted), whenever the token was
// issued: deleting a user removes the record that carries the cut-off, and
// the tombstone is what keeps that user's still-valid tokens from passing.
// A user with no record and no tombstone passes. That is deliberate and cannot
// be tightened here: the AS also issues tokens whose subject is an external
// identity that has no wallet user record (an OIDC-authenticated admin, whose
// UserID is the IdP's sub), and refusing "no record" would lock all of them
// out. Such a token is never a deleted wallet user's, since every deletion
// writes the tombstone first.
//
// An empty userID (anonymous token) is not judged here: Check only
// enforces lifecycle state. Keeping anonymous tokens off wallet-scoped routes
// is the routing layer's job (pkg/middleware, RequireUser). A token without a
// readable iat is refused once a cut-off exists, since it cannot prove it
// postdates the cut-off.
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

// IssuedBeforeCutoff is the one comparison behind every cut-off decision.
// JWT iat has whole-second precision while the cut-off is recorded with the
// store's precision, so both are compared as whole seconds: a token is
// refused when its iat second is not after the cut-off second. A token
// minted in the same second as the cut-off is therefore refused too (it
// cannot prove it postdates the cut-off); issuers avoid that by minting
// again in the next second, see WebAuthnService.mintAccessToken. A zero
// cut-off refuses nothing; a zero iat is refused once a cut-off exists.
func IssuedBeforeCutoff(issuedAt, cutoff time.Time) bool {
	if cutoff.IsZero() {
		return false
	}
	return issuedAt.Unix() <= cutoff.Unix()
}

type issuedAtKey struct{}
type subjectKey struct{}

// WithSubject is WithIssuedAt plus the token's user id, for writes that have no
// user record in hand (stored credentials and presentations are keyed by holder
// DID) and so cannot use RefuseLoaded. They call RefuseNow instead.
func WithSubject(ctx context.Context, userID string, issuedAt time.Time) context.Context {
	return context.WithValue(WithIssuedAt(ctx, issuedAt), subjectKey{}, userID)
}

// RefuseNow reads the token's user cut-off at the mutation boundary and judges
// the request's token against it. It is the recheck for a write that loads no
// user: it cannot make the write atomic with a revocation, but it takes the
// decision immediately before persisting instead of at request admission. A
// context without a token is not judged. A user the store has no record of is
// refused if it has a deletion tombstone, and otherwise not judged (see
// Gate.Check).
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

// IssuedAtFrom returns the iat of the bearer token that authenticated the
// request, as recorded by WithIssuedAt or WithSubject. ok is false for a
// context without a token (an internal caller), which is not judged.
func IssuedAtFrom(ctx context.Context) (time.Time, bool) {
	t, ok := ctx.Value(issuedAtKey{}).(time.Time)
	return t, ok
}

// WithIssuedAt records, on the request context, the iat of the bearer token
// that authenticated the request. The middlewares call it once the token has
// passed Gate.Check, so that a write further down can judge the same token
// against the record it loads (see RefuseLoaded).
func WithIssuedAt(ctx context.Context, issuedAt time.Time) context.Context {
	return context.WithValue(ctx, issuedAtKey{}, issuedAt)
}

// RefuseLoaded is the write-side half of the gate. Gate.Check runs once, before
// the handler, so a request that passed it with a token issued just before a
// revocation can still reach a write after the revocation has erased the
// wallet: it then loads the fresh user record - which carries the advanced
// cut-off and write fence, so the store accepts it - and puts erased data
// back. A write that loads a user therefore calls RefuseLoaded with the
// cut-off of the record it loaded; the store's fence covers the rest, since a
// cut-off landing after the load makes the write itself fail.
//
// A context without a token iat (an internal caller, a login flow that has no
// bearer token yet) is not judged.
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

// IssuedAt reads the iat claim out of a compact JWS/JWT without verifying
// it. Callers must have verified the token already (go-tokenauth surfaces
// no iat in its result); this only decodes the payload segment, it performs
// no signature or claim validation of its own. The zero time means "no iat".
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
