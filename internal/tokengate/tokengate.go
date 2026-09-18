// Package tokengate refuses bearer tokens that were issued before a user's
// authorization was cut off by a wallet lifecycle event (SID-AUTH-06).
//
// Suspending or revoking a wallet instance drops the user's live sessions,
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
// read of the one auth field, not the whole user record.
type UserLookup interface {
	GetAuthCutoff(ctx context.Context, id domain.UserID) (time.Time, error)
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
// asked for it. An empty userID (anonymous token) always passes, and so does
// a user the store does not know: the gate only enforces lifecycle cut-offs,
// it is not an existence check (handlers do that where it matters). A token
// without a readable iat is refused once a cut-off exists, since it cannot
// prove it postdates the cut-off.
func (g *Gate) Check(ctx context.Context, userID string, issuedAt time.Time) error {
	if g == nil || userID == "" {
		return nil
	}
	cutoff, err := g.users.GetAuthCutoff(ctx, domain.UserIDFromString(userID))
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil
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
