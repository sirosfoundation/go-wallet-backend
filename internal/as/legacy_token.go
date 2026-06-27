package as

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// LegacyTokenIssuer issues HMAC-signed all-in-one tokens for legacy clients.
// These tokens combine session identity and access authorization in a single JWT,
// matching the current format that wallet-frontend expects.
type LegacyTokenIssuer struct {
	secret []byte
	issuer string
	ttl    time.Duration
}

// NewLegacyTokenIssuer creates a legacy token issuer.
func NewLegacyTokenIssuer(secret []byte, issuer string, ttl time.Duration) *LegacyTokenIssuer {
	return &LegacyTokenIssuer{
		secret: secret,
		issuer: issuer,
		ttl:    ttl,
	}
}

// LegacyTokenClaims are the claims in a legacy all-in-one token.
// This matches the current go-wallet-backend token format.
type LegacyTokenClaims struct {
	jwt.RegisteredClaims
	UserID   string `json:"user_id"`
	DID      string `json:"did,omitempty"`
	TenantID string `json:"tenant_id"`
}

// Issue creates an HMAC-signed legacy token.
func (lti *LegacyTokenIssuer) Issue(userID, did, tenantID, rpID string) (string, error) {
	jti, err := generateLegacyJTI()
	if err != nil {
		return "", err
	}

	now := time.Now()
	claims := LegacyTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        jti,
			Issuer:    lti.issuer,
			Subject:   userID,
			Audience:  jwt.ClaimStrings{rpID},
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(lti.ttl)),
		},
		UserID:   userID,
		DID:      did,
		TenantID: tenantID,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(lti.secret)
	if err != nil {
		return "", fmt.Errorf("as: failed to sign legacy token: %w", err)
	}

	return signed, nil
}

// IssueRefresh creates an HMAC-signed legacy refresh token.
func (lti *LegacyTokenIssuer) IssueRefresh(userID, did, tenantID, rpID string, refreshTTL time.Duration) (string, error) {
	jti, err := generateLegacyJTI()
	if err != nil {
		return "", err
	}

	now := time.Now()
	claims := jwt.MapClaims{
		"jti":       jti,
		"iss":       lti.issuer,
		"sub":       userID,
		"aud":       rpID,
		"iat":       now.Unix(),
		"nbf":       now.Unix(),
		"exp":       now.Add(refreshTTL).Unix(),
		"user_id":   userID,
		"did":       did,
		"tenant_id": tenantID,
		"type":      "refresh",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(lti.secret)
	if err != nil {
		return "", fmt.Errorf("as: failed to sign legacy refresh token: %w", err)
	}

	return signed, nil
}

// Validate parses and validates a legacy HMAC token, returning the claims.
func (lti *LegacyTokenIssuer) Validate(raw string, audiences ...string) (*LegacyTokenClaims, error) {
	opts := []jwt.ParserOption{
		jwt.WithLeeway(5 * time.Second),
		jwt.WithIssuer(lti.issuer),
	}
	for _, aud := range audiences {
		opts = append(opts, jwt.WithAudience(aud))
	}

	token, err := jwt.ParseWithClaims(raw, &LegacyTokenClaims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return lti.secret, nil
	}, opts...)
	if err != nil {
		return nil, fmt.Errorf("as: legacy token validation failed: %w", err)
	}

	claims, ok := token.Claims.(*LegacyTokenClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("as: invalid legacy token claims")
	}

	return claims, nil
}

func generateLegacyJTI() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("as: failed to generate JTI: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
