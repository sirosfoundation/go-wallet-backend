package as

import (
	"fmt"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/uuid"
)

// TAC represents token access control permissions as a string of permission characters.
type TAC string

const (
	TACRead     byte = 'r' // read access on a per-object basis
	TACWrite    byte = 'w' // write access on a per-object basis
	TACList     byte = 'l' // read access on collections/indexes
	TACInsert   byte = 'i' // create new entries
	TACDelete   byte = 'd' // remove objects
	TACDelegate byte = 'k' // issue delegation tokens
	TACAdmin    byte = 'a' // full administrative rights
)

// validTACChars is the set of valid TAC permission characters.
var validTACChars = map[byte]bool{
	TACRead: true, TACWrite: true, TACList: true,
	TACInsert: true, TACDelete: true, TACDelegate: true,
	TACAdmin: true,
}

// Has returns true if the TAC contains the given permission character.
func (t TAC) Has(perm byte) bool {
	for i := range t {
		if t[i] == perm {
			return true
		}
	}
	return false
}

// HasAll returns true if the TAC contains all characters in perms.
func (t TAC) HasAll(perms string) bool {
	for i := range perms {
		if !t.Has(perms[i]) {
			return false
		}
	}
	return true
}

// IsSubsetOf returns true if every permission in t is also in other.
func (t TAC) IsSubsetOf(other TAC) bool {
	for i := range t {
		if !other.Has(t[i]) {
			return false
		}
	}
	return true
}

// Validate returns an error if the TAC contains invalid characters.
func (t TAC) Validate() error {
	for i := range t {
		if !validTACChars[t[i]] {
			return fmt.Errorf("invalid tac character %q at position %d", t[i], i)
		}
	}
	return nil
}

// AccessTokenClaims represents the claims in an AS-issued access token.
type AccessTokenClaims struct {
	jwt.Claims

	// TenantID is the tenant scope. "*" means cross-tenant.
	TenantID string `json:"tenant_id"`

	// TAC is the token access control permission set.
	TAC TAC `json:"tac"`

	// ACR is the authentication context class reference.
	ACR string `json:"acr,omitempty"`
}

// TokenRequest represents a client's request for an access token.
type TokenRequest struct {
	Audience string `json:"aud"`
	TenantID string `json:"tenant_id,omitempty"`
	TAC      string `json:"tac,omitempty"`
}

// TokenIssuer issues signed access tokens.
type TokenIssuer struct {
	km     *KeyManager
	issuer string
	ttl    func(audience string) time.Duration
}

// NewTokenIssuer creates a TokenIssuer.
func NewTokenIssuer(km *KeyManager, issuer string, ttlFunc func(audience string) time.Duration) *TokenIssuer {
	return &TokenIssuer{
		km:     km,
		issuer: issuer,
		ttl:    ttlFunc,
	}
}

// Issue creates and signs an access token with the given claims.
func (ti *TokenIssuer) Issue(sub, audience, tenantID string, tac TAC, acr string) (string, error) {
	sk := ti.km.ActiveKey()
	if sk == nil {
		return "", fmt.Errorf("as: no active signing key")
	}

	now := time.Now()
	ttl := ti.ttl(audience)
	jti := uuid.New().String()

	claims := AccessTokenClaims{
		Claims: jwt.Claims{
			ID:        jti,
			Issuer:    ti.issuer,
			Subject:   sub,
			Audience:  jwt.Audience{audience},
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now.Add(-time.Second)),
			Expiry:    jwt.NewNumericDate(now.Add(ttl)),
		},
		TenantID: tenantID,
		TAC:      tac,
		ACR:      acr,
	}

	sig, err := jose.NewSigner(
		jose.SigningKey{
			Algorithm: sk.Algorithm,
			Key:       sk.Signer,
		},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", sk.Kid),
	)
	if err != nil {
		return "", fmt.Errorf("as: failed to create signer: %w", err)
	}

	token, err := jwt.Signed(sig).Claims(claims).Serialize()
	if err != nil {
		return "", fmt.Errorf("as: failed to sign token: %w", err)
	}

	return token, nil
}

// ParseAndVerify parses a JWT string and verifies its signature against the KeyManager's JWKS.
// Returns the validated claims or an error.
func (ti *TokenIssuer) ParseAndVerify(raw string, audiences []string) (*AccessTokenClaims, error) {
	tok, err := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{jose.ES256, jose.ES384, jose.EdDSA})
	if err != nil {
		return nil, fmt.Errorf("as: failed to parse token: %w", err)
	}

	jwks := ti.km.JWKS()
	var claims AccessTokenClaims
	if err := tok.Claims(jwks, &claims); err != nil {
		return nil, fmt.Errorf("as: failed to verify token: %w", err)
	}

	expected := jwt.Expected{
		Issuer: ti.issuer,
		Time:   time.Now(),
	}
	if len(audiences) > 0 {
		expected.AnyAudience = audiences
	}

	if err := claims.ValidateWithLeeway(expected, 5*time.Second); err != nil {
		return nil, fmt.Errorf("as: token validation failed: %w", err)
	}

	return &claims, nil
}
