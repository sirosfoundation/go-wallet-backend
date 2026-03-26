// Package oidc provides OpenID Connect token validation for OIDC gate middleware.
package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"
)

var (
	// ErrTokenExpired indicates the token has expired
	ErrTokenExpired = errors.New("token has expired")
	// ErrInvalidSignature indicates the token signature is invalid
	ErrInvalidSignature = errors.New("invalid token signature")
	// ErrInvalidIssuer indicates the issuer claim doesn't match expected
	ErrInvalidIssuer = errors.New("invalid issuer")
	// ErrInvalidAudience indicates the audience claim doesn't match expected
	ErrInvalidAudience = errors.New("invalid audience")
	// ErrMissingClaim indicates a required claim is missing
	ErrMissingClaim = errors.New("missing required claim")
	// ErrClaimMismatch indicates a claim value doesn't match expected
	ErrClaimMismatch = errors.New("claim value mismatch")
	// ErrJWKSFetchFailed indicates JWKS fetching failed
	ErrJWKSFetchFailed = errors.New("failed to fetch JWKS")
	// ErrKeyNotFound indicates no matching key was found in JWKS
	ErrKeyNotFound = errors.New("key not found in JWKS")
)

// ValidatorConfig configures the OIDC token validator
type ValidatorConfig struct {
	// Issuer is the expected token issuer (required)
	Issuer string

	// Audience is the expected audience claim (required)
	Audience string

	// JWKSURI is the JWKS endpoint; if empty, discovered from issuer
	JWKSURI string

	// RequiredClaims specifies claims that must be present and match
	RequiredClaims map[string]interface{}

	// ClockSkew allows some leeway for clock differences (default: 1 minute)
	ClockSkew time.Duration

	// JWKSCacheTTL is how long to cache JWKS (default: 1 hour)
	JWKSCacheTTL time.Duration
}

// ValidationResult contains the result of token validation
type ValidationResult struct {
	// Subject is the token's sub claim
	Subject string

	// Issuer is the token's iss claim
	Issuer string

	// Claims contains all token claims
	Claims jwt.MapClaims

	// ValidatedAt is when the token was validated
	ValidatedAt time.Time
}

// Validator validates OIDC ID tokens
type Validator struct {
	config     ValidatorConfig
	httpClient *http.Client
	logger     *zap.Logger

	// JWKS cache
	jwksMu      sync.RWMutex
	jwksCache   *JWKS
	jwksFetched time.Time

	// Discovery cache
	discoveryMu      sync.RWMutex
	discoveryCache   *DiscoveryDocument
	discoveryFetched time.Time
}

// NewValidator creates a new OIDC token validator.
// If httpClient is nil, a default client with 10s timeout is used.
func NewValidator(config ValidatorConfig, httpClient *http.Client, logger *zap.Logger) *Validator {
	if config.ClockSkew == 0 {
		config.ClockSkew = time.Minute
	}
	if config.JWKSCacheTTL == 0 {
		config.JWKSCacheTTL = time.Hour
	}
	if httpClient == nil {
		httpClient = &http.Client{
			Timeout: 10 * time.Second,
		}
	}

	return &Validator{
		config:     config,
		httpClient: httpClient,
		logger:     logger.Named("oidc"),
	}
}

// Validate validates an ID token and returns the validation result
func (v *Validator) Validate(ctx context.Context, tokenString string) (*ValidationResult, error) {
	// Parse the token without verification first to get the key ID
	token, _, err := jwt.NewParser().ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	// Get the key ID from the header
	kid, _ := token.Header["kid"].(string)
	if kid == "" {
		return nil, errors.New("token missing kid header")
	}

	// Get the signing key from JWKS
	key, err := v.getSigningKey(ctx, kid)
	if err != nil {
		return nil, fmt.Errorf("failed to get signing key: %w", err)
	}

	// Parse and validate the token with the key
	validToken, err := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
		return key, nil
	},
		jwt.WithIssuer(v.config.Issuer),
		jwt.WithAudience(v.config.Audience),
		jwt.WithLeeway(v.config.ClockSkew),
		jwt.WithIssuedAt(),
		jwt.WithExpirationRequired(),
	)

	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrTokenExpired
		}
		if errors.Is(err, jwt.ErrTokenSignatureInvalid) {
			return nil, ErrInvalidSignature
		}
		if errors.Is(err, jwt.ErrTokenInvalidIssuer) {
			return nil, ErrInvalidIssuer
		}
		if errors.Is(err, jwt.ErrTokenInvalidAudience) {
			return nil, ErrInvalidAudience
		}
		return nil, fmt.Errorf("token validation failed: %w", err)
	}

	claims, ok := validToken.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("invalid claims type")
	}

	// Validate required claims
	if err := v.validateRequiredClaims(claims); err != nil {
		return nil, err
	}

	// Extract subject
	sub, _ := claims["sub"].(string)
	if sub == "" {
		return nil, fmt.Errorf("%w: sub", ErrMissingClaim)
	}

	iss, _ := claims["iss"].(string)

	return &ValidationResult{
		Subject:     sub,
		Issuer:      iss,
		Claims:      claims,
		ValidatedAt: time.Now(),
	}, nil
}

// validateRequiredClaims checks that all required claims are present and match
func (v *Validator) validateRequiredClaims(claims jwt.MapClaims) error {
	for key, expected := range v.config.RequiredClaims {
		actual, exists := claims[key]
		if !exists {
			return fmt.Errorf("%w: %s", ErrMissingClaim, key)
		}

		if !claimsEqual(expected, actual) {
			return fmt.Errorf("%w: %s (expected %v, got %v)", ErrClaimMismatch, key, expected, actual)
		}
	}
	return nil
}

// claimsEqual compares two claim values for equality
func claimsEqual(expected, actual interface{}) bool {
	// Handle numeric comparison (JSON numbers can be float64)
	switch e := expected.(type) {
	case bool:
		a, ok := actual.(bool)
		return ok && e == a
	case string:
		a, ok := actual.(string)
		return ok && e == a
	case float64:
		a, ok := actual.(float64)
		return ok && e == a
	case int:
		a, ok := actual.(float64) // JSON numbers are float64
		return ok && float64(e) == a
	case []interface{}:
		// For array claims, check if expected values are present
		a, ok := actual.([]interface{})
		if !ok {
			return false
		}
		for _, ev := range e {
			found := false
			for _, av := range a {
				if claimsEqual(ev, av) {
					found = true
					break
				}
			}
			if !found {
				return false
			}
		}
		return true
	default:
		// Fallback to JSON comparison
		ej, _ := json.Marshal(expected)
		aj, _ := json.Marshal(actual)
		return string(ej) == string(aj)
	}
}

// getSigningKey retrieves the signing key for the given key ID
func (v *Validator) getSigningKey(ctx context.Context, kid string) (interface{}, error) {
	jwks, err := v.getJWKS(ctx)
	if err != nil {
		return nil, err
	}

	key := jwks.GetKey(kid)
	if key == nil {
		// Key not found, try refreshing JWKS (key rotation)
		v.invalidateJWKSCache()
		jwks, err = v.getJWKS(ctx)
		if err != nil {
			return nil, err
		}
		key = jwks.GetKey(kid)
		if key == nil {
			return nil, fmt.Errorf("%w: kid=%s", ErrKeyNotFound, kid)
		}
	}

	return key.PublicKey()
}

// getJWKS retrieves the JWKS, using cache if valid
func (v *Validator) getJWKS(ctx context.Context) (*JWKS, error) {
	v.jwksMu.RLock()
	if v.jwksCache != nil && time.Since(v.jwksFetched) < v.config.JWKSCacheTTL {
		jwks := v.jwksCache
		v.jwksMu.RUnlock()
		return jwks, nil
	}
	v.jwksMu.RUnlock()

	// Need to fetch JWKS
	jwksURI := v.config.JWKSURI
	if jwksURI == "" {
		// Discover JWKS URI from issuer
		discovery, err := v.getDiscovery(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to discover JWKS URI: %w", err)
		}
		jwksURI = discovery.JWKSURI
	}

	jwks, err := v.fetchJWKS(ctx, jwksURI)
	if err != nil {
		return nil, err
	}

	v.jwksMu.Lock()
	v.jwksCache = jwks
	v.jwksFetched = time.Now()
	v.jwksMu.Unlock()

	return jwks, nil
}

// invalidateJWKSCache clears the JWKS cache
func (v *Validator) invalidateJWKSCache() {
	v.jwksMu.Lock()
	v.jwksCache = nil
	v.jwksMu.Unlock()
}

// getDiscovery retrieves the OIDC discovery document
func (v *Validator) getDiscovery(ctx context.Context) (*DiscoveryDocument, error) {
	v.discoveryMu.RLock()
	if v.discoveryCache != nil && time.Since(v.discoveryFetched) < 24*time.Hour {
		discovery := v.discoveryCache
		v.discoveryMu.RUnlock()
		return discovery, nil
	}
	v.discoveryMu.RUnlock()

	discovery, err := v.fetchDiscovery(ctx)
	if err != nil {
		return nil, err
	}

	v.discoveryMu.Lock()
	v.discoveryCache = discovery
	v.discoveryFetched = time.Now()
	v.discoveryMu.Unlock()

	return discovery, nil
}
