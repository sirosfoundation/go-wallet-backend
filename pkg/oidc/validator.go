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

	// JWKSMaxRetries is the maximum number of fetch attempts for transient failures.
	// Retries use exponential backoff starting at 500ms. (default: 3)
	JWKSMaxRetries int

	// JWKSCircuitBreakerThreshold is the number of consecutive fetch failures
	// after which the circuit is opened and fetches are skipped until the
	// cooldown period elapses. (default: 5)
	JWKSCircuitBreakerThreshold int

	// JWKSCircuitBreakerCooldown is how long the circuit stays open before a
	// probe attempt is allowed. (default: 30s)
	JWKSCircuitBreakerCooldown time.Duration
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

	// Base backoff for JWKS retry; kept internal so tests can run quickly.
	jwksRetryBaseDelay time.Duration

	// JWKS cache
	jwksMu      sync.RWMutex
	jwksCache   *JWKS
	jwksFetched time.Time

	// JWKS circuit breaker (guarded by jwksMu)
	jwksFailures    int       // consecutive fetch failures
	jwksCircuitOpen time.Time // zero = circuit closed; non-zero = when circuit was opened

	// Discovery cache
	discoveryMu      sync.RWMutex
	discoveryCache   *DiscoveryDocument
	discoveryFetched time.Time
}

// NewValidator creates a new OIDC token validator.
// If httpClient is nil, a default client with 10s timeout is used.
func NewValidator(config ValidatorConfig, httpClient *http.Client, logger *zap.Logger) *Validator {
	if config.ClockSkew <= 0 {
		config.ClockSkew = time.Minute
	}
	if config.JWKSCacheTTL <= 0 {
		config.JWKSCacheTTL = time.Hour
	}
	if config.JWKSMaxRetries <= 0 {
		config.JWKSMaxRetries = 3
	}
	if config.JWKSCircuitBreakerThreshold <= 0 {
		config.JWKSCircuitBreakerThreshold = 5
	}
	if config.JWKSCircuitBreakerCooldown <= 0 {
		config.JWKSCircuitBreakerCooldown = 30 * time.Second
	}
	if httpClient == nil {
		httpClient = &http.Client{
			Timeout: 10 * time.Second,
		}
	}

	return &Validator{
		config:             config,
		httpClient:         httpClient,
		logger:             logger.Named("oidc"),
		jwksRetryBaseDelay: 500 * time.Millisecond,
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
		jwt.WithValidMethods([]string{"RS256", "RS384", "RS512", "ES256", "ES384", "ES512"}),
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

// getJWKS retrieves the JWKS, using cache if valid.
//
// Fetch failures are handled with exponential backoff retry (up to JWKSMaxRetries).
// A circuit breaker opens after JWKSCircuitBreakerThreshold consecutive failures,
// skipping further fetch attempts for JWKSCircuitBreakerCooldown to protect the IdP.
// When a fetch fails but a stale cached JWKS exists, it is returned as a fallback
// rather than failing the request outright (the cache may still have the needed key).
func (v *Validator) getJWKS(ctx context.Context) (*JWKS, error) {
	v.jwksMu.RLock()
	cached := v.jwksCache
	circuitOpenedAt := v.jwksCircuitOpen
	fresh := cached != nil && time.Since(v.jwksFetched) < v.config.JWKSCacheTTL
	circuitOpen := !circuitOpenedAt.IsZero() &&
		time.Since(circuitOpenedAt) < v.config.JWKSCircuitBreakerCooldown
	v.jwksMu.RUnlock()

	if fresh {
		return cached, nil
	}

	// Circuit is open — skip the fetch and return stale cache if available.
	if circuitOpen {
		if cached != nil {
			v.logger.Warn("JWKS circuit open, returning stale cache",
				zap.Duration("cooldown_remaining", v.config.JWKSCircuitBreakerCooldown-time.Since(circuitOpenedAt)))
			return cached, nil
		}
		return nil, fmt.Errorf("%w: circuit open, no cached JWKS available", ErrJWKSFetchFailed)
	}

	// Need to fetch (fresh cache miss or circuit just closed for probe).
	jwksURI := v.config.JWKSURI
	if jwksURI == "" {
		discovery, err := v.getDiscovery(ctx)
		if err != nil {
			if cached != nil {
				v.logger.Warn("JWKS discovery failed, returning stale cache", zap.Error(err))
				return cached, nil
			}
			return nil, fmt.Errorf("failed to discover JWKS URI: %w", err)
		}
		jwksURI = discovery.JWKSURI
	}

	jwks, err := v.fetchJWKSWithRetry(ctx, jwksURI)
	if err != nil {
		v.jwksMu.Lock()
		v.jwksFailures++
		failures := v.jwksFailures
		if v.jwksFailures >= v.config.JWKSCircuitBreakerThreshold {
			v.jwksCircuitOpen = time.Now()
			v.logger.Warn("JWKS circuit breaker opened",
				zap.Int("consecutive_failures", failures),
				zap.Duration("cooldown", v.config.JWKSCircuitBreakerCooldown))
		}
		stale := v.jwksCache
		v.jwksMu.Unlock()

		if stale != nil {
			v.logger.Warn("JWKS fetch failed, returning stale cache",
				zap.Error(err),
				zap.Int("consecutive_failures", failures))
			return stale, nil
		}
		return nil, err
	}

	v.jwksMu.Lock()
	v.jwksCache = jwks
	v.jwksFetched = time.Now()
	v.jwksFailures = 0
	v.jwksCircuitOpen = time.Time{} // close circuit on success
	v.jwksMu.Unlock()

	return jwks, nil
}

// fetchJWKSWithRetry calls fetchJWKS with exponential backoff.
// Only transient errors (network failures, 5xx responses) are retried.
// 4xx responses and parse errors are returned immediately.
func (v *Validator) fetchJWKSWithRetry(ctx context.Context, jwksURI string) (*JWKS, error) {
	var lastErr error
	backoff := v.jwksRetryBaseDelay
	for attempt := 0; attempt < v.config.JWKSMaxRetries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(backoff):
			}
			backoff *= 2
		}

		jwks, err := v.fetchJWKS(ctx, jwksURI)
		if err == nil {
			if attempt > 0 {
				v.logger.Info("JWKS fetch succeeded after retry",
					zap.Int("attempt", attempt+1))
			}
			return jwks, nil
		}

		lastErr = err
		// Retry only transient errors (transport and 5xx responses).
		if !isRetryableJWKSError(err) {
			return nil, err
		}
		v.logger.Warn("JWKS fetch failed, retrying",
			zap.Int("attempt", attempt+1),
			zap.Int("max_retries", v.config.JWKSMaxRetries),
			zap.Duration("backoff", backoff),
			zap.Error(err))
	}
	return nil, fmt.Errorf("%w after %d attempts: %v", ErrJWKSFetchFailed, v.config.JWKSMaxRetries, lastErr)
}

// isRetryableJWKSError returns true only for transient transport errors and 5xx HTTP responses.
func isRetryableJWKSError(err error) bool {
	var transportErr *jwksTransportError
	if errors.As(err, &transportErr) {
		return true
	}

	var statusErr *jwksHTTPStatusError
	if errors.As(err, &statusErr) {
		return statusErr.StatusCode >= http.StatusInternalServerError
	}

	return false
}

// invalidateJWKSCache marks the JWKS cache stale so next lookup refreshes,
// while keeping keys available as stale fallback during transient outages.
func (v *Validator) invalidateJWKSCache() {
	v.jwksMu.Lock()
	v.jwksFetched = time.Time{}
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
