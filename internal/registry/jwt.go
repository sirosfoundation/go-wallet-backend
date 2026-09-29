package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-tokenauth/claims"
	tokenvalidator "github.com/sirosfoundation/go-tokenauth/validator"
)

// LogLegacyStatus logs once at startup whether HMAC tokens are accepted.
func (j JWTConfig) LogLegacyStatus(logger *zap.Logger) {
	if j.legacyEnabled() {
		logger.Info("legacy HMAC JWT validation is enabled")
		return
	}
	logger.Info("legacy HMAC JWT validation is disabled",
		zap.Bool("jwks_configured", j.JWKSURL != ""), zap.Bool("as_url_configured", j.ASURL != ""))
}

// JWTOption customizes JWTMiddleware.
type JWTOption func(*jwtOptions)

type jwtOptions struct {
	client         *http.Client
	allowPlaintext bool
}

// WithJWTAllowPlaintext permits http:// for jwks_url / as_url / the discovered
// jwks_uri (local development; pass http_client.AllowsPlaintext()). Default:
// HTTPS only.
func WithJWTAllowPlaintext(allow bool) JWTOption {
	return func(o *jwtOptions) { o.allowPlaintext = allow }
}

// DefaultRegistryAudience is the "aud" the registry requires of new-style
// (ES256) tokens when jwt.audiences is not set: the audience the AS issues
// for registry access (as.audiences documents "wallet-registry").
const DefaultRegistryAudience = "wallet-registry"

// effectiveAudiences returns jwt.audiences or the registry default; the
// registry must never accept AS tokens minted for other services.
func (j JWTConfig) effectiveAudiences() []string {
	if len(j.Audiences) > 0 {
		return j.Audiences
	}
	return []string{DefaultRegistryAudience}
}

// WithJWTHTTPClient sets the (SSRF-guarded) HTTP client used for AS metadata
// discovery. Defaults to a 5s-timeout client that does not follow redirects.
func WithJWTHTTPClient(c *http.Client) JWTOption {
	return func(o *jwtOptions) { o.client = c }
}

const (
	asMetadataPath   = "/.well-known/oauth-authorization-server"
	discoveryBackoff = time.Second
	discoveryMaxWait = 5 * time.Minute
)

// sessionValidator validates session tokens: HMAC (legacy) tokens against
// jwt.secret while legacy is enabled, ES256/ES384/EdDSA tokens against the AS
// JWKS. The JWKS side is either configured explicitly (jwks_url) or
// discovered from the AS metadata (as_url); until it is available ES256
// tokens are refused (fail closed) and discovery is retried with backoff.
type sessionValidator struct {
	cfg            JWTConfig
	client         *http.Client
	logger         *zap.Logger
	allowPlaintext bool

	legacyOnly *tokenvalidator.Validator // no JWKS: HMAC only, ES256 refused

	mu       sync.Mutex
	es       *tokenvalidator.Validator // set once JWKS + issuer are known
	failures int
	nextTry  time.Time
	backoff  time.Duration
}

func newSessionValidator(cfg JWTConfig, client *http.Client, logger *zap.Logger, allowPlaintext bool) *sessionValidator {
	if client == nil {
		client = &http.Client{
			Timeout:       5 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}
	}
	sv := &sessionValidator{cfg: cfg, client: client, logger: logger, allowPlaintext: allowPlaintext, backoff: discoveryBackoff}
	sv.legacyOnly = sv.build("", "")
	if cfg.JWKSURL != "" {
		iss := cfg.ASIssuer
		if iss == "" {
			iss = cfg.Issuer
		}
		if err := checkScheme(cfg.JWKSURL, allowPlaintext); err != nil {
			// Fail closed: no JWKS, so ES256 tokens are refused.
			logger.Error("jwt.jwks_url rejected; ES256 tokens will be refused", zap.Error(err))
		} else {
			sv.setES(cfg.JWKSURL, iss)
		}
	} else if cfg.ASURL != "" {
		go sv.discoverLoop(context.Background())
	}
	return sv
}

// build creates a validator. Audiences are deliberately not passed: go-tokenauth
// would also apply them to legacy HMAC tokens (aud = RP ID) and reject those;
// they are enforced for new-style tokens by the caller instead.
func (s *sessionValidator) build(jwksURL, issuer string) *tokenvalidator.Validator {
	return tokenvalidator.New(tokenvalidator.Config{
		JWKSURL: jwksURL,
		Issuer:  issuer,
		Legacy: tokenvalidator.LegacyConfig{
			// An empty secret must never enable HMAC (empty-key forgery).
			Enabled:    s.cfg.legacyEnabled(),
			HMACSecret: []byte(s.cfg.Secret),
			Issuers:    []string{s.cfg.Issuer},
		},
	})
}

func (s *sessionValidator) setES(jwksURL, issuer string) {
	v := s.build(jwksURL, issuer)
	v.Start(context.Background())
	s.mu.Lock()
	s.es = v
	s.mu.Unlock()
}

func (s *sessionValidator) current() *tokenvalidator.Validator {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.es != nil {
		return s.es
	}
	return s.legacyOnly
}

func (s *sessionValidator) ready() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.es != nil
}

// validate lazily retries discovery (backoff-gated) before validating.
func (s *sessionValidator) validate(ctx context.Context, raw string) (*claims.Result, error) {
	if s.cfg.JWKSURL == "" && s.cfg.ASURL != "" && !s.ready() {
		s.tryDiscover(ctx)
	}
	return s.current().Validate(ctx, raw)
}

func (s *sessionValidator) discoverLoop(ctx context.Context) {
	for !s.ready() {
		wait := s.tryDiscover(ctx)
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

// tryDiscover attempts discovery unless still inside the backoff window and
// returns how long to wait before the next attempt is allowed.
func (s *sessionValidator) tryDiscover(ctx context.Context) time.Duration {
	s.mu.Lock()
	if s.es != nil {
		s.mu.Unlock()
		return 0
	}
	if wait := time.Until(s.nextTry); wait > 0 {
		s.mu.Unlock()
		return wait
	}
	// Hold the lock across the fetch so concurrent requests do not stampede
	// the AS; the client timeout bounds it.
	defer s.mu.Unlock()
	issuer, jwks, err := discoverAS(ctx, s.client, s.cfg.ASURL, s.cfg.ASIssuer, s.allowPlaintext)
	if err != nil {
		s.failures++
		s.backoff *= 2
		if s.backoff > discoveryMaxWait || s.backoff <= 0 {
			s.backoff = discoveryMaxWait
		}
		s.nextTry = time.Now().Add(s.backoff)
		s.logger.Warn("AS metadata discovery failed; ES256 tokens are refused until it succeeds",
			zap.String("as_url", s.cfg.ASURL), zap.Error(err), zap.Duration("retry_in", s.backoff))
		return s.backoff
	}
	v := s.build(jwks, issuer)
	v.Start(context.Background())
	s.es = v
	s.logger.Info("AS metadata discovered", zap.String("issuer", issuer), zap.String("jwks_uri", jwks))
	return 0
}

// checkScheme requires https unless plaintext is explicitly allowed.
func checkScheme(raw string, allowPlaintext bool) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return fmt.Errorf("invalid URL %q", raw)
	}
	if u.Scheme == "https" || (u.Scheme == "http" && allowPlaintext) {
		return nil
	}
	return fmt.Errorf("URL %q must use https (http is only allowed with http_client.allow_http / allow_private_ips)", raw)
}

// discoverAS fetches asURL+/.well-known/oauth-authorization-server and returns
// the issuer to expect and the jwks_uri. The metadata issuer must match: the
// explicit override if given, and, when it is itself an http(s) URL, asURL
// (RFC 8414 / OIDC Discovery exact match); the jwks_uri must be same-origin
// with asURL.
func discoverAS(ctx context.Context, client *http.Client, asURL, issuerOverride string, allowPlaintext bool) (issuer, jwksURI string, err error) {
	base := strings.TrimRight(asURL, "/")
	baseURL, err := url.Parse(base)
	if err != nil || baseURL.Host == "" {
		return "", "", fmt.Errorf("invalid as_url")
	}
	if err := checkScheme(base, allowPlaintext); err != nil {
		return "", "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+asMetadataPath, nil)
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return "", "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("metadata endpoint returned HTTP %d", resp.StatusCode)
	}
	var md struct {
		Issuer  string `json:"issuer"`
		JWKSURI string `json:"jwks_uri"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&md); err != nil {
		return "", "", fmt.Errorf("invalid metadata: %w", err)
	}
	if md.Issuer == "" || md.JWKSURI == "" {
		return "", "", fmt.Errorf("metadata lacks issuer or jwks_uri")
	}
	if issuerOverride != "" && md.Issuer != issuerOverride {
		return "", "", fmt.Errorf("metadata issuer %q does not match jwt.as_issuer %q", md.Issuer, issuerOverride)
	}
	if iu, perr := url.Parse(md.Issuer); perr == nil && (iu.Scheme == "https" || iu.Scheme == "http") && iu.Host != "" {
		if strings.TrimRight(md.Issuer, "/") != base {
			return "", "", fmt.Errorf("metadata issuer %q does not match requested %q", md.Issuer, base)
		}
	}
	ju, err := url.Parse(md.JWKSURI)
	if err != nil || ju.Host == "" || ju.Scheme != baseURL.Scheme || ju.Host != baseURL.Host {
		return "", "", fmt.Errorf("metadata jwks_uri %q is not same-origin with as_url", md.JWKSURI)
	}
	if err := checkScheme(md.JWKSURI, allowPlaintext); err != nil {
		return "", "", err
	}
	return md.Issuer, md.JWKSURI, nil
}

// JWTMiddleware validates JWT tokens and sets authentication status.
// When present and valid, it also extracts tenant_id from claims and sets it in context.
// This enables per-tenant authorization for authenticated endpoints.
func JWTMiddleware(config JWTConfig, logger *zap.Logger, opts ...JWTOption) gin.HandlerFunc {
	var o jwtOptions
	for _, opt := range opts {
		opt(&o)
	}
	// Nothing can validate without a JWKS/AS URL or an HMAC secret; then no
	// validator (and no fetcher) is built and every token is rejected.
	auds := config.effectiveAudiences()
	var sv *sessionValidator
	if config.JWKSURL != "" || config.ASURL != "" || config.Secret != "" {
		sv = newSessionValidator(config, o.client, logger, o.allowPlaintext)
	}
	return func(c *gin.Context) {
		// Default to unauthenticated
		c.Set(string(AuthenticatedKey), false)

		reject := func(status int, errCode, message string) {
			if config.RequireAuth {
				c.JSON(status, gin.H{"error": errCode, "message": message})
				c.Abort()
				return
			}
			c.Next()
		}

		// Get Authorization header
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			reject(http.StatusUnauthorized, "unauthorized", "Authorization header required")
			return
		}

		// Parse Bearer token
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			reject(http.StatusUnauthorized, "unauthorized", "Invalid authorization header format")
			return
		}

		if sv == nil {
			logger.Debug("no JWKS/AS URL or JWT secret configured, rejecting token")
			reject(http.StatusUnauthorized, "unauthorized", "Authentication not configured")
			return
		}

		result, err := sv.validate(c.Request.Context(), parts[1])
		if err != nil {
			logger.Debug("JWT validation failed", zap.Error(err))
			reject(http.StatusUnauthorized, "unauthorized", "Invalid or expired token")
			return
		}

		// The audience list applies to new-style tokens only; legacy HMAC
		// tokens carry the RP ID as "aud" and must never be filtered by it.
		if result.Mode != claims.ModeLegacy && !result.HasAudience(auds...) {
			logger.Debug("JWT audience not accepted")
			reject(http.StatusUnauthorized, "unauthorized", "Invalid or expired token")
			return
		}

		// Token is valid, mark as authenticated
		c.Set(string(AuthenticatedKey), true)

		if result.TenantID != "" {
			c.Set(string(TenantIDKey), result.TenantID)
			logger.Debug("request authenticated with tenant",
				zap.String("tenant_id", result.TenantID))
		} else {
			logger.Debug("request authenticated (no tenant_id in token)")
		}

		c.Next()
	}
}

// OptionalJWTMiddleware is a variant that never requires authentication
// but still validates tokens when present and sets authenticated status
func OptionalJWTMiddleware(config JWTConfig, logger *zap.Logger, opts ...JWTOption) gin.HandlerFunc {
	// Force RequireAuth to false
	optionalConfig := config
	optionalConfig.RequireAuth = false
	return JWTMiddleware(optionalConfig, logger, opts...)
}
