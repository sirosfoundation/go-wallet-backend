package as

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
	"github.com/sirosfoundation/go-wallet-backend/pkg/oidc"
)

// OIDCHandlers provides OIDC RP authentication for the AS.
// Admin users authenticate via their tenant's configured OIDC provider.
// The provider configuration (issuer, client_id, etc.) is read from the
// tenant's OIDCGateConfig at runtime — no build-time dependency on any
// specific IdP.
type OIDCHandlers struct {
	store       storage.Store
	sessions    SessionStore
	cfg         *config.ASConfig
	stateSecret []byte
	logger      *zap.Logger
}

// NewOIDCHandlers creates OIDC auth handlers.
// stateSecret keys the HMAC that binds the OIDC `state` parameter to a
// signed cookie set at login-start (go-wallet-backend#385 / T-4); it must
// be at least 32 bytes. Callers pass the AS's existing JWT secret
// (pkg/config.JWTConfig.Secret), which pkg/config.Config.Validate already
// requires to be >=32 bytes - no new secret to provision.
func NewOIDCHandlers(
	store storage.Store,
	sessions SessionStore,
	cfg *config.ASConfig,
	stateSecret []byte,
	logger *zap.Logger,
) *OIDCHandlers {
	return &OIDCHandlers{
		store:       store,
		sessions:    sessions,
		cfg:         cfg,
		stateSecret: stateSecret,
		logger:      logger,
	}
}

// oidcState ties together the OIDC authorization code flow state.
// Stored in the challenge store with action "oidc_login".
const oidcChallengeAction = "oidc_login"

// oidcChallengeTTL bounds how long an in-flight OIDC login (state + PKCE
// verifier + nonce) is valid for. Also used as the state-binding cookie's
// MaxAge so the two expire together.
const oidcChallengeTTL = 10 * time.Minute

// Login handles GET /auth/oidc/login.
// Redirects the user to the tenant's OIDC provider for authentication.
func (h *OIDCHandlers) Login(c *gin.Context) {
	tenantID := c.GetHeader("X-Tenant-ID")
	if tenantID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "X-Tenant-ID header required"})
		return
	}

	// Look up tenant and its OIDC config.
	tenant, err := h.store.Tenants().GetByID(c.Request.Context(), domain.TenantID(tenantID))
	if err != nil {
		h.logger.Warn("tenant not found", zap.String("tenant_id", tenantID), zap.Error(err))
		c.JSON(http.StatusNotFound, gin.H{"error": "tenant not found"})
		return
	}

	// Disabled tenants must not be able to start (or complete) an OIDC
	// login — see the matching check in Callback and go-wallet-backend#385.
	if !tenant.Enabled {
		h.logger.Warn("OIDC login attempted for disabled tenant", zap.String("tenant_id", tenantID))
		c.JSON(http.StatusForbidden, gin.H{"error": "tenant is disabled"})
		return
	}

	op := tenant.OIDCGate.GetLoginOP()
	if op == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "tenant has no OIDC provider configured"})
		return
	}

	// Generate state parameter (CSRF protection).
	state, err := generateOIDCState()
	if err != nil {
		h.logger.Error("failed to generate OIDC state", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": errInternalError})
		return
	}

	// Generate nonce for ID token replay protection.
	nonce, err := generateOIDCState()
	if err != nil {
		h.logger.Error("failed to generate OIDC nonce", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": errInternalError})
		return
	}
	// Store the nonce hash for validation — we don't need to recover the raw nonce.
	nonceHash := hashNonce(nonce)

	// Generate a PKCE code_verifier/code_challenge pair (RFC 7636, S256).
	// Required because this is a public client (no client_secret) doing an
	// authorization-code exchange — without PKCE, an authorization code
	// intercepted in transit could be redeemed by anyone. See
	// go-wallet-backend#373 / M-1.
	codeVerifier, err := generatePKCECodeVerifier()
	if err != nil {
		h.logger.Error("failed to generate PKCE code_verifier", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": errInternalError})
		return
	}
	codeChallenge := pkceCodeChallengeS256(codeVerifier)

	// Store state as a challenge for validation on callback.
	// The nonce hash is stored in the UserID field (unused for OIDC flows).
	challenge := &domain.WebauthnChallenge{
		ID:           state,
		TenantID:     tenantID,
		UserID:       nonceHash,
		Challenge:    state,
		Action:       oidcChallengeAction,
		CodeVerifier: codeVerifier,
		ExpiresAt:    time.Now().Add(oidcChallengeTTL),
		CreatedAt:    time.Now(),
	}
	if err := h.store.Challenges().Create(c.Request.Context(), challenge); err != nil {
		h.logger.Error("failed to store OIDC state", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": errInternalError})
		return
	}

	// Build authorization URL.
	// Uses OIDC discovery to find the authorization endpoint.
	disc, err := oidc.DiscoverProvider(c.Request.Context(), op.Issuer, nil)
	if err != nil {
		h.logger.Error("OIDC discovery failed", zap.Error(err), zap.String("issuer", op.Issuer))
		c.JSON(http.StatusBadGateway, gin.H{"error": "OIDC provider unavailable"})
		return
	}

	redirectURI := h.redirectURI()
	scopes := op.EffectiveScopes()

	// Build auth URL with properly encoded parameters.
	params := url.Values{
		"response_type":         {"code"},
		"client_id":             {op.ClientID},
		"redirect_uri":          {redirectURI},
		"scope":                 {scopes},
		"state":                 {state},
		"nonce":                 {nonce},
		"code_challenge":        {codeChallenge},
		"code_challenge_method": {"S256"},
	}
	authURL := disc.AuthorizationEndpoint + "?" + params.Encode()

	// Bind state to this browser via a signed cookie, checked at Callback
	// (go-wallet-backend#385 / T-4).
	setOIDCStateCookie(c, h.stateSecret, state, int(oidcChallengeTTL.Seconds()), h.cfg.InsecureCookies)

	c.Redirect(http.StatusFound, authURL)
}

// Callback handles GET /auth/oidc/callback.
// Validates the authorization code response and creates an AS session.
func (h *OIDCHandlers) Callback(c *gin.Context) {
	state := c.Query("state")
	code := c.Query("code")
	errParam := c.Query("error")

	if errParam != "" {
		errDesc := c.Query("error_description")
		h.logger.Warn("OIDC error response",
			zap.String("error", errParam),
			zap.String("description", errDesc),
		)
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":             errParam,
			"error_description": errDesc,
		})
		return
	}

	if state == "" || code == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing state or code"})
		return
	}

	challenge, ok := h.validateCallbackState(c, state)
	if !ok {
		return
	}

	tenantID := challenge.TenantID

	// Look up tenant's OIDC config.
	tenant, err := h.store.Tenants().GetByID(c.Request.Context(), domain.TenantID(tenantID))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "tenant lookup failed"})
		return
	}

	// Disabled tenants must not be able to complete an OIDC login and mint
	// a session, even with a valid state/code/ID token. See
	// go-wallet-backend#385 / T-4.
	if !tenant.Enabled {
		h.logger.Warn("OIDC callback for disabled tenant", zap.String("tenant_id", tenantID))
		c.JSON(http.StatusForbidden, gin.H{"error": "tenant is disabled"})
		return
	}

	op := tenant.OIDCGate.GetLoginOP()
	if op == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "OIDC config missing"})
		return
	}

	// Exchange code for tokens (token endpoint).
	disc, err := oidc.DiscoverProvider(c.Request.Context(), op.Issuer, nil)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "OIDC provider unavailable"})
		return
	}

	redirectURI := h.redirectURI()
	tokenResp, err := exchangeCode(c.Request.Context(), disc.TokenEndpoint, code, op.ClientID, redirectURI, challenge.CodeVerifier)
	if err != nil {
		h.logger.Error("OIDC token exchange failed", zap.Error(err))
		c.JSON(http.StatusUnauthorized, gin.H{"error": "token exchange failed"})
		return
	}

	// Validate ID token.
	validator := oidc.NewValidator(oidc.ValidatorConfig{
		Issuer:   op.Issuer,
		Audience: op.ClientID,
		JWKSURI:  op.JWKSURI,
	}, nil, h.logger)

	result, err := validator.Validate(c.Request.Context(), tokenResp.IDToken)
	if err != nil {
		h.logger.Warn("OIDC ID token validation failed", zap.Error(err))
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid ID token"})
		return
	}

	// Validate nonce: the ID token's nonce claim must match the stored hash.
	if !h.validateNonce(c, challenge.UserID, result.Claims) {
		return
	}

	// Map claims to session.
	sub := result.Subject

	// Determine MaxTAC from OIDC claims. Admin users may get elevated
	// permissions, but ONLY when the tenant has explicitly opted in via
	// oidc_gate.trust_admin_claim: the AS doesn't control an IdP's claim
	// semantics, so trusting a "groups"/"roles"/"realm_roles" claim to mint
	// full admin + delegation access by default would let a misconfigured
	// or malicious IdP (or a tenant's own users, if the IdP lets them
	// self-manage group membership) grant themselves admin on this AS. See
	// go-wallet-backend#376 / M-4.
	maxTAC := TAC(h.cfg.DefaultMaxTAC)
	if tenant.OIDCGate.TrustAdminClaim && hasAdminClaim(result.Claims) {
		maxTAC = TAC("rwlidka") // full admin
	}

	sessionID, err := GenerateSessionID()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": errInternalError})
		return
	}

	now := time.Now()
	session := &Session{
		JTI:       sessionID,
		UserID:    sub,
		TenantID:  tenantID,
		ACR:       "urn:siros:acr:oidc",
		MaxTAC:    maxTAC,
		CreatedAt: now,
		ExpiresAt: now.Add(h.cfg.SessionTTL),
	}

	if err := h.sessions.Create(c.Request.Context(), session); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": errInternalError})
		return
	}

	SetSessionCookie(c, sessionID, CookieOptions{
		MaxAge:   int(h.cfg.SessionTTL.Seconds()),
		Insecure: h.cfg.InsecureCookies,
	})

	h.logger.Info("OIDC login success",
		zap.String("sub", sub),
		zap.String("tenant_id", tenantID),
		zap.String("issuer", op.Issuer),
	)

	c.JSON(http.StatusOK, gin.H{
		"uuid":     sub,
		"tenantId": tenantID,
	})
}

// validateCallbackState validates the state param against its stored
// challenge (existence, action, expiry) and its browser-binding cookie
// (go-wallet-backend#385 / T-4: without the cookie check, a completed
// (state, code) callback obtained via one browser - e.g. the attacker's own
// login attempt - could be replayed into a victim's browser, since the
// checks above alone only rely on server-side state storage). On any
// failure it writes the JSON error response itself and returns ok=false.
// The challenge is deleted and the cookie cleared exactly once, on every
// path, so neither can be replayed for a second callback attempt.
func (h *OIDCHandlers) validateCallbackState(c *gin.Context, state string) (challenge *domain.WebauthnChallenge, ok bool) {
	// Atomically consume the state challenge (single find-and-delete). A
	// separate GetByID+Delete here would let two concurrent callbacks
	// presenting the same state both pass validation before either deletion
	// landed — the same challenge-reuse TOCTOU fixed for the WebAuthn paths
	// in internal/service/webauthn.go (issue #379); this consumer shares the
	// same ChallengeStore and was missed in that fix. ConsumeByID guarantees
	// at most one caller ever gets a non-nil challenge back for a given ID.
	challenge, err := h.store.Challenges().ConsumeByID(c.Request.Context(), state)
	if err != nil {
		h.logger.Warn("OIDC state not found", zap.Error(err))
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired state"})
		return nil, false
	}

	if challenge.Action != oidcChallengeAction {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid state"})
		return nil, false
	}

	if time.Now().After(challenge.ExpiresAt) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "state expired"})
		return nil, false
	}

	cookieOK := verifyOIDCStateCookie(c, h.stateSecret, state, h.cfg.InsecureCookies)
	clearOIDCStateCookie(c, h.cfg.InsecureCookies)
	if !cookieOK {
		h.logger.Warn("OIDC state cookie missing or mismatched")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "state cookie mismatch"})
		return nil, false
	}

	return challenge, true
}

// validateNonce checks the ID token's nonce claim against the hash stored
// on the login challenge (skipped when no hash was stored). Writes the
// JSON error response itself and returns false on a missing or mismatched
// nonce.
func (h *OIDCHandlers) validateNonce(c *gin.Context, expectedNonceHash string, claims map[string]interface{}) bool {
	if expectedNonceHash == "" {
		return true
	}
	nonceClaim, ok := claims["nonce"].(string)
	if !ok {
		h.logger.Warn("OIDC ID token missing nonce claim")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "missing nonce in ID token"})
		return false
	}
	if hashNonce(nonceClaim) != expectedNonceHash {
		h.logger.Warn("OIDC nonce mismatch")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "nonce mismatch"})
		return false
	}
	return true
}

// hasAdminClaim checks OIDC claims for admin group/role membership.
func hasAdminClaim(claims map[string]interface{}) bool {
	// Check common group/role claim patterns.
	for _, key := range []string{"groups", "roles", "realm_roles"} {
		if v, ok := claims[key]; ok {
			if groups, ok := v.([]interface{}); ok {
				for _, g := range groups {
					if s, ok := g.(string); ok && s == "admin" {
						return true
					}
				}
			}
		}
	}
	return false
}

func generateOIDCState() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// generatePKCECodeVerifier generates a PKCE code_verifier per RFC 7636 §4.1:
// a high-entropy cryptographically random string. Reuses generateOIDCState's
// 32-random-bytes/base64url construction (43 chars, comfortably within the
// 43-128 character requirement) - a PKCE code_verifier has the same
// "unguessable random token" requirement as an OIDC state value, so a
// second implementation would just be the same code under a different name.
func generatePKCECodeVerifier() (string, error) {
	return generateOIDCState()
}

// pkceCodeChallengeS256 computes the PKCE code_challenge for the S256
// method (RFC 7636 §4.2): BASE64URL-ENCODE(SHA256(ASCII(code_verifier))).
func pkceCodeChallengeS256(codeVerifier string) string {
	sum := sha256.Sum256([]byte(codeVerifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// redirectURI returns the OIDC callback URI from config.
// Using a configured value prevents Host header injection attacks.
func (h *OIDCHandlers) redirectURI() string {
	return strings.TrimRight(h.cfg.ExternalURL, "/") + "/auth/oidc/callback"
}

// hashNonce returns a base64url-encoded SHA-256 hash of the nonce.
// We store the hash rather than the raw nonce to avoid leaking it from the store.
func hashNonce(nonce string) string {
	h := sha256.Sum256([]byte(nonce))
	return base64.RawURLEncoding.EncodeToString(h[:])
}
