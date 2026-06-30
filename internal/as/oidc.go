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
	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
	"github.com/sirosfoundation/go-wallet-backend/pkg/oidc"
	"go.uber.org/zap"
)

// OIDCHandlers provides OIDC RP authentication for the AS.
// Admin users authenticate via their tenant's configured OIDC provider.
// The provider configuration (issuer, client_id, etc.) is read from the
// tenant's OIDCGateConfig at runtime — no build-time dependency on any
// specific IdP.
type OIDCHandlers struct {
	store    storage.Store
	sessions SessionStore
	cfg      *config.ASConfig
	logger   *zap.Logger
}

// NewOIDCHandlers creates OIDC auth handlers.
func NewOIDCHandlers(
	store storage.Store,
	sessions SessionStore,
	cfg *config.ASConfig,
	logger *zap.Logger,
) *OIDCHandlers {
	return &OIDCHandlers{
		store:    store,
		sessions: sessions,
		cfg:      cfg,
		logger:   logger,
	}
}

// oidcState ties together the OIDC authorization code flow state.
// Stored in the challenge store with action "oidc_login".
const oidcChallengeAction = "oidc_login"

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

	// Store state as a challenge for validation on callback.
	// The nonce hash is stored in the UserID field (unused for OIDC flows).
	challenge := &domain.WebauthnChallenge{
		ID:        state,
		TenantID:  tenantID,
		UserID:    nonceHash,
		Challenge: state,
		Action:    oidcChallengeAction,
		ExpiresAt: time.Now().Add(10 * time.Minute),
		CreatedAt: time.Now(),
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
		"response_type": {"code"},
		"client_id":     {op.ClientID},
		"redirect_uri":  {redirectURI},
		"scope":         {scopes},
		"state":         {state},
		"nonce":         {nonce},
	}
	authURL := disc.AuthorizationEndpoint + "?" + params.Encode()

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

	// Validate state against stored challenge.
	challenge, err := h.store.Challenges().GetByID(c.Request.Context(), state)
	if err != nil {
		h.logger.Warn("OIDC state not found", zap.Error(err))
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired state"})
		return
	}

	if challenge.Action != oidcChallengeAction {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid state"})
		return
	}

	if time.Now().After(challenge.ExpiresAt) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "state expired"})
		return
	}

	// Clean up challenge.
	_ = h.store.Challenges().Delete(c.Request.Context(), state)

	tenantID := challenge.TenantID

	// Look up tenant's OIDC config.
	tenant, err := h.store.Tenants().GetByID(c.Request.Context(), domain.TenantID(tenantID))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "tenant lookup failed"})
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
	tokenResp, err := exchangeCode(c.Request.Context(), disc.TokenEndpoint, code, op.ClientID, redirectURI)
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
	expectedNonceHash := challenge.UserID // stored nonce hash
	if expectedNonceHash != "" {
		if nonceClaim, ok := result.Claims["nonce"].(string); ok {
			if hashNonce(nonceClaim) != expectedNonceHash {
				h.logger.Warn("OIDC nonce mismatch")
				c.JSON(http.StatusUnauthorized, gin.H{"error": "nonce mismatch"})
				return
			}
		} else {
			h.logger.Warn("OIDC ID token missing nonce claim")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "missing nonce in ID token"})
			return
		}
	}

	// Map claims to session.
	sub := result.Subject

	// Determine MaxTAC from OIDC claims. Admin users get elevated permissions.
	maxTAC := TAC(h.cfg.DefaultMaxTAC)
	// Check for admin role/group claims — tenant policy could customize this.
	if hasAdminClaim(result.Claims) {
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
		MaxAge: int(h.cfg.SessionTTL.Seconds()),
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
