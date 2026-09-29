package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	tokenauthclaims "github.com/sirosfoundation/go-tokenauth/claims"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/service"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage/memory"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

// setupLogoutTestHandlers is like setupTestHandlers but with the token
// blacklist enabled - setupTestHandlers leaves it at its zero-value
// (disabled) default, which would make every blacklist check in these
// tests a silent no-op.
func setupLogoutTestHandlers(t *testing.T) (*Handlers, *gin.Engine) {
	t.Helper()
	logger := zap.NewNop()
	cfg := &config.Config{
		Server: config.ServerConfig{
			Host:     "localhost",
			Port:     8080,
			RPID:     "localhost",
			RPOrigin: "http://localhost:8080",
			RPName:   "Test Wallet",
		},
		JWT: config.JWTConfig{
			Secret:      "test-secret",
			ExpiryHours: 24,
			Issuer:      "test-wallet",
		},
		Security: config.SecurityConfig{
			TokenBlacklist: config.TokenBlacklistConfig{Enabled: true},
		},
	}

	store := memory.NewStore()
	services := service.NewServices(store, cfg, logger)
	handlers := NewHandlers(services, cfg, logger, []string{"test"})

	return handlers, gin.New()
}

// TestHandlers_Logout_NoToken proves logging out with no token present
// (already logged out, or never authenticated) is a harmless 200 - not an
// error.
func TestHandlers_Logout_NoToken(t *testing.T) {
	handlers, router := setupLogoutTestHandlers(t)
	router.POST("/logout", handlers.Logout)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/logout", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

// TestHandlers_Logout_LegacyToken proves the pre-existing legacy path: a
// raw HMAC token set in context by pkg/middleware.AuthMiddlewareWithBlacklist
// gets its jti blacklisted.
func TestHandlers_Logout_LegacyToken(t *testing.T) {
	handlers, router := setupLogoutTestHandlers(t)

	secret := handlers.cfg.JWT.Secret
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": "user-1",
		"jti":     "jti-legacy-logout",
		"exp":     time.Now().Add(time.Hour).Unix(),
	})
	tokenStr, err := token.SignedString([]byte(secret))
	if err != nil {
		t.Fatalf("SignedString: %v", err)
	}

	router.POST("/logout", func(c *gin.Context) {
		c.Set("token", tokenStr)
		c.Next()
	}, handlers.Logout)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/logout", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if !handlers.services.TokenBlacklist.IsBlacklisted(context.Background(), "jti-legacy-logout") {
		t.Error("expected the legacy token's jti to be blacklisted")
	}
}

// TestHandlers_Logout_ASToken proves the #391 review fix: when the request
// was authenticated via go-tokenauth (pkg/middleware.TokenAuthMiddleware
// sets "tokenauth_result" in context, and the raw token itself may be
// ES256/EdDSA-signed, which the legacy HMAC re-parse below can't handle),
// Logout still blacklists the token's jti, taken from the already-validated
// result instead of re-parsing the raw token.
func TestHandlers_Logout_ASToken(t *testing.T) {
	handlers, router := setupLogoutTestHandlers(t)

	result := &tokenauthclaims.Result{
		UserID: "user-1",
		JTI:    "jti-as-logout",
		Mode:   tokenauthclaims.ModeSession,
	}

	router.POST("/logout", func(c *gin.Context) {
		// Deliberately also set "token" to an ES256-shaped opaque string
		// that the legacy jwt.Parse(..., HMACSecret) call would fail to
		// verify, proving Logout takes the tokenauth_result branch instead
		// of falling through to (and silently no-op'ing in) the legacy one.
		c.Set("token", "not-a-valid-hmac-token")
		c.Set("tokenauth_result", result)
		c.Next()
	}, handlers.Logout)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/logout", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if !handlers.services.TokenBlacklist.IsBlacklisted(context.Background(), "jti-as-logout") {
		t.Error("expected the AS-issued token's jti to be blacklisted via tokenauth_result")
	}
}

// TestHandlers_Logout_LegacyToken_RevokesFamily is a regression test for
// #402: a legacy HMAC access token carrying a "sid" claim (the
// refresh-token family/session id minted alongside its paired refresh
// token - see WebAuthnService.generateToken's doc comment) must have that
// whole family revoked on logout, not just its own jti.
func TestHandlers_Logout_LegacyToken_RevokesFamily(t *testing.T) {
	handlers, router := setupLogoutTestHandlers(t)

	secret := handlers.cfg.JWT.Secret
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": "user-1",
		"jti":     "jti-legacy-family-logout",
		"sid":     "sid-legacy-family-1",
		"exp":     time.Now().Add(time.Hour).Unix(),
	})
	tokenStr, err := token.SignedString([]byte(secret))
	if err != nil {
		t.Fatalf("SignedString: %v", err)
	}

	router.POST("/logout", func(c *gin.Context) {
		c.Set("token", tokenStr)
		c.Next()
	}, handlers.Logout)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/logout", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if !handlers.services.TokenBlacklist.IsFamilyRevoked(context.Background(), "sid-legacy-family-1") {
		t.Error("expected the refresh-token family to be revoked on logout")
	}
}

// TestHandlers_Logout_LegacyToken_NoSidClaim_NoFamilyRevocationAttempted is
// the sanity check for the test above: a legacy token minted before #402
// (no "sid" claim at all) must not error or panic - there is simply no
// family to revoke.
func TestHandlers_Logout_LegacyToken_NoSidClaim_NoFamilyRevocationAttempted(t *testing.T) {
	handlers, router := setupLogoutTestHandlers(t)

	secret := handlers.cfg.JWT.Secret
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": "user-1",
		"jti":     "jti-legacy-no-sid",
		"exp":     time.Now().Add(time.Hour).Unix(),
	})
	tokenStr, err := token.SignedString([]byte(secret))
	if err != nil {
		t.Fatalf("SignedString: %v", err)
	}

	router.POST("/logout", func(c *gin.Context) {
		c.Set("token", tokenStr)
		c.Next()
	}, handlers.Logout)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/logout", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if !handlers.services.TokenBlacklist.IsBlacklisted(context.Background(), "jti-legacy-no-sid") {
		t.Error("expected the token's own jti to still be blacklisted")
	}
}

// TestHandlers_Logout_ASToken_ModeLegacy_RevokesFamily is a regression test
// for #402: go-tokenauth's Validator "auto-detects new-style vs legacy"
// tokens (see pkg/middleware.TokenAuthMiddleware's doc comment), so a
// WebAuthnService-issued legacy HMAC token - carrying a "sid" claim -
// reaches Logout's tokenauth_result branch, not the legacy one below it,
// whenever the AS is enabled. That branch must still revoke the family:
// go-tokenauth's shared *claims.Result has no "sid" field at all, so Logout
// has to re-parse the raw token itself (still available via the "token"
// context key TokenAuthMiddleware also sets) to reach it.
func TestHandlers_Logout_ASToken_ModeLegacy_RevokesFamily(t *testing.T) {
	handlers, router := setupLogoutTestHandlers(t)

	secret := handlers.cfg.JWT.Secret
	rawToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": "user-1",
		"jti":     "jti-modelegacy-family",
		"sid":     "sid-modelegacy-family-1",
		"exp":     time.Now().Add(time.Hour).Unix(),
	})
	rawTokenStr, err := rawToken.SignedString([]byte(secret))
	if err != nil {
		t.Fatalf("SignedString: %v", err)
	}

	result := &tokenauthclaims.Result{
		UserID: "user-1",
		JTI:    "jti-modelegacy-family",
		Mode:   tokenauthclaims.ModeLegacy,
	}

	router.POST("/logout", func(c *gin.Context) {
		c.Set("token", rawTokenStr)
		c.Set("tokenauth_result", result)
		c.Next()
	}, handlers.Logout)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/logout", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if !handlers.services.TokenBlacklist.IsFamilyRevoked(context.Background(), "sid-modelegacy-family-1") {
		t.Error("expected the refresh-token family to be revoked via the tokenauth_result/ModeLegacy path")
	}
}

// TestHandlers_Logout_ASToken_ModeSession_NoFamilyRevocationAttempted is
// the sanity check that new-style AS-issued tokens (which have no
// sid/refresh-token-family concept in this codebase) never even attempt a
// re-parse - the existing TestHandlers_Logout_ASToken already proves this
// implicitly (its "token" context value is deliberately unparseable), but
// this makes the ModeSession-skips-family-revocation behavior explicit.
func TestHandlers_Logout_ASToken_ModeSession_NoFamilyRevocationAttempted(t *testing.T) {
	handlers, router := setupLogoutTestHandlers(t)

	result := &tokenauthclaims.Result{
		UserID: "user-1",
		JTI:    "jti-modesession-no-family",
		Mode:   tokenauthclaims.ModeSession,
	}

	router.POST("/logout", func(c *gin.Context) {
		c.Set("token", "not-a-valid-hmac-token")
		c.Set("tokenauth_result", result)
		c.Next()
	}, handlers.Logout)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/logout", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	// No sid was ever presented and Mode is ModeSession, so nothing should
	// be revoked under any sid - there is nothing meaningful to assert
	// beyond "this didn't error/panic", which the 200 above already covers.
}

// TestMaxConfiguredASTokenTTL proves the #391 review fix (round 2): the
// blacklist entry Logout creates for an AS-issued token is sized from the
// AS's own configured TTLs, not a fixed guess that an operator's
// AudienceTTLs/DefaultTokenTTL could exceed.
func TestMaxConfiguredASTokenTTL(t *testing.T) {
	cfg := &config.Config{
		AS: config.ASConfig{
			DefaultTokenTTL: 2 * time.Minute,
			AudienceTTLs: map[string]time.Duration{
				"wallet-backend": time.Minute,
				"wallet-engine":  48 * time.Hour, // longer than the old fixed 24h fallback
			},
		},
	}

	got := maxConfiguredASTokenTTL(cfg)
	want := 48 * time.Hour
	if got != want {
		t.Errorf("maxConfiguredASTokenTTL() = %v, want %v", got, want)
	}
}

func TestMaxConfiguredASTokenTTL_NoAudienceOverrides(t *testing.T) {
	cfg := &config.Config{
		AS: config.ASConfig{DefaultTokenTTL: 2 * time.Minute},
	}

	got := maxConfiguredASTokenTTL(cfg)
	want := 2 * time.Minute
	if got != want {
		t.Errorf("maxConfiguredASTokenTTL() = %v, want %v", got, want)
	}
}

// TestTTLForTokenAuthResult proves the #391 review fix (round 3):
// go-tokenauth's Validator "auto-detects new-style vs legacy" tokens, so
// Logout's tokenauth_result branch is reached for BOTH kinds, and a legacy
// token's real lifetime (JWT.ExpiryHours, typically ~24h) is very different
// from an AS-issued token's (DefaultTokenTTL/AudienceTTLs, typically
// minutes) - using the wrong one would size the blacklist entry far too
// short for whichever kind wasn't intended.
func TestTTLForTokenAuthResult(t *testing.T) {
	cfg := &config.Config{
		JWT: config.JWTConfig{ExpiryHours: 24},
		AS: config.ASConfig{
			DefaultTokenTTL: 2 * time.Minute,
			AudienceTTLs:    map[string]time.Duration{"wallet-engine": 5 * time.Minute},
		},
	}

	t.Run("legacy mode uses JWT.ExpiryHours", func(t *testing.T) {
		got := ttlForTokenAuthResult(cfg, &tokenauthclaims.Result{Mode: tokenauthclaims.ModeLegacy})
		want := 24 * time.Hour
		if got != want {
			t.Errorf("ttlForTokenAuthResult() = %v, want %v", got, want)
		}
	})

	t.Run("session mode uses the AS's configured TTLs", func(t *testing.T) {
		got := ttlForTokenAuthResult(cfg, &tokenauthclaims.Result{Mode: tokenauthclaims.ModeSession})
		want := 5 * time.Minute
		if got != want {
			t.Errorf("ttlForTokenAuthResult() = %v, want %v", got, want)
		}
	})
}
