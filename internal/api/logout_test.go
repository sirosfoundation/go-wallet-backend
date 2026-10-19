package api

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	tokenauthclaims "github.com/sirosfoundation/go-tokenauth/claims"
	tokenvalidator "github.com/sirosfoundation/go-tokenauth/validator"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/service"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage/memory"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
	"github.com/sirosfoundation/go-wallet-backend/pkg/middleware"
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
	if !blacklisted(t, handlers.services.TokenBlacklist, context.Background(), "jti-legacy-logout") {
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
	if !blacklisted(t, handlers.services.TokenBlacklist, context.Background(), "jti-as-logout") {
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
	if !blacklisted(t, handlers.services.TokenBlacklist, context.Background(), "jti-legacy-no-sid") {
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

// TestFamilyRetention is a regression test for a Copilot review finding on
// #414: config.Config.Validate does not enforce JWT.RefreshDays outliving
// JWT.ExpiryHours, so familyRetention must use the MAX of both configured
// lifetimes, not just assume the refresh token is always the longer-lived
// of the pair. Getting this wrong would let a Logout-triggered family
// revocation marker expire while an access token from an earlier
// rotation - its own jti never individually blacklisted - was still
// unexpired and usable again.
func TestFamilyRetention(t *testing.T) {
	t.Run("lifetimes beyond the floor are honoured", func(t *testing.T) {
		cfg := &config.Config{JWT: config.JWTConfig{RefreshDays: 400, ExpiryHours: 24}}
		if got, want := familyRetention(cfg), 400*24*time.Hour; got != want {
			t.Errorf("familyRetention() = %v, want %v", got, want)
		}
	})

	t.Run("refresh token outlives access token (the common case)", func(t *testing.T) {
		cfg := &config.Config{JWT: config.JWTConfig{RefreshDays: 7, ExpiryHours: 24}}
		got := familyRetention(cfg)
		want := config.MinFamilyRetention
		if got != want {
			t.Errorf("familyRetention() = %v, want %v", got, want)
		}
	})

	t.Run("access token outlives refresh token (unusual but valid config)", func(t *testing.T) {
		cfg := &config.Config{JWT: config.JWTConfig{RefreshDays: 1, ExpiryHours: 720}} // 30 days
		got := familyRetention(cfg)
		want := config.MinFamilyRetention
		if got != want {
			t.Errorf("familyRetention() = %v, want %v", got, want)
		}
	})

	t.Run("refresh tokens disabled: falls back to the access token's own lifetime", func(t *testing.T) {
		cfg := &config.Config{JWT: config.JWTConfig{RefreshDays: 0, ExpiryHours: 24}}
		got := familyRetention(cfg)
		want := config.MinFamilyRetention
		if got != want {
			t.Errorf("familyRetention() = %v, want %v", got, want)
		}
	})
}

// TestHandlers_Logout_ASToken_ModeLegacy_UndeterminableSIDFailsClosed proves
// Logout does not report success when the family id cannot be derived from
// the (already validated) legacy token, since the refresh token would then
// stay usable.
func TestHandlers_Logout_ASToken_ModeLegacy_UndeterminableSIDFailsClosed(t *testing.T) {
	handlers, router := setupLogoutTestHandlers(t)

	wrongSecretToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": "user-1", "jti": "jti-unverifiable", "sid": "sid-x",
		"exp": time.Now().Add(time.Hour).Unix(),
	}).SignedString([]byte("not-the-configured-secret"))
	if err != nil {
		t.Fatal(err)
	}
	result := &tokenauthclaims.Result{UserID: "user-1", JTI: "jti-unverifiable", Mode: tokenauthclaims.ModeLegacy}

	router.POST("/logout", func(c *gin.Context) {
		c.Set("token", wrongSecretToken)
		c.Set("tokenauth_result", result)
		c.Next()
	}, handlers.Logout)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/logout", nil))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d: %s", w.Code, w.Body.String())
	}
}

// TestLogout_RealLegacyToken_EndToEnd_RPIDAudience reproduces the review
// finding that the legacy logout path was unreachable: a WebAuthn-shaped
// legacy token has aud=Server.RPID (not "wallet-backend"), and the real
// chain TokenAuthMiddleware -> RequireAudience("wallet-backend") -> Logout
// used to answer 403 before the family could be revoked.
func TestLogout_RealLegacyToken_EndToEnd_RPIDAudience(t *testing.T) {
	gin.SetMode(gin.TestMode)
	logger := zap.NewNop()
	cfg := &config.Config{
		Server: config.ServerConfig{RPID: "wallet.example.com"},
		JWT:    config.JWTConfig{Secret: "test-secret", ExpiryHours: 24, RefreshDays: 7, Issuer: "test-wallet"},
		Security: config.SecurityConfig{
			TokenBlacklist: config.TokenBlacklistConfig{Enabled: true},
		},
	}
	store := memory.NewStore()
	services := service.NewServices(store, cfg, logger)
	handlers := NewHandlers(services, cfg, logger, []string{"test"})

	v := tokenvalidator.New(tokenvalidator.Config{
		Audiences: []string{"wallet-backend", "wallet-engine", "wallet-registry", "wallet.example.com"},
		Legacy: tokenvalidator.LegacyConfig{
			Enabled: true, HMACSecret: []byte(cfg.JWT.Secret), Issuers: []string{cfg.JWT.Issuer},
		},
	})

	router := gin.New()
	router.Use(middleware.TokenAuthMiddleware(cfg, v, store.Tenants(), services.TokenBlacklist, logger))
	router.Use(middleware.RequireAudience("wallet-backend"))
	router.POST("/user/session/logout", handlers.Logout)
	router.GET("/user/session/account-info", func(c *gin.Context) { c.Status(200) })

	tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": "user-1", "tenant_id": "default", "jti": "jti-e2e", "sid": "sid-e2e",
		"iss": "test-wallet", "aud": "wallet.example.com", "exp": time.Now().Add(time.Hour).Unix(),
	}).SignedString([]byte(cfg.JWT.Secret))
	if err != nil {
		t.Fatal(err)
	}
	do := func(method, path string) int {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(method, path, nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		router.ServeHTTP(w, req)
		return w.Code
	}

	if code := do(http.MethodPost, "/user/session/logout"); code != http.StatusOK {
		t.Fatalf("logout with a real legacy token: expected 200, got %d", code)
	}
	if !services.TokenBlacklist.IsFamilyRevoked(context.Background(), "sid-e2e") {
		t.Error("expected the refresh-token family to be revoked by the registered logout route")
	}
	if code := do(http.MethodGet, "/user/session/account-info"); code != http.StatusUnauthorized {
		t.Errorf("token of a revoked family must be rejected, got %d", code)
	}
}

// TestHandlers_Logout_RevokeFamilyFailure_FailsClosed drives Logout down each path with a request
// context that is already cancelled, which makes RevokeFamily return an
// error, then retries with a live context to prove the logout is
// idempotent and succeeds once the blacklist recovers.
func TestHandlers_Logout_RevokeFamilyFailure_FailsClosed(t *testing.T) {
	secret := "test-secret"
	mkToken := func(t *testing.T, jti, sid string) string {
		t.Helper()
		s, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"user_id": "user-1", "jti": jti, "sid": sid,
			"exp": time.Now().Add(time.Hour).Unix(),
		}).SignedString([]byte(secret))
		if err != nil {
			t.Fatalf("SignedString: %v", err)
		}
		return s
	}

	for _, tc := range []struct {
		name      string
		tokenAuth bool
	}{
		{"legacy HMAC path", false},
		{"tokenauth ModeLegacy path", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			handlers, router := setupLogoutTestHandlers(t)
			sid := "sid-failclosed-" + tc.name
			raw := mkToken(t, "jti-failclosed", sid)

			router.POST("/logout", func(c *gin.Context) {
				c.Set("token", raw)
				if tc.tokenAuth {
					c.Set("tokenauth_result", &tokenauthclaims.Result{
						UserID: "user-1", JTI: "jti-failclosed", Mode: tokenauthclaims.ModeLegacy,
					})
				}
				c.Next()
			}, handlers.Logout)

			cancelled, cancel := context.WithCancel(context.Background())
			cancel()
			w := httptest.NewRecorder()
			router.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/logout", nil).WithContext(cancelled))

			if w.Code != http.StatusInternalServerError {
				t.Fatalf("expected 500, got %d: %s", w.Code, w.Body.String())
			}
			if strings.Contains(w.Body.String(), "Logged out successfully") {
				t.Errorf("success message must not be returned: %s", w.Body.String())
			}
			if !strings.Contains(w.Body.String(), "Failed to revoke session") {
				t.Errorf("expected revoke-session error, got %s", w.Body.String())
			}
			if handlers.services.TokenBlacklist.IsFamilyRevoked(context.Background(), sid) {
				t.Error("family must not be revoked after the failure")
			}

			// Retry once the blacklist has recovered.
			w = httptest.NewRecorder()
			router.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/logout", nil))
			if w.Code != http.StatusOK {
				t.Fatalf("retry: expected 200, got %d: %s", w.Code, w.Body.String())
			}
			if !handlers.services.TokenBlacklist.IsFamilyRevoked(context.Background(), sid) {
				t.Error("retry: expected the family to be revoked")
			}
		})
	}
}

// TestLogout_FailedFamilyRevocation_RetryableThroughRealMiddleware is the
// regression test for the #414 review finding that a failed family
// revocation was not actually retryable: Logout used to blacklist the
// access token's jti BEFORE revoking the family, so the auth middleware
// rejected the very same token on the retry and the refresh token stayed
// usable. It drives the real auth middleware (not just the handler): the
// first attempt has its request context cancelled after authentication
// (making RevokeFamily fail), the retry runs normally.
func TestLogout_FailedFamilyRevocation_RetryableThroughRealMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)

	for _, tc := range []struct {
		name      string
		tokenAuth bool
	}{
		{"legacy HMAC path", false},
		{"tokenauth ModeLegacy path", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logger := zap.NewNop()
			cfg := &config.Config{
				Server: config.ServerConfig{RPID: "wallet.example.com"},
				JWT:    config.JWTConfig{Secret: "test-secret", ExpiryHours: 24, RefreshDays: 7, Issuer: "test-wallet"},
				Security: config.SecurityConfig{
					TokenBlacklist: config.TokenBlacklistConfig{Enabled: true},
				},
			}
			store := memory.NewStore()
			services := service.NewServices(store, cfg, logger)
			handlers := NewHandlers(services, cfg, logger, []string{"test"})

			router := gin.New()
			if tc.tokenAuth {
				v := tokenvalidator.New(tokenvalidator.Config{
					Audiences: []string{"wallet-backend", "wallet.example.com"},
					Legacy: tokenvalidator.LegacyConfig{
						Enabled: true, HMACSecret: []byte(cfg.JWT.Secret), Issuers: []string{cfg.JWT.Issuer},
					},
				})
				router.Use(middleware.TokenAuthMiddleware(cfg, v, store.Tenants(), services.TokenBlacklist, logger))
				router.Use(middleware.RequireAudience("wallet-backend"))
			} else {
				router.Use(middleware.AuthMiddlewareWithBlacklist(cfg, store, services.TokenBlacklist, logger))
			}

			// Simulates a recovering store: while failing is true the
			// request context is already cancelled by the time Logout
			// runs (authentication itself has already succeeded).
			failing := true
			router.Use(func(c *gin.Context) {
				if failing {
					ctx, cancel := context.WithCancel(c.Request.Context())
					cancel()
					c.Request = c.Request.WithContext(ctx)
				}
				c.Next()
			})
			router.POST("/user/session/logout", handlers.Logout)

			jti, sid := "jti-retry-"+tc.name, "sid-retry-"+tc.name
			tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
				"user_id": "user-1", "tenant_id": "default", "jti": jti, "sid": sid,
				"iss": "test-wallet", "aud": "wallet.example.com", "exp": time.Now().Add(time.Hour).Unix(),
			}).SignedString([]byte(cfg.JWT.Secret))
			if err != nil {
				t.Fatal(err)
			}
			logout := func() *httptest.ResponseRecorder {
				w := httptest.NewRecorder()
				req := httptest.NewRequest(http.MethodPost, "/user/session/logout", nil)
				req.Header.Set("Authorization", "Bearer "+tok)
				router.ServeHTTP(w, req)
				return w
			}
			ctx := context.Background()

			// Attempt 1: family revocation fails -> 500, nothing recorded.
			if w := logout(); w.Code != http.StatusInternalServerError {
				t.Fatalf("attempt 1: expected 500, got %d: %s", w.Code, w.Body.String())
			}
			// The jti entry is shared and monotonic: it is not withdrawn after
			// the failure (see revokeSessionTokens).
			if !blacklisted(t, services.TokenBlacklist, ctx, jti) {
				t.Fatal("the jti revocation must not be withdrawn after a failed family revocation")
			}
			if services.TokenBlacklist.IsFamilyRevoked(ctx, sid) {
				t.Fatal("family must not be revoked after the failure")
			}

			// Attempt 2: the store has recovered; the SAME token must still
			// get through the real auth middleware and complete the logout.
			failing = false
			if w := logout(); w.Code != http.StatusOK {
				t.Fatalf("retry with the same token: expected 200, got %d: %s", w.Code, w.Body.String())
			}
			if !services.TokenBlacklist.IsFamilyRevoked(ctx, sid) {
				t.Error("retry: expected the family to be revoked")
			}
			if !blacklisted(t, services.TokenBlacklist, ctx, jti) {
				t.Error("a successful logout must blacklist the access token's jti")
			}

			// The token is now dead through the real middleware.
			// Logout is idempotent: repeating it with the revoked token is
			// admitted (and harmless), see middleware.IsLogout.
			if w := logout(); w.Code != http.StatusOK {
				t.Errorf("repeating a completed logout must stay idempotent, got %d", w.Code)
			}
		})
	}
}

// revocationReader is the check half of a revocation checker.
type revocationReader interface {
	IsBlacklisted(ctx context.Context, jti string) (bool, error)
	IsUserRevoked(ctx context.Context, userID string) (bool, error)
}

func blacklisted(t *testing.T, r revocationReader, ctx context.Context, jti string) bool {
	t.Helper()
	ok, err := r.IsBlacklisted(ctx, jti)
	if err != nil {
		t.Fatalf("IsBlacklisted: %v", err)
	}
	return ok
}

func userRevoked(t *testing.T, r revocationReader, ctx context.Context, userID string) bool {
	t.Helper()
	ok, err := r.IsUserRevoked(ctx, userID)
	if err != nil {
		t.Fatalf("IsUserRevoked: %v", err)
	}
	return ok
}

// flakyAddStore is a RevocationStore whose Add fails while failing is set.
type flakyAddStore struct {
	failing bool
	jtis    map[string]bool
}

func (s *flakyAddStore) Add(_ context.Context, jti string, _ time.Time) error {
	if s.failing {
		return errors.New("store write failed")
	}
	s.jtis[jti] = true
	return nil
}
func (s *flakyAddStore) Has(_ context.Context, jti string) (bool, error) { return s.jtis[jti], nil }
func (s *flakyAddStore) RevokeUser(context.Context, string) error        { return nil }
func (s *flakyAddStore) IsUserRevoked(context.Context, string) (bool, error) {
	return false, nil
}

// A failed jti blacklist write fails the logout (500) instead of being
// logged; the retry then succeeds.
func TestLogout_FailedJTIBlacklistWrite_FailsClosed(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, tokenAuth := range []bool{false, true} {
		name := "legacy HMAC path"
		if tokenAuth {
			name = "tokenauth path"
		}
		t.Run(name, func(t *testing.T) {
			logger := zap.NewNop()
			cfg := &config.Config{
				Server: config.ServerConfig{RPID: "wallet.example.com"},
				JWT:    config.JWTConfig{Secret: "test-secret", ExpiryHours: 24, Issuer: "test-wallet"},
			}
			store := &flakyAddStore{failing: true, jtis: map[string]bool{}}
			services := service.NewServices(memory.NewStore(), cfg, logger)
			services.TokenBlacklist = service.NewTokenBlacklistWithStore(config.TokenBlacklistConfig{Enabled: true}, logger, store)
			handlers := NewHandlers(services, cfg, logger, []string{"test"})

			tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
				"user_id": "user-1", "jti": "jti-w", "exp": time.Now().Add(time.Hour).Unix(),
			}).SignedString([]byte(cfg.JWT.Secret))
			require.NoError(t, err)

			router := gin.New()
			router.POST("/logout", func(c *gin.Context) {
				c.Set("token", tok)
				if tokenAuth {
					c.Set("tokenauth_result", &tokenauthclaims.Result{UserID: "user-1", JTI: "jti-w"})
				}
				c.Next()
			}, handlers.Logout)
			do := func() *httptest.ResponseRecorder {
				w := httptest.NewRecorder()
				router.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/logout", nil))
				return w
			}

			w := do()
			require.Equal(t, http.StatusInternalServerError, w.Code, w.Body.String())
			require.NotContains(t, w.Body.String(), "Logged out successfully")
			require.False(t, store.jtis["jti-w"])

			store.failing = false
			require.Equal(t, http.StatusOK, do().Code, "retry")
			require.True(t, store.jtis["jti-w"])
		})
	}
}

type failingRevoker struct{}

func (failingRevoker) RevokeUser(context.Context, string) error {
	return errors.New("store write failed")
}

// A failed user-revocation write answers 500 and leaves the user in place.
func TestDeleteUser_RevocationFailureAnswers500(t *testing.T) {
	gin.SetMode(gin.TestMode)
	logger := zap.NewNop()
	cfg := &config.Config{
		Server: config.ServerConfig{RPID: "localhost", RPOrigin: "http://localhost:8080"},
		JWT:    config.JWTConfig{Secret: "test-secret", ExpiryHours: 24, Issuer: "test"},
	}
	services := service.NewServices(memory.NewStore(), cfg, logger)
	services.User.SetTokenBlacklist(failingRevoker{})
	handlers := NewHandlers(services, cfg, logger, []string{"test"})

	name := "del-user"
	user, err := services.User.Register(context.Background(), &domain.RegisterRequest{Username: &name, DisplayName: "d", WalletType: domain.WalletTypeDB})
	require.NoError(t, err)

	router := gin.New()
	router.DELETE("/user", func(c *gin.Context) { c.Set("user_id", user.UUID.String()); c.Next() }, handlers.DeleteUser)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodDelete, "/user", nil))
	require.Equal(t, http.StatusInternalServerError, w.Code, w.Body.String())
	require.Contains(t, w.Body.String(), "Failed to revoke tokens")
}

// With sid and jti on the token, a failed shared jti write must leave the
// retry admissible through the real auth middleware: nothing may have been
// revoked locally by the failed attempt.
func TestLogout_FailedJTIWriteWithSID_RetryableThroughRealMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, tokenAuth := range []bool{false, true} {
		name := "legacy HMAC path"
		if tokenAuth {
			name = "tokenauth ModeLegacy path"
		}
		t.Run(name, func(t *testing.T) {
			logger := zap.NewNop()
			cfg := &config.Config{
				Server: config.ServerConfig{RPID: "wallet.example.com"},
				JWT:    config.JWTConfig{Secret: "test-secret", ExpiryHours: 24, RefreshDays: 7, Issuer: "test-wallet"},
			}
			mem := memory.NewStore()
			store := &flakyAddStore{failing: true, jtis: map[string]bool{}}
			services := service.NewServices(mem, cfg, logger)
			services.TokenBlacklist = service.NewTokenBlacklistWithStore(config.TokenBlacklistConfig{Enabled: true}, logger, store)
			handlers := NewHandlers(services, cfg, logger, []string{"test"})

			router := gin.New()
			if tokenAuth {
				v := tokenvalidator.New(tokenvalidator.Config{
					Audiences: []string{"wallet-backend", "wallet.example.com"},
					Legacy: tokenvalidator.LegacyConfig{
						Enabled: true, HMACSecret: []byte(cfg.JWT.Secret), Issuers: []string{cfg.JWT.Issuer},
					},
				})
				router.Use(middleware.TokenAuthMiddleware(cfg, v, mem.Tenants(), services.TokenBlacklist, logger))
				router.Use(middleware.RequireAudience("wallet-backend"))
			} else {
				router.Use(middleware.AuthMiddlewareWithBlacklist(cfg, mem, services.TokenBlacklist, logger))
			}
			router.POST("/user/session/logout", handlers.Logout)

			tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
				"user_id": "user-1", "tenant_id": "default", "jti": "jti-s", "sid": "sid-s",
				"iss": "test-wallet", "aud": "wallet.example.com", "exp": time.Now().Add(time.Hour).Unix(),
			}).SignedString([]byte(cfg.JWT.Secret))
			require.NoError(t, err)
			logout := func() int {
				w := httptest.NewRecorder()
				req := httptest.NewRequest(http.MethodPost, "/user/session/logout", nil)
				req.Header.Set("Authorization", "Bearer "+tok)
				router.ServeHTTP(w, req)
				return w.Code
			}

			require.Equal(t, http.StatusInternalServerError, logout())
			require.False(t, services.TokenBlacklist.IsFamilyRevoked(context.Background(), "sid-s"),
				"a failed attempt must not revoke the family: the retry would be rejected")

			store.failing = false
			require.Equal(t, http.StatusOK, logout(), "retry with the same token")
			require.True(t, store.jtis["jti-s"], "the shared jti entry is written on the retry")
			require.True(t, services.TokenBlacklist.IsFamilyRevoked(context.Background(), "sid-s"))
		})
	}
}

// userStore records a user revocation and fails the first write anyway, like
// a MongoDB write whose majority acknowledgement was lost after it applied.
type lostAckUserStore struct {
	users    map[string]bool
	failNext bool
}

func (s *lostAckUserStore) Add(context.Context, string, time.Time) error { return nil }
func (s *lostAckUserStore) Has(context.Context, string) (bool, error)    { return false, nil }
func (s *lostAckUserStore) RevokeUser(_ context.Context, id string) error {
	s.users[id] = true
	if s.failNext {
		s.failNext = false
		return errors.New("write concern timeout")
	}
	return nil
}
func (s *lostAckUserStore) IsUserRevoked(_ context.Context, id string) (bool, error) {
	return s.users[id], nil
}

// A revocation that was stored although its write reported an error leaves
// the user revoked but undeleted; the retry must still reach the deletion
// through the real auth middleware, and other routes must stay closed to the
// revoked user.
func TestDeleteUser_LostAckRevocation_RetryCompletesThroughRealMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)
	logger := zap.NewNop()
	cfg := &config.Config{
		Server: config.ServerConfig{RPID: "wallet.example.com"},
		JWT:    config.JWTConfig{Secret: "test-secret", ExpiryHours: 24, Issuer: "test-wallet"},
	}
	mem := memory.NewStore()
	rs := &lostAckUserStore{users: map[string]bool{}, failNext: true}
	services := service.NewServices(mem, cfg, logger)
	bl := service.NewTokenBlacklistWithStore(config.TokenBlacklistConfig{Enabled: true}, logger, rs)
	services.TokenBlacklist = bl
	services.User.SetTokenBlacklist(bl)
	handlers := NewHandlers(services, cfg, logger, []string{"test"})

	name := "lost-ack"
	user, err := services.User.Register(context.Background(), &domain.RegisterRequest{Username: &name, DisplayName: "d", WalletType: domain.WalletTypeDB})
	require.NoError(t, err)

	router := gin.New()
	router.Use(middleware.AuthMiddlewareWithBlacklist(cfg, mem, bl, logger))
	router.DELETE("/user/session", handlers.DeleteUser)
	router.GET("/user/session/account-info", func(c *gin.Context) { c.Status(http.StatusOK) })

	tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": user.UUID.String(), "tenant_id": "default", "jti": "jti-d",
		"iss": "test-wallet", "aud": "wallet.example.com", "exp": time.Now().Add(time.Hour).Unix(),
	}).SignedString([]byte(cfg.JWT.Secret))
	require.NoError(t, err)
	do := func(method, path string) int {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(method, path, nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		router.ServeHTTP(w, req)
		return w.Code
	}

	require.Equal(t, http.StatusInternalServerError, do(http.MethodDelete, "/user/session"))
	_, err = mem.Users().GetByID(context.Background(), user.UUID)
	require.NoError(t, err, "the user survives the failed attempt")
	require.True(t, rs.users[user.UUID.String()], "precondition: the revocation was stored")

	require.Equal(t, http.StatusUnauthorized, do(http.MethodGet, "/user/session/account-info"), "a revoked user stays locked out of every other route")
	require.Equal(t, http.StatusOK, do(http.MethodDelete, "/user/session"), "the retry completes the deletion")
	_, err = mem.Users().GetByID(context.Background(), user.UUID)
	require.Error(t, err, "the user is deleted")
}

// lostAckJTIStore applies Add and then reports an error, like a MongoDB
// update whose majority acknowledgement timed out after it was applied.
type lostAckJTIStore struct {
	jtis     map[string]bool
	failNext bool
}

func (s *lostAckJTIStore) Add(_ context.Context, jti string, _ time.Time) error {
	s.jtis[jti] = true
	if s.failNext {
		s.failNext = false
		return errors.New("write concern timeout")
	}
	return nil
}
func (s *lostAckJTIStore) Remove(_ context.Context, jti string) error {
	delete(s.jtis, jti)
	return nil
}
func (s *lostAckJTIStore) Has(_ context.Context, jti string) (bool, error) { return s.jtis[jti], nil }
func (s *lostAckJTIStore) RevokeUser(context.Context, string) error        { return nil }
func (s *lostAckJTIStore) IsUserRevoked(context.Context, string) (bool, error) {
	return false, nil
}

// logoutRig wires the real auth middleware in front of Logout plus a
// protected route, around the given jti store.
func logoutRig(t *testing.T, tokenAuth bool, store service.RevocationStore) (*service.Services, http.Handler, string) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	logger := zap.NewNop()
	cfg := &config.Config{
		Server: config.ServerConfig{RPID: "wallet.example.com"},
		JWT:    config.JWTConfig{Secret: "test-secret", ExpiryHours: 24, RefreshDays: 7, Issuer: "test-wallet"},
	}
	mem := memory.NewStore()
	services := service.NewServices(mem, cfg, logger)
	services.TokenBlacklist = service.NewTokenBlacklistWithStore(config.TokenBlacklistConfig{Enabled: true}, logger, store)
	handlers := NewHandlers(services, cfg, logger, []string{"test"})

	router := gin.New()
	if tokenAuth {
		v := tokenvalidator.New(tokenvalidator.Config{
			Audiences: []string{"wallet-backend", "wallet.example.com"},
			Legacy: tokenvalidator.LegacyConfig{
				Enabled: true, HMACSecret: []byte(cfg.JWT.Secret), Issuers: []string{cfg.JWT.Issuer},
			},
			Revocation: tokenRevocationChecker{services.TokenBlacklist},
		})
		router.Use(middleware.TokenAuthMiddleware(cfg, v, mem.Tenants(), services.TokenBlacklist, logger))
		router.Use(middleware.RequireAudience("wallet-backend"))
	} else {
		router.Use(middleware.AuthMiddlewareWithBlacklist(cfg, mem, services.TokenBlacklist, logger))
	}
	router.POST("/user/session/logout", handlers.Logout)
	router.GET("/user/session/protected", func(c *gin.Context) { c.Status(http.StatusOK) })

	tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": "user-1", "tenant_id": "default", "jti": "jti-x", "sid": "sid-x",
		"iss": "test-wallet", "aud": "wallet.example.com", "exp": time.Now().Add(time.Hour).Unix(),
	}).SignedString([]byte(cfg.JWT.Secret))
	require.NoError(t, err)
	return services, router, tok
}

// tokenRevocationChecker mirrors internal/server's adapter (which this
// package cannot import): store errors reject, a revoked jti is admitted only
// for the logout call.
type tokenRevocationChecker struct{ bl *service.TokenBlacklist }

func (c tokenRevocationChecker) IsRevoked(ctx context.Context, jti string) bool {
	revoked, err := c.bl.IsBlacklisted(ctx, jti)
	if err != nil {
		return true
	}
	return revoked && !middleware.IsLogoutCompletion(ctx)
}

func doReq(router http.Handler, method, path, tok string, ctx context.Context) int {
	w := httptest.NewRecorder()
	req := httptest.NewRequest(method, path, nil).WithContext(ctx)
	req.Header.Set("Authorization", "Bearer "+tok)
	router.ServeHTTP(w, req)
	return w.Code
}

// An Add error does not prove the jti write was rejected. When the write was
// applied and only its acknowledgement was lost, the first logout fails but
// the jti is revoked; the retry with the same token must still get through
// the real middleware to revoke the refresh-token family, and afterwards the
// token must be dead everywhere else.
func TestLogout_LostAckJTIWrite_RetryCompletesFamilyRevocation(t *testing.T) {
	for _, tokenAuth := range []bool{false, true} {
		name := "legacy HMAC path"
		if tokenAuth {
			name = "tokenauth ModeLegacy path"
		}
		t.Run(name, func(t *testing.T) {
			store := &lostAckJTIStore{jtis: map[string]bool{}, failNext: true}
			services, router, tok := logoutRig(t, tokenAuth, store)
			bg := context.Background()

			require.Equal(t, http.StatusInternalServerError, doReq(router, http.MethodPost, "/user/session/logout", tok, bg))
			require.True(t, store.jtis["jti-x"], "the write was applied despite the error")
			require.False(t, services.TokenBlacklist.IsFamilyRevoked(bg, "sid-x"))
			if !tokenAuth {
				// go-tokenauth does not consult the jti checker for legacy HMAC
				// tokens, which are covered by the family check instead.
				require.Equal(t, http.StatusUnauthorized, doReq(router, http.MethodGet, "/user/session/protected", tok, bg),
					"a revoked jti is refused everywhere except the logout call")
			}

			require.Equal(t, http.StatusOK, doReq(router, http.MethodPost, "/user/session/logout", tok, bg), "retry")
			require.True(t, services.TokenBlacklist.IsFamilyRevoked(bg, "sid-x"), "retry must revoke the family")
			require.Equal(t, http.StatusOK, doReq(router, http.MethodPost, "/user/session/logout", tok, bg), "logout is idempotent")
			require.Equal(t, http.StatusUnauthorized, doReq(router, http.MethodGet, "/user/session/protected", tok, bg))
		})
	}
}

// Two requests present the same token; one completes the logout and the
// other is abandoned (cancelled context) before it revokes the family. The
// abandoned request must not undo the completed one: the shared jti entry
// stays.
func TestLogout_AbandonedRequestDoesNotUndoCompletedLogout(t *testing.T) {
	for _, tokenAuth := range []bool{false, true} {
		name := "legacy HMAC path"
		if tokenAuth {
			name = "tokenauth ModeLegacy path"
		}
		t.Run(name, func(t *testing.T) {
			store := &lostAckJTIStore{jtis: map[string]bool{}}
			services, router, tok := logoutRig(t, tokenAuth, store)
			bg := context.Background()

			// Request B authenticates, then is abandoned before RevokeFamily.
			// (Run it first here; its jti write is the shared entry either way.)
			cancelled, cancel := context.WithCancel(bg)
			cancel()
			_ = doReq(router, http.MethodPost, "/user/session/logout", tok, cancelled)

			// Request A completes.
			require.Equal(t, http.StatusOK, doReq(router, http.MethodPost, "/user/session/logout", tok, bg))
			require.True(t, store.jtis["jti-x"])
			require.True(t, services.TokenBlacklist.IsFamilyRevoked(bg, "sid-x"))

			// Another abandoned request after the completed logout.
			_ = doReq(router, http.MethodPost, "/user/session/logout", tok, cancelled)
			require.True(t, store.jtis["jti-x"], "an abandoned request must not withdraw the shared jti entry")
			require.Equal(t, http.StatusUnauthorized, doReq(router, http.MethodGet, "/user/session/protected", tok, bg))
		})
	}
}
