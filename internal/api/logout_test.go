package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	tokenauthclaims "github.com/sirosfoundation/go-tokenauth/claims"
	tokenvalidator "github.com/sirosfoundation/go-tokenauth/validator"
	"go.uber.org/zap"

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
