package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"

	tokenauthclaims "github.com/sirosfoundation/go-tokenauth/claims"

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
			Secret: "test-secret",
			Issuer: "test-wallet",
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

// TestHandlers_Logout_ASToken: when the request was authenticated via go-tokenauth ("tokenauth_result"
// in context), Logout blacklists the jti from that validated result (the raw token cannot be re-parsed).
func TestHandlers_Logout_ASToken(t *testing.T) {
	handlers, router := setupLogoutTestHandlers(t)

	result := &tokenauthclaims.Result{
		UserID: "user-1",
		JTI:    "jti-as-logout",
		Mode:   tokenauthclaims.ModeSession,
	}

	router.POST("/logout", func(c *gin.Context) {
		c.Set("token", "an-opaque-es256-token")
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

// A raw HMAC token in the context without a validated tokenauth_result is never parsed: Logout revokes nothing.
func TestHandlers_Logout_HMACTokenWithoutValidatedResultRevokesNothing(t *testing.T) {
	handlers, router := setupLogoutTestHandlers(t)

	hmacToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": "user-1",
		"jti":     "jti-hmac-logout",
		"exp":     time.Now().Add(time.Hour).Unix(),
	}).SignedString([]byte("test-secret"))
	if err != nil {
		t.Fatal(err)
	}
	router.POST("/logout", func(c *gin.Context) {
		c.Set("token", hmacToken)
		c.Next()
	}, handlers.Logout)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/logout", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if handlers.services.TokenBlacklist.IsBlacklisted(context.Background(), "jti-hmac-logout") {
		t.Error("an HMAC token must not be parsed or blacklisted by Logout any more")
	}
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
