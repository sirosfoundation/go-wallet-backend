package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage/memory"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

func boolPtr(b bool) *bool { return &b }

// Every process logs once that the legacy AS is gone.
func TestLogLegacyTokenStatus_ReportsRemoval(t *testing.T) {
	core, logs := observer.New(zap.InfoLevel)
	LogLegacyTokenStatus(&config.Config{}, zap.New(core))
	require.Equal(t, 1, logs.Len())
	assert.Equal(t, "info", logs.All()[0].Level.String())
	assert.Contains(t, logs.All()[0].Message, "has been removed")
}

// Leftover settings are warned about, one warning per setting, before the
// removal notice.
func TestLogLegacyTokenStatus_WarnsAboutRemovedSettings(t *testing.T) {
	core, logs := observer.New(zap.InfoLevel)
	cfg := &config.Config{
		AS:  config.ASConfig{Legacy: config.ASLegacyConfig{Enabled: boolPtr(false), SunsetDate: "2027-10-01T00:00:00Z"}},
		JWT: config.JWTConfig{RefreshDays: 7},
	}
	LogLegacyTokenStatus(cfg, zap.New(core))
	require.Equal(t, 4, logs.Len(), "three warnings plus the removal notice")
	var settings []string
	for _, e := range logs.All()[:3] {
		assert.Equal(t, "warn", e.Level.String())
		settings = append(settings, e.ContextMap()["setting"].(string))
	}
	joined := strings.Join(settings, " ")
	for _, want := range []string{"as.legacy.enabled", "as.legacy.sunset_date", "jwt.refresh_days"} {
		assert.Contains(t, joined, want)
	}
}

// The /user/* endpoints that used to mint HS256 tokens answer 410 (before any
// tenant or OIDC gate logic), so an old client gets a clear error.
func TestAuthProvider_RemovedLegacyUserRoutes_Answer410(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store := memory.NewStore()
	require.NoError(t, store.Tenants().Create(context.Background(), &domain.Tenant{
		ID: "gated", Name: "Gated", Enabled: true,
		OIDCGate: domain.OIDCGateConfig{
			Mode:           domain.OIDCGateModeBoth,
			RegistrationOP: &domain.OIDCProviderConfig{Issuer: "https://idp.example.com", ClientID: "c"},
			LoginOP:        &domain.OIDCProviderConfig{Issuer: "https://idp.example.com", ClientID: "c"},
		},
	}))
	p := NewAuthProvider(minimalTestConfig(), store, zap.NewNop(), nil)
	router := gin.New()
	p.RegisterRoutes(router)

	for _, path := range []string{
		"/user/register-webauthn-begin", "/user/register-webauthn-finish",
		"/user/login-webauthn-begin", "/user/login-webauthn-finish",
		"/user/session/refresh",
	} {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{}`))
		req.Header.Set("X-Tenant-ID", "gated")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		assert.Equal(t, 410, w.Code, path)
		assert.Contains(t, w.Body.String(), "legacy_tokens_disabled", path)
	}
}

// Providers must not log the legacy status; cmd/server/main.go does, once.
func TestProviders_DoNotLogLegacyStatus(t *testing.T) {
	core, logs := observer.New(zap.DebugLevel)
	p, err := NewWalletProviderProvider(walletProviderASConfig(t, "https://as.example.com"), zap.New(core))
	require.NoError(t, err)
	defer func() { _ = p.Close() }()
	for _, e := range logs.All() {
		assert.NotContains(t, e.Message, "legacy HMAC authorization server")
	}
}
