package server

import (
	"context"
	"strings"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage/memory"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

func TestLogLegacyTokenStatus(t *testing.T) {
	cases := []struct {
		name  string
		as    config.ASConfig
		want  string
		level string
		none  bool
	}{
		{"no AS, unloaded config: HMAC is the only mechanism", config.ASConfig{}, "enabled", "info", false},
		{"enabled", config.ASConfig{Enabled: true, Legacy: config.ASLegacyConfig{Enabled: true}}, "enabled", "info", false},
		{"disabled", config.ASConfig{Enabled: true}, "DISABLED", "warn", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			core, logs := observer.New(zap.InfoLevel)
			LogLegacyTokenStatus(&config.Config{AS: tc.as}, zap.New(core))
			if tc.none {
				assert.Equal(t, 0, logs.Len())
				return
			}
			require.Equal(t, 1, logs.Len())
			assert.Contains(t, logs.All()[0].Message, tc.want)
			assert.Equal(t, tc.level, logs.All()[0].Level.String())
		})
	}
}

func TestAuthProvider_legacyIssuanceGate(t *testing.T) {
	gin.SetMode(gin.TestMode)
	status := func(cfg *config.Config) int {
		p := &AuthProvider{cfg: cfg}
		r := gin.New()
		r.POST("/x", p.legacyIssuanceGate(), func(c *gin.Context) { c.Status(200) })
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/x", nil))
		return w.Code
	}
	// AS disabled: HMAC is the only mechanism, gate is a no-op.
	c := &config.Config{}
	assert.Equal(t, 200, status(c))
	// AS enabled, legacy disabled: refused.
	c.AS.Enabled = true
	assert.Equal(t, 410, status(c))
	// AS enabled, legacy enabled: open.
	c.AS.Legacy.Enabled = true
	assert.Equal(t, 200, status(c))
}

// With the AS disabled but legacy disabled (loaded config semantics), the
// /user/* issuance routes must still answer 410 - and before the OIDC gate.
func TestAuthProvider_legacyIssuanceGate_NoASStillGated(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfg := &config.Config{}
	cfg.AS.Enabled = true // unloaded configs only honour the switch with the AS on
	p := &AuthProvider{cfg: cfg}
	reached := false
	r := gin.New()
	r.POST("/x", p.legacyIssuanceGate(), func(c *gin.Context) { reached = true; c.Status(200) })
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/x", nil))
	assert.Equal(t, 410, w.Code)
	assert.False(t, reached)
}

// With legacy disabled, every /user/* route that mints HS256 tokens answers
// 410 - before the OIDC gate - and this must not depend on the AS being
// enabled in this process.
func TestAuthProvider_UserRoutes_410BeforeOIDCGate(t *testing.T) {
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
	cfg := minimalTestConfig()
	cfg.AS.Enabled = true // unloaded config: the switch is honoured with the AS on
	cfg.AS.Legacy.Enabled = false
	p := NewAuthProvider(cfg, store, zap.NewNop(), nil)
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

// Providers must not log the legacy status themselves: cmd/server/main.go
// logs it once per process for every role combination.
func TestProviders_DoNotLogLegacyStatus(t *testing.T) {
	core, logs := observer.New(zap.DebugLevel)
	p, err := NewWalletProviderProvider(walletProviderASConfig(t, "", true), zap.New(core))
	require.NoError(t, err)
	defer func() { _ = p.Close() }()
	for _, e := range logs.All() {
		assert.NotContains(t, e.Message, "Legacy HMAC session tokens")
	}
}
