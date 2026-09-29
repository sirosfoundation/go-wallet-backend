package server

import (
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
		{"AS disabled logs nothing", config.ASConfig{Legacy: config.ASLegacyConfig{Enabled: true}}, "", "", true},
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
