package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

func TestLogLegacyTokenStatus(t *testing.T) {
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	ts := func(d time.Duration) string { return now.Add(d).Format(time.RFC3339) }
	cases := []struct {
		name    string
		as      config.ASConfig
		want    string
		level   string
		nothing bool
	}{
		{"AS disabled logs nothing", config.ASConfig{Legacy: config.ASLegacyConfig{Enabled: true}}, "", "", true},
		{"disabled", config.ASConfig{Enabled: true}, "disabled (as.legacy.enabled=false)", "info", false},
		{"sunset passed", config.ASConfig{Enabled: true, Legacy: config.ASLegacyConfig{Enabled: true, SunsetDate: ts(-time.Second)}}, "sunset_date has passed", "warn", false},
		{"exactly at sunset", config.ASConfig{Enabled: true, Legacy: config.ASLegacyConfig{Enabled: true, SunsetDate: ts(0)}}, "sunset_date has passed", "warn", false},
		{"inside 30 days", config.ASConfig{Enabled: true, Legacy: config.ASLegacyConfig{Enabled: true, SunsetDate: ts(30 * 24 * time.Hour)}}, "DEPRECATION", "warn", false},
		{"just outside 30 days", config.ASConfig{Enabled: true, Legacy: config.ASLegacyConfig{Enabled: true, SunsetDate: ts(30*24*time.Hour + time.Second)}}, "enabled until", "info", false},
		{"no sunset", config.ASConfig{Enabled: true, Legacy: config.ASLegacyConfig{Enabled: true}}, "no as.legacy.sunset_date", "info", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			core, logs := observer.New(zap.InfoLevel)
			LogLegacyTokenStatus(&config.Config{AS: tc.as}, zap.New(core), now)
			if tc.nothing {
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
	past := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
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
	c.AS.Legacy = config.ASLegacyConfig{Enabled: true, SunsetDate: past}
	assert.Equal(t, 200, status(c))
	// AS enabled, sunset passed: refused.
	c.AS.Enabled = true
	assert.Equal(t, 410, status(c))
	// AS enabled, legacy active: open.
	c.AS.Legacy.SunsetDate = ""
	assert.Equal(t, 200, status(c))
}
