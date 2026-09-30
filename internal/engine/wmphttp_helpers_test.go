package engine

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

// Shared helpers for the WMP HTTP tests.

const testSecret = "test-secret-for-wmp"

func testManager() *Manager {
	cfg := &config.Config{
		JWT: config.JWTConfig{
			Secret: testSecret,
		},
	}
	return NewManager(cfg, zap.NewNop())
}

func testToken(userID, tenantID string) string {
	claims := jwt.MapClaims{
		"user_id": userID,
		"exp":     time.Now().Add(time.Hour).Unix(),
	}
	if tenantID != "" {
		claims["tenant_id"] = tenantID
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	s, _ := token.SignedString([]byte(testSecret))
	return s
}

func expiredToken(userID string) string {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": userID,
		"exp":     time.Now().Add(-time.Hour).Unix(),
	})
	s, _ := token.SignedString([]byte(testSecret))
	return s
}

// --- HandleRPC tests ---

func TestWriteBodyReadError_Generic400(t *testing.T) {
	w := httptest.NewRecorder()
	writeBodyReadError(w, errors.New("boom"))
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestExtractBearerToken(t *testing.T) {
	tests := []struct {
		name   string
		header string
		want   string
	}{
		{"valid", "Bearer abc123", "abc123"},
		{"no prefix", "abc123", ""},
		{"empty", "", ""},
		{"basic", "Basic abc123", ""},
		{"bearer lowercase", "bearer abc", "abc"},
		{"bearer uppercase", "BEARER abc", "abc"},
		{"bearer mixed case", "bEaReR abc", "abc"},
		{"whitespace trimmed", "Bearer  abc ", "abc"},
		{"scheme only", "Bearer", ""},
		{"scheme with empty token", "Bearer ", ""},
		{"no separator", "Bearerabc", ""},
		{"longer scheme", "Bearers abc", ""},
		{"leading space", " Bearer abc", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tt.header != "" {
				req.Header.Set("Authorization", tt.header)
			}
			assert.Equal(t, tt.want, extractBearerToken(req))
		})
	}
}
