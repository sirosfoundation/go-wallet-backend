package engine

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
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

// testBearerToken stands in for middleware.ExtractBearerToken (which the
// engine package cannot import: pkg/middleware depends on the engine).
func testBearerToken(r *http.Request) string {
	_, tok, _ := strings.Cut(r.Header.Get("Authorization"), " ")
	return strings.TrimSpace(tok)
}
