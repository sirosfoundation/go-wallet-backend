package engine

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

func TestManager_validateToken_UserID(t *testing.T) {
	cfg := &config.Config{
		JWT: config.JWTConfig{
			Secret: "test-secret",
		},
	}
	logger := zap.NewNop()
	m := NewManager(cfg, logger)

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id":   "test-user-123",
		"tenant_id": "test-tenant",
		"exp":       time.Now().Add(time.Hour).Unix(),
	})
	tokenString, err := token.SignedString([]byte("test-secret"))
	require.NoError(t, err)

	userID, tenantID, err := m.validateToken(tokenString)
	require.NoError(t, err)
	assert.Equal(t, "test-user-123", userID)
	assert.Equal(t, "test-tenant", tenantID)
}

func TestManager_validateToken_UUID(t *testing.T) {
	// Test wallet-backend-server compatibility: token has "uuid" instead of "user_id"
	cfg := &config.Config{
		JWT: config.JWTConfig{
			Secret: "test-secret",
		},
	}
	logger := zap.NewNop()
	m := NewManager(cfg, logger)

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"uuid": "uuid-user-456",
		"v":    1, // wallet-backend-server includes version
		"exp":  time.Now().Add(time.Hour).Unix(),
	})
	tokenString, err := token.SignedString([]byte("test-secret"))
	require.NoError(t, err)

	userID, tenantID, err := m.validateToken(tokenString)
	require.NoError(t, err)
	assert.Equal(t, "uuid-user-456", userID)
	assert.Empty(t, tenantID) // wallet-backend-server tokens don't have tenant_id
}

func TestManager_validateToken_UserIDTakesPrecedence(t *testing.T) {
	// When both user_id and uuid are present, user_id should take precedence
	cfg := &config.Config{
		JWT: config.JWTConfig{
			Secret: "test-secret",
		},
	}
	logger := zap.NewNop()
	m := NewManager(cfg, logger)

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": "native-user",
		"uuid":    "compat-user",
		"exp":     time.Now().Add(time.Hour).Unix(),
	})
	tokenString, err := token.SignedString([]byte("test-secret"))
	require.NoError(t, err)

	userID, _, err := m.validateToken(tokenString)
	require.NoError(t, err)
	assert.Equal(t, "native-user", userID)
}

func TestManager_validateToken_MissingBothUserIDAndUUID(t *testing.T) {
	cfg := &config.Config{
		JWT: config.JWTConfig{
			Secret: "test-secret",
		},
	}
	logger := zap.NewNop()
	m := NewManager(cfg, logger)

	// Create token without user_id or uuid
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"some_other_claim": "value",
		"exp":              time.Now().Add(time.Hour).Unix(),
	})
	tokenString, err := token.SignedString([]byte("test-secret"))
	require.NoError(t, err)

	_, _, err = m.validateToken(tokenString)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing user_id or uuid")
}

func TestManager_validateToken_InvalidSigningMethod(t *testing.T) {
	cfg := &config.Config{
		JWT: config.JWTConfig{
			Secret: "test-secret",
		},
	}
	logger := zap.NewNop()
	m := NewManager(cfg, logger)

	// Create token with None signing method (not HMAC)
	token := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims{
		"user_id": "test-user",
		"exp":     time.Now().Add(time.Hour).Unix(),
	})
	tokenString, _ := token.SignedString(jwt.UnsafeAllowNoneSignatureType)

	_, _, err := m.validateToken(tokenString)
	assert.Error(t, err)
}

func TestManager_validateToken_ExpiredToken(t *testing.T) {
	cfg := &config.Config{
		JWT: config.JWTConfig{
			Secret: "test-secret",
		},
	}
	logger := zap.NewNop()
	m := NewManager(cfg, logger)

	// Create expired token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": "test-user",
		"exp":     time.Now().Add(-time.Hour).Unix(),
	})
	tokenString, err := token.SignedString([]byte("test-secret"))
	require.NoError(t, err)

	_, _, err = m.validateToken(tokenString)
	assert.Error(t, err)
}

func TestManager_validateToken_WrongSecret(t *testing.T) {
	cfg := &config.Config{
		JWT: config.JWTConfig{
			Secret: "correct-secret",
		},
	}
	logger := zap.NewNop()
	m := NewManager(cfg, logger)

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": "test-user",
		"exp":     time.Now().Add(time.Hour).Unix(),
	})
	tokenString, err := token.SignedString([]byte("wrong-secret"))
	require.NoError(t, err)

	_, _, err = m.validateToken(tokenString)
	assert.Error(t, err)
}
