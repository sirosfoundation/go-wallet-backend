package websocket

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

func TestNewManager(t *testing.T) {
	cfg := &config.Config{
		JWT: config.JWTConfig{
			Secret: "test-secret",
		},
	}
	logger := zap.NewNop()

	m := NewManager(cfg, logger)
	assert.NotNil(t, m)
	assert.NotNil(t, m.clients)
	assert.Empty(t, m.clients)
}

func TestManager_IsConnected_NoClient(t *testing.T) {
	cfg := &config.Config{
		JWT: config.JWTConfig{
			Secret: "test-secret",
		},
	}
	logger := zap.NewNop()

	m := NewManager(cfg, logger)
	assert.False(t, m.IsConnected("user-123"))
}

func TestManager_Close(t *testing.T) {
	cfg := &config.Config{
		JWT: config.JWTConfig{
			Secret: "test-secret",
		},
	}
	logger := zap.NewNop()

	m := NewManager(cfg, logger)
	m.Close()
	assert.Empty(t, m.clients)
}

func TestManager_WebSocketHandshake(t *testing.T) {
	cfg := &config.Config{
		JWT: config.JWTConfig{
			Secret: "test-secret",
		},
	}
	logger := zap.NewNop()

	m := NewManager(cfg, logger)

	// Create test server
	server := httptest.NewServer(http.HandlerFunc(m.HandleConnection))
	defer server.Close()

	// Convert HTTP URL to WebSocket URL
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")

	// Connect WebSocket client
	ws, resp, err := websocket.DefaultDialer.Dial(wsURL, nil)
	require.NoError(t, err)
	require.Equal(t, 101, resp.StatusCode)
	defer func() { _ = ws.Close() }()

	// Create valid JWT token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": "test-user-123",
		"exp":     time.Now().Add(time.Hour).Unix(),
	})
	tokenString, err := token.SignedString([]byte("test-secret"))
	require.NoError(t, err)

	// Send handshake message
	handshake := ClientMessage{
		AppToken: tokenString,
	}
	err = ws.WriteJSON(handshake)
	require.NoError(t, err)

	// Read response
	_, message, err := ws.ReadMessage()
	require.NoError(t, err)

	var response ServerMessage
	err = json.Unmarshal(message, &response)
	require.NoError(t, err)
	assert.Equal(t, "FIN_INIT", response.Type)

	// Verify client is now connected
	time.Sleep(50 * time.Millisecond) // Give time for registration
	assert.True(t, m.IsConnected("test-user-123"))
}

func TestManager_WebSocketInvalidToken(t *testing.T) {
	cfg := &config.Config{
		JWT: config.JWTConfig{
			Secret: "test-secret",
		},
	}
	logger := zap.NewNop()

	m := NewManager(cfg, logger)

	// Create test server
	server := httptest.NewServer(http.HandlerFunc(m.HandleConnection))
	defer server.Close()

	// Connect WebSocket client
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")
	ws, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	require.NoError(t, err)
	defer func() { _ = ws.Close() }()

	// Send handshake with invalid token
	handshake := ClientMessage{
		AppToken: "invalid-token",
	}
	err = ws.WriteJSON(handshake)
	require.NoError(t, err)

	// Read error response
	_, message, err := ws.ReadMessage()
	require.NoError(t, err)

	var response ServerMessage
	err = json.Unmarshal(message, &response)
	require.NoError(t, err)
	assert.Equal(t, "ERROR", response.Type)
	assert.Equal(t, "auth_failed", response.MessageID)
}

// TestManager_ConnectionLimit_CountsUnhandshakedConnections is a regression
// test: an upgraded connection that never sends a handshake must still count
// against the connection limit. Before this fix, the limit only counted
// len(m.clients), which is populated post-handshake — letting an attacker
// open unlimited unauthenticated connections without ever being counted.
func TestManager_ConnectionLimit_CountsUnhandshakedConnections(t *testing.T) {
	cfg := &config.Config{JWT: config.JWTConfig{Secret: "test-secret"}}
	m := NewManager(cfg, zap.NewNop())

	server := httptest.NewServer(http.HandlerFunc(m.HandleConnection))
	defer server.Close()
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")

	ws, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	require.NoError(t, err)
	defer func() { _ = ws.Close() }()

	// Never send a handshake message. Give the server a moment to register
	// the upgraded connection.
	require.Eventually(t, func() bool {
		return m.activeConnections.Load() == 1
	}, time.Second, 10*time.Millisecond, "unhandshaked connection was not counted")

	// The old (buggy) check would have seen this as zero load.
	assert.Empty(t, m.clients, "connection never handshaked, so it must not appear in clients")

	require.NoError(t, ws.Close())
	require.Eventually(t, func() bool {
		return m.activeConnections.Load() == 0
	}, time.Second, 10*time.Millisecond, "connection count did not decrement after close")
}

// TestManager_ConnectionLimit_RejectsAtCapacity is a regression test: once
// activeConnections is at capacity, new connection attempts are rejected with
// 503 even if m.clients is empty (i.e. even if nobody has handshaked yet).
func TestManager_ConnectionLimit_RejectsAtCapacity(t *testing.T) {
	cfg := &config.Config{JWT: config.JWTConfig{Secret: "test-secret"}}
	m := NewManager(cfg, zap.NewNop())
	m.activeConnections.Store(maxConnections)

	server := httptest.NewServer(http.HandlerFunc(m.HandleConnection))
	defer server.Close()

	resp, err := http.Get(server.URL)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	assert.Empty(t, m.clients, "rejection must not depend on clients being non-empty")
}

func TestSignatureAction_Constants(t *testing.T) {
	assert.Equal(t, SignatureAction("generateOpenid4vciProof"), ActionGenerateOpenid4vciProof)
	assert.Equal(t, SignatureAction("signJwtPresentation"), ActionSignJwtPresentation)
}

func TestServerMessage_JSON(t *testing.T) {
	msg := ServerMessage{
		MessageID: "test-123",
		Type:      "FIN_INIT",
	}

	data, err := json.Marshal(msg)
	require.NoError(t, err)

	var parsed ServerMessage
	err = json.Unmarshal(data, &parsed)
	require.NoError(t, err)

	assert.Equal(t, msg.MessageID, parsed.MessageID)
	assert.Equal(t, msg.Type, parsed.Type)
}

func TestSigningRequest_JSON(t *testing.T) {
	req := SigningRequest{
		Action:   ActionSignJwtPresentation,
		Nonce:    "test-nonce",
		Audience: "https://verifier.example.com",
		VerifiableCredentials: []interface{}{
			map[string]interface{}{"type": "TestCredential"},
		},
	}

	data, err := json.Marshal(req)
	require.NoError(t, err)

	var parsed SigningRequest
	err = json.Unmarshal(data, &parsed)
	require.NoError(t, err)

	assert.Equal(t, req.Action, parsed.Action)
	assert.Equal(t, req.Nonce, parsed.Nonce)
	assert.Equal(t, req.Audience, parsed.Audience)
	assert.Len(t, parsed.VerifiableCredentials, 1)
}

func TestSigningResponse_JSON(t *testing.T) {
	resp := SigningResponse{
		Action: ActionSignJwtPresentation,
		VPJWT:  "eyJhbGciOiJFUzI1NiJ9...",
	}

	data, err := json.Marshal(resp)
	require.NoError(t, err)

	var parsed SigningResponse
	err = json.Unmarshal(data, &parsed)
	require.NoError(t, err)

	assert.Equal(t, resp.Action, parsed.Action)
	assert.Equal(t, resp.VPJWT, parsed.VPJWT)
}

func TestManager_SendSigningRequest_UserNotConnected(t *testing.T) {
	cfg := &config.Config{
		JWT: config.JWTConfig{
			Secret: "test-secret",
		},
	}
	logger := zap.NewNop()

	m := NewManager(cfg, logger)
	ctx := context.Background()

	_, err := m.SendSigningRequest(ctx, "nonexistent-user", &SigningRequest{
		Action: ActionSignJwtPresentation,
		Nonce:  "test-nonce",
	})
	assert.ErrorIs(t, err, ErrUserNotConnected)
}

func TestManager_GenerateOpenid4vciProof_UserNotConnected(t *testing.T) {
	cfg := &config.Config{
		JWT: config.JWTConfig{
			Secret: "test-secret",
		},
	}
	logger := zap.NewNop()

	m := NewManager(cfg, logger)
	ctx := context.Background()

	_, err := m.GenerateOpenid4vciProof(ctx, "nonexistent-user", "aud", "nonce")
	assert.ErrorIs(t, err, ErrUserNotConnected)
}

func TestManager_SignJwtPresentation_UserNotConnected(t *testing.T) {
	cfg := &config.Config{
		JWT: config.JWTConfig{
			Secret: "test-secret",
		},
	}
	logger := zap.NewNop()

	m := NewManager(cfg, logger)
	ctx := context.Background()

	_, err := m.SignJwtPresentation(ctx, "nonexistent-user", "nonce", "aud", nil)
	assert.ErrorIs(t, err, ErrUserNotConnected)
}

func TestClientMessage_JSON(t *testing.T) {
	msg := ClientMessage{
		MessageID: "msg-123",
		AppToken:  "token-456",
		Response: &SigningResponse{
			Action:   ActionGenerateOpenid4vciProof,
			ProofJWT: "eyJ...",
		},
	}

	data, err := json.Marshal(msg)
	require.NoError(t, err)

	var parsed ClientMessage
	err = json.Unmarshal(data, &parsed)
	require.NoError(t, err)

	assert.Equal(t, msg.MessageID, parsed.MessageID)
	assert.Equal(t, msg.AppToken, parsed.AppToken)
	assert.NotNil(t, parsed.Response)
	assert.Equal(t, msg.Response.Action, parsed.Response.Action)
	assert.Equal(t, msg.Response.ProofJWT, parsed.Response.ProofJWT)
}

func TestManager_validateToken_InvalidSigningMethod(t *testing.T) {
	cfg := &config.Config{
		JWT: config.JWTConfig{
			Secret: "test-secret",
		},
	}
	logger := zap.NewNop()

	m := NewManager(cfg, logger)

	// Create token with RS256 (not HMAC)
	token := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims{
		"user_id": "test-user",
		"exp":     time.Now().Add(time.Hour).Unix(),
	})
	tokenString, _ := token.SignedString(jwt.UnsafeAllowNoneSignatureType)

	_, err := m.validateToken(tokenString)
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

	_, err = m.validateToken(tokenString)
	assert.Error(t, err)
}

func TestManager_validateToken_MissingUserID(t *testing.T) {
	cfg := &config.Config{
		JWT: config.JWTConfig{
			Secret: "test-secret",
		},
	}
	logger := zap.NewNop()

	m := NewManager(cfg, logger)

	// Create token without user_id
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	tokenString, err := token.SignedString([]byte("test-secret"))
	require.NoError(t, err)

	_, err = m.validateToken(tokenString)
	assert.Error(t, err)
}

func TestManager_validateToken_ValidToken(t *testing.T) {
	cfg := &config.Config{
		JWT: config.JWTConfig{
			Secret: "test-secret",
		},
	}
	logger := zap.NewNop()

	m := NewManager(cfg, logger)

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": "test-user-123",
		"exp":     time.Now().Add(time.Hour).Unix(),
	})
	tokenString, err := token.SignedString([]byte("test-secret"))
	require.NoError(t, err)

	userID, err := m.validateToken(tokenString)
	require.NoError(t, err)
	assert.Equal(t, "test-user-123", userID)
}

func TestManager_validateToken_NbfSlightlyInFuture(t *testing.T) {
	cfg := &config.Config{
		JWT: config.JWTConfig{
			Secret: "test-secret",
		},
	}
	logger := zap.NewNop()
	m := NewManager(cfg, logger)

	// Token with nbf 2 seconds in the future — within the 5s leeway
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": "test-user",
		"nbf":     time.Now().Add(2 * time.Second).Unix(),
		"exp":     time.Now().Add(time.Hour).Unix(),
	})
	tokenString, err := token.SignedString([]byte("test-secret"))
	require.NoError(t, err)

	userID, err := m.validateToken(tokenString)
	require.NoError(t, err)
	assert.Equal(t, "test-user", userID)
}

func TestErrorVariables(t *testing.T) {
	assert.Equal(t, "user not connected", ErrUserNotConnected.Error())
	assert.Equal(t, "wrong message id", ErrWrongMessageID.Error())
	assert.Equal(t, "wrong action", ErrWrongAction.Error())
	assert.Equal(t, "failed to receive message", ErrFailedToReceive.Error())
	assert.Equal(t, "remote signing failed", ErrRemoteSigningFailed.Error())
	assert.Equal(t, "operation timed out", ErrTimeout.Error())
}
