package websocket

import (
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
	defer ws.Close()

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
	defer ws.Close()

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
