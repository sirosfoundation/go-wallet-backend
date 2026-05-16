package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

// --- Helpers ---

const testJWTSecret = "test-secret-for-stress-tests-minimum-32-chars"

func stressConfig() *config.Config {
	return &config.Config{
		Server: config.ServerConfig{
			RegistryPort: 8097,
		},
		JWT: config.JWTConfig{
			Secret: testJWTSecret,
		},
		HTTPClient: config.HTTPClientConfig{
			AllowPrivateIPs: true,
		},
	}
}

// generateToken creates a signed JWT for testing. A negative duration produces
// an already-expired token.
func generateToken(userID, tenantID string, lifetime time.Duration) string {
	claims := jwt.MapClaims{
		"user_id":   userID,
		"tenant_id": tenantID,
		"exp":       time.Now().Add(lifetime).Unix(),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	s, _ := tok.SignedString([]byte(testJWTSecret))
	return s
}

// engineServer spins up an httptest.Server backed by a real engine Manager.
// It returns the manager, a WebSocket-connectable URL, and a cleanup function.
func engineServer(t *testing.T, cfg *config.Config) (*Manager, string, func()) {
	t.Helper()
	logger, _ := zap.NewDevelopment()
	m := NewManager(cfg, logger)

	// Register a minimal OID4VCI handler that echoes progress and completes.
	// Real flows require an issuer; we register a stub that exercises the
	// flow lifecycle (start → progress → sign → complete/error).
	m.RegisterFlowHandler(ProtocolOID4VCI, stubVCIHandlerFactory)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.HandleConnection(w, r)
	}))
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")
	return m, wsURL, func() { server.Close() }
}

// wsConnect dials the engine WebSocket, performs the handshake, and returns
// the connection and session ID.
func wsConnect(t *testing.T, wsURL, token string) (*websocket.Conn, string) {
	t.Helper()
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	require.NoError(t, err)

	// Send handshake
	hs := HandshakeMessage{
		Message:  Message{Type: TypeHandshake, Timestamp: Now()},
		AppToken: token,
	}
	require.NoError(t, conn.WriteJSON(hs))

	// Read response
	_, data, err := conn.ReadMessage()
	require.NoError(t, err)
	var msg Message
	require.NoError(t, json.Unmarshal(data, &msg))

	if msg.Type == TypeError {
		t.Fatalf("handshake failed: %s", string(data))
	}
	require.Equal(t, TypeHandshakeComplete, msg.Type)

	var complete HandshakeCompleteMessage
	require.NoError(t, json.Unmarshal(data, &complete))
	return conn, complete.SessionID
}

// readMessage reads and parses the next message from the WebSocket with a timeout.
func readMessage(t *testing.T, conn *websocket.Conn, timeout time.Duration) (MessageType, json.RawMessage) {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	_, data, err := conn.ReadMessage()
	require.NoError(t, err)

	var msg Message
	require.NoError(t, json.Unmarshal(data, &msg))
	return msg.Type, data
}

// readUntilType reads messages until it finds one of the specified type, or times out.
func readUntilType(t *testing.T, conn *websocket.Conn, target MessageType, timeout time.Duration) json.RawMessage {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		remaining := time.Until(deadline)
		if remaining < 0 {
			break
		}
		_ = conn.SetReadDeadline(time.Now().Add(remaining))
		_, data, err := conn.ReadMessage()
		if err != nil {
			t.Fatalf("readUntilType(%s): %v", target, err)
		}
		var msg Message
		if err := json.Unmarshal(data, &msg); err != nil {
			continue
		}
		if msg.Type == target {
			return data
		}
	}
	t.Fatalf("timed out waiting for message type %s", target)
	return nil
}

// startFlow sends a flow_start message and returns the flow ID.
func startFlow(t *testing.T, conn *websocket.Conn, protocol Protocol, offer string) string {
	t.Helper()
	flowID := fmt.Sprintf("test-flow-%d", time.Now().UnixNano())
	msg := FlowStartMessage{
		Message:  Message{Type: TypeFlowStart, FlowID: flowID, Timestamp: Now()},
		Protocol: protocol,
		Offer:    offer,
	}
	require.NoError(t, conn.WriteJSON(msg))
	return flowID
}

// --- Stub flow handler ---

// stubVCIHandler is a minimal OID4VCI handler for stress testing.
// It requests a sign operation from the client, waits for the response,
// and then completes (or errors if the sign times out).
type stubVCIHandler struct {
	flow   *Flow
	logger *zap.Logger
	cancel func()
}

func stubVCIHandlerFactory(flow *Flow, _ *config.Config, logger *zap.Logger, _ *TrustService, _ *RegistryClient, _ storage.VerifierStore, _ *TrustCache) (FlowHandler, error) {
	return &stubVCIHandler{flow: flow, logger: logger}, nil
}

func (h *stubVCIHandler) Execute(ctx context.Context, msg *FlowStartMessage) error {
	session := h.flow.Session

	// Step 1: send progress
	_ = session.SendProgress(h.flow.ID, StepParsingOffer, nil)
	_ = session.SendProgress(h.flow.ID, StepFetchingMetadata, nil)

	// Step 2: request signing from the client
	signReq := &SignRequestMessage{
		Message: Message{
			Type:      TypeSignRequest,
			FlowID:    h.flow.ID,
			MessageID: fmt.Sprintf("sign-%d", time.Now().UnixNano()),
			Timestamp: Now(),
		},
		Action: SignActionGenerateProof,
		Params: SignRequestParams{
			Audience: "https://test-issuer.example",
			Nonce:    "test-nonce",
		},
	}
	if err := session.Send(signReq); err != nil {
		_ = session.SendFlowError(h.flow.ID, StepRequestingCredential, ErrCodeSignError, "failed to send sign request")
		return err
	}

	// Step 3: wait for sign response (with timeout from context)
	select {
	case resp := <-session.signCh:
		if resp.ProofJWT == "" && len(resp.Proofs) == 0 {
			_ = session.SendFlowError(h.flow.ID, StepRequestingCredential, ErrCodeSignError, "empty proof")
			return fmt.Errorf("empty proof")
		}
		h.logger.Debug("Received sign response", zap.String("flow_id", h.flow.ID))
	case <-ctx.Done():
		_ = session.SendFlowError(h.flow.ID, StepRequestingCredential, ErrCodeSignTimeout, "sign timeout")
		return fmt.Errorf("sign timeout")
	case <-session.closeCh:
		return fmt.Errorf("session closed")
	}

	// Step 4: complete
	complete := &FlowCompleteMessage{
		Message: Message{
			Type:      TypeFlowComplete,
			FlowID:    h.flow.ID,
			Timestamp: Now(),
		},
		Credentials: []CredentialResult{
			{
				Format:     "jwt_vc_json",
				Credential: `{"test":"credential"}`,
			},
		},
	}
	return session.Send(complete)
}

func (h *stubVCIHandler) Cancel() {
	if h.cancel != nil {
		h.cancel()
	}
}

// --- Stress Tests ---

// TestStress_ExpiredTokenHandshake verifies that expired tokens are rejected
// at the WebSocket handshake.
func TestStress_ExpiredTokenHandshake(t *testing.T) {
	cfg := stressConfig()
	_, wsURL, cleanup := engineServer(t, cfg)
	defer cleanup()

	// Already-expired token
	token := generateToken("user-expired", "default", -1*time.Hour)

	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	require.NoError(t, err)
	defer conn.Close()

	hs := HandshakeMessage{
		Message:  Message{Type: TypeHandshake, Timestamp: Now()},
		AppToken: token,
	}
	require.NoError(t, conn.WriteJSON(hs))

	// Should get an error back
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, data, err := conn.ReadMessage()
	require.NoError(t, err)

	var msg ErrorMessage
	require.NoError(t, json.Unmarshal(data, &msg))
	assert.Equal(t, TypeError, msg.Type)
	assert.Equal(t, ErrCodeAuthFailed, msg.Code)
}

// TestStress_InvalidTokenHandshake verifies that garbage tokens are rejected.
func TestStress_InvalidTokenHandshake(t *testing.T) {
	cfg := stressConfig()
	_, wsURL, cleanup := engineServer(t, cfg)
	defer cleanup()

	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	require.NoError(t, err)
	defer conn.Close()

	hs := HandshakeMessage{
		Message:  Message{Type: TypeHandshake, Timestamp: Now()},
		AppToken: "not-a-real-token",
	}
	require.NoError(t, conn.WriteJSON(hs))

	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, data, err := conn.ReadMessage()
	require.NoError(t, err)

	var msg2 ErrorMessage
	require.NoError(t, json.Unmarshal(data, &msg2))
	assert.Equal(t, TypeError, msg2.Type)
	assert.Equal(t, ErrCodeAuthFailed, msg2.Code)
}

// TestStress_ShortLivedTokenMidFlow verifies behavior when the JWT expires
// during a flow. Since token is only checked at handshake, the flow should
// still complete.
func TestStress_ShortLivedTokenMidFlow(t *testing.T) {
	cfg := stressConfig()
	_, wsURL, cleanup := engineServer(t, cfg)
	defer cleanup()

	// Token that expires in 2 seconds
	token := generateToken("user-short-lived", "default", 2*time.Second)

	conn, _ := wsConnect(t, wsURL, token)
	defer conn.Close()

	// Start a flow
	flowID := startFlow(t, conn, ProtocolOID4VCI, "openid-credential-offer://test")

	// Wait for sign request (which means the flow is running)
	data := readUntilType(t, conn, TypeSignRequest, 10*time.Second)
	var signReq SignRequestMessage
	require.NoError(t, json.Unmarshal(data, &signReq))

	// Wait for the JWT to expire
	time.Sleep(3 * time.Second)

	// Send sign response — flow should still work since token isn't re-validated
	signResp := SignResponseMessage{
		Message: Message{
			Type:      TypeSignResponse,
			FlowID:    flowID,
			MessageID: signReq.MessageID,
			Timestamp: Now(),
		},
		ProofJWT: "eyJhbGciOiJFUzI1NiJ9.test.sig",
	}
	require.NoError(t, conn.WriteJSON(signResp))

	// Should get flow_complete
	data = readUntilType(t, conn, TypeFlowComplete, 10*time.Second)
	var complete FlowCompleteMessage
	require.NoError(t, json.Unmarshal(data, &complete))
	assert.Equal(t, flowID, complete.FlowID)
}

// TestStress_ConcurrentFlowLimit verifies that the MaxPendingFlowsPerSession
// limit is enforced.
func TestStress_ConcurrentFlowLimit(t *testing.T) {
	cfg := stressConfig()
	_, wsURL, cleanup := engineServer(t, cfg)
	defer cleanup()

	token := generateToken("user-concurrent", "default", time.Hour)
	conn, _ := wsConnect(t, wsURL, token)
	defer conn.Close()

	// Start MaxPendingFlowsPerSession flows (they'll block waiting for sign)
	for i := 0; i < MaxPendingFlowsPerSession; i++ {
		startFlow(t, conn, ProtocolOID4VCI, fmt.Sprintf("openid-credential-offer://test-%d", i))
	}

	// Wait for all sign requests (one per flow)
	for i := 0; i < MaxPendingFlowsPerSession; i++ {
		readUntilType(t, conn, TypeSignRequest, 10*time.Second)
	}

	// Now start one more — should get rejected
	extraFlowID := startFlow(t, conn, ProtocolOID4VCI, "openid-credential-offer://overflow")

	// Read the error
	data := readUntilType(t, conn, TypeFlowError, 10*time.Second)
	var errMsg FlowErrorMessage
	require.NoError(t, json.Unmarshal(data, &errMsg))
	assert.Equal(t, extraFlowID, errMsg.FlowID)
	assert.Equal(t, ErrCodeTooManyRequests, errMsg.Error.Code)
}

// TestStress_SessionReplacementDuringFlow verifies that connecting with the
// same user ID replaces the existing session and cancels active flows.
func TestStress_SessionReplacementDuringFlow(t *testing.T) {
	cfg := stressConfig()
	_, wsURL, cleanup := engineServer(t, cfg)
	defer cleanup()

	token := generateToken("user-replace", "default", time.Hour)

	// First connection — start a flow
	conn1, _ := wsConnect(t, wsURL, token)
	defer conn1.Close()

	startFlow(t, conn1, ProtocolOID4VCI, "openid-credential-offer://test")
	readUntilType(t, conn1, TypeSignRequest, 10*time.Second)

	// Second connection with same user — should kill conn1
	conn2, _ := wsConnect(t, wsURL, token)
	defer conn2.Close()

	// conn1 should be closed by the server
	_ = conn1.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, _, err := conn1.ReadMessage()
	assert.Error(t, err, "first connection should be closed after replacement")
}

// TestStress_ClientDisconnectMidFlow verifies that the server cleans up
// properly when the client disconnects in the middle of a flow.
func TestStress_ClientDisconnectMidFlow(t *testing.T) {
	cfg := stressConfig()
	m, wsURL, cleanup := engineServer(t, cfg)
	defer cleanup()

	token := generateToken("user-disconnect", "default", time.Hour)
	conn, _ := wsConnect(t, wsURL, token)

	startFlow(t, conn, ProtocolOID4VCI, "openid-credential-offer://test")
	readUntilType(t, conn, TypeSignRequest, 10*time.Second)

	// Abruptly close the connection (simulates browser tab close)
	conn.Close()

	// Give the server time to clean up
	time.Sleep(500 * time.Millisecond)

	// Verify session was cleaned up
	m.sessionsMu.RLock()
	_, exists := m.userIndex["user-disconnect"]
	m.sessionsMu.RUnlock()
	assert.False(t, exists, "session should be cleaned up after disconnect")
}

// TestStress_SlowSignResponse verifies behavior when the client takes a long
// time to respond to a sign request (simulates user thinking/slow network).
func TestStress_SlowSignResponse(t *testing.T) {
	cfg := stressConfig()
	_, wsURL, cleanup := engineServer(t, cfg)
	defer cleanup()

	token := generateToken("user-slow", "default", time.Hour)
	conn, _ := wsConnect(t, wsURL, token)
	defer conn.Close()

	flowID := startFlow(t, conn, ProtocolOID4VCI, "openid-credential-offer://test")
	data := readUntilType(t, conn, TypeSignRequest, 10*time.Second)
	var signReq SignRequestMessage
	require.NoError(t, json.Unmarshal(data, &signReq))

	// Simulate a 30-second delay (long user interaction)
	time.Sleep(30 * time.Second)

	// Send the response
	signResp := SignResponseMessage{
		Message: Message{
			Type:      TypeSignResponse,
			FlowID:    flowID,
			MessageID: signReq.MessageID,
			Timestamp: Now(),
		},
		ProofJWT: "eyJhbGciOiJFUzI1NiJ9.test.sig",
	}
	require.NoError(t, conn.WriteJSON(signResp))

	// Should still complete (flow timeout is 5 minutes)
	data = readUntilType(t, conn, TypeFlowComplete, 10*time.Second)
	var complete FlowCompleteMessage
	require.NoError(t, json.Unmarshal(data, &complete))
	assert.Equal(t, flowID, complete.FlowID)
}

// TestStress_RapidReconnect verifies that rapid disconnect/reconnect cycles
// don't leak sessions or goroutines.
func TestStress_RapidReconnect(t *testing.T) {
	cfg := stressConfig()
	m, wsURL, cleanup := engineServer(t, cfg)
	defer cleanup()

	const cycles = 10

	for i := 0; i < cycles; i++ {
		token := generateToken("user-rapid", "default", time.Hour)
		conn, _ := wsConnect(t, wsURL, token)

		// Optionally start a flow
		if i%2 == 0 {
			startFlow(t, conn, ProtocolOID4VCI, "openid-credential-offer://test")
			// Don't wait for sign — just disconnect immediately
		}
		conn.Close()
		time.Sleep(50 * time.Millisecond)
	}

	// Wait for cleanup
	time.Sleep(1 * time.Second)

	// Should have at most 1 session (or 0 if the last one was cleaned up)
	m.sessionsMu.RLock()
	count := len(m.sessions)
	m.sessionsMu.RUnlock()
	assert.LessOrEqual(t, count, 1, "should not leak sessions after rapid reconnect")
}

// TestStress_MultipleUsersConcurrent verifies that multiple users can run
// flows concurrently without interference.
func TestStress_MultipleUsersConcurrent(t *testing.T) {
	cfg := stressConfig()
	_, wsURL, cleanup := engineServer(t, cfg)
	defer cleanup()

	const numUsers = 5
	var wg sync.WaitGroup
	var successes atomic.Int32

	for i := 0; i < numUsers; i++ {
		wg.Add(1)
		go func(userIdx int) {
			defer wg.Done()

			userID := fmt.Sprintf("user-multi-%d", userIdx)
			token := generateToken(userID, "default", time.Hour)

			conn, _ := wsConnect(t, wsURL, token)
			defer conn.Close()

			flowID := startFlow(t, conn, ProtocolOID4VCI, "openid-credential-offer://test")

			// Wait for sign request
			data := readUntilType(t, conn, TypeSignRequest, 10*time.Second)
			var signReq SignRequestMessage
			if err := json.Unmarshal(data, &signReq); err != nil {
				return
			}

			// Respond
			signResp := SignResponseMessage{
				Message: Message{
					Type:      TypeSignResponse,
					FlowID:    flowID,
					MessageID: signReq.MessageID,
					Timestamp: Now(),
				},
				ProofJWT: "eyJhbGciOiJFUzI1NiJ9.test.sig",
			}
			if err := conn.WriteJSON(signResp); err != nil {
				return
			}

			// Wait for completion
			data = readUntilType(t, conn, TypeFlowComplete, 10*time.Second)
			var complete FlowCompleteMessage
			if err := json.Unmarshal(data, &complete); err != nil {
				return
			}
			if complete.FlowID == flowID {
				successes.Add(1)
			}
		}(i)
	}

	wg.Wait()
	assert.Equal(t, int32(numUsers), successes.Load(), "all users should complete their flows")
}

// TestStress_FlowStartBeforeHandshake verifies that sending a flow_start
// before the handshake is properly rejected (connection should close).
func TestStress_FlowStartBeforeHandshake(t *testing.T) {
	cfg := stressConfig()
	_, wsURL, cleanup := engineServer(t, cfg)
	defer cleanup()

	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	require.NoError(t, err)
	defer conn.Close()

	// Send flow_start without handshake first
	msg := FlowStartMessage{
		Message:  Message{Type: TypeFlowStart, FlowID: "rogue-flow", Timestamp: Now()},
		Protocol: ProtocolOID4VCI,
		Offer:    "openid-credential-offer://test",
	}
	require.NoError(t, conn.WriteJSON(msg))

	// Server should respond with error and close
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, data, err := conn.ReadMessage()
	require.NoError(t, err)

	var errMsg Message
	require.NoError(t, json.Unmarshal(data, &errMsg))
	assert.Equal(t, TypeError, errMsg.Type)
}

// TestStress_MalformedMessages verifies that malformed messages don't crash
// the server.
func TestStress_MalformedMessages(t *testing.T) {
	cfg := stressConfig()
	_, wsURL, cleanup := engineServer(t, cfg)
	defer cleanup()

	token := generateToken("user-malformed", "default", time.Hour)
	conn, _ := wsConnect(t, wsURL, token)
	defer conn.Close()

	malformed := []string{
		`{}`,
		`{"type":"flow_start"}`, // missing protocol
		`{"type":"flow_start","protocol":"oid4vci"}`,                                  // missing flow_id
		`{"type":"flow_action","flow_id":"nonexistent","action":"select_credential"}`, // unknown flow
		`not json at all`,
		`{"type":"sign_response","message_id":"orphan","proof_jwt":"test"}`, // no waiting flow
	}

	for _, msg := range malformed {
		err := conn.WriteMessage(websocket.TextMessage, []byte(msg))
		require.NoError(t, err, "writing malformed message should not fail")
	}

	// Connection should still be alive — send a valid flow_start and verify
	time.Sleep(500 * time.Millisecond)
	startFlow(t, conn, ProtocolOID4VCI, "openid-credential-offer://test")
	data := readUntilType(t, conn, TypeSignRequest, 10*time.Second)
	assert.NotNil(t, data, "connection should survive malformed messages")
}

// TestStress_ActionForCompletedFlow verifies that actions sent after a flow
// completes are handled gracefully (not crash or hang).
func TestStress_ActionForCompletedFlow(t *testing.T) {
	cfg := stressConfig()
	_, wsURL, cleanup := engineServer(t, cfg)
	defer cleanup()

	token := generateToken("user-stale-action", "default", time.Hour)
	conn, _ := wsConnect(t, wsURL, token)
	defer conn.Close()

	flowID := startFlow(t, conn, ProtocolOID4VCI, "openid-credential-offer://test")

	// Complete the flow normally
	data := readUntilType(t, conn, TypeSignRequest, 10*time.Second)
	var signReq SignRequestMessage
	require.NoError(t, json.Unmarshal(data, &signReq))

	signResp := SignResponseMessage{
		Message: Message{
			Type:      TypeSignResponse,
			FlowID:    flowID,
			MessageID: signReq.MessageID,
			Timestamp: Now(),
		},
		ProofJWT: "eyJhbGciOiJFUzI1NiJ9.test.sig",
	}
	require.NoError(t, conn.WriteJSON(signResp))
	readUntilType(t, conn, TypeFlowComplete, 10*time.Second)

	// Now send an action for the completed flow
	action := FlowActionMessage{
		Message: Message{Type: TypeFlowAction, FlowID: flowID, Timestamp: Now()},
		Action:  ActionSelectCredential,
	}
	require.NoError(t, conn.WriteJSON(action))

	// Should get UNKNOWN_FLOW error
	errData := readUntilType(t, conn, TypeFlowError, 5*time.Second)
	var errMsg FlowErrorMessage
	require.NoError(t, json.Unmarshal(errData, &errMsg))
	assert.Equal(t, ErrCodeUnknownFlow, errMsg.Error.Code)
}

// TestStress_WrongTenantToken verifies that tokens with different tenant IDs
// create separate sessions.
func TestStress_WrongTenantToken(t *testing.T) {
	cfg := stressConfig()
	m, wsURL, cleanup := engineServer(t, cfg)
	defer cleanup()

	token1 := generateToken("user-tenant", "tenant-a", time.Hour)
	conn1, sid1 := wsConnect(t, wsURL, token1)
	defer conn1.Close()

	// Same user, different tenant — should replace the session
	token2 := generateToken("user-tenant", "tenant-b", time.Hour)
	conn2, sid2 := wsConnect(t, wsURL, token2)
	defer conn2.Close()

	assert.NotEqual(t, sid1, sid2, "different sessions expected")

	// Original connection should be closed (same user_id, last connection wins)
	_ = conn1.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, _, err := conn1.ReadMessage()
	assert.Error(t, err, "first connection should be closed")

	// Manager should have exactly 1 session for this user
	m.sessionsMu.RLock()
	_, exists := m.userIndex["user-tenant"]
	m.sessionsMu.RUnlock()
	assert.True(t, exists)
}
