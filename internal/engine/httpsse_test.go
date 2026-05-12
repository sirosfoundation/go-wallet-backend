package engine

import (
	"bufio"
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

const testSecret = "test-secret-for-httpsse"

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

func TestHandleRPC_Handshake_CreatesSession(t *testing.T) {
	m := testManager()
	defer m.Close()

	body, _ := json.Marshal(Message{Type: TypeHandshake})
	req := httptest.NewRequest(http.MethodPost, "/api/v2/wallet/rpc", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+testToken("user-1", "tenant-a"))
	w := httptest.NewRecorder()

	m.HandleRPC(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)

	var resp HandshakeCompleteMessage
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, TypeHandshakeComplete, resp.Type)
	assert.NotEmpty(t, resp.SessionID)
}

func TestHandleRPC_NoAuth(t *testing.T) {
	m := testManager()
	defer m.Close()

	body, _ := json.Marshal(Message{Type: TypeHandshake})
	req := httptest.NewRequest(http.MethodPost, "/api/v2/wallet/rpc", bytes.NewReader(body))
	w := httptest.NewRecorder()

	m.HandleRPC(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestHandleRPC_ExpiredToken(t *testing.T) {
	m := testManager()
	defer m.Close()

	body, _ := json.Marshal(Message{Type: TypeHandshake})
	req := httptest.NewRequest(http.MethodPost, "/api/v2/wallet/rpc", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+expiredToken("user-1"))
	w := httptest.NewRecorder()

	m.HandleRPC(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestHandleRPC_WrongMethod(t *testing.T) {
	m := testManager()
	defer m.Close()

	req := httptest.NewRequest(http.MethodGet, "/api/v2/wallet/rpc", nil)
	w := httptest.NewRecorder()

	m.HandleRPC(w, req)

	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
}

func TestHandleRPC_FlowStart_RequiresSessionID(t *testing.T) {
	m := testManager()
	defer m.Close()

	body, _ := json.Marshal(Message{Type: TypeFlowStart})
	req := httptest.NewRequest(http.MethodPost, "/api/v2/wallet/rpc", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+testToken("user-1", ""))
	w := httptest.NewRecorder()

	m.HandleRPC(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandleRPC_FlowStart_SessionNotFound(t *testing.T) {
	m := testManager()
	defer m.Close()

	body, _ := json.Marshal(Message{Type: TypeFlowStart})
	req := httptest.NewRequest(http.MethodPost, "/api/v2/wallet/rpc", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+testToken("user-1", ""))
	req.Header.Set("X-Session-ID", "nonexistent")
	w := httptest.NewRecorder()

	m.HandleRPC(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestHandleRPC_SessionOwnershipCheck(t *testing.T) {
	m := testManager()
	defer m.Close()

	// Create a session for user-1.
	handshakeBody, _ := json.Marshal(Message{Type: TypeHandshake})
	hReq := httptest.NewRequest(http.MethodPost, "/api/v2/wallet/rpc", bytes.NewReader(handshakeBody))
	hReq.Header.Set("Authorization", "Bearer "+testToken("user-1", "tenant-a"))
	hW := httptest.NewRecorder()
	m.HandleRPC(hW, hReq)
	require.Equal(t, http.StatusCreated, hW.Code)

	var hResp HandshakeCompleteMessage
	require.NoError(t, json.Unmarshal(hW.Body.Bytes(), &hResp))
	sessionID := hResp.SessionID

	// Try to send a message as user-2 to user-1's session.
	body, _ := json.Marshal(Message{Type: TypeFlowStart})
	req := httptest.NewRequest(http.MethodPost, "/api/v2/wallet/rpc", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+testToken("user-2", "tenant-a"))
	req.Header.Set("X-Session-ID", sessionID)
	w := httptest.NewRecorder()

	m.HandleRPC(w, req)

	// Should get 404 (not 403) to avoid leaking session existence.
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestHandleRPC_TenantMismatchBlocked(t *testing.T) {
	m := testManager()
	defer m.Close()

	// Create session as tenant-a.
	handshakeBody, _ := json.Marshal(Message{Type: TypeHandshake})
	hReq := httptest.NewRequest(http.MethodPost, "/api/v2/wallet/rpc", bytes.NewReader(handshakeBody))
	hReq.Header.Set("Authorization", "Bearer "+testToken("user-1", "tenant-a"))
	hW := httptest.NewRecorder()
	m.HandleRPC(hW, hReq)
	require.Equal(t, http.StatusCreated, hW.Code)

	var hResp HandshakeCompleteMessage
	require.NoError(t, json.Unmarshal(hW.Body.Bytes(), &hResp))
	sessionID := hResp.SessionID

	// Try to send as same user but different tenant.
	body, _ := json.Marshal(Message{Type: TypeFlowStart})
	req := httptest.NewRequest(http.MethodPost, "/api/v2/wallet/rpc", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+testToken("user-1", "tenant-b"))
	req.Header.Set("X-Session-ID", sessionID)
	w := httptest.NewRecorder()

	m.HandleRPC(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestHandleRPC_MessageAccepted(t *testing.T) {
	m := testManager()
	defer m.Close()

	// Create session.
	handshakeBody, _ := json.Marshal(Message{Type: TypeHandshake})
	hReq := httptest.NewRequest(http.MethodPost, "/api/v2/wallet/rpc", bytes.NewReader(handshakeBody))
	hReq.Header.Set("Authorization", "Bearer "+testToken("user-1", ""))
	hW := httptest.NewRecorder()
	m.HandleRPC(hW, hReq)
	require.Equal(t, http.StatusCreated, hW.Code)

	var hResp HandshakeCompleteMessage
	require.NoError(t, json.Unmarshal(hW.Body.Bytes(), &hResp))

	// Send a flow_start message.
	flowMsg := FlowStartMessage{
		Message:  Message{Type: TypeFlowStart, FlowID: "test-flow-1"},
		Protocol: ProtocolOID4VCI,
	}
	body, _ := json.Marshal(flowMsg)
	req := httptest.NewRequest(http.MethodPost, "/api/v2/wallet/rpc", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+testToken("user-1", ""))
	req.Header.Set("X-Session-ID", hResp.SessionID)
	w := httptest.NewRecorder()

	m.HandleRPC(w, req)

	assert.Equal(t, http.StatusAccepted, w.Code)
}

// --- HandleEvents tests ---

func TestHandleEvents_NoAuth(t *testing.T) {
	m := testManager()
	defer m.Close()

	req := httptest.NewRequest(http.MethodGet, "/api/v2/wallet/events?session_id=xxx", nil)
	w := httptest.NewRecorder()

	m.HandleEvents(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestHandleEvents_MissingSessionID(t *testing.T) {
	m := testManager()
	defer m.Close()

	req := httptest.NewRequest(http.MethodGet, "/api/v2/wallet/events", nil)
	req.Header.Set("Authorization", "Bearer "+testToken("user-1", ""))
	w := httptest.NewRecorder()

	m.HandleEvents(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandleEvents_SessionNotFound(t *testing.T) {
	m := testManager()
	defer m.Close()

	req := httptest.NewRequest(http.MethodGet, "/api/v2/wallet/events?session_id=nonexistent", nil)
	req.Header.Set("Authorization", "Bearer "+testToken("user-1", ""))
	w := httptest.NewRecorder()

	m.HandleEvents(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestHandleEvents_OwnershipCheck(t *testing.T) {
	m := testManager()
	defer m.Close()

	// Create session for user-1.
	handshakeBody, _ := json.Marshal(Message{Type: TypeHandshake})
	hReq := httptest.NewRequest(http.MethodPost, "/api/v2/wallet/rpc", bytes.NewReader(handshakeBody))
	hReq.Header.Set("Authorization", "Bearer "+testToken("user-1", ""))
	hW := httptest.NewRecorder()
	m.HandleRPC(hW, hReq)
	require.Equal(t, http.StatusCreated, hW.Code)

	var hResp HandshakeCompleteMessage
	require.NoError(t, json.Unmarshal(hW.Body.Bytes(), &hResp))

	// user-2 tries to connect to user-1's SSE stream.
	req := httptest.NewRequest(http.MethodGet, "/api/v2/wallet/events?session_id="+hResp.SessionID, nil)
	req.Header.Set("Authorization", "Bearer "+testToken("user-2", ""))
	w := httptest.NewRecorder()

	m.HandleEvents(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

// --- SSE transport tests ---

func TestSSETransport_BufferAndReplay(t *testing.T) {
	tr := newSSETransport(5)

	// Send some messages.
	msg1 := map[string]string{"step": "1"}
	msg2 := map[string]string{"step": "2"}
	msg3 := map[string]string{"step": "3"}

	require.NoError(t, tr.SendJSON(msg1))
	require.NoError(t, tr.SendJSON(msg2))
	require.NoError(t, tr.SendJSON(msg3))

	// Verify buffer has 3 events.
	tr.bufMu.Lock()
	assert.Len(t, tr.events, 3)
	assert.Equal(t, "evt-1", tr.events[0].ID)
	assert.Equal(t, "evt-2", tr.events[1].ID)
	assert.Equal(t, "evt-3", tr.events[2].ID)
	tr.bufMu.Unlock()
}

func TestSSETransport_Eviction(t *testing.T) {
	tr := newSSETransport(2)

	require.NoError(t, tr.SendJSON("a"))
	require.NoError(t, tr.SendJSON("b"))
	require.NoError(t, tr.SendJSON("c"))

	tr.bufMu.Lock()
	assert.Len(t, tr.events, 2)
	assert.Equal(t, "evt-2", tr.events[0].ID)
	assert.Equal(t, "evt-3", tr.events[1].ID)
	tr.bufMu.Unlock()
}

func TestSSETransport_PushAndRead(t *testing.T) {
	tr := newSSETransport(10)

	msg := []byte(`{"type":"flow_start"}`)
	require.NoError(t, tr.pushMessage(msg))

	data, err := tr.ReadMessage(t.Context())
	require.NoError(t, err)
	assert.Equal(t, msg, data)
}

func TestSSETransport_ServeSSE_ReplayAndStream(t *testing.T) {
	tr := newSSETransport(200)

	// Buffer two events before SSE connects.
	require.NoError(t, tr.SendJSON(map[string]int{"n": 1}))
	require.NoError(t, tr.SendJSON(map[string]int{"n": 2}))

	// Start an SSE handler in a test server.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tr.serveSSE(w, r)
	}))
	defer ts.Close()

	// Close transport after a short delay so the SSE handler returns.
	go func() {
		time.Sleep(500 * time.Millisecond)
		_ = tr.Close()
	}()

	// Connect with Last-Event-ID: evt-1 to replay evt-2.
	req, _ := http.NewRequest(http.MethodGet, ts.URL, nil)
	req.Header.Set("Last-Event-ID", "evt-1")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, "text/event-stream", resp.Header.Get("Content-Type"))

	reader := bufio.NewReader(resp.Body)
	var ids []string
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			break
		}
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "id: ") {
			ids = append(ids, strings.TrimPrefix(line, "id: "))
		}
	}
	require.GreaterOrEqual(t, len(ids), 1)
	assert.Equal(t, "evt-2", ids[0])
}

// --- extractBearerToken tests ---

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
		{"bearer lowercase", "bearer abc", ""},
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
