package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
	"github.com/sirosfoundation/go-wmp/pkg/wmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func testWMPAdapter() (*WMPAdapter, *Manager) {
	m := testManager()
	a := NewWMPAdapter(m, zap.NewNop())
	return a, m
}

// cleanupWMP shuts down both the adapter and manager.
func cleanupWMP(a *WMPAdapter, m *Manager) {
	a.Close()
	m.Close()
}

// wmpRequest builds a JSON-RPC request body.
func wmpRequest(id string, method string, params interface{}) []byte {
	p, _ := json.Marshal(params)
	req := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      id,
		"method":  method,
		"params":  json.RawMessage(p),
	}
	data, _ := json.Marshal(req)
	return data
}

// --- HandleRPC: session.create ---

func TestWMP_SessionCreate_Success(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)

	body := wmpRequest("1", "wmp.session.create", wmp.SessionCreateParams{
		WMP:      wmp.Metadata{Version: wmp.Version},
		Security: wmp.SecurityMode{Mode: "tls"},
		Auth:     &wmp.AuthObject{Type: "bearer", Token: testToken("user-1", "tenant-a")},
	})

	resp, err := a.HandleRPC(context.Background(), "", body)
	require.NoError(t, err)

	var rpcResp wmp.Response
	require.NoError(t, json.Unmarshal(resp, &rpcResp))
	assert.Nil(t, rpcResp.Error)

	var result wmp.SessionCreateResult
	require.NoError(t, json.Unmarshal(rpcResp.Result, &result))
	assert.NotEmpty(t, result.WMP.SessionID)
	assert.Equal(t, wmp.Version, result.WMP.Version)
}

func TestWMP_SessionCreate_NoAuth(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)

	body := wmpRequest("1", "wmp.session.create", wmp.SessionCreateParams{
		WMP:      wmp.Metadata{Version: wmp.Version},
		Security: wmp.SecurityMode{Mode: "tls"},
	})

	resp, err := a.HandleRPC(context.Background(), "", body)
	require.NoError(t, err)

	var rpcResp wmp.Response
	require.NoError(t, json.Unmarshal(resp, &rpcResp))
	assert.NotNil(t, rpcResp.Error)
	assert.Equal(t, wmp.ErrNotAuthorized, rpcResp.Error.Code)
}

func TestWMP_SessionCreate_ExpiredToken(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)

	body := wmpRequest("1", "wmp.session.create", wmp.SessionCreateParams{
		WMP:      wmp.Metadata{Version: wmp.Version},
		Security: wmp.SecurityMode{Mode: "tls"},
		Auth:     &wmp.AuthObject{Type: "bearer", Token: expiredToken("user-1")},
	})

	resp, err := a.HandleRPC(context.Background(), "", body)
	require.NoError(t, err)

	var rpcResp wmp.Response
	require.NoError(t, json.Unmarshal(resp, &rpcResp))
	assert.NotNil(t, rpcResp.Error)
	assert.Equal(t, wmp.ErrNotAuthorized, rpcResp.Error.Code)
}

func TestWMP_SessionCreate_EmptyToken(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)

	body := wmpRequest("1", "wmp.session.create", wmp.SessionCreateParams{
		WMP:      wmp.Metadata{Version: wmp.Version},
		Security: wmp.SecurityMode{Mode: "tls"},
		Auth:     &wmp.AuthObject{Type: "bearer", Token: ""},
	})

	resp, err := a.HandleRPC(context.Background(), "", body)
	require.NoError(t, err)

	var rpcResp wmp.Response
	require.NoError(t, json.Unmarshal(resp, &rpcResp))
	assert.NotNil(t, rpcResp.Error)
	assert.Equal(t, wmp.ErrNotAuthorized, rpcResp.Error.Code)
}

// --- HandleRPC: missing session ---

func TestWMP_HandleRPC_MissingSession(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)

	body := wmpRequest("1", "wmp.flow.start", map[string]string{"flow_type": "test"})
	resp, err := a.HandleRPC(context.Background(), "", body)
	require.NoError(t, err)

	var rpcResp wmp.Response
	require.NoError(t, json.Unmarshal(resp, &rpcResp))
	assert.NotNil(t, rpcResp.Error)
	assert.Equal(t, wmp.ErrNotAuthorized, rpcResp.Error.Code)
}

func TestWMP_HandleRPC_UnknownSession(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)

	body := wmpRequest("1", "wmp.flow.start", map[string]string{"flow_type": "test"})
	resp, err := a.HandleRPC(context.Background(), "nonexistent-session", body)
	require.NoError(t, err)

	var rpcResp wmp.Response
	require.NoError(t, json.Unmarshal(resp, &rpcResp))
	assert.NotNil(t, rpcResp.Error)
	assert.Equal(t, wmp.ErrSessionNotFound, rpcResp.Error.Code)
}

// --- HandleRPC: flow.start ---

func TestWMP_FlowStart_UnknownProtocol(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)

	sessionID := createWMPSession(t, a)

	body := wmpRequest("2", "wmp.flow.start", wmp.FlowStartParams{
		WMP:      wmp.Metadata{Version: wmp.Version, SessionID: sessionID},
		FlowType: "nonexistent_protocol",
		FlowID:   "flow-1",
	})

	resp, err := a.HandleRPC(context.Background(), sessionID, body)
	require.NoError(t, err)

	var rpcResp wmp.Response
	require.NoError(t, json.Unmarshal(resp, &rpcResp))
	assert.NotNil(t, rpcResp.Error)
	assert.Equal(t, wmp.ErrInvalidParams, rpcResp.Error.Code)
}

func TestWMP_FlowStart_WithMockHandler(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)

	// Register a mock flow handler that sends progress + completes.
	progressSent := make(chan struct{})
	m.RegisterFlowHandler("test_proto", func(flow *Flow, cfg *config.Config, logger *zap.Logger, trustSvc *TrustService, registry *RegistryClient, verifiers storage.VerifierStore, trustCache *TrustCache) (FlowHandler, error) {
		return &mockFlowHandler{
			flow:         flow,
			progressSent: progressSent,
		}, nil
	})

	sessionID := createWMPSession(t, a)

	body := wmpRequest("2", "wmp.flow.start", wmp.FlowStartParams{
		WMP:      wmp.Metadata{Version: wmp.Version, SessionID: sessionID},
		FlowType: "test_proto",
		FlowID:   "flow-1",
	})

	resp, err := a.HandleRPC(context.Background(), sessionID, body)
	require.NoError(t, err)

	var rpcResp wmp.Response
	require.NoError(t, json.Unmarshal(resp, &rpcResp))
	assert.Nil(t, rpcResp.Error)

	var result wmp.FlowStartResult
	require.NoError(t, json.Unmarshal(rpcResp.Result, &result))
	assert.Equal(t, "flow-1", result.FlowID)
	assert.Equal(t, "test_proto", result.FlowType)

	// Wait for the flow handler to send progress.
	select {
	case <-progressSent:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for progress")
	}

	// Read the WMP notification from the SSE channel.
	events, err := a.Events(sessionID)
	require.NoError(t, err)

	select {
	case data := <-events:
		// Should be a WMP JSON-RPC notification.
		var notification struct {
			JSONRPC string          `json:"jsonrpc"`
			Method  string          `json:"method"`
			Params  json.RawMessage `json:"params"`
		}
		require.NoError(t, json.Unmarshal(data, &notification))
		assert.Equal(t, "2.0", notification.JSONRPC)
		// Could be flow.progress or flow.complete depending on timing.
		assert.Contains(t, []string{wmp.MethodFlowProgress, wmp.MethodFlowComplete}, notification.Method)
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for WMP notification")
	}
}

// --- FlowAction routing ---

func TestWMP_FlowAction_SignResponse(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)

	// Register a handler that requests signing.
	signReceived := make(chan *SignResponseMessage, 1)
	m.RegisterFlowHandler("sign_test", func(flow *Flow, cfg *config.Config, logger *zap.Logger, trustSvc *TrustService, registry *RegistryClient, verifiers storage.VerifierStore, trustCache *TrustCache) (FlowHandler, error) {
		return &signFlowHandler{
			flow:         flow,
			signReceived: signReceived,
		}, nil
	})

	sessionID := createWMPSession(t, a)

	// Start flow.
	body := wmpRequest("2", "wmp.flow.start", wmp.FlowStartParams{
		WMP:      wmp.Metadata{Version: wmp.Version, SessionID: sessionID},
		FlowType: "sign_test",
		FlowID:   "flow-sign",
	})
	resp, err := a.HandleRPC(context.Background(), sessionID, body)
	require.NoError(t, err)

	var startResp wmp.Response
	require.NoError(t, json.Unmarshal(resp, &startResp))
	assert.Nil(t, startResp.Error)

	// Read the sign sub-flow start request from the SSE channel.
	// The WMP adapter translates RequestSign into a Peer.Call(wmp.flow.start)
	// which appears on the events channel as a JSON-RPC request.
	eventsCh, err := a.Events(sessionID)
	require.NoError(t, err)

	var childFlowID string
	var rpcRequestID json.RawMessage
	timeout := time.After(2 * time.Second)
	for childFlowID == "" {
		select {
		case msg := <-eventsCh:
			var parsed struct {
				JSONRPC string          `json:"jsonrpc"`
				Method  string          `json:"method"`
				ID      json.RawMessage `json:"id"`
				Params  struct {
					FlowType string          `json:"flow_type"`
					FlowID   string          `json:"flow_id"`
					Params   json.RawMessage `json:"params"`
				} `json:"params"`
			}
			if err := json.Unmarshal(msg, &parsed); err != nil {
				continue
			}
			if parsed.Method == wmp.MethodFlowStart && parsed.Params.FlowType == wmp.FlowTypeSign {
				childFlowID = parsed.Params.FlowID
				rpcRequestID = parsed.ID
			}
		case <-timeout:
			t.Fatal("timeout waiting for sign sub-flow start")
		}
	}
	require.NotEmpty(t, childFlowID)
	require.NotNil(t, rpcRequestID)

	// Simulate client responding to the sub-flow start request with a result,
	// then sending flow.complete for the child flow.
	// First, respond to the JSON-RPC Call with a FlowStartResult.
	startResult := wmp.FlowStartResult{
		WMP:      wmp.Metadata{Version: wmp.Version, SessionID: sessionID},
		FlowID:   childFlowID,
		FlowType: wmp.FlowTypeSign,
	}
	resultJSON, _ := json.Marshal(startResult)
	rpcResponse, _ := json.Marshal(map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      rpcRequestID,
		"result":  json.RawMessage(resultJSON),
	})

	// Feed the response back through the channel transport so Peer.Call unblocks.
	a.mu.RLock()
	ws := a.peers[sessionID]
	a.mu.RUnlock()
	err = ws.transport.Push(rpcResponse)
	require.NoError(t, err)

	// Small delay for Peer.Call to unblock and RequestSign to start waiting on signCh.
	time.Sleep(100 * time.Millisecond)

	// Now send flow.complete for the child sign sub-flow as a JSON-RPC notification.
	// The Peer's Serve loop will receive this and call FlowComplete on the handler,
	// which routes the result to signCh with the correct messageID.
	completeResult, _ := json.Marshal(map[string]string{
		"proof_jwt": "eyJ.test.proof",
	})
	completeNotification, _ := json.Marshal(map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  wmp.MethodFlowComplete,
		"params": wmp.FlowCompleteParams{
			FlowID: childFlowID,
			Result: completeResult,
		},
	})
	err = ws.transport.Push(completeNotification)
	require.NoError(t, err)

	// Wait for the handler to receive the sign response.
	select {
	case sr := <-signReceived:
		assert.Equal(t, "eyJ.test.proof", sr.ProofJWT)
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for sign response in handler")
	}
}

func TestWMP_FlowAction_GenericAction(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)

	actionReceived := make(chan *FlowActionMessage, 1)
	m.RegisterFlowHandler("action_test", func(flow *Flow, cfg *config.Config, logger *zap.Logger, trustSvc *TrustService, registry *RegistryClient, verifiers storage.VerifierStore, trustCache *TrustCache) (FlowHandler, error) {
		return &actionFlowHandler{
			flow:           flow,
			actionReceived: actionReceived,
		}, nil
	})

	sessionID := createWMPSession(t, a)

	// Start flow.
	body := wmpRequest("2", "wmp.flow.start", wmp.FlowStartParams{
		WMP:      wmp.Metadata{Version: wmp.Version, SessionID: sessionID},
		FlowType: "action_test",
		FlowID:   "flow-action",
	})
	resp, err := a.HandleRPC(context.Background(), sessionID, body)
	require.NoError(t, err)

	// Give the handler goroutine time to reach WaitForAction.
	time.Sleep(100 * time.Millisecond)

	// Send consent action.
	consentPayload, _ := json.Marshal(map[string]bool{"approved": true})
	body = wmpRequest("3", "wmp.flow.action", wmp.FlowActionParams{
		WMP:    wmp.Metadata{Version: wmp.Version, SessionID: sessionID},
		FlowID: "flow-action",
		Action: "consent",
		Params: consentPayload,
	})

	resp, err = a.HandleRPC(context.Background(), sessionID, body)
	require.NoError(t, err)

	var actionResp wmp.Response
	require.NoError(t, json.Unmarshal(resp, &actionResp))
	assert.Nil(t, actionResp.Error)

	select {
	case am := <-actionReceived:
		assert.Equal(t, "consent", am.Action)
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for action in handler")
	}
}

func TestWMP_FlowAction_UnknownFlow(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)

	sessionID := createWMPSession(t, a)

	body := wmpRequest("2", "wmp.flow.action", wmp.FlowActionParams{
		WMP:    wmp.Metadata{Version: wmp.Version, SessionID: sessionID},
		FlowID: "nonexistent-flow",
		Action: "consent",
	})

	resp, err := a.HandleRPC(context.Background(), sessionID, body)
	require.NoError(t, err)

	var rpcResp wmp.Response
	require.NoError(t, json.Unmarshal(resp, &rpcResp))
	assert.NotNil(t, rpcResp.Error)
	assert.Equal(t, wmp.ErrFlowError, rpcResp.Error.Code)
}

// --- Session close ---

func TestWMP_SessionClose(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)

	sessionID := createWMPSession(t, a)

	// Verify session exists.
	_, err := a.Events(sessionID)
	require.NoError(t, err)

	// Close it.
	a.CloseSession(sessionID)

	// Verify session is gone.
	_, err = a.Events(sessionID)
	assert.Error(t, err)
}

// --- HTTP endpoint tests ---

func TestWMP_HTTPEndpoint_RPC(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)

	body := wmpRequest("1", "wmp.session.create", wmp.SessionCreateParams{
		WMP:      wmp.Metadata{Version: wmp.Version},
		Security: wmp.SecurityMode{Mode: "tls"},
		Auth:     &wmp.AuthObject{Type: "bearer", Token: testToken("user-1", "tenant-a")},
	})

	req := httptest.NewRequest(http.MethodPost, "/wmp/rpc", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+testToken("user-1", "tenant-a"))
	w := httptest.NewRecorder()

	a.HandleWMPRPC(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))

	var rpcResp wmp.Response
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &rpcResp))
	assert.Nil(t, rpcResp.Error)
}

func TestWMP_HTTPEndpoint_RPC_NoAuth(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)

	body := wmpRequest("1", "wmp.session.create", map[string]string{})
	req := httptest.NewRequest(http.MethodPost, "/wmp/rpc", bytes.NewReader(body))
	w := httptest.NewRecorder()

	a.HandleWMPRPC(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestWMP_HTTPEndpoint_RPC_MethodNotAllowed(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)

	req := httptest.NewRequest(http.MethodGet, "/wmp/rpc", nil)
	w := httptest.NewRecorder()

	a.HandleWMPRPC(w, req)

	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
}

func TestWMP_HTTPEndpoint_Events_NoSession(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)

	req := httptest.NewRequest(http.MethodGet, "/wmp/events?session_id=nonexistent", nil)
	req.Header.Set("Authorization", "Bearer "+testToken("user-1", ""))
	w := httptest.NewRecorder()

	a.HandleWMPEvents(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestWMP_HTTPEndpoint_Events_MissingSessionID(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)

	req := httptest.NewRequest(http.MethodGet, "/wmp/events", nil)
	req.Header.Set("Authorization", "Bearer "+testToken("user-1", ""))
	w := httptest.NewRecorder()

	a.HandleWMPEvents(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// --- Message translation tests ---

func TestWMP_MessageTranslation_Progress(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)

	progressSent := make(chan struct{})
	m.RegisterFlowHandler("translate_test", func(flow *Flow, cfg *config.Config, logger *zap.Logger, trustSvc *TrustService, registry *RegistryClient, verifiers storage.VerifierStore, trustCache *TrustCache) (FlowHandler, error) {
		return &mockFlowHandler{
			flow:         flow,
			progressSent: progressSent,
		}, nil
	})

	sessionID := createWMPSession(t, a)

	// Start flow.
	body := wmpRequest("2", "wmp.flow.start", wmp.FlowStartParams{
		WMP:      wmp.Metadata{Version: wmp.Version, SessionID: sessionID},
		FlowType: "translate_test",
		FlowID:   "flow-translate",
	})
	resp, err := a.HandleRPC(context.Background(), sessionID, body)
	require.NoError(t, err)
	var startResp wmp.Response
	require.NoError(t, json.Unmarshal(resp, &startResp))
	assert.Nil(t, startResp.Error)

	// Wait for handler to send progress.
	select {
	case <-progressSent:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout")
	}

	// Read notification.
	events, err := a.Events(sessionID)
	require.NoError(t, err)

	select {
	case data := <-events:
		var notif struct {
			JSONRPC string                 `json:"jsonrpc"`
			Method  string                 `json:"method"`
			Params  wmp.FlowProgressParams `json:"params"`
		}
		require.NoError(t, json.Unmarshal(data, &notif))
		assert.Equal(t, "2.0", notif.JSONRPC)
		assert.Equal(t, wmp.MethodFlowProgress, notif.Method)
		assert.Equal(t, "flow-translate", notif.Params.FlowID)
		assert.Equal(t, "test_step", notif.Params.Step)
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for WMP notification")
	}
}

// --- Error code mapping ---

func TestWMP_MapErrorCode(t *testing.T) {
	tests := []struct {
		engine ErrorCode
		wmp    int
	}{
		{ErrCodeAuthFailed, wmp.ErrNotAuthorized},
		{ErrCodeAuthorizationFail, wmp.ErrNotAuthorized},
		{ErrCodeInvalidMessage, wmp.ErrInvalidRequest},
		{ErrCodeSignError, wmp.ErrSignatureInvalid},
		{ErrCodeTooManyRequests, wmp.ErrRateLimited},
		{ErrCodeInternalError, wmp.ErrInternalError},
		{ErrCodeOfferParseError, wmp.ErrFlowError},
		{ErrCodeMetadataFetchErr, wmp.ErrFlowError},
		{ErrCodeUntrustedIssuer, wmp.ErrFlowError},
		{ErrCodeFlowTimeout, wmp.ErrFlowError},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.wmp, mapErrorCode(tt.engine), "ErrorCode %s", tt.engine)
	}
}

// --- Helpers ---

// createWMPSession creates a WMP session and returns the session ID.
func createWMPSession(t *testing.T, a *WMPAdapter) string {
	t.Helper()
	body := wmpRequest("1", "wmp.session.create", wmp.SessionCreateParams{
		WMP:      wmp.Metadata{Version: wmp.Version},
		Security: wmp.SecurityMode{Mode: "tls"},
		Auth:     &wmp.AuthObject{Type: "bearer", Token: testToken("user-1", "tenant-a")},
	})

	resp, err := a.HandleRPC(context.Background(), "", body)
	require.NoError(t, err)

	var rpcResp wmp.Response
	require.NoError(t, json.Unmarshal(resp, &rpcResp))
	require.Nil(t, rpcResp.Error, "session.create failed: %v", rpcResp.Error)

	var result wmp.SessionCreateResult
	require.NoError(t, json.Unmarshal(rpcResp.Result, &result))
	return result.WMP.SessionID
}

// --- Mock flow handlers ---

// mockFlowHandler sends a progress notification and completes.
type mockFlowHandler struct {
	flow         *Flow
	progressSent chan struct{}
}

func (h *mockFlowHandler) Execute(ctx context.Context, msg *FlowStartMessage) error {
	_ = h.flow.Session.SendProgress(h.flow.ID, "test_step", map[string]string{"info": "hello"})
	close(h.progressSent)
	// Small delay to let SSE pick up progress before complete.
	time.Sleep(50 * time.Millisecond)
	_ = h.flow.Session.SendFlowComplete(h.flow.ID, nil, "")
	return nil
}

func (h *mockFlowHandler) Cancel() {}

// signFlowHandler requests a signature and reports what it received.
type signFlowHandler struct {
	flow         *Flow
	signReceived chan *SignResponseMessage
}

func (h *signFlowHandler) Execute(ctx context.Context, msg *FlowStartMessage) error {
	_ = h.flow.Session.SendProgress(h.flow.ID, "preparing", nil)

	resp, err := h.flow.Session.RequestSign(ctx, h.flow.ID, SignActionGenerateProof, SignRequestParams{
		Audience: "https://issuer.example.com",
		Nonce:    "test-nonce",
	})
	if err != nil {
		_ = h.flow.Session.SendFlowError(h.flow.ID, "", ErrCodeSignTimeout, err.Error())
		return err
	}

	h.signReceived <- resp
	_ = h.flow.Session.SendFlowComplete(h.flow.ID, nil, "")
	return nil
}

func (h *signFlowHandler) Cancel() {}

// actionFlowHandler waits for a generic action and reports it.
type actionFlowHandler struct {
	flow           *Flow
	actionReceived chan *FlowActionMessage
}

func (h *actionFlowHandler) Execute(ctx context.Context, msg *FlowStartMessage) error {
	_ = h.flow.Session.SendProgress(h.flow.ID, "awaiting_consent", nil)

	action, err := h.flow.Session.WaitForAction(ctx, h.flow.ID, "consent", "decline")
	if err != nil {
		_ = h.flow.Session.SendFlowError(h.flow.ID, "", ErrCodeFlowTimeout, err.Error())
		return err
	}

	h.actionReceived <- action
	_ = h.flow.Session.SendFlowComplete(h.flow.ID, nil, "")
	return nil
}

func (h *actionFlowHandler) Cancel() {}

// silence unused import warnings
var _ = io.ReadAll
