package engine

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
	"github.com/sirosfoundation/go-wmp/pkg/wmp"
	"github.com/sirosfoundation/go-wmp/pkg/wmp/httpsse"
	"github.com/sirosfoundation/go-wmp/pkg/wmp/openid4x"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func testWMPAdapter() (*WMPAdapter, *Manager) {
	m := testManager()
	a := NewWMPAdapter(m, zap.NewNop(), testBearerToken)
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

// wmpNotification builds an id-less JSON-RPC notification; go-wmp only treats
// that wire shape as one (go-wmp#26/#27), unlike wmpRequest, which sets an id.
func wmpNotification(method string, params interface{}) []byte {
	p, _ := json.Marshal(params)
	req := map[string]interface{}{
		"jsonrpc": "2.0",
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

	resp, err := a.HandleRPC(context.Background(), "", "", "", body)
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

	resp, err := a.HandleRPC(context.Background(), "", "", "", body)
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

	resp, err := a.HandleRPC(context.Background(), "", "", "", body)
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

	resp, err := a.HandleRPC(context.Background(), "", "", "", body)
	require.NoError(t, err)

	var rpcResp wmp.Response
	require.NoError(t, json.Unmarshal(resp, &rpcResp))
	assert.NotNil(t, rpcResp.Error)
	assert.Equal(t, wmp.ErrNotAuthorized, rpcResp.Error.Code)
}

// TestWMP_SessionCreate_NonBearerAuthType: a non-bearer auth type must not be treated as bearer.
func TestWMP_SessionCreate_NonBearerAuthType(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)

	body := wmpRequest("1", "wmp.session.create", wmp.SessionCreateParams{
		WMP:      wmp.Metadata{Version: wmp.Version},
		Security: wmp.SecurityMode{Mode: "tls"},
		Auth:     &wmp.AuthObject{Type: "dpop", Token: testToken("user-1", "tenant-a")},
	})

	resp, err := a.HandleRPC(context.Background(), "", "", "", body)
	require.NoError(t, err)

	var rpcResp wmp.Response
	require.NoError(t, json.Unmarshal(resp, &rpcResp))
	require.NotNil(t, rpcResp.Error)
	assert.Equal(t, wmp.ErrNotAuthorized, rpcResp.Error.Code)
}

// TestWMP_SessionCreate_UnsupportedVersion: an unimplemented protocol version is rejected.
func TestWMP_SessionCreate_UnsupportedVersion(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)

	body := wmpRequest("1", "wmp.session.create", wmp.SessionCreateParams{
		WMP:      wmp.Metadata{Version: "99.0"},
		Security: wmp.SecurityMode{Mode: "tls"},
		Auth:     &wmp.AuthObject{Type: "bearer", Token: testToken("user-1", "tenant-a")},
	})

	resp, err := a.HandleRPC(context.Background(), "", "", "", body)
	require.NoError(t, err)

	var rpcResp wmp.Response
	require.NoError(t, json.Unmarshal(resp, &rpcResp))
	require.NotNil(t, rpcResp.Error)
	assert.Equal(t, wmp.ErrVersionNotSupported, rpcResp.Error.Code)
}

// TestWMP_SessionCreate_MLSNotSupported: only the TLS mode is implemented, so "mls" is rejected.
func TestWMP_SessionCreate_MLSNotSupported(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)

	body := wmpRequest("1", "wmp.session.create", wmp.SessionCreateParams{
		WMP:      wmp.Metadata{Version: wmp.Version},
		Security: wmp.SecurityMode{Mode: "mls"},
		Auth:     &wmp.AuthObject{Type: "bearer", Token: testToken("user-1", "tenant-a")},
	})

	resp, err := a.HandleRPC(context.Background(), "", "", "", body)
	require.NoError(t, err)

	var rpcResp wmp.Response
	require.NoError(t, json.Unmarshal(resp, &rpcResp))
	require.NotNil(t, rpcResp.Error)
	assert.Equal(t, wmp.ErrInvalidParams, rpcResp.Error.Code)
}

// TestWMP_SessionCreate_InvalidParams: params that do not decode into SessionCreateParams.
func TestWMP_SessionCreate_InvalidParams(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)

	req := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      "1",
		"method":  "wmp.session.create",
		"params":  "not-an-object",
	}
	body, err := json.Marshal(req)
	require.NoError(t, err)

	resp, err := a.HandleRPC(context.Background(), "", "", "", body)
	require.NoError(t, err)

	var rpcResp wmp.Response
	require.NoError(t, json.Unmarshal(resp, &rpcResp))
	require.NotNil(t, rpcResp.Error)
	assert.Equal(t, wmp.ErrInvalidParams, rpcResp.Error.Code)
}

// TestWMP_HandleSessionCreate_MalformedBody: invalid JSON yields a JSON-RPC parse error.
func TestWMP_HandleSessionCreate_MalformedBody(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)

	resp, err := a.HandleRPC(context.Background(), "", "", "", []byte("not json"))
	require.NoError(t, err)

	var rpcResp wmp.Response
	require.NoError(t, json.Unmarshal(resp, &rpcResp))
	require.NotNil(t, rpcResp.Error)
	assert.Equal(t, wmp.ErrParseError, rpcResp.Error.Code)
}

// TestWMP_SessionCreate_TTLCapped: a TTL above maxSessionTTL is capped.
func TestWMP_SessionCreate_TTLCapped(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)

	body := wmpRequest("1", "wmp.session.create", wmp.SessionCreateParams{
		WMP:      wmp.Metadata{Version: wmp.Version},
		Security: wmp.SecurityMode{Mode: "tls"},
		Auth:     &wmp.AuthObject{Type: "bearer", Token: testToken("user-1", "tenant-a")},
		TTL:      int((maxSessionTTL + time.Hour).Seconds()),
	})

	resp, err := a.HandleRPC(context.Background(), "", "", "", body)
	require.NoError(t, err)

	var rpcResp wmp.Response
	require.NoError(t, json.Unmarshal(resp, &rpcResp))
	require.Nil(t, rpcResp.Error)

	var result wmp.SessionCreateResult
	require.NoError(t, json.Unmarshal(rpcResp.Result, &result))

	a.mu.RLock()
	ws := a.peers[result.WMP.SessionID]
	a.mu.RUnlock()
	require.NotNil(t, ws)
	assert.WithinDuration(t, time.Now().Add(maxSessionTTL), ws.expiresAt, 5*time.Second,
		"TTL beyond maxSessionTTL should be capped, not honored verbatim")
}

// TestWMP_SessionCreate_TTLWithinLimit: a TTL under the cap is honored.
func TestWMP_SessionCreate_TTLWithinLimit(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)

	body := wmpRequest("1", "wmp.session.create", wmp.SessionCreateParams{
		WMP:      wmp.Metadata{Version: wmp.Version},
		Security: wmp.SecurityMode{Mode: "tls"},
		Auth:     &wmp.AuthObject{Type: "bearer", Token: testToken("user-1", "tenant-a")},
		TTL:      60,
	})

	resp, err := a.HandleRPC(context.Background(), "", "", "", body)
	require.NoError(t, err)

	var rpcResp wmp.Response
	require.NoError(t, json.Unmarshal(resp, &rpcResp))
	require.Nil(t, rpcResp.Error)

	var result wmp.SessionCreateResult
	require.NoError(t, json.Unmarshal(rpcResp.Result, &result))

	a.mu.RLock()
	ws := a.peers[result.WMP.SessionID]
	a.mu.RUnlock()
	require.NotNil(t, ws)
	assert.WithinDuration(t, time.Now().Add(60*time.Second), ws.expiresAt, 3*time.Second)
}

// TestWMP_SessionCreate_CapabilitiesOffered: capabilities are intersected with the client's offer.
func TestWMP_SessionCreate_CapabilitiesOffered(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)

	body := wmpRequest("1", "wmp.session.create", wmp.SessionCreateParams{
		WMP:                 wmp.Metadata{Version: wmp.Version},
		Security:            wmp.SecurityMode{Mode: "tls"},
		Auth:                &wmp.AuthObject{Type: "bearer", Token: testToken("user-1", "tenant-a")},
		CapabilitiesOffered: wmp.Capabilities{"sign": json.RawMessage(`{}`)},
	})

	resp, err := a.HandleRPC(context.Background(), "", "", "", body)
	require.NoError(t, err)

	var rpcResp wmp.Response
	require.NoError(t, json.Unmarshal(resp, &rpcResp))
	require.Nil(t, rpcResp.Error)

	var result wmp.SessionCreateResult
	require.NoError(t, json.Unmarshal(rpcResp.Result, &result))
	assert.Contains(t, result.Capabilities, "sign")
	assert.NotContains(t, result.Capabilities, "flows",
		"capabilities not offered by the client should be filtered out of negotiation")
}

// --- HandleRPC: session.resume ---

// createWMPSessionWithToken is createWMPSession plus the resumption token.
func createWMPSessionWithToken(t *testing.T, a *WMPAdapter, userID, tenantID string) (sessionID, resumptionToken string) {
	t.Helper()
	body := wmpRequest("1", "wmp.session.create", wmp.SessionCreateParams{
		WMP:      wmp.Metadata{Version: wmp.Version},
		Security: wmp.SecurityMode{Mode: "tls"},
		Auth:     &wmp.AuthObject{Type: "bearer", Token: testToken(userID, tenantID)},
	})

	resp, err := a.HandleRPC(context.Background(), "", "", "", body)
	require.NoError(t, err)

	var rpcResp wmp.Response
	require.NoError(t, json.Unmarshal(resp, &rpcResp))
	require.Nil(t, rpcResp.Error, "session.create failed: %v", rpcResp.Error)

	var result wmp.SessionCreateResult
	require.NoError(t, json.Unmarshal(rpcResp.Result, &result))
	return result.WMP.SessionID, result.ResumptionToken
}

func TestWMP_SessionResume_Success(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)

	sessionID, token := createWMPSessionWithToken(t, a, "user-1", "tenant-a")

	body := wmpRequest("2", "wmp.session.resume", wmp.SessionResumeParams{
		WMP:             wmp.Metadata{Version: wmp.Version},
		SessionID:       sessionID,
		ResumptionToken: token,
	})

	resp, err := a.HandleRPC(context.Background(), "", "user-1", "tenant-a", body)
	require.NoError(t, err)

	var rpcResp wmp.Response
	require.NoError(t, json.Unmarshal(resp, &rpcResp))
	require.Nil(t, rpcResp.Error, "session.resume failed: %v", rpcResp.Error)

	var result wmp.SessionResumeResult
	require.NoError(t, json.Unmarshal(rpcResp.Result, &result))
	assert.True(t, result.Resumed)
	assert.NotEmpty(t, result.ResumptionToken)
	assert.NotEqual(t, token, result.ResumptionToken, "resumption token should rotate")
}

// TestWMP_SessionResume_IdentityMismatch: a resumption token alone must not resume another user's session.
func TestWMP_SessionResume_IdentityMismatch(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)

	sessionID, token := createWMPSessionWithToken(t, a, "user-1", "tenant-a")

	body := wmpRequest("2", "wmp.session.resume", wmp.SessionResumeParams{
		WMP:             wmp.Metadata{Version: wmp.Version},
		SessionID:       sessionID,
		ResumptionToken: token,
	})

	// Attacker: bearer token for another user plus user-1's resumption token and session ID.
	resp, err := a.HandleRPC(context.Background(), "", "user-2", "tenant-a", body)
	require.NoError(t, err)

	var rpcResp wmp.Response
	require.NoError(t, json.Unmarshal(resp, &rpcResp))
	require.NotNil(t, rpcResp.Error, "expected resume to be rejected")
	assert.Equal(t, wmp.ErrNotAuthorized, rpcResp.Error.Code)
}

func TestWMP_SessionResume_TenantMismatch(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)

	sessionID, token := createWMPSessionWithToken(t, a, "user-1", "tenant-a")

	body := wmpRequest("2", "wmp.session.resume", wmp.SessionResumeParams{
		WMP:             wmp.Metadata{Version: wmp.Version},
		SessionID:       sessionID,
		ResumptionToken: token,
	})

	// Same user ID, but a different tenant context — must still be rejected.
	resp, err := a.HandleRPC(context.Background(), "", "user-1", "tenant-b", body)
	require.NoError(t, err)

	var rpcResp wmp.Response
	require.NoError(t, json.Unmarshal(resp, &rpcResp))
	require.NotNil(t, rpcResp.Error, "expected resume to be rejected")
	assert.Equal(t, wmp.ErrNotAuthorized, rpcResp.Error.Code)
}

func TestWMP_SessionResume_InvalidToken(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)

	sessionID, _ := createWMPSessionWithToken(t, a, "user-1", "tenant-a")

	body := wmpRequest("2", "wmp.session.resume", wmp.SessionResumeParams{
		WMP:             wmp.Metadata{Version: wmp.Version},
		SessionID:       sessionID,
		ResumptionToken: "not-a-real-token",
	})

	resp, err := a.HandleRPC(context.Background(), "", "user-1", "tenant-a", body)
	require.NoError(t, err)

	var rpcResp wmp.Response
	require.NoError(t, json.Unmarshal(resp, &rpcResp))
	require.NotNil(t, rpcResp.Error)
	assert.Equal(t, wmp.ErrSessionNotFound, rpcResp.Error.Code)
}

// TestWMP_CloseSessionIfCurrent_SkipsSupersededSession: the old transport's Serve
// goroutine runs cleanup after a resume installed a new wmpSession; that cleanup
// must not delete the new session.
func TestWMP_CloseSessionIfCurrent_SkipsSupersededSession(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)

	const sessionID = "session-under-test"
	session := &Session{ID: sessionID, UserID: "user-1", logger: zap.NewNop()}
	m.registerSession(session)

	staleWS := &wmpSession{
		transport: wmp.NewChannelTransport(1, 1),
		session:   session,
		cancel:    func() {},
	}
	currentWS := &wmpSession{
		transport: wmp.NewChannelTransport(1, 1),
		session:   session,
		cancel:    func() {},
	}

	a.mu.Lock()
	a.peers[sessionID] = currentWS
	a.mu.Unlock()

	// Old goroutine's deferred cleanup runs after a resume installed currentWS.
	a.closeSessionIfCurrent(sessionID, staleWS)

	a.mu.RLock()
	got, ok := a.peers[sessionID]
	a.mu.RUnlock()
	require.True(t, ok, "resumed session must survive the superseded goroutine's cleanup")
	assert.Same(t, currentWS, got)

	// The current session's own cleanup must still work normally.
	a.closeSessionIfCurrent(sessionID, currentWS)
	a.mu.RLock()
	_, ok = a.peers[sessionID]
	a.mu.RUnlock()
	assert.False(t, ok, "current session should be removed by its own cleanup")
}

// --- replayActiveFlowProgress ---

// TestWMP_ReplayActiveFlowProgress_NotifiesActiveFlowsSkipsEmpty: after resume
// (spec §6.2.1) flows with a non-empty State get flow.progress; empty ones are skipped.
func TestWMP_ReplayActiveFlowProgress_NotifiesActiveFlowsSkipsEmpty(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)

	sessionID := createWMPSession(t, a)

	a.mu.RLock()
	ws := a.peers[sessionID]
	a.mu.RUnlock()

	ws.session.flowsMu.Lock()
	ws.session.flows["flow-active"] = &Flow{ID: "flow-active", State: FlowStep("awaiting_consent")}
	ws.session.flows["flow-not-started"] = &Flow{ID: "flow-not-started", State: ""}
	ws.session.flowsMu.Unlock()

	events, err := a.Events(sessionID)
	require.NoError(t, err)

	a.replayActiveFlowProgress(sessionID, ws.peer)

	select {
	case data := <-events:
		var notif struct {
			Method string                 `json:"method"`
			Params wmp.FlowProgressParams `json:"params"`
		}
		require.NoError(t, json.Unmarshal(data, &notif))
		assert.Equal(t, wmp.MethodFlowProgress, notif.Method)
		assert.Equal(t, "flow-active", notif.Params.FlowID)
		assert.Equal(t, "awaiting_consent", notif.Params.Step)
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for flow.progress replay")
	}

	// The empty-State flow must not have produced a second notification.
	select {
	case data := <-events:
		t.Fatalf("unexpected extra notification for empty-State flow: %s", data)
	case <-time.After(100 * time.Millisecond):
	}
}

// TestWMP_ReplayActiveFlowProgress_UnknownSession: a missing session must not panic.
func TestWMP_ReplayActiveFlowProgress_UnknownSession(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)

	assert.NotPanics(t, func() {
		a.replayActiveFlowProgress("nonexistent-session", nil)
	})
}

// --- HandleRPC: missing session ---

func TestWMP_HandleRPC_MissingSession(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)

	body := wmpRequest("1", "wmp.flow.start", map[string]string{"flow_type": "test"})
	resp, err := a.HandleRPC(context.Background(), "", "", "", body)
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
	resp, err := a.HandleRPC(context.Background(), "nonexistent-session", "", "", body)
	require.NoError(t, err)

	var rpcResp wmp.Response
	require.NoError(t, json.Unmarshal(resp, &rpcResp))
	assert.NotNil(t, rpcResp.Error)
	assert.Equal(t, wmp.ErrSessionNotFound, rpcResp.Error.Code)
}

// --- cleanupExpired ---

// TestWMP_CleanupExpired_RemovesExpiredToken: expired tokens are swept; healthy sessions survive.
func TestWMP_CleanupExpired_RemovesExpiredToken(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)

	sessionID, token := createWMPSessionWithToken(t, a, "user-1", "tenant-a")

	a.mu.Lock()
	a.resumptionTokens[token].expiresAt = time.Now().Add(-time.Minute)
	a.mu.Unlock()

	a.cleanupExpired()

	a.mu.RLock()
	_, stillThere := a.resumptionTokens[token]
	a.mu.RUnlock()
	assert.False(t, stillThere, "expired resumption token should have been removed")

	_, err := a.Events(sessionID)
	assert.NoError(t, err, "the session itself should not be affected by an unrelated token expiring")
}

// TestWMP_CleanupExpired_ClosesIdleSession: sessions idle past wmpSessionIdleTimeout are closed.
func TestWMP_CleanupExpired_ClosesIdleSession(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)

	sessionID := createWMPSession(t, a)

	a.mu.Lock()
	a.peers[sessionID].lastActivity = time.Now().Add(-2 * wmpSessionIdleTimeout)
	a.mu.Unlock()

	a.cleanupExpired()

	_, err := a.Events(sessionID)
	assert.Error(t, err, "an idle session past wmpSessionIdleTimeout should have been closed")
}

// TestWMP_CleanupExpired_ClosesTTLExpiredSession: sessions past expiresAt are closed even if not idle.
func TestWMP_CleanupExpired_ClosesTTLExpiredSession(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)

	sessionID := createWMPSession(t, a)

	a.mu.Lock()
	a.peers[sessionID].expiresAt = time.Now().Add(-time.Minute)
	a.peers[sessionID].lastActivity = time.Now() // not idle
	a.mu.Unlock()

	a.cleanupExpired()

	_, err := a.Events(sessionID)
	assert.Error(t, err, "a TTL-expired session should have been closed even though it is not idle")
}

// TestWMP_CleanupExpired_KeepsHealthySession: a session neither idle nor expired survives.
func TestWMP_CleanupExpired_KeepsHealthySession(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)

	sessionID := createWMPSession(t, a)

	a.cleanupExpired()

	_, err := a.Events(sessionID)
	assert.NoError(t, err, "a healthy session should not be closed by cleanupExpired")
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

	resp, err := a.HandleRPC(context.Background(), sessionID, "", "", body)
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

	resp, err := a.HandleRPC(context.Background(), sessionID, "", "", body)
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
	resp, err := a.HandleRPC(context.Background(), sessionID, "", "", body)
	require.NoError(t, err)

	var startResp wmp.Response
	require.NoError(t, json.Unmarshal(resp, &startResp))
	assert.Nil(t, startResp.Error)

	// The adapter turns RequestSign into a Peer.Call(wmp.flow.start) seen on the events channel.
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

	// Respond to the Call with a FlowStartResult, then send flow.complete for the child flow.
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

	// Send flow.complete for the child sign sub-flow; FlowComplete routes it to signCh by messageID.
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
	resp, err := a.HandleRPC(context.Background(), sessionID, "", "", body)
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

	resp, err = a.HandleRPC(context.Background(), sessionID, "", "", body)
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

	resp, err := a.HandleRPC(context.Background(), sessionID, "", "", body)
	require.NoError(t, err)

	var rpcResp wmp.Response
	require.NoError(t, json.Unmarshal(resp, &rpcResp))
	assert.NotNil(t, rpcResp.Error)
	assert.Equal(t, wmp.ErrFlowError, rpcResp.Error.Code)
}

// TestWMP_FlowAction_ActionChannelBackpressure_WaitsBriefly: a momentarily-full
// actionCh must wait briefly rather than reject instantly.
func TestWMP_FlowAction_ActionChannelBackpressure_WaitsBriefly(t *testing.T) {
	session := &Session{
		ID:       "sess-1",
		flows:    map[string]*Flow{"flow-1": {ID: "flow-1"}},
		actionCh: make(chan *FlowActionMessage, 1),
		logger:   zap.NewNop(),
	}
	handler := &wmpEngineHandler{session: session, sessionID: session.ID}

	// Fill the channel to capacity.
	session.actionCh <- &FlowActionMessage{}

	// Drain one slot within flowActionSendWait; the action must succeed.
	go func() {
		time.Sleep(50 * time.Millisecond)
		<-session.actionCh
	}()

	start := time.Now()
	result, err := handler.FlowAction(context.Background(), &wmp.FlowActionParams{
		FlowID: "flow-1",
		Action: "consent",
	})
	elapsed := time.Since(start)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Less(t, elapsed, flowActionSendWait, "should succeed once the channel drains, not wait out the full timeout")
	assert.GreaterOrEqual(t, elapsed, 40*time.Millisecond, "should have actually waited for the drain, not raced past it")
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

// TestWMP_SessionClose_RPC: wmp.session.close tears down the session.
func TestWMP_SessionClose_RPC(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)

	sessionID := createWMPSession(t, a)

	body := wmpRequest("2", wmp.MethodSessionClose, wmp.SessionCloseParams{
		WMP:    wmp.Metadata{Version: wmp.Version, SessionID: sessionID},
		Reason: wmp.ReasonUserCancelled,
	})

	resp, err := a.HandleRPC(context.Background(), sessionID, "", "", body)
	require.NoError(t, err)

	var rpcResp wmp.Response
	require.NoError(t, json.Unmarshal(resp, &rpcResp))
	assert.Nil(t, rpcResp.Error)

	_, err = a.Events(sessionID)
	assert.Error(t, err, "session should be torn down after wmp.session.close")
}

// TestWMP_SessionClose_NilParams: nil params default the reason to "unknown" without a nil dereference.
func TestWMP_SessionClose_NilParams(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)

	sessionID := createWMPSession(t, a)

	a.mu.RLock()
	ws := a.peers[sessionID]
	a.mu.RUnlock()

	ws.handler.SessionClose(context.Background(), nil)

	_, err := a.Events(sessionID)
	assert.Error(t, err, "session should be closed even when params is nil")
}

// --- FlowCancel ---

// TestWMP_FlowCancel_UnknownFlow: cancelling an unknown flow reports it already terminal (spec §6.2).
func TestWMP_FlowCancel_UnknownFlow(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)

	sessionID := createWMPSession(t, a)

	body := wmpRequest("2", wmp.MethodFlowCancel, wmp.FlowCancelParams{
		WMP:    wmp.Metadata{Version: wmp.Version, SessionID: sessionID},
		FlowID: "nonexistent-flow",
	})

	resp, err := a.HandleRPC(context.Background(), sessionID, "", "", body)
	require.NoError(t, err)

	var rpcResp wmp.Response
	require.NoError(t, json.Unmarshal(resp, &rpcResp))
	require.NotNil(t, rpcResp.Error)
	assert.Equal(t, wmp.ErrFlowError, rpcResp.Error.Code)
}

// TestWMP_FlowCancel_Success: the RPC succeeds and invokes Handler.Cancel().
func TestWMP_FlowCancel_Success(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)

	cancelled := make(chan struct{})
	release := make(chan struct{})
	m.RegisterFlowHandler("cancel_test", func(flow *Flow, cfg *config.Config, logger *zap.Logger, trustSvc *TrustService, registry *RegistryClient, verifiers storage.VerifierStore, trustCache *TrustCache) (FlowHandler, error) {
		return &cancellableFlowHandler{flow: flow, cancelled: cancelled, release: release}, nil
	})

	sessionID := createWMPSession(t, a)

	body := wmpRequest("2", "wmp.flow.start", wmp.FlowStartParams{
		WMP:      wmp.Metadata{Version: wmp.Version, SessionID: sessionID},
		FlowType: "cancel_test",
		FlowID:   "flow-cancel",
	})
	resp, err := a.HandleRPC(context.Background(), sessionID, "", "", body)
	require.NoError(t, err)
	var startResp wmp.Response
	require.NoError(t, json.Unmarshal(resp, &startResp))
	require.Nil(t, startResp.Error)

	body = wmpRequest("3", wmp.MethodFlowCancel, wmp.FlowCancelParams{
		WMP:    wmp.Metadata{Version: wmp.Version, SessionID: sessionID},
		FlowID: "flow-cancel",
		Reason: wmp.CancelReasonUserCancelled,
	})
	resp, err = a.HandleRPC(context.Background(), sessionID, "", "", body)
	require.NoError(t, err)

	var rpcResp wmp.Response
	require.NoError(t, json.Unmarshal(resp, &rpcResp))
	require.Nil(t, rpcResp.Error)

	var result wmp.FlowCancelResult
	require.NoError(t, json.Unmarshal(rpcResp.Result, &result))
	assert.Equal(t, "flow-cancel", result.FlowID)
	assert.Equal(t, "cancelled", result.Status)

	select {
	case <-cancelled:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for flow handler's Cancel() to be invoked")
	}
}

// --- CapabilityList ---

// TestWMP_CapabilityList_Success: echoes the capabilities negotiated at session.create.
func TestWMP_CapabilityList_Success(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)

	sessionID := createWMPSession(t, a)

	body := wmpRequest("2", wmp.MethodCapabilityList, wmp.CapabilityListParams{
		WMP: wmp.Metadata{Version: wmp.Version, SessionID: sessionID},
	})
	resp, err := a.HandleRPC(context.Background(), sessionID, "", "", body)
	require.NoError(t, err)

	var rpcResp wmp.Response
	require.NoError(t, json.Unmarshal(resp, &rpcResp))
	require.Nil(t, rpcResp.Error)

	var result wmp.CapabilityListResult
	require.NoError(t, json.Unmarshal(rpcResp.Result, &result))
	assert.Contains(t, result.Capabilities, "flows")
	assert.Equal(t, "tls", result.Security.Mode)
}

// TestWMP_CapabilityList_SessionNotFound: the handler's own lookup for an unregistered session
// (HandleRPC normally gates this).
func TestWMP_CapabilityList_SessionNotFound(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)

	handler := &wmpEngineHandler{adapter: a, sessionID: "not-registered"}
	result, err := handler.CapabilityList(context.Background(), &wmp.CapabilityListParams{})
	assert.Nil(t, result)
	require.Error(t, err)
	rpcErr, ok := err.(*wmp.RPCError)
	require.True(t, ok, "expected a *wmp.RPCError, got %T", err)
	assert.Equal(t, wmp.ErrSessionNotFound, rpcErr.Code)
}

// --- CredentialNotification ---

// TestWMP_CredentialNotification_MissingID: wmp.credential.notification reaches
// dispatchCredentialNotification; a rejection arrives as a notification_ack event
// (not a JSON-RPC error), which also covers SendJSON's fallback branch. It must be sent as an
// id-less Notification: go-wmp rejects an invalid Request itself with -32602 (go-wmp#26/#27).
func TestWMP_CredentialNotification_MissingID(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)

	sessionID := createWMPSession(t, a)

	body := wmpNotification(wmp.MethodCredentialNotification, wmp.CredentialNotificationParams{
		WMP:    wmp.Metadata{Version: wmp.Version, SessionID: sessionID},
		FlowID: "flow-1",
		Event:  "credential_accepted",
		// NotificationID intentionally omitted.
	})

	resp, err := a.HandleRPC(context.Background(), sessionID, "", "", body)
	require.NoError(t, err)
	assert.Empty(t, resp, "a Notification must never produce a response body")

	events, err := a.Events(sessionID)
	require.NoError(t, err)

	select {
	case data := <-events:
		var env struct {
			JSONRPC string                   `json:"jsonrpc"`
			Method  string                   `json:"method"`
			Params  wmp.MessageDeliverParams `json:"params"`
		}
		require.NoError(t, json.Unmarshal(data, &env))
		assert.Equal(t, "2.0", env.JSONRPC)
		assert.Equal(t, wmp.MethodMessageDeliver, env.Method)
		var ack struct {
			Type   string `json:"type"`
			FlowID string `json:"flow_id"`
			Status string `json:"status"`
			Error  string `json:"error"`
		}
		require.NoError(t, json.Unmarshal(env.Params.Body, &ack))
		assert.Equal(t, "notification_ack", ack.Type)
		assert.Equal(t, "flow-1", ack.FlowID)
		assert.Equal(t, "rejected", ack.Status)
		assert.Equal(t, "missing notification_id", ack.Error)
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for notification_ack")
	}
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

// readSSELine reads lines until one contains want, or fails on timeout.
func readSSEUntil(t *testing.T, br *bufio.Reader, want string) {
	t.Helper()
	got := make(chan bool, 1)
	go func() {
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				got <- false
				return
			}
			if strings.Contains(line, want) {
				got <- true
				return
			}
		}
	}()
	select {
	case ok := <-got:
		require.True(t, ok, "stream ended before %q", want)
	case <-time.After(3 * time.Second):
		t.Fatalf("timeout waiting for %q", want)
	}
}

// Events_NewConnectionSupersedesStale: a second GET supersedes a stale open stream,
// ends the first, and replays from its own cursor without loss.
func TestWMP_HTTPEndpoint_Events_NewConnectionSupersedesStale(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)

	sessionID := createWMPSession(t, a)
	token := testToken("user-1", "tenant-a")
	buf := a.getOrCreateEventBuffer(sessionID)
	buf.append([]byte(`{"n":1}`))

	ts := httptest.NewServer(http.HandlerFunc(a.HandleWMPEvents))
	defer ts.Close()

	req1, _ := http.NewRequest(http.MethodGet, ts.URL+"?session_id="+sessionID, nil)
	req1.Header.Set("Authorization", "Bearer "+token)
	resp1, err := http.DefaultClient.Do(req1)
	require.NoError(t, err)
	defer resp1.Body.Close()
	require.Equal(t, http.StatusOK, resp1.StatusCode)
	br1 := bufio.NewReader(resp1.Body)
	readSSEUntil(t, br1, `"n":1`)

	// Event emitted while the (stale) first stream is still attached.
	buf.append([]byte(`{"n":2}`))
	readSSEUntil(t, br1, `"n":2`)

	req2, _ := http.NewRequest(http.MethodGet, ts.URL+"?session_id="+sessionID, nil)
	req2.Header.Set("Authorization", "Bearer "+token)
	req2.Header.Set("Last-Event-ID", "1")
	resp2, err := http.DefaultClient.Do(req2)
	require.NoError(t, err)
	defer resp2.Body.Close()
	require.Equal(t, http.StatusOK, resp2.StatusCode)
	br2 := bufio.NewReader(resp2.Body)
	readSSEUntil(t, br2, `"n":2`) // replayed after the cursor, not lost

	// The first stream is terminated by the supersede.
	done := make(chan struct{})
	go func() { _, _ = io.Copy(io.Discard, br1); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("superseded stream did not end")
	}

	// The new stream keeps receiving.
	buf.append([]byte(`{"n":3}`))
	readSSEUntil(t, br2, `"n":3`)
}

func TestWMP_HTTPEndpoint_Events_Heartbeat(t *testing.T) {
	old := wmpSSEHeartbeatInterval
	wmpSSEHeartbeatInterval = 20 * time.Millisecond
	defer func() { wmpSSEHeartbeatInterval = old }()

	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)
	sessionID := createWMPSession(t, a)

	ts := httptest.NewServer(http.HandlerFunc(a.HandleWMPEvents))
	defer ts.Close()
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"?session_id="+sessionID, nil)
	req.Header.Set("Authorization", "Bearer "+testToken("user-1", "tenant-a"))
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	readSSEUntil(t, bufio.NewReader(resp.Body), ": keepalive")
}

// TestWMPEventBuffer_AppendReplayAndAcquire: durable IDs, Last-Event-ID replay
// filtering, and single-active-connection enforcement.
func TestWMPEventBuffer_AppendReplayAndAcquire(t *testing.T) {
	buf := &wmpEventBuffer{}

	id1 := buf.append([]byte(`{"n":1}`))
	id2 := buf.append([]byte(`{"n":2}`))
	id3 := buf.append([]byte(`{"n":3}`))
	assert.Equal(t, []int64{1, 2, 3}, []int64{id1, id2, id3})
	assert.Equal(t, 3, buf.pendingCount())

	replay := buf.replaySince(strconv.FormatInt(id1, 10))
	require.Len(t, replay, 2)
	assert.Equal(t, id2, replay[0].ID)
	assert.Equal(t, id3, replay[1].ID)

	// Malformed/unknown Last-Event-ID: best-effort, no replay rather than an error.
	assert.Nil(t, buf.replaySince("not-a-number"))

	ctx1, cancel1 := context.WithCancel(context.Background())
	s1 := buf.acquire(cancel1)
	ctx2, cancel2 := context.WithCancel(context.Background())
	s2 := buf.acquire(cancel2)
	assert.Error(t, ctx1.Err(), "second connection must supersede the first")
	assert.NoError(t, ctx2.Err())

	buf.release(s1) // stale release must not clear the newer registration
	buf.acquire(func() {})
	assert.Error(t, ctx2.Err(), "newer registration must still have been active")
	buf.release(s2)
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
	resp, err := a.HandleRPC(context.Background(), sessionID, "", "", body)
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

// TestWMP_FlowAction_MatchResponse_FullPipeline: RequestMatch becomes a "match"
// sub-flow Call, and the client's flow.complete for it is routed back via matchCh.
func TestWMP_FlowAction_MatchResponse_FullPipeline(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)

	matchReceived := make(chan *MatchResponseMessage, 1)
	m.RegisterFlowHandler("match_test", func(flow *Flow, cfg *config.Config, logger *zap.Logger, trustSvc *TrustService, registry *RegistryClient, verifiers storage.VerifierStore, trustCache *TrustCache) (FlowHandler, error) {
		return &matchFlowHandler{
			flow:          flow,
			matchReceived: matchReceived,
		}, nil
	})

	sessionID := createWMPSession(t, a)

	body := wmpRequest("2", "wmp.flow.start", wmp.FlowStartParams{
		WMP:      wmp.Metadata{Version: wmp.Version, SessionID: sessionID},
		FlowType: "match_test",
		FlowID:   "flow-match",
	})
	resp, err := a.HandleRPC(context.Background(), sessionID, "", "", body)
	require.NoError(t, err)
	var startResp wmp.Response
	require.NoError(t, json.Unmarshal(resp, &startResp))
	assert.Nil(t, startResp.Error)

	// Read the match sub-flow start request off the SSE channel.
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
					FlowType string `json:"flow_type"`
					FlowID   string `json:"flow_id"`
				} `json:"params"`
			}
			if err := json.Unmarshal(msg, &parsed); err != nil {
				continue
			}
			if parsed.Method == wmp.MethodFlowStart && parsed.Params.FlowType == "match" {
				childFlowID = parsed.Params.FlowID
				rpcRequestID = parsed.ID
			}
		case <-timeout:
			t.Fatal("timeout waiting for match sub-flow start")
		}
	}
	require.NotEmpty(t, childFlowID)
	require.NotNil(t, rpcRequestID)

	// Respond to the JSON-RPC Call so Peer.Call unblocks.
	startResult := wmp.FlowStartResult{
		WMP:      wmp.Metadata{Version: wmp.Version, SessionID: sessionID},
		FlowID:   childFlowID,
		FlowType: "match",
	}
	resultJSON, _ := json.Marshal(startResult)
	rpcResponse, _ := json.Marshal(map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      rpcRequestID,
		"result":  json.RawMessage(resultJSON),
	})

	a.mu.RLock()
	ws := a.peers[sessionID]
	a.mu.RUnlock()
	require.NoError(t, ws.transport.Push(rpcResponse))

	time.Sleep(100 * time.Millisecond)

	// Send flow.complete for the child match sub-flow with the match result.
	completeResult, _ := json.Marshal(map[string]interface{}{
		"matches": []map[string]string{{"credential_id": "cred-1", "format": "vc+sd-jwt"}},
	})
	completeNotification, _ := json.Marshal(map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  wmp.MethodFlowComplete,
		"params": wmp.FlowCompleteParams{
			FlowID: childFlowID,
			Result: completeResult,
		},
	})
	require.NoError(t, ws.transport.Push(completeNotification))

	select {
	case mr := <-matchReceived:
		require.Len(t, mr.Matches, 1)
		assert.Equal(t, "cred-1", mr.Matches[0].CredentialID)
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for match response in handler")
	}
}

// TestWmpSessionTransport_SendJSON_FlowError: a FlowErrorMessage becomes wmp.flow.error with the mapped code.
func TestWmpSessionTransport_SendJSON_FlowError(t *testing.T) {
	ct := wmp.NewChannelTransport(5, 5)
	handler := &wmpEngineHandler{sessionID: "sess-err"}
	peer := wmp.NewPeer(ct, handler)
	transport := newWMPSessionTransport(peer, ct)
	transport.handler = handler

	err := transport.SendJSON(&FlowErrorMessage{
		Message: Message{FlowID: "flow-1"},
		Error:   FlowError{Code: ErrCodeSignError, Message: "boom"},
	})
	require.NoError(t, err)

	select {
	case data := <-ct.Out():
		var notif struct {
			Method string              `json:"method"`
			Params wmp.FlowErrorParams `json:"params"`
		}
		require.NoError(t, json.Unmarshal(data, &notif))
		assert.Equal(t, wmp.MethodFlowError, notif.Method)
		assert.Equal(t, "flow-1", notif.Params.FlowID)
		assert.Equal(t, wmp.ErrSignatureInvalid, notif.Params.Code)
		assert.Equal(t, "boom", notif.Params.Message)
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for flow.error notification")
	}
}

// TestWmpSessionTransport_SendJSON_SignRequest_FieldParity: every SignRequestParams
// field (DPoP params, selection, verifier-session binding) must survive the
// translation to openid4x.SignSubFlowParams.
func TestWmpSessionTransport_SendJSON_SignRequest_FieldParity(t *testing.T) {
	ct := wmp.NewChannelTransport(5, 5)
	handler := &wmpEngineHandler{sessionID: "sess-sign"}
	peer := wmp.NewPeer(ct, handler)
	transport := newWMPSessionTransport(peer, ct)
	transport.handler = handler

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go peer.Serve(ctx)

	in := SignRequestMessage{
		Message: Message{FlowID: "flow-1", MessageID: "msg-1"},
		Action:  SignActionSignClientAuth,
		Params: SignRequestParams{
			Audience:              "aud",
			Nonce:                 "nonce-1",
			Issuer:                "https://wallet.example.com/cb",
			ProofType:             "jwt",
			ProofTypesSupported:   map[string]interface{}{"jwt": map[string]interface{}{}},
			Count:                 2,
			ResponseURI:           "https://verifier.example.com/response",
			VerifierJwkThumbprint: "thumb-1",
			VerifierSessionID:     "vsess-1",
			ReissuanceKid:         "kid-1",
			HTM:                   "POST",
			HTU:                   "https://as.example.com/token",
			DPoPNonce:             "dpop-nonce-1",
			ATH:                   "ath-1",
			KeyID:                 "instance-key-1",
			AttestationChallenge:  "chal-abc",
			ResponseMode:          "direct_post",
			TransactionData: []TransactionData{{
				Type:                     "payment",
				Raw:                      "eyJ0eXBlIjoicGF5bWVudCJ9",
				Payload:                  json.RawMessage(`{"amount":"10"}`),
				Params:                   map[string]interface{}{"amount": "10"},
				CredentialIDs:            []string{"cred-1"},
				HashAlgorithm:            "sha-256",
				TransactionDataHashesAlg: HashAlgList{"sha-256", "sha-384"},
			}},
			CredentialsToInclude: []CredentialRef{{
				CredentialQueryID: "q-1",
				CredentialID:      "cred-1",
				DisclosedClaims:   []string{"given_name"},
			}},
		},
	}

	errCh := make(chan error, 1)
	go func() { errCh <- transport.SendJSON(&in) }()

	var params openid4x.SignSubFlowParams
	var rpcID json.RawMessage
	select {
	case data := <-ct.Out():
		var req struct {
			ID     json.RawMessage     `json:"id"`
			Method string              `json:"method"`
			Params wmp.FlowStartParams `json:"params"`
		}
		require.NoError(t, json.Unmarshal(data, &req))
		require.Equal(t, wmp.MethodFlowStart, req.Method)
		require.NoError(t, json.Unmarshal(req.Params.Params, &params))
		rpcID = req.ID
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for wmp.flow.start")
	}

	// Unblock the Call() by responding to the child flow.start.
	resultJSON, _ := json.Marshal(wmp.FlowStartResult{
		WMP: wmp.Metadata{Version: wmp.Version, SessionID: "sess-sign"},
	})
	rpcResponse, _ := json.Marshal(map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      rpcID,
		"result":  json.RawMessage(resultJSON),
	})
	require.NoError(t, ct.Push(rpcResponse))

	select {
	case err := <-errCh:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for SendJSON to return")
	}

	assert.Equal(t, string(in.Action), params.Action)
	assert.Equal(t, in.Params.Nonce, params.Nonce)
	assert.Equal(t, in.Params.Audience, params.Audience)
	assert.Equal(t, in.Params.ProofType, params.ProofType)
	assert.Equal(t, in.FlowID, params.ParentFlowID)
	assert.Equal(t, in.Params.Issuer, params.Issuer)
	assert.Equal(t, in.Params.ProofTypesSupported, params.ProofTypesSupported)
	assert.Equal(t, in.Params.Count, params.Count)
	assert.Equal(t, in.Params.ResponseURI, params.ResponseURI)
	assert.Equal(t, in.Params.VerifierJwkThumbprint, params.VerifierJWKThumbprint)
	assert.Equal(t, in.Params.VerifierSessionID, params.VerifierSessionID)
	assert.Equal(t, in.Params.ReissuanceKid, params.ReissuanceKid)
	assert.Equal(t, in.Params.HTM, params.HTM)
	assert.Equal(t, in.Params.HTU, params.HTU)
	assert.Equal(t, in.Params.DPoPNonce, params.DPoPNonce)
	assert.Equal(t, in.Params.ATH, params.ATH)
	assert.Equal(t, in.Params.KeyID, params.KeyID)
	assert.Equal(t, in.Params.AttestationChallenge, params.AttestationChallenge)
	require.Len(t, params.TransactionData, 1)
	assert.Equal(t, in.Params.TransactionData[0].Type, params.TransactionData[0].Type)
	assert.Equal(t, in.Params.TransactionData[0].CredentialIDs, params.TransactionData[0].CredentialIDs)
	// The wallet needs the string to hash, the payload, the hash algorithms and the response mode.
	assert.Equal(t, in.Params.TransactionData[0].Raw, params.TransactionData[0].Raw)
	assert.JSONEq(t, string(in.Params.TransactionData[0].Payload), string(params.TransactionData[0].Payload))
	assert.Equal(t, openid4x.HashAlgs{"sha-256", "sha-384"}, params.TransactionData[0].TransactionDataHashesAlg)
	assert.Equal(t, in.Params.ResponseMode, params.ResponseMode)
	require.Len(t, params.CredentialsToInclude, 1)
	assert.Equal(t, in.Params.CredentialsToInclude[0].CredentialID, params.CredentialsToInclude[0].CredentialID)
	assert.Equal(t, in.Params.CredentialsToInclude[0].DisclosedClaims, params.CredentialsToInclude[0].DisclosedClaims)
}

// TestWmpSessionTransport_ReadMessage: delegates to the ChannelTransport.
func TestWmpSessionTransport_ReadMessage(t *testing.T) {
	ct := wmp.NewChannelTransport(1, 1)
	transport := newWMPSessionTransport(nil, ct)

	require.NoError(t, ct.Push([]byte(`{"hello":"world"}`)))

	data, err := transport.ReadMessage(context.Background())
	require.NoError(t, err)
	assert.JSONEq(t, `{"hello":"world"}`, string(data))
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

// TestWmpResponseBytes_MarshalFailureFallsBackToInternalError: a result that
// cannot be marshaled degrades to an internal-error response.
func TestWmpResponseBytes_MarshalFailureFallsBackToInternalError(t *testing.T) {
	resp, err := wmpResponseBytes(json.RawMessage(`"1"`), make(chan int))
	require.NoError(t, err)

	var rpcResp wmp.Response
	require.NoError(t, json.Unmarshal(resp, &rpcResp))
	require.NotNil(t, rpcResp.Error)
	assert.Equal(t, wmp.ErrInternalError, rpcResp.Error.Code)
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

	resp, err := a.HandleRPC(context.Background(), "", "", "", body)
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

// cancellableFlowHandler blocks in Execute until Cancel() is invoked or the test times out.
type cancellableFlowHandler struct {
	flow      *Flow
	cancelled chan struct{}
	release   chan struct{}
	once      sync.Once
}

func (h *cancellableFlowHandler) Execute(ctx context.Context, msg *FlowStartMessage) error {
	<-h.release
	return nil
}

// Cancel is idempotent: session teardown cancels active flows again.
func (h *cancellableFlowHandler) Cancel() {
	h.once.Do(func() {
		close(h.cancelled)
		close(h.release)
	})
}

// matchFlowHandler requests a DCQL match and reports what it received.
type matchFlowHandler struct {
	flow          *Flow
	matchReceived chan *MatchResponseMessage
}

func (h *matchFlowHandler) Execute(ctx context.Context, msg *FlowStartMessage) error {
	_ = h.flow.Session.SendProgress(h.flow.ID, "preparing", nil)

	resp, err := h.flow.Session.RequestMatch(ctx, h.flow.ID, json.RawMessage(`{"credentials":{}}`))
	if err != nil {
		_ = h.flow.Session.SendFlowError(h.flow.ID, "", ErrCodeFlowTimeout, err.Error())
		return err
	}

	h.matchReceived <- resp
	_ = h.flow.Session.SendFlowComplete(h.flow.ID, nil, "")
	return nil
}

func (h *matchFlowHandler) Cancel() {}

// FlowAction branches: handlers are built directly, since FlowAction only needs a
// Session with a registered flow and the relevant channel.

func TestWMP_FlowAction_SignResponse_MessageIDFromStructDecode(t *testing.T) {
	session := &Session{
		flows:  map[string]*Flow{"flow-1": {ID: "flow-1"}},
		signCh: make(chan *SignResponseMessage, 1),
	}
	handler := &wmpEngineHandler{session: session, sessionID: "sess-1"}

	params, _ := json.Marshal(map[string]string{
		"proof_jwt":  "eyJ.header.sig",
		"message_id": "msg-42",
	})

	result, err := handler.FlowAction(context.Background(), &wmp.FlowActionParams{
		FlowID: "flow-1",
		Action: "sign_response",
		Params: params,
	})
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "accepted", result.Status)
	assert.Equal(t, "flow-1", result.FlowID)

	select {
	case sr := <-session.signCh:
		assert.Equal(t, "flow-1", sr.FlowID)
		assert.Equal(t, "msg-42", sr.MessageID)
		assert.Equal(t, "eyJ.header.sig", sr.ProofJWT)
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for sign response on signCh")
	}
}

// TestWMP_FlowAction_SignResponse_MessageIDFallbackWhenAbsent: exercises the
// raw-params fallback; message_id is already promoted by the embedded Message,
// so the fallback recovers nothing extra.
func TestWMP_FlowAction_SignResponse_MessageIDFallbackWhenAbsent(t *testing.T) {
	session := &Session{
		flows:  map[string]*Flow{"flow-1": {ID: "flow-1"}},
		signCh: make(chan *SignResponseMessage, 1),
	}
	handler := &wmpEngineHandler{session: session, sessionID: "sess-1"}

	params, _ := json.Marshal(map[string]string{"proof_jwt": "eyJ.header.sig"})

	result, err := handler.FlowAction(context.Background(), &wmp.FlowActionParams{
		FlowID: "flow-1",
		Action: "sign_response",
		Params: params,
	})
	require.NoError(t, err)
	require.NotNil(t, result)

	select {
	case sr := <-session.signCh:
		assert.Equal(t, "flow-1", sr.FlowID)
		assert.Empty(t, sr.MessageID)
		assert.Equal(t, "eyJ.header.sig", sr.ProofJWT)
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for sign response on signCh")
	}
}

func TestWMP_FlowAction_SignResponse_NilParams(t *testing.T) {
	session := &Session{
		flows:  map[string]*Flow{"flow-1": {ID: "flow-1"}},
		signCh: make(chan *SignResponseMessage, 1),
	}
	handler := &wmpEngineHandler{session: session, sessionID: "sess-1"}

	result, err := handler.FlowAction(context.Background(), &wmp.FlowActionParams{
		FlowID: "flow-1",
		Action: "sign_response",
		Params: nil,
	})
	require.NoError(t, err)
	require.NotNil(t, result)

	select {
	case sr := <-session.signCh:
		assert.Equal(t, "flow-1", sr.FlowID)
		assert.Empty(t, sr.MessageID)
		assert.Empty(t, sr.ProofJWT)
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for sign response on signCh")
	}
}

func TestWMP_FlowAction_SignResponse_InvalidParamsJSON(t *testing.T) {
	session := &Session{
		flows:  map[string]*Flow{"flow-1": {ID: "flow-1"}},
		signCh: make(chan *SignResponseMessage, 1),
	}
	handler := &wmpEngineHandler{session: session, sessionID: "sess-1"}

	result, err := handler.FlowAction(context.Background(), &wmp.FlowActionParams{
		FlowID: "flow-1",
		Action: "sign_response",
		Params: json.RawMessage(`{not-valid-json`),
	})
	require.Nil(t, result)
	require.Error(t, err)
	rpcErr, ok := err.(*wmp.RPCError)
	require.True(t, ok, "expected *wmp.RPCError, got %T", err)
	assert.Equal(t, wmp.ErrInvalidParams, rpcErr.Code)

	// The channel must not have received anything.
	select {
	case <-session.signCh:
		t.Fatal("signCh should not have received a message on decode failure")
	default:
	}
}

func TestWMP_FlowAction_MatchResponse_Success(t *testing.T) {
	session := &Session{
		flows:   map[string]*Flow{"flow-1": {ID: "flow-1"}},
		matchCh: make(chan *MatchResponseMessage, 1),
	}
	handler := &wmpEngineHandler{session: session, sessionID: "sess-1"}

	params, _ := json.Marshal(map[string]interface{}{
		"message_id": "msg-99",
		"matches": []map[string]string{
			{"credential_id": "cred-abc", "format": "vc+sd-jwt"},
		},
	})

	result, err := handler.FlowAction(context.Background(), &wmp.FlowActionParams{
		FlowID: "flow-1",
		Action: "match_response",
		Params: params,
	})
	require.NoError(t, err)
	require.NotNil(t, result)

	select {
	case mr := <-session.matchCh:
		assert.Equal(t, "flow-1", mr.FlowID)
		assert.Equal(t, "msg-99", mr.MessageID)
		require.Len(t, mr.Matches, 1)
		assert.Equal(t, "cred-abc", mr.Matches[0].CredentialID)
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for match response on matchCh")
	}
}

func TestWMP_FlowAction_MatchResponse_InvalidParamsJSON(t *testing.T) {
	session := &Session{
		flows:   map[string]*Flow{"flow-1": {ID: "flow-1"}},
		matchCh: make(chan *MatchResponseMessage, 1),
	}
	handler := &wmpEngineHandler{session: session, sessionID: "sess-1"}

	result, err := handler.FlowAction(context.Background(), &wmp.FlowActionParams{
		FlowID: "flow-1",
		Action: "match_response",
		Params: json.RawMessage(`[[[`),
	})
	require.Nil(t, result)
	require.Error(t, err)
	rpcErr, ok := err.(*wmp.RPCError)
	require.True(t, ok, "expected *wmp.RPCError, got %T", err)
	assert.Equal(t, wmp.ErrInvalidParams, rpcErr.Code)
}

// TestWMP_FlowAction_SpecActionTranslation: spec action names (specToEngineAction)
// are translated to engine names; engine-native names pass through.
func TestWMP_FlowAction_SpecActionTranslation(t *testing.T) {
	tests := []struct {
		name           string
		specAction     string
		expectedEngine string
	}{
		{"accept_offer_maps_to_consent", "accept_offer", ActionConsent},
		{"provide_tx_code_maps_to_provide_pin", "provide_tx_code", ActionProvidePin},
		{"authorize_maps_to_authorization_complete", "authorize", ActionAuthorizationComplete},
		{"select_credentials_maps_to_consent", "select_credentials", ActionConsent},
		{"cancel_maps_to_decline", "cancel", ActionDecline},
		{"trust_result_passes_through_untranslated", "trust_result", "trust_result"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := &Session{
				flows:    map[string]*Flow{"flow-1": {ID: "flow-1"}},
				actionCh: make(chan *FlowActionMessage, 1),
			}
			handler := &wmpEngineHandler{session: session, sessionID: "sess-1"}

			result, err := handler.FlowAction(context.Background(), &wmp.FlowActionParams{
				FlowID: "flow-1",
				Action: tt.specAction,
			})
			require.NoError(t, err)
			require.NotNil(t, result)
			// The result always echoes back the original (untranslated) action name.
			assert.Equal(t, tt.specAction, result.Action)

			select {
			case am := <-session.actionCh:
				assert.Equal(t, tt.expectedEngine, am.Action)
				assert.Equal(t, "flow-1", am.FlowID)
			case <-time.After(time.Second):
				t.Fatal("timeout waiting for translated action on actionCh")
			}
		})
	}
}

// FlowStart: validation, limit and error branches.

func TestWMP_FlowStart_FlowIDTooLong(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)

	sessionID := createWMPSession(t, a)

	tooLong := string(bytes.Repeat([]byte("a"), maxFlowIDLength+1))
	body := wmpRequest("2", "wmp.flow.start", wmp.FlowStartParams{
		WMP:      wmp.Metadata{Version: wmp.Version, SessionID: sessionID},
		FlowType: "any_protocol",
		FlowID:   tooLong,
	})

	resp, err := a.HandleRPC(context.Background(), sessionID, "", "", body)
	require.NoError(t, err)

	var rpcResp wmp.Response
	require.NoError(t, json.Unmarshal(resp, &rpcResp))
	require.NotNil(t, rpcResp.Error)
	assert.Equal(t, wmp.ErrInvalidParams, rpcResp.Error.Code)
}

func TestWMP_FlowStart_ConcurrentFlowLimit(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)

	m.RegisterFlowHandler("limit_test", func(flow *Flow, cfg *config.Config, logger *zap.Logger, trustSvc *TrustService, registry *RegistryClient, verifiers storage.VerifierStore, trustCache *TrustCache) (FlowHandler, error) {
		return nil, nil
	})

	sessionID := createWMPSession(t, a)

	a.mu.RLock()
	ws := a.peers[sessionID]
	a.mu.RUnlock()
	require.NotNil(t, ws)

	ws.session.flowsMu.Lock()
	for i := 0; i < MaxPendingFlowsPerSession; i++ {
		id := "existing-flow-" + strconv.Itoa(i)
		ws.session.flows[id] = &Flow{ID: id}
	}
	ws.session.flowsMu.Unlock()

	body := wmpRequest("2", "wmp.flow.start", wmp.FlowStartParams{
		WMP:      wmp.Metadata{Version: wmp.Version, SessionID: sessionID},
		FlowType: "limit_test",
		FlowID:   "flow-overflow",
	})

	resp, err := a.HandleRPC(context.Background(), sessionID, "", "", body)
	require.NoError(t, err)

	var rpcResp wmp.Response
	require.NoError(t, json.Unmarshal(resp, &rpcResp))
	require.NotNil(t, rpcResp.Error)
	assert.Equal(t, wmp.ErrRateLimited, rpcResp.Error.Code)

	ws.session.flowsMu.RLock()
	_, exists := ws.session.flows["flow-overflow"]
	ws.session.flowsMu.RUnlock()
	assert.False(t, exists, "flow must not be registered once the concurrency limit rejects it")
}

func TestWMP_FlowStart_InvalidParamsJSON(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)

	m.RegisterFlowHandler("invalid_params_test", func(flow *Flow, cfg *config.Config, logger *zap.Logger, trustSvc *TrustService, registry *RegistryClient, verifiers storage.VerifierStore, trustCache *TrustCache) (FlowHandler, error) {
		return &mockFlowHandler{flow: flow, progressSent: make(chan struct{})}, nil
	})

	sessionID := createWMPSession(t, a)

	// A JSON string is valid JSON but does not unmarshal into FlowStartMessage ("invalid flow params").
	body := wmpRequest("2", "wmp.flow.start", wmp.FlowStartParams{
		WMP:      wmp.Metadata{Version: wmp.Version, SessionID: sessionID},
		FlowType: "invalid_params_test",
		FlowID:   "flow-bad-params",
		Params:   json.RawMessage(`"not-an-object"`),
	})

	resp, err := a.HandleRPC(context.Background(), sessionID, "", "", body)
	require.NoError(t, err)

	var rpcResp wmp.Response
	require.NoError(t, json.Unmarshal(resp, &rpcResp))
	require.NotNil(t, rpcResp.Error)
	assert.Equal(t, wmp.ErrInvalidParams, rpcResp.Error.Code)

	a.mu.RLock()
	ws := a.peers[sessionID]
	a.mu.RUnlock()
	require.NotNil(t, ws)
	ws.session.flowsMu.RLock()
	_, exists := ws.session.flows["flow-bad-params"]
	ws.session.flowsMu.RUnlock()
	assert.False(t, exists, "flow must be de-registered when params fail to parse")
}

func TestWMP_FlowStart_HandlerFactoryError(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)

	m.RegisterFlowHandler("factory_error_test", func(flow *Flow, cfg *config.Config, logger *zap.Logger, trustSvc *TrustService, registry *RegistryClient, verifiers storage.VerifierStore, trustCache *TrustCache) (FlowHandler, error) {
		return nil, context.Canceled
	})

	sessionID := createWMPSession(t, a)

	body := wmpRequest("2", "wmp.flow.start", wmp.FlowStartParams{
		WMP:      wmp.Metadata{Version: wmp.Version, SessionID: sessionID},
		FlowType: "factory_error_test",
		FlowID:   "flow-factory-fail",
	})

	resp, err := a.HandleRPC(context.Background(), sessionID, "", "", body)
	require.NoError(t, err)

	var rpcResp wmp.Response
	require.NoError(t, json.Unmarshal(resp, &rpcResp))
	require.NotNil(t, rpcResp.Error)
	assert.Equal(t, wmp.ErrInternalError, rpcResp.Error.Code)

	a.mu.RLock()
	ws := a.peers[sessionID]
	a.mu.RUnlock()
	require.NotNil(t, ws)
	ws.session.flowsMu.RLock()
	_, exists := ws.session.flows["flow-factory-fail"]
	ws.session.flowsMu.RUnlock()
	assert.False(t, exists, "flow must be de-registered when the handler factory fails")
}

// TestWMP_FlowStart_CustomTimeoutAppliedToContext: a client timeout is applied to the flow context.
func TestWMP_FlowStart_CustomTimeoutAppliedToContext(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)

	deadlines := make(chan time.Time, 1)
	m.RegisterFlowHandler("timeout_test", func(flow *Flow, cfg *config.Config, logger *zap.Logger, trustSvc *TrustService, registry *RegistryClient, verifiers storage.VerifierStore, trustCache *TrustCache) (FlowHandler, error) {
		return &deadlineCapturingFlowHandler{flow: flow, deadlines: deadlines}, nil
	})

	sessionID := createWMPSession(t, a)

	body := wmpRequest("2", "wmp.flow.start", wmp.FlowStartParams{
		WMP:      wmp.Metadata{Version: wmp.Version, SessionID: sessionID},
		FlowType: "timeout_test",
		FlowID:   "flow-custom-timeout",
		Timeout:  2, // seconds -- far below defaultFlowTimeout (5 minutes)
	})

	resp, err := a.HandleRPC(context.Background(), sessionID, "", "", body)
	require.NoError(t, err)

	var rpcResp wmp.Response
	require.NoError(t, json.Unmarshal(resp, &rpcResp))
	require.Nil(t, rpcResp.Error)

	select {
	case dl := <-deadlines:
		assert.WithinDuration(t, time.Now().Add(2*time.Second), dl, 1*time.Second,
			"context deadline should reflect the client-supplied 2s timeout, not the 5-minute default")
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for handler to report its context deadline")
	}
}

// deadlineCapturingFlowHandler reports the deadline of its execution context.
type deadlineCapturingFlowHandler struct {
	flow      *Flow
	deadlines chan time.Time
}

func (h *deadlineCapturingFlowHandler) Execute(ctx context.Context, msg *FlowStartMessage) error {
	if dl, ok := ctx.Deadline(); ok {
		h.deadlines <- dl
	}
	_ = h.flow.Session.SendFlowComplete(h.flow.ID, nil, "")
	return nil
}

func (h *deadlineCapturingFlowHandler) Cancel() {}

// FlowComplete: child-flow result routing.

func TestWMP_FlowComplete_MatchRouting(t *testing.T) {
	session := &Session{matchCh: make(chan *MatchResponseMessage, 1)}
	handler := &wmpEngineHandler{
		adapter:   &WMPAdapter{logger: zap.NewNop()},
		session:   session,
		sessionID: "sess-1",
	}
	handler.registerChildFlow("child-match-1", "parent-flow-1", "msg-match-1", "match")

	result, _ := json.Marshal(map[string]interface{}{
		"matches": []map[string]string{{"credential_id": "cred-xyz", "format": "mso_mdoc"}},
	})
	handler.FlowComplete(context.Background(), &wmp.FlowCompleteParams{
		FlowID: "child-match-1",
		Result: result,
	})

	select {
	case mr := <-session.matchCh:
		assert.Equal(t, "parent-flow-1", mr.FlowID)
		assert.Equal(t, "msg-match-1", mr.MessageID)
		require.Len(t, mr.Matches, 1)
		assert.Equal(t, "cred-xyz", mr.Matches[0].CredentialID)
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for match response on matchCh")
	}

	// The child flow entry must have been consumed (popped) by FlowComplete.
	_, stillTracked := handler.popChildFlow("child-match-1")
	assert.False(t, stillTracked, "child flow should have been popped by FlowComplete")
}

// TestWMP_FlowComplete_UnknownChildFlow_NoOp: flow.complete for an unregistered child flow is ignored.
func TestWMP_FlowComplete_UnknownChildFlow_NoOp(t *testing.T) {
	session := &Session{
		signCh:  make(chan *SignResponseMessage, 1),
		matchCh: make(chan *MatchResponseMessage, 1),
	}
	handler := &wmpEngineHandler{
		adapter:   &WMPAdapter{logger: zap.NewNop()},
		session:   session,
		sessionID: "sess-1",
	}

	result, _ := json.Marshal(map[string]string{"proof_jwt": "irrelevant"})
	handler.FlowComplete(context.Background(), &wmp.FlowCompleteParams{
		FlowID: "top-level-flow-not-a-child",
		Result: result,
	})

	select {
	case <-session.signCh:
		t.Fatal("signCh should not receive anything for an untracked flow ID")
	case <-session.matchCh:
		t.Fatal("matchCh should not receive anything for an untracked flow ID")
	case <-time.After(100 * time.Millisecond):
		// Expected: no routing happened.
	}
}

// TestWMP_FlowComplete_MalformedResultStillRoutes: an undecodable Result is still
// routed with the FlowID/MessageID so RequestSign/RequestMatch does not hang.
func TestWMP_FlowComplete_MalformedResultStillRoutes(t *testing.T) {
	session := &Session{signCh: make(chan *SignResponseMessage, 1)}
	handler := &wmpEngineHandler{
		adapter:   &WMPAdapter{logger: zap.NewNop()},
		session:   session,
		sessionID: "sess-1",
	}
	handler.registerChildFlow("child-sign-1", "parent-flow-2", "msg-sign-2", "sign")

	handler.FlowComplete(context.Background(), &wmp.FlowCompleteParams{
		FlowID: "child-sign-1",
		Result: json.RawMessage(`{"proof_jwt": not-valid}`),
	})

	select {
	case sr := <-session.signCh:
		assert.Equal(t, "parent-flow-2", sr.FlowID)
		assert.Equal(t, "msg-sign-2", sr.MessageID)
		assert.Empty(t, sr.ProofJWT, "malformed result should decode to a zero-valued field, not error out")
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for sign response on signCh")
	}
}

// HandleWMPRPC / HandleWMPEvents / HandleWMPConfiguration: HTTP handler coverage.

func TestWMP_HTTPEndpoint_RPC_InvalidToken(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)

	body := wmpRequest("1", "wmp.session.create", map[string]string{})
	req := httptest.NewRequest(http.MethodPost, "/wmp/rpc", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+expiredToken("user-1"))
	w := httptest.NewRecorder()

	a.HandleWMPRPC(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestWMP_HTTPEndpoint_RPC_SessionOwnershipMismatch: another user's session ID must
// answer 404, not leak existence via 403.
func TestWMP_HTTPEndpoint_RPC_SessionOwnershipMismatch(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)

	sessionID := createWMPSession(t, a) // owned by user-1/tenant-a

	body := wmpRequest("2", "wmp.flow.action", wmp.FlowActionParams{
		FlowID: "flow-1",
		Action: "consent",
	})
	req := httptest.NewRequest(http.MethodPost, "/wmp/rpc", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+testToken("user-2", "tenant-a"))
	req.Header.Set("Wmp-Session-Id", sessionID)
	w := httptest.NewRecorder()

	a.HandleWMPRPC(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

// TestWMP_HTTPEndpoint_RPC_OversizedBody: a body over maxWMPRPCBodyBytes gets 413.
func TestWMP_HTTPEndpoint_RPC_OversizedBody(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)

	padding := strings.Repeat("x", maxWMPRPCBodyBytes+1024)
	body := wmpRequest("1", "wmp.session.create", map[string]string{"padding": padding})
	require.Greater(t, len(body), maxWMPRPCBodyBytes, "body must exceed the RPC size cap for this test to be meaningful")

	req := httptest.NewRequest(http.MethodPost, "/wmp/rpc", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+testToken("user-1", "tenant-a"))
	w := httptest.NewRecorder()

	a.HandleWMPRPC(w, req)

	assert.Equal(t, http.StatusRequestEntityTooLarge, w.Code)
}

// TestWMP_HTTPEndpoint_RPC_Notification_Accepted: an id-less notification gets 202
// with no body even though dispatch fails. HandleWMPRPC's error-envelope fallback
// (HandleRPC returning a non-nil error) is unreachable through this endpoint.
func TestWMP_HTTPEndpoint_RPC_Notification_Accepted(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)

	sessionID := createWMPSession(t, a)

	notif, err := json.Marshal(map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "wmp.flow.action",
		"params": wmp.FlowActionParams{
			FlowID: "nonexistent-flow",
			Action: "consent",
		},
	})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/wmp/rpc", bytes.NewReader(notif))
	req.Header.Set("Authorization", "Bearer "+testToken("user-1", "tenant-a"))
	req.Header.Set("Wmp-Session-Id", sessionID)
	w := httptest.NewRecorder()

	a.HandleWMPRPC(w, req)

	assert.Equal(t, http.StatusAccepted, w.Code, "go-wmp client accepts only 200/202")
	assert.Empty(t, w.Body.Bytes())
}

func TestWMP_HTTPEndpoint_Events_WrongMethod(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)

	req := httptest.NewRequest(http.MethodPost, "/wmp/events", nil)
	w := httptest.NewRecorder()

	a.HandleWMPEvents(w, req)

	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
}

func TestWMP_HTTPEndpoint_Events_NoAuth(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)

	req := httptest.NewRequest(http.MethodGet, "/wmp/events?session_id=whatever", nil)
	w := httptest.NewRecorder()

	a.HandleWMPEvents(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestWMP_HTTPEndpoint_Events_InvalidToken(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)

	req := httptest.NewRequest(http.MethodGet, "/wmp/events?session_id=whatever", nil)
	req.Header.Set("Authorization", "Bearer "+expiredToken("user-1"))
	w := httptest.NewRecorder()

	a.HandleWMPEvents(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestWMP_HTTPEndpoint_Events_StreamsEvent: a flow's progress notification arrives over SSE.
func TestWMP_HTTPEndpoint_Events_StreamsEvent(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)

	progressSent := make(chan struct{})
	m.RegisterFlowHandler("stream_test", func(flow *Flow, cfg *config.Config, logger *zap.Logger, trustSvc *TrustService, registry *RegistryClient, verifiers storage.VerifierStore, trustCache *TrustCache) (FlowHandler, error) {
		return &mockFlowHandler{
			flow:         flow,
			progressSent: progressSent,
		}, nil
	})

	sessionID := createWMPSession(t, a)
	token := testToken("user-1", "tenant-a")

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.HandleWMPEvents(w, r)
	}))
	defer ts.Close()

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"?session_id="+sessionID, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// Start a flow while the SSE connection is live.
	body := wmpRequest("2", "wmp.flow.start", wmp.FlowStartParams{
		WMP:      wmp.Metadata{Version: wmp.Version, SessionID: sessionID},
		FlowType: "stream_test",
		FlowID:   "flow-stream",
	})
	rpcResp, err := a.HandleRPC(context.Background(), sessionID, "", "", body)
	require.NoError(t, err)
	var startResp wmp.Response
	require.NoError(t, json.Unmarshal(rpcResp, &startResp))
	require.Nil(t, startResp.Error)

	select {
	case <-progressSent:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for handler to send progress")
	}

	type readResult struct {
		line string
		err  error
	}
	lines := make(chan readResult, 4)
	go func() {
		reader := bufio.NewReader(resp.Body)
		for {
			l, err := reader.ReadString('\n')
			lines <- readResult{l, err}
			if err != nil {
				return
			}
		}
	}()

	var gotData string
	deadline := time.After(3 * time.Second)
readLoop:
	for {
		select {
		case r := <-lines:
			if r.err != nil {
				t.Fatalf("read error before seeing an SSE data line: %v", r.err)
			}
			trimmed := strings.TrimSpace(r.line)
			if strings.HasPrefix(trimmed, "data: ") {
				gotData = strings.TrimPrefix(trimmed, "data: ")
				break readLoop
			}
		case <-deadline:
			t.Fatal("timeout waiting for SSE data line")
		}
	}

	var notif struct {
		JSONRPC string `json:"jsonrpc"`
		Method  string `json:"method"`
	}
	require.NoError(t, json.Unmarshal([]byte(gotData), &notif))
	assert.Equal(t, "2.0", notif.JSONRPC)
	assert.Contains(t, []string{wmp.MethodFlowProgress, wmp.MethodFlowComplete}, notif.Method)
}

func TestWMP_HTTPEndpoint_Configuration(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)
	require.NoError(t, a.SetExternalURL("https://wallet.example.com/"))

	req := httptest.NewRequest(http.MethodGet, "/.well-known/wmp-configuration", nil)
	w := httptest.NewRecorder()

	a.HandleWMPConfiguration(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))

	var cfg wmp.WellKnownConfig
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &cfg))
	assert.Equal(t, wmp.SupportedVersions, cfg.SupportedVersions)
	assert.Equal(t, []string{"tls"}, cfg.SecurityModes)
	assert.Contains(t, cfg.Capabilities, "sign")
	assert.Contains(t, cfg.Capabilities, "flows")
	assert.Equal(t, "https://wallet.example.com/api/v2/wallet/rpc", cfg.Endpoints["rpc"])
	assert.Equal(t, "https://wallet.example.com/api/v2/wallet/rpc/events", cfg.Endpoints["events"])
}

// Without a usable external URL, discovery fails closed.
func TestWMP_HTTPEndpoint_Configuration_NoExternalURL_FailsClosed(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)

	w := httptest.NewRecorder()
	a.HandleWMPConfiguration(w, httptest.NewRequest(http.MethodGet, "/.well-known/wmp-configuration", nil))
	assert.Equal(t, http.StatusServiceUnavailable, w.Code)

	for _, bad := range []string{"", "/api", "ftp://x.example", "https://", "https://x.example/?q=1", "https://x.example/#f", "::"} {
		assert.Error(t, a.SetExternalURL(bad), bad)
	}
	assert.False(t, a.HasExternalURL())
	require.NoError(t, a.SetExternalURL("https://x.example/prefix"))
	assert.True(t, a.HasExternalURL())
}

// The discovery document must work with the bundled client: it POSTs to the rpc URL
// and derives the SSE URL as rpc + "/events".
func TestWMP_HTTPEndpoint_Configuration_DiscoverConfigRoundTrip(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/wmp-configuration", a.HandleWMPConfiguration)
	mux.HandleFunc(WMPRPCPath, a.HandleWMPRPC)
	mux.HandleFunc(WMPEventsPath, a.HandleWMPEvents)
	mux.HandleFunc(WMPClientEventsPath, a.HandleWMPEvents)
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()

	// The httptest certificate is valid for example.com; route that name to
	// the test server.
	client := srv.Client()
	tr := client.Transport.(*http.Transport).Clone()
	tr.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, srv.Listener.Addr().String())
	}
	client.Transport = tr

	_, port, err := net.SplitHostPort(srv.Listener.Addr().String())
	require.NoError(t, err)
	host := "example.com:" + port
	require.NoError(t, a.SetExternalURL("https://"+host))

	cfg, err := wmp.DiscoverConfigWithClient(context.Background(), host, client)
	require.NoError(t, err)
	assert.Equal(t, wmp.SupportedVersions, cfg.SupportedVersions)
	assert.Equal(t, []string{"tls"}, cfg.SecurityModes)
	assert.Equal(t, "https://"+host+WMPRPCPath, cfg.Endpoints["rpc"])
	assert.Equal(t, cfg.Endpoints["rpc"]+"/events", cfg.Endpoints["events"])
	assert.Contains(t, cfg.Capabilities, "flows")

	// Drive the whole bundled client off the discovered endpoint alone.
	hdr := http.Header{"Authorization": {"Bearer " + testToken("user-1", "tenant-a")}}
	ct, err := httpsse.NewClientTransport(cfg.Endpoints["rpc"], httpsse.WithHTTPClient(client), httpsse.WithHeaders(hdr))
	require.NoError(t, err)
	defer ct.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.NoError(t, ct.WriteMessage(ctx, wmpRequest("1", wmp.MethodSessionCreate, wmp.SessionCreateParams{
		WMP:      wmp.Metadata{Version: wmp.Version},
		Security: wmp.SecurityMode{Mode: "tls"},
		Auth:     &wmp.AuthObject{Type: "bearer", Token: testToken("user-1", "tenant-a")},
	})))
	raw, err := ct.ReadMessage(ctx)
	require.NoError(t, err)
	var resp wmp.Response
	require.NoError(t, json.Unmarshal(raw, &resp))
	require.Nil(t, resp.Error)
	var created wmp.SessionCreateResult
	require.NoError(t, json.Unmarshal(resp.Result, &created))
	sid := created.WMP.SessionID

	// SSE at the URL the client derives itself.
	require.NoError(t, ct.ConnectSSE(ctx, sid))

	// A notification carrying only params.wmp.session_id (no header) is
	// accepted: 202, which WriteMessage treats as success.
	require.NoError(t, ct.WriteMessage(ctx, wmpNotification(wmp.MethodFlowAction, wmp.FlowActionParams{
		WMP: wmp.Metadata{Version: wmp.Version, SessionID: sid}, FlowID: "nope", Action: "consent",
	})))
}

// FlowError.Details (e.g. OID4VP's redirect_uri) must reach the WMP client.
func TestWmpSessionTransport_SendJSON_FlowError_Details(t *testing.T) {
	ct := wmp.NewChannelTransport(5, 5)
	handler := &wmpEngineHandler{sessionID: "sess-det"}
	peer := wmp.NewPeer(ct, handler)
	transport := newWMPSessionTransport(peer, ct)
	transport.handler = handler

	require.NoError(t, transport.SendJSON(&FlowErrorMessage{
		Message: Message{FlowID: "flow-1"},
		Error: FlowError{Code: ErrCodeSignError, Message: "boom",
			Details: map[string]interface{}{"redirect_uri": "https://rp.example/cb?error=x"}},
	}))
	select {
	case data := <-ct.Out():
		var notif struct {
			Params wmp.FlowErrorParams `json:"params"`
		}
		require.NoError(t, json.Unmarshal(data, &notif))
		var d map[string]string
		require.NoError(t, json.Unmarshal(notif.Params.Data, &d))
		assert.Equal(t, "https://rp.example/cb?error=x", d["redirect_uri"])
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
}

// Every event written by the transport, including the fallback path
// (credential-notification acks, push), must be a JSON-RPC 2.0 notification.
func TestWmpSessionTransport_SendJSON_AllEventsAreJSONRPC(t *testing.T) {
	ct := wmp.NewChannelTransport(10, 10)
	handler := &wmpEngineHandler{sessionID: "sess-rpc"}
	peer := wmp.NewPeer(ct, handler)
	transport := newWMPSessionTransport(peer, ct)
	transport.handler = handler

	msgs := []interface{}{
		&FlowProgressMessage{Message: Message{FlowID: "f"}, Step: "s"},
		&FlowErrorMessage{Message: Message{FlowID: "f"}, Error: FlowError{Code: ErrCodeSignError, Message: "m"}},
		&NotificationAckMessage{Message: Message{FlowID: "f", Type: TypeNotificationAck}},
		&PushMessage{Message: Message{Type: TypePush}, PushType: "credential"},
	}
	for _, m := range msgs {
		require.NoError(t, transport.SendJSON(m))
	}
	for i := range msgs {
		select {
		case data := <-ct.Out():
			var env struct {
				JSONRPC string          `json:"jsonrpc"`
				Method  string          `json:"method"`
				ID      json.RawMessage `json:"id"`
				Params  json.RawMessage `json:"params"`
			}
			require.NoError(t, json.Unmarshal(data, &env), "event %d: %s", i, data)
			assert.Equal(t, "2.0", env.JSONRPC, "event %d: %s", i, data)
			assert.NotEmpty(t, env.Method, "event %d: %s", i, data)
			assert.Empty(t, env.ID, "notification must have no id")
			if i >= 2 {
				assert.Equal(t, wmp.MethodMessageDeliver, env.Method)
				var p wmp.MessageDeliverParams
				require.NoError(t, json.Unmarshal(env.Params, &p))
				assert.NotEmpty(t, p.Body, "legacy payload must be preserved in body")
			}
		case <-time.After(time.Second):
			t.Fatalf("timeout on event %d", i)
		}
	}
}

// The engine URL setting is a WebSocket URL in shipped configs; discovery must
// derive the matching HTTP(S) base from it.
func TestWMPAdapter_SetExternalURL_WebSocketSchemes(t *testing.T) {
	for in, want := range map[string]string{
		"wss://ws.wallet.example.com":      "https://ws.wallet.example.com",
		"wss://ws.wallet.example.com/":     "https://ws.wallet.example.com",
		"wss://ws.example.com:8443/prefix": "https://ws.example.com:8443/prefix",
		"ws://localhost:8082":              "http://localhost:8082",
		"ws://127.0.0.1:8082":              "http://127.0.0.1:8082",
		"http://[::1]:8080":                "http://[::1]:8080",
		"https://wallet.example.com":       "https://wallet.example.com",
		"http://localhost:8080":            "http://localhost:8080",
	} {
		a, m := testWMPAdapter()
		require.NoError(t, a.SetExternalURL(in), in)
		assert.Equal(t, want, a.externalURL, in)
		cleanupWMP(a, m)
	}
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)
	for _, bad := range []string{"wss://", "wss://x.example/?q=1", "ws://x.example/#f", "wss://%zz"} {
		assert.Error(t, a.SetExternalURL(bad), bad)
	}
	assert.False(t, a.HasExternalURL())
}

// Discovery advertises security mode "tls", so plaintext endpoints are only
// acceptable for loopback development.
func TestWMPAdapter_SetExternalURL_RejectsPlaintextNonLoopback(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)
	for _, bad := range []string{
		"http://wallet.example.com",
		"ws://wallet.example.com",
		"ws://wallet.example.com:8080/prefix",
		"http://10.0.0.5:8080",
		"http://192.168.1.1",
		"http://localhost.example.com",
		"http://127.0.0.1.example.com",
		"http://[2001:db8::1]:8080",
		"http://0.0.0.0:8080",
	} {
		err := a.SetExternalURL(bad)
		if assert.Error(t, err, bad) {
			assert.Contains(t, err.Error(), "https", bad)
		}
	}
	assert.False(t, a.HasExternalURL())
	for _, ok := range []string{"http://localhost:8080", "http://LOCALHOST", "ws://127.0.0.2:8080", "http://[::1]"} {
		assert.NoError(t, a.SetExternalURL(ok), ok)
	}
}
