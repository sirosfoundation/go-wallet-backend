package engine

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
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

// TestWMP_SessionCreate_NonBearerAuthType is a regression test: a client
// declaring an auth type other than "bearer" (e.g. "dpop") must not have its
// token silently treated as a bearer token.
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

// TestWMP_SessionCreate_UnsupportedVersion is a regression test for version
// negotiation: a client requesting a WMP protocol version this server does
// not implement must be rejected rather than silently proceeding.
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

// TestWMP_SessionCreate_MLSNotSupported is a regression test: this server
// only implements the TLS security mode (no MLS layer), so a client
// requesting "mls" must be rejected rather than accepted and silently
// downgraded.
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

// TestWMP_SessionCreate_InvalidParams covers the case where the top-level
// JSON-RPC envelope is valid but "params" does not decode into
// SessionCreateParams (e.g. a JSON string instead of an object).
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

// TestWMP_HandleSessionCreate_MalformedBody covers handleSessionCreate being
// invoked with a body that isn't valid JSON at all (defensive parse-error
// path; HandleRPC's own peek-unmarshal would normally catch this first, but
// handleSessionCreate must handle it safely if reached directly).
func TestWMP_HandleSessionCreate_MalformedBody(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)

	resp, err := a.handleSessionCreate(context.Background(), []byte("not json"))
	require.NoError(t, err)

	var rpcResp wmp.Response
	require.NoError(t, json.Unmarshal(resp, &rpcResp))
	require.NotNil(t, rpcResp.Error)
	assert.Equal(t, wmp.ErrParseError, rpcResp.Error.Code)
}

// TestWMP_SessionCreate_TTLCapped is a regression test: a client requesting
// a TTL longer than maxSessionTTL must have it capped, not honored verbatim
// (an unbounded client-chosen TTL would let a session outlive any reasonable
// idle/lifetime policy).
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

// TestWMP_SessionCreate_TTLWithinLimit covers the companion branch: a TTL
// under the cap is honored as requested.
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

// TestWMP_SessionCreate_CapabilitiesOffered is a regression test for
// capability negotiation: when the client offers a restricted set of
// capabilities, the server must intersect with its own supported set rather
// than always advertising everything it supports.
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

// createWMPSessionWithToken is like createWMPSession but also returns the
// resumption token, needed by the resume tests below.
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

// TestWMP_SessionResume_IdentityMismatch is a regression test for a session
// hijack: possession of a valid resumption token alone must not be enough
// to resume another user's session.
func TestWMP_SessionResume_IdentityMismatch(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)

	sessionID, token := createWMPSessionWithToken(t, a, "user-1", "tenant-a")

	body := wmpRequest("2", "wmp.session.resume", wmp.SessionResumeParams{
		WMP:             wmp.Metadata{Version: wmp.Version},
		SessionID:       sessionID,
		ResumptionToken: token,
	})

	// Attacker: valid bearer token for a *different* user, but has somehow
	// obtained user-1's resumption token and session ID.
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

// TestWMP_CloseSessionIfCurrent_SkipsSupersededSession is a regression test
// for a race in resume: the peer.Serve goroutine started by
// handleSessionCreate/handleSessionResume runs a's cleanup when Serve
// returns, which happens whenever the *old* transport is closed — including
// when a resume closes it deliberately to install a *new* wmpSession for the
// same ID. The old goroutine's cleanup must be a no-op once superseded,
// rather than deleting the new session out from under the client that just
// resumed it.
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

	// Simulate the pre-resume goroutine's Serve() returning and running its
	// deferred cleanup *after* a resume has already installed currentWS.
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

// TestWMP_ReplayActiveFlowProgress_NotifiesActiveFlowsSkipsEmpty is a
// regression test for post-resume state recovery (spec §6.2.1): every flow
// with a non-empty State must get a fresh flow.progress notification so the
// client can rebuild its UI, while flows that haven't reached a state yet
// (empty State) must be skipped rather than sending a bogus empty step.
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

// TestWMP_ReplayActiveFlowProgress_UnknownSession covers the early-return
// guard when the session no longer exists (e.g. closed concurrently with the
// resume) — must not panic on a nil peer/session.
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

// TestWMP_CleanupExpired_RemovesExpiredToken covers the resumption-token
// sweep: a token past its expiresAt must be removed, while a session that is
// otherwise healthy must survive the same pass.
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

// TestWMP_CleanupExpired_ClosesIdleSession covers the idle-timeout sweep: a
// session whose lastActivity is older than wmpSessionIdleTimeout must be
// closed.
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

// TestWMP_CleanupExpired_ClosesTTLExpiredSession covers the TTL sweep: a
// session past its absolute expiresAt deadline must be closed even though it
// is not idle.
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

// TestWMP_CleanupExpired_KeepsHealthySession is the negative-space companion
// to the two tests above: a session that is neither idle nor TTL-expired
// must survive a cleanup pass untouched.
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

// TestWMP_FlowAction_ActionChannelBackpressure_WaitsBriefly is a regression
// test: a momentarily-full actionCh must not be rejected instantly. A brief
// wait gives a legitimate single in-flight action somewhere to land once the
// channel drains, instead of forcing the client to recover only via the
// server-side timeout.
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

	// Drain one slot shortly after FlowAction starts waiting — well within
	// flowActionSendWait, so this must succeed rather than reject instantly.
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

// TestWMP_SessionClose_RPC covers the wmp.session.close RPC method (the
// client-initiated counterpart to a.CloseSession above): the handler must
// tear down the WMP session in response to the client's own close request.
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

// TestWMP_SessionClose_NilParams covers SessionClose being invoked with nil
// params directly (the "reason" defaults to "unknown" rather than the
// handler dereferencing a nil pointer).
func TestWMP_SessionClose_NilParams(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)

	sessionID := createWMPSession(t, a)

	a.mu.RLock()
	ws := a.peers[sessionID]
	a.mu.RUnlock()

	handler := &wmpEngineHandler{adapter: a, sessionID: sessionID, session: ws.session}
	handler.SessionClose(context.Background(), nil)

	_, err := a.Events(sessionID)
	assert.Error(t, err, "session should be closed even when params is nil")
}

// --- FlowCancel ---

// TestWMP_FlowCancel_UnknownFlow covers wmp.flow.cancel for a flow that is
// not (or no longer) in the session's flow map. Per spec §6.2 this must
// report the flow as already terminal rather than a generic flow error.
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

// TestWMP_FlowCancel_Success covers wmp.flow.cancel for an active flow:
// the RPC must succeed and the flow's Handler.Cancel() must actually be
// invoked (not just a status echoed back without doing anything).
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

// TestWMP_CapabilityList_Success covers wmp.capability.list echoing back the
// capabilities/security negotiated at session.create time.
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

// TestWMP_CapabilityList_SessionNotFound covers the handler's own defensive
// session lookup. HandleRPC already gates on session existence before
// dispatching, so this exercises the handler directly for a sessionID that
// was never registered (e.g. a lookup racing a concurrent close).
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

// TestWMP_CredentialNotification_MissingID covers wmp.credential.notification
// being routed through to the engine's dispatchCredentialNotification. It is
// a fire-and-forget notification method (no JSON-RPC error is returned to
// the caller even on rejection); the outcome instead arrives as a
// notification_ack message on the session's event stream. This also
// exercises wmpSessionTransport.SendJSON's default/fallback branch, since
// NotificationAckMessage has no dedicated WMP notification mapping.
func TestWMP_CredentialNotification_MissingID(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)

	sessionID := createWMPSession(t, a)

	body := wmpRequest("2", wmp.MethodCredentialNotification, wmp.CredentialNotificationParams{
		WMP:    wmp.Metadata{Version: wmp.Version, SessionID: sessionID},
		FlowID: "flow-1",
		Event:  "credential_accepted",
		// NotificationID intentionally omitted.
	})

	resp, err := a.HandleRPC(context.Background(), sessionID, "", "", body)
	require.NoError(t, err)

	var rpcResp wmp.Response
	require.NoError(t, json.Unmarshal(resp, &rpcResp))
	assert.Nil(t, rpcResp.Error)

	events, err := a.Events(sessionID)
	require.NoError(t, err)

	select {
	case data := <-events:
		var ack struct {
			Type   string `json:"type"`
			FlowID string `json:"flow_id"`
			Status string `json:"status"`
			Error  string `json:"error"`
		}
		require.NoError(t, json.Unmarshal(data, &ack))
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

// TestWMP_HTTPEndpoint_Events_RejectsConcurrentConnection is a regression
// test: a second GET /wmp/events for the same session while a first is
// still connected must not race it to read from the same events channel
// (which would silently split the notification stream between them).
func TestWMP_HTTPEndpoint_Events_RejectsConcurrentConnection(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)

	sessionID := createWMPSession(t, a)
	token := testToken("user-1", "tenant-a")

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.HandleWMPEvents(w, r)
	}))
	defer ts.Close()

	req1, _ := http.NewRequest(http.MethodGet, ts.URL+"?session_id="+sessionID, nil)
	req1.Header.Set("Authorization", "Bearer "+token)
	resp1, err := http.DefaultClient.Do(req1)
	require.NoError(t, err)
	defer resp1.Body.Close()
	require.Equal(t, http.StatusOK, resp1.StatusCode)

	require.Eventually(t, func() bool {
		buf := a.getOrCreateEventBuffer(sessionID)
		return !buf.tryAcquire(context.Background()) // still held by req1 => can't acquire
	}, time.Second, 5*time.Millisecond)

	req2, _ := http.NewRequest(http.MethodGet, ts.URL+"?session_id="+sessionID, nil)
	req2.Header.Set("Authorization", "Bearer "+token)
	resp2, err := http.DefaultClient.Do(req2)
	require.NoError(t, err)
	defer resp2.Body.Close()
	assert.Equal(t, http.StatusConflict, resp2.StatusCode)
}

// TestWMPEventBuffer_AppendReplayAndAcquire covers the wmpEventBuffer
// mechanics directly: durable IDs across "reconnects" (append calls),
// replay filtering by Last-Event-ID, and single-active-connection
// enforcement — the building blocks behind message replay on resume.
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
	require.True(t, buf.tryAcquire(ctx1), "first connection should acquire")
	assert.False(t, buf.tryAcquire(context.Background()), "second connection should be rejected while first is active")

	cancel1()
	buf.release(ctx1)
	assert.True(t, buf.tryAcquire(context.Background()), "should be acquirable again after release")
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

// TestWMP_FlowAction_MatchResponse_FullPipeline exercises
// wmpSessionTransport.SendJSON's *MatchRequestMessage branch end-to-end: a
// flow handler calls Session.RequestMatch, which the transport turns into a
// nested "match" sub-flow (wmp.flow.start Call), and the client's eventual
// wmp.flow.complete for that child flow must be routed back to the
// original handler via matchCh. This mirrors TestWMP_FlowAction_SignResponse
// but for the match sub-flow, which no other test in this file drives
// end-to-end.
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

// TestWmpSessionTransport_SendJSON_FlowError exercises the *FlowErrorMessage
// branch of wmpSessionTransport.SendJSON directly: it must translate the
// engine error into a wmp.flow.error notification with the mapped WMP error
// code.
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

// TestWmpSessionTransport_ReadMessage covers ReadMessage's delegation to the
// underlying ChannelTransport.
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

// TestWmpResponseBytes_MarshalFailureFallsBackToInternalError covers the
// fallback in wmpResponseBytes when wmp.NewResponse fails to marshal the
// result (e.g. a value json.Marshal cannot encode): the function must
// degrade to an internal-error JSON-RPC response rather than propagating
// the marshal error or panicking.
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

// cancellableFlowHandler blocks in Execute until Cancel() is invoked (or the
// test times out), so tests can verify that wmp.flow.cancel actually
// triggers the flow handler's Cancel() rather than just acknowledging the
// request without doing anything.
type cancellableFlowHandler struct {
	flow      *Flow
	cancelled chan struct{}
	release   chan struct{}
}

func (h *cancellableFlowHandler) Execute(ctx context.Context, msg *FlowStartMessage) error {
	<-h.release
	return nil
}

func (h *cancellableFlowHandler) Cancel() {
	close(h.cancelled)
	close(h.release)
}

// matchFlowHandler requests a DCQL credential match and reports what it
// received, mirroring signFlowHandler above but for the match sub-flow.
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

// ---------------------------------------------------------------------------
// FlowAction: sign_response / match_response / generic action branches
//
// These tests construct a wmpEngineHandler directly (as
// TestWMP_FlowAction_ActionChannelBackpressure_WaitsBriefly does above)
// rather than going through the full session.create + flow.start dance,
// since FlowAction only needs a Session with a registered flow and the
// relevant channel to exercise its routing logic.
// ---------------------------------------------------------------------------

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

// TestWMP_FlowAction_SignResponse_MessageIDFallbackWhenAbsent exercises the
// "extract message_id from raw params" fallback path (params present, but
// with no message_id key so the struct decode leaves MessageID empty).
// Because SignResponseMessage embeds Message anonymously, message_id is
// already promoted into the struct-level JSON decode; this test documents
// that the fallback is exercised but — given that embedding — cannot
// actually recover anything the struct decode missed.
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

// TestWMP_FlowAction_SpecActionTranslation covers the generic/default branch
// with spec-compliant action names (per specToEngineAction) that must be
// translated to the engine's internal action vocabulary before being
// delivered on actionCh, as well as an already-engine-native name that
// passes through untranslated.
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

// ---------------------------------------------------------------------------
// FlowStart: validation, limits, and error branches not covered by
// TestWMP_FlowStart_UnknownProtocol / TestWMP_FlowStart_WithMockHandler above.
// ---------------------------------------------------------------------------

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

	// A JSON string is syntactically valid JSON but cannot be unmarshaled
	// into the FlowStartMessage struct, exercising the "invalid flow
	// params" branch distinctly from a session/protocol-level rejection.
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

// TestWMP_FlowStart_CustomTimeoutAppliedToContext verifies that a
// client-supplied timeout (well under defaultFlowTimeout) is actually
// applied to the flow's execution context, rather than the 5-minute
// server default silently winning.
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

// deadlineCapturingFlowHandler reports the deadline of the context it's
// executed with, so tests can verify FlowStart applied the client-supplied
// timeout rather than the server default.
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

// ---------------------------------------------------------------------------
// FlowComplete: child-flow result routing.
// ---------------------------------------------------------------------------

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

// TestWMP_FlowComplete_UnknownChildFlow_NoOp verifies that a flow.complete
// notification for a flow ID that was never registered via
// registerChildFlow (e.g. a top-level flow's own completion, which is
// handled elsewhere) is silently ignored rather than delivered anywhere.
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

// TestWMP_FlowComplete_MalformedResultStillRoutes verifies that a
// flow.complete whose Result can't be decoded into the expected message
// type doesn't block delivery: the error is swallowed and a (partially
// zero-valued) response is still routed with the correct FlowID/MessageID
// so a blocked RequestSign/RequestMatch call doesn't hang forever on a
// malformed payload.
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

// ---------------------------------------------------------------------------
// HandleWMPRPC / HandleWMPEvents / HandleWMPConfiguration: additional HTTP
// handler coverage (session ownership, oversized bodies, notifications,
// discovery endpoint, and streaming). Appended by a coverage pass targeting
// wmphttp.go; see wmphttp_test-adjacent comments below for a note on one
// branch that appears unreachable through the public API.
// ---------------------------------------------------------------------------

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

// TestWMP_HTTPEndpoint_RPC_SessionOwnershipMismatch is a regression test: a
// caller authenticated as a different user must not be able to target
// another user's session by simply supplying its Wmp-Session-Id — the
// handler must respond as if the session doesn't exist (404), not leak its
// existence via a 403 or similar.
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

// TestWMP_HTTPEndpoint_RPC_OversizedBody verifies that a request body larger
// than maxWMPRPCBodyBytes is bounded (silently truncated by the
// io.LimitReader) rather than read into memory unbounded, and that the
// resulting truncated/invalid JSON is handled gracefully as a JSON-RPC parse
// error rather than a crash or hang.
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

	assert.Equal(t, http.StatusOK, w.Code)
	var rpcResp wmp.Response
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &rpcResp))
	require.NotNil(t, rpcResp.Error, "truncated body should yield a JSON-RPC parse error, not a crash")
	assert.Equal(t, wmp.ErrParseError, rpcResp.Error.Code)
}

// TestWMP_HTTPEndpoint_RPC_Notification_NoContent verifies that a JSON-RPC
// notification (no "id" field) gets a 204 with no body, per JSON-RPC
// semantics — even though the underlying dispatch fails (unknown flow),
// notifications never produce an error response.
//
// Note: HandleWMPRPC has an error-envelope fallback path for when
// a.HandleRPC itself returns a non-nil error (as opposed to a marshaled
// JSON-RPC error response with a nil error, which is the normal way
// protocol-level failures are surfaced). Tracing HandleRPC and the
// go-wmp Peer.HandleRequestSync it delegates to, every internal failure
// (decode errors, dispatch errors) is already converted into a marshaled
// (bytes, nil) response before it reaches HandleWMPRPC; HandleRequestSync
// only returns a non-nil error if json.Marshal of its own response struct
// fails, which isn't reachable through any input this HTTP endpoint accepts.
// That fallback branch is defensive dead code from the caller's perspective;
// no test constructs it.
func TestWMP_HTTPEndpoint_RPC_Notification_NoContent(t *testing.T) {
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

	assert.Equal(t, http.StatusNoContent, w.Code)
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

// TestWMP_HTTPEndpoint_Events_StreamsEvent exercises the full success path
// of HandleWMPEvents over a real HTTP connection: it starts a flow that
// sends a progress notification and verifies that notification actually
// arrives over the SSE stream.
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

	// Start a flow while the SSE connection is live so its progress
	// notification is delivered over the stream we're reading.
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

	req := httptest.NewRequest(http.MethodGet, "/.well-known/wmp-configuration", nil)
	w := httptest.NewRecorder()

	a.HandleWMPConfiguration(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))

	var cfg map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &cfg))
	assert.Equal(t, "1.0", cfg["version"])
	assert.Contains(t, cfg, "security")
	assert.Contains(t, cfg, "capabilities")
	require.Contains(t, cfg, "endpoints")

	endpoints, ok := cfg["endpoints"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "/wmp/rpc", endpoints["rpc"])
	assert.Equal(t, "/wmp/events", endpoints["events"])
}

func TestMustMarshalJSON_Success(t *testing.T) {
	got := mustMarshalJSON(map[string]int{"a": 1})
	assert.JSONEq(t, `{"a":1}`, got)
}

// TestMustMarshalJSON_MarshalFailure verifies the json.Marshal-failure
// fallback: a channel value can never be marshaled to JSON, so
// mustMarshalJSON must return "{}" rather than panicking or propagating the
// error.
func TestMustMarshalJSON_MarshalFailure(t *testing.T) {
	got := mustMarshalJSON(make(chan int))
	assert.Equal(t, "{}", got)
}
