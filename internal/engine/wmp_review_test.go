package engine

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sirosfoundation/go-tokenauth/claims"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
	"github.com/sirosfoundation/go-wmp/pkg/wmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// revokeOnSecondCheck reports a user as not revoked on the first IsUserRevoked
// call (the token validation) and revoked on every later call (the
// registerSession re-check), simulating a revocation landing in the window
// between the two.
type revokeOnSecondCheck struct{ calls atomic.Int32 }

func (r *revokeOnSecondCheck) IsBlacklisted(context.Context, string) bool { return false }
func (r *revokeOnSecondCheck) IsUserRevoked(context.Context, string) bool {
	return r.calls.Add(1) > 1
}

func wmpCreateBody(token string, params func(*wmp.SessionCreateParams)) []byte {
	p := wmp.SessionCreateParams{
		WMP:      wmp.Metadata{Version: wmp.Version},
		Security: wmp.SecurityMode{Mode: "tls"},
		Auth:     &wmp.AuthObject{Type: "bearer", Token: token},
	}
	if params != nil {
		params(&p)
	}
	return wmpRequest("1", wmp.MethodSessionCreate, p)
}

func rpcErrCode(t *testing.T, resp []byte) int {
	t.Helper()
	var r wmp.Response
	require.NoError(t, json.Unmarshal(resp, &r))
	require.NotNil(t, r.Error, "expected JSON-RPC error, got %s", resp)
	return r.Error.Code
}

func resumeBody(sessionID, token, lastReceived string) []byte {
	return wmpRequest("2", wmp.MethodSessionResume, wmp.SessionResumeParams{
		WMP: wmp.Metadata{Version: wmp.Version}, SessionID: sessionID,
		ResumptionToken: token, LastReceivedID: lastReceived,
	})
}

// --- registerSession result is honoured ---

func TestHTTPHandshake_RevokedBetweenValidateAndRegister_Returns401(t *testing.T) {
	m := testManager()
	defer m.Close()
	m.SetTokenBlacklist(&revokeOnSecondCheck{})

	req := httptest.NewRequest(http.MethodPost, "/api/v2/wallet/rpc", strings.NewReader(`{"type":"handshake"}`))
	req.Header.Set("Authorization", "Bearer "+testToken("user-r", "t"))
	w := httptest.NewRecorder()
	m.HandleRPC(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	m.sessionsMu.RLock()
	defer m.sessionsMu.RUnlock()
	assert.Empty(t, m.sessions, "rejected session must not be stored")
}

func TestWMP_SessionCreate_RevokedBetweenValidateAndRegister_NotAuthorized(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)
	m.SetTokenBlacklist(&revokeOnSecondCheck{})

	resp, err := a.HandleRPC(context.Background(), "", "", "", wmpCreateBody(testToken("user-r", "t"), nil))
	require.NoError(t, err)
	assert.Equal(t, wmp.ErrNotAuthorized, rpcErrCode(t, resp))

	a.mu.RLock()
	defer a.mu.RUnlock()
	assert.Empty(t, a.peers, "rejected session must not be stored")
	assert.Empty(t, a.eventBufs)
}

// --- ownership for identity-less (anonymous) sessions ---

func TestOwnsSession_AnonymousBoundToTokenID(t *testing.T) {
	anon := &wmpSession{session: &Session{UserID: "", TenantID: "t"}, ownerTokenID: "jti-1"}
	assert.True(t, ownsSession(anon, wmpCaller{TenantID: "t", TokenID: "jti-1"}))
	assert.False(t, ownsSession(anon, wmpCaller{TenantID: "t", TokenID: "jti-2"}), "other anonymous token")
	assert.False(t, ownsSession(anon, wmpCaller{TenantID: "t"}), "anonymous token without jti")
	assert.False(t, ownsSession(anon, wmpCaller{UserID: "u", TenantID: "t", TokenID: "jti-1"}))

	unbound := &wmpSession{session: &Session{UserID: "", TenantID: "t"}}
	assert.False(t, ownsSession(unbound, wmpCaller{TenantID: "t"}), "session with no owner binding is never addressable anonymously")

	user := &wmpSession{session: &Session{UserID: "u", TenantID: "t"}}
	assert.True(t, ownsSession(user, wmpCaller{UserID: "u", TenantID: "t"}))
	assert.False(t, ownsSession(user, wmpCaller{UserID: "v", TenantID: "t"}))
	assert.False(t, ownsSession(user, wmpCaller{UserID: "u", TenantID: "x"}))
}

func TestValidateTokenID_ReturnsJTI(t *testing.T) {
	m := testManager()
	defer m.Close()
	_, _, _, jti, err := m.validateTokenID(testToken("u", "t"))
	require.NoError(t, err)
	assert.Empty(t, jti, "test token carries no jti")
}

// --- envelope and security mode ---

func TestWMP_SessionCreate_RejectsNon20Envelope(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)

	for _, body := range []string{
		`{"jsonrpc":"1.0","id":"1","method":"wmp.session.create","params":{}}`,
		`{"id":"1","method":"wmp.session.create","params":{}}`,
		`{"id":"1","method":"wmp.session.resume","params":{}}`,
	} {
		resp, err := a.HandleRPC(context.Background(), "", "u", "t", []byte(body))
		require.NoError(t, err)
		assert.Equal(t, wmp.ErrParseError, rpcErrCode(t, resp), body)
	}
}

func TestWMP_SessionCreate_SecurityModeTLSOnly(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)
	tok := testToken("user-1", "t")

	for _, mode := range []string{"none", "mls", "TLS", "plaintext"} {
		resp, err := a.HandleRPC(context.Background(), "", "", "", wmpCreateBody(tok, func(p *wmp.SessionCreateParams) { p.Security.Mode = mode }))
		require.NoError(t, err)
		assert.Equal(t, wmp.ErrInvalidParams, rpcErrCode(t, resp), mode)
	}

	// Omitted mode defaults to tls and is echoed as such.
	resp, err := a.HandleRPC(context.Background(), "", "", "", wmpCreateBody(tok, func(p *wmp.SessionCreateParams) { p.Security.Mode = "" }))
	require.NoError(t, err)
	var r wmp.Response
	require.NoError(t, json.Unmarshal(resp, &r))
	require.Nil(t, r.Error)
	var res wmp.SessionCreateResult
	require.NoError(t, json.Unmarshal(r.Result, &res))
	assert.Equal(t, "tls", res.Security.Mode)
}

// --- resume ---

func createSessionFull(t *testing.T, a *WMPAdapter, user, tenant string, params func(*wmp.SessionCreateParams)) (string, string, wmp.SessionCreateResult) {
	t.Helper()
	resp, err := a.HandleRPC(context.Background(), "", "", "", wmpCreateBody(testToken(user, tenant), params))
	require.NoError(t, err)
	var r wmp.Response
	require.NoError(t, json.Unmarshal(resp, &r))
	require.Nil(t, r.Error, "%v", r.Error)
	var res wmp.SessionCreateResult
	require.NoError(t, json.Unmarshal(r.Result, &res))
	return res.WMP.SessionID, res.ResumptionToken, res
}

func doResume(t *testing.T, a *WMPAdapter, user, tenant string, body []byte) (wmp.SessionResumeResult, *wmp.RPCError) {
	t.Helper()
	resp, err := a.HandleRPC(context.Background(), "", user, tenant, body)
	require.NoError(t, err)
	var r wmp.Response
	require.NoError(t, json.Unmarshal(resp, &r))
	if r.Error != nil {
		return wmp.SessionResumeResult{}, r.Error
	}
	var res wmp.SessionResumeResult
	require.NoError(t, json.Unmarshal(r.Result, &res))
	return res, nil
}

func TestWMP_Resume_RejectedCallerDoesNotConsumeToken(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)
	sid, token, _ := createSessionFull(t, a, "owner", "t", nil)

	_, rpcErr := doResume(t, a, "attacker", "t", resumeBody(sid, token, ""))
	require.NotNil(t, rpcErr)
	assert.Equal(t, wmp.ErrNotAuthorized, rpcErr.Code)

	res, rpcErr := doResume(t, a, "owner", "t", resumeBody(sid, token, ""))
	require.Nil(t, rpcErr, "owner must still be able to use the token after a rejected attempt")
	assert.True(t, res.Resumed)

	// One-time use: replaying the consumed token fails.
	_, rpcErr = doResume(t, a, "owner", "t", resumeBody(sid, token, ""))
	require.NotNil(t, rpcErr)
	assert.Equal(t, wmp.ErrSessionNotFound, rpcErr.Code)
}

func TestWMP_Resume_PreservesNegotiatedStateAndTTL(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)
	m.RegisterFlowHandler("test_proto", func(flow *Flow, _ *config.Config, _ *zap.Logger, _ *TrustService, _ *RegistryClient, _ storage.VerifierStore, _ *TrustCache) (FlowHandler, error) {
		return stubFlowHandler{}, nil
	})
	sid, token, created := createSessionFull(t, a, "u", "t", func(p *wmp.SessionCreateParams) {
		p.TTL = 3600
		p.CapabilitiesOffered = wmp.Capabilities{"flows": json.RawMessage(`{}`)}
	})
	require.Contains(t, created.Capabilities, "flows")
	require.NotContains(t, created.Capabilities, "sign")

	a.mu.RLock()
	oldExp := a.peers[sid].expiresAt
	a.mu.RUnlock()
	require.False(t, oldExp.IsZero())

	res, rpcErr := doResume(t, a, "u", "t", resumeBody(sid, token, ""))
	require.Nil(t, rpcErr)
	assert.Equal(t, created.Capabilities, res.Capabilities)
	assert.Equal(t, "tls", res.Security.Mode)

	a.mu.RLock()
	ws := a.peers[sid]
	a.mu.RUnlock()
	assert.Equal(t, oldExp, ws.expiresAt, "TTL deadline must survive resume")
	assert.Equal(t, created.Capabilities, ws.capabilities)

	// A TTL-expired session is still closed by cleanup after resume.
	a.mu.Lock()
	ws.expiresAt = time.Now().Add(-time.Second)
	a.mu.Unlock()
	a.cleanupExpired()
	a.mu.RLock()
	_, still := a.peers[sid]
	a.mu.RUnlock()
	assert.False(t, still)
}

func TestWMP_Resume_TransfersChildFlows(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)
	sid, token, _ := createSessionFull(t, a, "u", "t", nil)

	a.mu.RLock()
	old := a.peers[sid]
	a.mu.RUnlock()
	old.handler.registerChildFlow("child-1", "parent", "msg-1", "sign")

	_, rpcErr := doResume(t, a, "u", "t", resumeBody(sid, token, ""))
	require.Nil(t, rpcErr)

	a.mu.RLock()
	cur := a.peers[sid]
	a.mu.RUnlock()
	require.NotSame(t, old, cur)

	// The child's flow.complete arriving after resume reaches the parent.
	cur.handler.FlowComplete(context.Background(), &wmp.FlowCompleteParams{FlowID: "child-1", Result: json.RawMessage(`{"jwt":"x"}`)})
	select {
	case got := <-cur.session.signCh:
		assert.Equal(t, "parent", got.FlowID)
		assert.Equal(t, "msg-1", got.MessageID)
	case <-time.After(time.Second):
		t.Fatal("child flow result not routed after resume")
	}
}

// TestWMP_Resume_DoesNotTearDownSession runs many resumes to catch the old
// peer's Serve cleanup unregistering the engine session.
func TestWMP_Resume_DoesNotTearDownSession(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)
	sid, token, _ := createSessionFull(t, a, "u", "t", nil)

	for i := 0; i < 30; i++ {
		res, rpcErr := doResume(t, a, "u", "t", resumeBody(sid, token, ""))
		require.Nil(t, rpcErr, "resume %d", i)
		token = res.ResumptionToken
	}
	time.Sleep(100 * time.Millisecond) // let superseded Serve goroutines run their cleanup

	a.mu.RLock()
	_, peerOK := a.peers[sid]
	buf := a.eventBufs[sid]
	a.mu.RUnlock()
	assert.True(t, peerOK)
	assert.NotNil(t, buf, "replay buffer must survive resume")
	m.sessionsMu.RLock()
	_, engineOK := m.sessions[sid]
	m.sessionsMu.RUnlock()
	assert.True(t, engineOK, "engine session must stay registered")
}

func TestWMP_Resume_MissedMessagesFromCursor(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)
	sid, token, _ := createSessionFull(t, a, "u", "t", nil)

	a.mu.RLock()
	sess := a.peers[sid].session
	buf := a.eventBufs[sid]
	a.mu.RUnlock()
	for i := 0; i < 3; i++ {
		require.NoError(t, sess.SendProgress("f", "step", nil))
	}
	require.Eventually(t, func() bool { return buf.pendingCount() == 3 }, time.Second, 5*time.Millisecond)

	// Client has everything: nothing missed.
	res, rpcErr := doResume(t, a, "u", "t", resumeBody(sid, token, "3"))
	require.Nil(t, rpcErr)
	assert.Equal(t, 0, res.MissedMessages)

	// Cursor in the middle.
	res, rpcErr = doResume(t, a, "u", "t", resumeBody(sid, res.ResumptionToken, "1"))
	require.Nil(t, rpcErr)
	assert.Equal(t, 2, res.MissedMessages)

	// No cursor: nothing was ever written to an SSE connection, so all 3.
	res, rpcErr = doResume(t, a, "u", "t", resumeBody(sid, res.ResumptionToken, ""))
	require.Nil(t, rpcErr)
	assert.Equal(t, 3, res.MissedMessages)

	// Cursor older than anything retained counts everything retained.
	res, rpcErr = doResume(t, a, "u", "t", resumeBody(sid, res.ResumptionToken, "0"))
	require.Nil(t, rpcErr)
	assert.Equal(t, 3, res.MissedMessages)
}

// TestWMP_Resume_KeepsNotificationsEmittedWhileDisconnected covers events
// queued in the old transport before resume: they must reach the replay
// buffer, in order, rather than being discarded with the old transport.
func TestWMP_Resume_KeepsNotificationsEmittedWhileDisconnected(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)
	sid, token, _ := createSessionFull(t, a, "u", "t", nil)

	a.mu.RLock()
	sess := a.peers[sid].session
	buf := a.eventBufs[sid]
	a.mu.RUnlock()

	for i := 0; i < 5; i++ { // no SSE consumer connected at any point
		require.NoError(t, sess.SendProgress("f", "before", nil))
	}
	_, rpcErr := doResume(t, a, "u", "t", resumeBody(sid, token, ""))
	require.Nil(t, rpcErr)
	require.NoError(t, sess.SendProgress("f", "after", nil))

	require.Eventually(t, func() bool { return buf.pendingCount() == 6 }, time.Second, 5*time.Millisecond)
	evs, _ := buf.after(0)
	require.Len(t, evs, 6)
	for i, ev := range evs {
		assert.Equal(t, int64(i+1), ev.ID)
		step := "before"
		if i == 5 {
			step = "after"
		}
		assert.Contains(t, string(ev.Data), step)
	}
}

// TestWMP_Resume_ConcurrentSendsNotLost sends notifications while resuming;
// run with -race. Every send that returned nil must end up buffered.
func TestWMP_Resume_ConcurrentSendsNotLost(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)
	sid, token, _ := createSessionFull(t, a, "u", "t", nil)

	a.mu.RLock()
	sess := a.peers[sid].session
	buf := a.eventBufs[sid]
	a.mu.RUnlock()

	var sent atomic.Int32
	var wg sync.WaitGroup
	stop := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			if sess.SendProgress("f", "s", nil) == nil {
				sent.Add(1)
			}
			time.Sleep(time.Millisecond)
			if sent.Load() >= 150 {
				return
			}
		}
	}()
	for i := 0; i < 10; i++ {
		res, rpcErr := doResume(t, a, "u", "t", resumeBody(sid, token, ""))
		require.Nil(t, rpcErr)
		token = res.ResumptionToken
		time.Sleep(5 * time.Millisecond)
	}
	close(stop)
	wg.Wait()

	require.Eventually(t, func() bool { return buf.pendingCount() == int(sent.Load()) }, 2*time.Second, 5*time.Millisecond,
		"sent=%d buffered=%d", sent.Load(), buf.pendingCount())
}

// --- flow start ---

func startFlowBody(sid, flowType, flowID string) []byte {
	return wmpRequest("3", wmp.MethodFlowStart, wmp.FlowStartParams{
		WMP: wmp.Metadata{Version: wmp.Version, SessionID: sid}, FlowType: flowType, FlowID: flowID,
	})
}

type blockingHandler struct {
	release chan struct{}
	cancels atomic.Int32
}

func (h *blockingHandler) Execute(ctx context.Context, _ *FlowStartMessage) error {
	select {
	case <-h.release:
	case <-ctx.Done():
	}
	return nil
}
func (h *blockingHandler) Cancel() { h.cancels.Add(1) }

func TestWMP_FlowStart_EnforcesTAC(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)
	for _, p := range []Protocol{ProtocolOID4VCI, ProtocolOID4VP} {
		m.RegisterFlowHandler(p, func(flow *Flow, _ *config.Config, _ *zap.Logger, _ *TrustService, _ *RegistryClient, _ storage.VerifierStore, _ *TrustCache) (FlowHandler, error) {
			return stubFlowHandler{}, nil
		})
	}
	sid := createWMPSession(t, a)
	a.mu.RLock()
	sess := a.peers[sid].session
	a.mu.RUnlock()

	sess.TAC = claims.TAC("r") // may present, may not issue
	resp, err := a.HandleRPC(context.Background(), sid, "", "", startFlowBody(sid, string(ProtocolOID4VCI), "f-i"))
	require.NoError(t, err)
	assert.Equal(t, wmp.ErrNotAuthorized, rpcErrCode(t, resp))
	sess.flowsMu.RLock()
	assert.Empty(t, sess.flows, "rejected flow must not be registered")
	sess.flowsMu.RUnlock()

	resp, err = a.HandleRPC(context.Background(), sid, "", "", startFlowBody(sid, string(ProtocolOID4VP), "f-r"))
	require.NoError(t, err)
	var ok wmp.Response
	require.NoError(t, json.Unmarshal(resp, &ok))
	assert.Nil(t, ok.Error, "token with r may start OID4VP")

	sess.TAC = claims.TAC("i") // may issue, may not present
	resp, err = a.HandleRPC(context.Background(), sid, "", "", startFlowBody(sid, string(ProtocolOID4VP), "f-r2"))
	require.NoError(t, err)
	assert.Equal(t, wmp.ErrNotAuthorized, rpcErrCode(t, resp))
}

func TestWMP_FlowStart_DuplicateFlowIDRejected(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)
	h := &blockingHandler{release: make(chan struct{})}
	m.RegisterFlowHandler("blocker", func(*Flow, *config.Config, *zap.Logger, *TrustService, *RegistryClient, storage.VerifierStore, *TrustCache) (FlowHandler, error) {
		return h, nil
	})
	sid := createWMPSession(t, a)

	resp, err := a.HandleRPC(context.Background(), sid, "", "", startFlowBody(sid, "blocker", "dup"))
	require.NoError(t, err)
	var first wmp.Response
	require.NoError(t, json.Unmarshal(resp, &first))
	require.Nil(t, first.Error)

	for i := 0; i < 5; i++ { // repeating the ID must not bypass the flow limit
		resp, err = a.HandleRPC(context.Background(), sid, "", "", startFlowBody(sid, "blocker", "dup"))
		require.NoError(t, err)
		assert.Equal(t, wmp.ErrInvalidParams, rpcErrCode(t, resp))
	}

	a.mu.RLock()
	sess := a.peers[sid].session
	a.mu.RUnlock()
	sess.flowsMu.RLock()
	require.Len(t, sess.flows, 1)
	orig := sess.flows["dup"]
	sess.flowsMu.RUnlock()

	close(h.release)
	require.Eventually(t, func() bool {
		sess.flowsMu.RLock()
		defer sess.flowsMu.RUnlock()
		return sess.flows["dup"] != orig
	}, time.Second, 5*time.Millisecond)
}

// --- child flow completion backpressure ---

func TestWMP_FlowComplete_KeepsMappingWhenChannelFull(t *testing.T) {
	sess := &Session{signCh: make(chan *SignResponseMessage, 1), matchCh: make(chan *MatchResponseMessage, 1), logger: zap.NewNop()}
	h := &wmpEngineHandler{adapter: &WMPAdapter{logger: zap.NewNop()}, session: sess}
	sess.signCh <- &SignResponseMessage{} // full
	h.registerChildFlow("c1", "p", "m", "sign")

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // give up immediately instead of waiting flowActionSendWait
	h.FlowComplete(ctx, &wmp.FlowCompleteParams{FlowID: "c1", Result: json.RawMessage(`{}`)})
	_, still := h.popChildFlow("c1")
	assert.True(t, still, "mapping must be kept so the result can be retried")

	// With room in the channel the retry delivers and clears the mapping.
	<-sess.signCh
	h.registerChildFlow("c1", "p", "m", "sign")
	h.FlowComplete(context.Background(), &wmp.FlowCompleteParams{FlowID: "c1", Result: json.RawMessage(`{}`)})
	select {
	case got := <-sess.signCh:
		assert.Equal(t, "p", got.FlowID)
	default:
		t.Fatal("result not delivered")
	}
	_, still = h.popChildFlow("c1")
	assert.False(t, still)

	// match path, waiting briefly for a slot to free up.
	sess.matchCh <- &MatchResponseMessage{}
	h.registerChildFlow("c2", "p", "m2", "match")
	go func() { time.Sleep(50 * time.Millisecond); <-sess.matchCh }()
	h.FlowComplete(context.Background(), &wmp.FlowCompleteParams{FlowID: "c2"})
	got := <-sess.matchCh
	assert.Equal(t, "m2", got.MessageID)
}

// --- session teardown ---

func TestWMP_CloseSession_EndsEngineSession(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)
	sid := createWMPSession(t, a)

	a.mu.RLock()
	sess := a.peers[sid].session
	a.mu.RUnlock()
	h := &blockingHandler{release: make(chan struct{})}
	sess.flowsMu.Lock()
	sess.flows["f"] = &Flow{ID: "f", Handler: h}
	sess.flowsMu.Unlock()

	a.CloseSession(sid)

	select {
	case <-sess.closeCh:
	case <-time.After(time.Second):
		t.Fatal("closeCh not closed on WMP session close")
	}
	assert.Equal(t, int32(1), h.cancels.Load(), "active flows must be cancelled")

	// Idempotent; and safe for sessions without a closeCh.
	sess.endSession()
	(&Session{}).endSession()
	a.CloseSession(sid)
}

func TestWMP_SSE_TerminatesWhenSessionCloses(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)
	sid, _, _ := createSessionFull(t, a, "u", "t", nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v2/wallet/events?session_id="+sid, nil)
	req.Header.Set("Authorization", "Bearer "+testToken("u", "t"))
	w := httptest.NewRecorder()
	done := make(chan struct{})
	go func() { a.HandleWMPEvents(w, req); close(done) }()

	time.Sleep(50 * time.Millisecond)
	a.CloseSession(sid)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("SSE handler still blocked after the session was closed")
	}
}

func TestWMP_SSE_DeliversEventsBufferedBeforeConnect(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)
	sid, _, _ := createSessionFull(t, a, "u", "t", nil)
	a.mu.RLock()
	sess := a.peers[sid].session
	buf := a.eventBufs[sid]
	a.mu.RUnlock()
	require.NoError(t, sess.SendProgress("f", "early", nil))
	require.Eventually(t, func() bool { return buf.pendingCount() == 1 }, time.Second, 5*time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest(http.MethodGet, "/api/v2/wallet/events?session_id="+sid, nil).WithContext(ctx)
	req.Header.Set("Authorization", "Bearer "+testToken("u", "t"))
	w := &syncRecorder{ResponseRecorder: httptest.NewRecorder()}
	done := make(chan struct{})
	go func() { a.HandleWMPEvents(w, req); close(done) }()

	require.Eventually(t, func() bool { return strings.Contains(w.String(), "early") }, 2*time.Second, 10*time.Millisecond)

	// A live event after connect is streamed too, with the next ID.
	require.NoError(t, sess.SendProgress("f", "late", nil))
	require.Eventually(t, func() bool { return strings.Contains(w.String(), "late") }, 2*time.Second, 10*time.Millisecond)
	assert.Contains(t, w.String(), "id: 2\n")
	cancel()
	<-done

	// Reconnect without Last-Event-ID resumes after what was delivered.
	assert.Equal(t, int64(2), buf.delivered())
}

type syncRecorder struct {
	*httptest.ResponseRecorder
	mu sync.Mutex
}

func (s *syncRecorder) Write(b []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ResponseRecorder.Write(b)
}
func (s *syncRecorder) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.Body.String()
}

// --- sseTransport reconnect race ---

func TestSSETransport_StaleCleanupDoesNotClearNewRegistration(t *testing.T) {
	tr := newSSETransport(10)
	ctx1, cancel1 := context.WithCancel(context.Background())
	req1 := httptest.NewRequest(http.MethodGet, "/events", nil).WithContext(ctx1)
	done1 := make(chan struct{})
	go func() { tr.serveSSE(httptest.NewRecorder(), req1); close(done1) }()

	require.Eventually(t, func() bool {
		tr.sseMu.Lock()
		defer tr.sseMu.Unlock()
		return tr.sseCtx == ctx1
	}, time.Second, time.Millisecond)

	// Hold sseMu so the first handler's deferred cleanup blocks; meanwhile
	// the reconnect registers (as serveSSE does once the old ctx is done).
	tr.sseMu.Lock()
	cancel1()
	time.Sleep(20 * time.Millisecond)
	ctx2 := context.Background()
	rec2 := httptest.NewRecorder()
	tr.sseW, tr.sseFl, tr.sseCtx = rec2, rec2, ctx2
	tr.sseMu.Unlock()

	<-done1
	tr.sseMu.Lock()
	defer tr.sseMu.Unlock()
	assert.Equal(t, ctx2, tr.sseCtx, "stale cleanup must not clear the new connection")
	assert.NotNil(t, tr.sseW)
}

// --- misc buffer / endSession helpers ---

func TestWMPEventBuffer_ZeroValueAndClose(t *testing.T) {
	var b wmpEventBuffer
	evs, wake := b.after(0)
	assert.Empty(t, evs)
	id := b.append([]byte("x"))
	select {
	case <-wake:
	default:
		t.Fatal("append must wake waiters")
	}
	assert.Equal(t, int64(1), id)
	assert.Equal(t, 1, b.missedSince("garbage"))
	b.markDelivered(1)
	assert.Equal(t, 0, b.missedSince(""))
	b.close()
	b.close() // idempotent
	select {
	case <-b.doneCh():
	default:
		t.Fatal("done must be closed")
	}
}

func TestWMP_Events_SubscriptionClosesWithSession(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)
	sid := createWMPSession(t, a)
	ch, err := a.Events(sid)
	require.NoError(t, err)
	a.CloseSession(sid)
	require.Eventually(t, func() bool {
		select {
		case _, ok := <-ch:
			return !ok
		default:
			return false
		}
	}, time.Second, 5*time.Millisecond)
}

// --- second review round ---

func TestCapSeconds(t *testing.T) {
	const maxInt = int(^uint(0) >> 1)
	assert.Equal(t, time.Duration(0), capSeconds(0, time.Hour))
	assert.Equal(t, time.Duration(0), capSeconds(-5, time.Hour))
	assert.Equal(t, 90*time.Second, capSeconds(90, time.Hour))
	assert.Equal(t, time.Hour, capSeconds(3600, time.Hour))
	assert.Equal(t, time.Hour, capSeconds(3601, time.Hour))
	assert.Equal(t, 24*time.Hour, capSeconds(maxInt, 24*time.Hour), "MaxInt seconds must cap, not overflow to a negative duration")
	assert.Equal(t, 24*time.Hour, capSeconds(maxInt/2, 24*time.Hour))
}

func TestWMP_SessionCreate_HugeTTLIsCapped(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)
	const maxInt = int(^uint(0) >> 1)
	sid, _, _ := createSessionFull(t, a, "u", "t", func(p *wmp.SessionCreateParams) { p.TTL = maxInt })

	a.mu.RLock()
	exp := a.peers[sid].expiresAt
	a.mu.RUnlock()
	require.False(t, exp.IsZero())
	assert.True(t, exp.After(time.Now()), "expiry must be in the future, not wrapped negative")
	assert.WithinDuration(t, time.Now().Add(maxSessionTTL), exp, time.Minute)
}

func TestWMP_FlowStart_HugeTimeoutIsCapped(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)
	const maxInt = int(^uint(0) >> 1)
	h := &blockingHandler{release: make(chan struct{})}
	defer close(h.release)
	m.RegisterFlowHandler("blocker", func(*Flow, *config.Config, *zap.Logger, *TrustService, *RegistryClient, storage.VerifierStore, *TrustCache) (FlowHandler, error) {
		return h, nil
	})
	sid := createWMPSession(t, a)
	body := wmpRequest("3", wmp.MethodFlowStart, wmp.FlowStartParams{
		WMP: wmp.Metadata{Version: wmp.Version, SessionID: sid}, FlowType: "blocker", FlowID: "f", Timeout: maxInt,
	})
	resp, err := a.HandleRPC(context.Background(), sid, "", "", body)
	require.NoError(t, err)
	var r wmp.Response
	require.NoError(t, json.Unmarshal(resp, &r))
	require.Nil(t, r.Error)
	// The flow must still be running (a wrapped-negative timeout would have
	// expired its context immediately, but blockingHandler only exits on
	// release or ctx.Done, so check the flow is still registered).
	time.Sleep(50 * time.Millisecond)
	a.mu.RLock()
	sess := a.peers[sid].session
	a.mu.RUnlock()
	sess.flowsMu.RLock()
	_, running := sess.flows["f"]
	sess.flowsMu.RUnlock()
	assert.True(t, running)
}

func TestWMP_Resume_LosingConcurrentResumeKeepsChildFlows(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)
	sid, token, _ := createSessionFull(t, a, "u", "t", nil)
	a.mu.RLock()
	old := a.peers[sid]
	a.mu.RUnlock()
	old.handler.registerChildFlow("child-1", "parent", "msg-1", "sign")

	var wg sync.WaitGroup
	var okCount atomic.Int32
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := a.HandleRPC(context.Background(), "", "u", "t", resumeBody(sid, token, ""))
			require.NoError(t, err)
			var r wmp.Response
			require.NoError(t, json.Unmarshal(resp, &r))
			if r.Error == nil {
				okCount.Add(1)
			}
		}()
	}
	wg.Wait()
	assert.Equal(t, int32(1), okCount.Load(), "exactly one concurrent resume may win the one-time token")

	a.mu.RLock()
	cur := a.peers[sid]
	a.mu.RUnlock()
	info, ok := cur.handler.popChildFlow("child-1")
	require.True(t, ok, "losing resumes must not discard outstanding child flows")
	assert.Equal(t, "parent", info.parentFlowID)
	// The retired handler shares the same table, so late frames still route.
	old.handler.registerChildFlow("child-2", "p2", "m2", "match")
	_, ok = cur.handler.popChildFlow("child-2")
	assert.True(t, ok)
}

func TestWMP_Resume_RejectedWhenUserRevokedAtCommit(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)
	sid, token, _ := createSessionFull(t, a, "victim", "t", nil)

	// Revocation lands after the token was validated by the HTTP layer
	// (HandleRPC takes the already-validated caller) but before the resume
	// commits: the revoked mark is set while the session-closing scan of
	// RevokeUser has not (yet) reached this session.
	m.revokedUsersMu.Lock()
	m.revokedUsers["victim"] = struct{}{}
	m.revokedUsersMu.Unlock()

	resp, err := a.HandleRPC(context.Background(), "", "victim", "t", resumeBody(sid, token, ""))
	require.NoError(t, err)
	assert.Equal(t, wmp.ErrNotAuthorized, rpcErrCode(t, resp))

	require.Eventually(t, func() bool {
		a.mu.RLock()
		defer a.mu.RUnlock()
		_, still := a.peers[sid]
		return !still
	}, time.Second, 5*time.Millisecond, "revoked user's resumed session must be torn down")
	m.sessionsMu.RLock()
	_, engineStill := m.sessions[sid]
	m.sessionsMu.RUnlock()
	assert.False(t, engineStill)
}

func TestManager_UserRevoked(t *testing.T) {
	m := testManager()
	defer m.Close()
	assert.False(t, m.userRevoked(""))
	assert.False(t, m.userRevoked("u"))
	m.revokedUsersMu.Lock()
	m.revokedUsers["u"] = struct{}{}
	m.revokedUsersMu.Unlock()
	assert.True(t, m.userRevoked("u"))
	m.SetTokenBlacklist(&revokeOnSecondCheck{})
	_ = m.userRevoked("v")
	assert.True(t, m.userRevoked("v"), "blacklist consulted")
}

// A concurrent wmp.flow.cancel can only see fully-constructed flows: the
// flow becomes visible in session.flows with its Handler already set. Run
// with -race.
func TestWMP_FlowStart_HandlerSetBeforeFlowVisible(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)
	h := &blockingHandler{release: make(chan struct{})}
	defer close(h.release)
	m.RegisterFlowHandler("blocker", func(*Flow, *config.Config, *zap.Logger, *TrustService, *RegistryClient, storage.VerifierStore, *TrustCache) (FlowHandler, error) {
		time.Sleep(20 * time.Millisecond) // widen the old factory window
		return h, nil
	})
	sid := createWMPSession(t, a)
	a.mu.RLock()
	sess := a.peers[sid].session
	a.mu.RUnlock()

	stop := make(chan struct{})
	var sawNilHandler atomic.Bool
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			sess.flowsMu.RLock()
			if f, ok := sess.flows["racy"]; ok && f.Handler == nil {
				sawNilHandler.Store(true)
			}
			sess.flowsMu.RUnlock()
		}
	}()

	resp, err := a.HandleRPC(context.Background(), sid, "", "", startFlowBody(sid, "blocker", "racy"))
	require.NoError(t, err)
	var r wmp.Response
	require.NoError(t, json.Unmarshal(resp, &r))
	require.Nil(t, r.Error)
	close(stop)
	wg.Wait()
	assert.False(t, sawNilHandler.Load(), "flow visible before its handler was set")

	// Cancel now reaches the handler.
	cancelBody := wmpRequest("4", wmp.MethodFlowCancel, wmp.FlowCancelParams{
		WMP: wmp.Metadata{Version: wmp.Version, SessionID: sid}, FlowID: "racy",
	})
	_, err = a.HandleRPC(context.Background(), sid, "", "", cancelBody)
	require.NoError(t, err)
	assert.Equal(t, int32(1), h.cancels.Load())
}

func TestWMP_FlowStart_FactoryErrorAndBadParamsLeaveNoFlow(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)
	m.RegisterFlowHandler("failing", func(*Flow, *config.Config, *zap.Logger, *TrustService, *RegistryClient, storage.VerifierStore, *TrustCache) (FlowHandler, error) {
		return nil, assert.AnError
	})
	sid := createWMPSession(t, a)
	resp, err := a.HandleRPC(context.Background(), sid, "", "", startFlowBody(sid, "failing", "f1"))
	require.NoError(t, err)
	assert.Equal(t, wmp.ErrInternalError, rpcErrCode(t, resp))

	bad := wmpRequest("5", wmp.MethodFlowStart, map[string]interface{}{
		"wmp": wmp.Metadata{Version: wmp.Version, SessionID: sid}, "flow_type": "failing", "flow_id": "f2", "params": "not-an-object",
	})
	resp, err = a.HandleRPC(context.Background(), sid, "", "", bad)
	require.NoError(t, err)
	assert.Equal(t, wmp.ErrInvalidParams, rpcErrCode(t, resp))

	a.mu.RLock()
	sess := a.peers[sid].session
	a.mu.RUnlock()
	sess.flowsMu.RLock()
	defer sess.flowsMu.RUnlock()
	assert.Empty(t, sess.flows)
}

// Resume replay reads Flow.State under flow.mu while a handler is
// concurrently reporting progress. Run with -race.
func TestWMP_ReplayActiveFlowProgress_RacesWithProgress(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)
	sid := createWMPSession(t, a)
	a.mu.RLock()
	ws := a.peers[sid]
	a.mu.RUnlock()

	flow := &Flow{ID: "f", Session: ws.session, State: "started"}
	ws.session.flowsMu.Lock()
	ws.session.flows["f"] = flow
	ws.session.flowsMu.Unlock()
	bh := &BaseHandler{Flow: flow}

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			_ = bh.Progress(FlowStep("step"), nil)
		}
	}()
	for i := 0; i < 200; i++ {
		a.replayActiveFlowProgress(sid, ws.peer)
	}
	close(stop)
	wg.Wait()
}

// --- adapter lifecycle ---

func TestWMPAdapter_CloseStopsCleanupLoop(t *testing.T) {
	m := testManager()
	defer m.Close()
	a := NewWMPAdapter(m, zap.NewNop())
	select {
	case <-a.loopDone:
		t.Fatal("loop should be running before Close")
	default:
	}
	a.Close()
	select {
	case <-a.loopDone:
	case <-time.After(time.Second):
		t.Fatal("cleanup goroutine still running after Close")
	}
	a.Close() // idempotent
}

func TestWMP_Resume_AfterFullRevocationIsSessionNotFound(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)
	sid, token, _ := createSessionFull(t, a, "victim2", "t", nil)
	m.RevokeUser("victim2")
	require.Eventually(t, func() bool {
		a.mu.RLock()
		defer a.mu.RUnlock()
		_, still := a.peers[sid]
		return !still
	}, time.Second, 5*time.Millisecond)
	resp, err := a.HandleRPC(context.Background(), "", "victim2", "t", resumeBody(sid, token, ""))
	require.NoError(t, err)
	assert.Equal(t, wmp.ErrSessionNotFound, rpcErrCode(t, resp))
}

// A sign/match send blocks in Peer.Call until the client acknowledges the
// sub-flow start, while holding Session.Send's read lock. A resume must abort
// that call instead of waiting out the call timeout for the write lock.
func TestWMP_Resume_DoesNotWaitForUnacknowledgedCall(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)
	sid, token, _ := createSessionFull(t, a, "u", "t", nil)

	a.mu.RLock()
	sess := a.peers[sid].session
	a.mu.RUnlock()

	sendErr := make(chan error, 1)
	go func() {
		sendErr <- sess.Send(&SignRequestMessage{
			Message: Message{Type: TypeSignRequest, FlowID: "f", MessageID: "m"},
		})
	}()
	// Let the Call start and block (nobody acknowledges it).
	time.Sleep(100 * time.Millisecond)
	select {
	case err := <-sendErr:
		t.Fatalf("send returned before resume: %v", err)
	default:
	}

	start := time.Now()
	res, rpcErr := doResume(t, a, "u", "t", resumeBody(sid, token, ""))
	require.Nil(t, rpcErr)
	assert.True(t, res.Resumed)
	assert.Less(t, time.Since(start), 5*time.Second, "resume must not wait for the unacknowledged call")

	select {
	case err := <-sendErr:
		assert.Error(t, err, "the aborted call reports failure")
	case <-time.After(5 * time.Second):
		t.Fatal("blocked send was not released by resume")
	}
}
