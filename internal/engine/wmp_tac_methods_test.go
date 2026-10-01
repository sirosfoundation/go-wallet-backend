package engine

import (
	gojosejwt "github.com/go-jose/go-jose/v4/jwt"
	"net/http"
	"net/http/httptest"

	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-tokenauth/claims"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
	"github.com/sirosfoundation/go-wmp/pkg/wmp"
)

// tacMethodFixture starts an OID4VCI (issuance) flow in a session created with
// a broad TAC, so the per-method tests can drive it with a reduced ("r") token
// that lacks the issuance permission.
type tacMethodFixture struct {
	a       *WMPAdapter
	m       *Manager
	sid     string
	sess    *Session
	handler *blockingHandler
}

var (
	tacFull    = wmpCaller{TAC: claims.TAC("ir")}
	tacReduced = wmpCaller{TAC: claims.TAC("r")}
)

func newTACMethodFixture(t *testing.T) *tacMethodFixture {
	t.Helper()
	a, m := testWMPAdapter()
	t.Cleanup(func() { cleanupWMP(a, m) })
	h := &blockingHandler{release: make(chan struct{})}
	t.Cleanup(func() { close(h.release) })
	m.RegisterFlowHandler(ProtocolOID4VCI, func(*Flow, *config.Config, *zap.Logger, *TrustService, *RegistryClient, storage.VerifierStore, *TrustCache) (FlowHandler, error) {
		return h, nil
	})
	sid := createWMPSession(t, a)
	a.mu.RLock()
	sess := a.peers[sid].session
	a.mu.RUnlock()
	sess.TAC = claims.TAC("ir")

	resp, err := a.HandleRPCAs(context.Background(), sid, tacFull, startFlowBody(sid, string(ProtocolOID4VCI), "f-i"))
	require.NoError(t, err)
	var r wmp.Response
	require.NoError(t, json.Unmarshal(resp, &r))
	require.Nil(t, r.Error)
	return &tacMethodFixture{a: a, m: m, sid: sid, sess: sess, handler: h}
}

func (f *tacMethodFixture) meta() wmp.Metadata {
	return wmp.Metadata{Version: wmp.Version, SessionID: f.sid}
}

func TestWMP_FlowAction_EnforcesFlowProtocolTAC(t *testing.T) {
	f := newTACMethodFixture(t)
	body := wmpRequest("4", wmp.MethodFlowAction, wmp.FlowActionParams{
		WMP: f.meta(), FlowID: "f-i", Action: "consent", Params: json.RawMessage(`{"approved":true}`),
	})

	resp, err := f.a.HandleRPCAs(context.Background(), f.sid, tacReduced, body)
	require.NoError(t, err)
	assert.Equal(t, wmp.ErrNotAuthorized, rpcErrCode(t, resp))
	assert.Empty(t, f.sess.actionCh, "denied action must not reach the flow")

	resp, err = f.a.HandleRPCAs(context.Background(), f.sid, tacFull, body)
	require.NoError(t, err)
	var ok wmp.Response
	require.NoError(t, json.Unmarshal(resp, &ok))
	assert.Nil(t, ok.Error)
	assert.Len(t, f.sess.actionCh, 1)
}

func TestWMP_FlowAction_SignMatchEnforceFlowProtocolTAC(t *testing.T) {
	f := newTACMethodFixture(t)
	for _, action := range []string{"sign_response", "match_response"} {
		body := wmpRequest("4", wmp.MethodFlowAction, wmp.FlowActionParams{
			WMP: f.meta(), FlowID: "f-i", Action: action, Params: json.RawMessage(`{}`),
		})
		resp, err := f.a.HandleRPCAs(context.Background(), f.sid, tacReduced, body)
		require.NoError(t, err)
		assert.Equal(t, wmp.ErrNotAuthorized, rpcErrCode(t, resp), action)
	}
	assert.Empty(t, f.sess.signCh)
	assert.Empty(t, f.sess.matchCh)
}

func TestWMP_FlowCancel_EnforcesFlowProtocolTAC(t *testing.T) {
	f := newTACMethodFixture(t)
	body := wmpRequest("5", wmp.MethodFlowCancel, wmp.FlowCancelParams{WMP: f.meta(), FlowID: "f-i"})

	resp, err := f.a.HandleRPCAs(context.Background(), f.sid, tacReduced, body)
	require.NoError(t, err)
	assert.Equal(t, wmp.ErrNotAuthorized, rpcErrCode(t, resp))
	assert.EqualValues(t, 0, f.handler.cancels.Load(), "denied cancel must not cancel the flow")

	resp, err = f.a.HandleRPCAs(context.Background(), f.sid, tacFull, body)
	require.NoError(t, err)
	var ok wmp.Response
	require.NoError(t, json.Unmarshal(resp, &ok))
	assert.Nil(t, ok.Error)
	assert.EqualValues(t, 1, f.handler.cancels.Load())
}

func TestWMP_FlowComplete_ChildEnforcesParentProtocolTAC(t *testing.T) {
	f := newTACMethodFixture(t)
	f.a.mu.RLock()
	h := f.a.peers[f.sid].handler
	f.a.mu.RUnlock()
	h.registerChildFlow("child-1", "f-i", "msg-1", "sign")

	body := wmpNotification(wmp.MethodFlowComplete, wmp.FlowCompleteParams{
		WMP: f.meta(), FlowID: "child-1", Result: json.RawMessage(`{"jwt":"x"}`),
	})

	_, err := f.a.HandleRPCAs(context.Background(), f.sid, tacReduced, body)
	require.NoError(t, err)
	assert.Empty(t, f.sess.signCh, "denied child result must not reach the parent flow")
	_, stillMapped := h.peekChildFlow("child-1")
	assert.True(t, stillMapped, "denied caller must not consume the child mapping")

	_, err = f.a.HandleRPCAs(context.Background(), f.sid, tacFull, body)
	require.NoError(t, err)
	select {
	case got := <-f.sess.signCh:
		assert.Equal(t, "f-i", got.FlowID)
		assert.Equal(t, "msg-1", got.MessageID)
	case <-time.After(2 * time.Second):
		t.Fatal("authorised child result was not delivered")
	}
}

func TestWMP_CredentialNotification_EnforcesIssuanceTAC(t *testing.T) {
	f := newTACMethodFixture(t)
	events, err := f.a.Events(f.sid)
	require.NoError(t, err)

	body := wmpNotification(wmp.MethodCredentialNotification, wmp.CredentialNotificationParams{
		WMP: f.meta(), FlowID: "f-i", NotificationID: "n-1", Event: "credential_accepted",
	})
	_, err = f.a.HandleRPCAs(context.Background(), f.sid, tacReduced, body)
	require.NoError(t, err)

	deadline := time.After(2 * time.Second)
	for {
		select {
		case ev := <-events:
			if strings.Contains(string(ev), "insufficient permissions") {
				return
			}
		case <-deadline:
			t.Fatal("expected a rejected ack citing insufficient permissions")
		}
	}
}

// The SSE stream of a session created with a broad token must not be
// readable with a same-user, same-tenant token that holds fewer capabilities.
func TestWMP_SSE_RequiresTokenCoveringSessionCapabilities(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)
	v, key, issuer := setupEngineTokenValidatorTest(t)
	m.SetTokenValidator(v)
	tokenWith := func(tac string) string {
		return signEngineToken(t, key, issuer, claims.AccessTokenClaims{
			Claims:   gojosejwt.Claims{Audience: gojosejwt.Audience{"wallet-registry"}, Subject: "u"},
			TenantID: "t",
			TAC:      claims.TAC(tac),
			ACR:      "urn:siros:acr:passkey",
		})
	}

	sid, _, _ := createSessionFull(t, a, "u", "t", func(p *wmp.SessionCreateParams) {
		p.Auth.Token = tokenWith("ir")
	})
	a.mu.RLock()
	sessTAC := a.peers[sid].session.TAC
	a.mu.RUnlock()
	require.Equal(t, claims.TAC("ir"), sessTAC)

	open := func(tok string) *httptest.ResponseRecorder {
		ctx, cancel := context.WithCancel(context.Background())
		req := httptest.NewRequest(http.MethodGet, "/api/v2/wallet/events?session_id="+sid, nil).WithContext(ctx)
		req.Header.Set("Authorization", "Bearer "+tok)
		w := httptest.NewRecorder()
		done := make(chan struct{})
		go func() { a.HandleWMPEvents(w, req); close(done) }()
		// A denied request returns at once; an allowed one streams until
		// its context is cancelled.
		select {
		case <-done:
		case <-time.After(200 * time.Millisecond):
		}
		cancel()
		<-done
		return w
	}

	assert.Equal(t, http.StatusForbidden, open(tokenWith("r")).Code, "reduced TAC must be denied")
	assert.Equal(t, http.StatusForbidden, open(tokenWith("")).Code, "no TAC must be denied")
	assert.Equal(t, http.StatusOK, open(tokenWith("ir")).Code, "the creating capabilities are allowed")
	assert.Equal(t, http.StatusOK, open(tokenWith("irw")).Code, "a superset is allowed")
}

// A modern token whose TAC is empty has NO permissions; it must not be
// treated like a legacy token (which has no TAC concept) and skip the check.
var tacModernEmpty = wmpCaller{EnforceTAC: true}

func TestWMP_ModernEmptyTAC_RefusedOnEveryStateChangingMethod(t *testing.T) {
	f := newTACMethodFixture(t)
	f.a.mu.RLock()
	h := f.a.peers[f.sid].handler
	f.a.mu.RUnlock()
	h.registerChildFlow("child-1", "f-i", "msg-1", "sign")
	ctx := context.Background()

	for _, action := range []string{"consent", "sign_response", "match_response"} {
		body := wmpRequest("4", wmp.MethodFlowAction, wmp.FlowActionParams{
			WMP: f.meta(), FlowID: "f-i", Action: action, Params: json.RawMessage(`{}`),
		})
		resp, err := f.a.HandleRPCAs(ctx, f.sid, tacModernEmpty, body)
		require.NoError(t, err)
		assert.Equal(t, wmp.ErrNotAuthorized, rpcErrCode(t, resp), action)
	}
	assert.Empty(t, f.sess.actionCh)
	assert.Empty(t, f.sess.signCh)
	assert.Empty(t, f.sess.matchCh)

	resp, err := f.a.HandleRPCAs(ctx, f.sid, tacModernEmpty,
		wmpRequest("5", wmp.MethodFlowCancel, wmp.FlowCancelParams{WMP: f.meta(), FlowID: "f-i"}))
	require.NoError(t, err)
	assert.Equal(t, wmp.ErrNotAuthorized, rpcErrCode(t, resp))
	assert.EqualValues(t, 0, f.handler.cancels.Load())

	resp, err = f.a.HandleRPCAs(ctx, f.sid, tacModernEmpty, startFlowBody(f.sid, string(ProtocolOID4VCI), "f-new"))
	require.NoError(t, err)
	assert.Equal(t, wmp.ErrNotAuthorized, rpcErrCode(t, resp), "flow.start")

	_, err = f.a.HandleRPCAs(ctx, f.sid, tacModernEmpty, wmpNotification(wmp.MethodFlowComplete,
		wmp.FlowCompleteParams{WMP: f.meta(), FlowID: "child-1", Result: json.RawMessage(`{"jwt":"x"}`)}))
	require.NoError(t, err)
	assert.Empty(t, f.sess.signCh)
	_, stillMapped := h.peekChildFlow("child-1")
	assert.True(t, stillMapped)

	events, err := f.a.Events(f.sid)
	require.NoError(t, err)
	_, err = f.a.HandleRPCAs(ctx, f.sid, tacModernEmpty, wmpNotification(wmp.MethodCredentialNotification,
		wmp.CredentialNotificationParams{WMP: f.meta(), FlowID: "f-i", NotificationID: "n-1", Event: "credential_accepted"}))
	require.NoError(t, err)
	deadline := time.After(2 * time.Second)
	for done := false; !done; {
		select {
		case ev := <-events:
			done = strings.Contains(string(ev), "insufficient permissions")
		case <-deadline:
			t.Fatal("expected a rejected ack citing insufficient permissions")
		}
	}
}

// Legacy tokens (no TAC concept) are unaffected: only the session's own TAC
// is consulted, so a legacy caller on a legacy session still works.
func TestWMP_LegacyCaller_SkipsTACCheck(t *testing.T) {
	f := newTACMethodFixture(t)
	f.sess.TAC = "" // legacy session
	f.sess.TACEnforced = false
	resp, err := f.a.HandleRPCAs(context.Background(), f.sid, wmpCaller{},
		wmpRequest("5", wmp.MethodFlowCancel, wmp.FlowCancelParams{WMP: f.meta(), FlowID: "f-i"}))
	require.NoError(t, err)
	var r wmp.Response
	require.NoError(t, json.Unmarshal(resp, &r))
	assert.Nil(t, r.Error)
	assert.EqualValues(t, 1, f.handler.cancels.Load())
}

// A session created by a modern token with an empty TAC is authoritative:
// it can start nothing, even when the later request is also modern-empty.
func TestWMP_ModernEmptyTAC_SessionCannotStartFlows(t *testing.T) {
	f := newTACMethodFixture(t)
	f.sess.TAC = ""
	f.sess.TACEnforced = true
	resp, err := f.a.HandleRPCAs(context.Background(), f.sid, wmpCaller{},
		startFlowBody(f.sid, string(ProtocolOID4VCI), "f-x"))
	require.NoError(t, err)
	assert.Equal(t, wmp.ErrNotAuthorized, rpcErrCode(t, resp))
}

// End to end over HTTP: a real modern token with no tac claim is refused on
// a broad session, on RPC and on SSE.
func TestWMP_HTTP_ModernEmptyTAC_Refused(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)
	v, key, issuer := setupEngineTokenValidatorTest(t)
	m.SetTokenValidator(v)
	tokenWith := func(tac string) string {
		return signEngineToken(t, key, issuer, claims.AccessTokenClaims{
			Claims:   gojosejwt.Claims{Audience: gojosejwt.Audience{"wallet-registry"}, Subject: "u"},
			TenantID: "t", TAC: claims.TAC(tac), ACR: "urn:siros:acr:passkey",
		})
	}
	sid, _, _ := createSessionFull(t, a, "u", "t", func(p *wmp.SessionCreateParams) { p.Auth.Token = tokenWith("ir") })
	h := &blockingHandler{release: make(chan struct{})}
	defer close(h.release)
	m.RegisterFlowHandler(ProtocolOID4VCI, func(*Flow, *config.Config, *zap.Logger, *TrustService, *RegistryClient, storage.VerifierStore, *TrustCache) (FlowHandler, error) {
		return h, nil
	})

	post := func(tok string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, WMPRPCPath, strings.NewReader(string(startFlowBody(sid, string(ProtocolOID4VCI), "f-h"))))
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set("Wmp-Session-Id", sid)
		w := httptest.NewRecorder()
		a.HandleWMPRPC(w, req)
		return w
	}
	w := post(tokenWith(""))
	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, wmp.ErrNotAuthorized, rpcErrCode(t, w.Body.Bytes()))
	w = post(tokenWith("ir"))
	var r wmp.Response
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &r))
	assert.Nil(t, r.Error)

	req := httptest.NewRequest(http.MethodGet, WMPEventsPath+"?session_id="+sid, nil)
	req.Header.Set("Authorization", "Bearer "+tokenWith(""))
	sw := httptest.NewRecorder()
	a.HandleWMPEvents(sw, req)
	assert.Equal(t, http.StatusForbidden, sw.Code)
}

// A session created by a legacy token has effective permissions defined by
// what the legacy RPC path allows. A modern token with an empty TAC (no
// permissions) must not stream it; a modern token covering those
// permissions, and a legacy token, may.
func TestWMP_SSE_LegacySessionRequiresEffectivePermissionsFromModernToken(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)
	sid, _, _ := createSessionFull(t, a, "u", "t", nil) // legacy HMAC token
	a.mu.RLock()
	sess := a.peers[sid].session
	a.mu.RUnlock()
	require.False(t, sess.TACEnforced)
	require.Empty(t, sess.TAC)

	require.Equal(t, claims.TAC("ir"), legacySessionEffectiveTAC())

	assert.False(t, a.tokenCoversSession(sid, "", true), "modern empty TAC must not cover a legacy session")
	assert.False(t, a.tokenCoversSession(sid, "r", true), "partial modern TAC must not cover")
	assert.True(t, a.tokenCoversSession(sid, "ir", true))
	assert.True(t, a.tokenCoversSession(sid, "irw", true))
	assert.True(t, a.tokenCoversSession(sid, "", false), "legacy token streams its own legacy session")

	v, key, issuer := setupEngineTokenValidatorTest(t)
	m.SetTokenValidator(v)
	modern := signEngineToken(t, key, issuer, claims.AccessTokenClaims{
		Claims:   gojosejwt.Claims{Audience: gojosejwt.Audience{"wallet-registry"}, Subject: "u"},
		TenantID: "t", ACR: "urn:siros:acr:passkey",
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req := httptest.NewRequest(http.MethodGet, "/api/v2/wallet/events?session_id="+sid, nil).WithContext(ctx)
	req.Header.Set("Authorization", "Bearer "+modern)
	w := httptest.NewRecorder()
	a.HandleWMPEvents(w, req)
	assert.Equal(t, http.StatusForbidden, w.Code)
}
