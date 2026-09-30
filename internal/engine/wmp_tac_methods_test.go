package engine

import (
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
