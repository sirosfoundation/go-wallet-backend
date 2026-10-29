package engine

import (
	"context"
	"encoding/json"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sirosfoundation/go-wmp/pkg/wmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A flow without a flow_id would run under an ID the engine makes up, while the
// WMP side stays keyed by "": it is refused at the start.
func TestWMPBridge_FlowStartWithoutFlowID(t *testing.T) {
	e := newWMPEnv(t)
	registerScripted(e.m, ProtocolOID4VP, func(ctx context.Context, _ *Flow, _ *FlowStartMessage) error {
		<-ctx.Done()
		return ctx.Err()
	})
	tok := e.token("alice", "t1", "ir", "j1")
	sid := e.create(tok, "oid4vp")
	msg := startOID4VP(sid, "")
	assert.Equal(t, wmp.ErrInvalidParams, e.post(tok, sid, msg).code())
	delete(msg["params"].(map[string]any), "flow_id")
	assert.Equal(t, wmp.ErrInvalidParams, e.post(tok, sid, msg).code())
}

// A malformed selection after a valid one was handed over cannot be consumed as
// a decline, even though the flow still reports the selection step: it ends the
// flow, which does not run on to sign.
func TestWMPBridge_MalformedSelectionAfterAConsent(t *testing.T) {
	e := newWMPEnv(t)
	ranOn := make(chan bool, 1)
	registerScripted(e.m, ProtocolOID4VP, func(ctx context.Context, f *Flow, _ *FlowStartMessage) error {
		f.mu.Lock()
		f.State = StepCredentialSelection // what BaseHandler.Progress records
		f.mu.Unlock()
		_ = f.Session.SendProgress(f.ID, StepCredentialSelection, nil)
		if _, err := f.Session.WaitForAction(ctx, f.ID, ActionConsent); err != nil {
			return err
		}
		// Consumed, the sign request not registered yet: the window.
		select {
		case <-ctx.Done():
			ranOn <- false
			return ctx.Err()
		case <-time.After(1500 * time.Millisecond):
			ranOn <- true
			return f.Session.SendFlowComplete(f.ID, nil, "")
		}
	})
	tok := e.token("alice", "t1", "ir", "j1")
	sid := e.create(tok, "oid4vp")
	st, _ := e.openStream(tok, sid, "")
	require.Equal(t, 0, e.post(tok, sid, startOID4VP(sid, "f1")).code())
	st.nextMethod(t, wmp.MethodFlowProgress)

	good := map[string]any{"consent": true, "selections": []any{map[string]any{"query_id": "q", "selection_handle": testHandle}}}
	assert.Equal(t, 0, e.post(tok, sid, req(wmp.MethodFlowAction, map[string]any{"wmp": meta(sid), "flow_id": "f1", "action": "select_credentials", "params": good})).code())
	bad := map[string]any{"consent": true, "selections": []any{map[string]any{"query_id": "q", "selection_handle": testHandle, "credential_id": "c"}}}
	assert.Equal(t, wmp.ErrInvalidParams, e.post(tok, sid, req(wmp.MethodFlowAction, map[string]any{"wmp": meta(sid), "flow_id": "f1", "action": "select_credentials", "params": bad})).code())
	ev := st.nextMethod(t, wmp.MethodFlowError)
	assert.EqualValues(t, wmp.ErrInvalidParams, params(ev)["code"])
	assert.False(t, <-ranOn, "the flow was stopped, not left to sign and complete")
}

// A second valid selection is not queued for a flow that already has one.
func TestWMPBridge_SecondSelectionIsRefused(t *testing.T) {
	e := newWMPEnv(t)
	registerScripted(e.m, ProtocolOID4VP, func(ctx context.Context, f *Flow, _ *FlowStartMessage) error {
		_ = f.Session.SendProgress(f.ID, StepCredentialSelection, nil)
		<-ctx.Done()
		return ctx.Err()
	})
	tok := e.token("alice", "t1", "ir", "j1")
	sid := e.create(tok, "oid4vp")
	require.Equal(t, 0, e.post(tok, sid, startOID4VP(sid, "f1")).code())
	waitFlows(t, e, sid, 1)
	do := func() int {
		return e.post(tok, sid, req(wmp.MethodFlowAction, map[string]any{"wmp": meta(sid), "flow_id": "f1", "action": "select_credentials",
			"params": map[string]any{"consent": true, "selections": []any{map[string]any{"query_id": "q", "selection_handle": testHandle}}}})).code()
	}
	assert.Equal(t, 0, do())
	assert.Equal(t, wmp.ErrFlowError, do())
}

func TestNormalizeSignResult(t *testing.T) {
	for name, tc := range map[string]struct{ in, want string }{
		"string": {`{"vp_token":"a"}`, `{"vp_token":"a"}`},
		"array":  {`{"vp_token":["a","b"]}`, `{"vp_token":"a\nb"}`},
		"object": {`{"vp_token":{"pid":["a"]}}`, `{"vp_token":"{\"pid\":[\"a\"]}"}`},
		"none":   {`{"response_jwe":"x"}`, `{"response_jwe":"x"}`},
	} {
		assert.JSONEq(t, tc.want, string(normalizeSignResult(json.RawMessage(tc.in))), name)
	}
	assert.Equal(t, "x", string(normalizeSignResult(json.RawMessage("x"))), "not JSON: unchanged")
}

// A conforming sign result (a DCQL object, an array) reaches the engine instead
// of failing the presentation.
func TestWMPBridge_SignResultVPTokenForms(t *testing.T) {
	for name, tc := range map[string]struct {
		token any
		want  string
	}{
		"object": {map[string]any{"pid": []string{"presentation"}}, `{"pid":["presentation"]}`},
		"array":  {[]string{"p1", "p2"}, "p1\np2"},
	} {
		t.Run(name, func(t *testing.T) {
			e := newWMPEnv(t)
			got := make(chan *SignResponseMessage, 1)
			registerScripted(e.m, ProtocolOID4VP, func(ctx context.Context, f *Flow, _ *FlowStartMessage) error {
				resp, err := f.Session.RequestSign(ctx, f.ID, SignActionSignPresentation, SignRequestParams{Audience: "https://v.example", Nonce: "n-1"})
				if err != nil {
					return err
				}
				got <- resp
				return f.Session.SendFlowComplete(f.ID, nil, "")
			})
			tok := e.token("alice", "t1", "ir", "j1")
			sid := e.create(tok, "oid4vp")
			st, _ := e.openStream(tok, sid, "")
			require.Equal(t, 0, e.post(tok, sid, startOID4VP(sid, "f1")).code())
			start := st.nextMethod(t, wmp.MethodFlowStart)
			sub := params(start)["flow_id"].(string)
			e.post(tok, sid, map[string]any{"id": start.Data["id"], "result": map[string]any{"wmp": meta(sid), "flow_id": sub, "flow_type": "sign"}})
			e.post(tok, sid, notification(wmp.MethodFlowComplete, map[string]any{"wmp": meta(sid), "flow_id": sub, "result": map[string]any{"vp_token": tc.token}}))
			select {
			case resp := <-got:
				assert.Empty(t, resp.Error)
				assert.Equal(t, tc.want, resp.VPToken)
			case <-time.After(5 * time.Second):
				t.Fatal("the engine's RequestSign did not return")
			}
		})
	}
}

const preAuthSecret = "SECRET-PRE-AUTH-CODE"

// The pre-authorized code is the engine's: not in the parsed offer, not in the
// credential offer of the authorization step, and not in the replay log.
func TestWMPBridge_PreAuthorizedCodeNeverRelayed(t *testing.T) {
	grants := map[string]any{"urn:ietf:params:oauth:grant-type:pre-authorized_code": map[string]any{"pre-authorized_code": preAuthSecret}, "authorization_code": map[string]any{}}
	e := newWMPEnv(t)
	registerScripted(e.m, ProtocolOID4VCI, func(_ context.Context, f *Flow, _ *FlowStartMessage) error {
		_ = f.Session.SendProgress(f.ID, StepAuthorizationReq, map[string]any{"authorization_url": "https://as", "credential_offer": map[string]any{"grants": grants}})
		_ = f.Session.SendProgress(f.ID, StepOfferParsed, map[string]any{"credential_issuer": "https://i", "grants": grants})
		return f.Session.SendFlowComplete(f.ID, nil, "")
	})
	tok := e.token("alice", "t1", "ir", "j1")
	sid := e.create(tok, "oid4vci")
	live, _ := e.openStream(tok, sid, "")
	require.Equal(t, 0, e.post(tok, sid, startVCI(sid, "f1")).code())
	first := live.nextMethod(t, wmp.MethodFlowProgress)
	second := live.nextMethod(t, wmp.MethodFlowProgress)
	live.nextMethod(t, wmp.MethodFlowComplete)
	for _, ev := range []sseEvent{first, second} {
		assert.NotContains(t, ev.Raw, preAuthSecret)
	}
	assert.Contains(t, first.Raw, "https://as", "the rest of the step is relayed")
	assert.Contains(t, second.Raw, "https://i", "the rest of the offer is relayed")
	replayed, status := e.openStream(tok, sid, first.ID)
	require.Equal(t, 200, status)
	assert.NotContains(t, replayed.next(t).Raw, preAuthSecret)
}

func TestWMPBridge_AcceptOfferNeedsAffirmativeConsent(t *testing.T) {
	e := newWMPEnv(t)
	actions := make(chan *FlowActionMessage, 2)
	registerScripted(e.m, ProtocolOID4VCI, func(ctx context.Context, f *Flow, _ *FlowStartMessage) error {
		_ = f.Session.SendProgress(f.ID, StepAwaitingSelection, map[string]any{"available_credentials": []any{map[string]any{"id": "a"}, map[string]any{"id": "b"}}})
		act, err := f.Session.WaitForAction(ctx, f.ID, ActionSelectCredential)
		if err == nil {
			actions <- act
		}
		return err
	})
	tok := e.token("alice", "t1", "ir", "j1")
	sid := e.create(tok, "oid4vci")
	st, _ := e.openStream(tok, sid, "")
	require.Equal(t, 0, e.post(tok, sid, startVCI(sid, "f1")).code())
	st.nextMethod(t, wmp.MethodFlowProgress)
	for name, p := range map[string]map[string]any{"missing": {"selected_indices": []int{0}}, "null": {"selected_indices": []int{0}, "consent": nil}} {
		assert.Equal(t, wmp.ErrInvalidParams, e.post(tok, sid, flowAction(sid, "f1", "accept_offer", p)).code(), name)
	}
	assert.Empty(t, actions)
}

// The shutdown deadline bounds ending the sessions, whatever a slow store does.
func TestWMPAdapter_CloseContextIsBoundedBySlowStore(t *testing.T) {
	e := newWMPEnv(t)
	registerScripted(e.m, ProtocolOID4VP, func(ctx context.Context, _ *Flow, _ *FlowStartMessage) error {
		<-ctx.Done()
		return ctx.Err()
	})
	tok := e.token("alice", "t1", "ir", "j1")
	e.create(tok, "oid4vp")
	release := make(chan struct{})
	var entered atomic.Bool
	e.m.sessionStore = slowDeleteStore{SessionStore: e.m.sessionStore, release: release, entered: &entered}
	t.Cleanup(func() { close(release) })

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	done := make(chan struct{})
	go func() { e.a.CloseContext(ctx); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("CloseContext outlived its deadline")
	}
	assert.True(t, entered.Load(), "the store was reached")
}

type slowDeleteStore struct {
	SessionStore
	release chan struct{}
	entered *atomic.Bool
}

func (s slowDeleteStore) Delete(ctx context.Context, tenantID, userID, sessionID string) error {
	s.entered.Store(true)
	<-s.release
	return s.SessionStore.Delete(ctx, tenantID, userID, sessionID)
}

// Cancelling by action ends the flow with a terminal message, so a resume does not
// re-send the flow's last progress.
func TestWMPBridge_ActionCancelClearsRecoveryState(t *testing.T) {
	e := newWMPEnv(t)
	registerScripted(e.m, ProtocolOID4VCI, func(ctx context.Context, f *Flow, _ *FlowStartMessage) error {
		_ = f.Session.SendProgress(f.ID, StepAwaitingSelection, map[string]any{"available_credentials": []any{map[string]any{"id": "a"}, map[string]any{"id": "b"}}})
		<-ctx.Done()
		return ctx.Err()
	})
	tok := e.token("alice", "t1", "ir", "j1")
	r := e.post(tok, "", req(wmp.MethodSessionCreate, map[string]any{
		"wmp": map[string]any{"version": wmp.Version}, "security": map[string]any{"mode": "tls"},
		"capabilities_offered": map[string]any{"oid4vci": map[string]any{}}}))
	require.Equal(t, 0, r.code())
	sid, _ := r.result()["wmp"].(map[string]any)["session_id"].(string)
	resumption, _ := r.result()["resumption_token"].(string)
	require.NotEmpty(t, resumption)
	st, _ := e.openStream(tok, sid, "")
	require.Equal(t, 0, e.post(tok, sid, startVCI(sid, "f1")).code())
	st.nextMethod(t, wmp.MethodFlowProgress)

	assert.Equal(t, 0, e.post(tok, sid, flowAction(sid, "f1", "accept_offer", map[string]any{"selected_indices": []int{0}, "consent": false})).code())
	ev := st.nextMethod(t, wmp.MethodFlowError)
	assert.Equal(t, "cancelled", params(ev)["data"].(map[string]any)["reason"])

	r = e.post(tok, sid, req(wmp.MethodSessionResume, map[string]any{"wmp": meta(sid), "session_id": sid, "resumption_token": resumption}))
	require.Equal(t, 0, r.code(), "%v", r.Body)
	st2, _ := e.openStream(tok, sid, "")
	select {
	case ev := <-st2.events:
		assert.NotContains(t, ev.Raw, "awaiting_offer_acceptance", "no prompt for a flow that is gone")
	case <-time.After(500 * time.Millisecond):
	}
}
