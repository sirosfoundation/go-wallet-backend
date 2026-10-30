package engine

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sirosfoundation/go-wmp/pkg/wmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

const testHandle = "abcdefghijklmnopqrstuv"

// The WMP wire of the consent only translates: select_credentials (closed set,
// OpenID4x 3.2.3.1) to the transport-neutral answer.
func TestConsentFromSelectCredentials(t *testing.T) {
	a, err := consentFromSelectCredentials(json.RawMessage(
		`{"consent":true,"selections":[{"query_id":"q1","selection_handle":"` + testHandle + `"},{"query_id":"q2","selection_handle":"` + testHandle + `"}]}`))
	require.NoError(t, err)
	assert.False(t, a.Declined)
	assert.Equal(t, testHandle, a.Handle)
	assert.Equal(t, []ConsentSelection{{CredentialQueryID: "q1"}, {CredentialQueryID: "q2"}}, a.Selections,
		"the engine learns the query ids, not a credential or a claim")

	a, err = consentFromSelectCredentials(json.RawMessage(`{"consent":false}`))
	require.NoError(t, err)
	assert.True(t, a.Declined)

	for name, raw := range map[string]string{
		"credential data":     `{"consent":true,"selections":[{"query_id":"q","selection_handle":"` + testHandle + `","credential_id":"c"}]}`,
		"claims":              `{"consent":true,"selections":[{"query_id":"q","selection_handle":"` + testHandle + `"}],"disclosed_claims":["a"]}`,
		"consent only":        `{"consent":true}`,
		"differing handles":   `{"consent":true,"selections":[{"query_id":"a","selection_handle":"` + testHandle + `"},{"query_id":"b","selection_handle":"zzzzzzzzzzzzzzzzzzzzzz"}]}`,
		"repeated query id":   `{"consent":true,"selections":[{"query_id":"a","selection_handle":"` + testHandle + `"},{"query_id":"a","selection_handle":"` + testHandle + `"}]}`,
		"handle not a handle": `{"consent":true,"selections":[{"query_id":"a","selection_handle":"short"}]}`,
	} {
		_, err := consentFromSelectCredentials(json.RawMessage(raw))
		assert.Error(t, err, name)
	}
}

// consentFlow runs the engine's real credential selection (the code both
// transports share) in a WMP flow: it reports what the flow decided.
type consentFlowResult struct {
	decision consentDecision
	err      error
}

func consentFlowEnv(t *testing.T, mode config.DCQLConsentCheckMode, verifier *httptest.Server) (*wmpEnv, chan consentFlowResult) {
	t.Helper()
	cfg := &config.Config{Presentation: config.PresentationConfig{DCQLConsentCheck: mode}}
	e := newWMPEnvCfg(t, cfg)
	results := make(chan consentFlowResult, 1)
	registerScripted(e.m, ProtocolOID4VP, func(ctx context.Context, f *Flow, _ *FlowStartMessage) error {
		h := &OID4VPHandler{BaseHandler: BaseHandler{Flow: f, Logger: zap.NewNop(), Config: cfg}, httpClient: &http.Client{Timeout: 5 * time.Second}}
		authReq := &AuthorizationRequest{DCQLQuery: json.RawMessage(consentTestQuery), ResponseURI: verifier.URL, State: "s"}
		d, err := h.requestCredentialSelection(ctx, authReq, &VerifierInfo{})
		results <- consentFlowResult{d, err}
		return err
	})
	return e, results
}

func selectCredentialsAction(sid string, selections ...string) map[string]any {
	sels := make([]any, len(selections))
	for i, q := range selections {
		sels[i] = map[string]any{"query_id": q, "selection_handle": testHandle}
	}
	return req(wmp.MethodFlowAction, map[string]any{"wmp": meta(sid), "flow_id": "f1", "action": "select_credentials",
		"params": map[string]any{"consent": true, "selections": sels}})
}

// WMP follows the policy of the WebSocket path: the same configured check, so a
// selection outside the verifier's query is refused where it is enforced (the
// verifier is told access_denied, the flow ends -32602 without data, as
// OpenID4x 3.2.3.1 says) and accepted, with a warning, where it is not.
func TestWMPConsent_BridgeAppliesThePolicy(t *testing.T) {
	newVerifier := func() (*httptest.Server, *int32) {
		var n int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = r.ParseForm()
			assert.Equal(t, "access_denied", r.PostForm.Get("error"))
			assert.Equal(t, verifierRefusedDescription, r.PostForm.Get("error_description"), "the generic description, never the reason")
			atomic.AddInt32(&n, 1)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{}`))
		}))
		t.Cleanup(srv.Close)
		return srv, &n
	}
	start := func(e *wmpEnv) (string, string, *stream) {
		tok := e.token("alice", "t1", "ir", "j1")
		sid := e.create(tok, "oid4vp")
		st, _ := e.openStream(tok, sid, "")
		require.Equal(t, 0, e.post(tok, sid, startOID4VP(sid, "f1")).code())
		waitFlows(t, e, sid, 1)
		return tok, sid, st
	}

	t.Run("enforce refuses a query id outside the request", func(t *testing.T) {
		verifier, told := newVerifier()
		e, results := consentFlowEnv(t, config.DCQLConsentCheckEnforce, verifier)
		tok, sid, st := start(e)
		r := e.post(tok, sid, selectCredentialsAction(sid, "not-in-the-request"))
		assert.Equal(t, wmp.ErrInvalidParams, r.code(), "the action is answered -32602 (3.2.3.1), correlated: %v", r.Body)
		assert.Nil(t, r.errData())
		ev := st.nextMethod(t, wmp.MethodFlowError)
		assert.EqualValues(t, wmp.ErrInvalidParams, params(ev)["code"])
		assert.Nil(t, params(ev)["data"])
		assert.NotContains(t, ev.Raw, "not-in-the-request")
		res := <-results
		var refusal *consentRefusal
		require.ErrorAs(t, res.err, &refusal)
		assert.Equal(t, consentReasonOutsideQuery, refusal.Reason)
		assert.EqualValues(t, 1, atomic.LoadInt32(told), "the verifier is told")
	})

	t.Run("warn proceeds, like the WebSocket path", func(t *testing.T) {
		verifier, told := newVerifier()
		e, results := consentFlowEnv(t, config.DCQLConsentCheckWarn, verifier)
		tok, sid, _ := start(e)
		assert.Equal(t, 0, e.post(tok, sid, selectCredentialsAction(sid, "not-in-the-request")).code())
		res := <-results
		require.NoError(t, res.err)
		assert.Equal(t, []ConsentSelection{{CredentialQueryID: "not-in-the-request"}}, res.decision.Selected)
		assert.Equal(t, testHandle, res.decision.Handle)
		assert.EqualValues(t, 0, atomic.LoadInt32(told))
	})

	t.Run("a selection of the request is accepted in every mode", func(t *testing.T) {
		verifier, _ := newVerifier()
		e, results := consentFlowEnv(t, config.DCQLConsentCheckEnforce, verifier)
		tok, sid, _ := start(e)
		assert.Equal(t, 0, e.post(tok, sid, selectCredentialsAction(sid, "pid", "mdl")).code())
		res := <-results
		require.NoError(t, res.err)
		refs, handle := res.decision.signInclusion()
		assert.Equal(t, []CredentialRef{{CredentialQueryID: "pid"}, {CredentialQueryID: "mdl"}}, refs)
		assert.Equal(t, testHandle, handle)
	})
}

// The same logical consent through either wire reaches the same decision, and a
// refusal is the same refusal: the transports translate, the component decides.
func TestConsent_SameDecisionOnBothWires(t *testing.T) {
	cfg := &config.Config{Presentation: config.PresentationConfig{DCQLConsentCheck: config.DCQLConsentCheckEnforce}}
	for name, tc := range map[string]struct {
		queries []string
		reason  string
	}{
		"in the request": {[]string{"pid", "mdl"}, ""},
		"outside":        {[]string{"pid", "nope"}, consentReasonOutsideQuery},
	} {
		t.Run(name, func(t *testing.T) {
			var ws, wmpSel []any
			for _, q := range tc.queries {
				ws = append(ws, map[string]any{"credential_query_id": q, "credential_id": "c-" + q})
				wmpSel = append(wmpSel, map[string]any{"query_id": q, "selection_handle": testHandle})
			}
			wsRaw, _ := json.Marshal(map[string]any{"selected_credentials": ws})
			wmpRaw, _ := json.Marshal(map[string]any{"consent": true, "selections": wmpSel})

			wsAnswer, err := consentAnswerFrom(&FlowActionMessage{Action: ActionConsent, Payload: wsRaw})
			require.NoError(t, err)
			wmpAnswer, err := consentFromSelectCredentials(wmpRaw)
			require.NoError(t, err)

			p := newConsentPolicy(cfg, zap.NewNop())
			wsDecision, wsErr := p.Decide(json.RawMessage(consentTestQuery), wsAnswer)
			wmpDecision, wmpErr := p.Decide(json.RawMessage(consentTestQuery), *wmpAnswer)
			if tc.reason != "" {
				var a, b *consentRefusal
				require.ErrorAs(t, wsErr, &a)
				require.ErrorAs(t, wmpErr, &b)
				assert.Equal(t, a, b)
				assert.Equal(t, tc.reason, a.Reason)
				return
			}
			require.NoError(t, wsErr)
			require.NoError(t, wmpErr)
			var wsIDs, wmpIDs []string
			for _, s := range wsDecision.Selected {
				wsIDs = append(wsIDs, s.CredentialQueryID)
			}
			for _, s := range wmpDecision.Selected {
				wmpIDs = append(wmpIDs, s.CredentialQueryID)
			}
			assert.Equal(t, wsIDs, wmpIDs)
		})
	}
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

// An oid4vp cancel is a decline while the flow waits for the selection and
// nothing else can consume one. Once a selection was handed over (the flow is
// signing, the step still the selection) and before the flow asks for one, a
// cancel ends the flow: it is not acknowledged and ignored while the flow runs
// on to submit the presentation.
func TestWMPBridge_CancelWhenNothingWaitsForTheSelectionEndsTheFlow(t *testing.T) {
	cancelAction := func(sid string) map[string]any {
		return req(wmp.MethodFlowAction, map[string]any{"wmp": meta(sid), "flow_id": "f1", "action": "cancel", "params": map[string]any{"reason": "changed my mind"}})
	}

	t.Run("after the consent was handed over", func(t *testing.T) {
		e := newWMPEnv(t)
		ranOn := make(chan bool, 1)
		registerScripted(e.m, ProtocolOID4VP, func(ctx context.Context, f *Flow, _ *FlowStartMessage) error {
			f.mu.Lock()
			f.State = StepCredentialSelection
			f.mu.Unlock()
			_ = f.Session.SendProgress(f.ID, StepCredentialSelection, nil)
			if _, err := f.Session.WaitForAction(ctx, f.ID, ActionConsent); err != nil {
				return err
			}
			// Consumed, the sign request not registered yet: the window in which a
			// decline has no consumer.
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
		require.Equal(t, 0, e.post(tok, sid, req(wmp.MethodFlowAction, map[string]any{"wmp": meta(sid), "flow_id": "f1", "action": "select_credentials", "params": good})).code())

		assert.Equal(t, 0, e.post(tok, sid, cancelAction(sid)).code())
		ev := st.nextMethod(t, wmp.MethodFlowError)
		assert.EqualValues(t, wmp.ErrFlowError, params(ev)["code"])
		assert.Equal(t, map[string]any{"reason": "cancelled"}, params(ev)["data"])
		assert.False(t, <-ranOn, "the flow was stopped, not left to sign and submit")
	})

	t.Run("malformed cancel params are refused, not read as empty", func(t *testing.T) {
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
		r := e.post(tok, sid, req(wmp.MethodFlowAction, map[string]any{"wmp": meta(sid), "flow_id": "f1", "action": "cancel", "params": map[string]any{"reason": 42}}))
		assert.Equal(t, wmp.ErrInvalidParams, r.code())
	})

	t.Run("while the flow waits for the selection it is a decline", func(t *testing.T) {
		e := newWMPEnv(t)
		got := make(chan string, 1)
		registerScripted(e.m, ProtocolOID4VP, func(ctx context.Context, f *Flow, _ *FlowStartMessage) error {
			f.mu.Lock()
			f.State = StepCredentialSelection
			f.mu.Unlock()
			_ = f.Session.SendProgress(f.ID, StepCredentialSelection, nil)
			act, err := f.Session.WaitForAction(ctx, f.ID, ActionConsent, ActionDecline)
			if err != nil {
				return err
			}
			got <- act.Action
			return f.Session.SendFlowError(f.ID, StepCredentialSelection, ErrCodePresentationError, "declined")
		})
		tok := e.token("alice", "t1", "ir", "j1")
		sid := e.create(tok, "oid4vp")
		st, _ := e.openStream(tok, sid, "")
		require.Equal(t, 0, e.post(tok, sid, startOID4VP(sid, "f1")).code())
		st.nextMethod(t, wmp.MethodFlowProgress)
		assert.Equal(t, 0, e.post(tok, sid, cancelAction(sid)).code())
		assert.Equal(t, ActionDecline, <-got, "the verifier-refusal path is kept while the selection is awaited")
	})

	t.Run("before the flow asks for a selection", func(t *testing.T) {
		e := newWMPEnv(t)
		stopped := make(chan struct{})
		registerScripted(e.m, ProtocolOID4VP, func(ctx context.Context, _ *Flow, _ *FlowStartMessage) error {
			<-ctx.Done()
			close(stopped)
			return ctx.Err()
		})
		tok := e.token("alice", "t1", "ir", "j1")
		sid := e.create(tok, "oid4vp")
		st, _ := e.openStream(tok, sid, "")
		require.Equal(t, 0, e.post(tok, sid, startOID4VP(sid, "f1")).code())
		waitFlows(t, e, sid, 1)
		assert.Equal(t, 0, e.post(tok, sid, cancelAction(sid)).code())
		ev := st.nextMethod(t, wmp.MethodFlowError)
		assert.Equal(t, map[string]any{"reason": "cancelled"}, params(ev)["data"])
		select {
		case <-stopped:
		case <-time.After(5 * time.Second):
			t.Fatal("the flow was not cancelled")
		}
	})
}
