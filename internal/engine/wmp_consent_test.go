package engine

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
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

// A repeated malformed selection while the verifier is being told must not cut
// that refusal short: the first one is carried out.
func TestWMPBridge_RepeatedMalformedSelectionLeavesTheRefusalRunning(t *testing.T) {
	hit := make(chan struct{}, 1)
	release := make(chan struct{})
	var releaseOnce sync.Once
	doRelease := func() { releaseOnce.Do(func() { close(release) }) }
	delivered := make(chan bool, 1)
	verifier := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit <- struct{}{}
		<-release
		delivered <- r.Context().Err() == nil
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer verifier.Close()
	defer doRelease() // a failing test must not leave the handler blocked

	e := newWMPEnv(t)
	registerScripted(e.m, ProtocolOID4VP, func(ctx context.Context, f *Flow, _ *FlowStartMessage) error {
		h := &OID4VPHandler{BaseHandler: BaseHandler{Logger: zap.NewNop(), Flow: f}, httpClient: verifier.Client()}
		authReq := &AuthorizationRequest{ClientID: "https://v", ResponseMode: ResponseModeDirectPost, ResponseURI: verifier.URL, State: "st", Nonce: "n"}
		f.mu.Lock()
		f.State = StepCredentialSelection
		f.mu.Unlock()
		_, err := h.requestVPSignature(ctx, authReq, decisionOf(ConsentSelection{CredentialQueryID: "q1"}), "https://v")
		h.failSign(ctx, authReq, err)
		return err
	})
	tok := e.token("alice", "t1", "ir", "j1")
	sid := e.create(tok, "oid4vp")
	st, _ := e.openStream(tok, sid, "")
	require.Equal(t, 0, e.post(tok, sid, startOID4VP(sid, "f1")).code())
	st.nextMethod(t, wmp.MethodFlowStart) // the sign sub-flow is pending

	bad := req(wmp.MethodFlowAction, map[string]any{"wmp": meta(sid), "flow_id": "f1", "action": "select_credentials",
		"params": map[string]any{"consent": true, "selections": []any{map[string]any{"query_id": "q1", "selection_handle": testHandle, "credential_id": "c"}}}})
	assert.Equal(t, wmp.ErrInvalidParams, e.post(tok, sid, bad).code())
	<-hit // the sign request is gone, the verifier is being told
	assert.Equal(t, wmp.ErrInvalidParams, e.post(tok, sid, bad).code())
	select {
	case ev := <-st.events:
		t.Fatalf("the flow ended before the verifier was told: %s", ev.Raw)
	case <-time.After(300 * time.Millisecond):
	}
	doRelease()
	select {
	case ok := <-delivered:
		assert.True(t, ok, "the verifier's notification was not cancelled")
	case <-time.After(5 * time.Second):
		t.Fatal("the verifier was not told")
	}
	ev := st.nextMethod(t, wmp.MethodFlowError)
	assert.EqualValues(t, wmp.ErrInvalidParams, params(ev)["code"])
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

// blockedRefusal is a flow that has a sign request pending, with a verifier that
// holds back its answer until released: the window in which the pending request's
// entry is gone and the verifier is still being told.
type blockedRefusal struct {
	e         *wmpEnv
	tok, sid  string
	st        *stream
	told      chan struct{ errCode, vp string }
	hit       chan struct{}
	delivered chan bool
	release   func()
}

func newBlockedRefusal(t *testing.T) *blockedRefusal {
	t.Helper()
	b := &blockedRefusal{
		told:      make(chan struct{ errCode, vp string }, 4),
		hit:       make(chan struct{}, 4),
		delivered: make(chan bool, 4),
	}
	releaseCh := make(chan struct{})
	var once sync.Once
	b.release = func() { once.Do(func() { close(releaseCh) }) }
	verifier := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		b.told <- struct{ errCode, vp string }{r.PostForm.Get("error"), r.PostForm.Get("vp_token")}
		b.hit <- struct{}{}
		<-releaseCh
		b.delivered <- r.Context().Err() == nil
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"redirect_uri":"https://verifier.example/done"}`))
	}))
	t.Cleanup(verifier.Close)
	t.Cleanup(b.release) // a failing test must not leave the handler blocked

	b.e = newWMPEnv(t)
	registerScripted(b.e.m, ProtocolOID4VP, func(ctx context.Context, f *Flow, _ *FlowStartMessage) error {
		h := &OID4VPHandler{BaseHandler: BaseHandler{Logger: zap.NewNop(), Flow: f}, httpClient: verifier.Client()}
		authReq := &AuthorizationRequest{ClientID: "https://v", ResponseMode: ResponseModeDirectPost, ResponseURI: verifier.URL, State: "st", Nonce: "n"}
		f.mu.Lock()
		f.State = StepCredentialSelection // after the consent the step stays the selection
		f.mu.Unlock()
		_, err := h.requestVPSignature(ctx, authReq, decisionOf(ConsentSelection{CredentialQueryID: "q1"}), "https://v")
		h.failSign(ctx, authReq, err)
		return err
	})
	b.tok = b.e.token("alice", "t1", "ir", "j1")
	b.sid = b.e.create(b.tok, "oid4vp")
	b.st, _ = b.e.openStream(b.tok, b.sid, "")
	require.Equal(t, 0, b.e.post(b.tok, b.sid, startOID4VP(b.sid, "f1")).code())
	b.st.nextMethod(t, wmp.MethodFlowStart) // the sign sub-flow is pending
	return b
}

func (b *blockedRefusal) cancel() int {
	return b.e.post(b.tok, b.sid, req(wmp.MethodFlowAction, map[string]any{"wmp": meta(b.sid), "flow_id": "f1", "action": "cancel", "params": map[string]any{}})).code()
}

func (b *blockedRefusal) malformed() int {
	return b.e.post(b.tok, b.sid, req(wmp.MethodFlowAction, map[string]any{"wmp": meta(b.sid), "flow_id": "f1", "action": "select_credentials",
		"params": map[string]any{"consent": true, "selections": []any{map[string]any{"query_id": "q1", "selection_handle": testHandle, "credential_id": "c"}}}})).code()
}

func (b *blockedRefusal) awaitHit(t *testing.T) {
	t.Helper()
	select {
	case <-b.hit:
	case <-time.After(5 * time.Second):
		t.Fatal("the verifier was not told")
	}
}

// finish releases the verifier and checks the refusal was carried out to its end:
// the verifier was told access_denied once with no presentation, its answer was
// delivered (the exchange was not cancelled), and its redirect reaches the client.
func (b *blockedRefusal) finish(t *testing.T) {
	t.Helper()
	b.finishWith(t, "https://verifier.example/done")
}

// finishWith is finish for a refusal whose terminal message is wantInTerminal
// (the verifier's redirect, or "" for the terminal -32602 of a malformed selection).
func (b *blockedRefusal) finishWith(t *testing.T, wantInTerminal string) {
	t.Helper()
	select {
	case ev := <-b.st.events:
		t.Fatalf("the flow ended before the verifier was told: %s", ev.Raw)
	case <-time.After(300 * time.Millisecond):
	}
	b.release()
	select {
	case ok := <-b.delivered:
		assert.True(t, ok, "the verifier's notification was not cancelled")
	case <-time.After(5 * time.Second):
		t.Fatal("the verifier's answer was not delivered")
	}
	f := <-b.told
	assert.Equal(t, "access_denied", f.errCode)
	assert.Empty(t, f.vp, "no presentation is submitted")
	ev := b.st.nextMethod(t, wmp.MethodFlowError)
	if wantInTerminal != "" {
		assert.Contains(t, ev.Raw, wantInTerminal, "the verifier's redirect reaches the client")
	} else {
		assert.EqualValues(t, wmp.ErrInvalidParams, params(ev)["code"])
	}
	select {
	case f := <-b.told:
		t.Fatalf("the verifier was told twice: %+v", f)
	case <-time.After(300 * time.Millisecond):
	}
}

// With a sign request pending, an oid4vp cancel refuses it: the engine tells the
// verifier access_denied (the same refusal as every other sign refusal) and the
// flow ends with the verifier's redirect; the presentation is not submitted. A
// repeated cancel while the verifier is being told, after the pending request's
// entry is gone, leaves the refusal running: it is not cut short and the verifier
// is told once.
func TestWMPBridge_CancelWithASignRequestPendingTellsTheVerifier(t *testing.T) {
	b := newBlockedRefusal(t)
	assert.Equal(t, 0, b.cancel())
	b.awaitHit(t) // the pending request is gone, the verifier is being told
	assert.Equal(t, 0, b.cancel(), "a repeated cancel leaves the refusal running")
	b.finish(t)
}

// Overlapping cancels decide once: whichever runs second never finds the pending
// request gone and the refusal flag not yet set.
func TestWMPBridge_OverlappingCancelsRefuseOnce(t *testing.T) {
	for i := 0; i < 5; i++ {
		b := newBlockedRefusal(t)
		var wg sync.WaitGroup
		for j := 0; j < 4; j++ {
			wg.Add(1)
			go func() { defer wg.Done(); _ = b.cancel() }()
		}
		wg.Wait()
		b.awaitHit(t)
		b.finish(t)
	}
}

// A malformed select_credentials after a cancel refused the pending request does
// not cut that refusal short either: it is answered -32602 as always, and the
// verifier's exchange completes.
func TestWMPBridge_MalformedSelectionAfterACancelLeavesTheRefusalRunning(t *testing.T) {
	b := newBlockedRefusal(t)
	assert.Equal(t, 0, b.cancel())
	b.awaitHit(t)
	assert.Equal(t, wmp.ErrInvalidParams, b.malformed())
	b.finishWith(t, "") // the terminal message is the -32602 of the malformed selection
}
