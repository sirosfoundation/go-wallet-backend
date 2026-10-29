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
