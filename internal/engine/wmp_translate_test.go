package engine

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/sirosfoundation/go-wmp/pkg/wmp"
	"github.com/sirosfoundation/go-wmp/pkg/wmp/openid4x"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func tr(t *testing.T, flowType string, step FlowStep, payload string) (wmpStep, bool) {
	t.Helper()
	return translateProgress(&wmpFlow{}, flowType, step, json.RawMessage(payload))
}

func asMap(t *testing.T, v interface{}) map[string]interface{} {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	m := map[string]interface{}{}
	require.NoError(t, json.Unmarshal(b, &m))
	return m
}

// Every step the engine defines is either translated to a step of the profile
// or deliberately not sent: a new engine step cannot reach a WMP client under
// its own name, and a test must say what becomes of it.
func TestWMPTranslate_EveryEngineStepIsDecided(t *testing.T) {
	vci := map[FlowStep]string{
		StepParsingOffer:         openid4x.StepParsingOffer,
		StepOfferParsed:          openid4x.StepParsingOffer,
		StepFetchingMetadata:     openid4x.StepResolvingMetadata,
		StepMetadataFetched:      openid4x.StepMetadataFetched,
		StepEvaluatingTrust:      openid4x.StepEvaluatingTrust,
		StepTrustEvaluated:       openid4x.StepTrustEvaluated,
		StepAwaitingSelection:    openid4x.StepAwaitingOfferAcceptance,
		StepAuthorizationReq:     openid4x.StepAuthorizationPending,
		StepRequestingCredential: openid4x.StepRequestingCredential,
		StepDeferred:             openid4x.StepRequestingCredential,
		StepExchangingToken:      "",
		StepTokenObtained:        "",
		// OID4VP steps in an issuance flow, and the reverse, are not translated.
		StepParsingRequest:          "",
		StepRequestParsed:           "",
		StepEvaluatingVerifierTrust: "",
		StepMatchCredentials:        "",
		StepAwaitingConsent:         "",
		StepCredentialSelection:     "",
		StepSubmittingResponse:      "",
	}
	for step, want := range vci {
		got, ok := tr(t, openid4x.FlowTypeOID4VCI, step, `{}`)
		assert.Equal(t, want != "", ok, "oid4vci %s", step)
		assert.Equal(t, want, got.Step, "oid4vci %s", step)
	}
	vp := map[FlowStep]string{
		StepParsingRequest:          openid4x.StepParsingRequest,
		StepEvaluatingVerifierTrust: openid4x.StepVPEvaluatingTrust,
		StepTrustEvaluated:          openid4x.StepVPTrustEvaluated,
		StepCredentialSelection:     openid4x.StepAwaitingConsent,
		StepSubmittingResponse:      "",
		StepRequestParsed:           "",
		StepMatchCredentials:        "",
		StepAwaitingConsent:         "",
		StepParsingOffer:            "",
		StepAwaitingSelection:       "",
		StepAuthorizationReq:        "",
		StepDeferred:                "",
	}
	for step, want := range vp {
		got, ok := tr(t, openid4x.FlowTypeOID4VP, step, `{}`)
		assert.Equal(t, want != "", ok, "oid4vp %s", step)
		assert.Equal(t, want, got.Step, "oid4vp %s", step)
	}
	// No engine step name is a step name of the profile unless it is the same
	// name: nothing slips through untranslated.
	_, ok := tr(t, openid4x.FlowTypeOID4VCI, "no_such_step", `{}`)
	assert.False(t, ok)
	_, ok = tr(t, "sign", StepParsingOffer, `{}`)
	assert.False(t, ok)
}

func TestWMPTranslate_ProgressPayloads(t *testing.T) {
	t.Run("offer_parsed is the offer of parsing_offer", func(t *testing.T) {
		s, _ := tr(t, openid4x.FlowTypeOID4VCI, StepOfferParsed, `{"credential_issuer":"https://i","credential_configuration_ids":["a"],"grants":{}}`)
		offer := asMap(t, s.Payload)["offer"].(map[string]interface{})
		assert.Equal(t, "https://i", offer["credential_issuer"])
	})
	t.Run("metadata_fetched carries issuer_metadata", func(t *testing.T) {
		f := &wmpFlow{}
		s, _ := translateProgress(f, openid4x.FlowTypeOID4VCI, StepMetadataFetched, json.RawMessage(`{"credential_issuer":"https://i","display":[{"name":"I"}],"validated":true}`))
		assert.Equal(t, "https://i", asMap(t, s.Payload)["issuer_metadata"].(map[string]interface{})["credential_issuer"])
		assert.Equal(t, "https://i", f.issuer["issuer"], "recorded for awaiting_offer_acceptance")
	})
	t.Run("a message-only progress carries no payload", func(t *testing.T) {
		s, _ := tr(t, openid4x.FlowTypeOID4VCI, StepEvaluatingTrust, `{"message":"Evaluating issuer trust"}`)
		assert.Nil(t, s.Payload)
	})
	t.Run("a request for the client's own trust evaluation is relayed", func(t *testing.T) {
		s, _ := tr(t, openid4x.FlowTypeOID4VCI, StepEvaluatingTrust, `{"trust_evaluation_required":true,"request":{"subject_id":"x"}}`)
		assert.Equal(t, true, asMap(t, s.Payload)["trust_evaluation_required"])
	})
	t.Run("trust_evaluated carries trust_info next to the engine's members", func(t *testing.T) {
		s, _ := tr(t, openid4x.FlowTypeOID4VP, StepTrustEvaluated,
			`{"verifier_trust_evaluated":true,"verifier":"v","trusted":true,"framework":"etsi","reason":"ok","context":{"verifier_ids":[]}}`)
		m := asMap(t, s.Payload)
		assert.Equal(t, map[string]interface{}{"trusted": true, "framework": "etsi", "reason": "ok"}, m["trust_info"])
		assert.Equal(t, true, m["verifier_trust_evaluated"], "7.4 reads it")
		assert.NotNil(t, m["context"])
	})
	t.Run("credential_selection is awaiting_consent", func(t *testing.T) {
		s, _ := tr(t, openid4x.FlowTypeOID4VP, StepCredentialSelection,
			`{"dcql_query":{"credentials":[]},"verifier":{"name":"V","trusted":true},"client_metadata":{"a":1},"verified_request":{"signed":true}}`)
		m := asMap(t, s.Payload)
		assert.Equal(t, "V", m["verifier_info"].(map[string]interface{})["name"])
		assert.NotContains(t, m, "verifier")
		assert.Contains(t, m, "dcql_query")
		assert.Contains(t, m, "client_metadata")
		assert.Contains(t, m, "verified_request")
		assert.NotContains(t, m, "matched_credentials", "the engine does not match (3.3.3)")
	})
	t.Run("authorization_required: transaction code", func(t *testing.T) {
		s, _ := tr(t, openid4x.FlowTypeOID4VCI, StepAuthorizationReq,
			`{"type":"tx_code","pre_authorized_code":"SECRET-PRE-AUTH","tx_code":{"input_mode":"numeric","length":4,"description":"SMS","x":1},"credential_issuer":"https://i","message":"Enter the code"}`)
		assert.Equal(t, openid4x.StepAwaitingTxCode, s.Step)
		m := asMap(t, s.Payload)
		assert.Equal(t, "Enter the code", m["tx_code_description"])
		assert.Equal(t, map[string]interface{}{"input_mode": "numeric", "length": float64(4), "description": "SMS"}, m["tx_code"])
		b, _ := json.Marshal(s.Payload)
		assert.NotContains(t, string(b), "SECRET-PRE-AUTH", "the engine's pre-authorized code is not relayed")
	})
	t.Run("authorization_required: authorization", func(t *testing.T) {
		s, _ := tr(t, openid4x.FlowTypeOID4VCI, StepAuthorizationReq,
			`{"authorization_url":"https://as/auth","expected_redirect_uri":"https://w/cb","state":"st","code_verifier":"cv","credential_offer":{"a":1}}`)
		assert.Equal(t, openid4x.StepAuthorizationPending, s.Step)
		m := asMap(t, s.Payload)
		for _, k := range []string{"authorization_url", "expected_redirect_uri", "state", "code_verifier", "credential_offer"} {
			assert.Contains(t, m, k)
		}
	})
	t.Run("deferred is requesting_credential without the transaction id", func(t *testing.T) {
		s, _ := tr(t, openid4x.FlowTypeOID4VCI, StepDeferred, `{"transaction_id":"TX-SECRET","interval":5,"attempt":2,"max_attempts":10,"message":"x"}`)
		assert.Equal(t, openid4x.StepRequestingCredential, s.Step)
		assert.Equal(t, map[string]interface{}{"deferred": true, "interval": float64(5), "attempt": float64(2), "max_attempts": float64(10)}, asMap(t, s.Payload))
	})
	t.Run("awaiting_selection is awaiting_offer_acceptance by index", func(t *testing.T) {
		f := &wmpFlow{issuer: map[string]interface{}{"issuer": "https://i"}}
		s, _ := translateProgress(f, openid4x.FlowTypeOID4VCI, StepAwaitingSelection, json.RawMessage(
			`{"available_credentials":[{"id":"cfg-a","format":"dc+sd-jwt","vct":"v1","display":{"name":"A","locale":"en"}},{"id":"cfg-b","format":"mso_mdoc"}]}`))
		assert.Equal(t, openid4x.StepAwaitingOfferAcceptance, s.Step)
		m := asMap(t, s.Payload)
		creds := m["credentials"].([]interface{})
		require.Len(t, creds, 2)
		assert.Equal(t, map[string]interface{}{"index": float64(0), "format": "dc+sd-jwt", "vct": "v1", "display": map[string]interface{}{"name": "A", "locale": "en"}}, creds[0])
		assert.Equal(t, map[string]interface{}{"index": float64(1), "format": "mso_mdoc"}, creds[1])
		b, _ := json.Marshal(s.Payload)
		assert.NotContains(t, string(b), "cfg-a", "configuration ids are the engine's")
		assert.Equal(t, []string{"cfg-a", "cfg-b"}, f.offerIDs)
		assert.Equal(t, "https://i", m["issuer_metadata"].(map[string]interface{})["issuer"])
	})
}

func TestWMPTranslate_CompletionHasNoEnvelope(t *testing.T) {
	m := &FlowCompleteMessage{Message: Message{Type: TypeFlowComplete, FlowID: "f1", MessageID: "m", Timestamp: Now()},
		RedirectURI: "https://v/done", Credentials: []CredentialResult{{Format: "dc+sd-jwt", Credential: "c"}}}
	raw, err := completionResult(m)
	require.NoError(t, err)
	res := map[string]interface{}{}
	require.NoError(t, json.Unmarshal(raw, &res))
	for _, k := range []string{"type", "flow_id", "message_id", "timestamp"} {
		assert.NotContains(t, res, k)
	}
	assert.Equal(t, "https://v/done", res["redirect_uri"])
	assert.Len(t, res["credentials"], 1)
}

// ---------------------------------------------------------------------------
// Through the bridge, driven as a wallet drives it.
// ---------------------------------------------------------------------------

func startVCI(sid, flowID string) map[string]any {
	return req(wmp.MethodFlowStart, map[string]any{"wmp": meta(sid), "flow_type": "oid4vci", "flow_id": flowID,
		"params": map[string]any{"credential_offer": "openid-credential-offer://x"}})
}

func flowAction(sid, flowID, action string, p map[string]any) map[string]any {
	return req(wmp.MethodFlowAction, map[string]any{"wmp": meta(sid), "flow_id": flowID, "action": action, "params": p})
}

// A multi-credential offer: the wallet sees awaiting_offer_acceptance with
// indices, answers accept_offer, and the engine gets select_credential with the
// configuration id it offered, nothing else.
func TestWMPBridge_AcceptOffer(t *testing.T) {
	setup := func(t *testing.T) (*wmpEnv, string, string, *stream, chan *FlowActionMessage) {
		e := newWMPEnv(t)
		actions := make(chan *FlowActionMessage, 4)
		registerScripted(e.m, ProtocolOID4VCI, func(ctx context.Context, f *Flow, _ *FlowStartMessage) error {
			_ = f.Session.SendProgress(f.ID, StepAwaitingSelection, map[string]any{"available_credentials": []any{
				map[string]any{"id": "cfg-a", "format": "dc+sd-jwt", "vct": "v1"},
				map[string]any{"id": "cfg-b", "format": "mso_mdoc"},
			}})
			for {
				act, err := f.Session.WaitForAction(ctx, f.ID, ActionSelectCredential, ActionDecline, ActionConsent)
				if err != nil {
					return err
				}
				actions <- act
			}
		})
		tok := e.token("alice", "t1", "ir", "j1")
		sid := e.create(tok, "oid4vci")
		st, _ := e.openStream(tok, sid, "")
		require.Equal(t, 0, e.post(tok, sid, startVCI(sid, "f1")).code())
		prog := st.nextMethod(t, wmp.MethodFlowProgress)
		assert.Equal(t, openid4x.StepAwaitingOfferAcceptance, params(prog)["step"])
		assert.NotContains(t, prog.Raw, "cfg-a")
		return e, tok, sid, st, actions
	}

	t.Run("the index names the engine's configuration", func(t *testing.T) {
		e, tok, sid, _, actions := setup(t)
		r := e.post(tok, sid, flowAction(sid, "f1", "accept_offer", map[string]any{"selected_indices": []int{1}, "consent": true}))
		assert.Equal(t, 0, r.code(), "%v", r.Body)
		act := <-actions
		assert.Equal(t, ActionSelectCredential, act.Action)
		assert.JSONEq(t, `{"credential_configuration_id":"cfg-b"}`, string(act.Payload))
	})

	t.Run("an index outside the offered credentials is refused, and the flow goes on", func(t *testing.T) {
		e, tok, sid, _, actions := setup(t)
		for name, idx := range map[string][]int{"past the end": {2}, "negative": {-1}, "none": {}, "two": {0, 1}} {
			r := e.post(tok, sid, flowAction(sid, "f1", "accept_offer", map[string]any{"selected_indices": idx, "consent": true}))
			assert.Equal(t, wmp.ErrInvalidParams, r.code(), name)
		}
		select {
		case act := <-actions:
			t.Fatalf("nothing may reach the engine, got %s", act.Action)
		case <-time.After(200 * time.Millisecond):
		}
		r := e.post(tok, sid, flowAction(sid, "f1", "accept_offer", map[string]any{"selected_indices": []int{0}, "consent": true}))
		assert.Equal(t, 0, r.code())
		assert.JSONEq(t, `{"credential_configuration_id":"cfg-a"}`, string((<-actions).Payload))
	})

	t.Run("accept_offer before an offer awaits acceptance is refused", func(t *testing.T) {
		e := newWMPEnv(t)
		registerScripted(e.m, ProtocolOID4VCI, func(ctx context.Context, _ *Flow, _ *FlowStartMessage) error {
			<-ctx.Done()
			return ctx.Err()
		})
		tok := e.token("alice", "t1", "ir", "j1")
		sid := e.create(tok, "oid4vci")
		require.Equal(t, 0, e.post(tok, sid, startVCI(sid, "f1")).code())
		waitFlows(t, e, sid, 1)
		r := e.post(tok, sid, flowAction(sid, "f1", "accept_offer", map[string]any{"selected_indices": []int{0}, "consent": true}))
		assert.Equal(t, wmp.ErrInvalidParams, r.code())
	})

	t.Run("consent false ends the flow", func(t *testing.T) {
		e, tok, sid, _, actions := setup(t)
		r := e.post(tok, sid, flowAction(sid, "f1", "accept_offer", map[string]any{"selected_indices": []int{0}, "consent": false}))
		assert.Equal(t, 0, r.code(), "%v", r.Body)
		waitFlows(t, e, sid, 0)
		assert.Empty(t, actions, "the engine is not given a selection")
	})
}

// provide_tx_code and authorize reach the engine as provide_pin and
// authorization_complete, reshaped; cancel ends an issuance.
func TestWMPBridge_IssuanceActions(t *testing.T) {
	e := newWMPEnv(t)
	actions := make(chan *FlowActionMessage, 4)
	registerScripted(e.m, ProtocolOID4VCI, func(ctx context.Context, f *Flow, _ *FlowStartMessage) error {
		for {
			act, err := f.Session.WaitForAction(ctx, f.ID, ActionProvidePin, ActionAuthorizationComplete, ActionDecline, ActionConsent, ActionSelectCredential)
			if err != nil {
				return err
			}
			actions <- act
		}
	})
	tok := e.token("alice", "t1", "ir", "j1")
	sid := e.create(tok, "oid4vci")
	require.Equal(t, 0, e.post(tok, sid, startVCI(sid, "f1")).code())
	waitFlows(t, e, sid, 1)

	r := e.post(tok, sid, flowAction(sid, "f1", "provide_tx_code", map[string]any{"tx_code": "1234", "extra": "dropped"}))
	require.Equal(t, 0, r.code(), "%v", r.Body)
	act := <-actions
	assert.Equal(t, ActionProvidePin, act.Action)
	assert.JSONEq(t, `{"tx_code":"1234"}`, string(act.Payload))

	r = e.post(tok, sid, flowAction(sid, "f1", "authorize", map[string]any{"auth_code": "AC", "code_verifier": "CV", "state": "ST"}))
	require.Equal(t, 0, r.code(), "%v", r.Body)
	act = <-actions
	assert.Equal(t, ActionAuthorizationComplete, act.Action)
	assert.JSONEq(t, `{"code":"AC","code_verifier":"CV","state":"ST"}`, string(act.Payload))

	assert.Equal(t, wmp.ErrInvalidParams, e.post(tok, sid, flowAction(sid, "f1", "provide_tx_code", map[string]any{})).code())
	assert.Equal(t, wmp.ErrInvalidParams, e.post(tok, sid, flowAction(sid, "f1", "authorize", map[string]any{"code_verifier": "x"})).code())

	r = e.post(tok, sid, flowAction(sid, "f1", "cancel", map[string]any{"reason": "changed my mind"}))
	assert.Equal(t, 0, r.code(), "%v", r.Body)
	waitFlows(t, e, sid, 0)
}

// A WMP client speaks the profile's action names. The engine's own (and
// anything else) are refused, so a client cannot reach the engine's actions
// with a shape the profile does not define.
func TestWMPBridge_EngineActionNamesAreRefused(t *testing.T) {
	e := newWMPEnv(t)
	registerScripted(e.m, ProtocolOID4VCI, func(ctx context.Context, _ *Flow, _ *FlowStartMessage) error {
		<-ctx.Done()
		return ctx.Err()
	})
	registerScripted(e.m, ProtocolOID4VP, func(ctx context.Context, _ *Flow, _ *FlowStartMessage) error {
		<-ctx.Done()
		return ctx.Err()
	})
	tok := e.token("alice", "t1", "ir", "j1")
	sid := e.create(tok, "oid4vci", "oid4vp")
	require.Equal(t, 0, e.post(tok, sid, startVCI(sid, "fi")).code())
	require.Equal(t, 0, e.post(tok, sid, startOID4VP(sid, "fp")).code())
	waitFlows(t, e, sid, 2)

	for _, name := range []string{"consent", "decline", "provide_pin", "authorization_complete", "select_credential", "credentials_matched", "sign_response", "nonsense"} {
		for _, fid := range []string{"fi", "fp"} {
			r := e.post(tok, sid, flowAction(sid, fid, name, map[string]any{}))
			assert.Equal(t, wmp.ErrInvalidParams, r.code(), "%s on %s", name, fid)
		}
	}
	// Actions of the other flow type are refused too.
	assert.Equal(t, wmp.ErrInvalidParams, e.post(tok, sid, flowAction(sid, "fp", "accept_offer", map[string]any{"consent": true, "selected_indices": []int{0}})).code())
	assert.Equal(t, wmp.ErrInvalidParams, e.post(tok, sid, flowAction(sid, "fi", "select_credentials", map[string]any{"consent": false})).code())
}

// The sign sub-flow is reported as the profile's generating_proof and
// generating_presentation, and the progress the engine sends around the token
// endpoint, which the profile has no step for, is not sent.
func TestWMPBridge_SignStepsAndDroppedSteps(t *testing.T) {
	e := newWMPEnv(t)
	registerScripted(e.m, ProtocolOID4VCI, func(ctx context.Context, f *Flow, _ *FlowStartMessage) error {
		_ = f.Session.SendProgress(f.ID, StepExchangingToken, map[string]string{"message": "x"})
		_ = f.Session.SendProgress(f.ID, StepTokenObtained, nil)
		_, err := f.Session.RequestSign(ctx, f.ID, SignActionGenerateProof, SignRequestParams{Nonce: "n", ProofType: "jwt"})
		return err
	})
	tok := e.token("alice", "t1", "ir", "j1")
	sid := e.create(tok, "oid4vci")
	st, _ := e.openStream(tok, sid, "")
	require.Equal(t, 0, e.post(tok, sid, startVCI(sid, "f1")).code())
	prog := st.nextMethod(t, wmp.MethodFlowProgress)
	assert.Equal(t, openid4x.StepGeneratingProof, params(prog)["step"], "the token steps were not sent")
	st.nextMethod(t, wmp.MethodFlowStart)
}
