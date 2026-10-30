package engine

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/sirosfoundation/go-wmp/pkg/wmp"
	"github.com/sirosfoundation/go-wmp/pkg/wmp/openid4x"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

// The bridge wires the entitlement mapping (wmp_entitlement.go) into the two
// places an engine flow reaches a WMP client: errorWire (flow errors) and
// translateVCIProgress (trust_evaluated). These tests drive the REAL engine
// code (OID4VCIHandler.checkIssuerEntitlement / failNotEntitled /
// awaitCredentialSelection, bound to the flow the bridge started) over the real
// bridge, so they fail if either side's shape drifts from the other.

const entitlementTestIssuer = "https://issuer.example"

func entitlementEnv(t *testing.T, mode string) *wmpEnv {
	t.Helper()
	return newWMPEnvCfg(t, &config.Config{Trust: config.TrustConfig{IssuerEntitlementMode: mode}})
}

// realEntitlementHandler is the engine's OID4VCI handler bound to the flow the
// bridge started, as handleFlowStart binds it.
func realEntitlementHandler(e *wmpEnv, f *Flow) *OID4VCIHandler {
	h := &OID4VCIHandler{}
	h.BaseHandler = BaseHandler{Flow: f, Logger: zap.NewNop(), Config: e.m.cfg}
	return h
}

// runEntitlementStep is step 3b of OID4VCIHandler.Execute, calling the engine's
// own functions: the check, and its failure report.
func runEntitlementStep(t *testing.T, e *wmpEnv, f *Flow, offerIDs []string) error {
	h := realEntitlementHandler(e, f)
	offer := &CredentialOffer{CredentialIssuer: entitlementTestIssuer, CredentialConfigurationIDs: offerIDs}
	// No registration certificate: the finding no_access_certificate.
	d, err := h.checkIssuerEntitlement(context.Background(), offer.CredentialIssuer, metaOf(t, metaWithIssuerInfo("")), offer)
	if err != nil {
		h.failNotEntitled(offer.CredentialIssuer, d)
	}
	return err
}

func startEntitlementFlow(t *testing.T, e *wmpEnv) (tok, sid string, st *stream) {
	t.Helper()
	tok = e.token("alice", "t1", "ir", "j1")
	sid = e.create(tok, "oid4vci")
	st, status := e.openStream(tok, sid, "")
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, 0, e.post(tok, sid, startVCI(sid, "f1")).code())
	return tok, sid, st
}

// Fail mode: the engine's own refusal is exactly one -31020 on the wire, with
// go-wmp's typed data, preceded by the findings progress; never a -31006 for
// the same flow.
func TestWMPBridge_EntitlementRefusalOverTheRealEngine(t *testing.T) {
	e := entitlementEnv(t, "fail")
	registerScripted(e.m, ProtocolOID4VCI, func(_ context.Context, f *Flow, _ *FlowStartMessage) error {
		return runEntitlementStep(t, e, f, []string{"pid"})
	})
	_, _, st := startEntitlementFlow(t, e)

	prog := params(st.nextMethod(t, wmp.MethodFlowProgress))
	assert.Equal(t, openid4x.StepTrustEvaluated, prog["step"])
	ev := st.nextMethod(t, wmp.MethodFlowError)
	p := params(ev)
	assert.EqualValues(t, wmp.ErrIssuerNotEntitled, p["code"])
	assert.Equal(t, openid4x.IssuerNotEntitledMessage, p["message"])

	d, err := openid4x.ParseIssuerNotEntitledData(mustJSON(t, p["data"]))
	require.NoError(t, err)
	assert.Equal(t, entitlementTestIssuer, d.Issuer)
	assert.False(t, d.IssuerEntitlement.Allowed)
	assert.Equal(t, "fail", d.IssuerEntitlement.Mode)
	require.NotEmpty(t, d.IssuerEntitlement.Findings)

	// One terminal message: no further error (-31006 or otherwise) follows.
	for {
		select {
		case more, ok := <-st.events:
			if !ok {
				return
			}
			assert.NotEqual(t, wmp.MethodFlowError, more.Data["method"], "a second flow error: %s", more.Raw)
		case <-time.After(300 * time.Millisecond):
			return
		}
	}
}

// Warn mode: the findings are a trust_evaluated progress with the typed payload
// (issuer_entitlement_evaluated, no trust_info: it is not a trust decision), and
// the flow goes on and completes.
func TestWMPBridge_EntitlementWarnProgressOverTheRealEngine(t *testing.T) {
	e := entitlementEnv(t, "warn")
	registerScripted(e.m, ProtocolOID4VCI, func(_ context.Context, f *Flow, _ *FlowStartMessage) error {
		if err := runEntitlementStep(t, e, f, []string{"pid"}); err != nil {
			return err
		}
		return f.Session.SendFlowComplete(f.ID, nil, "")
	})
	_, _, st := startEntitlementFlow(t, e)

	ev := st.nextMethod(t, wmp.MethodFlowProgress)
	p := params(ev)
	assert.Equal(t, openid4x.StepTrustEvaluated, p["step"])
	payload, _ := p["payload"].(map[string]any)
	require.NotNil(t, payload, ev.Raw)
	assert.Equal(t, true, payload["issuer_entitlement_evaluated"])
	assert.Equal(t, entitlementTestIssuer, payload["issuer"])
	assert.NotContains(t, payload, "trust_info", "the findings are not a trust decision")
	ent, _ := payload["issuer_entitlement"].(map[string]any)
	require.NotNil(t, ent)
	assert.Equal(t, "warn", ent["mode"])
	assert.NotEmpty(t, ent["findings"])
	assert.NotContains(t, ev.Raw, "SECRET", "registration-certificate content is not relayed")

	st.nextMethod(t, wmp.MethodFlowComplete)
}

// The wire mapping of every issuer/verifier refusal, once: exactly one code per
// flow, the engine's details not relayed for the issuer codes, an unknown code a
// flow error and never an internal one.
func TestWMPBridge_ErrorWireIssuerRefusals(t *testing.T) {
	tr := &wmpTransport{}
	wire := func(code ErrorCode, details map[string]interface{}) (int, interface{}) {
		c, _, d := tr.errorWire(&FlowErrorMessage{Error: FlowError{Code: code, Message: "m", Details: details}})
		return c, d
	}

	c, d := wire(ErrCodeIssuerNotEntitled, failNotEntitledDetails(entitlementTestIssuer, refusedDecision(1)))
	assert.Equal(t, wmp.ErrIssuerNotEntitled, c)
	assert.IsType(t, &openid4x.IssuerNotEntitledData{}, d)

	// A refusal go-wmp does not accept is -31006 without data, never a made-up
	// decision and never -31020.
	c, d = wire(ErrCodeIssuerNotEntitled, map[string]interface{}{"issuer": ""})
	assert.Equal(t, wmp.ErrFlowError, c)
	assert.Nil(t, d)

	c, d = wire(ErrCodeUntrustedIssuer, map[string]interface{}{"x": 1})
	assert.Equal(t, wmp.ErrFlowError, c)
	assert.Equal(t, openid4x.NewUntrustedIssuerData(), d)

	c, d = wire(ErrCodeUntrustedVerifier, map[string]interface{}{"reason": "x", "a": 1})
	assert.Equal(t, wmp.ErrFlowError, c)
	assert.Equal(t, map[string]interface{}{"reason": "untrusted_verifier", "a": 1}, d)

	c, d = wire("SOME_FUTURE_CODE", map[string]interface{}{"a": 1})
	assert.Equal(t, wmp.ErrFlowError, c, "an unknown engine code is a flow error, not an internal error")
	assert.Equal(t, map[string]interface{}{"a": 1}, d)
}

// A findings progress go-wmp refuses (no issuer) is dropped, never relayed
// unvalidated and never as the issuer's trust result.
func TestWMPBridge_MalformedEntitlementProgressIsDropped(t *testing.T) {
	e := entitlementEnv(t, "warn")
	registerScripted(e.m, ProtocolOID4VCI, func(_ context.Context, f *Flow, _ *FlowStartMessage) error {
		_ = f.Session.SendProgress(f.ID, StepTrustEvaluated, map[string]any{
			"issuer_entitlement_evaluated": true,
			"issuer_entitlement":           map[string]any{"allowed": true, "mode": "warn", "evaluated": true},
		})
		_ = f.Session.SendProgress(f.ID, StepTrustEvaluated, map[string]any{"trusted": true, "framework": "x"})
		return f.Session.SendFlowComplete(f.ID, nil, "")
	})
	_, _, st := startEntitlementFlow(t, e)
	ev := st.nextMethod(t, wmp.MethodFlowProgress)
	payload, _ := params(ev)["payload"].(map[string]any)
	assert.NotContains(t, payload, "issuer_entitlement_evaluated", "the malformed findings were relayed: %s", ev.Raw)
	assert.Contains(t, payload, "trust_info", "the first relayed progress must be the issuer's own trust result")
}

// A selection outside the offer never reaches the engine over WMP: the wallet
// can only name an index of the credentials the engine listed (the offer's),
// and the real awaitCredentialSelection, which refuses a configuration outside
// the offer for every transport, stays the backstop.
func TestWMPBridge_SelectionOutsideTheOfferOverTheRealEngine(t *testing.T) {
	e := entitlementEnv(t, "fail")
	selected := make(chan string, 1)
	registerScripted(e.m, ProtocolOID4VCI, func(ctx context.Context, f *Flow, _ *FlowStartMessage) error {
		h := realEntitlementHandler(e, f)
		offer := &CredentialOffer{CredentialIssuer: entitlementTestIssuer, CredentialConfigurationIDs: []string{"pid", "mdl"}}
		id, _, err := h.awaitCredentialSelection(ctx, offer, selectionMeta()) // supports "diploma" too
		if err != nil {
			return err
		}
		selected <- id
		return f.Session.SendFlowComplete(f.ID, nil, "")
	})
	tok, sid, st := startEntitlementFlow(t, e)

	prog := params(st.nextMethod(t, wmp.MethodFlowProgress))
	assert.Equal(t, openid4x.StepAwaitingOfferAcceptance, prog["step"])
	creds := prog["payload"].(map[string]any)["credentials"].([]any)
	require.Len(t, creds, 2, "only the offered configurations are listed, not the issuer's third")

	// index 2 would be "diploma" if the bridge listed everything the issuer supports.
	r := e.post(tok, sid, flowAction(sid, "f1", "accept_offer", map[string]any{"selected_indices": []int{2}, "consent": true}))
	assert.Equal(t, wmp.ErrInvalidParams, r.code())
	select {
	case id := <-selected:
		t.Fatalf("a selection outside the offer reached the engine: %s", id)
	case <-time.After(200 * time.Millisecond):
	}

	r = e.post(tok, sid, flowAction(sid, "f1", "accept_offer", map[string]any{"selected_indices": []int{1}, "consent": true}))
	assert.Equal(t, 0, r.code(), "%v", r.Body)
	assert.Equal(t, "mdl", <-selected)
}
