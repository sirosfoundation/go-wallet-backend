package engine

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/sirosfoundation/go-wmp/pkg/wmp"
	"github.com/sirosfoundation/go-wmp/pkg/wmp/openid4x"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The payloads below are the shape #522 sends (its "Client contract").
const entitlementProgress = `{"issuer_entitlement_evaluated":true,"issuer":"https://issuer.example",
 "issuer_entitlement":{"allowed":true,"mode":"warn","evaluated":true,
  "findings":[{"code":"attestation_type_not_registered","message":"fixed text","credential_type":"eu.europa.ec.eudi.pid.1"}]}}`

func TestWMPEntitlement_FindingsAreATrustEvaluatedWithoutTrustInfo(t *testing.T) {
	s, ok := tr(t, openid4x.FlowTypeOID4VCI, StepTrustEvaluated, entitlementProgress)
	require.True(t, ok)
	assert.Equal(t, openid4x.StepTrustEvaluated, s.Step)
	m := asMap(t, s.Payload)
	assert.NotContains(t, m, "trust_info", "the findings are not a trust decision")
	assert.Equal(t, true, m["issuer_entitlement_evaluated"])
	ent := m["issuer_entitlement"].(map[string]interface{})
	assert.Equal(t, "warn", ent["mode"])
	assert.Equal(t, true, ent["allowed"])
	findings := ent["findings"].([]interface{})
	require.Len(t, findings, 1)
	assert.Equal(t, map[string]interface{}{"code": "attestation_type_not_registered", "message": "fixed text", "credential_type": "eu.europa.ec.eudi.pid.1"}, findings[0])

	// The issuer's own trust result keeps its trust_info.
	s, _ = tr(t, openid4x.FlowTypeOID4VCI, StepTrustEvaluated, `{"issuer_trust_evaluated":true,"issuer":"i","trusted":true,"framework":"f"}`)
	assert.Contains(t, asMap(t, s.Payload), "trust_info")
}

func TestWMPEntitlement_PayloadIsBounded(t *testing.T) {
	var findings []any
	for i := 0; i < 40; i++ {
		findings = append(findings, map[string]any{
			"code": strings.Repeat("c", 200), "message": strings.Repeat("m", 1000), "credential_type": strings.Repeat("t", 1000),
			"issuer_text": "free text of the issuer"})
	}
	raw, _ := json.Marshal(map[string]any{
		"issuer_entitlement_evaluated": true, "issuer": strings.Repeat("i", 5000), "registration_certificate": "SECRET-RC", "subject": "S",
		"issuer_entitlement": map[string]any{"allowed": false, "mode": "fail", "evaluated": false, "findings": findings, "entitlements": []string{"E"}},
	})
	s, ok := tr(t, openid4x.FlowTypeOID4VCI, StepTrustEvaluated, string(raw))
	require.True(t, ok)
	b, _ := json.Marshal(s.Payload)
	assert.Less(t, len(b), 12<<10, "bounded whatever the engine sent")
	m := asMap(t, s.Payload)
	assert.NotContains(t, string(b), "SECRET-RC")
	assert.NotContains(t, string(b), "free text of the issuer")
	assert.NotContains(t, string(b), "entitlements")
	ent := m["issuer_entitlement"].(map[string]interface{})
	assert.Len(t, ent["findings"], maxEntitlementFindings)
	assert.Equal(t, true, ent["findings_truncated"])
	f0 := ent["findings"].([]interface{})[0].(map[string]interface{})
	assert.Len(t, f0["code"], maxEntitlementCodeLen)
	assert.Len(t, f0["message"], maxEntitlementMessageLen)
	assert.Len(t, f0["credential_type"], maxEntitlementTypeLen)
	assert.Len(t, m["issuer"], maxEntitlementIssuerLen)
}

// UNTRUSTED_ISSUER ends the flow -31006 with the reason the client keys on;
// the details the engine attached stay and the reason wins over a member of the
// same name.
func TestWMPBridge_UntrustedIssuerRefusal(t *testing.T) {
	e := newWMPEnv(t)
	registerScripted(e.m, ProtocolOID4VCI, func(_ context.Context, f *Flow, _ *FlowStartMessage) error {
		return f.Session.SendFlowError(f.ID, StepEvaluatingTrust, ErrCodeUntrustedIssuer, ErrCodeUntrustedIssuer.UserFacingMessage(),
			map[string]interface{}{"reason": "from-the-engine", "other": 1})
	})
	tok := e.token("alice", "t1", "ir", "j1")
	sid := e.create(tok, "oid4vci")
	st, _ := e.openStream(tok, sid, "")
	require.Equal(t, 0, e.post(tok, sid, startVCI(sid, "f1")).code())
	ev := st.nextMethod(t, wmp.MethodFlowError)
	assert.EqualValues(t, wmp.ErrFlowError, params(ev)["code"])
	data := params(ev)["data"].(map[string]any)
	assert.Equal(t, "untrusted_issuer", data["reason"])
	assert.EqualValues(t, 1, data["other"])
}

func TestWMPEntitlement_TrustRefusalReason(t *testing.T) {
	assert.Equal(t, "untrusted_issuer", trustRefusalReason(ErrCodeUntrustedIssuer))
	assert.Equal(t, "untrusted_verifier", trustRefusalReason(ErrCodeUntrustedVerifier))
	assert.Empty(t, trustRefusalReason(ErrCodeSignError))
}

// ISSUER_NOT_ENTITLED is told apart from UNTRUSTED_ISSUER; its details
// ({issuer, issuer_entitlement}, #522) are bounded and nothing else is relayed.
func TestWMPBridge_IssuerNotEntitledRefusal(t *testing.T) {
	assert.Empty(t, trustRefusalReason(errCodeIssuerNotEntitled), "not a reason on -31006: it has its own code")
	e := newWMPEnv(t)
	var many []any
	for i := 0; i < 40; i++ {
		many = append(many, map[string]any{"code": "no_registration_certificate", "message": strings.Repeat("m", 1000), "issuer_text": "free"})
	}
	registerScripted(e.m, ProtocolOID4VCI, func(_ context.Context, f *Flow, _ *FlowStartMessage) error {
		return f.Session.SendFlowError(f.ID, StepEvaluatingTrust, errCodeIssuerNotEntitled, "Issuer is not registered to issue this credential", map[string]interface{}{
			"issuer": "https://issuer.example", "extra": "dropped",
			"issuer_entitlement": map[string]any{"allowed": false, "mode": "fail", "evaluated": true, "findings": many}})
	})
	tok := e.token("alice", "t1", "ir", "j1")
	sid := e.create(tok, "oid4vci")
	st, _ := e.openStream(tok, sid, "")
	require.Equal(t, 0, e.post(tok, sid, startVCI(sid, "f1")).code())
	ev := st.nextMethod(t, wmp.MethodFlowError)
	assert.EqualValues(t, -31020, params(ev)["code"])
	assert.Equal(t, "Issuer not entitled", params(ev)["message"])
	data := params(ev)["data"].(map[string]any)
	assert.NotContains(t, data, "reason")
	assert.Equal(t, "https://issuer.example", data["issuer"])
	ent := data["issuer_entitlement"].(map[string]any)
	assert.Equal(t, false, ent["allowed"])
	assert.Len(t, ent["findings"], maxEntitlementFindings)
	assert.Equal(t, true, ent["findings_truncated"])
	assert.NotContains(t, ev.Raw, "free")
	assert.NotContains(t, ev.Raw, "dropped")
}

// An engine error code the bridge does not know is a flow error (-31006), never
// an internal error.
func TestWMPBridge_UnknownEngineErrorCodeIsAFlowError(t *testing.T) {
	assert.Equal(t, wmp.ErrFlowError, mapErrorCode("SOME_FUTURE_CODE"))
	assert.Equal(t, -31020, mapErrorCode(errCodeIssuerNotEntitled))
	assert.Equal(t, wmp.ErrFlowError, mapErrorCode(ErrCodeUntrustedIssuer))
}
