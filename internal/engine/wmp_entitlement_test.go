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

// The payload is go-wmp's typed one, bounded by go-wmp whatever the engine sent:
// at most 16 findings (and the truncation flag), a message or credential_type
// that is too long or has control characters is left out, a finding whose code
// is not of the defined form is dropped, and the registration certificate's own
// content (entitlements, subject) and members the profile does not define never
// travel.
func TestWMPEntitlement_PayloadIsBounded(t *testing.T) {
	var findings []any
	for i := 0; i < 40; i++ {
		findings = append(findings, map[string]any{
			"code": "no_registration_certificate", "message": strings.Repeat("m", 1000), "credential_type": strings.Repeat("t", 1000),
			"issuer_text": "free text of the issuer"})
	}
	findings = append([]any{map[string]any{"code": strings.Repeat("c", 200), "message": "bad code"}}, findings...)
	raw, _ := json.Marshal(map[string]any{
		"issuer_entitlement_evaluated": true, "issuer": "https://issuer.example", "registration_certificate": "SECRET-RC", "subject": "S",
		"issuer_entitlement": map[string]any{"allowed": false, "mode": "fail", "evaluated": false, "findings": findings,
			"entitlements": []string{"E"}, "subject": "S2"},
	})
	s, ok := tr(t, openid4x.FlowTypeOID4VCI, StepTrustEvaluated, string(raw))
	require.True(t, ok)
	b, _ := json.Marshal(s.Payload)
	assert.Less(t, len(b), 12<<10, "bounded whatever the engine sent")
	for _, leaked := range []string{"SECRET-RC", "free text of the issuer", "entitlements", "bad code", "S2", `"subject"`} {
		assert.NotContains(t, string(b), leaked)
	}
	m := asMap(t, s.Payload)
	assert.NotContains(t, m, "trust_info")
	ent := m["issuer_entitlement"].(map[string]interface{})
	require.Len(t, ent["findings"], openid4x.MaxEntitlementFindings)
	assert.Equal(t, true, ent["findings_truncated"])
	f0 := ent["findings"].([]interface{})[0].(map[string]interface{})
	assert.Equal(t, map[string]interface{}{"code": "no_registration_certificate"}, f0, "an over-long message and credential_type are left out")
	// go-wmp's own validation accepts what was relayed.
	_, isEnt, err := openid4x.ParseIssuerEntitlementPayload(b)
	require.NoError(t, err)
	assert.True(t, isEnt)
}

// A findings progress go-wmp refuses (an issuer that is too long or missing, a
// mode that is neither warn nor fail, a decision that is not an object) is not
// relayed at all: not as the findings, and not as a trust decision.
func TestWMPEntitlement_RefusedFindingsProgressIsNotRelayed(t *testing.T) {
	ok := func(issuer, mode string) string {
		return `{"issuer_entitlement_evaluated":true,"issuer":"` + issuer + `","issuer_entitlement":{"allowed":true,"mode":"` + mode + `","evaluated":true}}`
	}
	for name, payload := range map[string]string{
		"issuer too long":   ok(strings.Repeat("i", 5000), "warn"),
		"no issuer":         ok("", "warn"),
		"unknown mode":      ok("https://i", "off"),
		"decision a string": `{"issuer_entitlement_evaluated":true,"issuer":"https://i","issuer_entitlement":"allowed"}`,
		"decision missing":  `{"issuer_entitlement_evaluated":true,"issuer":"https://i"}`,
	} {
		t.Run(name, func(t *testing.T) {
			_, relayed := tr(t, openid4x.FlowTypeOID4VCI, StepTrustEvaluated, payload)
			assert.False(t, relayed)
		})
	}
	_, relayed := tr(t, openid4x.FlowTypeOID4VCI, StepTrustEvaluated, ok("https://i", "warn"))
	assert.True(t, relayed, "the well-formed one is")
}

// UNTRUSTED_ISSUER ends the flow -31006 with go-wmp's closed data; the engine
// attaches nothing to it, and nothing the engine did attach is relayed.
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
	assert.Equal(t, map[string]any{"reason": "untrusted_issuer", "retryable": false}, data)
	d, isRefusal, err := openid4x.ParseUntrustedIssuerData(mustJSON(t, data))
	require.NoError(t, err)
	assert.True(t, isRefusal)
	assert.Equal(t, openid4x.NewUntrustedIssuerData(), d)
}

func mustJSON(t *testing.T, v any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	return b
}

// The verifier's refusal keeps its reason next to the engine's details, and the
// reason wins over a member of the same name.
func TestWMPEntitlement_UntrustedRefusalData(t *testing.T) {
	assert.Equal(t, openid4x.NewUntrustedIssuerData(), untrustedRefusalData(ErrCodeUntrustedIssuer, map[string]interface{}{"x": 1}))
	assert.Equal(t, map[string]interface{}{"reason": "untrusted_verifier", "other": 1},
		untrustedRefusalData(ErrCodeUntrustedVerifier, map[string]interface{}{"reason": "from-the-engine", "other": 1}))
	assert.Nil(t, untrustedRefusalData(ErrCodeSignError, nil))
	assert.Nil(t, untrustedRefusalData(errCodeIssuerNotEntitled, nil), "-31020 has its own data")
}

// ISSUER_NOT_ENTITLED is told apart from UNTRUSTED_ISSUER; its details
// ({issuer, issuer_entitlement}, #522) are go-wmp's typed -31020 data, bounded,
// and nothing else is relayed. Never both: no reason on it.
func TestWMPBridge_IssuerNotEntitledRefusal(t *testing.T) {
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
	assert.EqualValues(t, wmp.ErrIssuerNotEntitled, params(ev)["code"])
	assert.EqualValues(t, -31020, params(ev)["code"])
	assert.Equal(t, openid4x.IssuerNotEntitledMessage, params(ev)["message"])
	data := params(ev)["data"].(map[string]any)
	assert.NotContains(t, data, "reason", "an entitlement refusal is not an untrusted_issuer one")
	assert.Equal(t, "https://issuer.example", data["issuer"])
	ent := data["issuer_entitlement"].(map[string]any)
	assert.Equal(t, false, ent["allowed"])
	assert.Len(t, ent["findings"], openid4x.MaxEntitlementFindings)
	assert.Equal(t, true, ent["findings_truncated"])
	assert.NotContains(t, ev.Raw, "free")
	assert.NotContains(t, ev.Raw, "dropped")
	// go-wmp accepts it as a -31020.
	_, err := openid4x.ParseIssuerNotEntitledData(mustJSON(t, data))
	require.NoError(t, err)
}

// An ISSUER_NOT_ENTITLED go-wmp does not accept as a refusal (no issuer, a
// decision that is allowed, not in fail mode or without a finding) is not made
// into one: the flow ends with a plain flow error with no data.
func TestWMPBridge_IssuerNotEntitledWithoutUsableDecision(t *testing.T) {
	finding := []any{map[string]any{"code": "no_registration_certificate"}}
	for name, details := range map[string]map[string]interface{}{
		"no decision": {"issuer": "https://i"},
		"no issuer":   {"issuer_entitlement": map[string]any{"allowed": false, "mode": "fail", "evaluated": true, "findings": finding}},
		"allowed":     {"issuer": "https://i", "issuer_entitlement": map[string]any{"allowed": true, "mode": "fail", "evaluated": true, "findings": finding}},
		"warn mode":   {"issuer": "https://i", "issuer_entitlement": map[string]any{"allowed": false, "mode": "warn", "evaluated": true, "findings": finding}},
		"no findings": {"issuer": "https://i", "issuer_entitlement": map[string]any{"allowed": false, "mode": "fail", "evaluated": true}},
	} {
		t.Run(name, func(t *testing.T) {
			assert.Nil(t, notEntitledData(details))
			e := newWMPEnv(t)
			registerScripted(e.m, ProtocolOID4VCI, func(_ context.Context, f *Flow, _ *FlowStartMessage) error {
				return f.Session.SendFlowError(f.ID, StepEvaluatingTrust, errCodeIssuerNotEntitled, "x", details)
			})
			tok := e.token("alice", "t1", "ir", "j1")
			sid := e.create(tok, "oid4vci")
			st, _ := e.openStream(tok, sid, "")
			require.Equal(t, 0, e.post(tok, sid, startVCI(sid, "f1")).code())
			ev := st.nextMethod(t, wmp.MethodFlowError)
			assert.EqualValues(t, wmp.ErrFlowError, params(ev)["code"])
			assert.NotContains(t, params(ev), "data")
		})
	}
}

// An engine error code the bridge does not know is a flow error (-31006), never
// an internal error.
func TestWMPBridge_UnknownEngineErrorCodeIsAFlowError(t *testing.T) {
	assert.Equal(t, wmp.ErrFlowError, mapErrorCode("SOME_FUTURE_CODE"))
	assert.Equal(t, -31020, mapErrorCode(errCodeIssuerNotEntitled))
	assert.Equal(t, wmp.ErrFlowError, mapErrorCode(ErrCodeUntrustedIssuer))
	assert.Equal(t, wmp.ErrIssuerNotEntitled, mapErrorCode(errCodeIssuerNotEntitled))
}

// The engine puts a typed decision (a struct) in the error's details: it is
// normalised through its JSON form, not dropped.
func TestWMPEntitlement_TypedDecisionInDetails(t *testing.T) {
	type finding struct {
		Code           string `json:"code"`
		Message        string `json:"message"`
		CredentialType string `json:"credential_type,omitempty"`
	}
	type decision struct {
		Allowed      bool      `json:"allowed"`
		Mode         string    `json:"mode"`
		Evaluated    bool      `json:"evaluated"`
		Findings     []finding `json:"findings"`
		Entitlements []string  `json:"entitlements,omitempty"`
		Subject      string    `json:"subject,omitempty"`
	}
	d := notEntitledData(map[string]interface{}{
		"issuer": "https://i",
		"issuer_entitlement": &decision{Allowed: false, Mode: "fail", Evaluated: true, Entitlements: []string{"E"}, Subject: "S",
			Findings: []finding{{Code: "no_registration_certificate", Message: "fixed", CredentialType: "t"}}},
	})
	require.NotNil(t, d)
	assert.Equal(t, "https://i", d.Issuer)
	assert.False(t, d.IssuerEntitlement.Allowed)
	assert.Equal(t, "fail", d.IssuerEntitlement.Mode)
	assert.True(t, d.IssuerEntitlement.Evaluated)
	assert.Equal(t, []openid4x.EntitlementFinding{{Code: "no_registration_certificate", Message: "fixed", CredentialType: "t"}}, d.IssuerEntitlement.Findings)
	assert.Empty(t, d.IssuerEntitlement.Entitlements, "the certificate's own content is display-only and issuer-controlled")
}
