package engine

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/sirosfoundation/go-wmp/pkg/wmp"
	"github.com/sirosfoundation/go-wmp/pkg/wmp/openid4x"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sirosfoundation/go-wallet-backend/pkg/issuertrust"
)

// refusedDecision is a decision as the engine refuses with: fail mode, not
// allowed, with the registration certificate's own content set (which Summary
// strips, and which must never reach a WMP client).
func refusedDecision(nFindings int) *issuertrust.Decision {
	d := &issuertrust.Decision{
		Allowed: false, Mode: issuertrust.ModeFail, Evaluated: true,
		Entitlements: []string{"SECRET-ENTITLEMENT"}, Subject: "SECRET-SUBJECT",
	}
	for i := 0; i < nFindings; i++ {
		d.Findings = append(d.Findings, issuertrust.Finding{
			Code: issuertrust.CodeTypeNotRegistered, Message: "provider is not registered to issue this credential",
			CredentialType: "eu.europa.ec.eudi.pid.1"})
	}
	return d
}

// failNotEntitledDetails are the details of the engine's ISSUER_NOT_ENTITLED
// exactly as failNotEntitled builds them: the typed Summary(), not its JSON.
func failNotEntitledDetails(issuer string, d *issuertrust.Decision) map[string]interface{} {
	return map[string]interface{}{"issuer": issuer, "issuer_entitlement": d.Summary()}
}

// The codes this file maps are the engine's and go-wmp's.
func TestIssuerErrorWire_ConstantsAreTheEngineAndWMPOnes(t *testing.T) {
	assert.Equal(t, ErrorCode("ISSUER_NOT_ENTITLED"), ErrCodeIssuerNotEntitled)
	assert.Equal(t, -31020, wmp.ErrIssuerNotEntitled)
	assert.Equal(t, -31006, wmp.ErrFlowError)
}

// ISSUER_NOT_ENTITLED is -31020 with go-wmp's typed data, from the real
// engine shape: {issuer, issuer_entitlement: Decision.Summary()}.
func TestIssuerErrorWire_NotEntitledIsMinus31020WithTypedData(t *testing.T) {
	code, msg, data, handled := issuerErrorWire(ErrCodeIssuerNotEntitled, ErrCodeIssuerNotEntitled.UserFacingMessage(),
		failNotEntitledDetails("https://issuer.example", refusedDecision(2)))
	require.True(t, handled)
	assert.Equal(t, wmp.ErrIssuerNotEntitled, code)
	assert.Equal(t, openid4x.IssuerNotEntitledMessage, msg)

	raw, err := json.Marshal(data)
	require.NoError(t, err)
	var m map[string]interface{}
	require.NoError(t, json.Unmarshal(raw, &m))
	assert.NotContains(t, m, "reason", "an entitlement refusal is not an untrusted_issuer one")
	assert.Equal(t, "https://issuer.example", m["issuer"])
	ent := m["issuer_entitlement"].(map[string]interface{})
	assert.Equal(t, false, ent["allowed"])
	assert.Equal(t, "fail", ent["mode"])
	assert.Len(t, ent["findings"], 2)
	assert.NotContains(t, string(raw), "SECRET", "the registration certificate's own content is never relayed")

	// go-wmp accepts what was produced as a -31020.
	parsed, err := openid4x.ParseIssuerNotEntitledData(raw)
	require.NoError(t, err)
	assert.Equal(t, "https://issuer.example", parsed.Issuer)
}

// The decision is bounded whatever the engine sent: at most 16 findings and the
// truncation flag, over-long and non-printable text left out, a finding whose
// code is not of the defined form dropped, members the profile does not define
// never relayed, and the engine's own extra details never travel.
func TestIssuerErrorWire_NotEntitledIsBounded(t *testing.T) {
	findings := []interface{}{map[string]interface{}{"code": strings.Repeat("c", 200), "message": "bad code"}}
	for i := 0; i < 40; i++ {
		findings = append(findings, map[string]interface{}{
			"code": "no_registration_certificate", "message": strings.Repeat("m", 1000),
			"credential_type": strings.Repeat("t", 1000), "issuer_text": "free text of the issuer"})
	}
	details := map[string]interface{}{
		"issuer": "https://issuer.example", "extra": "dropped",
		"issuer_entitlement": map[string]interface{}{"allowed": false, "mode": "fail", "evaluated": true,
			"findings": findings, "entitlements": []string{"E"}, "subject": "S"},
	}
	code, _, data, handled := issuerErrorWire(ErrCodeIssuerNotEntitled, "x", details)
	require.True(t, handled)
	require.Equal(t, wmp.ErrIssuerNotEntitled, code)
	raw, _ := json.Marshal(data)
	var m map[string]interface{}
	require.NoError(t, json.Unmarshal(raw, &m))
	ent := m["issuer_entitlement"].(map[string]interface{})
	assert.Len(t, ent["findings"], openid4x.MaxEntitlementFindings)
	assert.Equal(t, true, ent["findings_truncated"])
	for _, s := range []string{"free text", "dropped", `"entitlements"`, `"subject"`, "bad code", strings.Repeat("m", 100)} {
		assert.NotContains(t, string(raw), s)
	}
}

// A refusal go-wmp does not accept as one is not made into one: -31006 with the
// engine's message and no data. Table: no decision, no issuer, an allowed
// decision, warn mode, no findings, a decision of the wrong type.
func TestIssuerErrorWire_NotEntitledWithoutUsableDecisionIsAFlowError(t *testing.T) {
	finding := []interface{}{map[string]interface{}{"code": "no_registration_certificate"}}
	for name, details := range map[string]map[string]interface{}{
		"nil details": nil,
		"no decision": {"issuer": "https://i"},
		"no issuer":   {"issuer_entitlement": map[string]interface{}{"allowed": false, "mode": "fail", "evaluated": true, "findings": finding}},
		"allowed":     {"issuer": "https://i", "issuer_entitlement": map[string]interface{}{"allowed": true, "mode": "fail", "evaluated": true, "findings": finding}},
		"warn mode":   {"issuer": "https://i", "issuer_entitlement": map[string]interface{}{"allowed": false, "mode": "warn", "evaluated": true, "findings": finding}},
		"no findings": {"issuer": "https://i", "issuer_entitlement": map[string]interface{}{"allowed": false, "mode": "fail", "evaluated": true}},
		"wrong type":  {"issuer": "https://i", "issuer_entitlement": "refused"},
	} {
		t.Run(name, func(t *testing.T) {
			assert.Nil(t, notEntitledData(details))
			code, msg, data, handled := issuerErrorWire(ErrCodeIssuerNotEntitled, "the engine's text", details)
			assert.True(t, handled, "still an entitlement code: the caller must not map it a second way")
			assert.Equal(t, wmp.ErrFlowError, code)
			assert.Equal(t, "the engine's text", msg)
			assert.Nil(t, data)
		})
	}
}

// UNTRUSTED_ISSUER stays -31006 with go-wmp's closed data; the engine's details
// are not relayed. Never both reasons.
func TestIssuerErrorWire_UntrustedIssuerStaysMinus31006(t *testing.T) {
	code, msg, data, handled := issuerErrorWire(ErrCodeUntrustedIssuer, "untrusted", map[string]interface{}{"reason": "from-the-engine", "other": 1})
	require.True(t, handled)
	assert.Equal(t, wmp.ErrFlowError, code)
	assert.Equal(t, "untrusted", msg)
	assert.Equal(t, openid4x.NewUntrustedIssuerData(), data)
	raw, _ := json.Marshal(data)
	assert.JSONEq(t, `{"reason":"untrusted_issuer","retryable":false}`, string(raw))
	assert.NotContains(t, string(raw), "from-the-engine")
}

// Any other engine code is not handled here (the caller's generic mapping
// applies, -31006 for a code the profile does not name).
func TestIssuerErrorWire_OtherCodesAreNotHandled(t *testing.T) {
	for _, c := range []ErrorCode{ErrCodeSignError, ErrCodeUntrustedVerifier, ErrCodeInternalError, "SOME_FUTURE_CODE", ""} {
		_, _, _, handled := issuerErrorWire(c, "m", map[string]interface{}{"issuer": "i"})
		assert.False(t, handled, string(c))
	}
}

// The findings progress of the engine (issuer_entitlement.go) is go-wmp's
// typed payload, without trust_info, bounded.
func TestEntitlementProgress_FindingsAreTypedAndBounded(t *testing.T) {
	d := refusedDecision(40)
	d.Allowed, d.Mode = true, issuertrust.ModeWarn
	raw, err := json.Marshal(map[string]interface{}{
		"issuer_entitlement_evaluated": true, "issuer": "https://issuer.example",
		"registration_certificate": "SECRET-RC", "issuer_entitlement": d.Summary()})
	require.NoError(t, err)

	p, isFindings := entitlementProgress(raw)
	require.True(t, isFindings)
	require.NotNil(t, p)
	out, _ := json.Marshal(p)
	var m map[string]interface{}
	require.NoError(t, json.Unmarshal(out, &m))
	assert.NotContains(t, m, "trust_info", "the findings are not a trust decision")
	assert.Equal(t, true, m["issuer_entitlement_evaluated"])
	assert.Equal(t, "https://issuer.example", m["issuer"])
	ent := m["issuer_entitlement"].(map[string]interface{})
	assert.Equal(t, "warn", ent["mode"])
	assert.Equal(t, true, ent["allowed"])
	assert.Len(t, ent["findings"], openid4x.MaxEntitlementFindings)
	assert.NotContains(t, string(out), "SECRET")
}

// A trust_evaluated that is the issuer's own trust result is not a findings
// progress; a findings progress go-wmp refuses is dropped (isFindings true, nil
// payload), never relayed unvalidated or as a trust decision.
func TestEntitlementProgress_WhatIsAndIsNotAFindingsProgress(t *testing.T) {
	p, isFindings := entitlementProgress(json.RawMessage(`{"issuer_trust_evaluated":true,"issuer":"i","trusted":true,"framework":"f"}`))
	assert.Nil(t, p)
	assert.False(t, isFindings)

	for name, raw := range map[string]string{
		"not an object":          `"x"`,
		"flag false":             `{"issuer_entitlement_evaluated":false,"issuer":"i"}`,
		"flag of the wrong type": `{"issuer_entitlement_evaluated":"yes","issuer":"i"}`,
	} {
		p, isFindings := entitlementProgress(json.RawMessage(raw))
		assert.Nil(t, p, name)
		assert.False(t, isFindings, name)
	}

	for name, raw := range map[string]string{
		"no issuer":      `{"issuer_entitlement_evaluated":true,"issuer_entitlement":{"allowed":true,"mode":"warn","evaluated":true}}`,
		"mode off":       `{"issuer_entitlement_evaluated":true,"issuer":"i","issuer_entitlement":{"allowed":true,"mode":"off","evaluated":false}}`,
		"no decision":    `{"issuer_entitlement_evaluated":true,"issuer":"i"}`,
		"decision wrong": `{"issuer_entitlement_evaluated":true,"issuer":"i","issuer_entitlement":"x"}`,
	} {
		p, isFindings := entitlementProgress(json.RawMessage(raw))
		assert.Nil(t, p, name)
		assert.True(t, isFindings, name)
	}
}

// The engine puts a typed decision (a struct) in the error's details: it is
// normalised through its JSON form, not dropped.
func TestEntitlementDecision_TypedAndMapFormsAgree(t *testing.T) {
	d := refusedDecision(1)
	typed, ok := entitlementDecision(d.Summary())
	require.True(t, ok)
	raw, _ := json.Marshal(d.Summary())
	var asMap map[string]interface{}
	require.NoError(t, json.Unmarshal(raw, &asMap))
	fromMap, ok := entitlementDecision(asMap)
	require.True(t, ok)
	assert.Equal(t, typed, fromMap)

	_, ok = entitlementDecision(nil)
	assert.False(t, ok)
	_, ok = entitlementDecision(make(chan int)) // cannot be marshalled
	assert.False(t, ok)
	_, ok = entitlementDecision(map[string]interface{}{"allowed": "yes"})
	assert.False(t, ok, "a member of the wrong type")
}
