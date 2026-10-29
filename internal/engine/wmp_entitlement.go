package engine

// The issuer-entitlement outcomes (go-wallet-backend#522, ARF 6.6.2.3) as a WMP
// client receives them. The engine core enforces; this file only maps its two
// outcomes, and bounds what is relayed whatever the core sent:
//
//   - a refusal is the flow error UNTRUSTED_ISSUER, which WMP carries as
//     -31006 (Flow error) with data {"reason": "untrusted_issuer"}: Core 3.8
//     has no code for a trust refusal, so the reason is the additive member
//     the client keys on, as it is for "rejected" (Core 6.2);
//   - the findings are a trust_evaluated progress whose payload has
//     issuer_entitlement_evaluated: true. It carries no trust_info and is not a
//     trust decision (the issuer's own trust_evaluated is the one with
//     trust_info).

import (
	"encoding/json"
	"unicode/utf8"
)

// Bounds on what the bridge relays of the findings, whatever the engine sent.
const (
	maxEntitlementFindings   = 16
	maxEntitlementCodeLen    = 64
	maxEntitlementMessageLen = 256
	maxEntitlementTypeLen    = 128
	maxEntitlementIssuerLen  = 2048
	maxEntitlementModeLen    = 16
)

// The reasons of the -31006 data of a trust refusal.
const (
	reasonUntrustedIssuer   = "untrusted_issuer"
	reasonUntrustedVerifier = "untrusted_verifier"
)

// codeIssuerNotEntitled and issuerNotEntitledMessage are the WMP error of an
// entitlement refusal (wmp spec #36/#37, go-wmp wmp.ErrIssuerNotEntitled and
// openid4x.IssuerNotEntitledMessage, on go-wmp main, not in a release: v0.12.1 is
// the latest). TODO: use go-wmp's constants and NewIssuerNotEntitledData once
// v0.13.0 is tagged.
const (
	codeIssuerNotEntitled    = -31020
	issuerNotEntitledMessage = "Issuer not entitled"
)

// errCodeIssuerNotEntitled is the engine's refusal of an issuer entitlement
// check in fail mode (go-wallet-backend#522); UNTRUSTED_ISSUER stays the trust
// decision's. Declared here until #522's constant is on main.
const errCodeIssuerNotEntitled ErrorCode = "ISSUER_NOT_ENTITLED"

// trustRefusalReason is the data.reason of a flow error that is a trust
// refusal, or "" for any other error.
func trustRefusalReason(code ErrorCode) string {
	switch code {
	case ErrCodeUntrustedIssuer:
		return reasonUntrustedIssuer
	case ErrCodeUntrustedVerifier:
		return reasonUntrustedVerifier
	}
	return ""
}

// entitlementPayload is the bounded trust_evaluated payload of the findings, and
// whether m is one (it names issuer_entitlement_evaluated). Only the members
// the engine defines are relayed, strings are length-bounded and at most
// maxEntitlementFindings findings are kept; no free text of the issuer travels
// (the message of a finding is fixed text per code, credential_type is bounded).
func entitlementPayload(m map[string]interface{}) (map[string]interface{}, bool) {
	if evaluated, _ := m["issuer_entitlement_evaluated"].(bool); !evaluated {
		return nil, false
	}
	out := map[string]interface{}{"issuer_entitlement_evaluated": true}
	if s, ok := boundedString(m["issuer"], maxEntitlementIssuerLen); ok {
		out["issuer"] = s
	}
	out["issuer_entitlement"] = boundedDecision(m["issuer_entitlement"])
	return out, true
}

// asJSONObject is v as a decoded JSON object: the engine puts typed values (a
// struct decision) in an error's details, which only their JSON form describes.
func asJSONObject(v interface{}) map[string]interface{} {
	if m, ok := v.(map[string]interface{}); ok {
		return m
	}
	b, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	var m map[string]interface{}
	if json.Unmarshal(b, &m) != nil {
		return nil
	}
	return m
}

// boundedDecision is the bounded form of the engine's entitlement decision
// {allowed, mode, evaluated, findings, findings_truncated}.
func boundedDecision(v interface{}) map[string]interface{} {
	raw := asJSONObject(v)
	ent := map[string]interface{}{}
	for _, k := range []string{"allowed", "evaluated"} {
		if b, ok := raw[k].(bool); ok {
			ent[k] = b
		}
	}
	if s, ok := boundedString(raw["mode"], maxEntitlementModeLen); ok {
		ent["mode"] = s
	}
	findings, truncated := boundedFindings(raw["findings"])
	ent["findings"] = findings
	if t, _ := raw["findings_truncated"].(bool); t || truncated {
		ent["findings_truncated"] = true
	}
	return ent
}

func boundedFindings(v interface{}) ([]map[string]interface{}, bool) {
	in, _ := v.([]interface{})
	out := make([]map[string]interface{}, 0, len(in))
	truncated := false
	for _, e := range in {
		if len(out) == maxEntitlementFindings {
			truncated = true
			break
		}
		f, ok := e.(map[string]interface{})
		if !ok {
			continue
		}
		code, ok := boundedString(f["code"], maxEntitlementCodeLen)
		if !ok {
			continue
		}
		finding := map[string]interface{}{"code": code}
		if s, ok := boundedString(f["message"], maxEntitlementMessageLen); ok {
			finding["message"] = s
		}
		if s, ok := boundedString(f["credential_type"], maxEntitlementTypeLen); ok {
			finding["credential_type"] = s
		}
		out = append(out, finding)
	}
	return out, truncated
}

// boundedString is v as a string of at most max bytes (cut at a rune boundary).
func boundedString(v interface{}, max int) (string, bool) {
	s, ok := v.(string)
	if !ok {
		return "", false
	}
	if len(s) > max {
		s = s[:max]
		for len(s) > 0 && !utf8.ValidString(s) {
			s = s[:len(s)-1]
		}
	}
	return s, true
}

// boundedErrorDetails is the data of a trust refusal: the engine's details, and
// for ISSUER_NOT_ENTITLED ({issuer, issuer_entitlement}, #522) only those two,
// bounded like the findings progress.
func boundedErrorDetails(code ErrorCode, details map[string]interface{}) map[string]interface{} {
	if code == errCodeIssuerNotEntitled {
		out := map[string]interface{}{}
		if s, ok := boundedString(details["issuer"], maxEntitlementIssuerLen); ok {
			out["issuer"] = s
		}
		if d, ok := details["issuer_entitlement"]; ok {
			out["issuer_entitlement"] = boundedDecision(d)
		}
		return out
	}
	out := make(map[string]interface{}, len(details))
	for k, v := range details {
		out[k] = v
	}
	return out
}

// entitlementRaw decodes a trust_evaluated payload for entitlementPayload.
func entitlementRaw(payload json.RawMessage) (map[string]interface{}, bool) {
	return entitlementPayload(payloadObject(payload))
}
