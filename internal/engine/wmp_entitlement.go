package engine

// The issuer-entitlement outcomes (go-wallet-backend#522, ARF 6.6.2.3) as a WMP
// client receives them. The engine core enforces; this file only maps its two
// outcomes, and bounds what is relayed whatever the core sent:
//
//   - a refusal of the trust decision is the flow error UNTRUSTED_ISSUER,
//     which WMP carries as -31006 (Flow error) with
//     openid4x.NewUntrustedIssuerData() ({"reason": "untrusted_issuer",
//     "retryable": false}); a refusal that rests on entitlement findings is
//     ISSUER_NOT_ENTITLED, -31020 (wmp.ErrIssuerNotEntitled) with
//     openid4x.NewIssuerNotEntitledData(). Never both for one flow;
//   - the findings are a trust_evaluated progress whose payload has
//     issuer_entitlement_evaluated: true. It carries no trust_info and is not a
//     trust decision (the issuer's own trust_evaluated is the one with
//     trust_info).

import (
	"encoding/json"

	"github.com/sirosfoundation/go-wmp/pkg/wmp/openid4x"
)

// The reason of the -31006 data of a verifier trust refusal (the issuer's is
// openid4x.ReasonUntrustedIssuer).
const reasonUntrustedVerifier = "untrusted_verifier"

// errCodeIssuerNotEntitled is the engine's refusal of an issuer entitlement
// check in fail mode (go-wallet-backend#522, messages.go: ErrCodeIssuerNotEntitled,
// the same string). Declared here until #522 is on main; remove it then.
const errCodeIssuerNotEntitled ErrorCode = "ISSUER_NOT_ENTITLED"

// untrustedRefusalData is the data of a trust-decision refusal (-31006), or nil
// for any other error. The issuer's is go-wmp's closed shape (the engine
// attaches no details to the refusal); the verifier's keeps its reason next to
// the engine's details, the reason winning over a member of the same name.
func untrustedRefusalData(code ErrorCode, details map[string]interface{}) interface{} {
	switch code {
	case ErrCodeUntrustedIssuer:
		return openid4x.NewUntrustedIssuerData()
	case ErrCodeUntrustedVerifier:
		out := make(map[string]interface{}, len(details)+1)
		for k, v := range details {
			out[k] = v
		}
		out["reason"] = reasonUntrustedVerifier
		return out
	}
	return nil
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

// entitlementDecision is the engine's decision {allowed, mode, evaluated,
// findings, findings_truncated} (#522 issuertrust.Decision.Summary) as go-wmp's
// type, bounded by go-wmp (findings, lengths, characters, finding codes of the
// defined form) whatever the engine sent. The registration certificate's own
// content (entitlements, subject) is issuer-controlled and display-only: not
// relayed. A decision that is not an object, or a member of the wrong type,
// yields false.
func entitlementDecision(v interface{}) (openid4x.IssuerEntitlement, bool) {
	raw := asJSONObject(v)
	if raw == nil {
		return openid4x.IssuerEntitlement{}, false
	}
	delete(raw, "entitlements")
	b, err := json.Marshal(raw)
	if err != nil {
		return openid4x.IssuerEntitlement{}, false
	}
	var e openid4x.IssuerEntitlement
	if json.Unmarshal(b, &e) != nil {
		return openid4x.IssuerEntitlement{}, false
	}
	return e.Bounded(), true
}

// entitlementPayload is the typed trust_evaluated payload of the findings, and
// whether m is one (it names issuer_entitlement_evaluated). ok is true with a
// nil payload when m names it but go-wmp refuses what it carries (no issuer, a
// mode that is neither warn nor fail): the progress is then dropped rather
// than relayed unvalidated or as a trust decision.
func entitlementPayload(m map[string]interface{}) (payload *openid4x.IssuerEntitlementPayload, ok bool) {
	if evaluated, _ := m["issuer_entitlement_evaluated"].(bool); !evaluated {
		return nil, false
	}
	issuer, _ := m["issuer"].(string)
	dec, valid := entitlementDecision(m["issuer_entitlement"])
	if !valid {
		return nil, true
	}
	p, err := openid4x.NewIssuerEntitlementPayload(issuer, dec)
	if err != nil {
		return nil, true
	}
	return p, true
}

// notEntitledData is the data of the -31020 refusal from the details of the
// engine's ISSUER_NOT_ENTITLED ({issuer, issuer_entitlement}, #522). It is nil
// when go-wmp does not accept what the engine sent as a refusal (an empty
// issuer, a decision that is not allowed=false, mode=fail with a finding); the
// caller then ends the flow with a plain flow error, not a made-up decision.
func notEntitledData(details map[string]interface{}) *openid4x.IssuerNotEntitledData {
	issuer, _ := details["issuer"].(string)
	dec, ok := entitlementDecision(details["issuer_entitlement"])
	if !ok {
		return nil
	}
	d, err := openid4x.NewIssuerNotEntitledData(issuer, dec)
	if err != nil {
		return nil
	}
	return d
}

// entitlementRaw decodes a trust_evaluated payload for entitlementPayload. A
// nil payload with ok true is a findings progress the bridge does not relay.
func entitlementRaw(payload json.RawMessage) (*openid4x.IssuerEntitlementPayload, bool) {
	return entitlementPayload(payloadObject(payload))
}
