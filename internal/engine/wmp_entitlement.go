package engine

// The issuer-entitlement outcomes (ARF 6.6.2.3, issuer_entitlement.go) as a WMP
// client receives them, as pure functions from the engine's shapes to go-wmp's
// types. Nothing here depends on a WMP session, a transport or the bridge: the
// bridge calls these where it relays an engine flow error and a trust_evaluated
// progress. The engine core enforces; this file only maps its outcomes, and
// bounds what is relayed whatever the core sent:
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

	"github.com/sirosfoundation/go-wmp/pkg/wmp"
	"github.com/sirosfoundation/go-wmp/pkg/wmp/openid4x"
)

// issuerErrorWire is the WMP code, message and data of an engine flow error that
// is about the issuer's trust or entitlement, and whether it is one (handled).
// A code it does not handle is for the caller's generic mapping, which for an
// engine code the profile does not name is -31006 (wmp.ErrFlowError).
//
//   - UNTRUSTED_ISSUER: -31006 with go-wmp's closed NewUntrustedIssuerData; the
//     engine attaches no details to it, and nothing it did attach is relayed.
//   - ISSUER_NOT_ENTITLED: -31020 "Issuer not entitled" with go-wmp's typed
//     {issuer, issuer_entitlement}, bounded. A refusal go-wmp does not accept as
//     one (no issuer, a decision that is not allowed=false, mode=fail with no
//     finding, a decision of the wrong type) is a plain -31006 with the engine's
//     message and no data, never a made-up decision.
func issuerErrorWire(code ErrorCode, message string, details map[string]interface{}) (wmpCode int, wmpMessage string, data interface{}, handled bool) {
	switch code {
	case ErrCodeUntrustedIssuer:
		return wmp.ErrFlowError, message, openid4x.NewUntrustedIssuerData(), true
	case ErrCodeIssuerNotEntitled:
		if d := notEntitledData(details); d != nil {
			return wmp.ErrIssuerNotEntitled, openid4x.IssuerNotEntitledMessage, d, true
		}
		return wmp.ErrFlowError, message, nil, true
	}
	return 0, "", nil, false
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
// findings, findings_truncated} (issuertrust.Decision.Summary) as go-wmp's
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

// entitlementProgress is the typed trust_evaluated payload of the findings, and
// whether payload is one (it names issuer_entitlement_evaluated). isFindings is
// true with a nil payload when payload names it but go-wmp refuses what it
// carries (no issuer, a mode that is neither warn nor fail): the progress is
// then to be dropped rather than relayed unvalidated or as a trust decision. A
// payload that is not a findings progress is (nil, false): the caller translates
// it as the issuer's own trust result.
func entitlementProgress(payload json.RawMessage) (p *openid4x.IssuerEntitlementPayload, isFindings bool) {
	var m map[string]interface{}
	if json.Unmarshal(payload, &m) != nil {
		return nil, false
	}
	if evaluated, _ := m["issuer_entitlement_evaluated"].(bool); !evaluated {
		return nil, false
	}
	issuer, _ := m["issuer"].(string)
	dec, valid := entitlementDecision(m["issuer_entitlement"])
	if !valid {
		return nil, true
	}
	out, err := openid4x.NewIssuerEntitlementPayload(issuer, dec)
	if err != nil {
		return nil, true
	}
	return out, true
}

// notEntitledData is the data of the -31020 refusal from the details of the
// engine's ISSUER_NOT_ENTITLED ({issuer, issuer_entitlement}). It is nil when
// go-wmp does not accept what the engine sent as a refusal (an empty issuer, a
// decision that is not allowed=false, mode=fail with a finding); the caller then
// ends the flow with a plain flow error, not a made-up decision.
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
