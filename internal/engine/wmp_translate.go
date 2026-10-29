package engine

// Step and action translation at the WMP bridge. The engine keeps its own names
// and payload shapes (the WebSocket protocol is unchanged); what reaches a WMP
// client are the steps of OpenID4x 3.1.2 and 3.2.2, and what a WMP client sends
// are the actions of 3.1.3 and 3.2.3, translated here to the engine's. Members
// the profile does not define travel as additive members (Core 9.5), and the
// ones that are secrets of the engine's own (the pre-authorized code) do not
// travel at all. The table of every change is in docs/wmp-migration-analysis.md.

import (
	"encoding/json"
	"fmt"
	"unicode/utf8"

	"github.com/sirosfoundation/go-wmp/pkg/wmp"
	"github.com/sirosfoundation/go-wmp/pkg/wmp/openid4x"
)

// maxNotificationEndpointLen is the bound of notification_endpoint in a completion
// (OpenID4x 3.1.4), in characters.
const maxNotificationEndpointLen = 2048

// wmpStep is one progress message as a WMP client receives it.
type wmpStep struct {
	Step    string
	Payload interface{} // nil: no payload
}

// translateProgress maps an engine progress message of a flow of flowType to
// the WMP step, and reports false for a step the profile has no counterpart for
// (it is not sent). f is the flow the message belongs to: translating a step
// may record what a later action refers to (the configurations of an offer).
func translateProgress(f *wmpFlow, flowType string, step FlowStep, payload json.RawMessage) (wmpStep, bool) {
	switch flowType {
	case openid4x.FlowTypeOID4VCI:
		return translateVCIProgress(f, step, payload)
	case openid4x.FlowTypeOID4VP:
		return translateVPProgress(step, payload)
	}
	return wmpStep{}, false
}

func translateVCIProgress(f *wmpFlow, step FlowStep, payload json.RawMessage) (wmpStep, bool) {
	switch step {
	case StepParsingOffer:
		return wmpStep{Step: openid4x.StepParsingOffer}, true
	case StepOfferParsed:
		// The parsed offer is the payload of parsing_offer (3.1.2).
		return wmpStep{Step: openid4x.StepParsingOffer, Payload: map[string]interface{}{"offer": withoutPreAuthorizedCode(payloadObject(payload))}}, true
	case StepFetchingMetadata:
		return wmpStep{Step: openid4x.StepResolvingMetadata}, true
	case StepMetadataFetched:
		m := payloadObject(payload)
		f.rememberIssuer(m)
		return wmpStep{Step: openid4x.StepMetadataFetched, Payload: map[string]interface{}{"issuer_metadata": m}}, true
	case StepEvaluatingTrust:
		return wmpStep{Step: openid4x.StepEvaluatingTrust, Payload: evaluatingTrustPayload(payload)}, true
	case StepTrustEvaluated:
		out, ok := trustEvaluatedPayload(payload)
		return wmpStep{Step: openid4x.StepTrustEvaluated, Payload: out}, ok
	case StepAwaitingSelection:
		return wmpStep{Step: openid4x.StepAwaitingOfferAcceptance, Payload: f.offerAcceptancePayload(payload)}, true
	case StepAuthorizationReq:
		return authorizationStep(payload), true
	case StepRequestingCredential:
		return wmpStep{Step: openid4x.StepRequestingCredential}, true
	case StepDeferred:
		return wmpStep{Step: openid4x.StepRequestingCredential, Payload: deferredPayload(payload)}, true
	}
	// exchanging_token and token_obtained are the engine's own bookkeeping
	// around the token endpoint: the profile has no step for them.
	return wmpStep{}, false
}

func translateVPProgress(step FlowStep, payload json.RawMessage) (wmpStep, bool) {
	switch step {
	case StepParsingRequest:
		return wmpStep{Step: openid4x.StepParsingRequest}, true
	case StepEvaluatingVerifierTrust:
		return wmpStep{Step: openid4x.StepVPEvaluatingTrust, Payload: evaluatingTrustPayload(payload)}, true
	case StepTrustEvaluated:
		out, ok := trustEvaluatedPayload(payload)
		return wmpStep{Step: openid4x.StepVPTrustEvaluated, Payload: out}, ok
	case StepCredentialSelection:
		return wmpStep{Step: openid4x.StepAwaitingConsent, Payload: awaitingConsentPayload(payload)}, true
	}
	// submitting_response follows the signing the profile reports as
	// generating_presentation (see relaySign); nothing else is emitted.
	return wmpStep{}, false
}

// payloadObject decodes a payload object; anything else is the empty object.
func payloadObject(payload json.RawMessage) map[string]interface{} {
	m := map[string]interface{}{}
	if len(payload) > 0 {
		var decoded map[string]interface{}
		if json.Unmarshal(payload, &decoded) == nil && decoded != nil {
			m = decoded
		}
	}
	return m
}

// evaluatingTrustPayload is the payload of an evaluating_trust step: none (3.1.2
// and 3.2.2 define none), except when the engine asks the client to evaluate
// trust itself, where the request travels unchanged.
func evaluatingTrustPayload(payload json.RawMessage) interface{} {
	m := payloadObject(payload)
	if _, ok := m["trust_evaluation_required"]; ok {
		return m
	}
	return nil
}

// trustEvaluatedMembers are the members of the engine's trust result that make
// up the profile's trust_info.
var trustEvaluatedMembers = []string{"trusted", "framework", "reason", "certificates"}

// trustEvaluatedPayload is the payload of trust_evaluated: trust_info (3.1.2,
// 3.2.2) next to the engine's own members, which stay (Section 7.4 reads
// verifier_trust_evaluated and context from them). ok is false for a findings
// progress go-wmp refuses (see entitlementPayload): it is not relayed.
func trustEvaluatedPayload(payload json.RawMessage) (out interface{}, ok bool) {
	if ent, isFindings := entitlementRaw(payload); isFindings {
		if ent == nil {
			return nil, false
		}
		return ent, true // the findings of the issuer-entitlement check, not a trust decision
	}
	m := payloadObject(payload)
	info := map[string]interface{}{}
	for _, k := range trustEvaluatedMembers {
		if v, ok := m[k]; ok {
			info[k] = v
		}
	}
	m["trust_info"] = info
	return m, true
}

// awaitingConsentPayload is the payload of awaiting_consent (3.2.2). The engine
// does not match credentials, so matched_credentials and requested_claims are
// omitted (3.3.3); the request travels as dcql_query, verifier_info (the
// profile's name for the verifier's metadata), client_metadata and
// verified_request (7.1, 7.5).
func awaitingConsentPayload(payload json.RawMessage) interface{} {
	m := payloadObject(payload)
	out := map[string]interface{}{}
	for _, k := range []string{"dcql_query", "client_metadata", "verified_request"} {
		if v, ok := m[k]; ok {
			out[k] = v
		}
	}
	if v, ok := m["verifier"]; ok {
		out["verifier_info"] = v
	}
	return out
}

// authorizationStep splits the engine's authorization_required, which carries
// both a transaction code request and the authorization URL, into the
// profile's awaiting_tx_code and authorization_pending.
func authorizationStep(payload json.RawMessage) wmpStep {
	m := payloadObject(payload)
	if t, _ := m["type"].(string); t == "tx_code" {
		out := map[string]interface{}{}
		if d, ok := m["message"].(string); ok && d != "" {
			out["tx_code_description"] = d
		}
		// The issuer's tx_code object (input_mode, length, description) is
		// additive. The pre-authorized code is the engine's, the client has no
		// use for it, and it is not relayed.
		if tc, ok := m["tx_code"].(map[string]interface{}); ok {
			spec := map[string]interface{}{}
			for _, k := range []string{"input_mode", "length", "description"} {
				if v, ok := tc[k]; ok {
					spec[k] = v
				}
			}
			out["tx_code"] = spec
		}
		return wmpStep{Step: openid4x.StepAwaitingTxCode, Payload: out}
	}
	// authorization_url is the profile's; expected_redirect_uri, state,
	// code_verifier and credential_offer are additive members the client needs
	// to complete the authorization (the engine checks the state it gets back).
	if offer, ok := m["credential_offer"]; ok {
		m["credential_offer"] = withoutPreAuthorizedCode(offer)
	}
	return wmpStep{Step: openid4x.StepAuthorizationPending, Payload: m}
}

// preAuthorizedCodeMember is the member of the pre-authorized_code grant that
// carries the code. The code is the engine's to redeem: it must not reach a
// client or the replay log.
const preAuthorizedCodeMember = "pre-authorized_code"

// withoutPreAuthorizedCode returns v (a decoded JSON value) with every
// pre-authorized_code member removed at any depth.
func withoutPreAuthorizedCode(v interface{}) interface{} {
	switch t := v.(type) {
	case map[string]interface{}:
		out := make(map[string]interface{}, len(t))
		for k, e := range t {
			if k == preAuthorizedCodeMember {
				continue
			}
			out[k] = withoutPreAuthorizedCode(e)
		}
		return out
	case []interface{}:
		out := make([]interface{}, len(t))
		for i, e := range t {
			out[i] = withoutPreAuthorizedCode(e)
		}
		return out
	}
	return v
}

// deferredPayload is the payload a deferred issuance's progress carries: the
// transaction id stays with the engine, which polls.
func deferredPayload(payload json.RawMessage) interface{} {
	m := payloadObject(payload)
	out := map[string]interface{}{"deferred": true}
	for _, k := range []string{"interval", "attempt", "max_attempts"} {
		if v, ok := m[k]; ok {
			out[k] = v
		}
	}
	return out
}

// offerAcceptancePayload is the payload of awaiting_offer_acceptance (3.1.2):
// the credentials the offer lists as {index, format, vct, display}, in the
// order the client's accept_offer refers to by selected_indices. The
// configuration ids are the engine's: they are recorded here, per flow, and
// never sent.
func (f *wmpFlow) offerAcceptancePayload(payload json.RawMessage) interface{} {
	var in struct {
		Available []struct {
			ID      string                 `json:"id"`
			Format  string                 `json:"format"`
			VCT     string                 `json:"vct"`
			Display map[string]interface{} `json:"display"`
		} `json:"available_credentials"`
	}
	_ = json.Unmarshal(payload, &in)
	ids := make([]string, 0, len(in.Available))
	creds := make([]map[string]interface{}, 0, len(in.Available))
	for i, a := range in.Available {
		ids = append(ids, a.ID)
		c := map[string]interface{}{"index": i, "format": a.Format}
		if a.VCT != "" {
			c["vct"] = a.VCT
		}
		if len(a.Display) > 0 {
			c["display"] = a.Display
		}
		creds = append(creds, c)
	}
	f.mu.Lock()
	f.offerIDs = ids
	issuer := f.issuer
	f.mu.Unlock()
	out := map[string]interface{}{"credentials": creds}
	if issuer != nil {
		out["issuer_metadata"] = issuer
	}
	return out
}

// rememberIssuer records the issuer of the flow (metadata_fetched) for the
// issuer_metadata of awaiting_offer_acceptance.
func (f *wmpFlow) rememberIssuer(m map[string]interface{}) {
	issuer := map[string]interface{}{}
	if v, ok := m["credential_issuer"]; ok {
		issuer["issuer"] = v
	}
	if v, ok := m["display"]; ok {
		issuer["display"] = v
	}
	f.mu.Lock()
	f.issuer = issuer
	f.mu.Unlock()
}

// signStep is the step a sign sub-flow starts: generating_proof for the
// issuance's key proof, generating_presentation for the presentation. The
// other sign actions have no step.
func signStep(action SignAction) (string, bool) {
	switch action {
	case SignActionGenerateProof:
		return openid4x.StepGeneratingProof, true
	case SignActionSignPresentation:
		return openid4x.StepGeneratingPresentation, true
	}
	return "", false
}

// --- actions -----------------------------------------------------------------

// actionOutcome is what a translated client action asks the bridge to do.
type actionOutcome struct {
	// Msg is handed to the engine flow; nil when the action ends the flow here.
	Msg *FlowActionMessage
	// Cancel ends the flow (the engine's issuance flow has no decline).
	Cancel bool
}

// errInvalidParams is the -32602 answer of a refused action; reason is a fixed
// word, never a member of the params.
func errInvalidParams(reason string) error {
	return wmp.NewRPCError(wmp.ErrInvalidParams, map[string]string{"reason": reason})
}

// translateAction maps the wmp.flow.action of a flow of flowType to the
// engine's. Only the actions of the profile are accepted (go-wmp's
// ValidateAction also lets the engine's own names through, which a WMP client
// must not send), plus trust_result, the engine's request for the client to
// evaluate trust, which the profile has no action for.
func translateAction(f *wmpFlow, flowType string, params *wmp.FlowActionParams) (*actionOutcome, error) {
	var out *actionOutcome
	var err error
	handled := false
	switch flowType {
	case openid4x.FlowTypeOID4VCI:
		out, err, handled = translateVCIAction(f, params)
	case openid4x.FlowTypeOID4VP:
		out, err, handled = translateVPAction(params)
	}
	if handled {
		return out, err
	}
	if params.Action == ActionTrustResult {
		return &actionOutcome{Msg: &FlowActionMessage{
			Message: Message{Type: TypeFlowAction, FlowID: params.FlowID}, Action: ActionTrustResult, Payload: params.Params,
		}}, nil
	}
	return nil, errInvalidParams("unknown action for flow type")
}

// actionMessage is the engine action msg of a flow with a JSON payload.
func actionMessage(params *wmp.FlowActionParams, action string, payload interface{}) (*actionOutcome, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	return &actionOutcome{Msg: &FlowActionMessage{
		Message: Message{Type: TypeFlowAction, FlowID: params.FlowID}, Action: action, Payload: raw,
	}}, nil
}

// translateVCIAction translates the actions of an oid4vci flow; handled is false
// for an action the profile does not define for it.
func translateVCIAction(f *wmpFlow, params *wmp.FlowActionParams) (out *actionOutcome, err error, handled bool) {
	switch params.Action {
	case openid4x.ActionAcceptOffer:
		out, err = translateAcceptOffer(f, params)
	case openid4x.ActionProvideTxCode:
		var in struct {
			TxCode string `json:"tx_code"`
		}
		if err = decodeActionParams(params.Params, &in); err != nil || in.TxCode == "" {
			return nil, errInvalidParams("tx_code is required"), true
		}
		out, err = actionMessage(params, ActionProvidePin, map[string]string{"tx_code": in.TxCode})
	case openid4x.ActionAuthorize:
		var in struct {
			AuthCode     string `json:"auth_code"`
			CodeVerifier string `json:"code_verifier"`
			State        string `json:"state"`
		}
		if err = decodeActionParams(params.Params, &in); err != nil || in.AuthCode == "" {
			return nil, errInvalidParams("auth_code is required"), true
		}
		// state is an additive member: the engine checks it against the one
		// it sent in authorization_pending, so it must come from the client.
		out, err = actionMessage(params, ActionAuthorizationComplete, map[string]string{
			"code": in.AuthCode, "state": in.State, "code_verifier": in.CodeVerifier,
		})
	case openid4x.ActionCancel:
		out = &actionOutcome{Cancel: true}
	default:
		return nil, nil, false
	}
	return out, err, true
}

// translateVPAction translates the actions of an oid4vp flow; handled is false
// for an action the profile does not define for it.
func translateVPAction(params *wmp.FlowActionParams) (out *actionOutcome, err error, handled bool) {
	switch params.Action {
	case openid4x.ActionSelectCredentials:
		answer, cerr := consentFromSelectCredentials(params.Params)
		if cerr != nil {
			return nil, cerr, true
		}
		action := ActionConsent
		if answer.Declined {
			action = ActionDecline
		}
		return &actionOutcome{Msg: &FlowActionMessage{
			Message: Message{Type: TypeFlowAction, FlowID: params.FlowID}, Action: action, consent: answer,
		}}, nil, true
	case openid4x.ActionCancel:
		var in struct {
			Reason string `json:"reason"`
		}
		_ = decodeActionParams(params.Params, &in)
		out, err = actionMessage(params, ActionDecline, map[string]string{"reason": in.Reason})
		return out, err, true
	}
	return nil, nil, false
}

// decodeActionParams decodes the params of an action; absent params are the
// zero value.
func decodeActionParams(raw json.RawMessage, out interface{}) error {
	if len(raw) == 0 {
		return nil
	}
	return json.Unmarshal(raw, out)
}

// translateAcceptOffer maps accept_offer {selected_indices, consent} to the
// engine's select_credential {credential_configuration_id}. The indices refer
// to the credentials of the awaiting_offer_acceptance the flow last sent, so
// the client can only name a configuration the engine offered it. The engine
// issues one configuration per flow: more than one index is refused. A
// consent that is not true ends the flow.
func translateAcceptOffer(f *wmpFlow, params *wmp.FlowActionParams) (*actionOutcome, error) {
	var in struct {
		SelectedIndices []int `json:"selected_indices"`
		Consent         *bool `json:"consent"`
	}
	if err := decodeActionParams(params.Params, &in); err != nil {
		return nil, errInvalidParams("accept_offer params are malformed")
	}
	// Consent is affirmative or it is nothing: a missing or null consent must not
	// advance the issuance.
	if in.Consent == nil {
		return nil, errInvalidParams("consent is required")
	}
	if !*in.Consent {
		return &actionOutcome{Cancel: true}, nil
	}
	f.mu.Lock()
	ids := f.offerIDs
	f.mu.Unlock()
	if ids == nil {
		return nil, errInvalidParams("no offer is awaiting acceptance")
	}
	if len(in.SelectedIndices) != 1 {
		return nil, errInvalidParams("exactly one selected index is supported")
	}
	i := in.SelectedIndices[0]
	if i < 0 || i >= len(ids) {
		return nil, errInvalidParams("selected index is not one of the offered credentials")
	}
	raw, err := json.Marshal(map[string]string{"credential_configuration_id": ids[i]})
	if err != nil {
		return nil, err
	}
	return &actionOutcome{Msg: &FlowActionMessage{
		Message: Message{Type: TypeFlowAction, FlowID: params.FlowID}, Action: ActionSelectCredential, Payload: raw,
	}}, nil
}

// consentFromSelectCredentials is the WMP wire of the consent: the closed
// select_credentials params (OpenID4x 3.2.3.1) to the transport-neutral answer.
// The engine learns the verifier's query ids and the opaque handle, nothing
// about the credentials. A params the closed shape refuses is an error (the
// caller answers -32602 without data and ends the flow).
func consentFromSelectCredentials(raw json.RawMessage) (*consentAnswer, error) {
	sel, err := openid4x.ParseSelectCredentials(raw)
	if err != nil {
		return nil, err
	}
	if !sel.Consent {
		return &consentAnswer{Declined: true}, nil
	}
	answer := &consentAnswer{Handle: sel.Selections[0].SelectionHandle}
	for _, s := range sel.Selections {
		answer.Selections = append(answer.Selections, ConsentSelection{CredentialQueryID: s.QueryID})
	}
	return answer, nil
}

// completionResult is the result of wmp.flow.complete: the engine's completion
// without the members of its WebSocket envelope (type, flow_id, message_id,
// timestamp), which WMP carries in the notification itself. For an oid4vci
// completion that the engine retained a notification context for, it carries
// notification_endpoint (OpenID4x 3.1.4); credentials[].notification_id (plain
// responses only: the engine's results have none for an encrypted one) stays
// when it is within the profile's bound (256 characters), else it is left out,
// as the wallet could not start a flow with it.
func completionResult(m *FlowCompleteMessage, notificationEndpoint string) (json.RawMessage, error) {
	b, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	obj := map[string]json.RawMessage{}
	if err := json.Unmarshal(b, &obj); err != nil {
		return nil, fmt.Errorf("completion is not an object: %w", err)
	}
	for _, k := range []string{"type", "flow_id", "message_id", "timestamp"} {
		delete(obj, k)
	}
	if raw, ok := obj["credentials"]; ok {
		obj["credentials"] = boundedNotificationIDs(raw)
	}
	if notificationEndpoint != "" && utf8.RuneCountInString(notificationEndpoint) <= maxNotificationEndpointLen {
		endpoint, _ := json.Marshal(notificationEndpoint)
		obj["notification_endpoint"] = endpoint
	}
	return json.Marshal(obj)
}

// boundedNotificationIDs leaves out a credentials[].notification_id longer than
// the profile allows.
func boundedNotificationIDs(raw json.RawMessage) json.RawMessage {
	var entries []map[string]json.RawMessage
	if json.Unmarshal(raw, &entries) != nil {
		return raw
	}
	changed := false
	for _, e := range entries {
		var id string
		if v, ok := e["notification_id"]; ok && (json.Unmarshal(v, &id) != nil || utf8.RuneCountInString(id) > openid4x.MaxNotificationIDLen) {
			delete(e, "notification_id")
			changed = true
		}
	}
	if !changed {
		return raw
	}
	out, err := json.Marshal(entries)
	if err != nil {
		return raw
	}
	return out
}
