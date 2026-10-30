package engine

import (
	"encoding/json"
	"fmt"
)

// The WebSocket wire of the consent: the decline action and the consent action
// with ConsentPayload (selected_credentials: {credential_query_id,
// credential_id, disclosed_claims}). The WebSocket protocol has no selection
// handle, so a selection_handle member a client sends is not read (it would
// reach the sign request as if the user's selection had produced it).

// consentAnswerFrom is the transport-neutral answer carried by a client
// action: already translated when the transport did it (the WMP bridge), else
// the WebSocket wire.
func consentAnswerFrom(action *FlowActionMessage) (consentAnswer, error) {
	if action.consent != nil {
		return *action.consent, nil
	}
	return consentFromWebSocket(action)
}

// consentFromWebSocket translates the decline or consent action of the
// WebSocket protocol.
func consentFromWebSocket(action *FlowActionMessage) (consentAnswer, error) {
	if action.Action == ActionDecline {
		var decline struct {
			Reason string `json:"reason"`
		}
		_ = json.Unmarshal(action.Payload, &decline)
		return consentAnswer{Declined: true, Reason: decline.Reason}, nil
	}
	var payload ConsentPayload
	if err := json.Unmarshal(action.Payload, &payload); err != nil {
		return consentAnswer{}, fmt.Errorf("invalid consent payload: %w", err)
	}
	return consentAnswer{Selections: payload.SelectedCredentials}, nil
}
