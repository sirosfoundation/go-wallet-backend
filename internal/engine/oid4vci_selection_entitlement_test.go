package engine

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- selection must stay inside what was checked ---------------------------

func selectionMeta() *IssuerMetadata {
	return &IssuerMetadata{CredentialConfigurationsSupported: CredentialConfigurations{
		"pid":     {Format: "dc+sd-jwt", VCT: "urn:eudi:pid:1"},
		"mdl":     {Format: "dc+sd-jwt", VCT: "urn:eudi:mdl:1"},
		"diploma": {Format: "dc+sd-jwt", VCT: "urn:eudi:diploma:1"}, // supported, never offered, never checked
	}}
}

func driveSelection(t *testing.T, offerIDs []string, selected string) (string, error) {
	t.Helper()
	h, _ := newRegistrarHandler(t, "fail", nil)
	flow := registerTestFlow(h.Flow.Session, "flow-sel")
	h.Flow = flow
	payload, _ := json.Marshal(map[string]string{"credential_configuration_id": selected})
	// Delivered the way the transports do (the WMP bridge and the WebSocket
	// read loop both put a FlowActionMessage on the flow's action channel).
	flow.actions <- &FlowActionMessage{Action: ActionSelectCredential, Payload: payload}
	offer := &CredentialOffer{CredentialIssuer: "https://issuer.example", CredentialConfigurationIDs: offerIDs}
	id, _, err := h.awaitCredentialSelection(context.Background(), offer, selectionMeta())
	return id, err
}

func TestAwaitCredentialSelection_RefusesAConfigurationOutsideTheOffer(t *testing.T) {
	_, err := driveSelection(t, []string{"pid", "mdl"}, "diploma")
	require.Error(t, err)
}

func TestAwaitCredentialSelection_AcceptsAnOfferedConfiguration(t *testing.T) {
	id, err := driveSelection(t, []string{"pid", "mdl"}, "mdl")
	require.NoError(t, err)
	assert.Equal(t, "mdl", id)
}

// authorization_details are forwarded to the AS, so they obey the same bound.
func TestExecute_RefusesAuthorizationDetailsOutsideTheOffer(t *testing.T) {
	h, _ := newRegistrarHandler(t, "fail", nil)
	h.Flow.Session.flows = map[string]*Flow{}
	msg := &FlowStartMessage{
		RefreshToken:                      "rt",
		CredentialIssuer:                  "https://issuer.example",
		SelectedCredentialConfigurationID: "pid",
		AuthorizationDetails: []AuthorizationDetail{
			{CredentialConfigurationID: "diploma"},
		},
	}
	err := h.Execute(context.Background(), msg)
	require.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "authorization_details"), err.Error())
}
