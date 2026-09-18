package engine

import (
	"encoding/json"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The Wallet decides whether to ask by authorization_details; the engine only
// forwards it. These pin the forwarding and the OID4VCI 1.0 §6 echo, which is
// the half a client has no surface for.

func TestFlowStartMessageCarriesAuthorizationDetails(t *testing.T) {
	raw := `{
		"type": "flow_start",
		"protocol": "oid4vci",
		"authorization_details": [
			{"type": "openid_credential", "credential_configuration_id": "pid"}
		]
	}`
	var msg FlowStartMessage
	require.NoError(t, json.Unmarshal([]byte(raw), &msg))
	require.Len(t, msg.AuthorizationDetails, 1)
	assert.Equal(t, "openid_credential", msg.AuthorizationDetails[0].Type)
	assert.Equal(t, "pid", msg.AuthorizationDetails[0].CredentialConfigurationID)
}

func TestFlowStartWithoutAuthorizationDetailsStaysAbsent(t *testing.T) {
	// Absent must mean "do not ask this way", not "ask with nothing" - a
	// client that never sends it has to behave exactly as before.
	var msg FlowStartMessage
	require.NoError(t, json.Unmarshal([]byte(`{"type":"flow_start","protocol":"oid4vci"}`), &msg))
	assert.Empty(t, msg.AuthorizationDetails)

	encoded, err := json.Marshal(msg)
	require.NoError(t, err)
	assert.NotContains(t, string(encoded), "authorization_details")
}

func TestGrantedCredentialIdentifierMatchesTheConfiguration(t *testing.T) {
	token := &TokenResponse{AuthorizationDetails: []AuthorizationDetail{
		{Type: "openid_credential", CredentialConfigurationID: "mdl", CredentialIdentifiers: []string{"id-mdl"}},
		{Type: "openid_credential", CredentialConfigurationID: "pid", CredentialIdentifiers: []string{"id-pid", "id-pid-2"}},
	}}
	assert.Equal(t, "id-pid", grantedCredentialIdentifier(token, "pid"))
	assert.Equal(t, "id-mdl", grantedCredentialIdentifier(token, "mdl"))
	assert.Empty(t, grantedCredentialIdentifier(token, "unknown"))
}

func TestGrantedCredentialIdentifierWithoutAnEchoIsEmpty(t *testing.T) {
	// No echo means the AS did not honour authorization_details, so the
	// Credential Request keeps naming the configuration id.
	assert.Empty(t, grantedCredentialIdentifier(&TokenResponse{}, "pid"))
	assert.Empty(t, grantedCredentialIdentifier(nil, "pid"))
	assert.Empty(t, grantedCredentialIdentifier(&TokenResponse{
		AuthorizationDetails: []AuthorizationDetail{{Type: "openid_credential", CredentialConfigurationID: "pid"}},
	}, "pid"))
}

func TestGrantedCredentialIdentifierAcceptsASoleUnlabelledEntry(t *testing.T) {
	// An AS that echoes identifiers without naming the configuration is
	// unambiguous only when it granted exactly one entry.
	sole := &TokenResponse{AuthorizationDetails: []AuthorizationDetail{
		{Type: "openid_credential", CredentialIdentifiers: []string{"id-only"}},
	}}
	assert.Equal(t, "id-only", grantedCredentialIdentifier(sole, "pid"))

	ambiguous := &TokenResponse{AuthorizationDetails: []AuthorizationDetail{
		{Type: "openid_credential", CredentialIdentifiers: []string{"a"}},
		{Type: "openid_credential", CredentialIdentifiers: []string{"b"}},
	}}
	assert.Empty(t, grantedCredentialIdentifier(ambiguous, "pid"))
}

func TestTokenResponseParsesTheAuthorizationDetailsEcho(t *testing.T) {
	raw := `{
		"access_token": "t",
		"token_type": "DPoP",
		"authorization_details": [
			{"type":"openid_credential","credential_configuration_id":"pid","credential_identifiers":["cid-1"]}
		]
	}`
	var token TokenResponse
	require.NoError(t, json.Unmarshal([]byte(raw), &token))
	assert.Equal(t, "cid-1", grantedCredentialIdentifier(&token, "pid"))
}

func TestResponseOnlyFieldsNeverReachTheAuthorizationRequest(t *testing.T) {
	// credential_identifiers is granted by the Authorization Server in its
	// token response. A client that puts them in flow_start must not have the
	// engine send them as a request parameter - the engine forwards intent,
	// not whatever it was handed.
	projected := requestAuthorizationDetails([]AuthorizationDetail{
		{
			Type:                      "openid_credential",
			CredentialConfigurationID: "pid",
			CredentialIdentifiers:     []string{"smuggled"},
		},
	})

	require.Len(t, projected, 1)
	assert.Equal(t, "openid_credential", projected[0].Type)
	assert.Equal(t, "pid", projected[0].CredentialConfigurationID)
	assert.Empty(t, projected[0].CredentialIdentifiers)

	encoded, err := json.Marshal(projected)
	require.NoError(t, err)
	assert.NotContains(t, string(encoded), "credential_identifiers")
	assert.NotContains(t, string(encoded), "smuggled")
}

func TestProjectionPreservesEveryRequestedConfiguration(t *testing.T) {
	projected := requestAuthorizationDetails([]AuthorizationDetail{
		{Type: "openid_credential", CredentialConfigurationID: "pid"},
		{Type: "openid_credential", CredentialConfigurationID: "mdl"},
	})
	require.Len(t, projected, 2)
	assert.Equal(t, "pid", projected[0].CredentialConfigurationID)
	assert.Equal(t, "mdl", projected[1].CredentialConfigurationID)
}

func TestAnEntryNamingNoConfigurationIsNotForwarded(t *testing.T) {
	// It identifies nothing, but would still produce a non-empty
	// authorization_details and so satisfy a guard that only tests presence.
	projected := requestAuthorizationDetails([]AuthorizationDetail{
		{Type: "openid_credential"},
		{Type: "openid_credential", CredentialConfigurationID: "pid"},
	})

	require.Len(t, projected, 1)
	assert.Equal(t, "pid", projected[0].CredentialConfigurationID)
}

func TestAMissingTypeIsFilledInRatherThanSentEmpty(t *testing.T) {
	// OID4VCI 1.0 §5.1.1 requires this value; the client not saying so is not
	// a reason to send the AS something it must reject.
	projected := requestAuthorizationDetails([]AuthorizationDetail{
		{CredentialConfigurationID: "pid"},
	})

	require.Len(t, projected, 1)
	assert.Equal(t, "openid_credential", projected[0].Type)
}

func TestAnyOtherTypeIsNormalisedRatherThanForwarded(t *testing.T) {
	// §5.1.1 fixes `type` at "openid_credential" for a credential
	// authorization detail, and AuthorizationDetail can express no other kind.
	// Forwarding anything else produces a request the AS must reject, while
	// the detail's actual intent - the configuration - is untouched.
	projected := requestAuthorizationDetails([]AuthorizationDetail{
		{Type: "openid_credential_v2", CredentialConfigurationID: "pid"},
		{Type: "urn:example:something-else", CredentialConfigurationID: "mdl"},
	})

	require.Len(t, projected, 2)
	assert.Equal(t, "openid_credential", projected[0].Type)
	assert.Equal(t, "pid", projected[0].CredentialConfigurationID)
	assert.Equal(t, "openid_credential", projected[1].Type)
	assert.Equal(t, "mdl", projected[1].CredentialConfigurationID)
}

func TestProjectingNothingUsableYieldsNothing(t *testing.T) {
	assert.Empty(t, requestAuthorizationDetails(nil))
	assert.Empty(t, requestAuthorizationDetails([]AuthorizationDetail{}))
	assert.Empty(t, requestAuthorizationDetails([]AuthorizationDetail{{Type: "openid_credential"}}))
}

func TestSeveralUnlabelledEntriesAreAmbiguousRatherThanTheFirstOne(t *testing.T) {
	// Matching "" against the entries would pick whichever unlabelled one came
	// first - a guess dressed up as a match.
	token := &TokenResponse{AuthorizationDetails: []AuthorizationDetail{
		{Type: "openid_credential", CredentialIdentifiers: []string{"cid-1"}},
		{Type: "openid_credential", CredentialIdentifiers: []string{"cid-2"}},
	}}
	assert.Equal(t, "", grantedCredentialIdentifier(token, ""))

	// And one labelled entry is not reachable without naming it either.
	labelled := &TokenResponse{AuthorizationDetails: []AuthorizationDetail{
		{Type: "openid_credential", CredentialConfigurationID: "pid", CredentialIdentifiers: []string{"cid-1"}},
	}}
	assert.Equal(t, "", grantedCredentialIdentifier(labelled, ""))
	assert.Equal(t, "cid-1", grantedCredentialIdentifier(labelled, "pid"))
}

func TestAnAuthorizationRequestMustNameACredential(t *testing.T) {
	// Any one of the three is enough; none of them asks the AS for nothing.
	named := func(pairs ...string) url.Values {
		params := url.Values{}
		for i := 0; i < len(pairs); i += 2 {
			params.Set(pairs[i], pairs[i+1])
		}
		return params
	}

	assert.True(t, authorizationRequestNamesACredential(named("scope", "pid")))
	assert.True(t, authorizationRequestNamesACredential(
		named("authorization_details", `[{"type":"openid_credential","credential_configuration_id":"pid"}]`)))
	// An issuer-initiated offer names the credential server-side. A
	// configuration with no scope, from a client that has not adopted
	// authorization_details, is a working flow and must stay one.
	assert.True(t, authorizationRequestNamesACredential(named("issuer_state", "sess-1")))

	assert.False(t, authorizationRequestNamesACredential(named()))
	assert.False(t, authorizationRequestNamesACredential(
		named("scope", "", "authorization_details", "", "issuer_state", "")))
	assert.False(t, authorizationRequestNamesACredential(named("response_type", "code")))
}
