package engine

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

// The credentials of a plain response are opaque: only the response's own
// member names and its credential_metadata are held to the strict rules.
func TestDecodeCredentialResponse(t *testing.T) {
	var ok CredentialResponse
	require.NoError(t, decodeCredentialResponse([]byte(`{"credentials":[{"credential":{"credentialSubject":{"Type":"x","type":"y"},"@context":[{"Type":1,"type":2}]}}],"credential_metadata":{"display":[]}}`), &ok))
	for name, in := range map[string]string{
		"repeated credential_metadata":     `{"credential_metadata":{"x":1},"credential_metadata":null}`,
		"case-variant credential_metadata": `{"credential_metadata":{"x":1},"Credential_Metadata":null}`,
		"repeated member in metadata":      `{"credential_metadata":{"a":1,"a":2}}`,
		"trailing data":                    `{"credentials":[]} {}`,
	} {
		t.Run(name, func(t *testing.T) {
			var r CredentialResponse
			require.ErrorIs(t, decodeCredentialResponse([]byte(in), &r), errAmbiguousJSON)
		})
	}
}

// A credential offer with a repeated or case-variant member is refused: the
// engine and the client that passed it on could otherwise read different
// grants or issuers.
func TestParseOffer_AmbiguousIsRefused(t *testing.T) {
	h, _, cleanup := captureHandler(t)
	defer cleanup()
	const ok = `{"credential_issuer":"https://i.example","credential_configuration_ids":["a"],"grants":{"authorization_code":{}}}`
	_, err := h.parseOffer(context.Background(), &FlowStartMessage{Offer: ok})
	require.NoError(t, err)
	for name, offer := range map[string]string{
		"repeated issuer": `{"credential_issuer":"https://i.example","credential_issuer":"https://evil.example","credential_configuration_ids":["a"]}`,
		"repeated grants": `{"credential_issuer":"https://i.example","credential_configuration_ids":["a"],"grants":{"authorization_code":{}},"grants":{}}`,
		"repeated grant":  `{"credential_issuer":"https://i.example","credential_configuration_ids":["a"],"grants":{"authorization_code":{},"authorization_code":{"issuer_state":"x"}}}`,
		"trailing data":   ok + ` {}`,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := h.parseOffer(context.Background(), &FlowStartMessage{Offer: offer})
			require.Error(t, err)
		})
	}
}
