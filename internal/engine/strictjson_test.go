package engine

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

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
		"alias Grants":    `{"credential_issuer":"https://i.example","credential_configuration_ids":["a"],"Grants":{"authorization_code":{}}}`,
		"alias issuer":    `{"Credential_Issuer":"https://i.example","credential_configuration_ids":["a"]}`,
		"alias ids":       `{"credential_issuer":"https://i.example","Credential_Configuration_IDs":["a"]}`,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := h.parseOffer(context.Background(), &FlowStartMessage{Offer: offer})
			require.Error(t, err)
		})
	}
}
