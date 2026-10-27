package engine

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

// The superseded secret-bearing members are refused, not ignored. Ignoring an
// advertisement would make the engine ask for no response encryption and let
// the secret travel in clear through it.
var legacyMemberValues = map[string]string{
	"org.siros.secret_seed":        `{"namespaces":["ns"]}`,
	"org.siros.holder_commitments": `{"commitments":["psc"]}`,
	"org.siros.psc":                `"` + secretSeedA + `"`,
	"holder_commitments":           `["psc"]`,
	"secret_members":               `["x"]`,
}

func flowErrorCode(t *testing.T, m map[string]json.RawMessage) ErrorCode {
	t.Helper()
	require.JSONEq(t, `"flow_error"`, string(m["type"]))
	var e FlowError
	require.NoError(t, json.Unmarshal(m["error"], &e))
	assert.NotContains(t, e.Message, secretSeedA)
	return e.Code
}

// Offer time: a configuration advertising one is refused at selection, before
// any authorization or request, so the issuer is never reached.
func TestLegacySecretMember_AdvertisementRefusedAtSelection(t *testing.T) {
	for member, value := range legacyMemberValues {
		t.Run(member, func(t *testing.T) {
			var md IssuerMetadata
			require.NoError(t, json.Unmarshal([]byte(`{"credential_issuer":"https://i.example","credential_configurations_supported":{
				"cfg":{"format":"mso_mdoc","credential_metadata":{"`+member+`":`+value+`}}}}`), &md))
			require.Contains(t, md.CredentialConfigurationsSupported, "cfg", "kept so that its use is refused with a clear reason")
			core, logs := observer.New(zap.DebugLevel)
			h, ch, cleanup := captureHandler(t)
			defer cleanup()
			h.Logger = zap.New(core)
			offer := &CredentialOffer{CredentialIssuer: "https://i.example", CredentialConfigurationIDs: []string{"cfg"}}
			_, _, err := h.awaitCredentialSelection(context.Background(), offer, &md)
			require.ErrorIs(t, err, errLegacySecretMember)
			assert.Equal(t, ErrCodeLegacySecretMember, flowErrorCode(t, nextMsg(t, ch)))
			assertNoSecrets(t, "logs", logDump(logs))
		})
	}
}

// Defence in depth: even when a legacy-advertising configuration reaches the
// issuance steps, no request is made and no key is asked for.
func TestLegacySecretMember_AdvertisementNeverReachesTheIssuer(t *testing.T) {
	for member, value := range legacyMemberValues {
		t.Run(member, func(t *testing.T) {
			st := newIssuerStub(t, seedResponse)
			fc := &fakeClient{t: t}
			h, logs, cleanup := newBlindHandler(t, fc, st.srv.Client())
			defer cleanup()
			cfg := seedConfig()
			cfg.AuxiliaryDataSupported = nil
			cfg.CredentialMetadata = json.RawMessage(`{"` + member + `":` + value + `}`)
			err := h.issueCredential(context.Background(), st.metadata(gcmCfg(false)), tokenBearer(), "cfg", cfg, nil, "")
			require.ErrorIs(t, err, errLegacySecretMember)
			assert.Empty(t, st.requests)
			assert.Empty(t, fc.actions())
			assertNoSecrets(t, "logs", logDump(logs))
		})
	}
}

// Response time: a plain response whose credential_metadata carries one is
// refused whole; nothing is completed or relayed.
func TestLegacySecretMember_PlainResponseRefused(t *testing.T) {
	for member, value := range legacyMemberValues {
		t.Run(member, func(t *testing.T) {
			core, logs := observer.New(zap.DebugLevel)
			h, ch, cleanup := captureHandler(t)
			defer cleanup()
			h.Logger = zap.New(core)
			var resp CredentialResponse
			body := `{"credentials":["c0"],"credential_metadata":{"display":[{"name":"D"}],"` + member + `":` + value + `}}`
			require.NoError(t, json.Unmarshal([]byte(body), &resp))
			err := h.finishIssuance(context.Background(), &resp, &CredentialConfig{Format: "x"}, nil, nil, &TokenResponse{})
			require.ErrorIs(t, err, errLegacySecretMember)
			assert.Equal(t, ErrCodeLegacySecretMember, flowErrorCode(t, nextMsg(t, ch)))
			assertNoSecrets(t, "logs", logDump(logs))
			select {
			case extra := <-ch:
				t.Fatalf("unexpected %s", extra["type"])
			default:
			}
		})
	}
}
