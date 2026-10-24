package engine

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

// secretSeedAdvertised is the legacy-only view of secretDeliveryOf that the
// older advertisement tests use.
func secretSeedAdvertised(c *CredentialConfig) (bool, error) {
	d, err := secretDeliveryOf(c)
	return d.requireEncryption, err
}

// withSecretMembers sets the configured secret member set for one test.
func withSecretMembers(t *testing.T, names ...string) {
	t.Helper()
	SetSecretMembers(names)
	t.Cleanup(func() { SetSecretMembers([]string{secretSeedMember, auxiliaryDataMember}) })
}

func auxCfg(aux string) *CredentialConfig {
	c := &CredentialConfig{Format: "mso_mdoc", ProofTypesSupported: map[string]interface{}{"jwt": map[string]interface{}{}}}
	if aux != "" {
		c.AuxiliaryDataSupported = json.RawMessage(aux)
	}
	return c
}

const (
	auxToWalletSSC = `{"type":"hash_commitment","alg":"sha-256","path":["eu.europa.ec.eudi.nym_auth.1","ssc"]}`
	auxToIssuerPSC = `{"type":"hash_commitment","alg":"sha-256","path":["eu.europa.ec.eudi.nym_auth.1","psc"],"required":true}`
	auxAdvFull     = `{"to_wallet":[` + auxToWalletSSC + `],"to_issuer":[` + auxToIssuerPSC + `]}`
)

func TestAuxiliaryDataSupported_Valid(t *testing.T) {
	d, err := secretDeliveryOf(auxCfg(auxAdvFull))
	require.NoError(t, err)
	assert.True(t, d.requireEncryption)
	assert.True(t, d.requiredToIssuer)
	require.Len(t, d.toIssuer, 1)
	assert.JSONEq(t, auxToIssuerPSC, string(d.toIssuer[0]))

	// to_issuer alone: nothing secret goes to the wallet.
	d, err = secretDeliveryOf(auxCfg(`{"to_issuer":[{"type":"hash_commitment","alg":"sha-256","path":["a","b"]}]}`))
	require.NoError(t, err)
	assert.False(t, d.requireEncryption)
	assert.False(t, d.requiredToIssuer)
	assert.Len(t, d.toIssuer, 1)

	// An unrecognised type is ignored, not an error, and carries no secret.
	d, err = secretDeliveryOf(auxCfg(`{"to_wallet":[{"type":"https://x.example/t","foo":1}],"to_issuer":[{"type":"https://x.example/t","required":true}]}`))
	require.NoError(t, err)
	assert.False(t, d.requireEncryption)
	assert.True(t, d.requiredToIssuer)
	assert.JSONEq(t, `{"type":"https://x.example/t","required":true}`, string(d.toIssuer[0]))

	// Path elements may be strings, nulls and non-negative integers.
	_, err = secretDeliveryOf(auxCfg(`{"to_wallet":[{"type":"hash_commitment","alg":"sha-256","path":["a",null,0]}]}`))
	require.NoError(t, err)

	// Absent: zero value.
	d, err = secretDeliveryOf(auxCfg(""))
	require.NoError(t, err)
	assert.Equal(t, secretDelivery{}, d)
}

func TestAuxiliaryDataSupported_Malformed(t *testing.T) {
	hc := func(extra string) string {
		return `{"type":"hash_commitment","alg":"sha-256","path":["a","b"]` + extra + `}`
	}
	for name, adv := range map[string]string{
		"null":                    `null`,
		"array":                   `[]`,
		"string":                  `"x"`,
		"empty object":            `{}`,
		"unknown members only":    `{"foo":[]}`,
		"to_wallet not array":     `{"to_wallet":{}}`,
		"to_wallet empty":         `{"to_wallet":[]}`,
		"to_wallet null":          `{"to_wallet":null}`,
		"to_issuer empty":         `{"to_issuer":[]}`,
		"entry not object":        `{"to_wallet":["x"]}`,
		"entry null":              `{"to_wallet":[null]}`,
		"entry without type":      `{"to_wallet":[{"alg":"sha-256"}]}`,
		"type not string":         `{"to_wallet":[{"type":1}]}`,
		"empty type":              `{"to_wallet":[{"type":""}]}`,
		"hc without alg":          `{"to_wallet":[{"type":"hash_commitment","path":["a"]}]}`,
		"hc alg not string":       `{"to_wallet":[{"type":"hash_commitment","alg":1,"path":["a"]}]}`,
		"hc without path":         `{"to_wallet":[{"type":"hash_commitment","alg":"sha-256"}]}`,
		"hc empty path":           `{"to_wallet":[{"type":"hash_commitment","alg":"sha-256","path":[]}]}`,
		"hc path not array":       `{"to_wallet":[{"type":"hash_commitment","alg":"sha-256","path":"a"}]}`,
		"hc path negative":        `{"to_wallet":[{"type":"hash_commitment","alg":"sha-256","path":["a",-1]}]}`,
		"hc path bool":            `{"to_wallet":[{"type":"hash_commitment","alg":"sha-256","path":["a",true]}]}`,
		"hc path object":          `{"to_wallet":[{"type":"hash_commitment","alg":"sha-256","path":[{}]}]}`,
		"opening in metadata":     `{"to_wallet":[` + hc(`,"opening":"SECRETOPENING"`) + `]}`,
		"commitment in metadata":  `{"to_issuer":[` + hc(`,"commitment":"x"`) + `]}`,
		"required not bool":       `{"to_issuer":[` + hc(`,"required":"yes"`) + `]}`,
		"required null":           `{"to_issuer":[` + hc(`,"required":null`) + `]}`,
		"duplicate escaped path":  `{"to_wallet":[` + hc("") + `,{"type":"hash_commitment","alg":"sha-256","path":["\u0061","b"]}]}`,
		"duplicate unknown path":  `{"to_wallet":[{"type":"https://x.example/t","path":["a"]},{"type":"https://x.example/t","path":[ "\u0061" ]}]}`,
		"required in to_wallet":   `{"to_wallet":[` + hc(`,"required":true`) + `]}`,
		"duplicate type and path": `{"to_wallet":[` + hc("") + `,` + hc("") + `]}`,
		"too many entries":        `{"to_wallet":[` + strings.TrimSuffix(strings.Repeat(hc("")+",", 17), ",") + `]}`,
	} {
		t.Run(name, func(t *testing.T) {
			d, err := secretDeliveryOf(auxCfg(adv))
			require.Error(t, err)
			assert.Equal(t, secretDelivery{}, d)
			assert.NotContains(t, err.Error(), "SECRETOPENING")
			assert.True(t, AdvertisementMalformed(json.RawMessage(`{"format":"mso_mdoc","auxiliary_data_supported":`+adv+`}`)))
			// The configuration is not offered.
			var ccs CredentialConfigurations
			require.NoError(t, json.Unmarshal([]byte(`{"c":{"format":"mso_mdoc","auxiliary_data_supported":`+adv+`}}`), &ccs))
			assert.NotContains(t, ccs, "c")
		})
	}

	// A type error elsewhere in the configuration must not disable the check.
	assert.True(t, AdvertisementMalformed(json.RawMessage(`{"format":123,"credential_metadata":{"auxiliary_data":[{"opening":"SECRETOPENING"}]}}`)))
	assert.True(t, AdvertisementMalformed(json.RawMessage(`{"format":123,"auxiliary_data_supported":{"to_wallet":[]}}`)))
	assert.False(t, AdvertisementMalformed(json.RawMessage(`{"format":123}`)))

	// Distinct paths are not duplicates.
	_, err := secretDeliveryOf(auxCfg(`{"to_wallet":[` + hc("") + `,{"type":"hash_commitment","alg":"sha-256","path":["a","c"]}]}`))
	require.NoError(t, err)
}

// A secret member in the issuer metadata's credential_metadata is malformed
// (auxiliary_data MUST NOT appear there), unless it is the legacy member in
// its advertisement shape.
func TestSecretMemberInIssuerMetadataIsMalformed(t *testing.T) {
	_, err := secretDeliveryOf(seedCfg(`{"auxiliary_data":[{"type":"hash_commitment","opening":"SECRETOPENING"}]}`))
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "SECRETOPENING")

	d, err := secretDeliveryOf(seedCfg(advOK))
	require.NoError(t, err)
	assert.True(t, d.requireEncryption)

	// Not configured as secret: ordinary metadata, ignored.
	withSecretMembers(t, "x.secret")
	d, err = secretDeliveryOf(seedCfg(`{"auxiliary_data":[1],"org.siros.secret_seed":"anything"}`))
	require.NoError(t, err)
	assert.Equal(t, secretDelivery{}, d)
	_, err = secretDeliveryOf(seedCfg(`{"x.secret":{"namespaces":["a"]}}`))
	require.Error(t, err)
}

func TestPlainResponse_ConfiguredSecretMembersRefused(t *testing.T) {
	for _, member := range []string{"org.siros.secret_seed", "auxiliary_data"} {
		t.Run(member, func(t *testing.T) {
			core, logs := observer.New(zap.DebugLevel)
			h, ch, cleanup := captureHandler(t)
			defer cleanup()
			h.Logger = zap.New(core)
			var resp CredentialResponse
			body := `{"credentials":["c0"],"credential_metadata":{"display":[{"name":"D"}],"` + member + `":[{"type":"hash_commitment","opening":"` + secretSeedA + `"}]}}`
			require.NoError(t, json.Unmarshal([]byte(body), &resp))
			err := h.finishIssuance(context.Background(), &resp, &CredentialConfig{Format: "x"}, nil, nil, &TokenResponse{})
			require.Error(t, err)
			assertNoSecrets(t, "error", err.Error())
			m := nextMsg(t, ch)
			assert.JSONEq(t, `"flow_error"`, string(m["type"]))
			assertNoSecrets(t, "logs", logDump(logs))
		})
	}
}

func TestPlainResponse_SecretMemberSetIsConfigured(t *testing.T) {
	withSecretMembers(t, "x.secret")
	h, ch, cleanup := captureHandler(t)
	defer cleanup()
	var resp CredentialResponse
	require.NoError(t, json.Unmarshal([]byte(`{"credentials":["c0"],"credential_metadata":{"x.secret":"S","display":[]}}`), &resp))
	require.Error(t, h.finishIssuance(context.Background(), &resp, &CredentialConfig{Format: "x"}, nil, nil, &TokenResponse{}))
	assert.JSONEq(t, `"flow_error"`, string(nextMsg(t, ch)["type"]))

	// A member that is no longer in the set is not special (and the engine
	// relays display members only, so it is dropped regardless).
	resp = CredentialResponse{}
	require.NoError(t, json.Unmarshal([]byte(`{"credentials":["c0"],"credential_metadata":{"auxiliary_data":[],"display":[]}}`), &resp))
	require.NoError(t, h.finishIssuance(context.Background(), &resp, &CredentialConfig{Format: "x"}, nil, nil, &TokenResponse{}))
	assert.JSONEq(t, `"flow_complete"`, string(nextMsg(t, ch)["type"]))
}

func TestNegotiate_AuxiliaryDataToWalletRequiresEncryption(t *testing.T) {
	h, _, cleanup := newBlindHandler(t, &fakeClient{t: t}, http.DefaultClient)
	defer cleanup()

	got, err := h.negotiateResponseEncryption(&IssuerMetadata{CredentialResponseEncryption: gcmCfg(false)}, auxCfg(auxAdvFull))
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.True(t, got.Required)
	assert.True(t, got.Seed)

	// No encryption offered by the issuer: refused, fail closed.
	_, err = h.negotiateResponseEncryption(&IssuerMetadata{}, auxCfg(auxAdvFull))
	require.Error(t, err)
	// No mutually supported pair: refused.
	_, err = h.negotiateResponseEncryption(&IssuerMetadata{CredentialResponseEncryption: &CredentialResponseEncryptionConfig{
		AlgValuesSupported: []string{"RSA-OAEP"}, EncValuesSupported: []string{"A128GCM"}}}, auxCfg(auxAdvFull))
	require.Error(t, err)

	// to_issuer only, or only an unrecognised to_wallet type: not required.
	for _, adv := range []string{
		`{"to_issuer":[` + auxToIssuerPSC + `]}`,
		`{"to_wallet":[{"type":"https://x.example/t"}]}`,
	} {
		got, err = h.negotiateResponseEncryption(&IssuerMetadata{CredentialResponseEncryption: gcmCfg(false)}, auxCfg(adv))
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.False(t, got.Required)
		assert.False(t, got.Seed)
		got, err = h.negotiateResponseEncryption(&IssuerMetadata{}, auxCfg(adv))
		require.NoError(t, err)
		assert.Nil(t, got)
	}

	// Malformed: fail closed before any request.
	_, err = h.negotiateResponseEncryption(&IssuerMetadata{CredentialResponseEncryption: gcmCfg(false)}, auxCfg(`{"to_wallet":[]}`))
	require.Error(t, err)
}

func generateProofParams(t *testing.T, fc *fakeClient) map[string]json.RawMessage {
	t.Helper()
	for _, m := range fc.outboundMessages() {
		if string(m["action"]) == `"generate_proof"` {
			var p map[string]json.RawMessage
			require.NoError(t, json.Unmarshal(m["params"], &p))
			return p
		}
	}
	t.Fatal("no generate_proof request")
	return nil
}

func TestGenerateProof_CarriesToIssuerEntriesVerbatim(t *testing.T) {
	st := newIssuerStub(t, `{"credential":"c"}`)
	fc := &fakeClient{t: t}
	h, _, cleanup := newBlindHandler(t, fc, st.srv.Client())
	defer cleanup()
	// Entry members the engine does not know travel too (verbatim).
	adv := `{"to_issuer":[` + auxToIssuerPSC + `,{"type":"https://x.example/t","alg":"x","path":["q"],"extra":{"k":1}}]}`
	require.NoError(t, h.issueCredential(context.Background(), st.metadata(nil), tokenBearer(), "cfg", auxCfg(adv), nil, ""))
	p := generateProofParams(t, fc)
	var got []json.RawMessage
	require.NoError(t, json.Unmarshal(p["auxiliary_data_to_issuer"], &got))
	require.Len(t, got, 2)
	assert.JSONEq(t, auxToIssuerPSC, string(got[0]))
	assert.JSONEq(t, `{"type":"https://x.example/t","alg":"x","path":["q"],"extra":{"k":1}}`, string(got[1]))
}

func TestGenerateProof_NoToIssuerNoField(t *testing.T) {
	st := newIssuerStub(t, `{"credential":"c"}`)
	fc := &fakeClient{t: t}
	h, _, cleanup := newBlindHandler(t, fc, st.srv.Client())
	defer cleanup()
	require.NoError(t, h.issueCredential(context.Background(), st.metadata(nil), tokenBearer(), "cfg", auxCfg(""), nil, ""))
	assert.NotContains(t, generateProofParams(t, fc), "auxiliary_data_to_issuer")
}

func TestRequiredToIssuerWithoutProofTypeRefused(t *testing.T) {
	h, ch, cleanup := captureHandler(t)
	defer cleanup()
	noProof := &CredentialConfig{Format: "x", AuxiliaryDataSupported: json.RawMessage(`{"to_issuer":[` + auxToIssuerPSC + `]}`)}
	require.Error(t, h.checkRequiredAuxiliaryDataNeedsProof(noProof))
	assert.JSONEq(t, `"flow_error"`, string(nextMsg(t, ch)["type"]))

	// Optional entry, or a proof type present: fine.
	optional := &CredentialConfig{Format: "x", AuxiliaryDataSupported: json.RawMessage(`{"to_issuer":[{"type":"hash_commitment","alg":"sha-256","path":["a"]}]}`)}
	require.NoError(t, h.checkRequiredAuxiliaryDataNeedsProof(optional))
	withProof := auxCfg(`{"to_issuer":[` + auxToIssuerPSC + `]}`)
	require.NoError(t, h.checkRequiredAuxiliaryDataNeedsProof(withProof))
}

func conflictStub(t *testing.T, body string, dpopNonce bool) (*issuerStub, *int) {
	hits := 0
	st := newIssuerStub(t, `{"credential":"c"}`)
	st.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if dpopNonce {
			w.Header().Set("DPoP-Nonce", "n1")
		}
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(body))
	})
	return st, &hits
}

func TestAuxiliaryDataConflict_RelayedUnchangedNoRetry(t *testing.T) {
	const issuerText = "SECRET-ISSUER-TEXT reset with operator"
	for name, dpop := range map[string]bool{"plain": false, "with DPoP-Nonce header": true} {
		t.Run(name, func(t *testing.T) {
			st, hits := conflictStub(t, `{"error":"auxiliary_data_conflict","error_description":"`+issuerText+`"}`, dpop)
			fc := &fakeClient{t: t}
			h, _, cleanup := newBlindHandler(t, fc, st.srv.Client())
			defer cleanup()
			err := h.issueCredential(context.Background(), st.metadata(gcmCfg(false)), tokenBearer(), "cfg", auxCfg(auxAdvFull), nil, "")
			require.Error(t, err)
			assert.Equal(t, 1, *hits, "a conflict is never retried")
			fc.settle()
			var flowErrs []map[string]json.RawMessage
			for _, m := range fc.outboundMessages() {
				if string(m["type"]) == `"flow_error"` {
					flowErrs = append(flowErrs, m)
				}
			}
			require.Len(t, flowErrs, 1)
			var fe struct {
				Code    string                 `json:"code"`
				Message string                 `json:"message"`
				Details map[string]interface{} `json:"details"`
			}
			require.NoError(t, json.Unmarshal(flowErrs[0]["error"], &fe))
			assert.Equal(t, "AUXILIARY_DATA_CONFLICT", fe.Code)
			assert.Equal(t, map[string]interface{}{"error": "auxiliary_data_conflict"}, fe.Details)
			assert.NotContains(t, string(flowErrs[0]["error"]), "SECRET-ISSUER-TEXT")
			assert.NotContains(t, err.Error(), "SECRET-ISSUER-TEXT")
		})
	}
}

// Anything that is not exactly the code is an ordinary credential error.
func TestAuxiliaryDataConflict_OtherErrorsNotRelayedAsConflict(t *testing.T) {
	for name, body := range map[string]string{
		"invalid_proof":     `{"error":"invalid_proof","error_description":"auxiliary_data_conflict"}`,
		"different case":    `{"error":"Auxiliary_Data_Conflict"}`,
		"in description":    `{"error":"invalid_request","error_description":"auxiliary_data_conflict"}`,
		"not json":          `auxiliary_data_conflict`,
		"error not string":  `{"error":["auxiliary_data_conflict"]}`,
		"invalid_encr_prms": `{"error":"invalid_encryption_parameters"}`,
	} {
		t.Run(name, func(t *testing.T) {
			assert.False(t, isAuxiliaryDataConflict(http.StatusBadRequest, []byte(body)))
		})
	}
	assert.False(t, isAuxiliaryDataConflict(http.StatusUnauthorized, []byte(`{"error":"auxiliary_data_conflict"}`)))
	assert.True(t, isAuxiliaryDataConflict(http.StatusBadRequest, []byte(`{"error":"auxiliary_data_conflict"}`)))

	st, _ := conflictStub(t, `{"error":"invalid_proof"}`, false)
	fc := &fakeClient{t: t}
	h, _, cleanup := newBlindHandler(t, fc, st.srv.Client())
	defer cleanup()
	require.Error(t, h.issueCredential(context.Background(), st.metadata(gcmCfg(false)), tokenBearer(), "cfg", auxCfg(auxAdvFull), nil, ""))
	fc.settle()
	for _, m := range fc.outboundMessages() {
		assert.NotContains(t, string(m["error"]), "AUXILIARY_DATA_CONFLICT")
	}
}

// A non-conflict 400 hands its body back to the caller and closes the original.
func TestRelayAuxiliaryDataConflict_NonConflictBodyRestored(t *testing.T) {
	h, _, cleanup := captureHandler(t)
	defer cleanup()
	rc := &closeTracker{Reader: strings.NewReader(`{"error":"invalid_proof"}`)}
	resp := &http.Response{StatusCode: http.StatusBadRequest, Body: rc}
	require.NoError(t, h.relayAuxiliaryDataConflict(resp))
	assert.True(t, rc.closed, "the original body must be closed")
	b, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.JSONEq(t, `{"error":"invalid_proof"}`, string(b))
}

type closeTracker struct {
	io.Reader
	closed bool
}

func (c *closeTracker) Close() error { c.closed = true; return nil }
