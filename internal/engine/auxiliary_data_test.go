package engine

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
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
	c := &CredentialConfig{Format: "mso_mdoc", VCT: "urn:test", ProofTypesSupported: map[string]interface{}{"jwt": map[string]interface{}{}}}
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
	require.Len(t, d.toIssuer, 1)
	assert.JSONEq(t, auxToIssuerPSC, string(d.toIssuer[0]))

	// to_issuer alone: nothing secret goes to the wallet.
	d, err = secretDeliveryOf(auxCfg(`{"to_issuer":[{"type":"hash_commitment","alg":"sha-256","path":["a","b"]}]}`))
	require.NoError(t, err)
	assert.False(t, d.requireEncryption)
	assert.Len(t, d.toIssuer, 1)

	// An unrecognised type is ignored, not an error, and carries no secret.
	d, err = secretDeliveryOf(auxCfg(`{"to_wallet":[{"type":"https://x.example/t","foo":1}],"to_issuer":[{"type":"https://x.example/t","required":true}]}`))
	require.NoError(t, err)
	assert.False(t, d.requireEncryption)
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
		"Opening in metadata":     `{"to_wallet":[` + hc(`,"Opening":"SECRETOPENING"`) + `]}`,
		"OPENING in metadata":     `{"to_wallet":[` + hc(`,"OPENING":"SECRETOPENING"`) + `]}`,
		"Commitment in metadata":  `{"to_issuer":[` + hc(`,"Commitment":"x"`) + `]}`,
		"Type shadow":             `{"to_issuer":[{"type":"https://x.example/t","Type":"hash_commitment","Opening":"SECRETOPENING"}]}`,
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

// A required to_issuer entry with no proof type declared is not the engine's to
// refuse: the request goes out and the issuer, which owns the rule, refuses it.
func TestRequiredToIssuerWithoutProofTypeLeftToIssuer(t *testing.T) {
	st := newIssuerStub(t, `{"credential":"c"}`)
	fc := &fakeClient{t: t}
	h, _, cleanup := newBlindHandler(t, fc, st.srv.Client())
	defer cleanup()
	cfg := &CredentialConfig{Format: "x", VCT: "urn:v", AuxiliaryDataSupported: json.RawMessage(`{"to_issuer":[` + auxToIssuerPSC + `]}`)}
	require.NoError(t, h.issueCredential(context.Background(), st.metadata(nil), tokenBearer(), "cfg", cfg, nil, ""))
	assert.NotEmpty(t, st.requests, "the issuer, not the engine, decides")
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
			h, logs, cleanup := newBlindHandler(t, fc, st.srv.Client())
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
			assert.NotContains(t, logDump(logs), "SECRET-ISSUER-TEXT", "the raw body is never logged for a conflict")
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
	// A case-variant key alongside the exact one must not hide the conflict.
	assert.True(t, isAuxiliaryDataConflict(http.StatusBadRequest, []byte(`{"error":"auxiliary_data_conflict","ERROR":"invalid_proof","error_description":"C"}`)))
	assert.True(t, isAuxiliaryDataConflict(http.StatusBadRequest, []byte(`{"ERROR":"invalid_proof","error":"auxiliary_data_conflict"}`)))
	assert.False(t, isAuxiliaryDataConflict(http.StatusBadRequest, []byte(`{"ERROR":"auxiliary_data_conflict"}`)))
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

// encoding/json matches field names case-insensitively and folds U+017F to
// "s": a look-alike key must not shadow the real advertisement for any reader.
func TestAdvertisement_CaseFoldedLookAlikeKeysAreMalformed(t *testing.T) {
	const real = `"auxiliary_data_supported":{"to_wallet":[` + auxToWalletSSC + `]}`
	for name, doc := range map[string]string{
		"long s after":         `{"format":"mso_mdoc",` + real + `,"auxiliary_data_ſupported":{"to_issuer":[{"type":"x"}]}}`,
		"long s before":        `{"format":"mso_mdoc","auxiliary_data_ſupported":{"to_issuer":[{"type":"x"}]},` + real + `}`,
		"upper case":           `{"format":"mso_mdoc",` + real + `,"AUXILIARY_DATA_SUPPORTED":{"to_issuer":[{"type":"x"}]}}`,
		"metadata look-alike":  `{"format":"mso_mdoc","credential_metadata":{"display":[]},"Credential_Metadata":{"auxiliary_data":[{"opening":"SECRETOPENING"}]}}`,
		"metadata kelvin sign": `{"format":"mso_mdoc","credential_Key":1,"CREDENTIAL_METADATA":{}}`,
	} {
		t.Run(name, func(t *testing.T) {
			assert.True(t, AdvertisementMalformed(json.RawMessage(doc)))
			var ccs CredentialConfigurations
			require.NoError(t, json.Unmarshal([]byte(`{"c":`+doc+`}`), &ccs))
			assert.NotContains(t, ccs, "c", "the configuration is not offered")
			var cfg CredentialConfig
			require.Error(t, json.Unmarshal([]byte(doc), &cfg))
		})
	}

	// The exact key is what is read, and other members are untouched.
	var cfg CredentialConfig
	require.NoError(t, json.Unmarshal([]byte(`{"format":"mso_mdoc","vct":"v",`+real+`}`), &cfg))
	assert.Equal(t, "v", cfg.VCT)
	d, err := secretDeliveryOf(&cfg)
	require.NoError(t, err)
	assert.True(t, d.requireEncryption)
}

// auxProofJWT is an (unsigned) compact JWT whose body carries the given
// auxiliary_data claim (nil = no claim). The engine reads the body only.
func auxProofJWT(t *testing.T, claim interface{}) string {
	t.Helper()
	body := map[string]interface{}{"aud": "https://i.example", "nonce": "n"}
	if claim != nil {
		body["auxiliary_data"] = claim
	}
	b, err := json.Marshal(body)
	require.NoError(t, err)
	return "e30." + base64.RawURLEncoding.EncodeToString(b) + ".c2ln"
}

// validAuxClaim answers each advertised entry with a valid commitment
// (SHA-256 of a one-byte secret, varied by seed).
func validAuxClaim(t *testing.T, advertised []json.RawMessage, seed byte) []map[string]interface{} {
	t.Helper()
	var out []map[string]interface{}
	for _, raw := range advertised {
		var e map[string]interface{}
		require.NoError(t, json.Unmarshal(raw, &e))
		h := sha256.Sum256([]byte{seed})
		out = append(out, map[string]interface{}{
			"type": e["type"], "alg": e["alg"], "path": e["path"],
			"commitment": base64.RawURLEncoding.EncodeToString(h[:]),
		})
	}
	return out
}

func TestCheckProofsForwardNoOpening(t *testing.T) {
	adv := []json.RawMessage{json.RawMessage(auxToIssuerPSC)}
	good := func() []map[string]interface{} { return validAuxClaim(t, adv, 1) }
	proofs := func(claims ...interface{}) []ProofObject {
		var ps []ProofObject
		for _, c := range claims {
			ps = append(ps, ProofObject{ProofType: "jwt", JWT: auxProofJWT(t, c)})
		}
		return ps
	}
	entry := func(f func(e map[string]interface{})) []map[string]interface{} {
		c := good()
		f(c[0])
		return c
	}

	// Acceptance rules are the issuer's: none of these is the engine's to
	// refuse, whether or not to_issuer is advertised.
	left := map[string][]ProofObject{
		"valid":                       proofs(good()),
		"no claim":                    proofs(nil),
		"empty claim":                 proofs([]interface{}{}),
		"wrong alg":                   proofs(entry(func(e map[string]interface{}) { e["alg"] = "sha-512" })),
		"unlisted path":               proofs(entry(func(e map[string]interface{}) { e["path"] = []string{"n", "xxx"} })),
		"commitment wrong length":     proofs(entry(func(e map[string]interface{}) { e["commitment"] = "AAAA" })),
		"commitment missing":          proofs(entry(func(e map[string]interface{}) { delete(e, "commitment") })),
		"duplicate entry":             proofs(append(good(), good()...)),
		"required missing":            proofs([]map[string]interface{}{{"type": "https://x.example/t"}}),
		"proofs carry different data": proofs(good(), nil),
		"entry without type":          proofs([]map[string]interface{}{{"path": []string{"a"}}}),
	}
	for name, ps := range left {
		for _, inspect := range []bool{true, false} {
			t.Run(fmt.Sprintf("left to issuer/%s/inspect=%v", name, inspect), func(t *testing.T) {
				require.NoError(t, checkProofsForwardNoOpening(ps, inspect))
			})
		}
	}
	require.NoError(t, checkProofsForwardNoOpening(nil, true))
	require.NoError(t, checkProofsForwardNoOpening([]ProofObject{{ProofType: "attestation", Attestation: auxProofJWT(t, good())}}, true))

	// The engine's own rule: no opening is ever forwarded, advertised path or not.
	withOpening := map[string][]ProofObject{
		"opening instead of commitment": proofs(entry(func(e map[string]interface{}) { e["opening"] = "SECRET" })),
		"opening on an unlisted path": proofs(append(good(), map[string]interface{}{
			"type": "hash_commitment", "alg": "sha-256", "path": []string{"n", "other"}, "opening": "SECRET"})),
		"opening in the second proof": proofs(good(), entry(func(e map[string]interface{}) { e["opening"] = "SECRET" })),
		"Opening, case-folded":        proofs(entry(func(e map[string]interface{}) { e["Opening"] = "SECRET" })),
		"OPENING, case-folded":        proofs(entry(func(e map[string]interface{}) { e["OPENING"] = "SECRET" })),
		"Type and Opening folded":     proofs([]map[string]interface{}{{"Type": "hash_commitment", "Opening": "SECRET"}}),
		"opening in an attestation":   {{ProofType: "attestation", Attestation: auxProofJWT(t, entry(func(e map[string]interface{}) { e["opening"] = "SECRET" }))}},
	}
	for name, ps := range withOpening {
		for _, inspect := range []bool{true, false} {
			t.Run(fmt.Sprintf("opening/%s/inspect=%v", name, inspect), func(t *testing.T) {
				err := checkProofsForwardNoOpening(ps, inspect)
				require.Error(t, err)
				assert.ErrorIs(t, err, errAuxiliaryDataProof)
				assert.NotContains(t, err.Error(), "SECRET")
			})
		}
	}

	// A proof the engine cannot inspect: refused when it promised to look
	// (to_issuer advertised), left to the issuer's proof verification otherwise.
	uninspectable := map[string][]ProofObject{
		"not a JWT":                  {{ProofType: "jwt", JWT: "proof-0"}},
		"payload not base64url":      {{ProofType: "jwt", JWT: "a.!!.c"}},
		"unknown proof type":         {{ProofType: "di_vp"}},
		"claim not an array":         proofs("x"),
		"claim an array of non-objs": proofs([]interface{}{5}),
	}
	for name, ps := range uninspectable {
		t.Run("uninspectable/"+name, func(t *testing.T) {
			err := checkProofsForwardNoOpening(ps, true)
			require.Error(t, err)
			assert.ErrorIs(t, err, errAuxiliaryDataProof)
		})
	}
	require.NoError(t, checkProofsForwardNoOpening(uninspectable["not a JWT"], false))
	require.NoError(t, checkProofsForwardNoOpening(uninspectable["unknown proof type"], false))
}

func TestGenerateProof_CarriesCredentialTypeAndIssuer(t *testing.T) {
	for name, tc := range map[string]struct{ vct, doctype, want string }{
		"vct":     {"urn:v", "", "urn:v"},
		"doctype": {"", "org.iso.doc", "org.iso.doc"},
	} {
		t.Run(name, func(t *testing.T) {
			st := newIssuerStub(t, `{"credential":"c"}`)
			fc := &fakeClient{t: t}
			h, _, cleanup := newBlindHandler(t, fc, st.srv.Client())
			defer cleanup()
			cfg := auxCfg(`{"to_issuer":[` + auxToIssuerPSC + `]}`)
			cfg.VCT, cfg.Doctype = tc.vct, tc.doctype
			require.NoError(t, h.issueCredential(context.Background(), st.metadata(nil), tokenBearer(), "cfg", cfg, nil, ""))
			p := generateProofParams(t, fc)
			assert.JSONEq(t, `"`+tc.want+`"`, string(p["credential_type"]))
			assert.JSONEq(t, `"`+st.srv.URL+`"`, string(p["credential_issuer"]))
		})
	}
	// Not sent without to_issuer entries.
	st := newIssuerStub(t, `{"credential":"c"}`)
	fc := &fakeClient{t: t}
	h, _, cleanup := newBlindHandler(t, fc, st.srv.Client())
	defer cleanup()
	cfg := auxCfg("")
	cfg.VCT = "urn:v"
	require.NoError(t, h.issueCredential(context.Background(), st.metadata(nil), tokenBearer(), "cfg", cfg, nil, ""))
	p := generateProofParams(t, fc)
	assert.NotContains(t, p, "credential_type")
	assert.NotContains(t, p, "credential_issuer")

	// No vct or doctype: refused.
	st2 := newIssuerStub(t, `{"credential":"c"}`)
	fc2 := &fakeClient{t: t}
	h2, _, cleanup2 := newBlindHandler(t, fc2, st2.srv.Client())
	defer cleanup2()
	noType := auxCfg(`{"to_issuer":[` + auxToIssuerPSC + `]}`)
	noType.VCT = ""
	require.Error(t, h2.issueCredential(context.Background(), st2.metadata(nil), tokenBearer(), "cfg", noType, nil, ""))
}

// A client that returns an opening fails the flow with its own code, and
// nothing reaches the issuer.
func TestIssuance_OpeningInProofFailsClosed(t *testing.T) {
	st := newIssuerStub(t, `{"credential":"c"}`)
	adv := []json.RawMessage{json.RawMessage(auxToIssuerPSC)}
	claim := validAuxClaim(t, adv, 1)
	claim[0]["opening"] = "SECRET"
	fc := &fakeClient{t: t, proofMaker: func(int, *SignRequestMessage) string { return auxProofJWT(t, claim) }}
	h, _, cleanup := newBlindHandler(t, fc, st.srv.Client())
	defer cleanup()
	cfg := auxCfg(`{"to_issuer":[` + auxToIssuerPSC + `]}`)
	cfg.VCT = "urn:v"
	require.Error(t, h.issueCredential(context.Background(), st.metadata(nil), tokenBearer(), "cfg", cfg, nil, ""))
	assert.Empty(t, st.requests, "nothing is sent to the issuer")
	fc.settle()
	var codes []string
	for _, m := range fc.outboundMessages() {
		if string(m["type"]) == `"flow_error"` {
			var e struct {
				Code string `json:"code"`
			}
			require.NoError(t, json.Unmarshal(m["error"], &e))
			codes = append(codes, e.Code)
		}
	}
	assert.Equal(t, []string{"AUXILIARY_DATA_PROOF_INVALID"}, codes)
}

// An error body over the limit cannot be classified: it is neither logged nor
// retried (even with a DPoP-Nonce header), and is not taken for a conflict.
func TestOversizedErrorBodyFailsClosed(t *testing.T) {
	big := `{"error":"auxiliary_data_conflict","error_description":"SECRET-ISSUER-TEXT ` + strings.Repeat("x", MaxErrorBodyBytes) + `"}`
	for name, dpop := range map[string]bool{"plain": false, "with DPoP-Nonce header": true} {
		t.Run(name, func(t *testing.T) {
			st, hits := conflictStub(t, big, dpop)
			fc := &fakeClient{t: t}
			h, logs, cleanup := newBlindHandler(t, fc, st.srv.Client())
			defer cleanup()
			err := h.issueCredential(context.Background(), st.metadata(gcmCfg(false)), tokenBearer(), "cfg", auxCfg(auxAdvFull), nil, "")
			require.Error(t, err)
			assert.Equal(t, 1, *hits, "never retried")
			fc.settle()
			var terminal int
			for _, m := range fc.outboundMessages() {
				if string(m["type"]) == `"flow_error"` {
					terminal++
				}
			}
			assert.Equal(t, 1, terminal, "the client gets exactly one terminal flow_error")
			assert.NotContains(t, logDump(logs), "SECRET-ISSUER-TEXT")
			assert.NotContains(t, err.Error(), "SECRET-ISSUER-TEXT")
			fc.settle()
			for _, m := range fc.outboundMessages() {
				assert.NotContains(t, string(m["error"]), "SECRET-ISSUER-TEXT")
				assert.NotContains(t, string(m["error"]), "AUXILIARY_DATA_CONFLICT")
			}
		})
	}
}

// An issuer error that is not a conflict (an invalid_proof whose description
// echoes a commitment) is neither logged nor returned beyond its error code
// when the credential carries auxiliary data; the nonce retry still works.
func TestCredentialErrorTextNotLoggedWithAuxiliaryData(t *testing.T) {
	const echo = "COMMITMENT-ECHO-Zm9vYmFy"
	for name, body := range map[string]string{
		"invalid_proof":   `{"error":"invalid_proof","error_description":"the commitment ` + echo + ` is wrong"}`,
		"with c_nonce":    `{"error":"invalid_proof","c_nonce":"n2","error_description":"the commitment ` + echo + ` is wrong"}`,
		"odd error value": `{"error":"not a code ` + echo + `"}`,
	} {
		t.Run(name, func(t *testing.T) {
			st, _ := conflictStub(t, body, false)
			fc := &fakeClient{t: t}
			h, logs, cleanup := newBlindHandler(t, fc, st.srv.Client())
			defer cleanup()
			err := h.issueCredential(context.Background(), st.metadata(gcmCfg(false)), tokenBearer(), "cfg", auxCfg(auxAdvFull), nil, "")
			require.Error(t, err)
			assert.NotContains(t, err.Error(), echo)
			assert.NotContains(t, logDump(logs), echo)
			fc.settle()
			for _, m := range fc.outboundMessages() {
				assert.NotContains(t, string(m["error"]), echo)
			}
		})
	}
}

// A body that fails mid-read is neither logged, classified nor retried.
func TestAuxiliaryDataConflict_ReadFailureFailsClosed(t *testing.T) {
	st := newIssuerStub(t, `{"credential":"c"}`)
	hits := 0
	st.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.Header().Set("DPoP-Nonce", "n1")
		w.Header().Set("Content-Length", "1000")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"auxiliary_data_conflict","error_description":"SECRET-ISSUER-TEXT`)) // cut short
	})
	fc := &fakeClient{t: t}
	h, logs, cleanup := newBlindHandler(t, fc, st.srv.Client())
	defer cleanup()
	require.Error(t, h.issueCredential(context.Background(), st.metadata(gcmCfg(false)), tokenBearer(), "cfg", auxCfg(auxAdvFull), nil, ""))
	assert.Equal(t, 1, hits, "never retried")
	assert.NotContains(t, logDump(logs), "SECRET-ISSUER-TEXT")
	fc.settle()
	var n int
	for _, m := range fc.outboundMessages() {
		if string(m["type"]) == `"flow_error"` {
			n++
		}
	}
	assert.Equal(t, 1, n)
}
