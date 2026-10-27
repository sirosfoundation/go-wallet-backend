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
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

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
		"To_Wallet alias":         `{"to_issuer":[` + hc("") + `],"To_Wallet":[` + hc(`,"opening":"SECRETOPENING"`) + `]}`,
		"TO_ISSUER alias":         `{"to_wallet":[` + hc("") + `],"TO_ISSUER":[` + hc("") + `]}`,
		"nested opening":          `{"to_wallet":[{"type":"x","extra":{"opening":"SECRETOPENING"},"extra":null}]}`,
		"Type shadow":             `{"to_issuer":[{"type":"https://x.example/t","Type":"hash_commitment","Opening":"SECRETOPENING"}]}`,
		"opening in unknown type": `{"to_wallet":[{"type":"hash_commitment","type":"x","path":["a"],"opening":"SECRETOPENING"}]}`,
		"required not bool":       `{"to_issuer":[` + hc(`,"required":"yes"`) + `]}`,
		"required null":           `{"to_issuer":[` + hc(`,"required":null`) + `]}`,
		"duplicate escaped path":  `{"to_wallet":[` + hc("") + `,{"type":"hash_commitment","alg":"sha-256","path":["\u0061","b"]}]}`,
		"duplicate unknown path":  `{"to_wallet":[{"type":"https://x.example/t","path":["a"]},{"type":"https://x.example/t","path":[ "\u0061" ]}]}`,
		"required in to_wallet":   `{"to_wallet":[` + hc(`,"required":true`) + `]}`,
		"duplicate type and path": `{"to_wallet":[` + hc("") + `,` + hc("") + `]}`,
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

// auxiliary_data MUST NOT appear in the issuer metadata's credential_metadata
// (v0.1 section 7): the configuration is malformed, and no content is quoted.
func TestAuxiliaryDataInIssuerMetadataIsMalformed(t *testing.T) {
	cfg := &CredentialConfig{CredentialMetadata: json.RawMessage(`{"auxiliary_data":[{"type":"hash_commitment","opening":"SECRETOPENING"}]}`)}
	_, err := secretDeliveryOf(cfg)
	require.Error(t, err)
	assert.NotErrorIs(t, err, errLegacySecretMember)
	assert.NotContains(t, err.Error(), "SECRETOPENING")
}

func TestPlainResponse_AuxiliaryDataRefused(t *testing.T) {
	core, logs := observer.New(zap.DebugLevel)
	h, ch, cleanup := captureHandler(t)
	defer cleanup()
	h.Logger = zap.New(core)
	var resp CredentialResponse
	body := `{"credentials":["c0"],"credential_metadata":{"display":[{"name":"D"}],"auxiliary_data":[{"type":"hash_commitment","opening":"` + secretSeedA + `"}]}}`
	require.NoError(t, json.Unmarshal([]byte(body), &resp))
	err := h.finishIssuance(context.Background(), &resp, &CredentialConfig{Format: "x"}, nil, nil, &TokenResponse{})
	require.Error(t, err)
	assertNoSecrets(t, "error", err.Error())
	m := nextMsg(t, ch)
	assert.JSONEq(t, `"flow_error"`, string(m["type"]))
	assertNoSecrets(t, "logs", logDump(logs))
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

// The classification of a credential endpoint error body: exactly the code is
// a conflict; a body that cannot be read unambiguously is terminal and generic;
// everything else is an ordinary credential error.
func TestAuxiliaryDataConflict_Classification(t *testing.T) {
	const (
		conflict  = "conflict"
		ordinary  = "ordinary"
		ambiguous = "ambiguous"
	)
	for name, tc := range map[string]struct {
		status int
		body   string
		want   string
	}{
		"exact code":           {400, `{"error":"auxiliary_data_conflict"}`, conflict},
		"with description":     {400, `{"error":"auxiliary_data_conflict","error_description":"C"}`, conflict},
		"other status":         {401, `{"error":"auxiliary_data_conflict"}`, ordinary},
		"invalid_proof":        {400, `{"error":"invalid_proof","error_description":"auxiliary_data_conflict"}`, ordinary},
		"different case":       {400, `{"error":"Auxiliary_Data_Conflict"}`, ordinary},
		"in description":       {400, `{"error":"invalid_request","error_description":"auxiliary_data_conflict"}`, ordinary},
		"not json":             {400, `auxiliary_data_conflict`, ordinary},
		"error not string":     {400, `{"error":["auxiliary_data_conflict"]}`, ordinary},
		"encryption params":    {400, `{"error":"invalid_encryption_parameters"}`, ordinary},
		"repeated, null":       {400, `{"error":"auxiliary_data_conflict","error":null}`, ambiguous},
		"repeated, benign":     {400, `{"error":"invalid_request","error":"x"}`, ambiguous},
		"case-variant twin":    {400, `{"error":"auxiliary_data_conflict","ERROR":"invalid_proof"}`, ambiguous},
		"case-variant first":   {400, `{"ERROR":"invalid_proof","error":"auxiliary_data_conflict"}`, ambiguous},
		"only a variant":       {400, `{"ERROR":"auxiliary_data_conflict"}`, ambiguous},
		"trailing value":       {400, `{"error":"invalid_request"} {"error":"auxiliary_data_conflict"}`, ambiguous},
		"huge number":          {400, `{"x":1e400,"error":"auxiliary_data_conflict"}`, conflict},
		"repeated member, 500": {500, `{"error":"x","error":"y","c_nonce":"n"}`, ambiguous},
		"repeated member, 401": {401, `{"error":"auxiliary_data_conflict","ERROR":"x"}`, ambiguous},
	} {
		t.Run(name, func(t *testing.T) {
			h, ch, cleanup := captureHandler(t)
			defer cleanup()
			err := h.auxiliaryDataConflictError(tc.status, []byte(tc.body))
			switch tc.want {
			case ordinary:
				require.NoError(t, err)
			case conflict:
				require.Error(t, err)
				assert.Equal(t, ErrCodeAuxiliaryDataConflict, flowErrorCode(t, nextMsg(t, ch)))
			case ambiguous:
				require.Error(t, err)
				assert.Equal(t, ErrCodeCredentialError, flowErrorCode(t, nextMsg(t, ch)))
			}
		})
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

// rawProofJWT is a proof whose payload is exactly the given JSON text (so a
// repeated or case-variant member can be spelled).
func rawProofJWT(payload string) string {
	return "e30." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".c2ln"
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
	const dupType = `[{"type":"hash_commitment","type":null,"alg":"sha-256","path":["a"],"opening":"SECRET"}]`
	const benign = `[{"type":"hash_commitment","alg":"sha-256","path":["a"],"commitment":"AAAA"}]`
	const secretEntry = `[{"type":"hash_commitment","opening":"SECRET"}]`
	for name, payload := range map[string]string{
		"duplicate type, null last":      `{"auxiliary_data":` + dupType + `}`,
		"duplicate opening, null last":   `{"auxiliary_data":[{"type":"hash_commitment","opening":"SECRET","opening":null}]}`,
		"AUXILIARY_DATA alias":           `{"AUXILIARY_DATA":` + secretEntry + `}`,
		"alias next to benign canonical": `{"auxiliary_data":` + benign + `,"AUXILIARY_DATA":` + secretEntry + `}`,
		"secret first, benign alias":     `{"auxiliary_data":` + secretEntry + `,"Auxiliary_Data":` + benign + `}`,
		"secret first, benign twin":      `{"auxiliary_data":` + secretEntry + `,"auxiliary_data":` + benign + `}`,
		"canonical twice":                `{"auxiliary_data":` + benign + `,"auxiliary_data":` + secretEntry + `}`,
		"opening in an unknown type":     `{"auxiliary_data":[{"type":"hash_commitment","type":"x","opening":"SECRET"}]}`,
		"shadowed nested subtree":        `{"auxiliary_data":[{"type":"x","extra":{"opening":"SECRET"},"extra":null}]}`,
		"shadowed deeper subtree":        `{"auxiliary_data":[{"type":"x","a":{"b":[{"c":{"OPENING":"SECRET"}}],"b":1}}]}`,
		"nested opening":                 `{"auxiliary_data":[{"type":"x","v":{"Opening":"SECRET"}}]}`,
		"trailing object with opening":   `{"nonce":"n"}{"auxiliary_data":` + secretEntry + `}`,
		"trailing value after claim":     `{"auxiliary_data":` + benign + `} 1`,
		"opening beside a huge number":   `{"ignored":1e400,"auxiliary_data":` + secretEntry + `}`,
	} {
		withOpening["raw/jwt/"+name] = []ProofObject{{ProofType: "jwt", JWT: rawProofJWT(payload)}}
		withOpening["raw/attestation/"+name] = []ProofObject{{ProofType: "attestation", Attestation: rawProofJWT(payload)}}
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
		"not a JWT":             {{ProofType: "jwt", JWT: "proof-0"}},
		"payload not base64url": {{ProofType: "jwt", JWT: "a.!!.c"}},
		"unknown proof type":    {{ProofType: "di_vp"}},
		"claim not an array":    proofs("x"),
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

// The same policy holds for deferred polling: an error or an unexpected answer
// that echoes a commitment is neither returned nor logged when the credential
// carries auxiliary data, and is still returned for one that does not.
func TestDeferredPollingErrorTextNotLoggedWithAuxiliaryData(t *testing.T) {
	const echo = "COMMITMENT-ECHO-Zm9vYmFy"
	for name, status := range map[string]int{"400": 400, "unexpected 500": 500} {
		for _, withAux := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s/aux=%v", name, withAux), func(t *testing.T) {
				fastDeferredPolling(t)
				st := newIssuerStub(t, `{"credential":"c"}`)
				st.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(status)
					_, _ = w.Write([]byte(`{"error":"invalid_transaction_id","error_description":"the commitment ` + echo + ` is wrong"}`))
				})
				fc := &fakeClient{t: t}
				h, logs, cleanup := newBlindHandler(t, fc, st.srv.Client())
				defer cleanup()
				cfg := &CredentialConfig{Format: "x"}
				if withAux {
					cfg = auxCfg(auxAdvFull)
				}
				ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
				defer cancel()
				_, err := h.pollDeferredCredential(ctx, st.metadata(nil), tokenBearer(), "tx", 0, nil, cfg)
				require.Error(t, err)
				if withAux {
					assert.NotContains(t, err.Error(), echo)
					assert.NotContains(t, logDump(logs), echo)
				} else if status == 400 {
					assert.Contains(t, err.Error(), echo, "without auxiliary data the existing behaviour is unchanged")
				}
			})
		}
	}
}

// An optional entry of a type the wallet does not recognise must not stop
// ordinary proof generation for a configuration without vct or doctype.
func TestGenerateProof_UnrecognisedToIssuerNeedsNoCredentialType(t *testing.T) {
	st := newIssuerStub(t, `{"credential":"c"}`)
	fc := &fakeClient{t: t}
	h, _, cleanup := newBlindHandler(t, fc, st.srv.Client())
	defer cleanup()
	cfg := auxCfg(`{"to_issuer":[{"type":"https://issuer.example/optional"}]}`)
	cfg.VCT, cfg.Doctype = "", ""
	require.NoError(t, h.issueCredential(context.Background(), st.metadata(nil), tokenBearer(), "cfg", cfg, nil, ""))
	assert.NotEmpty(t, st.requests)
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

// Before the credential request the wallet refuses what it cannot handle
// (Auxiliary Data v0.1 sections 4.1 and 5): a to_wallet hash_commitment entry
// whose alg or encoding the spec does not define, and a required to_issuer
// entry it cannot send. The refusal is at selection, before any authorization.
func TestAuxiliaryData_UnusableConfigurationRefusedBeforeAnyRequest(t *testing.T) {
	hc := func(extra string) string {
		return `{"type":"hash_commitment","alg":"sha-256","path":["a","b"]` + extra + `}`
	}
	for name, tc := range map[string]struct {
		adv    string
		noJWT  bool
		refuse bool
	}{
		"to_wallet alg undefined":            {adv: `{"to_wallet":[{"type":"hash_commitment","alg":"sha-512","path":["a"]}]}`, refuse: true},
		"to_wallet alg wrong case":           {adv: `{"to_wallet":[{"type":"hash_commitment","alg":"SHA-256","path":["a"]}]}`, refuse: true},
		"to_wallet encoding undefined":       {adv: `{"to_wallet":[` + hc(`,"encoding":"base32"`) + `]}`, refuse: true},
		"to_wallet encoding not a string":    {adv: `{"to_wallet":[` + hc(`,"encoding":1`) + `]}`, refuse: true},
		"to_wallet one bad entry of two":     {adv: `{"to_wallet":[` + hc("") + `,{"type":"hash_commitment","alg":"md5","path":["a","c"]}]}`, refuse: true},
		"required to_issuer unknown type":    {adv: `{"to_issuer":[{"type":"https://x.example/t","required":true}]}`, refuse: true},
		"required to_issuer alg undefined":   {adv: `{"to_issuer":[{"type":"hash_commitment","alg":"sha-1","path":["a"],"required":true}]}`, refuse: true},
		"required to_issuer encoding":        {adv: `{"to_issuer":[` + hc(`,"encoding":"rot13","required":true`) + `]}`, refuse: true},
		"required to_issuer without a proof": {adv: `{"to_issuer":[` + hc(`,"required":true`) + `]}`, noJWT: true, refuse: true},
		"to_wallet sha-256, no encoding":     {adv: `{"to_wallet":[` + hc("") + `]}`},
		"to_wallet base64url":                {adv: `{"to_wallet":[` + hc(`,"encoding":"base64url"`) + `]}`},
		"to_wallet base64":                   {adv: `{"to_wallet":[` + hc(`,"encoding":"base64"`) + `]}`},
		"to_wallet hex":                      {adv: `{"to_wallet":[` + hc(`,"encoding":"hex"`) + `]}`},
		"to_wallet unknown type ignored":     {adv: `{"to_wallet":[{"type":"https://x.example/t","alg":"x"}]}`},
		"optional to_issuer bad alg ignored": {adv: `{"to_issuer":[{"type":"hash_commitment","alg":"sha-1","path":["a"]}]}`},
		"optional to_issuer unknown ignored": {adv: `{"to_issuer":[{"type":"https://x.example/t"}]}`},
		"unknown type with a numeric alg":    {adv: `{"to_issuer":[{"type":"https://x.example/t","alg":123}]}`},
		"required to_issuer, jwt proof":      {adv: `{"to_issuer":[` + hc(`,"required":true`) + `]}`},
		"optional to_issuer without a proof": {adv: `{"to_issuer":[` + hc("") + `]}`, noJWT: true},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := auxCfg(tc.adv)
			if tc.noJWT {
				cfg.ProofTypesSupported = nil
			}
			var md IssuerMetadata
			md.CredentialConfigurationsSupported = CredentialConfigurations{"cfg": *cfg}
			offer := &CredentialOffer{CredentialConfigurationIDs: []string{"cfg"}}
			h, ch, cleanup := captureHandler(t)
			defer cleanup()
			_, _, err := h.awaitCredentialSelection(context.Background(), offer, &md)
			if !tc.refuse {
				require.NoError(t, err)
				return
			}
			require.ErrorIs(t, err, errAuxiliaryDataUnsupported)
			assert.Equal(t, ErrCodeAuxiliaryDataUnsupported, flowErrorCode(t, nextMsg(t, ch)))

			// Defence in depth: a configuration that gets past selection
			// reaches neither the issuer nor the client.
			st := newIssuerStub(t, `{"credential":"c"}`)
			fc := &fakeClient{t: t}
			h2, _, cleanup2 := newBlindHandler(t, fc, st.srv.Client())
			defer cleanup2()
			err = h2.issueCredential(context.Background(), st.metadata(gcmCfg(false)), tokenBearer(), "cfg", cfg, nil, "")
			require.ErrorIs(t, err, errAuxiliaryDataUnsupported)
			assert.Empty(t, st.requests)
			assert.Empty(t, fc.actions())
		})
	}
}

// One usable configuration is selected over a refused one; the refusal is not
// reported to the client when something else can be used.
func TestAuxiliaryData_RefusedConfigurationNotOfferedBesideUsableOne(t *testing.T) {
	bad := auxCfg(`{"to_wallet":[{"type":"hash_commitment","alg":"sha-512","path":["a"]}]}`)
	good := auxCfg(auxAdvFull)
	md := IssuerMetadata{CredentialConfigurationsSupported: CredentialConfigurations{"bad": *bad, "good": *good}}
	offer := &CredentialOffer{CredentialConfigurationIDs: []string{"bad", "good"}}
	h, ch, cleanup := captureHandler(t)
	defer cleanup()
	id, _, err := h.awaitCredentialSelection(context.Background(), offer, &md)
	require.NoError(t, err)
	assert.Equal(t, "good", id)
	select {
	case m := <-ch:
		t.Fatalf("unexpected %s", m["type"])
	default:
	}
}

// The client is told which entries the issuer will send (to_wallet) and which
// the wallet may send (to_issuer, minus what it cannot send), so it can check
// the response and refuse.
func TestGenerateProof_CarriesToWalletAndSendableToIssuer(t *testing.T) {
	st := newIssuerStub(t, seedResponse)
	fc := &fakeClient{t: t}
	h, _, cleanup := newBlindHandler(t, fc, st.srv.Client())
	defer cleanup()
	const dropped = `{"type":"hash_commitment","alg":"sha-1","path":["a","old"]}`
	const toWallet = `{"type":"hash_commitment","alg":"sha-256","encoding":"hex","path":["a","ssc"]}`
	adv := `{"to_wallet":[` + toWallet + `],"to_issuer":[` + auxToIssuerPSC + `,` + dropped + `]}`
	cfg := auxCfg(adv)
	require.NoError(t, h.issueCredential(context.Background(), st.metadata(gcmCfg(false)), tokenBearer(), "cfg", cfg, nil, ""))
	p := generateProofParams(t, fc)
	var w, i []json.RawMessage
	require.NoError(t, json.Unmarshal(p["auxiliary_data_to_wallet"], &w))
	require.NoError(t, json.Unmarshal(p["auxiliary_data_to_issuer"], &i))
	require.Len(t, w, 1)
	assert.JSONEq(t, toWallet, string(w[0]))
	require.Len(t, i, 1, "an entry the wallet cannot send is not passed on")
	assert.JSONEq(t, auxToIssuerPSC, string(i[0]))
}

// An optional entry the wallet drops does not make the credential type
// mandatory: only an entry it will send does.
func TestGenerateProof_DroppedEntryNeedsNoCredentialType(t *testing.T) {
	st := newIssuerStub(t, `{"credential":"c"}`)
	fc := &fakeClient{t: t}
	h, _, cleanup := newBlindHandler(t, fc, st.srv.Client())
	defer cleanup()
	cfg := auxCfg(`{"to_issuer":[{"type":"hash_commitment","alg":"sha-1","path":["a"]},{"type":"https://x.example/t","alg":123}]}`)
	cfg.VCT = ""
	require.NoError(t, h.issueCredential(context.Background(), st.metadata(nil), tokenBearer(), "cfg", cfg, nil, ""))
}

// A pending response (immediate or deferred) is a plain response too: a
// forbidden member ends the issuance there, before its metadata is discarded.
func TestPendingPlainResponse_ForbiddenMemberRefused(t *testing.T) {
	for name, member := range map[string]string{
		"auxiliary_data": `"auxiliary_data":[{"type":"hash_commitment","opening":"` + secretSeedA + `"}]`,
		"legacy":         `"org.siros.secret_seed":{"ns":"` + secretSeedA + `"}`,
	} {
		pending := `{"transaction_id":"t1","interval":1,"credential_metadata":{` + member + `}}`
		t.Run("credential response/"+name, func(t *testing.T) {
			st := newIssuerStub(t, pending)
			fc := &fakeClient{t: t}
			h, logs, cleanup := newBlindHandler(t, fc, st.srv.Client())
			defer cleanup()
			err := h.issueCredential(context.Background(), st.metadata(nil), tokenBearer(), "cfg", auxCfg(""), nil, "")
			require.Error(t, err)
			assert.Len(t, st.requests, 1, "no polling follows")
			assertNoSecrets(t, "error", err.Error())
			assertNoSecrets(t, "logs", logDump(logs))
		})
		t.Run("deferred 202/"+name, func(t *testing.T) {
			h, _, cleanup := captureHandler(t)
			defer cleanup()
			p := &deferredPoll{h: h}
			_, done, err := p.plainAnswer(http.StatusAccepted, []byte(pending), 0)
			require.Error(t, err)
			assert.True(t, done)
			assertNoSecrets(t, "error", err.Error())
		})
	}
}

// An optional to_issuer entry with no proof type to carry it must not break an
// issuance that only asks the client for a response-encryption key.
func TestGenerateProof_OptionalEntryWithoutProofTypeNeedsNoCredentialType(t *testing.T) {
	st := newIssuerStub(t, seedResponse)
	fc := &fakeClient{t: t}
	h, _, cleanup := newBlindHandler(t, fc, st.srv.Client())
	defer cleanup()
	cfg := auxCfg(`{"to_wallet":[` + auxToWalletSSC + `],"to_issuer":[{"type":"hash_commitment","alg":"sha-256","path":["a","b"]}]}`)
	cfg.VCT, cfg.ProofTypesSupported, cfg.Format = "", nil, "vc+sd-jwt"
	require.NoError(t, h.issueCredential(context.Background(), st.metadata(gcmCfg(false)), tokenBearer(), "cfg", cfg, nil, ""))
	assert.NotContains(t, generateProofParams(t, fc), "auxiliary_data_to_issuer")
}

// The response JSON is read strictly: a repeated credential_metadata cannot
// shadow a forbidden member, and a pending body that cannot be read ends the
// issuance instead of being skipped. Exactly one terminal flow_error is sent,
// the one naming the reason.
func TestPlainResponse_AmbiguousOrUnreadableEndsIssuance(t *testing.T) {
	old1, old2 := deferredPollDefaultInterval, deferredPollIntervalUnit
	deferredPollDefaultInterval, deferredPollIntervalUnit = time.Millisecond, time.Millisecond
	defer func() { deferredPollDefaultInterval, deferredPollIntervalUnit = old1, old2 }()
	secret := `"auxiliary_data":[{"type":"hash_commitment","opening":"` + secretSeedA + `"}]`
	legacy := `"org.siros.secret_seed":{"ns":"` + secretSeedA + `"}`
	for name, tc := range map[string]struct {
		first, deferred string
		deferredStatus  int
		code            ErrorCode
	}{
		"immediate, shadowed by a repeated member": {`{"credential":"c","credential_metadata":{` + secret + `},"credential_metadata":null}`, "", 0, ErrCodeCredentialError},
		"deferred 200, shadowed":                   {`{"transaction_id":"t"}`, `{"credential":"c","credential_metadata":{` + secret + `},"credential_metadata":null}`, 200, ErrCodeCredentialError},
		"deferred 202, shadowed":                   {`{"transaction_id":"t"}`, `{"credential_metadata":{` + secret + `},"credential_metadata":null}`, 202, ErrCodeCredentialError},
		"deferred 202, unreadable interval":        {`{"transaction_id":"t"}`, `{"interval":"bad","credential_metadata":{` + legacy + `}}`, 202, ErrCodeCredentialError},
		"deferred 202, legacy member":              {`{"transaction_id":"t"}`, `{"credential_metadata":{` + legacy + `}}`, 202, ErrCodeLegacySecretMember},
		"deferred 202, auxiliary_data":             {`{"transaction_id":"t"}`, `{"credential_metadata":{` + secret + `}}`, 202, ErrCodeCredentialError},
	} {
		t.Run(name, func(t *testing.T) {
			st := newIssuerStub(t, tc.first)
			st.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.HasSuffix(r.URL.Path, "/deferred_credential") {
					w.WriteHeader(tc.deferredStatus)
					_, _ = w.Write([]byte(tc.deferred))
					return
				}
				_, _ = w.Write([]byte(tc.first))
			})
			fc := &fakeClient{t: t}
			h, logs, cleanup := newBlindHandler(t, fc, st.srv.Client())
			defer cleanup()
			err := h.issueCredential(context.Background(), st.metadata(nil), tokenBearer(), "cfg", auxCfg(""), nil, "")
			require.Error(t, err)
			assertNoSecrets(t, "error", err.Error())
			assertNoSecrets(t, "logs", logDump(logs))
			fc.settle()
			var codes []ErrorCode
			for _, m := range fc.outboundMessages() {
				switch string(m["type"]) {
				case `"flow_error"`:
					var e FlowError
					require.NoError(t, json.Unmarshal(m["error"], &e))
					codes = append(codes, e.Code)
				case `"flow_complete"`:
					t.Fatal("the issuance must not complete")
				}
			}
			if tc.code == ErrCodeCredentialError && tc.first == tc.deferred {
				return
			}
			assert.Len(t, codes, 1, "exactly one terminal error")
			if len(codes) == 1 {
				assert.Equal(t, tc.code, codes[0])
			}
		})
	}
}

// A conflict answered to a deferred request is terminal, with or without a
// DPoP-Nonce header, and reported once with its own code.
func TestAuxiliaryDataConflict_DeferredIsTerminalAndReportedOnce(t *testing.T) {
	old1, old2 := deferredPollDefaultInterval, deferredPollIntervalUnit
	deferredPollDefaultInterval, deferredPollIntervalUnit = time.Millisecond, time.Millisecond
	defer func() { deferredPollDefaultInterval, deferredPollIntervalUnit = old1, old2 }()
	for name, nonce := range map[string]bool{"plain": false, "with DPoP-Nonce header": true} {
		t.Run(name, func(t *testing.T) {
			polls := 0
			st := newIssuerStub(t, `{"transaction_id":"t"}`)
			st.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if !strings.HasSuffix(r.URL.Path, "/deferred_credential") {
					_, _ = w.Write([]byte(`{"transaction_id":"t"}`))
					return
				}
				polls++
				if nonce {
					w.Header().Set("DPoP-Nonce", "n1")
				}
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":"auxiliary_data_conflict","error_description":"SECRET-ISSUER-TEXT"}`))
			})
			fc := &fakeClient{t: t}
			h, logs, cleanup := newBlindHandler(t, fc, st.srv.Client())
			defer cleanup()
			require.Error(t, h.issueCredential(context.Background(), st.metadata(nil), tokenBearer(), "cfg", auxCfg(""), nil, ""))
			assert.Equal(t, 1, polls, "never retried")
			assertNoSecrets(t, "logs", logDump(logs))
			assert.NotContains(t, logDump(logs), "SECRET-ISSUER-TEXT")
			fc.settle()
			var codes []ErrorCode
			for _, m := range fc.outboundMessages() {
				if string(m["type"]) == `"flow_error"` {
					var e FlowError
					require.NoError(t, json.Unmarshal(m["error"], &e))
					codes = append(codes, e.Code)
				}
			}
			assert.Equal(t, []ErrorCode{ErrCodeAuxiliaryDataConflict}, codes)
		})
	}
}
