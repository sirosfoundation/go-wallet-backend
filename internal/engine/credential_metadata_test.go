package engine

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

const secretSeedA = "SEED-A-d41d8cd98f00b204e9800998ecf8427e"
const secretSeedB = "SEED-B-0cc175b9c0f1b6a831c399e269772661"

func metaElem(cred, seed string) map[string]interface{} {
	return map[string]interface{}{
		"credential": cred,
		"credential_metadata": []interface{}{
			map[string]interface{}{"type": "org.siros.NS.secret_seed", "value": seed},
		},
	}
}

func parseResp(t *testing.T, body string) *CredentialResponse {
	t.Helper()
	var r CredentialResponse
	require.NoError(t, json.Unmarshal([]byte(body), &r))
	return &r
}

func TestBuildCredentialResults_CredentialMetadata_Plain(t *testing.T) {
	h := &OID4VCIHandler{}
	cfg := &CredentialConfig{Format: "mso_mdoc"}
	resp := parseResp(t, `{"credentials":[{"credential":"mdoc1","credential_metadata":[{"type":"org.siros.NS.secret_seed","value":"`+secretSeedA+`"}]}]}`)
	res, err := h.buildCredentialResults(context.Background(), resp, cfg, nil)
	require.NoError(t, err)
	require.Len(t, res, 1)
	assert.Equal(t, "mdoc1", res[0].Credential)
	require.Len(t, res[0].CredentialMetadata, 1)
	assert.Equal(t, "org.siros.NS.secret_seed", res[0].CredentialMetadata[0].Type)
	assert.JSONEq(t, `"`+secretSeedA+`"`, string(res[0].CredentialMetadata[0].Value))
	assert.False(t, res[0].CredentialMetadataEncryptedResponse)

	wire, err := json.Marshal(res[0])
	require.NoError(t, err)
	assert.Contains(t, string(wire), `"credential_metadata":[{"type":"org.siros.NS.secret_seed","value":"`+secretSeedA+`"}]`)
	assert.NotContains(t, string(wire), "credential_metadata_encrypted_response")
}

func TestBuildCredentialResults_CredentialMetadata_BatchPerCredential(t *testing.T) {
	h := &OID4VCIHandler{}
	resp := &CredentialResponse{Credentials: []interface{}{
		metaElem("c0", secretSeedA),
		"plain-string-cred",
		map[string]interface{}{"credential": "c2"},
		map[string]interface{}{"credential": "c3", "credential_metadata": []interface{}{
			map[string]interface{}{"type": "t1", "value": map[string]interface{}{"k": []interface{}{"x", "y"}}},
			map[string]interface{}{"type": "t2", "value": secretSeedB},
		}},
	}}
	res, err := h.buildCredentialResults(context.Background(), resp, &CredentialConfig{Format: "dc+sd-jwt"}, nil)
	require.NoError(t, err)
	require.Len(t, res, 4)
	assert.JSONEq(t, `"`+secretSeedA+`"`, string(res[0].CredentialMetadata[0].Value))
	assert.Empty(t, res[1].CredentialMetadata)
	assert.Empty(t, res[2].CredentialMetadata)
	require.Len(t, res[3].CredentialMetadata, 2)
	assert.JSONEq(t, `{"k":["x","y"]}`, string(res[3].CredentialMetadata[0].Value))
	assert.JSONEq(t, `"`+secretSeedB+`"`, string(res[3].CredentialMetadata[1].Value))
}

func TestBuildCredentialResults_CredentialMetadata_AbsentUnchanged(t *testing.T) {
	h := &OID4VCIHandler{}
	res, err := h.buildCredentialResults(context.Background(), &CredentialResponse{
		Credentials: []interface{}{map[string]interface{}{"credential": "c"}},
	}, &CredentialConfig{Format: "dc+sd-jwt"}, nil)
	require.NoError(t, err)
	wire, _ := json.Marshal(res[0])
	assert.NotContains(t, string(wire), "credential_metadata")
}

func TestBuildCredentialResults_CredentialMetadata_IgnoresResponseLevelAndSingleForm(t *testing.T) {
	// OID4VCI 1.1 response-level credential_metadata is an unrelated object;
	// the single-credential form carries no sibling.
	h := &OID4VCIHandler{}
	var raw struct {
		CredentialMetadata json.RawMessage `json:"credential_metadata"`
	}
	require.NoError(t, json.Unmarshal([]byte(`{"credential_metadata":{"display":[]}}`), &raw))
	res, err := h.buildCredentialResults(context.Background(), &CredentialResponse{Credential: "c"}, &CredentialConfig{Format: "dc+sd-jwt"}, nil)
	require.NoError(t, err)
	assert.Empty(t, res[0].CredentialMetadata)
}

func TestBuildCredentialResults_CredentialMetadata_Malformed(t *testing.T) {
	big := strings.Repeat("a", maxCredentialMetadataValueBytes+1)
	many := make([]interface{}, maxCredentialMetadataEntries+1)
	for i := range many {
		many[i] = map[string]interface{}{"type": "t", "value": "v"}
	}
	okEntry := func() map[string]interface{} { return map[string]interface{}{"type": "t", "value": secretSeedA} }
	cases := map[string]interface{}{
		"not array":          map[string]interface{}{"type": "t", "value": secretSeedA},
		"string":             secretSeedA,
		"entry not object":   []interface{}{secretSeedA},
		"no type":            []interface{}{map[string]interface{}{"value": secretSeedA}},
		"empty type":         []interface{}{map[string]interface{}{"type": "", "value": secretSeedA}},
		"non-string type":    []interface{}{map[string]interface{}{"type": 7, "value": secretSeedA}},
		"no value":           []interface{}{map[string]interface{}{"type": "t"}},
		"null value":         []interface{}{map[string]interface{}{"type": "t", "value": nil}},
		"extra member":       []interface{}{map[string]interface{}{"type": "t", "value": secretSeedA, "x": 1}},
		"too many entries":   many,
		"value too big":      []interface{}{map[string]interface{}{"type": "t", "value": big}},
		"one bad among good": []interface{}{okEntry(), map[string]interface{}{"type": "t"}},
		"type too long":      []interface{}{map[string]interface{}{"type": strings.Repeat("t", maxCredentialMetadataTypeBytes+1), "value": "v"}},
		"total too big":      []interface{}{bigEntry(7000), bigEntry(7000), bigEntry(7000), bigEntry(7000), bigEntry(7000)},
	}
	for name, md := range cases {
		t.Run(name, func(t *testing.T) {
			h := &OID4VCIHandler{}
			res, err := h.buildCredentialResults(context.Background(), &CredentialResponse{
				Credentials: []interface{}{
					map[string]interface{}{"credential": "good"},
					map[string]interface{}{"credential": "bad", "credential_metadata": md},
				},
			}, &CredentialConfig{Format: "dc+sd-jwt"}, nil)
			require.Error(t, err)
			assert.Nil(t, res, "must not half-pass")
			assert.NotContains(t, err.Error(), secretSeedA, "errors must not leak values")
			assert.Contains(t, err.Error(), "credentials[1]")
		})
	}
}

func bigEntry(n int) map[string]interface{} {
	return map[string]interface{}{"type": "t", "value": strings.Repeat("b", n)}
}

func encryptedCredServer(t *testing.T, body CredentialResponse) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var reqBody map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&reqBody)
		enc, ok := reqBody["credential_response_encryption"].(map[string]interface{})
		require.True(t, ok)
		jwk := enc["jwk"].(map[string]interface{})
		xb, _ := base64.RawURLEncoding.DecodeString(jwk["x"].(string))
		yb, _ := base64.RawURLEncoding.DecodeString(jwk["y"].(string))
		pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(xb), Y: new(big.Int).SetBytes(yb)}
		pt, _ := json.Marshal(body)
		encr, err := jose.NewEncrypter(jose.A128GCM, jose.Recipient{Algorithm: jose.ECDH_ES, Key: pub}, nil)
		require.NoError(t, err)
		jwe, err := encr.Encrypt(pt)
		require.NoError(t, err)
		s, _ := jwe.CompactSerialize()
		w.Header().Set("Content-Type", "application/jwt")
		_, _ = w.Write([]byte(s))
	}))
}

func TestRequestCredential_CredentialMetadata_JWEAndPlainFlag(t *testing.T) {
	body := CredentialResponse{Credentials: []interface{}{metaElem("c0", secretSeedA), metaElem("c1", secretSeedB)}}

	// Encrypted path.
	srv := encryptedCredServer(t, body)
	defer srv.Close()
	h, cleanup := testOID4VCIHandler(t, srv.Client())
	defer cleanup()
	md := &IssuerMetadata{CredentialEndpoint: srv.URL, CredentialResponseEncryption: &CredentialResponseEncryptionConfig{
		AlgValuesSupported: []string{"ECDH-ES"}, EncValuesSupported: []string{"A128GCM"}, EncryptionRequired: true,
	}}
	tok := &TokenResponse{AccessToken: "t", TokenType: "Bearer"}
	cfg := &CredentialConfig{Format: "mso_mdoc"}
	resp, err := h.requestCredential(context.Background(), md, tok, "", cfg, nil)
	require.NoError(t, err)
	res, err := h.buildCredentialResults(context.Background(), resp, cfg, nil)
	require.NoError(t, err)
	require.Len(t, res, 2)
	for i, want := range []string{secretSeedA, secretSeedB} {
		assert.JSONEq(t, `"`+want+`"`, string(res[i].CredentialMetadata[0].Value))
		assert.True(t, res[i].CredentialMetadataEncryptedResponse)
	}

	// Plain path: same body, no encryption negotiated.
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(body)
	}))
	defer plain.Close()
	h2, cleanup2 := testOID4VCIHandler(t, plain.Client())
	defer cleanup2()
	resp, err = h2.requestCredential(context.Background(), &IssuerMetadata{CredentialEndpoint: plain.URL}, tok, "", cfg, nil)
	require.NoError(t, err)
	res, err = h2.buildCredentialResults(context.Background(), resp, cfg, nil)
	require.NoError(t, err)
	require.Len(t, res, 2)
	assert.NotEmpty(t, res[0].CredentialMetadata)
	assert.False(t, res[0].CredentialMetadataEncryptedResponse)
}

func TestPollDeferredCredential_CredentialMetadata(t *testing.T) {
	if testing.Short() {
		t.Skip("deferred polling waits one 5s interval")
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(CredentialResponse{Credentials: []interface{}{metaElem("deferred", secretSeedA)}})
	}))
	defer srv.Close()
	h, cleanup := testOID4VCIHandler(t, srv.Client())
	defer cleanup()
	resp, err := h.pollDeferredCredential(context.Background(), &IssuerMetadata{CredentialIssuer: srv.URL}, &TokenResponse{AccessToken: "t", TokenType: "Bearer"}, "tx1")
	require.NoError(t, err)
	res, err := h.buildCredentialResults(context.Background(), resp, &CredentialConfig{Format: "mso_mdoc"}, nil)
	require.NoError(t, err)
	require.Len(t, res, 1)
	assert.Equal(t, "deferred", res[0].Credential)
	assert.JSONEq(t, `"`+secretSeedA+`"`, string(res[0].CredentialMetadata[0].Value))
	assert.False(t, res[0].CredentialMetadataEncryptedResponse, "deferred responses are never JWE-decrypted")
}

// The values must not reach the logs on the issuance request path, at any level.
func TestRequestCredential_CredentialMetadata_NotLogged(t *testing.T) {
	core, logs := observer.New(zap.DebugLevel)
	body := CredentialResponse{Credentials: []interface{}{metaElem("c0", secretSeedA)}}
	srv := encryptedCredServer(t, body)
	defer srv.Close()
	h, cleanup := testOID4VCIHandler(t, srv.Client())
	defer cleanup()
	h.Logger = zap.New(core)
	md := &IssuerMetadata{CredentialEndpoint: srv.URL, CredentialResponseEncryption: &CredentialResponseEncryptionConfig{
		AlgValuesSupported: []string{"ECDH-ES"}, EncValuesSupported: []string{"A128GCM"}, EncryptionRequired: true,
	}}
	cfg := &CredentialConfig{Format: "mso_mdoc"}
	resp, err := h.requestCredential(context.Background(), md, &TokenResponse{AccessToken: "t", TokenType: "Bearer"}, "", cfg, nil)
	require.NoError(t, err)
	_, err = h.buildCredentialResults(context.Background(), resp, cfg, nil)
	require.NoError(t, err)
	// Malformed variant: the error path must not echo the value either.
	_, err = h.buildCredentialResults(context.Background(), &CredentialResponse{Credentials: []interface{}{
		map[string]interface{}{"credential": "x", "credential_metadata": []interface{}{map[string]interface{}{"type": "t", "value": secretSeedB, "extra": 1}}},
	}}, cfg, nil)
	require.Error(t, err)
	h.Logger.Warn("rejecting credential response", zap.Error(err))

	for _, e := range logs.All() {
		dump := e.Message
		for _, f := range e.Context {
			dump += " " + f.Key + "=" + f.String + " " + func() string {
				if f.Interface != nil {
					b, _ := json.Marshal(f.Interface)
					return string(b)
				}
				return ""
			}()
		}
		assert.NotContains(t, dump, secretSeedA)
		assert.NotContains(t, dump, secretSeedB)
	}
}

// Source scan: the only log lines in oid4vci.go allowed to print a raw
// response body are the known error-status branches (issuer error responses,
// never a 200 credential response). Anything new must be reviewed against
// credential_metadata secrecy.
func TestOID4VCISource_NoResponseBodyLoggedOnSuccessPath(t *testing.T) {
	src, err := os.ReadFile("oid4vci.go")
	require.NoError(t, err)
	logLine := regexp.MustCompile(`Logger\.(Debug|Info|Warn|Error)\(`)
	bodyRef := regexp.MustCompile(`string\(body\)|credResp\b|deferredResp\b|resp\.Credential|zap\.Any\(|credential\)|results\b`)
	allowed := map[string]bool{
		`credential endpoint error`:           true,
		`PAR endpoint error`:                  true,
		`Unexpected deferred response status`: true,
	}
	lines := strings.Split(string(src), "\n")
	for i, l := range lines {
		if !logLine.MatchString(l) {
			continue
		}
		stmt := l
		for j := i + 1; strings.Count(stmt, "(") != strings.Count(stmt, ")") && j < len(lines); j++ {
			stmt += " " + lines[j]
		}
		if bodyRef.MatchString(stmt) {
			ok := false
			for k := range allowed {
				if strings.Contains(stmt, k) {
					ok = true
				}
			}
			if strings.Contains(stmt, `endpoint error", zap.Int("status"`) {
				ok = true // generic logContext+" endpoint error"
			}
			assert.True(t, ok, "oid4vci.go:%d logs a response body: %s", i+1, strings.TrimSpace(l))
		}
	}
}
