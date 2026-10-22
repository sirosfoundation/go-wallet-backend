package engine

import (
	"fmt"
	"time"

	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"github.com/gorilla/websocket"
	"go.uber.org/zap/zapcore"
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

const secretSeedA = "d41d8cd98f00b204e9800998ecf8427e"
const secretSeedB = "0cc175b9c0f1b6a831c399e269772661"

// Deliberately awkward spellings: integer, 1.50, 2.0, big int, nested object
// and array, null, unknown members; whitespace is insignificant.
const fidelityMD = `{"org.siros.secret_seed":{"ns1":"` + secretSeedA + `","ns2":"` + secretSeedB + `"},` +
	`"org.example.ext":{"n":1.50,"m":2.0,"big":12345678901234567890,"arr":[1,{"z":null}],"s":"x"},"alg":"ES256","count":7}`

// seedNS returns n distinct "<name>":"<seed>" members with names of nameLen bytes.
func seedNS(n, nameLen int) string {
	var parts []string
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("%0*d", nameLen, i)
		parts = append(parts, `"`+name+`":"`+secretSeedA+`"`)
	}
	return strings.Join(parts, ",")
}

func bodyWithMD(md string) string {
	return `{"credentials":[{"credential":"c0"},{"credential":"c1"}],"notification_id":"n-1","credential_metadata":` + md + `}`
}

func parseResp(t *testing.T, body string) *CredentialResponse {
	t.Helper()
	var r CredentialResponse
	require.NoError(t, json.Unmarshal([]byte(body), &r))
	return &r
}

func TestCredentialMetadataRelay_VerbatimUnknownMembersAndSpelling(t *testing.T) {
	spaced := strings.NewReplacer(",", " ,\n ", ":", " : ").Replace(fidelityMD)
	relay, err := credentialMetadataRelay(parseResp(t, bodyWithMD(spaced)))
	require.NoError(t, err)
	require.NotNil(t, relay)
	assert.Equal(t, fidelityMD, string(relay.Metadata), "members, order, number spelling preserved; only whitespace removed")
	assert.False(t, relay.Encrypted)
}

func TestCredentialMetadataRelay_Absent(t *testing.T) {
	relay, err := credentialMetadataRelay(parseResp(t, `{"credentials":[{"credential":"c"}]}`))
	require.NoError(t, err)
	assert.Nil(t, relay)
	relay, err = credentialMetadataRelay(nil)
	require.NoError(t, err)
	assert.Nil(t, relay)
}

func TestCredentialMetadataRelay_WithinLimits(t *testing.T) {
	deep := strings.Repeat(`{"a":`, maxCredentialMetadataDepth) + `1` + strings.Repeat(`}`, maxCredentialMetadataDepth)
	var many []string
	for i := 0; i < maxCredentialMetadataMembers; i++ {
		many = append(many, fmt.Sprintf(`"k%d":%d`, i, i))
	}
	for name, md := range map[string]string{
		"empty object":             `{}`,
		"only unknown":             `{"org.example.x":{"a":[1,2,3]}}`,
		"max depth":                deep,
		"max members":              `{` + strings.Join(many, ",") + `}`,
		"max key length":           `{"` + strings.Repeat("k", maxCredentialMetadataKeyLen) + `":1}`,
		"max seed namespaces":      `{"org.siros.secret_seed":{` + seedNS(maxSeedNamespaces, maxSeedNamespaceBytes) + `}}`,
		"same key in separate obj": `{"a":{"x":1},"b":{"x":2}}`,
		"huge number":              `{"org.example.ext":{"n":1e400,"big":123456789012345678901234567890,"m":1.50,"neg":-1E-999}}`,
		"nested duplicate names":   `{"display":[{"name":"a","name":"b"}]}`,
		"display data with logo":   `{"display":[{"name":"A","locale":"en","logo":{"uri":"data:image/png;base64,AAAA","alt_text":"x"},"background_image":{"uri":"data:image/png;base64,BBBB"}}],"claims":[{"path":["a"],"display":[{"name":"A"}]}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := credentialMetadataRelay(parseResp(t, bodyWithMD(md)))
			require.NoError(t, err)
		})
	}
}

func TestCredentialMetadataRelay_Malformed(t *testing.T) {
	deep := strings.Repeat(`{"a":`, maxCredentialMetadataDepth+1) + `1` + strings.Repeat(`}`, maxCredentialMetadataDepth+1)
	deepArr := `{"a":` + strings.Repeat(`[`, maxCredentialMetadataDepth) + strings.Repeat(`]`, maxCredentialMetadataDepth) + `}`
	var many, manyNested []string
	for i := 0; i <= maxCredentialMetadataMembers; i++ {
		many = append(many, fmt.Sprintf(`"k%d":"`+secretSeedA+`"`, i))
		manyNested = append(manyNested, fmt.Sprintf(`"k%d":1`, i))
	}
	cases := map[string]string{
		"array":                 `[{"org.siros.secret_seed":{"n":"` + secretSeedA + `"}}]`,
		"string":                `"` + secretSeedA + `"`,
		"number":                `7`,
		"null":                  `null`,
		"array of objects":      `[{"org.siros.secret_seed":{"n":"` + secretSeedA + `"}}]`,
		"too many members":      `{` + strings.Join(many, ",") + `}`,
		"too many nested":       `{"x":{` + strings.Join(manyNested, ",") + `}}`,
		"too deep objects":      deep,
		"too deep arrays":       deepArr,
		"key too long":          `{"` + strings.Repeat("k", maxCredentialMetadataKeyLen+1) + `":"` + secretSeedA + `"}`,
		"nested key too long":   `{"x":{"` + strings.Repeat("k", maxCredentialMetadataKeyLen+1) + `":1}}`,
		"too big":               `{"x":"` + strings.Repeat("p", maxCredentialMetadataBytes) + `"}`,
		"duplicate top key":     `{"x":1,"x":2}`,
		"duplicate seed key":    `{"org.siros.secret_seed":{"n":"` + secretSeedA + `","n":"` + secretSeedB + `"}}`,
		"duplicate seed member": `{"org.siros.secret_seed":{"n":"` + secretSeedA + `"},"org.siros.secret_seed":{"n":"` + secretSeedB + `"}}`,
		"seed not object":       `{"org.siros.secret_seed":"` + secretSeedA + `"}`,
		"seed array":            `{"org.siros.secret_seed":["` + secretSeedA + `"]}`,
		"seed empty":            `{"org.siros.secret_seed":{}}`,
		"seed null":             `{"org.siros.secret_seed":null}`,
		"seed non-string":       `{"org.siros.secret_seed":{"n":7}}`,
		"seed empty ns":         `{"org.siros.secret_seed":{"":"` + secretSeedA + `"}}`,
		"seed empty value":      `{"org.siros.secret_seed":{"n":""}}`,
		"seed uppercase hex":    `{"org.siros.secret_seed":{"n":"` + strings.ToUpper(secretSeedA) + `"}}`,
		"seed odd length":       `{"org.siros.secret_seed":{"n":"` + secretSeedA + `a"}}`,
		"seed non hex":          `{"org.siros.secret_seed":{"n":"` + secretSeedA[:30] + `zz"}}`,
		"seed 31 chars":         `{"org.siros.secret_seed":{"n":"` + secretSeedA[:31] + `"}}`,
		"seed 34 chars":         `{"org.siros.secret_seed":{"n":"` + secretSeedA + `ab"}}`,
		"too many namespaces":   `{"org.siros.secret_seed":{` + seedNS(maxSeedNamespaces+1, 4) + `}}`,
		"namespace too long":    `{"org.siros.secret_seed":{` + seedNS(1, maxSeedNamespaceBytes+1) + `}}`,
		"reserved namespace":    `{"org.siros.secret_seed":{"namespaces":"` + secretSeedA + `"}}`,
		"advertisement form":    `{"org.siros.secret_seed":{"namespaces":["org.siros.nym_auth"]}}`,
	}
	for name, md := range cases {
		t.Run(name, func(t *testing.T) {
			relay, err := credentialMetadataRelay(parseResp(t, bodyWithMD(md)))
			require.Error(t, err)
			assert.Nil(t, relay)
			for _, secret := range []string{secretSeedA, secretSeedB, strings.ToUpper(secretSeedA)} {
				assert.NotContains(t, err.Error(), secret, "errors must not leak values")
			}
		})
	}
}

// credential_metadata applies to the whole response, so it travels on the
// flow-complete message and not in the per-result entries.
func TestBuildCredentialResults_DoesNotCarryCredentialMetadata(t *testing.T) {
	h := &OID4VCIHandler{}
	res := h.buildCredentialResults(context.Background(), parseResp(t, bodyWithMD(fidelityMD)), &CredentialConfig{Format: "mso_mdoc"}, nil)
	require.Len(t, res, 2)
	wire, err := json.Marshal(res)
	require.NoError(t, err)
	assert.NotContains(t, string(wire), "credential_metadata")
	assert.NotContains(t, string(wire), secretSeedA)
}

// captureHandler returns a handler whose session echoes every sent message to
// the returned channel.
func captureHandler(t *testing.T) (*OID4VCIHandler, chan map[string]json.RawMessage, func()) {
	t.Helper()
	msgs := make(chan map[string]json.RawMessage, 8)
	conn, cleanup := wsTestServer(t, func(srvConn *websocket.Conn) {
		defer srvConn.Close()
		for {
			_, data, err := srvConn.ReadMessage()
			if err != nil {
				return
			}
			var m map[string]json.RawMessage
			if json.Unmarshal(data, &m) == nil {
				msgs <- m
			}
		}
	})
	session := testSession(conn)
	flow := &Flow{ID: "f1", Session: session, Data: map[string]interface{}{}}
	h := &OID4VCIHandler{clientAuthMode: clientAuthLegacy, legacyAttestationRequested: true}
	h.BaseHandler = BaseHandler{Flow: flow, Logger: zap.NewNop()}
	return h, msgs, cleanup
}

func nextMsg(t *testing.T, ch chan map[string]json.RawMessage) map[string]json.RawMessage {
	t.Helper()
	select {
	case m := <-ch:
		return m
	case <-time.After(5 * time.Second):
		t.Fatal("no message sent: flow hung")
		return nil
	}
}

// Same awkward members, but no seed: a plain response may carry this.
const fidelityNoSeedMD = `{"org.example.ext":{"n":1.50,"m":2.0,"big":12345678901234567890},"alg":"ES256","count":7}`

func TestFinishIssuance_RelaysCredentialMetadataOnFlowComplete(t *testing.T) {
	for _, step := range []FlowStep{StepRequestingCredential, StepDeferred} {
		for _, enc := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/encrypted=%v", step, enc), func(t *testing.T) {
				h, ch, cleanup := captureHandler(t)
				defer cleanup()
				want := fidelityNoSeedMD
				if enc {
					want = fidelityMD // only an encrypted response may carry a seed
				}
				resp := parseResp(t, bodyWithMD(want))
				resp.Encrypted = enc
				require.NoError(t, h.finishIssuance(context.Background(), step, resp, &CredentialConfig{Format: "mso_mdoc"}, nil, nil, &TokenResponse{}))
				m := nextMsg(t, ch)
				assert.JSONEq(t, `"flow_complete"`, string(m["type"]))
				assert.Equal(t, want, string(m["credential_metadata"]), "object relayed verbatim at top level")
				_, hasFlag := m["credential_metadata_encrypted_response"]
				assert.Equal(t, enc, hasFlag)
				if enc {
					assert.JSONEq(t, `true`, string(m["credential_metadata_encrypted_response"]))
				}
				var creds []map[string]json.RawMessage
				require.NoError(t, json.Unmarshal(m["credentials"], &creds))
				require.Len(t, creds, 2)
				for _, c := range creds {
					_, per := c["credential_metadata"]
					assert.False(t, per, "credential_metadata only at response level")
				}
			})
		}
	}
}

func TestFinishIssuance_AbsentMetadataOmitsFields(t *testing.T) {
	h, ch, cleanup := captureHandler(t)
	defer cleanup()
	resp := parseResp(t, `{"credentials":[{"credential":"c"}]}`)
	resp.Encrypted = true
	require.NoError(t, h.finishIssuance(context.Background(), StepRequestingCredential, resp, &CredentialConfig{Format: "x"}, nil, nil, &TokenResponse{}))
	m := nextMsg(t, ch)
	_, a := m["credential_metadata"]
	_, b := m["credential_metadata_encrypted_response"]
	assert.False(t, a)
	assert.False(t, b)
}

func TestFinishIssuance_MalformedFailsCleanly(t *testing.T) {
	for _, step := range []FlowStep{StepRequestingCredential, StepDeferred} {
		t.Run(string(step), func(t *testing.T) {
			h, ch, cleanup := captureHandler(t)
			defer cleanup()
			resp := parseResp(t, bodyWithMD(`{"org.siros.secret_seed":{"n":"NOT-HEX-`+secretSeedA+`"}}`))
			err := h.finishIssuance(context.Background(), step, resp, &CredentialConfig{Format: "x"}, nil, nil, &TokenResponse{})
			require.Error(t, err)
			m := nextMsg(t, ch)
			assert.JSONEq(t, `"flow_error"`, string(m["type"]))
			assert.Contains(t, string(m["error"]), string(ErrCodeCredentialError))
			assert.NotContains(t, string(m["error"]), secretSeedA)
			select {
			case extra := <-ch:
				t.Fatalf("unexpected extra message %s", extra["type"])
			case <-time.After(100 * time.Millisecond):
			}
		})
	}
}

func TestFlowCompleteMessage_Redacted(t *testing.T) {
	m := FlowCompleteMessage{
		Credentials:                         []CredentialResult{{Credential: "c"}},
		CredentialMetadata:                  json.RawMessage(fidelityMD),
		CredentialMetadataEncryptedResponse: true,
	}
	r := m.Redacted()
	wire, err := json.Marshal(r)
	require.NoError(t, err)
	assert.NotContains(t, string(wire), "credential_metadata")
	assert.NotContains(t, string(wire), secretSeedA)
	assert.Contains(t, string(wire), `"credential":"c"`)
	assert.NotNil(t, m.CredentialMetadata, "original untouched")
}

func encryptedCredServer(t *testing.T, body CredentialResponse) *httptest.Server {
	t.Helper()
	pt, err := json.Marshal(body)
	require.NoError(t, err)
	return encryptedRawServer(t, string(pt))
}

// encryptedRawServer JWE-encrypts the given raw JSON body for the requester's key.
func encryptedRawServer(t *testing.T, raw string) *httptest.Server {
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
		pt := []byte(raw)
		encr, err := jose.NewEncrypter(jose.A128GCM, jose.Recipient{Algorithm: jose.ECDH_ES, Key: pub}, nil)
		require.NoError(t, err)
		jwe, err := encr.Encrypt(pt)
		require.NoError(t, err)
		s, _ := jwe.CompactSerialize()
		w.Header().Set("Content-Type", "application/jwt")
		_, _ = w.Write([]byte(s))
	}))
}

func issuerEnc(srvURL string) *IssuerMetadata {
	return &IssuerMetadata{CredentialEndpoint: srvURL, CredentialResponseEncryption: &CredentialResponseEncryptionConfig{
		AlgValuesSupported: []string{"ECDH-ES"}, EncValuesSupported: []string{"A128GCM"}, EncryptionRequired: true,
	}}
}

func TestRequestCredential_CredentialMetadata_JWEAndPlainFlag(t *testing.T) {
	body := bodyWithMD(fidelityMD)
	tok := &TokenResponse{AccessToken: "t", TokenType: "Bearer"}
	cfg := &CredentialConfig{Format: "mso_mdoc"}

	srv := encryptedRawServer(t, body)
	defer srv.Close()
	h, cleanup := testOID4VCIHandler(t, srv.Client())
	defer cleanup()
	resp, err := h.requestCredential(context.Background(), issuerEnc(srv.URL), tok, "", cfg, nil)
	require.NoError(t, err)
	relay, err := credentialMetadataRelay(resp)
	require.NoError(t, err)
	require.NotNil(t, relay)
	assert.Equal(t, fidelityMD, string(relay.Metadata))
	assert.True(t, relay.Encrypted)

	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	defer plain.Close()
	h2, cleanup2 := testOID4VCIHandler(t, plain.Client())
	defer cleanup2()
	resp, err = h2.requestCredential(context.Background(), &IssuerMetadata{CredentialEndpoint: plain.URL}, tok, "", cfg, nil)
	require.NoError(t, err)
	relay, err = credentialMetadataRelay(resp)
	require.NoError(t, err)
	require.NotNil(t, relay)
	assert.Equal(t, fidelityMD, string(relay.Metadata))
	assert.False(t, relay.Encrypted)
}

func TestPollDeferredCredential_CredentialMetadata(t *testing.T) {
	if testing.Short() {
		t.Skip("deferred polling waits one 5s interval")
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(bodyWithMD(fidelityMD)))
	}))
	defer srv.Close()
	h, cleanup := testOID4VCIHandler(t, srv.Client())
	defer cleanup()
	resp, err := h.pollDeferredCredential(context.Background(), &IssuerMetadata{CredentialIssuer: srv.URL}, &TokenResponse{AccessToken: "t", TokenType: "Bearer"}, "tx1")
	require.NoError(t, err)
	relay, err := credentialMetadataRelay(resp)
	require.NoError(t, err)
	require.NotNil(t, relay)
	assert.Equal(t, fidelityMD, string(relay.Metadata))
	assert.False(t, relay.Encrypted, "deferred responses are never JWE-decrypted")
}

// The values must not reach the logs on the issuance request path, at any level.
func TestRequestCredential_CredentialMetadata_NotLogged(t *testing.T) {
	core, logs := observer.New(zap.DebugLevel)
	srv := encryptedRawServer(t, bodyWithMD(fidelityMD))
	defer srv.Close()
	h, cleanup := testOID4VCIHandler(t, srv.Client())
	defer cleanup()
	h.Logger = zap.New(core)
	cfg := &CredentialConfig{Format: "mso_mdoc"}
	resp, err := h.requestCredential(context.Background(), issuerEnc(srv.URL), &TokenResponse{AccessToken: "t", TokenType: "Bearer"}, "", cfg, nil)
	require.NoError(t, err)
	_, err = credentialMetadataRelay(resp)
	require.NoError(t, err)
	// Malformed variant through the full finish path (logs a warning).
	h.Flow.Session.notifications = nil
	bad := parseResp(t, bodyWithMD(`{"EXTRA-SECRET-MEMBER":"EXTRA-SECRET-MEMBER","org.siros.secret_seed":{"n":"`+strings.ToUpper(secretSeedB)+`"}}`))
	require.Error(t, h.finishIssuance(context.Background(), StepRequestingCredential, bad, cfg, nil, nil, &TokenResponse{}))

	require.NotEmpty(t, logs.All())
	for _, e := range logs.All() {
		dump := e.Message
		for _, f := range e.Context {
			dump += " " + f.Key + "=" + f.String
			if f.Interface != nil {
				b, _ := json.Marshal(f.Interface)
				dump += string(b)
			}
			if f.Type == zapcore.ErrorType && f.Interface != nil {
				dump += f.Interface.(error).Error()
			}
		}
		for _, secret := range []string{secretSeedA, secretSeedB, strings.ToUpper(secretSeedB), "EXTRA-SECRET-MEMBER"} {
			assert.NotContains(t, dump, secret)
		}
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

// --- issuer-metadata seed advertisement: encryption is mandatory ---

func seedCfg(cm string) *CredentialConfig {
	c := &CredentialConfig{Format: "mso_mdoc"}
	if cm != "" {
		c.CredentialMetadata = json.RawMessage(cm)
	}
	return c
}

const advOK = `{"display":[{"name":"x"}],"org.siros.secret_seed":{"namespaces":["org.iso.18013.5.1"]}}`

func TestSecretSeedAdvertised(t *testing.T) {
	for name, cm := range map[string]string{
		"none":                "",
		"no member":           `{"display":[]}`,
		"not an object":       `["x"]`,
		"credential_metadata": `null`,
	} {
		t.Run("absent/"+name, func(t *testing.T) {
			ok, err := secretSeedAdvertised(seedCfg(cm))
			require.NoError(t, err)
			assert.False(t, ok)
		})
	}
	ok, err := secretSeedAdvertised(seedCfg(advOK))
	require.NoError(t, err)
	assert.True(t, ok)
	for _, edge := range []string{
		`{"namespaces":["a","b","c","d","e","f","g","h"]}`,
		`{"namespaces":["` + strings.Repeat("n", 64) + `"]}`,
	} {
		ok, err = secretSeedAdvertised(seedCfg(`{"org.siros.secret_seed":` + edge + `}`))
		require.NoError(t, err)
		assert.True(t, ok)
	}

	for name, adv := range map[string]string{
		"hex values not namespaces": `{"ns":"` + secretSeedA + `"}`,
		"hex alongside namespaces":  `{"namespaces":["a"],"seed":"` + secretSeedA + `"}`,
		"namespaces as hex string":  `{"namespaces":"` + secretSeedA + `"}`,
		"namespaces object":         `{"namespaces":{"a":"` + secretSeedA + `"}}`,
		"empty namespaces":          `{"namespaces":[]}`,
		"nine namespaces":           `{"namespaces":["a","b","c","d","e","f","g","h","i"]}`,
		"duplicate namespace":       `{"namespaces":["a","a"]}`,
		"namespace 65 bytes":        `{"namespaces":["` + strings.Repeat("n", 65) + `"]}`,
		"reserved name":             `{"namespaces":["namespaces"]}`,
		"extra non-string member":   `{"namespaces":["a"],"x":1}`,
		"empty namespace name":      `{"namespaces":[""]}`,
		"non-string namespace":      `{"namespaces":[7]}`,
		"empty object":              `{}`,
		"not an object":             `"` + secretSeedA + `"`,
		"null":                      `null`,
	} {
		t.Run("malformed/"+name, func(t *testing.T) {
			ok, err := secretSeedAdvertised(seedCfg(`{"org.siros.secret_seed":` + adv + `}`))
			require.Error(t, err)
			assert.False(t, ok)
			assert.NotContains(t, err.Error(), secretSeedA)
		})
	}
}

func TestRequestCredential_SeedAdvertised_RequiresEncryption(t *testing.T) {
	tok := &TokenResponse{AccessToken: "t", TokenType: "Bearer"}
	hits := 0
	var sawEncryptionRequest bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		var rb map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&rb)
		_, sawEncryptionRequest = rb["credential_response_encryption"]
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(bodyWithMD(`{"org.siros.secret_seed":{"n":"` + secretSeedA + `"}}`)))
	}))
	defer srv.Close()
	adv := seedCfg(advOK)

	run := func(t *testing.T, md *IssuerMetadata, cfg *CredentialConfig) (*CredentialResponse, error, *observer.ObservedLogs) {
		core, logs := observer.New(zap.DebugLevel)
		h, cleanup := testOID4VCIHandler(t, srv.Client())
		t.Cleanup(cleanup)
		h.Logger = zap.New(core)
		r, err := h.requestCredential(context.Background(), md, tok, "cfg", cfg, nil)
		return r, err, logs
	}
	noLeak := func(t *testing.T, err error, logs *observer.ObservedLogs) {
		assert.NotContains(t, err.Error(), secretSeedA)
		for _, e := range logs.All() {
			assert.NotContains(t, e.Message, secretSeedA)
			for _, f := range e.Context {
				assert.NotContains(t, f.String, secretSeedA)
				if er, ok := f.Interface.(error); ok {
					assert.NotContains(t, er.Error(), secretSeedA)
				}
			}
		}
	}

	t.Run("issuer offers no response encryption: refused before any request", func(t *testing.T) {
		hits = 0
		_, err, logs := run(t, &IssuerMetadata{CredentialEndpoint: srv.URL}, adv)
		require.Error(t, err)
		assert.Equal(t, 0, hits)
		noLeak(t, err, logs)
	})
	t.Run("no mutually supported alg/enc: refused even if not required", func(t *testing.T) {
		hits = 0
		md := &IssuerMetadata{CredentialEndpoint: srv.URL, CredentialResponseEncryption: &CredentialResponseEncryptionConfig{
			AlgValuesSupported: []string{"RSA-OAEP"}, EncValuesSupported: []string{"A128GCM"},
		}}
		_, err, logs := run(t, md, adv)
		require.Error(t, err)
		assert.Equal(t, 0, hits)
		noLeak(t, err, logs)
	})
	t.Run("plain answer to an encrypted request is refused without leaking", func(t *testing.T) {
		hits, sawEncryptionRequest = 0, false
		r, err, logs := run(t, issuerEnc(srv.URL), adv)
		require.Error(t, err)
		assert.Nil(t, r)
		assert.Equal(t, 1, hits)
		assert.True(t, sawEncryptionRequest, "engine must request encryption")
		noLeak(t, err, logs)
	})
	t.Run("malformed advertisement refused before any request", func(t *testing.T) {
		hits = 0
		_, err, logs := run(t, issuerEnc(srv.URL), seedCfg(`{"org.siros.secret_seed":{"ns":"`+secretSeedA+`"}}`))
		require.Error(t, err)
		assert.Equal(t, 0, hits)
		noLeak(t, err, logs)
	})
	t.Run("not advertised: plain response still accepted", func(t *testing.T) {
		hits = 0
		r, err, _ := run(t, &IssuerMetadata{CredentialEndpoint: srv.URL}, seedCfg(""))
		require.NoError(t, err)
		require.NotNil(t, r)
	})
	t.Run("advertised and encrypted answer accepted", func(t *testing.T) {
		esrv := encryptedRawServer(t, bodyWithMD(`{"org.siros.secret_seed":{"n":"`+secretSeedA+`"}}`))
		defer esrv.Close()
		h, cleanup := testOID4VCIHandler(t, esrv.Client())
		defer cleanup()
		r, err := h.requestCredential(context.Background(), issuerEnc(esrv.URL), tok, "cfg", adv, nil)
		require.NoError(t, err)
		relay, err := credentialMetadataRelay(r)
		require.NoError(t, err)
		assert.True(t, relay.Encrypted)
	})
}

func TestRequestCredential_SeedAdvertised_FlowErrorSent(t *testing.T) {
	h, ch, cleanup := captureHandler(t)
	defer cleanup()
	h.httpClient = http.DefaultClient
	_, err := h.requestCredential(context.Background(), &IssuerMetadata{CredentialEndpoint: "http://127.0.0.1:1"}, &TokenResponse{AccessToken: "t", TokenType: "Bearer"}, "cfg", seedCfg(advOK), nil)
	require.Error(t, err)
	m := nextMsg(t, ch)
	if string(m["type"]) == `"flow_progress"` {
		m = nextMsg(t, ch)
	}
	assert.JSONEq(t, `"flow_error"`, string(m["type"]))
}

func TestFinishIssuance_SeedAdvertised_PlainDeferredRefused(t *testing.T) {
	seedMD := `{"org.siros.secret_seed":{"n":"` + secretSeedA + `"}}`
	t.Run("plain with seed refused", func(t *testing.T) {
		h, ch, cleanup := captureHandler(t)
		defer cleanup()
		err := h.finishIssuance(context.Background(), StepDeferred, parseResp(t, bodyWithMD(seedMD)), seedCfg(advOK), nil, nil, &TokenResponse{})
		require.Error(t, err)
		assert.NotContains(t, err.Error(), secretSeedA)
		m := nextMsg(t, ch)
		assert.JSONEq(t, `"flow_error"`, string(m["type"]))
	})
	t.Run("plain with seed refused even when not advertised", func(t *testing.T) {
		h, ch, cleanup := captureHandler(t)
		defer cleanup()
		err := h.finishIssuance(context.Background(), StepDeferred, parseResp(t, bodyWithMD(seedMD)), seedCfg(""), nil, nil, &TokenResponse{})
		require.Error(t, err)
		assert.JSONEq(t, `"flow_error"`, string(nextMsg(t, ch)["type"]))
	})
	t.Run("plain without seed member still completes", func(t *testing.T) {
		h, ch, cleanup := captureHandler(t)
		defer cleanup()
		require.NoError(t, h.finishIssuance(context.Background(), StepDeferred, parseResp(t, bodyWithMD(`{"x":1}`)), seedCfg(advOK), nil, nil, &TokenResponse{}))
		assert.JSONEq(t, `"flow_complete"`, string(nextMsg(t, ch)["type"]))
	})
	t.Run("encrypted with seed completes", func(t *testing.T) {
		h, ch, cleanup := captureHandler(t)
		defer cleanup()
		resp := parseResp(t, bodyWithMD(seedMD))
		resp.Encrypted = true
		require.NoError(t, h.finishIssuance(context.Background(), StepRequestingCredential, resp, seedCfg(advOK), nil, nil, &TokenResponse{}))
		assert.JSONEq(t, `"flow_complete"`, string(nextMsg(t, ch)["type"]))
	})
}

// A malformed advertisement makes the configuration "not offered": it is
// dropped when the issuer metadata is decoded (privatedata-spec 5A.3).
func TestCredentialConfigurations_MalformedSeedAdvertisementNotOffered(t *testing.T) {
	var c CredentialConfigurations
	require.NoError(t, json.Unmarshal([]byte(`{
		"good":{"format":"mso_mdoc","credential_metadata":`+advOK+`},
		"none":{"format":"mso_mdoc"},
		"hex":{"format":"mso_mdoc","credential_metadata":{"org.siros.secret_seed":{"ns":"`+secretSeedA+`"}}},
		"dup":{"format":"mso_mdoc","credential_metadata":{"org.siros.secret_seed":{"namespaces":["a","a"]}}}}`), &c))
	assert.Contains(t, c, "good")
	assert.Contains(t, c, "none")
	assert.NotContains(t, c, "hex")
	assert.NotContains(t, c, "dup")
}

func TestLogIgnoredCredentialConfigurations_MalformedSeedAdvertisementNoContent(t *testing.T) {
	core, logs := observer.New(zap.DebugLevel)
	h := &OID4VCIHandler{}
	h.BaseHandler = BaseHandler{Logger: zap.New(core)}
	src := map[string]interface{}{"credential_configurations_supported": map[string]interface{}{
		"hex": map[string]interface{}{"format": "mso_mdoc", "credential_metadata": map[string]interface{}{
			"org.siros.secret_seed": map[string]interface{}{"ns": secretSeedA}}},
	}}
	h.logIgnoredCredentialConfigurations(src, CredentialConfigurations{})
	require.Equal(t, 1, logs.Len())
	e := logs.All()[0]
	assert.NotContains(t, e.Message, secretSeedA)
	for _, f := range e.Context {
		assert.NotContains(t, f.String, secretSeedA)
	}
}

func TestCredentialMetadataRelay_DisplayDataWithLargeDataURIAndSeed(t *testing.T) {
	logo := "data:image/png;base64," + strings.Repeat("QUJD", 50*1024) // ~200 KB
	require.Greater(t, len(logo), 200*1000)
	md := `{"display":[{"name":"Nym","locale":"en","logo":{"uri":"` + logo + `","alt_text":"logo"}}],` +
		`"org.siros.secret_seed":{"org.siros.nym_auth":"` + secretSeedA + `"}}`
	resp := parseResp(t, bodyWithMD(md))
	resp.Encrypted = true
	relay, err := credentialMetadataRelay(resp)
	require.NoError(t, err)
	assert.Equal(t, md, string(relay.Metadata), "relayed verbatim")

	// And all the way out on flow_complete.
	h, ch, cleanup := captureHandler(t)
	defer cleanup()
	require.NoError(t, h.finishIssuance(context.Background(), StepRequestingCredential, resp, &CredentialConfig{Format: "mso_mdoc"}, nil, nil, &TokenResponse{}))
	m := nextMsg(t, ch)
	assert.JSONEq(t, `"flow_complete"`, string(m["type"]))
	assert.Equal(t, md, string(m["credential_metadata"]))
}

func TestCredentialMetadataRelay_SizeBoundary(t *testing.T) {
	pad := func(total int) string {
		const frame = `{"x":""}`
		return `{"x":"` + strings.Repeat("p", total-len(frame)) + `"}`
	}
	at := pad(maxCredentialMetadataBytes)
	require.Len(t, at, maxCredentialMetadataBytes)
	_, err := credentialMetadataRelay(parseResp(t, bodyWithMD(at)))
	require.NoError(t, err, "exactly at the cap passes")
	over := pad(maxCredentialMetadataBytes + 1)
	relay, err := credentialMetadataRelay(parseResp(t, bodyWithMD(over)))
	require.Error(t, err)
	assert.Nil(t, relay)
}

func TestFinishIssuance_PlainDisplayOnlyMetadataRelayed(t *testing.T) {
	md := `{"display":[{"name":"A","locale":"en","logo":{"uri":"data:image/png;base64,AAAA"}}],"claims":[]}`
	for _, cfg := range []*CredentialConfig{seedCfg(""), seedCfg(advOK)} {
		h, ch, cleanup := captureHandler(t)
		require.NoError(t, h.finishIssuance(context.Background(), StepRequestingCredential, parseResp(t, bodyWithMD(md)), cfg, nil, nil, &TokenResponse{}))
		m := nextMsg(t, ch)
		assert.Equal(t, md, string(m["credential_metadata"]))
		_, flag := m["credential_metadata_encrypted_response"]
		assert.False(t, flag)
		cleanup()
	}
}

func TestFinishIssuance_OversizeMetadataFailsCleanly(t *testing.T) {
	h, ch, cleanup := captureHandler(t)
	defer cleanup()
	md := `{"x":"` + strings.Repeat("p", maxCredentialMetadataBytes) + `"}`
	require.Error(t, h.finishIssuance(context.Background(), StepRequestingCredential, parseResp(t, bodyWithMD(md)), seedCfg(""), nil, nil, &TokenResponse{}))
	m := nextMsg(t, ch)
	assert.JSONEq(t, `"flow_error"`, string(m["type"]))
}

func TestFinishIssuance_SeedRequiresNotificationID(t *testing.T) {
	seedMD := `{"org.siros.secret_seed":{"n":"` + secretSeedA + `"}}`
	for _, step := range []FlowStep{StepRequestingCredential, StepDeferred} {
		withID := `{"credentials":[{"credential":"c"}],"notification_id":"n-1","credential_metadata":` + seedMD + `}`
		without := `{"credentials":[{"credential":"c"}],"credential_metadata":` + seedMD + `}`
		emptyID := `{"credentials":[{"credential":"c"}],"notification_id":"","credential_metadata":` + seedMD + `}`
		displayOnly := `{"credentials":[{"credential":"c"}],"credential_metadata":{"display":[{"name":"A"}]}}`

		t.Run(string(step)+"/seed with notification_id passes", func(t *testing.T) {
			h, ch, cleanup := captureHandler(t)
			defer cleanup()
			resp := parseResp(t, withID)
			resp.Encrypted = true
			require.NoError(t, h.finishIssuance(context.Background(), step, resp, seedCfg(""), nil, nil, &TokenResponse{}))
			assert.JSONEq(t, `"flow_complete"`, string(nextMsg(t, ch)["type"]))
		})
		for name, body := range map[string]string{"absent": without, "empty": emptyID} {
			t.Run(string(step)+"/seed with "+name+" notification_id fails", func(t *testing.T) {
				h, ch, cleanup := captureHandler(t)
				defer cleanup()
				resp := parseResp(t, body)
				resp.Encrypted = true
				err := h.finishIssuance(context.Background(), step, resp, seedCfg(""), nil, nil, &TokenResponse{})
				require.Error(t, err)
				assert.NotContains(t, err.Error(), secretSeedA)
				m := nextMsg(t, ch)
				assert.JSONEq(t, `"flow_error"`, string(m["type"]))
				assert.Contains(t, string(m["error"]), string(ErrCodeCredentialError))
				select {
				case extra := <-ch:
					t.Fatalf("unexpected extra message %s", extra["type"])
				case <-time.After(100 * time.Millisecond):
				}
			})
		}
		t.Run(string(step)+"/display-only without notification_id relays", func(t *testing.T) {
			h, ch, cleanup := captureHandler(t)
			defer cleanup()
			require.NoError(t, h.finishIssuance(context.Background(), step, parseResp(t, displayOnly), seedCfg(""), nil, nil, &TokenResponse{}))
			m := nextMsg(t, ch)
			assert.JSONEq(t, `"flow_complete"`, string(m["type"]))
			assert.Equal(t, `{"display":[{"name":"A"}]}`, string(m["credential_metadata"]))
		})
	}
}

func TestCredentialMetadataRelay_NumbersRelayedVerbatim(t *testing.T) {
	md := `{"org.example.ext":{"n":1e400,"big":123456789012345678901234567890,"m":1.50,"neg":-1E-999},"org.siros.secret_seed":{"ns":"` + secretSeedA + `"}}`
	relay, err := credentialMetadataRelay(parseResp(t, bodyWithMD(md)))
	require.NoError(t, err)
	assert.Equal(t, md, string(relay.Metadata))
}

// Decoding errors for the raw response must not quote response content, on
// the plain, JWE and deferred paths.
func TestCredentialResponseDecodeErrors_DoNotQuoteContent(t *testing.T) {
	const marker = "9e4004004"
	body := `{"credentials":[` + marker + `],"credential_metadata":{"org.siros.secret_seed":{"n":"` + secretSeedA + `"}}}`
	check := func(t *testing.T, err error) {
		require.Error(t, err)
		assert.NotContains(t, err.Error(), marker)
		assert.NotContains(t, err.Error(), secretSeedA)
	}
	tok := &TokenResponse{AccessToken: "t", TokenType: "Bearer"}
	cfg := &CredentialConfig{Format: "mso_mdoc"}

	t.Run("plain", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(body))
		}))
		defer srv.Close()
		h, cleanup := testOID4VCIHandler(t, srv.Client())
		defer cleanup()
		_, err := h.requestCredential(context.Background(), &IssuerMetadata{CredentialEndpoint: srv.URL}, tok, "", cfg, nil)
		check(t, err)
	})
	t.Run("jwe", func(t *testing.T) {
		srv := encryptedRawServer(t, body)
		defer srv.Close()
		h, cleanup := testOID4VCIHandler(t, srv.Client())
		defer cleanup()
		_, err := h.requestCredential(context.Background(), issuerEnc(srv.URL), tok, "", cfg, nil)
		check(t, err)
	})
	t.Run("deferred", func(t *testing.T) {
		if testing.Short() {
			t.Skip("deferred polling waits one 5s interval")
		}
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(body))
		}))
		defer srv.Close()
		h, cleanup := testOID4VCIHandler(t, srv.Client())
		defer cleanup()
		_, err := h.pollDeferredCredential(context.Background(), &IssuerMetadata{CredentialIssuer: srv.URL}, tok, "tx1")
		check(t, err)
	})
}

// TestEnforceCredentialMetadataLimits pins every branch of the token walker,
// including the exact rejection reason, independently of the later decode.
func TestEnforceCredentialMetadataLimits(t *testing.T) {
	const (
		invalid = "credential_metadata is not valid JSON"
		dup     = "credential_metadata has a duplicate member name"
	)
	depthMsg := fmt.Sprintf("credential_metadata nests deeper than %d", maxCredentialMetadataDepth)
	keyMsg := fmt.Sprintf("credential_metadata member name exceeds %d bytes", maxCredentialMetadataKeyLen)
	memMsg := fmt.Sprintf("credential_metadata object has more than %d members", maxCredentialMetadataMembers)
	members := func(n int) string {
		var m []string
		for i := 0; i < n; i++ {
			m = append(m, fmt.Sprintf(`"k%d":%d`, i, i))
		}
		return `{` + strings.Join(m, ",") + `}`
	}
	longKey := strings.Repeat("k", maxCredentialMetadataKeyLen+1)
	rep := func(s string, n int) string { return strings.Repeat(s, n) }

	cases := []struct {
		name, in, want string // want "" = accepted
	}{
		{"empty object", `{}`, ""},
		{"depth at cap objects", rep(`{"a":`, maxCredentialMetadataDepth) + `1` + rep(`}`, maxCredentialMetadataDepth), ""},
		{"depth over cap objects", rep(`{"a":`, maxCredentialMetadataDepth+1) + `1` + rep(`}`, maxCredentialMetadataDepth+1), depthMsg},
		{"depth at cap arrays", `{"a":` + rep(`[`, maxCredentialMetadataDepth-1) + rep(`]`, maxCredentialMetadataDepth-1) + `}`, ""},
		{"depth over cap arrays", `{"a":` + rep(`[`, maxCredentialMetadataDepth) + rep(`]`, maxCredentialMetadataDepth) + `}`, depthMsg},
		{"members at cap", members(maxCredentialMetadataMembers), ""},
		{"members over cap", members(maxCredentialMetadataMembers + 1), memMsg},
		{"nested members over cap", `{"x":` + members(maxCredentialMetadataMembers+1) + `}`, memMsg},
		{"members counted per object", `{"a":` + members(maxCredentialMetadataMembers) + `,"b":` + members(maxCredentialMetadataMembers) + `}`, ""},
		{"key at cap", `{"` + strings.Repeat("k", maxCredentialMetadataKeyLen) + `":1}`, ""},
		{"key over cap", `{"` + longKey + `":1}`, keyMsg},
		{"nested key over cap", `{"x":[{"` + longKey + `":1}]}`, keyMsg},
		{"duplicate top level", `{"x":1,"x":2}`, dup},
		{"duplicate top level after nested value", `{"x":{"a":1},"y":[1],"x":2}`, dup},
		{"duplicate in seed object", `{"org.siros.secret_seed":{"n":"a","n":"b"}}`, dup},
		{"duplicate in seed object after other member", `{"q":1,"org.siros.secret_seed":{"m":1,"n":2,"n":3}}`, dup},
		{"same key in distinct top-level objects", `{"a":{"x":1},"b":{"x":2}}`, ""},
		{"nested duplicate allowed", `{"display":[{"name":"a","name":"b"}]}`, ""},
		{"nested duplicate in object allowed", `{"a":{"x":1,"x":2}}`, ""},
		{"duplicate under a non-seed key allowed", `{"a":{"org.siros.secret_seed":{"n":1,"n":2}}}`, ""},
		{"duplicate inside array under seed key allowed", `{"org.siros.secret_seed":[{"n":1,"n":2}]}`, ""},
		{"duplicate deeper inside seed object allowed", `{"org.siros.secret_seed":{"n":{"a":1,"a":2}}}`, ""},
		{"seed key does not leak to later sibling", `{"org.siros.secret_seed":1,"x":{"a":1,"a":2}}`, ""},
		{"top-level array: objects not unique", `[{"a":1,"a":2}]`, ""},
		{"scalar top level", `7`, ""},
		{"numbers verbatim (UseNumber)", `{"n":1e400,"b":123456789012345678901234567890,"m":-1E-999}`, ""},
		{"empty input", ``, ""},
		{"truncated object", `{"a":1`, invalid},
		{"truncated array", `{"a":[1,2`, invalid},
		{"truncated mid-token", `{"a":`, invalid},
		{"bad token", `{"a":nul}`, invalid},
		{"trailing garbage", `{"a":1} x`, invalid},
		{"unquoted key", `{a:1}`, invalid},
		{"unbalanced close", `{"a":1}}`, invalid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := enforceCredentialMetadataLimits(json.RawMessage(tc.in))
			if tc.want == "" {
				require.NoError(t, err)
				return
			}
			require.EqualError(t, err, tc.want)
		})
	}
}
