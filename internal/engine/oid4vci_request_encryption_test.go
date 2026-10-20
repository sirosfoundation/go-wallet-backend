package engine

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const seedMetadata = `{"org.siros.secret_seed":{"namespaces":["ns1"]}}`

func issuerEncKey(t *testing.T, alg, use string) (*ecdsa.PrivateKey, json.RawMessage) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	jwk := jose.JSONWebKey{Key: &priv.PublicKey, Use: use, Algorithm: alg}
	tp, err := jwk.Thumbprint(0x5) // crypto.SHA256
	require.NoError(t, err)
	jwk.KeyID = encodeB64(tp)
	b, err := json.Marshal(map[string]any{"keys": []jose.JSONWebKey{jwk}})
	require.NoError(t, err)
	return priv, b
}

func encodeB64(b []byte) string {
	const a = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	out := ""
	for _, c := range b {
		out += string(a[int(c)%64])
	}
	return out
}

// encryptingIssuer decrypts the request and answers with a JWE response to the
// wallet's key, like an issuer requiring encrypted requests.
func encryptingIssuer(t *testing.T, priv *ecdsa.PrivateKey, got *map[string]any, gotCT *string, gotKID *string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*gotCT = r.Header.Get("Content-Type")
		body, _ := io.ReadAll(r.Body)
		if *gotCT != "application/jwt" {
			http.Error(w, "credential_response_encryption requires an encrypted request", 400)
			return
		}
		jwe, err := jose.ParseEncrypted(string(body), []jose.KeyAlgorithm{jose.ECDH_ES_A256KW}, []jose.ContentEncryption{jose.A256GCM})
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		*gotKID = jwe.Header.KeyID
		pt, err := jwe.Decrypt(priv)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		_ = json.Unmarshal(pt, got)
		resp := *got
		encObj := resp["credential_response_encryption"].(map[string]any)
		jb, _ := json.Marshal(encObj["jwk"])
		var wk jose.JSONWebKey
		require.NoError(t, json.Unmarshal(jb, &wk))
		enc, err := jose.NewEncrypter(jose.ContentEncryption(encObj["enc"].(string)),
			jose.Recipient{Algorithm: jose.KeyAlgorithm(encObj["alg"].(string)), Key: &wk}, nil)
		require.NoError(t, err)
		out, _ := enc.Encrypt([]byte(`{"credential":"c","credential_metadata":` + seedMetadata + `}`))
		s, _ := out.CompactSerialize()
		w.Header().Set("Content-Type", "application/jwt")
		_, _ = w.Write([]byte(s))
	}))
}

func respEnc() *CredentialResponseEncryptionConfig {
	return &CredentialResponseEncryptionConfig{
		AlgValuesSupported: []string{"ECDH-ES+A256KW"},
		EncValuesSupported: []string{"A256GCM"},
	}
}

func TestRequestCredential_EncryptedRequestRoundTrip(t *testing.T) {
	priv, jwks := issuerEncKey(t, "ECDH-ES+A256KW", "enc")
	var got map[string]any
	var ct, kid string
	srv := encryptingIssuer(t, priv, &got, &ct, &kid)
	defer srv.Close()
	h, cleanup := testOID4VCIHandler(t, srv.Client())
	defer cleanup()

	md := &IssuerMetadata{
		CredentialEndpoint:           srv.URL,
		CredentialResponseEncryption: respEnc(),
		CredentialRequestEncryption:  &CredentialRequestEncryptionConfig{JWKS: jwks, EncValuesSupported: []string{"A256GCM"}},
	}
	cfg := &CredentialConfig{Format: "vc+sd-jwt", CredentialMetadata: json.RawMessage(seedMetadata)}
	resp, err := h.requestCredential(context.Background(), md, &TokenResponse{AccessToken: "t", TokenType: "Bearer"}, "cfg", cfg, nil)
	require.NoError(t, err)
	assert.True(t, resp.Encrypted)
	assert.Equal(t, "application/jwt", ct)
	assert.NotEmpty(t, kid)
	assert.Equal(t, "cfg", got["credential_configuration_id"])
	assert.Contains(t, got, "credential_response_encryption")
}

func TestRequestCredential_RequestEncryptionFailsClosed(t *testing.T) {
	_, goodJWKS := issuerEncKey(t, "ECDH-ES+A256KW", "enc")
	_, wrongAlg := issuerEncKey(t, "RSA-OAEP", "enc")
	_, sigUse := issuerEncKey(t, "ECDH-ES+A256KW", "sig")
	cases := map[string]*CredentialRequestEncryptionConfig{
		"unsupported alg": {JWKS: wrongAlg, EncValuesSupported: []string{"A256GCM"}},
		"use sig":         {JWKS: sigUse, EncValuesSupported: []string{"A256GCM"}},
		"unsupported enc": {JWKS: goodJWKS, EncValuesSupported: []string{"XYZ"}},
		"no jwks":         {EncValuesSupported: []string{"A256GCM"}},
	}
	for name, rc := range cases {
		t.Run(name, func(t *testing.T) {
			hit := false
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }))
			defer srv.Close()
			h, cleanup := testOID4VCIHandler(t, srv.Client())
			defer cleanup()
			md := &IssuerMetadata{CredentialEndpoint: srv.URL, CredentialResponseEncryption: respEnc(), CredentialRequestEncryption: rc}
			cfg := &CredentialConfig{Format: "vc+sd-jwt", CredentialMetadata: json.RawMessage(seedMetadata)}
			_, err := h.requestCredential(context.Background(), md, &TokenResponse{AccessToken: "t", TokenType: "Bearer"}, "cfg", cfg, nil)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "cannot encrypt credential request")
			assert.False(t, hit, "no plain request may reach the issuer")
		})
	}
}

func TestRequestCredential_EncryptionRequiredWithoutKeyFails(t *testing.T) {
	hit := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }))
	defer srv.Close()
	h, cleanup := testOID4VCIHandler(t, srv.Client())
	defer cleanup()
	md := &IssuerMetadata{CredentialEndpoint: srv.URL, CredentialRequestEncryption: &CredentialRequestEncryptionConfig{EncryptionRequired: true}}
	_, err := h.requestCredential(context.Background(), md, &TokenResponse{AccessToken: "t", TokenType: "Bearer"}, "cfg", &CredentialConfig{Format: "vc+sd-jwt"}, nil)
	require.Error(t, err)
	assert.False(t, hit)
}

func TestRequestCredential_NoRequestEncryptionAdvertisedStaysPlain(t *testing.T) {
	var ct string
	var body map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ct = r.Header.Get("Content-Type")
		_ = json.NewDecoder(r.Body).Decode(&body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"credential":"c"}`))
	}))
	defer srv.Close()
	h, cleanup := testOID4VCIHandler(t, srv.Client())
	defer cleanup()
	md := &IssuerMetadata{CredentialEndpoint: srv.URL, CredentialResponseEncryption: respEnc()}
	_, err := h.requestCredential(context.Background(), md, &TokenResponse{AccessToken: "t", TokenType: "Bearer"}, "cfg", &CredentialConfig{Format: "vc+sd-jwt"}, nil)
	require.NoError(t, err)
	assert.Equal(t, "application/json", ct)
	assert.Contains(t, body, "credential_response_encryption")
}

func TestPollDeferredCredential_EncryptedWhenRequired(t *testing.T) {
	priv, jwks := issuerEncKey(t, "ECDH-ES+A256KW", "enc")
	var ct string
	var body map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ct = r.Header.Get("Content-Type")
		raw, _ := io.ReadAll(r.Body)
		jwe, err := jose.ParseEncrypted(string(raw), []jose.KeyAlgorithm{jose.ECDH_ES_A256KW}, []jose.ContentEncryption{jose.A256GCM})
		if err != nil {
			http.Error(w, "plain", 400)
			return
		}
		pt, _ := jwe.Decrypt(priv)
		_ = json.Unmarshal(pt, &body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"credential":"c"}`))
	}))
	defer srv.Close()
	h, cleanup := testOID4VCIHandler(t, srv.Client())
	defer cleanup()
	md := &IssuerMetadata{
		CredentialIssuer:            srv.URL,
		CredentialRequestEncryption: &CredentialRequestEncryptionConfig{JWKS: jwks, EncValuesSupported: []string{"A256GCM"}, EncryptionRequired: true},
	}
	_, err := h.pollDeferredCredential(context.Background(), md, &TokenResponse{AccessToken: "t", TokenType: "Bearer"}, "tx1")
	require.NoError(t, err)
	assert.Equal(t, "application/jwt", ct)
	assert.Equal(t, "tx1", body["transaction_id"])
}
