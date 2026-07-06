package engine

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestInferClientIDScheme(t *testing.T) {
	tests := []struct {
		name     string
		clientID string
		want     string
	}{
		{"did:web", "did:web:verifier.example.com", ClientIDSchemeDID},
		{"did:key", "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK", ClientIDSchemeDID},
		{"did:jwk", "did:jwk:eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2In0", ClientIDSchemeDID},
		{"url", "https://verifier.example.com", ClientIDSchemeRedirectURI},
		{"plain string", "my-verifier", ClientIDSchemeRedirectURI},
		{"empty", "", ClientIDSchemeRedirectURI},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := inferClientIDScheme(tt.clientID)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestVerifyDIDRequest_InvalidDID(t *testing.T) {
	h := &OID4VPHandler{}

	tests := []struct {
		name     string
		clientID string
	}{
		{"not a DID", "https://example.com"},
		{"incomplete DID", "did:"},
		{"missing specific-id", "did:web:"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authReq := &AuthorizationRequest{
				ClientID:       tt.clientID,
				ClientIDScheme: ClientIDSchemeDID,
				RequestJWT:     "a.b.c",
			}
			_, err := h.verifyDIDRequest(authReq)
			require.Error(t, err)
		})
	}
}

func TestVerifyDIDRequest_NoJWT(t *testing.T) {
	h := &OID4VPHandler{}
	authReq := &AuthorizationRequest{
		ClientID:       "did:web:verifier.example.com",
		ClientIDScheme: ClientIDSchemeDID,
		RequestJWT:     "",
	}
	_, err := h.verifyDIDRequest(authReq)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "requires a signed request JWT")
}

func TestVerifyDIDRequest_ValidJWT(t *testing.T) {
	// Generate a test EC key pair
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Build a JWT with embedded JWK in header
	jwk := map[string]any{
		"kty": "EC",
		"crv": "P-256",
		"x":   base64.RawURLEncoding.EncodeToString(privKey.PublicKey.X.Bytes()),
		"y":   base64.RawURLEncoding.EncodeToString(padBytes(privKey.PublicKey.Y.Bytes(), 32)),
	}
	headerMap := map[string]any{
		"alg": "ES256",
		"jwk": jwk,
	}
	headerBytes, _ := json.Marshal(headerMap)
	header := base64.RawURLEncoding.EncodeToString(headerBytes)

	claims := map[string]any{
		"client_id": "did:web:verifier.example.com",
		"iss":       "did:web:verifier.example.com",
	}
	payloadBytes, _ := json.Marshal(claims)
	payload := base64.RawURLEncoding.EncodeToString(payloadBytes)

	signingInput := header + "." + payload
	sigMethod := jwt.SigningMethodES256
	sigBytes, err := sigMethod.Sign(signingInput, privKey)
	require.NoError(t, err)

	jwtStr := signingInput + "." + base64.RawURLEncoding.EncodeToString(sigBytes)

	h := &OID4VPHandler{}
	authReq := &AuthorizationRequest{
		ClientID:       "did:web:verifier.example.com",
		ClientIDScheme: ClientIDSchemeDID,
		RequestJWT:     jwtStr,
	}
	km, err := h.verifyDIDRequest(authReq)
	require.NoError(t, err)
	require.NotNil(t, km)
	assert.Equal(t, "jwk", km.Type)
}

// padBytes pads b to the given length with leading zeros.
func padBytes(b []byte, length int) []byte {
	if len(b) >= length {
		return b
	}
	padded := make([]byte, length)
	copy(padded[length-len(b):], b)
	return padded
}

func TestExtractDomain(t *testing.T) {
	tests := []struct {
		name     string
		clientID string
		want     string
	}{
		{"did:web", "did:web:verifier.example.com", "verifier.example.com"},
		{"did:web with path", "did:web:verifier.example.com:path:to", "verifier.example.com"},
		{"did:key", "did:key:z6MkhaXg", ""},
		{"https URL", "https://verifier.example.com/callback", "verifier.example.com"},
		{"http URL with port", "http://localhost:8080/auth", "localhost:8080"},
		{"plain string", "my-verifier", ""},
		{"empty", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractDomain(tt.clientID)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestGetCanonicalVerifierURL(t *testing.T) {
	tests := []struct {
		name        string
		authReq     *AuthorizationRequest
		want        string
		description string
	}{
		{
			name: "response_uri takes priority",
			authReq: &AuthorizationRequest{
				ResponseURI: "https://verifier.example.com/response",
				RedirectURI: "https://verifier.example.com/redirect",
				ClientID:    "https://verifier.example.com",
			},
			want:        "https://verifier.example.com/response",
			description: "When response_uri is set, it should be returned",
		},
		{
			name: "redirect_uri when no response_uri",
			authReq: &AuthorizationRequest{
				ResponseURI: "",
				RedirectURI: "https://verifier.example.com/redirect",
				ClientID:    "https://verifier.example.com",
			},
			want:        "https://verifier.example.com/redirect",
			description: "When response_uri is empty, redirect_uri should be used",
		},
		{
			name: "client_id as fallback",
			authReq: &AuthorizationRequest{
				ResponseURI: "",
				RedirectURI: "",
				ClientID:    "https://verifier.example.com",
			},
			want:        "https://verifier.example.com",
			description: "When both response_uri and redirect_uri are empty, client_id should be used",
		},
		{
			name: "did client_id fallback",
			authReq: &AuthorizationRequest{
				ResponseURI: "",
				RedirectURI: "",
				ClientID:    "did:web:verifier.example.com",
			},
			want:        "did:web:verifier.example.com",
			description: "DID client_id should be returned when no URIs are set",
		},
		{
			name: "all empty returns empty string",
			authReq: &AuthorizationRequest{
				ResponseURI: "",
				RedirectURI: "",
				ClientID:    "",
			},
			want:        "",
			description: "When all fields are empty, empty string is returned",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getCanonicalVerifierURL(tt.authReq)
			assert.Equal(t, tt.want, got, tt.description)
		})
	}
}

func TestFetchRequestFromURI(t *testing.T) {
	// Build a minimal, unsigned JWT whose payload is a valid AuthorizationRequest.
	// parseRequestJWT does not verify the signature, so any three-part dot-separated
	// string with a valid base64url-encoded JSON payload works here.
	claims := map[string]any{
		"client_id":     "did:web:verifier",
		"response_type": "vp_token",
		"nonce":         "test-nonce",
	}
	payloadBytes, err := json.Marshal(claims)
	require.NoError(t, err)
	jwtPayload := base64.RawURLEncoding.EncodeToString(payloadBytes)
	// Use a fixed header and a dummy signature to form a three-part JWT.
	fakeHeader := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
	fakeJWT := fakeHeader + "." + jwtPayload + ".fakesig"

	// A plain JSON object whose client_id contains no dots so that the naive
	// dot-count heuristic in fetchRequestFromURI does not misclassify it as a JWT.
	plainJSON := `{"client_id":"verifier","response_type":"vp_token","nonce":"test-nonce"}`
	// The same JSON object encoded as a JSON string (as some verifiers return it).
	quotedJSON := `"{\"client_id\":\"verifier\",\"response_type\":\"vp_token\",\"nonce\":\"test-nonce\"}"`

	tests := []struct {
		name         string
		responseBody string
		statusCode   int
		wantClientID string
		wantErr      bool
		wantErrMsg   string
	}{
		{
			name:         "plain JWT response",
			responseBody: fakeJWT,
			statusCode:   http.StatusOK,
			wantClientID: "did:web:verifier",
		},
		{
			name:         "quoted JWT string response",
			responseBody: `"` + fakeJWT + `"`,
			statusCode:   http.StatusOK,
			wantClientID: "did:web:verifier",
		},
		{
			name:         "plain JSON object response",
			responseBody: plainJSON,
			statusCode:   http.StatusOK,
			wantClientID: "verifier",
		},
		{
			name:         "quoted JSON object string response",
			responseBody: quotedJSON,
			statusCode:   http.StatusOK,
			wantClientID: "verifier",
		},
		{
			name:         "HTTP error status",
			responseBody: "not found",
			statusCode:   http.StatusNotFound,
			wantErr:      true,
			wantErrMsg:   "404",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tt.statusCode)
				_, _ = fmt.Fprint(w, tt.responseBody)
			}))
			defer srv.Close()

			h := &OID4VPHandler{httpClient: srv.Client()}

			authReq, err := h.fetchRequestFromURI(context.Background(), srv.URL)
			if tt.wantErr {
				require.Error(t, err)
				if tt.wantErrMsg != "" {
					assert.Contains(t, err.Error(), tt.wantErrMsg)
				}
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantClientID, authReq.ClientID)
		})
	}
}

// ===== DCQL query tests =====

func TestCredentialMatch_QueryID(t *testing.T) {
	tests := []struct {
		name  string
		match CredentialMatch
		want  string
	}{
		{
			name:  "credential_query_id set",
			match: CredentialMatch{CredentialQueryID: "my_credential", CredentialID: "cred-1"},
			want:  "my_credential",
		},
		{
			name:  "not set",
			match: CredentialMatch{CredentialID: "cred-2"},
			want:  "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.match.QueryID())
		})
	}
}

func TestParseRequestFromURL_DCQLQuery(t *testing.T) {
	dcqlJSON := `{"credentials":[{"id":"my_credential","format":"vc+sd-jwt","meta":{"vct_values":["https://credentials.example.com/identity_credential"]},"claims":[{"path":["$.first_name"]},{"path":["$.last_name"]}]}]}`
	u, err := url.Parse("openid4vp://?response_type=vp_token&client_id=https://verifier.example.com&dcql_query=" + url.QueryEscape(dcqlJSON))
	require.NoError(t, err)

	h := &OID4VPHandler{}
	authReq, err := h.parseRequestFromURL(u)
	require.NoError(t, err)

	assert.NotNil(t, authReq.DCQLQuery)
	assert.JSONEq(t, dcqlJSON, string(authReq.DCQLQuery))
}

func TestParseRequestFromURL_InvalidDCQLQuery(t *testing.T) {
	u, err := url.Parse("openid4vp://?dcql_query=not-valid-json")
	require.NoError(t, err)

	h := &OID4VPHandler{}
	_, err = h.parseRequestFromURL(u)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid dcql_query")
}

func TestParseRequestJWT_DCQLQuery(t *testing.T) {
	dcqlJSON := `{"credentials":[{"id":"my_credential","format":"vc+sd-jwt"}]}`

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	headerMap := map[string]any{"alg": "ES256"}
	headerBytes, _ := json.Marshal(headerMap)
	header := base64.RawURLEncoding.EncodeToString(headerBytes)

	claims := map[string]any{
		"client_id":  "https://verifier.example.com",
		"dcql_query": json.RawMessage(dcqlJSON),
		"nonce":      "test-nonce",
	}
	payloadBytes, _ := json.Marshal(claims)
	payload := base64.RawURLEncoding.EncodeToString(payloadBytes)

	signingInput := header + "." + payload
	sigBytes, err := jwt.SigningMethodES256.Sign(signingInput, privKey)
	require.NoError(t, err)

	jwtStr := signingInput + "." + base64.RawURLEncoding.EncodeToString(sigBytes)

	h := &OID4VPHandler{}
	authReq, err := h.parseRequestJWT(jwtStr)
	require.NoError(t, err)

	assert.True(t, len(authReq.DCQLQuery) > 0)
	assert.JSONEq(t, dcqlJSON, string(authReq.DCQLQuery))
	assert.Equal(t, "test-nonce", authReq.Nonce)
}

func TestSubmitDirectPost_NoPresentationSubmission(t *testing.T) {
	// Verify that DCQL requests don't send presentation_submission
	var receivedForm url.Values
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err := r.ParseForm()
		require.NoError(t, err)
		receivedForm = r.PostForm
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{})
	}))
	defer server.Close()

	h := &OID4VPHandler{
		httpClient: server.Client(),
	}

	authReq := &AuthorizationRequest{
		DCQLQuery: json.RawMessage(`{"credentials":[{"id":"my_credential"}]}`),
		State:     "test-state",
	}

	_, err := h.submitDirectPost(context.Background(), server.URL, authReq, "test-vp-token")
	require.NoError(t, err)

	assert.Equal(t, "test-vp-token", receivedForm.Get("vp_token"))
	assert.Equal(t, "test-state", receivedForm.Get("state"))
	assert.Empty(t, receivedForm.Get("presentation_submission"), "should not send presentation_submission")
}

func TestMatchRequestMessage_DCQLQuery_JSON(t *testing.T) {
	dcqlJSON := json.RawMessage(`{"credentials":[{"id":"my_credential","format":"vc+sd-jwt"}]}`)
	msg := MatchRequestMessage{
		Message: Message{
			Type:   TypeMatchRequest,
			FlowID: "test-flow",
		},
		DCQLQuery: dcqlJSON,
	}

	data, err := json.Marshal(msg)
	require.NoError(t, err)

	var parsed map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &parsed))

	assert.NotNil(t, parsed["dcql_query"])
}

// ===== submitDirectPostJWT tests =====

func TestSubmitDirectPostJWT_EncryptsAndPosts(t *testing.T) {
	// Generate an ephemeral EC key for ECDH-ES encryption
	encKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	encJWK := map[string]any{
		"kty": "EC",
		"crv": "P-256",
		"x":   base64.RawURLEncoding.EncodeToString(padBytes(encKey.PublicKey.X.Bytes(), 32)),
		"y":   base64.RawURLEncoding.EncodeToString(padBytes(encKey.PublicKey.Y.Bytes(), 32)),
		"use": "enc",
		"kid": "enc-key-1",
	}
	jwksBytes, _ := json.Marshal(map[string]any{"keys": []any{encJWK}})

	var receivedForm url.Values
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err := r.ParseForm()
		require.NoError(t, err)
		receivedForm = r.PostForm
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()

	h := &OID4VPHandler{httpClient: server.Client()}
	authReq := &AuthorizationRequest{
		ClientID: "https://verifier.example.com",
		State:    "test-state",
		ClientMetadata: &ClientMetadata{
			JWKS:                              jwksBytes,
			AuthorizationEncryptedResponseAlg: "ECDH-ES",
			AuthorizationEncryptedResponseEnc: "A128CBC-HS256",
		},
	}

	_, err = h.submitDirectPostJWT(context.Background(), server.URL, authReq, "test-vp-token")
	require.NoError(t, err)

	// Should have posted a JWE in the "response" field
	response := receivedForm.Get("response")
	assert.NotEmpty(t, response, "should post a JWE in the 'response' field")
	// A JWE compact serialization has 5 dot-separated parts
	parts := len(splitDots(response))
	assert.Equal(t, 5, parts, "JWE should have 5 parts, got %d", parts)
}

func TestSubmitDirectPostJWT_MissingEncAlg(t *testing.T) {
	h := &OID4VPHandler{httpClient: http.DefaultClient}
	authReq := &AuthorizationRequest{
		ClientID:       "https://verifier.example.com",
		ClientMetadata: &ClientMetadata{},
	}

	_, err := h.submitDirectPostJWT(context.Background(), "https://example.com/post", authReq, "vp-token")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "authorization_encrypted_response_alg")
}

func TestSubmitDirectPostJWT_NilClientMetadata(t *testing.T) {
	h := &OID4VPHandler{httpClient: http.DefaultClient}
	authReq := &AuthorizationRequest{
		ClientID:       "https://verifier.example.com",
		ClientMetadata: nil,
	}

	_, err := h.submitDirectPostJWT(context.Background(), "https://example.com/post", authReq, "vp-token")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "authorization_encrypted_response_alg")
}

func TestSanitizeEndpointURL_InvalidScheme(t *testing.T) {
	_, err := sanitizeEndpointURL("ftp://evil.com")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid response endpoint URL scheme")
}

func TestSanitizeEndpointURL_ValidHTTPS(t *testing.T) {
	result, err := sanitizeEndpointURL("https://verifier.example.com/response")
	require.NoError(t, err)
	assert.Equal(t, "https://verifier.example.com/response", result)
}

func TestSanitizeEndpointURL_ValidHTTP(t *testing.T) {
	result, err := sanitizeEndpointURL("http://localhost:8080/callback")
	require.NoError(t, err)
	assert.Equal(t, "http://localhost:8080/callback", result)
}

// ===== extractVerifierEncryptionKey tests =====

func TestExtractVerifierEncryptionKey_PrefersUseEnc(t *testing.T) {
	sigKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	encKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	jwksBytes := makeJWKS(
		jose.JSONWebKey{Key: &sigKey.PublicKey, KeyID: "sig-key-1", Use: "sig"},
		jose.JSONWebKey{Key: &encKey.PublicKey, KeyID: "enc-key-1", Use: "enc"},
	)

	h := &OID4VPHandler{}
	authReq := &AuthorizationRequest{
		ClientMetadata: &ClientMetadata{JWKS: jwksBytes},
	}

	_, kid, err := h.extractVerifierEncryptionKey(authReq)
	require.NoError(t, err)
	assert.Equal(t, "enc-key-1", kid, "should select the key with use=enc")
}

func TestExtractVerifierEncryptionKey_FallsBackToFirstKey(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	jwk := map[string]any{
		"kty": "EC", "crv": "P-256",
		"x":   base64.RawURLEncoding.EncodeToString(padBytes(key.PublicKey.X.Bytes(), 32)),
		"y":   base64.RawURLEncoding.EncodeToString(padBytes(key.PublicKey.Y.Bytes(), 32)),
		"kid": "only-key",
	}
	jwksBytes, _ := json.Marshal(map[string]any{"keys": []any{jwk}})

	h := &OID4VPHandler{}
	authReq := &AuthorizationRequest{
		ClientMetadata: &ClientMetadata{JWKS: jwksBytes},
	}

	_, kid, err := h.extractVerifierEncryptionKey(authReq)
	require.NoError(t, err)
	assert.Equal(t, "only-key", kid)
}

func TestExtractVerifierEncryptionKey_NoKeysReturnsError(t *testing.T) {
	h := &OID4VPHandler{}
	authReq := &AuthorizationRequest{
		ClientMetadata: &ClientMetadata{},
	}

	_, _, err := h.extractVerifierEncryptionKey(authReq)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no verifier encryption key found")
}

// splitDots splits a string by "." — a minimal helper for counting JWE parts.
func splitDots(s string) []string {
	var parts []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '.' {
			parts = append(parts, s[start:i])
			start = i + 1
		}
	}
	parts = append(parts, s[start:])
	return parts
}

// ===== extractVerifierEncryptionJWK tests =====

func TestExtractVerifierEncryptionJWK_PrefersUseEnc(t *testing.T) {
	sigKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	encKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	jwksBytes := makeJWKS(
		jose.JSONWebKey{Key: &sigKey.PublicKey, KeyID: "sig-key-1", Use: "sig"},
		jose.JSONWebKey{Key: &encKey.PublicKey, KeyID: "enc-key-1", Use: "enc"},
	)

	h := &OID4VPHandler{}
	authReq := &AuthorizationRequest{
		ClientMetadata: &ClientMetadata{JWKS: jwksBytes},
	}

	jwk, err := h.extractVerifierEncryptionJWK(authReq)
	require.NoError(t, err)
	assert.Equal(t, "enc-key-1", jwk.KeyID)
}

func TestExtractVerifierEncryptionJWK_FallsBackToFirstKey(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	jwksBytes := makeJWKS(jose.JSONWebKey{Key: &key.PublicKey, KeyID: "only-key"})

	h := &OID4VPHandler{}
	authReq := &AuthorizationRequest{
		ClientMetadata: &ClientMetadata{JWKS: jwksBytes},
	}

	result, err := h.extractVerifierEncryptionJWK(authReq)
	require.NoError(t, err)
	assert.Equal(t, "only-key", result.KeyID)
}

func TestExtractVerifierEncryptionJWK_NoKeysReturnsError(t *testing.T) {
	h := &OID4VPHandler{}
	authReq := &AuthorizationRequest{
		ClientMetadata: &ClientMetadata{},
	}

	_, err := h.extractVerifierEncryptionJWK(authReq)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no verifier encryption JWK found")
}

func TestExtractVerifierEncryptionJWK_NilMetadata(t *testing.T) {
	h := &OID4VPHandler{}
	authReq := &AuthorizationRequest{}

	_, err := h.extractVerifierEncryptionJWK(authReq)
	require.Error(t, err)
}

func TestExtractVerifierEncryptionJWK_FallsBackToX5C(t *testing.T) {
	// Generate a key and self-signed certificate for the verifier
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-verifier"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	// Build a minimal request JWT header containing x5c (no client_metadata.jwks)
	certB64 := base64.StdEncoding.EncodeToString(certDER)
	headerBytes, err := json.Marshal(map[string]interface{}{
		"alg": "ES256",
		"kid": "test-x5c-kid",
		"x5c": []string{certB64},
	})
	require.NoError(t, err)
	requestJWT := base64.RawURLEncoding.EncodeToString(headerBytes) + ".payload.signature"

	h := &OID4VPHandler{}
	authReq := &AuthorizationRequest{RequestJWT: requestJWT}

	jwk, err := h.extractVerifierEncryptionJWK(authReq)
	require.NoError(t, err)
	assert.Equal(t, "test-x5c-kid", jwk.KeyID)
	assert.IsType(t, &ecdsa.PublicKey{}, jwk.Key)
}

func TestExtractVerifierEncryptionJWK_ThumbprintIsConsistent(t *testing.T) {
	encKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	jwksBytes := makeJWKS(jose.JSONWebKey{
		Key:   &encKey.PublicKey,
		KeyID: "enc-key-1",
		Use:   "enc",
	})

	h := &OID4VPHandler{}
	authReq := &AuthorizationRequest{
		ClientMetadata: &ClientMetadata{JWKS: jwksBytes},
	}

	jwk, err := h.extractVerifierEncryptionJWK(authReq)
	require.NoError(t, err)

	// Compute thumbprint twice — must be deterministic
	thumb1, err := jwk.Thumbprint(crypto.SHA256)
	require.NoError(t, err)
	thumb2, err := jwk.Thumbprint(crypto.SHA256)
	require.NoError(t, err)

	assert.Equal(t, thumb1, thumb2, "thumbprint must be deterministic")
	assert.Len(t, thumb1, 32, "SHA-256 thumbprint must be 32 bytes")

	// Base64url encoding must round-trip
	encoded := base64.RawURLEncoding.EncodeToString(thumb1)
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	require.NoError(t, err)
	assert.Equal(t, thumb1, decoded)
}

// ===== SignRequestParams serialization =====

func TestSignRequestParams_VerifierJwkThumbprint_JSON(t *testing.T) {
	params := SignRequestParams{
		Audience:              "https://verifier.example.com",
		Nonce:                 "test-nonce",
		ResponseURI:           "https://verifier.example.com/response",
		VerifierJwkThumbprint: "abc123thumbprint",
	}

	data, err := json.Marshal(params)
	require.NoError(t, err)

	var parsed map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &parsed))

	assert.Equal(t, "abc123thumbprint", parsed["verifier_jwk_thumbprint"])
	// MdocNonce field should not exist
	_, hasMdocNonce := parsed["mdoc_nonce"]
	assert.False(t, hasMdocNonce, "mdoc_nonce field should not be present")
}

func TestSignRequestParams_VerifierJwkThumbprint_OmittedWhenEmpty(t *testing.T) {
	params := SignRequestParams{
		Audience: "https://verifier.example.com",
		Nonce:    "test-nonce",
	}

	data, err := json.Marshal(params)
	require.NoError(t, err)

	var parsed map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &parsed))

	_, hasThumbprint := parsed["verifier_jwk_thumbprint"]
	assert.False(t, hasThumbprint, "verifier_jwk_thumbprint should be omitted when empty")
}

// makeJWKS builds a JWKS JSON blob from jose.JSONWebKey values.
func makeJWKS(keys ...jose.JSONWebKey) json.RawMessage {
	rawKeys := make([]json.RawMessage, len(keys))
	for i, k := range keys {
		b, _ := k.MarshalJSON()
		rawKeys[i] = b
	}
	out, _ := json.Marshal(map[string]any{"keys": rawKeys})
	return out
}

// --- Tests for validateAuthorizationRequest and extracted helpers ---

func TestValidateAuthorizationRequest_MissingNonce(t *testing.T) {
	h := &OID4VPHandler{}
	authReq := &AuthorizationRequest{
		ResponseMode:   ResponseModeDirectPost,
		ResponseURI:    "https://verifier.example.com/response",
		ClientID:       "https://verifier.example.com",
		ClientIDScheme: ClientIDSchemeRedirectURI,
	}
	err := h.validateAuthorizationRequest(authReq, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nonce")
}

func TestValidateAuthorizationRequest_RedirectURIForbidden(t *testing.T) {
	h := &OID4VPHandler{}
	authReq := &AuthorizationRequest{
		Nonce:          "abc",
		ResponseMode:   ResponseModeDirectPost,
		ResponseURI:    "https://verifier.example.com/response",
		RedirectURI:    "https://evil.example.com/redirect",
		ClientID:       "https://verifier.example.com",
		ClientIDScheme: ClientIDSchemeRedirectURI,
	}
	err := h.validateAuthorizationRequest(authReq, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "redirect_uri must not be present")
}

func TestValidateAuthorizationRequest_RedirectURIForbiddenJWT(t *testing.T) {
	h := &OID4VPHandler{}
	authReq := &AuthorizationRequest{
		Nonce:          "abc",
		ResponseMode:   ResponseModeDirectPostJWT,
		ResponseURI:    "https://verifier.example.com/response",
		RedirectURI:    "https://evil.example.com/redirect",
		ClientID:       "https://verifier.example.com",
		ClientIDScheme: ClientIDSchemeRedirectURI,
	}
	err := h.validateAuthorizationRequest(authReq, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "redirect_uri must not be present")
}

func TestValidateAuthorizationRequest_UnsupportedClientIDScheme(t *testing.T) {
	h := &OID4VPHandler{}
	authReq := &AuthorizationRequest{
		Nonce:          "abc",
		ResponseMode:   ResponseModeDirectPost,
		ResponseURI:    "https://verifier.example.com/response",
		ClientID:       "https://verifier.example.com",
		ClientIDScheme: "unknown_scheme",
	}
	err := h.validateAuthorizationRequest(authReq, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported client_id_scheme")
}

func TestValidateAuthorizationRequest_MissingResponseURI(t *testing.T) {
	h := &OID4VPHandler{}
	authReq := &AuthorizationRequest{
		Nonce:          "abc",
		ResponseMode:   ResponseModeDirectPost,
		ClientID:       "https://verifier.example.com",
		ClientIDScheme: ClientIDSchemeRedirectURI,
	}
	err := h.validateAuthorizationRequest(authReq, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "response_uri is required")
}

func TestValidateAuthorizationRequest_DefaultResponseMode(t *testing.T) {
	h := &OID4VPHandler{}
	// Empty ResponseMode should default to direct_post, which requires response_uri.
	authReq := &AuthorizationRequest{
		Nonce:          "abc",
		ResponseMode:   "", // defaults to direct_post
		ClientID:       "https://verifier.example.com",
		ClientIDScheme: ClientIDSchemeRedirectURI,
	}
	err := h.validateAuthorizationRequest(authReq, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "response_uri is required")
}

func TestValidateAuthorizationRequest_ValidMinimal(t *testing.T) {
	h := &OID4VPHandler{}
	authReq := &AuthorizationRequest{
		Nonce:          "abc",
		ResponseMode:   ResponseModeDirectPost,
		ResponseURI:    "https://verifier.example.com/response",
		ClientID:       "https://verifier.example.com",
		ClientIDScheme: ClientIDSchemeRedirectURI,
	}
	err := h.validateAuthorizationRequest(authReq, nil)
	assert.NoError(t, err)
}

func TestValidateClientIDMatch_Mismatch(t *testing.T) {
	authReq := &AuthorizationRequest{
		ClientID:   "https://real-verifier.example.com",
		RequestJWT: "dummy.jwt.token",
	}
	msg := &FlowStartMessage{
		RequestURI: "openid4vp://authorize?client_id=https%3A%2F%2Fother.example.com&request_uri=https%3A%2F%2Freal-verifier.example.com%2Frequest",
	}
	err := validateClientIDMatch(authReq, msg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "client_id mismatch")
}

func TestValidateClientIDMatch_Matching(t *testing.T) {
	authReq := &AuthorizationRequest{
		ClientID:   "https://verifier.example.com",
		RequestJWT: "dummy.jwt.token",
	}
	msg := &FlowStartMessage{
		RequestURI: "https://verifier.example.com/request?client_id=https%3A%2F%2Fverifier.example.com",
	}
	err := validateClientIDMatch(authReq, msg)
	assert.NoError(t, err)
}

func TestValidateClientIDMatch_NilMsg(t *testing.T) {
	authReq := &AuthorizationRequest{ClientID: "x", RequestJWT: "y"}
	assert.NoError(t, validateClientIDMatch(authReq, nil))
}

func TestValidateClientIDMatch_NoRequestURI(t *testing.T) {
	authReq := &AuthorizationRequest{ClientID: "x", RequestJWT: "y"}
	msg := &FlowStartMessage{}
	assert.NoError(t, validateClientIDMatch(authReq, msg))
}

func TestValidateClientIDMatch_NoJWT(t *testing.T) {
	authReq := &AuthorizationRequest{ClientID: "x"}
	msg := &FlowStartMessage{RequestURI: "https://example.com?client_id=other"}
	assert.NoError(t, validateClientIDMatch(authReq, msg))
}

func TestValidateResponseURIOrigin_Mismatch(t *testing.T) {
	authReq := &AuthorizationRequest{
		ResponseURI:    "https://evil.example.com/response",
		ClientIDScheme: ClientIDSchemeX509SANDNS,
	}
	msg := &FlowStartMessage{
		RequestURI: "https://verifier.example.com/request",
	}
	err := validateResponseURIOrigin(authReq, msg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not match request_uri origin")
}

func TestValidateResponseURIOrigin_Match(t *testing.T) {
	authReq := &AuthorizationRequest{
		ResponseURI:    "https://verifier.example.com/response",
		ClientIDScheme: ClientIDSchemeX509SANDNS,
	}
	msg := &FlowStartMessage{
		RequestURI: "https://verifier.example.com/request",
	}
	err := validateResponseURIOrigin(authReq, msg)
	assert.NoError(t, err)
}

func TestValidateResponseURIOrigin_OpenID4VPScheme(t *testing.T) {
	authReq := &AuthorizationRequest{
		ResponseURI:    "https://verifier.example.com/response",
		ClientIDScheme: ClientIDSchemeX509SANDNS,
	}
	msg := &FlowStartMessage{
		RequestURI: "openid4vp://authorize?request_uri=https%3A%2F%2Fverifier.example.com%2Frequest",
	}
	err := validateResponseURIOrigin(authReq, msg)
	assert.NoError(t, err)
}

func TestValidateResponseURIOrigin_SkipsNonX509Scheme(t *testing.T) {
	// Origin check should be skipped for non-x509_san_dns schemes.
	authReq := &AuthorizationRequest{
		ResponseURI:    "https://evil.example.com/response",
		ClientIDScheme: ClientIDSchemeRedirectURI,
	}
	msg := &FlowStartMessage{
		RequestURI: "https://verifier.example.com/request",
	}
	err := validateResponseURIOrigin(authReq, msg)
	assert.NoError(t, err)
}

func TestValidateResponseURIOrigin_RawQueryString(t *testing.T) {
	// When RequestURI is a raw query string (no scheme/host), skip origin check.
	authReq := &AuthorizationRequest{
		ResponseURI:    "https://verifier.example.com/response",
		ClientIDScheme: ClientIDSchemeX509SANDNS,
	}
	msg := &FlowStartMessage{
		RequestURI: "client_id=foo&request_uri=https%3A%2F%2Fverifier.example.com%2Frequest",
	}
	err := validateResponseURIOrigin(authReq, msg)
	assert.NoError(t, err)
}

func TestValidateResponseURIOrigin_NoResponseURI(t *testing.T) {
	authReq := &AuthorizationRequest{}
	msg := &FlowStartMessage{RequestURI: "https://verifier.example.com/request"}
	assert.NoError(t, validateResponseURIOrigin(authReq, msg))
}

func TestValidateResponseURIOrigin_NilMsg(t *testing.T) {
	authReq := &AuthorizationRequest{ResponseURI: "https://verifier.example.com"}
	assert.NoError(t, validateResponseURIOrigin(authReq, nil))
}

func TestValidateTransactionData_Empty(t *testing.T) {
	authReq := &AuthorizationRequest{}
	assert.NoError(t, validateTransactionData(authReq))
}

func TestValidateTransactionData_Valid(t *testing.T) {
	td := TransactionData{Type: "owf_payment_initiation"}
	tdJSON, _ := json.Marshal(td)
	encoded := base64.RawURLEncoding.EncodeToString(tdJSON)
	raw, _ := json.Marshal([]string{encoded})

	authReq := &AuthorizationRequest{TransactionDataRaw: raw}
	err := validateTransactionData(authReq)
	assert.NoError(t, err)
	require.Len(t, authReq.TransactionData, 1)
	assert.Equal(t, "owf_payment_initiation", authReq.TransactionData[0].Type)
}

func TestValidateTransactionData_InvalidBase64(t *testing.T) {
	raw, _ := json.Marshal([]string{"not-valid-base64!!!"})
	authReq := &AuthorizationRequest{TransactionDataRaw: raw}
	err := validateTransactionData(authReq)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid base64url encoding")
}

func TestValidateTransactionData_InvalidJSON(t *testing.T) {
	encoded := base64.RawURLEncoding.EncodeToString([]byte("{bad json"))
	raw, _ := json.Marshal([]string{encoded})
	authReq := &AuthorizationRequest{TransactionDataRaw: raw}
	err := validateTransactionData(authReq)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid JSON")
}

func TestValidateTransactionData_UnsupportedType(t *testing.T) {
	td := TransactionData{Type: "unsupported_type"}
	tdJSON, _ := json.Marshal(td)
	encoded := base64.RawURLEncoding.EncodeToString(tdJSON)
	raw, _ := json.Marshal([]string{encoded})

	authReq := &AuthorizationRequest{TransactionDataRaw: raw}
	err := validateTransactionData(authReq)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported transaction_data type")
}

func TestValidateTransactionData_NotStringArray(t *testing.T) {
	authReq := &AuthorizationRequest{TransactionDataRaw: json.RawMessage(`[123, 456]`)}
	err := validateTransactionData(authReq)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expected array of base64url strings")
}

func TestValidateTransactionData_Null(t *testing.T) {
	authReq := &AuthorizationRequest{TransactionDataRaw: json.RawMessage(`null`)}
	err := validateTransactionData(authReq)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must be an array, not null")
}

func TestBuildDCQLVPToken_SingleCredential(t *testing.T) {
	selected := []ConsentSelection{
		{CredentialQueryID: "query1"},
	}
	result, err := buildDCQLVPToken("token1", selected)
	require.NoError(t, err)

	var obj map[string][]string
	require.NoError(t, json.Unmarshal([]byte(result), &obj))
	assert.Equal(t, []string{"token1"}, obj["query1"])
}

func TestBuildDCQLVPToken_MultipleCredentials(t *testing.T) {
	selected := []ConsentSelection{
		{CredentialQueryID: "query1"},
		{CredentialQueryID: "query2"},
	}
	result, err := buildDCQLVPToken("token1\ntoken2", selected)
	require.NoError(t, err)

	var obj map[string][]string
	require.NoError(t, json.Unmarshal([]byte(result), &obj))
	assert.Equal(t, []string{"token1"}, obj["query1"])
	assert.Equal(t, []string{"token2"}, obj["query2"])
}

func TestBuildDCQLVPToken_SameQueryID(t *testing.T) {
	selected := []ConsentSelection{
		{CredentialQueryID: "query1"},
		{CredentialQueryID: "query1"},
	}
	result, err := buildDCQLVPToken("tokenA\ntokenB", selected)
	require.NoError(t, err)

	var obj map[string][]string
	require.NoError(t, json.Unmarshal([]byte(result), &obj))
	assert.Equal(t, []string{"tokenA", "tokenB"}, obj["query1"])
}

func TestBuildDCQLVPToken_EmptyQueryID(t *testing.T) {
	selected := []ConsentSelection{
		{CredentialQueryID: ""},
		{CredentialQueryID: "query1"},
	}
	result, err := buildDCQLVPToken("token0\ntoken1", selected)
	require.NoError(t, err)

	var obj map[string][]string
	require.NoError(t, json.Unmarshal([]byte(result), &obj))
	_, hasEmpty := obj[""]
	assert.False(t, hasEmpty, "empty query ID should be skipped")
	assert.Equal(t, []string{"token1"}, obj["query1"])
}

func TestBuildDCQLVPToken_JSONObjectPassThrough(t *testing.T) {
	jsonObj := `{"query1":["token1"],"query2":["token2"]}`
	selected := []ConsentSelection{{CredentialQueryID: "query1"}}
	result, err := buildDCQLVPToken(jsonObj, selected)
	require.NoError(t, err)
	assert.Equal(t, jsonObj, result)
}

func TestBuildDCQLVPToken_TokenCountMismatch(t *testing.T) {
	selected := []ConsentSelection{
		{CredentialQueryID: "query1"},
		{CredentialQueryID: "query2"},
	}
	_, err := buildDCQLVPToken("only-one-token", selected)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "1 tokens but 2 credentials")
}

// --- Tests for x509_san_dns JWT verification in validateAuthorizationRequest ---

// makeSignedJWTWithX5C creates a properly signed JWT with an x5c header for testing.
func makeSignedJWTWithX5C(t *testing.T) (string, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-verifier"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"verifier.example.com"},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	certB64 := base64.StdEncoding.EncodeToString(certDER)

	// Build JWT header with x5c
	headerJSON, _ := json.Marshal(map[string]interface{}{
		"alg": "ES256",
		"typ": "JWT",
		"x5c": []string{certB64},
	})
	header := base64.RawURLEncoding.EncodeToString(headerJSON)

	// Build JWT payload
	payloadJSON, _ := json.Marshal(map[string]interface{}{
		"iss": "verifier.example.com",
		"aud": "https://wallet.example.com",
		"iat": time.Now().Unix(),
	})
	payload := base64.RawURLEncoding.EncodeToString(payloadJSON)

	// Sign
	signingInput := header + "." + payload
	token := jwt.New(jwt.SigningMethodES256)
	sigBytes, err := token.Method.Sign(signingInput, key)
	require.NoError(t, err)

	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sigBytes), key
}

func TestValidateAuthorizationRequest_X509SANDNS_ValidJWT(t *testing.T) {
	jwtToken, _ := makeSignedJWTWithX5C(t)
	h := &OID4VPHandler{}
	authReq := &AuthorizationRequest{
		Nonce:          "abc",
		ResponseMode:   ResponseModeDirectPost,
		ResponseURI:    "https://verifier.example.com/response",
		ClientID:       "verifier.example.com",
		ClientIDScheme: ClientIDSchemeX509SANDNS,
		RequestJWT:     jwtToken,
	}
	err := h.validateAuthorizationRequest(authReq, nil)
	assert.NoError(t, err)
}

func TestValidateAuthorizationRequest_X509SANDNS_InvalidJWT(t *testing.T) {
	h := &OID4VPHandler{}
	authReq := &AuthorizationRequest{
		Nonce:          "abc",
		ResponseMode:   ResponseModeDirectPost,
		ResponseURI:    "https://verifier.example.com/response",
		ClientID:       "verifier.example.com",
		ClientIDScheme: ClientIDSchemeX509SANDNS,
		RequestJWT:     "invalid.jwt.token",
	}
	err := h.validateAuthorizationRequest(authReq, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "JWT signature verification failed")
}

func TestValidateAuthorizationRequest_X509SANDNS_JWKHeaderRejected(t *testing.T) {
	// Create a JWT with jwk header instead of x5c — should be rejected for x509_san_dns
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	jwkMap := map[string]interface{}{
		"kty": "EC",
		"crv": "P-256",
		"x":   base64.RawURLEncoding.EncodeToString(key.PublicKey.X.Bytes()),
		"y":   base64.RawURLEncoding.EncodeToString(key.PublicKey.Y.Bytes()),
	}
	headerJSON, _ := json.Marshal(map[string]interface{}{
		"alg": "ES256",
		"typ": "JWT",
		"jwk": jwkMap,
	})
	header := base64.RawURLEncoding.EncodeToString(headerJSON)
	payloadJSON, _ := json.Marshal(map[string]interface{}{"iss": "test"})
	payload := base64.RawURLEncoding.EncodeToString(payloadJSON)

	signingInput := header + "." + payload
	token := jwt.New(jwt.SigningMethodES256)
	sigBytes, err := token.Method.Sign(signingInput, key)
	require.NoError(t, err)

	h := &OID4VPHandler{}
	authReq := &AuthorizationRequest{
		Nonce:          "abc",
		ResponseMode:   ResponseModeDirectPost,
		ResponseURI:    "https://verifier.example.com/response",
		ClientID:       "verifier.example.com",
		ClientIDScheme: ClientIDSchemeX509SANDNS,
		RequestJWT:     signingInput + "." + base64.RawURLEncoding.EncodeToString(sigBytes),
	}
	err = h.validateAuthorizationRequest(authReq, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "requires x5c")
}

func TestValidateAuthorizationRequest_X509SANDNS_NoJWTSkipsCheck(t *testing.T) {
	h := &OID4VPHandler{}
	authReq := &AuthorizationRequest{
		Nonce:          "abc",
		ResponseMode:   ResponseModeDirectPost,
		ResponseURI:    "https://verifier.example.com/response",
		ClientID:       "verifier.example.com",
		ClientIDScheme: ClientIDSchemeX509SANDNS,
		// No RequestJWT — the JWT verification step should be skipped
	}
	err := h.validateAuthorizationRequest(authReq, nil)
	assert.NoError(t, err)
}

// --- Tests for inferClientIDScheme new branches ---

func TestInferClientIDScheme_ColonPrefix(t *testing.T) {
	// A colon-separated prefix that doesn't look like a domain should be returned raw
	got := inferClientIDScheme("custom_scheme:some-value")
	assert.Equal(t, "custom_scheme", got)
}

func TestInferClientIDScheme_ColonPrefixWithDots(t *testing.T) {
	// A prefix with dots looks like a domain — should default to redirect_uri
	got := inferClientIDScheme("example.com:8080")
	assert.Equal(t, ClientIDSchemeRedirectURI, got)
}

func TestInferClientIDScheme_ColonPrefixWithSlash(t *testing.T) {
	// A prefix with slashes looks like a path — should default to redirect_uri
	got := inferClientIDScheme("path/to:something")
	assert.Equal(t, ClientIDSchemeRedirectURI, got)
}

func TestInferClientIDScheme_X509SANDNS(t *testing.T) {
	got := inferClientIDScheme("x509_san_dns:verifier.example.com")
	assert.Equal(t, ClientIDSchemeX509SANDNS, got)
}

func TestInferClientIDScheme_X509SANURI(t *testing.T) {
	got := inferClientIDScheme("x509_san_uri:https://verifier.example.com")
	assert.Equal(t, ClientIDSchemeX509SANURI, got)
}

func TestInferClientIDScheme_VerifierAttestation(t *testing.T) {
	got := inferClientIDScheme("verifier_attestation:eyJ...")
	assert.Equal(t, ClientIDSchemeVerifierAttestation, got)
}

// --- Tests for computeVerifierJWKThumbprint ---

func TestComputeVerifierJWKThumbprint_NonJWTMode(t *testing.T) {
	h := &OID4VPHandler{}
	h.BaseHandler = BaseHandler{Logger: zap.NewNop()}
	authReq := &AuthorizationRequest{
		ResponseMode: ResponseModeDirectPost,
	}
	assert.Equal(t, "", h.computeVerifierJWKThumbprint(authReq))
}

func TestComputeVerifierJWKThumbprint_JWTMode(t *testing.T) {
	encKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	jwksBytes := makeJWKS(jose.JSONWebKey{
		Key:   &encKey.PublicKey,
		KeyID: "enc-key-1",
		Use:   "enc",
	})

	h := &OID4VPHandler{}
	h.BaseHandler = BaseHandler{Logger: zap.NewNop()}
	authReq := &AuthorizationRequest{
		ResponseMode: ResponseModeDirectPostJWT,
		ClientMetadata: &ClientMetadata{
			JWKS: jwksBytes,
		},
	}
	result := h.computeVerifierJWKThumbprint(authReq)
	assert.NotEmpty(t, result, "should return a non-empty thumbprint")
}

func TestComputeVerifierJWKThumbprint_JWTModeNoKeys(t *testing.T) {
	h := &OID4VPHandler{}
	h.BaseHandler = BaseHandler{Logger: zap.NewNop()}
	authReq := &AuthorizationRequest{
		ResponseMode: ResponseModeDirectPostJWT,
		// No client metadata — should warn and return empty
	}
	assert.Equal(t, "", h.computeVerifierJWKThumbprint(authReq))
}

// --- Test for validateAuthorizationRequest with all known schemes ---

func TestValidateAuthorizationRequest_AllKnownSchemes(t *testing.T) {
	schemes := []string{
		ClientIDSchemeRedirectURI,
		ClientIDSchemeDID,
		ClientIDSchemeX509SANDNS,
		ClientIDSchemeX509SANURI,
		ClientIDSchemeVerifierAttestation,
	}
	h := &OID4VPHandler{}
	for _, scheme := range schemes {
		t.Run(scheme, func(t *testing.T) {
			authReq := &AuthorizationRequest{
				Nonce:          "abc",
				ResponseMode:   ResponseModeDirectPost,
				ResponseURI:    "https://verifier.example.com/response",
				ClientID:       "https://verifier.example.com",
				ClientIDScheme: scheme,
			}
			err := h.validateAuthorizationRequest(authReq, nil)
			assert.NoError(t, err)
		})
	}
}

// --- Test for validateAuthorizationRequest with isDirectPost false ---

func TestValidateAuthorizationRequest_NonDirectPostMode(t *testing.T) {
	h := &OID4VPHandler{}
	// fragment response mode doesn't require response_uri
	authReq := &AuthorizationRequest{
		Nonce:          "abc",
		ResponseMode:   "fragment",
		ClientID:       "https://verifier.example.com",
		ClientIDScheme: ClientIDSchemeRedirectURI,
	}
	err := h.validateAuthorizationRequest(authReq, nil)
	assert.NoError(t, err)
}

// --- Tests for validateAuthorizationRequest calling through helpers ---

func TestValidateAuthorizationRequest_ClientIDMismatchViaMsg(t *testing.T) {
	h := &OID4VPHandler{}
	authReq := &AuthorizationRequest{
		Nonce:          "abc",
		ResponseMode:   ResponseModeDirectPost,
		ResponseURI:    "https://verifier.example.com/response",
		ClientID:       "verifier.example.com",
		ClientIDScheme: ClientIDSchemeRedirectURI,
		RequestJWT:     "some.jwt.token",
	}
	msg := &FlowStartMessage{
		RequestURI: "https://verifier.example.com/request?client_id=other-verifier",
	}
	err := h.validateAuthorizationRequest(authReq, msg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "client_id mismatch")
}

func TestValidateAuthorizationRequest_OriginMismatchViaMsg(t *testing.T) {
	h := &OID4VPHandler{}
	authReq := &AuthorizationRequest{
		Nonce:          "abc",
		ResponseMode:   ResponseModeDirectPost,
		ResponseURI:    "https://evil.example.com/response",
		ClientID:       "verifier.example.com",
		ClientIDScheme: ClientIDSchemeX509SANDNS,
	}
	msg := &FlowStartMessage{
		RequestURI: "https://verifier.example.com/request",
	}
	err := h.validateAuthorizationRequest(authReq, msg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not match request_uri origin")
}

func TestValidateAuthorizationRequest_WithTransactionData(t *testing.T) {
	td := TransactionData{Type: "owf_payment_initiation"}
	tdJSON, _ := json.Marshal(td)
	encoded := base64.RawURLEncoding.EncodeToString(tdJSON)
	raw, _ := json.Marshal([]string{encoded})

	h := &OID4VPHandler{}
	authReq := &AuthorizationRequest{
		Nonce:              "abc",
		ResponseMode:       ResponseModeDirectPost,
		ResponseURI:        "https://verifier.example.com/response",
		ClientID:           "https://verifier.example.com",
		ClientIDScheme:     ClientIDSchemeRedirectURI,
		TransactionDataRaw: raw,
	}
	err := h.validateAuthorizationRequest(authReq, nil)
	assert.NoError(t, err)
	require.Len(t, authReq.TransactionData, 1)
}

// --- Tests for submitErrorResponse ---

func TestSubmitErrorResponse_PostsToResponseURI(t *testing.T) {
	var receivedBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(body)
		receivedBody = string(body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	h := &OID4VPHandler{}
	h.BaseHandler = BaseHandler{Logger: zap.NewNop()}
	h.httpClient = srv.Client()

	authReq := &AuthorizationRequest{
		ResponseURI: srv.URL + "/response",
		State:       "test-state",
	}
	h.submitErrorResponse(context.Background(), authReq, "invalid_request", "bad nonce")

	assert.Contains(t, receivedBody, "error=invalid_request")
	assert.Contains(t, receivedBody, "error_description=bad+nonce")
	assert.Contains(t, receivedBody, "state=test-state")
}

func TestSubmitErrorResponse_NilAuthReq(t *testing.T) {
	h := &OID4VPHandler{}
	h.BaseHandler = BaseHandler{Logger: zap.NewNop()}
	// Should not panic
	h.submitErrorResponse(context.Background(), nil, "error", "desc")
}

func TestSubmitErrorResponse_EmptyResponseURI(t *testing.T) {
	h := &OID4VPHandler{}
	h.BaseHandler = BaseHandler{Logger: zap.NewNop()}
	authReq := &AuthorizationRequest{}
	// Should not panic
	h.submitErrorResponse(context.Background(), authReq, "error", "desc")
}

func TestSubmitErrorResponse_NoState(t *testing.T) {
	var receivedBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(body)
		receivedBody = string(body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	h := &OID4VPHandler{}
	h.BaseHandler = BaseHandler{Logger: zap.NewNop()}
	h.httpClient = srv.Client()

	authReq := &AuthorizationRequest{
		ResponseURI: srv.URL + "/response",
	}
	h.submitErrorResponse(context.Background(), authReq, "invalid_request", "")
	assert.Contains(t, receivedBody, "error=invalid_request")
	assert.NotContains(t, receivedBody, "state=")
}

// --- Tests for submitResponse via direct mode functions ---

func TestSubmitDirectPost_WithConstants(t *testing.T) {
	// Verify the Content-Type constant is used correctly
	var receivedContentType string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedContentType = r.Header.Get("Content-Type")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	h := &OID4VPHandler{httpClient: srv.Client()}
	authReq := &AuthorizationRequest{State: "s1"}

	_, err := h.submitDirectPost(context.Background(), srv.URL, authReq, "vp-token")
	require.NoError(t, err)
	assert.Equal(t, mimeFormURLEncoded, receivedContentType)
}

// --- Edge case tests for validateResponseURIOrigin ---

func TestValidateResponseURIOrigin_OpenID4VPNoRequestURI(t *testing.T) {
	// openid4vp:// scheme but no request_uri query param → requestURL becomes empty → skip
	authReq := &AuthorizationRequest{
		ResponseURI:    "https://verifier.example.com/response",
		ClientIDScheme: ClientIDSchemeX509SANDNS,
	}
	msg := &FlowStartMessage{
		RequestURI: "openid4vp://authorize?client_id=foo",
	}
	err := validateResponseURIOrigin(authReq, msg)
	assert.NoError(t, err)
}
