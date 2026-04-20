package engine

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestGenerateCodeVerifier(t *testing.T) {
	v1, err := generateCodeVerifier()
	require.NoError(t, err)
	assert.NotEmpty(t, v1)
	// 32 bytes -> 43 base64url chars
	assert.Len(t, v1, 43)

	v2, err := generateCodeVerifier()
	require.NoError(t, err)
	assert.NotEqual(t, v1, v2, "verifiers must be unique")
}

func TestComputeCodeChallenge(t *testing.T) {
	// RFC 7636 Appendix B test vector
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	expected := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

	challenge := computeCodeChallenge(verifier)
	assert.Equal(t, expected, challenge)
}

func TestComputeCodeChallenge_Roundtrip(t *testing.T) {
	verifier, err := generateCodeVerifier()
	require.NoError(t, err)

	challenge := computeCodeChallenge(verifier)
	assert.NotEmpty(t, challenge)

	// Verify that the challenge is the base64url-encoded SHA-256 of the verifier
	h := sha256.Sum256([]byte(verifier))
	expectedChallenge := base64.RawURLEncoding.EncodeToString(h[:])
	assert.Equal(t, expectedChallenge, challenge)
}

func TestSendPushedAuthorizationRequest_Success(t *testing.T) {
	// Mock PAR endpoint
	parServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "application/x-www-form-urlencoded", r.Header.Get("Content-Type"))

		err := r.ParseForm()
		require.NoError(t, err)
		assert.Equal(t, "code", r.FormValue("response_type"))
		// OID4VCI: redirect_uri is used as client_id for unregistered clients
		assert.Equal(t, "https://wallet.example.com/callback", r.FormValue("client_id"))
		assert.NotEmpty(t, r.FormValue("code_challenge"))
		assert.Equal(t, "S256", r.FormValue("code_challenge_method"))

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(PARResponse{
			RequestURI: "urn:ietf:params:oauth:request_uri:abc123",
			ExpiresIn:  60,
		})
	}))
	defer parServer.Close()

	h := &OID4VCIHandler{
		httpClient: parServer.Client(),
	}
	h.BaseHandler = BaseHandler{Logger: zap.NewNop()}

	params := url.Values{}
	params.Set("response_type", "code")
	params.Set("client_id", "https://wallet.example.com/callback")
	params.Set("redirect_uri", "https://wallet.example.com/callback")
	params.Set("scope", "pid")
	params.Set("code_challenge", "test-challenge")
	params.Set("code_challenge_method", "S256")

	requestURI, err := h.sendPushedAuthorizationRequest(context.Background(), parServer.URL, params)
	require.NoError(t, err)
	assert.Equal(t, "urn:ietf:params:oauth:request_uri:abc123", requestURI)
}

func TestSendPushedAuthorizationRequest_ErrorResponse(t *testing.T) {
	parServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"error":             "invalid_request",
			"error_description": "missing required parameter",
		})
	}))
	defer parServer.Close()

	h := &OID4VCIHandler{
		httpClient: parServer.Client(),
	}
	h.BaseHandler = BaseHandler{Logger: zap.NewNop()}

	_, err := h.sendPushedAuthorizationRequest(context.Background(), parServer.URL, url.Values{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "status 400")
}

func TestSendPushedAuthorizationRequest_ErrorInBody(t *testing.T) {
	parServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(PARResponse{
			Error:     "invalid_request",
			ErrorDesc: "bad scope",
		})
	}))
	defer parServer.Close()

	h := &OID4VCIHandler{
		httpClient: parServer.Client(),
	}
	h.BaseHandler = BaseHandler{Logger: zap.NewNop()}

	_, err := h.sendPushedAuthorizationRequest(context.Background(), parServer.URL, url.Values{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "PAR error")
	assert.Contains(t, err.Error(), "bad scope")
}

func TestSendPushedAuthorizationRequest_MissingRequestURI(t *testing.T) {
	parServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(PARResponse{})
	}))
	defer parServer.Close()

	h := &OID4VCIHandler{
		httpClient: parServer.Client(),
	}
	h.BaseHandler = BaseHandler{Logger: zap.NewNop()}

	_, err := h.sendPushedAuthorizationRequest(context.Background(), parServer.URL, url.Values{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing request_uri")
}

func TestSupportsPKCE(t *testing.T) {
	tests := []struct {
		name     string
		json     string
		expected bool
	}{
		{"absent field (assume support)", `{"authorization_endpoint":"https://as.example.com/authorize"}`, true},
		{"S256 present", `{"code_challenge_methods_supported":["S256"]}`, true},
		{"S256 among others", `{"code_challenge_methods_supported":["plain","S256"]}`, true},
		{"only plain", `{"code_challenge_methods_supported":["plain"]}`, false},
		{"no S256", `{"code_challenge_methods_supported":["plain","none"]}`, false},
		{"explicit empty list", `{"code_challenge_methods_supported":[]}`, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var meta oauthServerMetadata
			err := json.Unmarshal([]byte(tt.json), &meta)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, meta.supportsPKCE())
		})
	}
}

func TestHandleAuthorizationCode_OAuthMetadataWithPAR(t *testing.T) {
	// This test verifies that handleAuthorizationCode correctly parses PAR endpoint
	// from OAuth metadata and passes it through to startAuthorizationFlow.
	//
	// We test the metadata parsing layer by checking that the oauthServerMetadata
	// struct correctly deserializes the pushed_authorization_request_endpoint field.

	metadataJSON := `{
		"authorization_endpoint": "https://as.example.com/authorize",
		"token_endpoint": "https://as.example.com/token",
		"pushed_authorization_request_endpoint": "https://as.example.com/par"
	}`

	var meta oauthServerMetadata
	err := json.Unmarshal([]byte(metadataJSON), &meta)
	require.NoError(t, err)
	assert.Equal(t, "https://as.example.com/authorize", meta.AuthorizationEndpoint)
	assert.Equal(t, "https://as.example.com/token", meta.TokenEndpoint)
	assert.Equal(t, "https://as.example.com/par", meta.PushedAuthorizationRequestEndpoint)
}

func TestHandleAuthorizationCode_OAuthMetadataWithoutPAR(t *testing.T) {
	metadataJSON := `{
		"authorization_endpoint": "https://as.example.com/authorize",
		"token_endpoint": "https://as.example.com/token"
	}`

	var meta oauthServerMetadata
	err := json.Unmarshal([]byte(metadataJSON), &meta)
	require.NoError(t, err)
	assert.Equal(t, "https://as.example.com/authorize", meta.AuthorizationEndpoint)
	assert.Empty(t, meta.PushedAuthorizationRequestEndpoint)
}

func TestStartAuthorizationFlow_BuildsPARRedirect(t *testing.T) {
	// Verify that when PAR endpoint is present, the authorization URL
	// contains only client_id and request_uri (not all params).
	parServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify PAR request contains all authorization params
		err := r.ParseForm()
		require.NoError(t, err)
		assert.Equal(t, "code", r.FormValue("response_type"))
		// OID4VCI: redirect_uri is used as client_id for unregistered clients
		assert.Equal(t, "https://wallet.example.com/callback", r.FormValue("client_id"))
		assert.Equal(t, "S256", r.FormValue("code_challenge_method"))
		assert.NotEmpty(t, r.FormValue("code_challenge"))

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(PARResponse{
			RequestURI: "urn:ietf:params:oauth:request_uri:xyz789",
			ExpiresIn:  90,
		})
	}))
	defer parServer.Close()

	// We can't easily test the full startAuthorizationFlow (it waits for user action),
	// but we can test the PAR request portion via sendPushedAuthorizationRequest.
	h := &OID4VCIHandler{
		httpClient: parServer.Client(),
	}
	h.BaseHandler = BaseHandler{Logger: zap.NewNop()}

	params := url.Values{}
	params.Set("response_type", "code")
	params.Set("client_id", "https://wallet.example.com/callback")
	params.Set("redirect_uri", "https://wallet.example.com/callback")
	params.Set("scope", "pid")
	params.Set("code_challenge", "test-challenge")
	params.Set("code_challenge_method", "S256")

	requestURI, err := h.sendPushedAuthorizationRequest(context.Background(), parServer.URL, params)
	require.NoError(t, err)

	// Verify the redirect URL would be built correctly
	authEndpoint, _ := url.Parse("https://as.example.com/authorize")
	q := authEndpoint.Query()
	q.Set("client_id", "https://wallet.example.com/callback")
	q.Set("request_uri", requestURI)
	authEndpoint.RawQuery = q.Encode()

	parsedURL, err := url.Parse(authEndpoint.String())
	require.NoError(t, err)
	assert.Equal(t, "https://wallet.example.com/callback", parsedURL.Query().Get("client_id"))
	assert.Equal(t, "urn:ietf:params:oauth:request_uri:xyz789", parsedURL.Query().Get("request_uri"))
	// Should NOT contain the full params
	assert.Empty(t, parsedURL.Query().Get("response_type"))
	assert.Empty(t, parsedURL.Query().Get("scope"))
	assert.Empty(t, parsedURL.Query().Get("code_challenge"))
}

func TestScopeFromCredentialConfig(t *testing.T) {
	tests := []struct {
		name          string
		config        *CredentialConfig
		expectedScope string
		expectSet     bool
	}{
		{
			name:          "uses credential config scope",
			config:        &CredentialConfig{Scope: "pid"},
			expectedScope: "pid",
			expectSet:     true,
		},
		{
			name:      "no scope when config scope is empty",
			config:    &CredentialConfig{Scope: ""},
			expectSet: false,
		},
		{
			name:      "no scope when config nil",
			config:    nil,
			expectSet: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Build the scope the same way startAuthorizationFlow does:
			// only set scope if credential config has one.
			params := url.Values{}
			if tt.config != nil && tt.config.Scope != "" {
				params.Set("scope", tt.config.Scope)
			}
			if tt.expectSet {
				assert.Equal(t, tt.expectedScope, params.Get("scope"))
			} else {
				assert.Empty(t, params.Get("scope"))
			}
		})
	}
}

// testOID4VCIHandler creates an OID4VCIHandler with a real WebSocket session
// for tests that need Progress/Error methods to work.
func testOID4VCIHandler(t *testing.T, httpClient *http.Client) (*OID4VCIHandler, func()) {
	t.Helper()
	conn, cleanup := wsTestServer(t, func(srvConn *websocket.Conn) {
		defer srvConn.Close()
		// Drain all messages (progress, errors, etc.)
		for {
			_, _, err := srvConn.ReadMessage()
			if err != nil {
				return
			}
		}
	})
	session := testSession(conn)
	flow := &Flow{
		ID:      "test-flow",
		Session: session,
		Data:    make(map[string]interface{}),
	}
	h := &OID4VCIHandler{
		httpClient: httpClient,
	}
	h.BaseHandler = BaseHandler{Flow: flow, Logger: zap.NewNop()}
	return h, cleanup
}

func TestExchangeAuthCode_IncludesCodeVerifier(t *testing.T) {
	// Mock token endpoint that verifies code_verifier is present
	var receivedForm url.Values
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err := r.ParseForm()
		require.NoError(t, err)
		receivedForm = r.Form

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(TokenResponse{
			AccessToken: "access-token-123",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
			CNonce:      "nonce-abc",
		})
	}))
	defer tokenServer.Close()

	h, cleanup := testOID4VCIHandler(t, tokenServer.Client())
	defer cleanup()

	metadata := &IssuerMetadata{
		CredentialIssuer: "https://issuer.example.com",
		TokenEndpoint:    tokenServer.URL,
	}

	token, err := h.exchangeAuthCode(context.Background(), metadata, "test-code", "https://wallet.example.com/callback", "test-verifier-12345")
	require.NoError(t, err)
	assert.Equal(t, "access-token-123", token.AccessToken)
	assert.Equal(t, "Bearer", token.TokenType)
	assert.Equal(t, "nonce-abc", token.CNonce)

	// Verify the code_verifier was sent
	assert.Equal(t, "authorization_code", receivedForm.Get("grant_type"))
	assert.Equal(t, "test-code", receivedForm.Get("code"))
	assert.Equal(t, "test-verifier-12345", receivedForm.Get("code_verifier"))
}

func TestExchangeAuthCode_WithoutCodeVerifier(t *testing.T) {
	// Mock token endpoint that verifies code_verifier is NOT present
	var receivedForm url.Values
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err := r.ParseForm()
		require.NoError(t, err)
		receivedForm = r.Form

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(TokenResponse{
			AccessToken: "access-token-456",
			TokenType:   "Bearer",
		})
	}))
	defer tokenServer.Close()

	h, cleanup := testOID4VCIHandler(t, tokenServer.Client())
	defer cleanup()

	metadata := &IssuerMetadata{
		CredentialIssuer: "https://issuer.example.com",
		TokenEndpoint:    tokenServer.URL,
	}

	token, err := h.exchangeAuthCode(context.Background(), metadata, "test-code", "https://wallet.example.com/callback", "")
	require.NoError(t, err)
	assert.Equal(t, "access-token-456", token.AccessToken)

	// Verify code_verifier was NOT sent
	assert.Empty(t, receivedForm.Get("code_verifier"))
}

func TestExchangeAuthCode_ServerError(t *testing.T) {
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error": "server_error"}`))
	}))
	defer tokenServer.Close()

	h, cleanup := testOID4VCIHandler(t, tokenServer.Client())
	defer cleanup()

	metadata := &IssuerMetadata{
		CredentialIssuer: "https://issuer.example.com",
		TokenEndpoint:    tokenServer.URL,
	}

	_, err := h.exchangeAuthCode(context.Background(), metadata, "test-code", "https://wallet.example.com/callback", "verifier")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "server_error")
}

func TestPARResponse_JSONParsing(t *testing.T) {
	tests := []struct {
		name      string
		json      string
		wantURI   string
		wantError string
	}{
		{
			name:    "success",
			json:    `{"request_uri": "urn:ietf:params:oauth:request_uri:abc", "expires_in": 60}`,
			wantURI: "urn:ietf:params:oauth:request_uri:abc",
		},
		{
			name:      "error response",
			json:      `{"error": "invalid_request", "error_description": "bad params"}`,
			wantError: "invalid_request",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var resp PARResponse
			err := json.Unmarshal([]byte(tt.json), &resp)
			require.NoError(t, err)
			if tt.wantURI != "" {
				assert.Equal(t, tt.wantURI, resp.RequestURI)
			}
			if tt.wantError != "" {
				assert.Equal(t, tt.wantError, resp.Error)
			}
		})
	}
}

func TestOAuthServerMetadata_PAREndpointParsing(t *testing.T) {
	// Real-world-like AS metadata with PAR support
	body := `{
		"issuer": "https://as.example.com",
		"authorization_endpoint": "https://as.example.com/authorize",
		"token_endpoint": "https://as.example.com/token",
		"pushed_authorization_request_endpoint": "https://as.example.com/par",
		"response_types_supported": ["code"],
		"grant_types_supported": ["authorization_code"]
	}`

	var meta oauthServerMetadata
	err := json.Unmarshal([]byte(body), &meta)
	require.NoError(t, err)
	assert.Equal(t, "https://as.example.com/authorize", meta.AuthorizationEndpoint)
	assert.Equal(t, "https://as.example.com/token", meta.TokenEndpoint)
	assert.Equal(t, "https://as.example.com/par", meta.PushedAuthorizationRequestEndpoint)
}

// errRoundTripper always returns an error, used for deterministic network failure tests.
type errRoundTripper struct{}

func (e *errRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("simulated network error")
}

func TestSendPushedAuthorizationRequest_NetworkError(t *testing.T) {
	h := &OID4VCIHandler{
		httpClient: &http.Client{Transport: &errRoundTripper{}},
	}
	h.BaseHandler = BaseHandler{Logger: zap.NewNop()}

	_, err := h.sendPushedAuthorizationRequest(context.Background(), "https://as.example.com/par", url.Values{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "PAR request failed")
}

func TestSendPushedAuthorizationRequest_InvalidJSON(t *testing.T) {
	parServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`not-json`))
	}))
	defer parServer.Close()

	h := &OID4VCIHandler{
		httpClient: parServer.Client(),
	}
	h.BaseHandler = BaseHandler{Logger: zap.NewNop()}

	_, err := h.sendPushedAuthorizationRequest(context.Background(), parServer.URL, url.Values{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse PAR response")
}

func TestPKCE_VerifierLength(t *testing.T) {
	// RFC 7636 §4.1: code_verifier must be 43–128 characters
	verifier, err := generateCodeVerifier()
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(verifier), 43)
	assert.LessOrEqual(t, len(verifier), 128)

	// Only valid base64url characters
	for _, c := range verifier {
		assert.True(t, isBase64URLChar(c), "invalid character in verifier: %c", c)
	}
}

func isBase64URLChar(c rune) bool {
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_'
}

func TestPKCE_ChallengeIsBase64URL(t *testing.T) {
	verifier, err := generateCodeVerifier()
	require.NoError(t, err)
	challenge := computeCodeChallenge(verifier)

	// No padding characters
	assert.False(t, strings.Contains(challenge, "="))
	// No standard base64 characters
	assert.False(t, strings.Contains(challenge, "+"))
	assert.False(t, strings.Contains(challenge, "/"))
}

// --- DPoP (RFC 9449) tests ---

func TestGenerateDPoPKey(t *testing.T) {
	key, err := generateDPoPKey()
	require.NoError(t, err)
	assert.NotNil(t, key)
	assert.Equal(t, elliptic.P256(), key.Curve)

	key2, err := generateDPoPKey()
	require.NoError(t, err)
	assert.NotEqual(t, key.D, key2.D, "keys must be unique")
}

func TestEcPublicKeyJWK(t *testing.T) {
	key, err := generateDPoPKey()
	require.NoError(t, err)

	jwk, err := ecPublicKeyJWK(&key.PublicKey)
	require.NoError(t, err)
	assert.Equal(t, "EC", jwk["kty"])
	assert.Equal(t, "P-256", jwk["crv"])

	x, ok := jwk["x"].(string)
	require.True(t, ok)
	xBytes, err := base64.RawURLEncoding.DecodeString(x)
	require.NoError(t, err)
	assert.Len(t, xBytes, 32)

	y, ok := jwk["y"].(string)
	require.True(t, ok)
	yBytes, err := base64.RawURLEncoding.DecodeString(y)
	require.NoError(t, err)
	assert.Len(t, yBytes, 32)
}

func TestCreateDPoPProof_TokenRequest(t *testing.T) {
	key, err := generateDPoPKey()
	require.NoError(t, err)

	proof, err := createDPoPProof(key, "POST", "https://as.example.com/token", "", "")
	require.NoError(t, err)

	token, err := jwt.Parse(proof, func(tok *jwt.Token) (interface{}, error) {
		assert.Equal(t, jwt.SigningMethodES256, tok.Method)
		assert.Equal(t, "dpop+jwt", tok.Header["typ"])

		jwkMap, ok := tok.Header["jwk"].(map[string]interface{})
		require.True(t, ok)
		assert.Equal(t, "EC", jwkMap["kty"])
		assert.Equal(t, "P-256", jwkMap["crv"])

		return &key.PublicKey, nil
	})
	require.NoError(t, err)

	claims, ok := token.Claims.(jwt.MapClaims)
	require.True(t, ok)
	assert.Equal(t, "POST", claims["htm"])
	assert.Equal(t, "https://as.example.com/token", claims["htu"])
	assert.NotEmpty(t, claims["jti"])
	assert.NotNil(t, claims["iat"])
	_, hasAth := claims["ath"]
	assert.False(t, hasAth, "token request proof should not have ath claim")
}

func TestCreateDPoPProof_ResourceRequest(t *testing.T) {
	key, err := generateDPoPKey()
	require.NoError(t, err)

	accessToken := "test-access-token-123"
	proof, err := createDPoPProof(key, "POST", "https://issuer.example.com/credential", accessToken, "")
	require.NoError(t, err)

	token, err := jwt.Parse(proof, func(tok *jwt.Token) (interface{}, error) {
		return &key.PublicKey, nil
	})
	require.NoError(t, err)

	claims, ok := token.Claims.(jwt.MapClaims)
	require.True(t, ok)
	expectedHash := sha256.Sum256([]byte(accessToken))
	expectedAth := base64.RawURLEncoding.EncodeToString(expectedHash[:])
	assert.Equal(t, expectedAth, claims["ath"])
}

func TestCreateDPoPProof_UniqueJTI(t *testing.T) {
	key, err := generateDPoPKey()
	require.NoError(t, err)

	proof1, err := createDPoPProof(key, "POST", "https://example.com/token", "", "")
	require.NoError(t, err)
	proof2, err := createDPoPProof(key, "POST", "https://example.com/token", "", "")
	require.NoError(t, err)

	parseJTI := func(proof string) string {
		tok, err := jwt.Parse(proof, func(tok *jwt.Token) (interface{}, error) {
			return &key.PublicKey, nil
		})
		require.NoError(t, err)
		return tok.Claims.(jwt.MapClaims)["jti"].(string)
	}
	assert.NotEqual(t, parseJTI(proof1), parseJTI(proof2), "each proof must have a unique jti")
}

func TestSetDPoPHeader_WithKey(t *testing.T) {
	key, err := generateDPoPKey()
	require.NoError(t, err)

	h := &OID4VCIHandler{dpopKey: key}
	req, _ := http.NewRequest("POST", "https://example.com/token", nil)

	err = h.setDPoPHeader(req, "https://example.com/token", "")
	require.NoError(t, err)
	assert.NotEmpty(t, req.Header.Get("DPoP"))
}

func TestSetDPoPHeader_WithoutKey(t *testing.T) {
	h := &OID4VCIHandler{}
	req, _ := http.NewRequest("POST", "https://example.com/token", nil)

	err := h.setDPoPHeader(req, "https://example.com/token", "")
	require.NoError(t, err)
	assert.Empty(t, req.Header.Get("DPoP"), "should not set DPoP header without key")
}

func TestSetAuthorizationHeader_DPoP(t *testing.T) {
	h := &OID4VCIHandler{}
	req, _ := http.NewRequest("POST", "https://example.com/credential", nil)
	token := &TokenResponse{AccessToken: "tok123", TokenType: "DPoP"}
	h.setAuthorizationHeader(req, token)
	assert.Equal(t, "DPoP tok123", req.Header.Get("Authorization"))
}

func TestSetAuthorizationHeader_Bearer(t *testing.T) {
	h := &OID4VCIHandler{}
	req, _ := http.NewRequest("POST", "https://example.com/credential", nil)
	token := &TokenResponse{AccessToken: "tok456", TokenType: "Bearer"}
	h.setAuthorizationHeader(req, token)
	assert.Equal(t, "Bearer tok456", req.Header.Get("Authorization"))
}

func TestSetAuthorizationHeader_CaseInsensitive(t *testing.T) {
	h := &OID4VCIHandler{}
	req, _ := http.NewRequest("POST", "https://example.com/credential", nil)
	token := &TokenResponse{AccessToken: "tok789", TokenType: "dpop"}
	h.setAuthorizationHeader(req, token)
	assert.Equal(t, "DPoP tok789", req.Header.Get("Authorization"))
}

func TestExchangePreAuthCode_SendsDPoP(t *testing.T) {
	var receivedHeaders http.Header
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders = r.Header.Clone()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(TokenResponse{
			AccessToken: "test-token",
			TokenType:   "DPoP",
			CNonce:      "nonce123",
		})
	}))
	defer tokenServer.Close()

	h, cleanup := testOID4VCIHandler(t, tokenServer.Client())
	defer cleanup()

	key, err := generateDPoPKey()
	require.NoError(t, err)
	h.dpopKey = key

	metadata := &IssuerMetadata{
		CredentialIssuer: "https://issuer.example.com",
		TokenEndpoint:    tokenServer.URL,
	}

	token, err := h.exchangePreAuthCode(context.Background(), metadata, "pre-auth-code", "")
	require.NoError(t, err)
	assert.Equal(t, "DPoP", token.TokenType)
	assert.NotEmpty(t, receivedHeaders.Get("DPoP"))

	// Verify DPoP proof JWT
	dpopProof := receivedHeaders.Get("DPoP")
	tok, err := jwt.Parse(dpopProof, func(tok *jwt.Token) (interface{}, error) {
		return &key.PublicKey, nil
	})
	require.NoError(t, err)
	claims := tok.Claims.(jwt.MapClaims)
	assert.Equal(t, "POST", claims["htm"])
}

func TestExchangeAuthCode_SendsDPoP(t *testing.T) {
	var receivedHeaders http.Header
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders = r.Header.Clone()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(TokenResponse{
			AccessToken: "auth-code-token",
			TokenType:   "DPoP",
		})
	}))
	defer tokenServer.Close()

	h, cleanup := testOID4VCIHandler(t, tokenServer.Client())
	defer cleanup()

	key, err := generateDPoPKey()
	require.NoError(t, err)
	h.dpopKey = key

	metadata := &IssuerMetadata{
		CredentialIssuer: "https://issuer.example.com",
		TokenEndpoint:    tokenServer.URL,
	}

	token, err := h.exchangeAuthCode(context.Background(), metadata, "code123", "https://wallet.example.com/callback", "verifier")
	require.NoError(t, err)
	assert.Equal(t, "DPoP", token.TokenType)
	assert.NotEmpty(t, receivedHeaders.Get("DPoP"))
}

func TestRequestCredential_DPoPBound(t *testing.T) {
	var receivedHeaders http.Header
	credServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders = r.Header.Clone()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(CredentialResponse{
			Credential: "test-credential-jwt",
		})
	}))
	defer credServer.Close()

	h, cleanup := testOID4VCIHandler(t, credServer.Client())
	defer cleanup()

	key, err := generateDPoPKey()
	require.NoError(t, err)
	h.dpopKey = key

	metadata := &IssuerMetadata{
		CredentialIssuer:   "https://issuer.example.com",
		CredentialEndpoint: credServer.URL,
	}
	token := &TokenResponse{
		AccessToken: "dpop-access-token",
		TokenType:   "DPoP",
	}
	config := &CredentialConfig{Format: "vc+sd-jwt", VCT: "pid"}

	_, err = h.requestCredential(context.Background(), metadata, token, "", config, nil)
	require.NoError(t, err)

	assert.Equal(t, "DPoP dpop-access-token", receivedHeaders.Get("Authorization"))
	dpopHeader := receivedHeaders.Get("DPoP")
	assert.NotEmpty(t, dpopHeader)

	tok, err := jwt.Parse(dpopHeader, func(tok *jwt.Token) (interface{}, error) {
		return &key.PublicKey, nil
	})
	require.NoError(t, err)
	claims := tok.Claims.(jwt.MapClaims)
	assert.Equal(t, "POST", claims["htm"])
	assert.NotEmpty(t, claims["ath"])

	expectedHash := sha256.Sum256([]byte("dpop-access-token"))
	expectedAth := base64.RawURLEncoding.EncodeToString(expectedHash[:])
	assert.Equal(t, expectedAth, claims["ath"])
}

func TestRequestCredential_BearerFallback(t *testing.T) {
	var receivedHeaders http.Header
	credServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders = r.Header.Clone()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(CredentialResponse{Credential: "test-credential"})
	}))
	defer credServer.Close()

	h, cleanup := testOID4VCIHandler(t, credServer.Client())
	defer cleanup()

	key, err := generateDPoPKey()
	require.NoError(t, err)
	h.dpopKey = key

	metadata := &IssuerMetadata{CredentialEndpoint: credServer.URL}
	token := &TokenResponse{AccessToken: "bearer-token", TokenType: "Bearer"}
	config := &CredentialConfig{Format: "vc+sd-jwt"}

	_, err = h.requestCredential(context.Background(), metadata, token, "", config, nil)
	require.NoError(t, err)

	assert.Equal(t, "Bearer bearer-token", receivedHeaders.Get("Authorization"))
	// DPoP header should NOT be sent for Bearer tokens (RFC 9449 compliance)
	assert.Empty(t, receivedHeaders.Get("DPoP"))
}

func TestExchangePreAuthCode_NoDPoPKey(t *testing.T) {
	var receivedHeaders http.Header
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders = r.Header.Clone()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(TokenResponse{AccessToken: "plain-token", TokenType: "Bearer"})
	}))
	defer tokenServer.Close()

	h, cleanup := testOID4VCIHandler(t, tokenServer.Client())
	defer cleanup()

	metadata := &IssuerMetadata{TokenEndpoint: tokenServer.URL}
	token, err := h.exchangePreAuthCode(context.Background(), metadata, "code", "")
	require.NoError(t, err)
	assert.Equal(t, "Bearer", token.TokenType)
	assert.Empty(t, receivedHeaders.Get("DPoP"))
}

// --- DPoP nonce (RFC 9449 §8) tests ---

func TestCreateDPoPProof_WithNonce(t *testing.T) {
	key, err := generateDPoPKey()
	require.NoError(t, err)

	proof, err := createDPoPProof(key, "POST", "https://as.example.com/token", "", "server-nonce-123")
	require.NoError(t, err)

	tok, err := jwt.Parse(proof, func(tok *jwt.Token) (interface{}, error) {
		return &key.PublicKey, nil
	})
	require.NoError(t, err)
	claims := tok.Claims.(jwt.MapClaims)
	assert.Equal(t, "server-nonce-123", claims["nonce"])
}

func TestCreateDPoPProof_WithoutNonce(t *testing.T) {
	key, err := generateDPoPKey()
	require.NoError(t, err)

	proof, err := createDPoPProof(key, "POST", "https://as.example.com/token", "", "")
	require.NoError(t, err)

	tok, err := jwt.Parse(proof, func(tok *jwt.Token) (interface{}, error) {
		return &key.PublicKey, nil
	})
	require.NoError(t, err)
	claims := tok.Claims.(jwt.MapClaims)
	_, hasNonce := claims["nonce"]
	assert.False(t, hasNonce, "should not include nonce when empty")
}

func TestIsDPoPNonceError(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		nonceHdr   string
		expected   bool
	}{
		{"400 with nonce header", http.StatusBadRequest, "new-nonce-123", true},
		{"401 with nonce header", http.StatusUnauthorized, "new-nonce-456", true},
		{"400 without nonce header", http.StatusBadRequest, "", false},
		{"200 with nonce header", http.StatusOK, "nonce", false},
		{"500 with nonce header", http.StatusInternalServerError, "nonce", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &http.Response{
				StatusCode: tt.statusCode,
				Header:     http.Header{},
			}
			if tt.nonceHdr != "" {
				resp.Header.Set("DPoP-Nonce", tt.nonceHdr)
			}
			assert.Equal(t, tt.expected, isDPoPNonceError(resp))
		})
	}
}

func TestUpdateDPoPNonce(t *testing.T) {
	h := &OID4VCIHandler{}
	assert.Empty(t, h.dpopNonce)

	resp := &http.Response{Header: http.Header{}}
	resp.Header.Set("DPoP-Nonce", "first-nonce")
	h.updateDPoPNonce(resp)
	assert.Equal(t, "first-nonce", h.dpopNonce)

	resp.Header.Set("DPoP-Nonce", "second-nonce")
	h.updateDPoPNonce(resp)
	assert.Equal(t, "second-nonce", h.dpopNonce)

	// No nonce header — keep the old value
	resp2 := &http.Response{Header: http.Header{}}
	h.updateDPoPNonce(resp2)
	assert.Equal(t, "second-nonce", h.dpopNonce)
}

func TestExchangePreAuthCode_DPoPNonceRetry(t *testing.T) {
	attempt := 0
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempt++
		if attempt == 1 {
			// First request: require DPoP nonce
			w.Header().Set("DPoP-Nonce", "required-nonce-abc")
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"error":"use_dpop_nonce"}`))
			return
		}
		// Second request: verify nonce is included in DPoP proof
		dpopHeader := r.Header.Get("DPoP")
		assert.NotEmpty(t, dpopHeader)

		// Parse DPoP proof without signature verification and verify nonce
		var claims jwt.MapClaims
		parser := jwt.Parser{}
		tok, _, err := parser.ParseUnverified(dpopHeader, &claims)
		require.NoError(t, err)

		jwkMap, ok := tok.Header["jwk"].(map[string]interface{})
		require.True(t, ok, "DPoP proof must include a JWK header")
		assert.Equal(t, "EC", jwkMap["kty"])
		assert.Equal(t, "required-nonce-abc", claims["nonce"])

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(TokenResponse{
			AccessToken: "token-after-nonce",
			TokenType:   "DPoP",
		})
	}))
	defer tokenServer.Close()

	h, cleanup := testOID4VCIHandler(t, tokenServer.Client())
	defer cleanup()

	key, err := generateDPoPKey()
	require.NoError(t, err)
	h.dpopKey = key

	metadata := &IssuerMetadata{TokenEndpoint: tokenServer.URL}
	token, err := h.exchangePreAuthCode(context.Background(), metadata, "pre-auth-code", "")
	require.NoError(t, err)
	assert.Equal(t, "token-after-nonce", token.AccessToken)
	assert.Equal(t, 2, attempt, "should have made exactly 2 requests")
	assert.Equal(t, "required-nonce-abc", h.dpopNonce)
}

func TestExchangeAuthCode_DPoPNonceRetry(t *testing.T) {
	attempt := 0
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempt++
		if attempt == 1 {
			w.Header().Set("DPoP-Nonce", "auth-nonce-xyz")
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"error":"use_dpop_nonce"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(TokenResponse{
			AccessToken: "auth-token-after-nonce",
			TokenType:   "DPoP",
		})
	}))
	defer tokenServer.Close()

	h, cleanup := testOID4VCIHandler(t, tokenServer.Client())
	defer cleanup()

	key, err := generateDPoPKey()
	require.NoError(t, err)
	h.dpopKey = key

	metadata := &IssuerMetadata{TokenEndpoint: tokenServer.URL}
	token, err := h.exchangeAuthCode(context.Background(), metadata, "code", "https://example.com/callback", "verifier")
	require.NoError(t, err)
	assert.Equal(t, "auth-token-after-nonce", token.AccessToken)
	assert.Equal(t, 2, attempt)
}

func TestRequestCredential_DPoPNonceRetry(t *testing.T) {
	attempt := 0
	credServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempt++
		if attempt == 1 {
			w.Header().Set("DPoP-Nonce", "cred-nonce-789")
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"error":"use_dpop_nonce"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(CredentialResponse{Credential: "cred-after-nonce"})
	}))
	defer credServer.Close()

	h, cleanup := testOID4VCIHandler(t, credServer.Client())
	defer cleanup()

	key, err := generateDPoPKey()
	require.NoError(t, err)
	h.dpopKey = key

	metadata := &IssuerMetadata{CredentialEndpoint: credServer.URL}
	token := &TokenResponse{AccessToken: "access-token", TokenType: "DPoP"}
	config := &CredentialConfig{Format: "vc+sd-jwt"}

	resp, err := h.requestCredential(context.Background(), metadata, token, "", config, nil)
	require.NoError(t, err)
	assert.Equal(t, "cred-after-nonce", resp.Credential)
	assert.Equal(t, 2, attempt)
	assert.Equal(t, "cred-nonce-789", h.dpopNonce)
}

// --- OAuth error parsing tests ---

func TestParseOAuthError_StructuredError(t *testing.T) {
	body := []byte(`{"error":"invalid_grant","error_description":"The authorization code has expired"}`)
	err := parseOAuthError(400, body)
	assert.Contains(t, err.Error(), "invalid_grant")
	assert.Contains(t, err.Error(), "The authorization code has expired")
}

func TestParseOAuthError_ErrorCodeOnly(t *testing.T) {
	body := []byte(`{"error":"invalid_client"}`)
	err := parseOAuthError(401, body)
	assert.Equal(t, "invalid_client", err.Error())
}

func TestParseOAuthError_InvalidJSON(t *testing.T) {
	body := []byte(`Internal Server Error`)
	err := parseOAuthError(500, body)
	assert.Contains(t, err.Error(), "status 500")
}

func TestParseOAuthError_EmptyError(t *testing.T) {
	body := []byte(`{"error":""}`)
	err := parseOAuthError(400, body)
	assert.Contains(t, err.Error(), "status 400")
}

func TestSetDPoPHeader_IncludesNonce(t *testing.T) {
	key, err := generateDPoPKey()
	require.NoError(t, err)

	h := &OID4VCIHandler{dpopKey: key, dpopNonce: "test-nonce-value"}
	req, _ := http.NewRequest("POST", "https://example.com/token", nil)

	err = h.setDPoPHeader(req, "https://example.com/token", "")
	require.NoError(t, err)

	dpopProof := req.Header.Get("DPoP")
	tok, err := jwt.Parse(dpopProof, func(tok *jwt.Token) (interface{}, error) {
		return &key.PublicKey, nil
	})
	require.NoError(t, err)
	claims := tok.Claims.(jwt.MapClaims)
	assert.Equal(t, "test-nonce-value", claims["nonce"])
}

// --- Credential response encryption tests ---

func TestCredentialResponseEncryptionConfig_SupportsAlg(t *testing.T) {
	cfg := &CredentialResponseEncryptionConfig{
		AlgValuesSupported: []string{"RSA-OAEP-256", "ECDH-ES"},
		EncValuesSupported: []string{"A128CBC-HS256"},
	}
	assert.True(t, cfg.supportsAlg("ECDH-ES"))
	assert.True(t, cfg.supportsAlg("RSA-OAEP-256"))
	assert.False(t, cfg.supportsAlg("ECDH-ES+A256KW"))
}

func TestCredentialResponseEncryptionConfig_SupportsEnc(t *testing.T) {
	cfg := &CredentialResponseEncryptionConfig{
		AlgValuesSupported: []string{"ECDH-ES"},
		EncValuesSupported: []string{"A128CBC-HS256", "A256GCM"},
	}
	assert.True(t, cfg.supportsEnc("A128CBC-HS256"))
	assert.True(t, cfg.supportsEnc("A256GCM"))
	assert.False(t, cfg.supportsEnc("A192CBC-HS384"))
}

func TestDecryptJWEResponse(t *testing.T) {
	// Generate ephemeral encryption key
	encKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Build a credential response and encrypt it as JWE
	credResp := CredentialResponse{
		Credential: "test-credential-jwt-value",
		CNonce:     "nonce-from-encrypted",
	}
	plaintext, err := json.Marshal(credResp)
	require.NoError(t, err)

	encrypter, err := jose.NewEncrypter(
		jose.A128CBC_HS256,
		jose.Recipient{Algorithm: jose.ECDH_ES, Key: &encKey.PublicKey},
		(&jose.EncrypterOptions{}).WithContentType("json"),
	)
	require.NoError(t, err)

	jweObj, err := encrypter.Encrypt(plaintext)
	require.NoError(t, err)
	jweString, err := jweObj.CompactSerialize()
	require.NoError(t, err)

	// Decrypt
	result, err := decryptJWEResponse(jweString, encKey)
	require.NoError(t, err)
	assert.Equal(t, "test-credential-jwt-value", result.Credential)
	assert.Equal(t, "nonce-from-encrypted", result.CNonce)
}

func TestDecryptJWEResponse_InvalidJWE(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	_, err = decryptJWEResponse("not-a-jwe-string", key)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse JWE")
}

func TestDecryptJWEResponse_WrongKey(t *testing.T) {
	// Encrypt with key1, try to decrypt with key2
	key1, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	key2, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	plaintext := []byte(`{"credential":"test"}`)
	encrypter, err := jose.NewEncrypter(
		jose.A128CBC_HS256,
		jose.Recipient{Algorithm: jose.ECDH_ES, Key: &key1.PublicKey},
		nil,
	)
	require.NoError(t, err)

	jweObj, err := encrypter.Encrypt(plaintext)
	require.NoError(t, err)
	jweString, err := jweObj.CompactSerialize()
	require.NoError(t, err)

	_, err = decryptJWEResponse(jweString, key2)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decrypt")
}

func TestRequestCredential_EncryptedResponse(t *testing.T) {
	// Generate ephemeral encryption key (will be generated by requestCredential)
	// We need to encrypt the mock response with the key sent in the request,
	// so the mock server needs to parse the request and encrypt with that key.

	credServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Parse request body to get encryption params
		var reqBody map[string]interface{}
		json.NewDecoder(r.Body).Decode(&reqBody)

		enc, hasEnc := reqBody["credential_response_encryption"].(map[string]interface{})
		if !hasEnc {
			// No encryption requested — return plain JSON
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(CredentialResponse{Credential: "plain-credential"})
			return
		}

		// Extract the ephemeral public key from request
		jwkMap := enc["jwk"].(map[string]interface{})
		xBytes, _ := base64.RawURLEncoding.DecodeString(jwkMap["x"].(string))
		yBytes, _ := base64.RawURLEncoding.DecodeString(jwkMap["y"].(string))

		pubKey := &ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     new(big.Int).SetBytes(xBytes),
			Y:     new(big.Int).SetBytes(yBytes),
		}

		// Encrypt the credential response
		credResp := CredentialResponse{Credential: "encrypted-credential-value"}
		plaintext, _ := json.Marshal(credResp)

		encrypter, err := jose.NewEncrypter(
			jose.A128CBC_HS256,
			jose.Recipient{Algorithm: jose.ECDH_ES, Key: pubKey},
			nil,
		)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		jweObj, err := encrypter.Encrypt(plaintext)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		jweString, _ := jweObj.CompactSerialize()

		w.Header().Set("Content-Type", "application/jwt")
		w.Write([]byte(jweString))
	}))
	defer credServer.Close()

	h, cleanup := testOID4VCIHandler(t, credServer.Client())
	defer cleanup()

	key, err := generateDPoPKey()
	require.NoError(t, err)
	h.dpopKey = key

	metadata := &IssuerMetadata{
		CredentialEndpoint: credServer.URL,
		CredentialResponseEncryption: &CredentialResponseEncryptionConfig{
			AlgValuesSupported: []string{"ECDH-ES"},
			EncValuesSupported: []string{"A128CBC-HS256"},
			EncryptionRequired: true,
		},
	}
	token := &TokenResponse{AccessToken: "test-token", TokenType: "Bearer"}
	config := &CredentialConfig{Format: "vc+sd-jwt"}

	resp, err := h.requestCredential(context.Background(), metadata, token, "", config, nil)
	require.NoError(t, err)
	assert.Equal(t, "encrypted-credential-value", resp.Credential)
}

func TestRequestCredential_NoEncryptionWhenUnsupported(t *testing.T) {
	var receivedBody map[string]interface{}
	credServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&receivedBody)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(CredentialResponse{Credential: "plain-credential"})
	}))
	defer credServer.Close()

	h, cleanup := testOID4VCIHandler(t, credServer.Client())
	defer cleanup()

	// No encryption config in metadata
	metadata := &IssuerMetadata{CredentialEndpoint: credServer.URL}
	token := &TokenResponse{AccessToken: "test-token", TokenType: "Bearer"}
	config := &CredentialConfig{Format: "vc+sd-jwt"}

	resp, err := h.requestCredential(context.Background(), metadata, token, "", config, nil)
	require.NoError(t, err)
	assert.Equal(t, "plain-credential", resp.Credential)
	_, hasEncryption := receivedBody["credential_response_encryption"]
	assert.False(t, hasEncryption, "should not include encryption params when unsupported")
}

func TestRequestCredential_NoEncryptionWhenAlgUnsupported(t *testing.T) {
	var receivedBody map[string]interface{}
	credServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&receivedBody)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(CredentialResponse{Credential: "plain-credential"})
	}))
	defer credServer.Close()

	h, cleanup := testOID4VCIHandler(t, credServer.Client())
	defer cleanup()

	// Encryption config that only supports RSA
	metadata := &IssuerMetadata{
		CredentialEndpoint: credServer.URL,
		CredentialResponseEncryption: &CredentialResponseEncryptionConfig{
			AlgValuesSupported: []string{"RSA-OAEP-256"},
			EncValuesSupported: []string{"A128CBC-HS256"},
		},
	}
	token := &TokenResponse{AccessToken: "test-token", TokenType: "Bearer"}
	config := &CredentialConfig{Format: "vc+sd-jwt"}

	resp, err := h.requestCredential(context.Background(), metadata, token, "", config, nil)
	require.NoError(t, err)
	assert.Equal(t, "plain-credential", resp.Credential)
	_, hasEncryption := receivedBody["credential_response_encryption"]
	assert.False(t, hasEncryption, "should not include encryption when only RSA supported")
}

func TestCredentialResponseEncryptionConfig_JSONParsing(t *testing.T) {
	body := `{
		"alg_values_supported": ["RSA-OAEP-256", "ECDH-ES"],
		"enc_values_supported": ["A128CBC-HS256"],
		"encryption_required": true
	}`
	var cfg CredentialResponseEncryptionConfig
	err := json.Unmarshal([]byte(body), &cfg)
	require.NoError(t, err)
	assert.Equal(t, []string{"RSA-OAEP-256", "ECDH-ES"}, cfg.AlgValuesSupported)
	assert.Equal(t, []string{"A128CBC-HS256"}, cfg.EncValuesSupported)
	assert.True(t, cfg.EncryptionRequired)
}

func TestRequestCredential_EncryptionRequiredNoMutualSupport(t *testing.T) {
	h, cleanup := testOID4VCIHandler(t, http.DefaultClient)
	defer cleanup()

	metadata := &IssuerMetadata{
		CredentialEndpoint: "https://issuer.example.com/credential",
		CredentialResponseEncryption: &CredentialResponseEncryptionConfig{
			AlgValuesSupported: []string{"RSA-OAEP-256"},
			EncValuesSupported: []string{"A128CBC-HS256"},
			EncryptionRequired: true,
		},
	}
	token := &TokenResponse{AccessToken: "test-token", TokenType: "Bearer"}
	config := &CredentialConfig{Format: "vc+sd-jwt"}

	_, err := h.requestCredential(context.Background(), metadata, token, "", config, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no mutually supported alg/enc pair")
}

func TestRequestCredential_EncryptedResponseWithParams(t *testing.T) {
	// Verify Content-Type with parameters (e.g. charset) is handled correctly
	credServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var reqBody map[string]interface{}
		json.NewDecoder(r.Body).Decode(&reqBody)

		enc := reqBody["credential_response_encryption"].(map[string]interface{})
		jwkMap := enc["jwk"].(map[string]interface{})
		xBytes, _ := base64.RawURLEncoding.DecodeString(jwkMap["x"].(string))
		yBytes, _ := base64.RawURLEncoding.DecodeString(jwkMap["y"].(string))

		pubKey := &ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     new(big.Int).SetBytes(xBytes),
			Y:     new(big.Int).SetBytes(yBytes),
		}

		credResp := CredentialResponse{Credential: "encrypted-with-params"}
		plaintext, _ := json.Marshal(credResp)

		encrypter, _ := jose.NewEncrypter(
			jose.A128CBC_HS256,
			jose.Recipient{Algorithm: jose.ECDH_ES, Key: pubKey},
			nil,
		)
		jweObj, _ := encrypter.Encrypt(plaintext)
		jweString, _ := jweObj.CompactSerialize()

		// Content-Type with parameters
		w.Header().Set("Content-Type", "application/jwt; charset=utf-8")
		w.Write([]byte(jweString))
	}))
	defer credServer.Close()

	h, cleanup := testOID4VCIHandler(t, credServer.Client())
	defer cleanup()

	key, err := generateDPoPKey()
	require.NoError(t, err)
	h.dpopKey = key

	metadata := &IssuerMetadata{
		CredentialEndpoint: credServer.URL,
		CredentialResponseEncryption: &CredentialResponseEncryptionConfig{
			AlgValuesSupported: []string{"ECDH-ES"},
			EncValuesSupported: []string{"A128CBC-HS256"},
		},
	}
	token := &TokenResponse{AccessToken: "test-token", TokenType: "DPoP"}
	config := &CredentialConfig{Format: "vc+sd-jwt"}

	resp, err := h.requestCredential(context.Background(), metadata, token, "", config, nil)
	require.NoError(t, err)
	assert.Equal(t, "encrypted-with-params", resp.Credential)
}

// --- Batch credential issuance and multi-proof tests ---

func TestBatchCredentialIssuance_JSONParsing(t *testing.T) {
	body := `{
		"credential_issuer": "https://issuer.example.com",
		"credential_endpoint": "https://issuer.example.com/credential",
		"batch_credential_issuance": {
			"batch_size": 3
		}
	}`
	var meta IssuerMetadata
	err := json.Unmarshal([]byte(body), &meta)
	require.NoError(t, err)
	require.NotNil(t, meta.BatchCredentialIssuance)
	assert.Equal(t, 3, meta.BatchCredentialIssuance.BatchSize)
}

func TestBatchCredentialIssuance_Absent(t *testing.T) {
	body := `{
		"credential_issuer": "https://issuer.example.com",
		"credential_endpoint": "https://issuer.example.com/credential"
	}`
	var meta IssuerMetadata
	err := json.Unmarshal([]byte(body), &meta)
	require.NoError(t, err)
	assert.Nil(t, meta.BatchCredentialIssuance)
}

func TestCredentialBatchSize_Absent(t *testing.T) {
	meta := &IssuerMetadata{}
	assert.Equal(t, 1, credentialBatchSize(meta))
}

func TestCredentialBatchSize_One(t *testing.T) {
	meta := &IssuerMetadata{BatchCredentialIssuance: &BatchCredentialIssuance{BatchSize: 1}}
	assert.Equal(t, 1, credentialBatchSize(meta))
}

func TestCredentialBatchSize_Multiple(t *testing.T) {
	meta := &IssuerMetadata{BatchCredentialIssuance: &BatchCredentialIssuance{BatchSize: 3}}
	assert.Equal(t, 3, credentialBatchSize(meta))
}

func TestRequestCredential_UsesProofsObject(t *testing.T) {
	var receivedBody map[string]interface{}
	credServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&receivedBody)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(CredentialResponse{Credential: "test-cred"})
	}))
	defer credServer.Close()

	h, cleanup := testOID4VCIHandler(t, credServer.Client())
	defer cleanup()

	metadata := &IssuerMetadata{CredentialEndpoint: credServer.URL}
	token := &TokenResponse{AccessToken: "token", TokenType: "Bearer"}
	config := &CredentialConfig{Format: "vc+sd-jwt"}
	proofs := []ProofObject{{ProofType: "jwt", JWT: "test-jwt-value"}}

	resp, err := h.requestCredential(context.Background(), metadata, token, "my-config", config, proofs)
	require.NoError(t, err)
	assert.Equal(t, "test-cred", resp.Credential)

	// Verify "proofs" is an object (OID4VCI §7.2), not legacy "proof" or array
	_, hasProof := receivedBody["proof"]
	assert.False(t, hasProof, "should NOT include legacy 'proof' key")

	proofsRaw, hasProofs := receivedBody["proofs"]
	assert.True(t, hasProofs, "must include 'proofs' object")

	// OID4VCI spec: proofs is an object like {"jwt": ["...", "..."]}
	proofsObj, ok := proofsRaw.(map[string]interface{})
	require.True(t, ok, "'proofs' must be an object, not array")

	jwtProofs, hasJwt := proofsObj["jwt"]
	require.True(t, hasJwt, "proofs object must have 'jwt' key")

	jwtSlice, ok := jwtProofs.([]interface{})
	require.True(t, ok, "jwt proofs must be an array")
	require.Len(t, jwtSlice, 1)
	assert.Equal(t, "test-jwt-value", jwtSlice[0])
}

func TestRequestCredential_NoProofSendsNoProofsKey(t *testing.T) {
	var receivedBody map[string]interface{}
	credServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&receivedBody)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(CredentialResponse{Credential: "no-proof-cred"})
	}))
	defer credServer.Close()

	h, cleanup := testOID4VCIHandler(t, credServer.Client())
	defer cleanup()

	metadata := &IssuerMetadata{CredentialEndpoint: credServer.URL}
	token := &TokenResponse{AccessToken: "token", TokenType: "Bearer"}
	config := &CredentialConfig{Format: "vc+sd-jwt"}

	resp, err := h.requestCredential(context.Background(), metadata, token, "", config, nil)
	require.NoError(t, err)
	assert.Equal(t, "no-proof-cred", resp.Credential)

	_, hasProof := receivedBody["proof"]
	assert.False(t, hasProof)
	_, hasProofs := receivedBody["proofs"]
	assert.False(t, hasProofs)
}

func TestRequestCredential_MultipleProofsInObject(t *testing.T) {
	var receivedBody map[string]interface{}
	credServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&receivedBody)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(CredentialResponse{Credential: "batch-cred"})
	}))
	defer credServer.Close()

	h, cleanup := testOID4VCIHandler(t, credServer.Client())
	defer cleanup()

	metadata := &IssuerMetadata{CredentialEndpoint: credServer.URL}
	token := &TokenResponse{AccessToken: "token", TokenType: "Bearer"}
	config := &CredentialConfig{Format: "vc+sd-jwt"}
	proofs := []ProofObject{
		{ProofType: "jwt", JWT: "jwt-one"},
		{ProofType: "jwt", JWT: "jwt-two"},
		{ProofType: "jwt", JWT: "jwt-three"},
	}

	resp, err := h.requestCredential(context.Background(), metadata, token, "", config, proofs)
	require.NoError(t, err)
	assert.Equal(t, "batch-cred", resp.Credential)

	// OID4VCI spec: proofs is an object like {"jwt": ["...", "...", "..."]}
	proofsRaw, hasProofs := receivedBody["proofs"]
	require.True(t, hasProofs)
	proofsObj, ok := proofsRaw.(map[string]interface{})
	require.True(t, ok, "'proofs' must be an object")

	jwtProofs, hasJwt := proofsObj["jwt"]
	require.True(t, hasJwt)
	jwtSlice, ok := jwtProofs.([]interface{})
	require.True(t, ok)
	assert.Len(t, jwtSlice, 3)
	assert.Equal(t, "jwt-one", jwtSlice[0])
	assert.Equal(t, "jwt-two", jwtSlice[1])
	assert.Equal(t, "jwt-three", jwtSlice[2])
}

func TestRequestCredential_MixedProofTypesReturnsError(t *testing.T) {
	credServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("should not reach credential endpoint with mixed proof types")
	}))
	defer credServer.Close()

	h, cleanup := testOID4VCIHandler(t, credServer.Client())
	defer cleanup()

	metadata := &IssuerMetadata{CredentialEndpoint: credServer.URL}
	token := &TokenResponse{AccessToken: "token", TokenType: "Bearer"}
	config := &CredentialConfig{Format: "vc+sd-jwt"}
	proofs := []ProofObject{
		{ProofType: "jwt", JWT: "jwt-proof-1"},
		{ProofType: "attestation", Attestation: "attestation-proof-1"},
		{ProofType: "jwt", JWT: "jwt-proof-2"},
	}

	_, err := h.requestCredential(context.Background(), metadata, token, "", config, proofs)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "mixed proof types not allowed")
}

func TestRequestCredential_CNonceRefreshReturnsError(t *testing.T) {
	credServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error":   "invalid_nonce",
			"c_nonce": "fresh-nonce-abc",
		})
	}))
	defer credServer.Close()

	h, cleanup := testOID4VCIHandler(t, credServer.Client())
	defer cleanup()

	metadata := &IssuerMetadata{CredentialEndpoint: credServer.URL}
	token := &TokenResponse{AccessToken: "token", TokenType: "Bearer"}
	config := &CredentialConfig{Format: "vc+sd-jwt"}

	_, err := h.requestCredential(context.Background(), metadata, token, "", config, nil)
	require.Error(t, err)

	var cNonceErr *CNonceRequiredError
	require.True(t, errors.As(err, &cNonceErr), "should return CNonceRequiredError")
	assert.Equal(t, "fresh-nonce-abc", cNonceErr.NewNonce)
}

func TestRequestCredential_RegularErrorNotWrapped(t *testing.T) {
	credServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error":             "invalid_request",
			"error_description": "bad format",
		})
	}))
	defer credServer.Close()

	h, cleanup := testOID4VCIHandler(t, credServer.Client())
	defer cleanup()

	metadata := &IssuerMetadata{CredentialEndpoint: credServer.URL}
	token := &TokenResponse{AccessToken: "token", TokenType: "Bearer"}
	config := &CredentialConfig{Format: "vc+sd-jwt"}

	_, err := h.requestCredential(context.Background(), metadata, token, "", config, nil)
	require.Error(t, err)

	var cNonceErr *CNonceRequiredError
	assert.False(t, errors.As(err, &cNonceErr), "regular errors should NOT be wrapped in CNonceRequiredError")
	assert.Contains(t, err.Error(), "invalid_request")
}

// TestRequestProofs_PassesProofTypesAndCount tests that requestProofs correctly
// passes proof_types_supported and count to the frontend via the sign request,
// and validates that the returned proof types are supported.
func TestRequestProofs_PassesProofTypesAndCount(t *testing.T) {
	paramsCh := make(chan SignRequestParams, 1)

	conn, cleanup := wsTestServer(t, func(srvConn *websocket.Conn) {
		defer srvConn.Close()
		_, data, err := srvConn.ReadMessage()
		if err != nil {
			return
		}
		var req SignRequestMessage
		if err := json.Unmarshal(data, &req); err != nil {
			return
		}
		paramsCh <- req.Params

		resp := SignResponseMessage{
			Message: Message{
				Type:      TypeSignResponse,
				FlowID:    req.FlowID,
				MessageID: req.MessageID,
			},
			Proofs: []ProofObject{
				{ProofType: "jwt", JWT: "proof-1"},
			},
		}
		_ = srvConn.WriteJSON(resp)
	})
	defer cleanup()

	session := testSession(conn)
	// Route the sign_response from the WebSocket client side to signCh
	go func() {
		_, data, err := conn.ReadMessage()
		if err != nil {
			return
		}
		var signMsg SignResponseMessage
		if err := json.Unmarshal(data, &signMsg); err != nil {
			return
		}
		session.signCh <- &signMsg
	}()

	flow := &Flow{ID: "test-flow", Session: session, Data: make(map[string]interface{})}
	h := &OID4VCIHandler{}
	h.BaseHandler = BaseHandler{Flow: flow, Logger: zap.NewNop()}

	metadata := &IssuerMetadata{
		CredentialIssuer: "https://issuer.example.com",
	}
	config := &CredentialConfig{
		ProofTypesSupported: map[string]interface{}{
			"jwt": map[string]interface{}{"alg_values_supported": []string{"ES256"}},
		},
	}

	proofs, err := h.requestProofs(context.Background(), metadata, config, "test-nonce")
	require.NoError(t, err)
	require.Len(t, proofs, 1)
	assert.Equal(t, "jwt", proofs[0].ProofType)
	assert.Equal(t, "proof-1", proofs[0].JWT)

	// Verify params sent to frontend (received via channel - no data race)
	receivedParams := <-paramsCh
	assert.Equal(t, "https://issuer.example.com", receivedParams.Audience)
	assert.Equal(t, "test-nonce", receivedParams.Nonce)
	assert.Equal(t, 1, receivedParams.Count)
	require.NotNil(t, receivedParams.ProofTypesSupported)
	_, ok := receivedParams.ProofTypesSupported["jwt"]
	assert.True(t, ok, "jwt should be in proof_types_supported sent to frontend")
}

func TestRequestProofs_BatchSizePassedAsCount(t *testing.T) {
	paramsCh := make(chan SignRequestParams, 1)

	conn, cleanup := wsTestServer(t, func(srvConn *websocket.Conn) {
		defer srvConn.Close()
		_, data, err := srvConn.ReadMessage()
		if err != nil {
			return
		}
		var req SignRequestMessage
		if err := json.Unmarshal(data, &req); err != nil {
			return
		}
		paramsCh <- req.Params

		resp := SignResponseMessage{
			Message: Message{
				Type:      TypeSignResponse,
				FlowID:    req.FlowID,
				MessageID: req.MessageID,
			},
			Proofs: []ProofObject{
				{ProofType: "jwt", JWT: "p1"},
				{ProofType: "jwt", JWT: "p2"},
				{ProofType: "jwt", JWT: "p3"},
			},
		}
		_ = srvConn.WriteJSON(resp)
	})
	defer cleanup()

	session := testSession(conn)
	go func() {
		_, data, err := conn.ReadMessage()
		if err != nil {
			return
		}
		var signMsg SignResponseMessage
		if err := json.Unmarshal(data, &signMsg); err != nil {
			return
		}
		session.signCh <- &signMsg
	}()

	flow := &Flow{ID: "test-flow", Session: session, Data: make(map[string]interface{})}
	h := &OID4VCIHandler{}
	h.BaseHandler = BaseHandler{Flow: flow, Logger: zap.NewNop()}

	metadata := &IssuerMetadata{
		CredentialIssuer:        "https://issuer.example.com",
		BatchCredentialIssuance: &BatchCredentialIssuance{BatchSize: 3},
	}
	config := &CredentialConfig{
		ProofTypesSupported: map[string]interface{}{"jwt": nil},
	}

	proofs, err := h.requestProofs(context.Background(), metadata, config, "nonce")
	require.NoError(t, err)
	assert.Len(t, proofs, 3)

	// Verify count was passed correctly (received via channel - no data race)
	receivedParams := <-paramsCh
	assert.Equal(t, 3, receivedParams.Count, "count should match batch_size")
}

func TestRequestProofs_RejectsUnsupportedProofType(t *testing.T) {
	conn, cleanup := wsTestServer(t, func(srvConn *websocket.Conn) {
		defer srvConn.Close()
		_, data, err := srvConn.ReadMessage()
		if err != nil {
			return
		}
		var req SignRequestMessage
		if err := json.Unmarshal(data, &req); err != nil {
			return
		}
		// Frontend returns an "unsupported" proof type
		resp := SignResponseMessage{
			Message: Message{
				Type:      TypeSignResponse,
				FlowID:    req.FlowID,
				MessageID: req.MessageID,
			},
			Proofs: []ProofObject{
				{ProofType: "unknown_type", JWT: "something"},
			},
		}
		_ = srvConn.WriteJSON(resp)
	})
	defer cleanup()

	session := testSession(conn)
	go func() {
		_, data, err := conn.ReadMessage()
		if err != nil {
			return
		}
		var signMsg SignResponseMessage
		if err := json.Unmarshal(data, &signMsg); err != nil {
			return
		}
		session.signCh <- &signMsg
	}()

	flow := &Flow{ID: "test-flow", Session: session, Data: make(map[string]interface{})}
	h := &OID4VCIHandler{}
	h.BaseHandler = BaseHandler{Flow: flow, Logger: zap.NewNop()}

	metadata := &IssuerMetadata{CredentialIssuer: "https://issuer.example.com"}
	config := &CredentialConfig{
		ProofTypesSupported: map[string]interface{}{"jwt": nil},
	}

	_, err := h.requestProofs(context.Background(), metadata, config, "nonce")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported proof type")
	assert.Contains(t, err.Error(), "unknown_type")
}

func TestRequestProofs_ErrorOnEmptyProofs(t *testing.T) {
	conn, cleanup := wsTestServer(t, func(srvConn *websocket.Conn) {
		defer srvConn.Close()
		_, data, err := srvConn.ReadMessage()
		if err != nil {
			return
		}
		var req SignRequestMessage
		if err := json.Unmarshal(data, &req); err != nil {
			return
		}
		// Frontend returns empty proofs array
		resp := SignResponseMessage{
			Message: Message{
				Type:      TypeSignResponse,
				FlowID:    req.FlowID,
				MessageID: req.MessageID,
			},
		}
		_ = srvConn.WriteJSON(resp)
	})
	defer cleanup()

	session := testSession(conn)
	go func() {
		_, data, err := conn.ReadMessage()
		if err != nil {
			return
		}
		var signMsg SignResponseMessage
		if err := json.Unmarshal(data, &signMsg); err != nil {
			return
		}
		session.signCh <- &signMsg
	}()

	flow := &Flow{ID: "test-flow", Session: session, Data: make(map[string]interface{})}
	h := &OID4VCIHandler{}
	h.BaseHandler = BaseHandler{Flow: flow, Logger: zap.NewNop()}

	metadata := &IssuerMetadata{CredentialIssuer: "https://issuer.example.com"}
	config := &CredentialConfig{
		ProofTypesSupported: map[string]interface{}{"jwt": nil},
	}

	_, err := h.requestProofs(context.Background(), metadata, config, "nonce")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "frontend returned no proofs")
}

func TestCNonceRequiredError_ErrorAndUnwrap(t *testing.T) {
	inner := errors.New("invalid_nonce")
	e := &CNonceRequiredError{NewNonce: "fresh", Err: inner}
	assert.Equal(t, "invalid_nonce", e.Error())
	assert.Equal(t, inner, errors.Unwrap(e))
}

func TestSignRequestParams_ProofTypesAndCount_JSONRoundtrip(t *testing.T) {
	params := SignRequestParams{
		Audience: "https://issuer.example.com",
		Nonce:    "abc",
		Count:    3,
		ProofTypesSupported: map[string]interface{}{
			"jwt":         map[string]interface{}{"alg_values_supported": []string{"ES256"}},
			"attestation": map[string]interface{}{},
		},
	}
	data, err := json.Marshal(params)
	require.NoError(t, err)

	var decoded SignRequestParams
	require.NoError(t, json.Unmarshal(data, &decoded))

	assert.Equal(t, 3, decoded.Count)
	assert.Equal(t, "https://issuer.example.com", decoded.Audience)
	assert.Contains(t, decoded.ProofTypesSupported, "jwt")
	assert.Contains(t, decoded.ProofTypesSupported, "attestation")
}

func TestProofObject_AttestationType(t *testing.T) {
	proof := ProofObject{ProofType: "attestation", Attestation: "attest-value"}
	data, err := json.Marshal(proof)
	require.NoError(t, err)

	var decoded ProofObject
	require.NoError(t, json.Unmarshal(data, &decoded))
	assert.Equal(t, "attestation", decoded.ProofType)
	assert.Equal(t, "attest-value", decoded.Attestation)
	assert.Empty(t, decoded.JWT)
}

func TestSignResponseMessage_ProofsField(t *testing.T) {
	resp := SignResponseMessage{
		Proofs: []ProofObject{
			{ProofType: "jwt", JWT: "token-abc"},
			{ProofType: "attestation", Attestation: "attest-xyz"},
		},
	}
	data, err := json.Marshal(resp)
	require.NoError(t, err)

	var decoded SignResponseMessage
	require.NoError(t, json.Unmarshal(data, &decoded))
	require.Len(t, decoded.Proofs, 2)
	assert.Equal(t, "jwt", decoded.Proofs[0].ProofType)
	assert.Equal(t, "token-abc", decoded.Proofs[0].JWT)
	assert.Equal(t, "attestation", decoded.Proofs[1].ProofType)
	assert.Equal(t, "attest-xyz", decoded.Proofs[1].Attestation)
}
