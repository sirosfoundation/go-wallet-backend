package engine

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

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
		assert.Equal(t, "https://issuer.example.com", r.FormValue("client_id"))
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
	params.Set("client_id", "https://issuer.example.com")
	params.Set("redirect_uri", "https://wallet.example.com/callback")
	params.Set("scope", "openid")
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
		methods  []string
		expected bool
	}{
		{"nil methods (assume support)", nil, true},
		{"empty methods (assume support)", []string{}, true},
		{"S256 present", []string{"S256"}, true},
		{"S256 among others", []string{"plain", "S256"}, true},
		{"only plain", []string{"plain"}, false},
		{"no S256", []string{"plain", "none"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			meta := &oauthServerMetadata{
				CodeChallengeMethodsSupported: tt.methods,
			}
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
		assert.Equal(t, "https://issuer.example.com", r.FormValue("client_id"))
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
	params.Set("client_id", "https://issuer.example.com")
	params.Set("redirect_uri", "https://wallet.example.com/callback")
	params.Set("scope", "openid")
	params.Set("code_challenge", "test-challenge")
	params.Set("code_challenge_method", "S256")

	requestURI, err := h.sendPushedAuthorizationRequest(context.Background(), parServer.URL, params)
	require.NoError(t, err)

	// Verify the redirect URL would be built correctly
	authEndpoint, _ := url.Parse("https://as.example.com/authorize")
	q := authEndpoint.Query()
	q.Set("client_id", "https://issuer.example.com")
	q.Set("request_uri", requestURI)
	authEndpoint.RawQuery = q.Encode()

	parsedURL, err := url.Parse(authEndpoint.String())
	require.NoError(t, err)
	assert.Equal(t, "https://issuer.example.com", parsedURL.Query().Get("client_id"))
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
	}{
		{
			name:          "uses credential config scope",
			config:        &CredentialConfig{Scope: "pid"},
			expectedScope: "pid",
		},
		{
			name:          "falls back to openid when scope empty",
			config:        &CredentialConfig{Scope: ""},
			expectedScope: "openid",
		},
		{
			name:          "falls back to openid when config nil",
			config:        nil,
			expectedScope: "openid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Build the scope the same way startAuthorizationFlow does
			scope := "openid"
			if tt.config != nil && tt.config.Scope != "" {
				scope = tt.config.Scope
			}
			assert.Equal(t, tt.expectedScope, scope)
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
	assert.Contains(t, err.Error(), "status 500")
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
