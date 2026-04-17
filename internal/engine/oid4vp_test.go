package engine

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func TestBuildDCAPIResponse(t *testing.T) {
	h := &OID4VPHandler{}

	t.Run("basic dc_api response with state", func(t *testing.T) {
		authReq := &AuthorizationRequest{
			ResponseMode: "dc_api",
			State:        "test-state-123",
		}

		result, err := h.buildDCAPIResponse(authReq, "eyJ.vp_token.sig")
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Empty(t, result.redirectURI, "dc_api should not produce a redirect URI")
		require.NotNil(t, result.vpResponse)

		assert.Equal(t, "eyJ.vp_token.sig", result.vpResponse["vp_token"])
		assert.Equal(t, "test-state-123", result.vpResponse["state"])
	})

	t.Run("dc_api without state", func(t *testing.T) {
		authReq := &AuthorizationRequest{
			ResponseMode: "dc_api",
		}

		result, err := h.buildDCAPIResponse(authReq, "vp-token-data")
		require.NoError(t, err)
		require.NotNil(t, result.vpResponse)
		assert.Equal(t, "vp-token-data", result.vpResponse["vp_token"])
		_, hasState := result.vpResponse["state"]
		assert.False(t, hasState, "state should not be set when empty")
	})
}
