package engine

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/pkg/trust"
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
		// OpenID4VP 1.0 spells the same client_id with its scheme in front;
		// the domain must not depend on which spelling the verifier chose.
		{"prefixed did:web", "decentralized_identifier:did:web:verifier.example.com", "verifier.example.com"},
		{"prefixed did:key", "decentralized_identifier:did:key:z6MkhaXg", ""},
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

	// A plain JSON object whose client_id contains no dots.
	plainJSON := `{"client_id":"verifier","response_type":"vp_token","nonce":"test-nonce"}`
	// The same JSON object encoded as a JSON string (as some verifiers return it).
	quotedJSON := `"{\"client_id\":\"verifier\",\"response_type\":\"vp_token\",\"nonce\":\"test-nonce\"}"`
	// A JSON object containing exactly two '.' characters in a field value
	// (a response_uri host). fetchRequestObject used to classify body type
	// by counting '.' characters and treating exactly two as "must be a
	// JWT", which misclassified JSON bodies like this one and tried (and
	// failed) to parse them as a JWT. It now checks for a leading '{'/'['
	// instead, so this must parse as JSON.
	jsonWithTwoDots := `{"client_id":"verifier","response_type":"vp_token","nonce":"test-nonce","response_uri":"https://a.b.c/path"}`

	tests := []struct {
		name          string
		responseBody  string
		requestQuery  string
		statusCode    int
		wantClientID  string
		wantSessionID string
		wantErr       bool
		wantErrMsg    string
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
			name:         "JSON object response containing exactly two dots",
			responseBody: jsonWithTwoDots,
			statusCode:   http.StatusOK,
			wantClientID: "verifier",
		},
		{
			name:          "sessionId query param is forwarded as VerifierSessionID",
			responseBody:  plainJSON,
			requestQuery:  "sessionId=abc-123",
			statusCode:    http.StatusOK,
			wantClientID:  "verifier",
			wantSessionID: "abc-123",
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

			h := &OID4VPHandler{BaseHandler: BaseHandler{Logger: zap.NewNop()}, httpClient: srv.Client()}

			uri := srv.URL
			if tt.requestQuery != "" {
				uri += "?" + tt.requestQuery
			}

			authReq, err := h.fetchRequestObject(context.Background(), uri, "", nil)
			if tt.wantErr {
				require.Error(t, err)
				if tt.wantErrMsg != "" {
					assert.Contains(t, err.Error(), tt.wantErrMsg)
				}
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantClientID, authReq.ClientID)
			assert.Equal(t, tt.wantSessionID, authReq.VerifierSessionID)
		})
	}
}

func TestParseRequest(t *testing.T) {
	// A minimal by-value authorization request served by a reference URL,
	// reused by every "fetch" case below.
	referencedRequest := `{"client_id":"did:web:verifier","response_type":"vp_token","nonce":"fetched-nonce"}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, referencedRequest)
	}))
	defer srv.Close()

	// parseRequest calls h.ProgressMessage() unconditionally, which needs a
	// real Flow/Session/conn behind it (see testSession/wsTestServer in
	// match_test.go) or it panics on a nil websocket connection.
	conn, cleanup := wsTestServer(t, func(srvConn *websocket.Conn) {
		for {
			if _, _, err := srvConn.ReadMessage(); err != nil {
				return
			}
		}
	})
	defer cleanup()
	session := testSession(conn)
	flow := &Flow{ID: "test-flow", Session: session, Data: make(map[string]interface{})}

	h := &OID4VPHandler{BaseHandler: BaseHandler{Flow: flow, Logger: zap.NewNop()}, httpClient: srv.Client()}

	t.Run("openid4vp scheme with inline params", func(t *testing.T) {
		msg := &FlowStartMessage{
			RequestURI: "openid4vp://?response_type=vp_token&client_id=https://verifier.example.com&nonce=inline-nonce",
		}
		authReq, err := h.parseRequest(context.Background(), msg)
		require.NoError(t, err)
		assert.Equal(t, "inline-nonce", authReq.Nonce)
	})

	t.Run("openid4vp scheme with request_uri reference", func(t *testing.T) {
		msg := &FlowStartMessage{
			RequestURI: "openid4vp://?client_id=did:web:verifier&request_uri=" + url.QueryEscape(srv.URL),
		}
		authReq, err := h.parseRequest(context.Background(), msg)
		require.NoError(t, err)
		assert.Equal(t, "fetched-nonce", authReq.Nonce)
	})

	// HAIP (OpenID4VC High Assurance Interoperability Profile) uses the same
	// wire shape as plain OID4VP under its own scheme - regression test for a
	// bug where haip:// fell through to the "direct URL" branch instead of
	// being recognized and unwrapped the same way as openid4vp://.
	t.Run("haip scheme with request_uri reference", func(t *testing.T) {
		msg := &FlowStartMessage{
			RequestURI: "haip://?client_id=did:web:verifier&request_uri=" + url.QueryEscape(srv.URL),
		}
		authReq, err := h.parseRequest(context.Background(), msg)
		require.NoError(t, err)
		assert.Equal(t, "fetched-nonce", authReq.Nonce)
	})

	t.Run("haip scheme with inline params", func(t *testing.T) {
		msg := &FlowStartMessage{
			RequestURI: "haip://?response_type=vp_token&client_id=https://verifier.example.com&nonce=inline-nonce",
		}
		authReq, err := h.parseRequest(context.Background(), msg)
		require.NoError(t, err)
		assert.Equal(t, "inline-nonce", authReq.Nonce)
	})

	// HAIP 1.0 final replaced the early-draft "haip://" scheme with
	// "haip-vp://" (presentation) - regression test for a bug where real
	// verifiers (e.g. Multipaz) emitting haip-vp:// links fell through to
	// the "direct URL" branch (same bug class as haip:// above), which never
	// dereferenced the request_uri query param and failed with a generic
	// "invalid message format" instead of unwrapping it.
	t.Run("haip-vp scheme with request_uri reference", func(t *testing.T) {
		msg := &FlowStartMessage{
			RequestURI: "haip-vp://?client_id=did:web:verifier&request_uri=" + url.QueryEscape(srv.URL),
		}
		authReq, err := h.parseRequest(context.Background(), msg)
		require.NoError(t, err)
		assert.Equal(t, "fetched-nonce", authReq.Nonce)
	})

	t.Run("haip-vp scheme with inline params", func(t *testing.T) {
		msg := &FlowStartMessage{
			RequestURI: "haip-vp://?response_type=vp_token&client_id=https://verifier.example.com&nonce=inline-nonce",
		}
		authReq, err := h.parseRequest(context.Background(), msg)
		require.NoError(t, err)
		assert.Equal(t, "inline-nonce", authReq.Nonce)
	})

	// Regression test for a bug where a bare reference URL with no query
	// string (e.g. a QR/link that IS itself the request_uri, no
	// openid4vp://...&request_uri= wrapper at all) was parsed as if the
	// entire URL string were a raw query string - silently yielding every
	// field empty instead of being fetched.
	t.Run("bare https URL with no query is fetched as a reference", func(t *testing.T) {
		msg := &FlowStartMessage{RequestURI: srv.URL}
		authReq, err := h.parseRequest(context.Background(), msg)
		require.NoError(t, err)
		assert.Equal(t, "fetched-nonce", authReq.Nonce)
	})

	// Regression test: a raw query string with no scheme/host at all (as
	// validateResponseURIOrigin already anticipates) must be parsed as
	// inline params, not misidentified as a reference URL to fetch - it has
	// an empty RawQuery too (the whole string lands in url.URL.Path), so
	// scheme/host presence, not RawQuery, has to be the discriminator.
	t.Run("raw query string with no scheme is parsed directly", func(t *testing.T) {
		msg := &FlowStartMessage{
			RequestURI: "response_type=vp_token&client_id=https://verifier.example.com&nonce=raw-nonce",
		}
		authReq, err := h.parseRequest(context.Background(), msg)
		require.NoError(t, err)
		assert.Equal(t, "raw-nonce", authReq.Nonce)
	})

	t.Run("bare https URL with inline query params is parsed directly", func(t *testing.T) {
		msg := &FlowStartMessage{
			RequestURI: "https://wallet.example.com/present?response_type=vp_token&client_id=https://verifier.example.com&nonce=inline-nonce",
		}
		authReq, err := h.parseRequest(context.Background(), msg)
		require.NoError(t, err)
		assert.Equal(t, "inline-nonce", authReq.Nonce)
	})

	t.Run("no request provided", func(t *testing.T) {
		msg := &FlowStartMessage{}
		_, err := h.parseRequest(context.Background(), msg)
		require.Error(t, err)
	})
}

func TestHasURLScheme(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"https://verifier.example.com", true},
		{"http://127.0.0.1:8080", true},
		{"openid4vp://?client_id=foo", true},
		{"haip://?client_id=foo", true},
		{"", false},
		{"client_id=foo&nonce=bar", false},
		{"response_type=vp_token&client_id=https://verifier.example.com", false},
		{"://missing-scheme", false},
		{"1https://bad-first-char", false},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, hasURLScheme(tc.in), "hasURLScheme(%q)", tc.in)
	}
}

func TestRedactURIForLogging(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"", ""},
		{"https://verifier.example.com/req?nonce=secret&client_id=foo", "https://verifier.example.com"},
		{"client_id=foo&nonce=secret", "<non-url>"},
		{"not a url at all", "<non-url>"},
		// haip:// (and openid4vp://) requests with no callback/authority
		// segment are common and not malformed - Host is legitimately
		// empty. Must still report the scheme, not "<non-url>".
		{"haip://?client_id=foo&nonce=secret", "haip://"},
		{"openid4vp://?client_id=foo&nonce=secret", "openid4vp://"},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, redactURIForLogging(tc.in), "redactURIForLogging(%q)", tc.in)
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

	h := &OID4VPHandler{BaseHandler: BaseHandler{Logger: zap.NewNop()}, httpClient: server.Client()}
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

func TestSubmitDirectPostJWT_MissingEncAlg_InfersFromECKey(t *testing.T) {
	// When authorization_encrypted_response_alg is absent but an EC key is
	// available in client_metadata.jwks, the algorithm should be inferred as
	// ECDH-ES (EC key → ECDH-ES, RFC 7518 §4.6).
	encKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	encJWK := map[string]any{
		"kty": "EC", "crv": "P-256",
		"x":   base64.RawURLEncoding.EncodeToString(padBytes(encKey.PublicKey.X.Bytes(), 32)),
		"y":   base64.RawURLEncoding.EncodeToString(padBytes(encKey.PublicKey.Y.Bytes(), 32)),
		"use": "enc", "kid": "ec-enc-key",
	}
	jwksBytes, _ := json.Marshal(map[string]any{"keys": []any{encJWK}})

	var receivedForm url.Values
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		receivedForm = r.PostForm
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()

	h := &OID4VPHandler{BaseHandler: BaseHandler{Logger: zap.NewNop()}, httpClient: server.Client()}
	authReq := &AuthorizationRequest{
		ClientID: "https://verifier.example.com",
		// No AuthorizationEncryptedResponseAlg — should be inferred as ECDH-ES
		ClientMetadata: &ClientMetadata{JWKS: jwksBytes},
	}

	_, err = h.submitDirectPostJWT(context.Background(), server.URL, authReq, "test-vp-token")
	require.NoError(t, err, "should succeed by inferring ECDH-ES from EC key")

	response := receivedForm.Get("response")
	assert.NotEmpty(t, response, "should post a JWE in the 'response' field")
	assert.Equal(t, 5, len(splitDots(response)), "JWE should have 5 parts")
}

func TestSubmitDirectPostJWT_MissingEncAlg_HonorsJWKAlg(t *testing.T) {
	// When authorization_encrypted_response_alg is absent but the verifier's
	// encryption JWK declares its own "alg" (e.g. ECDH-ES+A256KW), that value
	// must be used for the JWE header rather than inferring ECDH-ES from the
	// EC key type. Verifiers validate the JWE header "alg" against their
	// selected encryption JWK and reject a mismatch (regression test for the
	// "JWE header does not match the selected verifier encryption JWK" failure).
	encKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	jwksBytes := makeJWKS(jose.JSONWebKey{
		Key:       &encKey.PublicKey,
		KeyID:     "enc-key-1",
		Use:       "enc",
		Algorithm: "ECDH-ES+A256KW",
	})

	var receivedForm url.Values
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		receivedForm = r.PostForm
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()

	h := &OID4VPHandler{BaseHandler: BaseHandler{Logger: zap.NewNop()}, httpClient: server.Client()}
	authReq := &AuthorizationRequest{
		ClientID: "https://verifier.example.com",
		// No AuthorizationEncryptedResponseAlg — must fall back to the JWK's alg.
		ClientMetadata: &ClientMetadata{JWKS: jwksBytes},
	}

	_, err = h.submitDirectPostJWT(context.Background(), server.URL, authReq, "test-vp-token")
	require.NoError(t, err, "should succeed by honoring the JWK's declared alg")

	response := receivedForm.Get("response")
	require.Equal(t, 5, len(splitDots(response)), "JWE should have 5 parts")

	headerJSON, err := base64.RawURLEncoding.DecodeString(splitDots(response)[0])
	require.NoError(t, err)
	var header struct {
		Alg string `json:"alg"`
	}
	require.NoError(t, json.Unmarshal(headerJSON, &header))
	assert.Equal(t, string(jose.ECDH_ES_A256KW), header.Alg,
		"JWE header alg should honor the JWK's declared ECDH-ES+A256KW, not inferred ECDH-ES")
}

func TestSubmitDirectPostJWT_MissingEncAlg_IgnoresNonJARMJWKAlg(t *testing.T) {
	// When authorization_encrypted_response_alg is absent and the verifier's
	// JWK carries a non-JARM key-management "alg" (e.g. a signature alg like
	// "ES256"), that value must NOT be forced onto the JWE. The code should
	// fall back to key-type inference (EC key → ECDH-ES) instead of failing on
	// an unsupported JARM key algorithm.
	encKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	jwksBytes := makeJWKS(jose.JSONWebKey{
		Key:       &encKey.PublicKey,
		KeyID:     "enc-key-1",
		Use:       "enc",
		Algorithm: "ES256", // signature alg, not a JARM key-management alg
	})

	var receivedForm url.Values
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		receivedForm = r.PostForm
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()

	h := &OID4VPHandler{BaseHandler: BaseHandler{Logger: zap.NewNop()}, httpClient: server.Client()}
	authReq := &AuthorizationRequest{
		ClientID:       "https://verifier.example.com",
		ClientMetadata: &ClientMetadata{JWKS: jwksBytes},
	}

	_, err = h.submitDirectPostJWT(context.Background(), server.URL, authReq, "test-vp-token")
	require.NoError(t, err, "should fall back to ECDH-ES key-type inference, not fail on ES256")

	response := receivedForm.Get("response")
	require.Equal(t, 5, len(splitDots(response)), "JWE should have 5 parts")

	headerJSON, err := base64.RawURLEncoding.DecodeString(splitDots(response)[0])
	require.NoError(t, err)
	var header struct {
		Alg string `json:"alg"`
	}
	require.NoError(t, json.Unmarshal(headerJSON, &header))
	assert.Equal(t, string(jose.ECDH_ES), header.Alg,
		"non-JARM JWK alg should be ignored in favor of inferred ECDH-ES")
}

func TestSubmitDirectPostJWT_MissingEncAlg_InfersFromRSAKey(t *testing.T) {
	// When authorization_encrypted_response_alg is absent but an RSA key is
	// available in client_metadata.jwks, the algorithm should be inferred as
	// RSA-OAEP (RSA key → RSA-OAEP, RFC 7518 §4.3).
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	jwksBytes := makeJWKS(jose.JSONWebKey{Key: &rsaKey.PublicKey, KeyID: "rsa-enc", Use: "enc"})

	var receivedForm url.Values
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		receivedForm = r.PostForm
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()

	h := &OID4VPHandler{BaseHandler: BaseHandler{Logger: zap.NewNop()}, httpClient: server.Client()}
	authReq := &AuthorizationRequest{
		ClientID:       "https://verifier.example.com",
		ClientMetadata: &ClientMetadata{JWKS: jwksBytes},
	}

	_, err = h.submitDirectPostJWT(context.Background(), server.URL, authReq, "test-vp-token")
	require.NoError(t, err, "should succeed by inferring RSA-OAEP from RSA key")

	response := receivedForm.Get("response")
	assert.NotEmpty(t, response)
	assert.Equal(t, 5, len(splitDots(response)), "JWE should have 5 parts")
}

func TestSubmitDirectPostJWT_MissingEncAlgAndNoKey_Errors(t *testing.T) {
	// When neither authorization_encrypted_response_alg nor any key material is
	// available, the call must fail with a clear error.
	h := &OID4VPHandler{BaseHandler: BaseHandler{Logger: zap.NewNop()}, httpClient: http.DefaultClient}
	authReq := &AuthorizationRequest{
		ClientID:       "https://verifier.example.com",
		ClientMetadata: &ClientMetadata{}, // no JWKS, no alg
	}

	_, err := h.submitDirectPostJWT(context.Background(), "https://example.com/post", authReq, "vp-token")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "authorization_encrypted_response_alg")
}

func TestSubmitDirectPostJWT_NilClientMetadata_InfersFromX5C(t *testing.T) {
	// When client_metadata is nil but the request JWT carries an x5c, the algorithm
	// should be inferred from the x5c leaf cert's public key.
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "verifier"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &leafKey.PublicKey, leafKey)
	require.NoError(t, err)
	certB64 := base64.StdEncoding.EncodeToString(der)

	requestJWT := buildMinimalJWT(t, leafKey, certB64)

	var receivedForm url.Values
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		receivedForm = r.PostForm
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()

	h := &OID4VPHandler{BaseHandler: BaseHandler{Logger: zap.NewNop()}, httpClient: server.Client()}
	authReq := &AuthorizationRequest{
		ClientID:   "x509_san_dns:verifier.example.com",
		RequestJWT: requestJWT,
		// No client_metadata — algorithm inferred from x5c leaf
	}

	_, err = h.submitDirectPostJWT(context.Background(), server.URL, authReq, "test-vp-token")
	require.NoError(t, err, "should succeed by inferring ECDH-ES from x5c EC key")

	response := receivedForm.Get("response")
	assert.NotEmpty(t, response)
	assert.Equal(t, 5, len(splitDots(response)), "JWE should have 5 parts")
}

func TestSubmitDirectPostJWT_DefaultEncIsA128GCM(t *testing.T) {
	// When authorization_encrypted_response_enc is absent, default should be
	// A128GCM, not A128CBC-HS256 (RFC 7518's first mandatory-to-implement
	// "enc" but not universally implemented - confirmed live against
	// verifier.multipaz.org's own JsonWebEncryption decrypter, which only
	// implements the GCM family and rejects CBC-HS256 outright).
	encKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	encJWK := map[string]any{
		"kty": "EC", "crv": "P-256",
		"x":   base64.RawURLEncoding.EncodeToString(padBytes(encKey.PublicKey.X.Bytes(), 32)),
		"y":   base64.RawURLEncoding.EncodeToString(padBytes(encKey.PublicKey.Y.Bytes(), 32)),
		"use": "enc",
	}
	jwksBytes, _ := json.Marshal(map[string]any{"keys": []any{encJWK}})

	var receivedForm url.Values
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		receivedForm = r.PostForm
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()

	h := &OID4VPHandler{BaseHandler: BaseHandler{Logger: zap.NewNop()}, httpClient: server.Client()}
	authReq := &AuthorizationRequest{
		ClientID: "https://verifier.example.com",
		ClientMetadata: &ClientMetadata{
			JWKS:                              jwksBytes,
			AuthorizationEncryptedResponseAlg: "ECDH-ES",
			// No enc — should default to A128GCM
		},
	}

	_, err = h.submitDirectPostJWT(context.Background(), server.URL, authReq, "vp-token")
	require.NoError(t, err, "should succeed with default A128GCM enc")
	response := receivedForm.Get("response")
	assert.Equal(t, 5, len(splitDots(response)))

	headerB64 := splitDots(response)[0]
	headerJSON, err := base64.RawURLEncoding.DecodeString(headerB64)
	require.NoError(t, err)
	var header struct {
		Enc string `json:"enc"`
	}
	require.NoError(t, json.Unmarshal(headerJSON, &header))
	assert.Equal(t, string(jose.A128GCM), header.Enc, "default enc should be A128GCM, not A128CBC-HS256")
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
		jose.JSONWebKey{Key: &encKey.PublicKey, KeyID: "enc-key-1", Use: "enc", Algorithm: "ECDH-ES+A256KW"},
	)

	h := &OID4VPHandler{}
	authReq := &AuthorizationRequest{
		ClientMetadata: &ClientMetadata{JWKS: jwksBytes},
	}

	_, kid, alg, err := h.extractVerifierEncryptionKey(authReq)
	require.NoError(t, err)
	assert.Equal(t, "enc-key-1", kid, "should select the key with use=enc")
	assert.Equal(t, "ECDH-ES+A256KW", alg, "should return the JWK's declared alg")
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

	_, kid, _, err := h.extractVerifierEncryptionKey(authReq)
	require.NoError(t, err)
	assert.Equal(t, "only-key", kid)
}

func TestExtractVerifierEncryptionKey_NoKeysReturnsError(t *testing.T) {
	h := &OID4VPHandler{}
	authReq := &AuthorizationRequest{
		ClientMetadata: &ClientMetadata{},
	}

	_, _, _, err := h.extractVerifierEncryptionKey(authReq)
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

// Regression test: parseRequest treats haip:// the same as openid4vp://,
// but validateResponseURIOrigin only unwrapped openid4vp:// to find the
// embedded request_uri. A HAIP request_uri parsed to an empty host and was
// silently treated as "not a proper URL", skipping the origin check
// entirely instead of enforcing it.
func TestValidateResponseURIOrigin_HAIPScheme(t *testing.T) {
	authReq := &AuthorizationRequest{
		ResponseURI:    "https://verifier.example.com/response",
		ClientIDScheme: ClientIDSchemeX509SANDNS,
	}
	msg := &FlowStartMessage{
		RequestURI: "haip://?request_uri=https%3A%2F%2Fverifier.example.com%2Frequest",
	}
	err := validateResponseURIOrigin(authReq, msg)
	assert.NoError(t, err)
}

func TestValidateResponseURIOrigin_HAIPScheme_Mismatch(t *testing.T) {
	authReq := &AuthorizationRequest{
		ResponseURI:    "https://evil.example.com/response",
		ClientIDScheme: ClientIDSchemeX509SANDNS,
	}
	msg := &FlowStartMessage{
		RequestURI: "haip://?request_uri=https%3A%2F%2Fverifier.example.com%2Frequest",
	}
	err := validateResponseURIOrigin(authReq, msg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not match request_uri origin")
}

func TestValidateResponseURIOrigin_HAIPVPScheme(t *testing.T) {
	authReq := &AuthorizationRequest{
		ResponseURI:    "https://verifier.example.com/response",
		ClientIDScheme: ClientIDSchemeX509SANDNS,
	}
	msg := &FlowStartMessage{
		RequestURI: "haip-vp://?request_uri=https%3A%2F%2Fverifier.example.com%2Frequest",
	}
	err := validateResponseURIOrigin(authReq, msg)
	assert.NoError(t, err)
}

func TestValidateResponseURIOrigin_HAIPVPScheme_Mismatch(t *testing.T) {
	authReq := &AuthorizationRequest{
		ResponseURI:    "https://evil.example.com/response",
		ClientIDScheme: ClientIDSchemeX509SANDNS,
	}
	msg := &FlowStartMessage{
		RequestURI: "haip-vp://?request_uri=https%3A%2F%2Fverifier.example.com%2Frequest",
	}
	err := validateResponseURIOrigin(authReq, msg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not match request_uri origin")
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

// buildMinimalJWT constructs a bare compact JWT with an x5c header containing certB64,
// signed with key. The payload is a minimal valid JSON object. Used by tests that
// need a request JWT carrying an embedded certificate.
func buildMinimalJWT(t *testing.T, key *ecdsa.PrivateKey, certB64 string) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256","x5c":["` + certB64 + `"]}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"https://verifier.example.com","nonce":"test"}`))
	signingInput := header + "." + payload
	h := crypto.SHA256.New()
	h.Write([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, key, h.Sum(nil))
	require.NoError(t, err)
	n := (key.Curve.Params().BitSize + 7) / 8
	sig := make([]byte, 2*n)
	r.FillBytes(sig[:n])
	s.FillBytes(sig[n:])
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// requestURIPostServer is a stub verifier request-object endpoint for
// request_uri_method=post (OpenID4VP 1.0 5.10). It records what the wallet
// sent and answers with a request object built from it, which is what lets
// the wallet_nonce round-trip be asserted end to end.
type requestURIPostServer struct {
	calls       int
	method      string
	contentType string
	form        url.Values
	// echoNonce, when set, replaces the wallet_nonce sent back in the
	// request object - "" omits the claim entirely.
	echoNonce func(sent string) string
}

func (s *requestURIPostServer) handler(t *testing.T) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		s.calls++
		s.method = r.Method
		s.contentType = r.Header.Get("Content-Type")
		s.form = r.PostForm

		sent := r.PostForm.Get("wallet_nonce")
		echoed := sent
		if s.echoNonce != nil {
			echoed = s.echoNonce(sent)
		}
		obj := map[string]interface{}{
			"client_id":     "did:web:verifier",
			"response_type": "vp_token",
			"nonce":         "verifier-nonce",
		}
		if echoed != "" {
			obj["wallet_nonce"] = echoed
		}
		w.WriteHeader(http.StatusOK)
		require.NoError(t, json.NewEncoder(w).Encode(obj))
	}
}

func TestFetchRequestObjectPost(t *testing.T) {
	t.Run("sends wallet_metadata and wallet_nonce and accepts the echo", func(t *testing.T) {
		stub := &requestURIPostServer{}
		srv := httptest.NewServer(stub.handler(t))
		defer srv.Close()
		h := &OID4VPHandler{BaseHandler: BaseHandler{Logger: zap.NewNop()}, httpClient: srv.Client()}

		authReq, err := h.fetchRequestObject(context.Background(), srv.URL, "post", nil)
		require.NoError(t, err)
		assert.Equal(t, "did:web:verifier", authReq.ClientID)

		assert.Equal(t, http.MethodPost, stub.method)
		assert.Equal(t, mimeFormURLEncoded, stub.contentType)
		assert.NotEmpty(t, stub.form.Get("wallet_nonce"))
		assert.JSONEq(t, string(defaultWalletMetadata), stub.form.Get("wallet_metadata"))
	})

	// The client knows what it can present; the engine's default is only a
	// stand-in for a client that says nothing.
	t.Run("client-supplied wallet_metadata is sent verbatim", func(t *testing.T) {
		stub := &requestURIPostServer{}
		srv := httptest.NewServer(stub.handler(t))
		defer srv.Close()
		h := &OID4VPHandler{BaseHandler: BaseHandler{Logger: zap.NewNop()}, httpClient: srv.Client()}

		metadata := json.RawMessage(`{"vp_formats_supported":{"mso_mdoc":{"alg_values":["ES256"]}}}`)
		_, err := h.fetchRequestObject(context.Background(), srv.URL, "post", metadata)
		require.NoError(t, err)
		assert.JSONEq(t, string(metadata), stub.form.Get("wallet_metadata"))
	})

	// Clients encode their defaults, so "the client said nothing" arrives as
	// a JSON null - which must fall back to the engine's own metadata rather
	// than be forwarded to the verifier as the string "null".
	t.Run("a null wallet_metadata falls back to the default", func(t *testing.T) {
		stub := &requestURIPostServer{}
		srv := httptest.NewServer(stub.handler(t))
		defer srv.Close()
		h := &OID4VPHandler{BaseHandler: BaseHandler{Logger: zap.NewNop()}, httpClient: srv.Client()}

		_, err := h.fetchRequestObject(context.Background(), srv.URL, "post", json.RawMessage(`null`))
		require.NoError(t, err)
		assert.JSONEq(t, string(defaultWalletMetadata), stub.form.Get("wallet_metadata"))
	})

	// OpenID4VP defines wallet_metadata as a JSON object, and well-formed
	// JSON that is not one is no more usable to a verifier than a syntax
	// error - better caught here than at the far end of the presentation.
	for name, metadata := range map[string]string{
		"a syntax error": `{not json`,
		"an array":       `[]`,
		"a number":       `123`,
		"a string":       `"metadata"`,
	} {
		t.Run("wallet_metadata that is "+name+" is rejected before any request", func(t *testing.T) {
			stub := &requestURIPostServer{}
			srv := httptest.NewServer(stub.handler(t))
			defer srv.Close()
			h := &OID4VPHandler{BaseHandler: BaseHandler{Logger: zap.NewNop()}, httpClient: srv.Client()}

			_, err := h.fetchRequestObject(context.Background(), srv.URL, "post", json.RawMessage(metadata))
			require.Error(t, err)
			assert.Equal(t, ErrCodeInvalidMessage, codedErrorCode(t, err))
			assert.Zero(t, stub.calls)
		})
	}

	// OpenID4VP 1.0 5.10 makes this a MUST: a request object that does not
	// carry the nonce back cannot have been produced for this request.
	t.Run("a missing wallet_nonce terminates request processing", func(t *testing.T) {
		stub := &requestURIPostServer{echoNonce: func(string) string { return "" }}
		srv := httptest.NewServer(stub.handler(t))
		defer srv.Close()
		h := &OID4VPHandler{BaseHandler: BaseHandler{Logger: zap.NewNop()}, httpClient: srv.Client()}

		_, err := h.fetchRequestObject(context.Background(), srv.URL, "post", nil)
		require.Error(t, err)
		assert.Equal(t, ErrCodeWalletNonceMismatch, codedErrorCode(t, err))
	})

	t.Run("a different wallet_nonce terminates request processing", func(t *testing.T) {
		stub := &requestURIPostServer{echoNonce: func(string) string { return "someone-elses-nonce" }}
		srv := httptest.NewServer(stub.handler(t))
		defer srv.Close()
		h := &OID4VPHandler{BaseHandler: BaseHandler{Logger: zap.NewNop()}, httpClient: srv.Client()}

		_, err := h.fetchRequestObject(context.Background(), srv.URL, "post", nil)
		require.Error(t, err)
		assert.Equal(t, ErrCodeWalletNonceMismatch, codedErrorCode(t, err))
	})

	// A nonce reused across requests would let a request object captured
	// from one presentation be replayed into the next.
	t.Run("each request gets a fresh wallet_nonce", func(t *testing.T) {
		var nonces []string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			require.NoError(t, r.ParseForm())
			sent := r.PostForm.Get("wallet_nonce")
			nonces = append(nonces, sent)
			_, _ = fmt.Fprintf(w, `{"client_id":"did:web:verifier","nonce":"n","wallet_nonce":%q}`, sent)
		}))
		defer srv.Close()
		h := &OID4VPHandler{BaseHandler: BaseHandler{Logger: zap.NewNop()}, httpClient: srv.Client()}

		for i := 0; i < 2; i++ {
			_, err := h.fetchRequestObject(context.Background(), srv.URL, "post", nil)
			require.NoError(t, err)
		}
		require.Len(t, nonces, 2)
		assert.NotEqual(t, nonces[0], nonces[1])
	})
}

func TestFetchRequestObjectMethodSelection(t *testing.T) {
	// Absent and "get" are RFC 9101's GET, which is also where a wallet
	// without POST support is expected to land - no wallet_nonce is sent,
	// so none is required back.
	for _, method := range []string{"", "get"} {
		t.Run("method "+method+" issues a GET", func(t *testing.T) {
			var gotMethod string
			var gotBody []byte
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotMethod = r.Method
				gotBody, _ = io.ReadAll(r.Body)
				_, _ = fmt.Fprint(w, `{"client_id":"did:web:verifier","nonce":"n"}`)
			}))
			defer srv.Close()
			h := &OID4VPHandler{BaseHandler: BaseHandler{Logger: zap.NewNop()}, httpClient: srv.Client()}

			authReq, err := h.fetchRequestObject(context.Background(), srv.URL, method, nil)
			require.NoError(t, err)
			assert.Equal(t, "did:web:verifier", authReq.ClientID)
			assert.Equal(t, http.MethodGet, gotMethod)
			assert.Empty(t, gotBody)
		})
	}

	// The values are case-sensitive per the specification, so "POST" is not
	// "post" - and an unsupported value must not be quietly downgraded to a
	// GET the verifier did not ask for.
	for _, method := range []string{"POST", "put", "anything"} {
		t.Run("method "+method+" is rejected without a request", func(t *testing.T) {
			calls := 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				calls++
				w.WriteHeader(http.StatusOK)
			}))
			defer srv.Close()
			h := &OID4VPHandler{BaseHandler: BaseHandler{Logger: zap.NewNop()}, httpClient: srv.Client()}

			_, err := h.fetchRequestObject(context.Background(), srv.URL, method, nil)
			require.Error(t, err)
			assert.Equal(t, ErrCodeInvalidRequestURIMethod, codedErrorCode(t, err))
			assert.Zero(t, calls)
		})
	}
}

// codedErrorCode returns the ErrorCode a request failure carries for the
// client, failing the test if it carries none.
func codedErrorCode(t *testing.T, err error) ErrorCode {
	t.Helper()
	var coded *requestCodedError
	require.ErrorAs(t, err, &coded)
	return coded.code
}

// TestParseRequestURIMethod covers how request_uri_method reaches the fetch:
// from the authorization request URI when the client forwards it whole, and
// from the FlowStart message when the client extracted request_uri itself
// and with it lost the query string the parameter arrived in.
func TestParseRequestURIMethod(t *testing.T) {
	stub := &requestURIPostServer{}
	srv := httptest.NewServer(stub.handler(t))
	defer srv.Close()

	conn, cleanup := wsTestServer(t, func(srvConn *websocket.Conn) {
		for {
			if _, _, err := srvConn.ReadMessage(); err != nil {
				return
			}
		}
	})
	defer cleanup()
	flow := &Flow{ID: "test-flow", Session: testSession(conn), Data: make(map[string]interface{})}
	h := &OID4VPHandler{BaseHandler: BaseHandler{Flow: flow, Logger: zap.NewNop()}, httpClient: srv.Client()}

	t.Run("read from the authorization request URI", func(t *testing.T) {
		msg := &FlowStartMessage{
			RequestURI: "openid4vp://?client_id=did:web:verifier&request_uri_method=post&request_uri=" + url.QueryEscape(srv.URL),
		}
		authReq, err := h.parseRequest(context.Background(), msg)
		require.NoError(t, err)
		assert.Equal(t, "verifier-nonce", authReq.Nonce)
		assert.Equal(t, http.MethodPost, stub.method)
	})

	t.Run("read from the flow start message for a pre-extracted reference", func(t *testing.T) {
		msg := &FlowStartMessage{RequestURIRef: srv.URL, RequestURIMethod: "post"}
		authReq, err := h.parseRequest(context.Background(), msg)
		require.NoError(t, err)
		assert.Equal(t, "verifier-nonce", authReq.Nonce)
		assert.Equal(t, http.MethodPost, stub.method)
	})

	t.Run("the URI parameter wins over the flow start message", func(t *testing.T) {
		msg := &FlowStartMessage{
			RequestURI:       "openid4vp://?client_id=did:web:verifier&request_uri_method=get&request_uri=" + url.QueryEscape(srv.URL),
			RequestURIMethod: "post",
		}
		_, err := h.parseRequest(context.Background(), msg)
		require.NoError(t, err)
		assert.Equal(t, http.MethodGet, stub.method)
	})

	// An explicitly empty request_uri_method is the authorization request
	// asking for a GET, and must not fall through to the client's value:
	// presence is what makes the URI authoritative, not a non-empty value.
	t.Run("an empty URI parameter still wins over the flow start message", func(t *testing.T) {
		msg := &FlowStartMessage{
			RequestURI:       "openid4vp://?client_id=did:web:verifier&request_uri_method=&request_uri=" + url.QueryEscape(srv.URL),
			RequestURIMethod: "post",
		}
		_, err := h.parseRequest(context.Background(), msg)
		require.NoError(t, err)
		assert.Equal(t, http.MethodGet, stub.method)
	})

	// A bare link that is itself the request_uri has no wrapper query to
	// carry the parameter, so the flow start message is the only source.
	t.Run("bare reference URL uses the flow start message", func(t *testing.T) {
		msg := &FlowStartMessage{RequestURI: srv.URL, RequestURIMethod: "post"}
		_, err := h.parseRequest(context.Background(), msg)
		require.NoError(t, err)
		assert.Equal(t, http.MethodPost, stub.method)
	})
}

// --- OpenID4VP 1.0 client_id scheme naming ---
//
// The drafts called the DID scheme "did"; the final specification calls it
// "decentralized_identifier" and carries it as a prefix on the client_id. A
// verifier built against the final spec was rejected outright with
// "unsupported client_id_scheme: decentralized_identifier" before its request
// was ever read - seen live against a third-party verifier whose client_id is
// decentralized_identifier:did:web:<host>.

func TestInferClientIDScheme_DecentralizedIdentifier(t *testing.T) {
	assert.Equal(t, ClientIDSchemeDecentralizedIdentifier,
		inferClientIDScheme("decentralized_identifier:did:web:verifier.example"))
	// The draft spelling still infers as before.
	assert.Equal(t, ClientIDSchemeDID, inferClientIDScheme("did:web:verifier.example"))
}

func TestValidateAuthorizationRequest_AcceptsDecentralizedIdentifier(t *testing.T) {
	h := &OID4VPHandler{}
	authReq := &AuthorizationRequest{
		Nonce:          "n",
		ClientID:       "decentralized_identifier:did:web:verifier.example",
		ClientIDScheme: ClientIDSchemeDecentralizedIdentifier,
		ResponseMode:   ResponseModeDirectPostJWT,
		ResponseURI:    "https://verifier.example/response",
	}
	require.NoError(t, h.validateAuthorizationRequest(authReq, nil))
}

func TestDIDFromClientID(t *testing.T) {
	// Resolution needs the DID itself...
	assert.Equal(t, "did:web:verifier.example",
		didFromClientID("decentralized_identifier:did:web:verifier.example"))
	// ...and an unprefixed client_id is already one.
	assert.Equal(t, "did:web:verifier.example", didFromClientID("did:web:verifier.example"))
	// Anything else is left alone, so a non-DID client_id still fails its own check.
	assert.Equal(t, "https://verifier.example", didFromClientID("https://verifier.example"))
}

func TestVerifyDIDRequest_AcceptsPrefixedClientID(t *testing.T) {
	h := &OID4VPHandler{}
	// No request JWT: the point is that it gets past the DID-shape check and
	// fails on the missing signature instead of on the prefix.
	_, err := h.verifyDIDRequest(&AuthorizationRequest{
		ClientID:       "decentralized_identifier:did:web:verifier.example",
		ClientIDScheme: ClientIDSchemeDecentralizedIdentifier,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "requires a signed request JWT")
}

// --- the active trust path, not just the deprecated one ---
//
// Execute never calls verifyDIDRequest; it goes through evaluateVerifierTrust,
// which resolves the DID and verifies the request JWT against the resolved
// verification methods. The tests above would all pass with that path broken,
// so this one drives it end to end with a stub resolver and pins the split the
// OpenID4VP 1.0 prefix forces: the bare DID is what gets resolved and what the
// displayed domain comes from, while trust evaluation sees the client_id
// exactly as the verifier sent it, prefix and all, because that is what the
// verifier signs and is trusted under.

// stubDIDResolver is a trust.TrustEvaluator that also resolves DIDs, standing
// in for the AuthZEN PDP. It records every subject it is asked to resolve.
type stubDIDResolver struct {
	didDoc   map[string]interface{}
	resolved []string
}

func (s *stubDIDResolver) Evaluate(_ context.Context, _ *trust.EvaluationRequest) (*trust.EvaluationResponse, error) {
	return &trust.EvaluationResponse{Decision: true}, nil
}

func (s *stubDIDResolver) Resolve(_ context.Context, subjectID string) (*trust.EvaluationResponse, error) {
	s.resolved = append(s.resolved, subjectID)
	return &trust.EvaluationResponse{Decision: true, TrustMetadata: s.didDoc}, nil
}

func (s *stubDIDResolver) Name() string { return "stub-did-resolver" }

func (s *stubDIDResolver) SupportedResourceTypes() []trust.ResourceType {
	return []trust.ResourceType{trust.ResourceTypeJWK}
}

func (s *stubDIDResolver) Healthy() bool { return true }

// ecPublicJWK renders an EC P-256 public key as a JWK with the given kid, the
// shape a DID document's verificationMethod carries.
func ecPublicJWK(pub *ecdsa.PublicKey, kid string) map[string]interface{} {
	return map[string]interface{}{
		"kty": "EC",
		"crv": "P-256",
		"x":   base64.RawURLEncoding.EncodeToString(padBytes(pub.X.Bytes(), 32)),
		"y":   base64.RawURLEncoding.EncodeToString(padBytes(pub.Y.Bytes(), 32)),
		"kid": kid,
	}
}

// buildKidSignedJWT builds an ES256 request JWT identifying its key by kid, the
// way a DID-identified verifier signs its request object.
func buildKidSignedJWT(t *testing.T, key *ecdsa.PrivateKey, kid string) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256","kid":"` + kid + `"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"nonce":"n"}`))
	signingInput := header + "." + payload
	sum := crypto.SHA256.New()
	sum.Write([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, key, sum.Sum(nil))
	require.NoError(t, err)
	n := (key.Curve.Params().BitSize + 7) / 8
	sig := make([]byte, 2*n)
	r.FillBytes(sig[:n])
	s.FillBytes(sig[n:])
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// trustEvaluationSubject returns the subject_id of the trust evaluation request
// the handler pushed to the frontend, from the progress messages the test's
// websocket peer collected.
func trustEvaluationSubject(t *testing.T, messages <-chan []byte) string {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		select {
		case raw := <-messages:
			var msg FlowProgressMessage
			if err := json.Unmarshal(raw, &msg); err != nil {
				continue
			}
			var payload struct {
				Request *TrustEvaluationRequest `json:"request"`
			}
			if err := json.Unmarshal(msg.Payload, &payload); err != nil || payload.Request == nil {
				continue
			}
			return payload.Request.SubjectID
		case <-deadline:
			t.Fatal("no trust evaluation request was sent to the frontend")
			return ""
		}
	}
}

func TestEvaluateVerifierTrust_DecentralizedIdentifier(t *testing.T) {
	const (
		did      = "did:web:verifier.example"
		clientID = ClientIDSchemeDecentralizedIdentifier + ":" + did
		kid      = did + "#jwk-1"
	)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	stub := &stubDIDResolver{didDoc: map[string]interface{}{
		"id": did,
		"verificationMethod": []interface{}{
			map[string]interface{}{
				"id":           kid,
				"type":         "JsonWebKey2020",
				"controller":   did,
				"publicKeyJwk": ecPublicJWK(&key.PublicKey, kid),
			},
		},
	}}

	cfg := testConfig()
	cfg.Trust.PDPURL = "http://pdp.test"
	trustSvc := trust.NewService(cfg, zap.NewNop(),
		func(_ string, _ time.Duration) (trust.TrustEvaluator, error) { return stub, nil })

	// The frontend side of the websocket: collect what the handler sends so the
	// trust evaluation request can be inspected.
	messages := make(chan []byte, 16)
	conn, cleanup := wsTestServer(t, func(srvConn *websocket.Conn) {
		for {
			_, data, err := srvConn.ReadMessage()
			if err != nil {
				return
			}
			select {
			case messages <- data:
			default:
			}
		}
	})
	defer cleanup()

	session := testSession(conn)
	flow := &Flow{ID: "test-flow", Session: session, Data: make(map[string]interface{})}

	// The frontend's verdict, queued up front: the handler blocks on it.
	result, err := json.Marshal(TrustResultPayload{Trusted: true, Framework: "did"})
	require.NoError(t, err)
	session.actionCh <- &FlowActionMessage{
		Message: Message{Type: TypeFlowAction, FlowID: flow.ID, Timestamp: Now()},
		Action:  ActionTrustResult,
		Payload: result,
	}

	h := &OID4VPHandler{BaseHandler: BaseHandler{
		Flow:     flow,
		Config:   cfg,
		Logger:   zap.NewNop(),
		TrustSvc: trustSvc,
	}}
	authReq := &AuthorizationRequest{
		ClientID:       clientID,
		ClientIDScheme: ClientIDSchemeDecentralizedIdentifier,
		Nonce:          "n",
		ResponseURI:    "https://verifier.example/response",
		RequestJWT:     buildKidSignedJWT(t, key, kid),
	}

	verifier, err := h.evaluateVerifierTrust(context.Background(), authReq)
	require.NoError(t, err)
	require.NotNil(t, verifier)
	assert.True(t, verifier.Trusted)

	// Resolution asks for the DID, not the client_id that carries it.
	assert.Equal(t, []string{did}, stub.resolved)
	// The domain shown to the user is the DID's either way.
	assert.Equal(t, "verifier.example", verifier.Domain)
	// Trust evaluation sees the client_id exactly as the verifier sent it.
	assert.Equal(t, clientID, trustEvaluationSubject(t, messages))
}

func TestEvaluateVerifierTrust_DecentralizedIdentifierRequiresSignedRequest(t *testing.T) {
	conn, cleanup := wsTestServer(t, func(srvConn *websocket.Conn) {
		for {
			if _, _, err := srvConn.ReadMessage(); err != nil {
				return
			}
		}
	})
	defer cleanup()

	session := testSession(conn)
	flow := &Flow{ID: "test-flow", Session: session, Data: make(map[string]interface{})}
	h := &OID4VPHandler{BaseHandler: BaseHandler{Flow: flow, Config: testConfig(), Logger: zap.NewNop()}}

	// An unsigned request under the new spelling is refused in the active path
	// for the same reason as under the old one - the prefix does not buy a way
	// past the JWT requirement.
	_, err := h.evaluateVerifierTrust(context.Background(), &AuthorizationRequest{
		ClientID:       ClientIDSchemeDecentralizedIdentifier + ":did:web:verifier.example",
		ClientIDScheme: ClientIDSchemeDecentralizedIdentifier,
		Nonce:          "n",
		ResponseURI:    "https://verifier.example/response",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "requires a signed request JWT")

	// A client_id that is not a DID under the prefix is still not a DID.
	_, err = h.evaluateVerifierTrust(context.Background(), &AuthorizationRequest{
		ClientID:       ClientIDSchemeDecentralizedIdentifier + ":https://verifier.example",
		ClientIDScheme: ClientIDSchemeDecentralizedIdentifier,
		Nonce:          "n",
		ResponseURI:    "https://verifier.example/response",
		RequestJWT:     "a.b.c",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "client_id is not a DID")
}

// --- no-matching-credential fast fail ---

// feedAction queues a client action on the session, the way the websocket
// reader does when a real client answers a credential_selection message.
func feedAction(t *testing.T, s *Session, flowID, action string, payload any) {
	t.Helper()
	raw, err := json.Marshal(payload)
	require.NoError(t, err)
	s.actionCh <- &FlowActionMessage{
		Message: Message{Type: TypeFlowAction, FlowID: flowID},
		Action:  action,
		Payload: raw,
	}
}

// newSelectionTestHandler returns a handler whose session writes to a real
// socket, plus the channel of messages the client end receives, so a test can
// assert what the wallet app would actually be told.
func newSelectionTestHandler(t *testing.T) (*OID4VPHandler, *Session, chan map[string]any, func()) {
	t.Helper()
	received := make(chan map[string]any, 20)
	conn, cleanup := wsTestServer(t, func(c *websocket.Conn) {
		for {
			_, data, err := c.ReadMessage()
			if err != nil {
				return
			}
			var msg map[string]any
			if json.Unmarshal(data, &msg) == nil {
				received <- msg
			}
		}
	})
	session := testSession(conn)
	flow := &Flow{ID: "flow-1", Protocol: ProtocolOID4VP, Session: session, Data: map[string]interface{}{}}
	session.flows[flow.ID] = flow
	h := &OID4VPHandler{BaseHandler: BaseHandler{Flow: flow, Logger: zap.NewNop()}}
	h.httpClient = &http.Client{Timeout: 5 * time.Second}
	return h, session, received, cleanup
}

// awaitMessage returns the first received message of the given type.
func awaitMessage(t *testing.T, received chan map[string]any, msgType string) map[string]any {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		select {
		case msg := <-received:
			if msg["type"] == msgType {
				return msg
			}
		case <-deadline:
			t.Fatalf("no %q message arrived", msgType)
		}
	}
}

func TestRequestCredentialSelection_NoMatchFailsFast(t *testing.T) {
	h, session, received, cleanup := newSelectionTestHandler(t)
	defer cleanup()

	// The verifier's response_uri, so the test can assert it is told.
	posted := make(chan url.Values, 1)
	verifier := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		posted <- r.PostForm
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"redirect_uri":"https://verifier.example/done"}`))
	}))
	defer verifier.Close()

	authReq := &AuthorizationRequest{
		DCQLQuery:   json.RawMessage(`{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:eudi:pid:arf-1.8:1"]}}]}`),
		ResponseURI: verifier.URL,
		State:       "state-123",
	}

	feedAction(t, session, h.Flow.ID, ActionCredentialsMatched, CredentialsMatchedPayload{
		NoMatchReason: "no credential with vct urn:eudi:pid:arf-1.8:1",
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	selected, err := h.requestCredentialSelection(ctx, authReq, &VerifierInfo{})

	require.Error(t, err, "an empty match set must end the flow, not wait for consent")
	assert.Nil(t, selected)
	assert.Contains(t, err.Error(), "no credential matches")

	// The verifier is told, so its session ends instead of expiring - with
	// access_denied, which OpenID4VP 1.0 defines for "the Wallet did not have
	// the requested Credentials" and for "the End-User did not give consent"
	// alike. The description must not name what was missing: that would tell
	// the verifier which of the two happened, and so whether this holder has
	// the credential it asked about.
	select {
	case form := <-posted:
		assert.Equal(t, "access_denied", form.Get("error"))
		assert.Equal(t, "state-123", form.Get("state"))
		assert.Equal(t, verifierRefusedDescription, form.Get("error_description"))
		assert.NotContains(t, form.Get("error_description"), "urn:eudi:pid:arf-1.8:1")
	case <-time.After(5 * time.Second):
		t.Fatal("verifier was never notified")
	}

	// The client is told what it needs to explain the failure to its user: a
	// code it can translate and the requested types as data, not an English
	// sentence it would have to re-parse.
	msg := awaitMessage(t, received, string(TypeFlowError))
	flowErr, ok := msg["error"].(map[string]any)
	require.True(t, ok, "flow error must carry an error object, got %v", msg["error"])
	assert.Equal(t, string(ErrCodeNoMatchingCredentials), flowErr["code"])
	assert.Equal(t, ErrCodeNoMatchingCredentials.UserFacingMessage(), flowErr["message"])
	details, ok := flowErr["details"].(map[string]any)
	require.True(t, ok, "flow error must carry details, got %v", flowErr["details"])
	assert.Equal(t, []any{"urn:eudi:pid:arf-1.8:1"}, details["requested_types"])
	assert.Equal(t, "no credential with vct urn:eudi:pid:arf-1.8:1", details["no_match_reason"])
	assert.Equal(t, "https://verifier.example/done", details["redirect_uri"])
}

func TestSubmitErrorResponse_QueryModeRedirectsInsteadOfPosting(t *testing.T) {
	// A verifier using query/fragment gives a redirect_uri and no
	// response_uri; it must still learn the request failed.
	h := &OID4VPHandler{BaseHandler: BaseHandler{Logger: zap.NewNop()}}
	authReq := &AuthorizationRequest{
		RedirectURI:  "https://verifier.example/cb",
		ResponseMode: ResponseModeQuery,
		State:        "state-123",
	}

	redirect := h.submitErrorResponse(context.Background(), authReq, "access_denied", "nothing to present")
	require.NotEmpty(t, redirect, "query mode must yield a redirect for the user agent")

	u, err := url.Parse(redirect)
	require.NoError(t, err)
	assert.Equal(t, "access_denied", u.Query().Get("error"))
	assert.Equal(t, "state-123", u.Query().Get("state"))
	assert.Equal(t, "nothing to present", u.Query().Get("error_description"))
}

func TestSubmitErrorResponse_FragmentModePutsErrorInFragment(t *testing.T) {
	h := &OID4VPHandler{BaseHandler: BaseHandler{Logger: zap.NewNop()}}
	authReq := &AuthorizationRequest{
		RedirectURI:  "https://verifier.example/cb",
		ResponseMode: ResponseModeFragment,
		State:        "s",
	}

	redirect := h.submitErrorResponse(context.Background(), authReq, "access_denied", "")
	require.NotEmpty(t, redirect)

	u, err := url.Parse(redirect)
	require.NoError(t, err)
	assert.Empty(t, u.RawQuery)
	frag, err := url.ParseQuery(u.Fragment)
	require.NoError(t, err)
	assert.Equal(t, "access_denied", frag.Get("error"))
	assert.Equal(t, "s", frag.Get("state"))
}

func TestRequestCredentialSelection_NonEmptyMatchKeepsWaitingForConsent(t *testing.T) {
	h, session, _, cleanup := newSelectionTestHandler(t)
	defer cleanup()

	// A client that reports its matches first and then asks the user must
	// behave exactly like one that only sends consent.
	feedAction(t, session, h.Flow.ID, ActionCredentialsMatched, CredentialsMatchedPayload{
		Matches: []CredentialMatch{{CredentialID: "cred-1"}},
	})
	feedAction(t, session, h.Flow.ID, ActionConsent, ConsentPayload{
		SelectedCredentials: []ConsentSelection{{CredentialID: "cred-1"}},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	selected, err := h.requestCredentialSelection(ctx, &AuthorizationRequest{}, &VerifierInfo{})

	require.NoError(t, err)
	require.Len(t, selected, 1)
	assert.Equal(t, "cred-1", selected[0].CredentialID)
}

func TestWaitForSelectionAction_RepeatedMatchesDoNotExtendTheDeadline(t *testing.T) {
	h, session, _, cleanup := newSelectionTestHandler(t)
	defer cleanup()

	// A client that keeps sending the informational credentials_matched action
	// must not be able to hold the flow open: each wait used to start a fresh
	// UserInteractionTimeout, so the deadline never arrived. Without one
	// deadline across the loop this call never returns and the test hangs.
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		raw, _ := json.Marshal(CredentialsMatchedPayload{
			Matches: []CredentialMatch{{CredentialID: "cred-1"}},
		})
		for {
			select {
			case <-stop:
				return
			case session.actionCh <- &FlowActionMessage{
				Message: Message{Type: TypeFlowAction, FlowID: h.Flow.ID},
				Action:  ActionCredentialsMatched,
				Payload: raw,
			}:
			}
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	start := time.Now()
	action, err := h.waitForSelectionActionUntil(ctx, &AuthorizationRequest{}, start.Add(300*time.Millisecond))

	require.ErrorIs(t, err, ErrFlowTimeout, "the deadline must survive repeated informational actions")
	assert.Nil(t, action)
	assert.Less(t, time.Since(start), 10*time.Second, "the wait must end at the original deadline")
}

func TestSubmitErrorResponse_QueryModePrefersResponseURILikeSubmitResponse(t *testing.T) {
	// validateAuthorizationRequest only forbids redirect_uri for the
	// direct_post modes, so a query/fragment request may carry both. The
	// failure has to go where submitResponse would have sent the vp_token -
	// response_uri first - or the verifier is left waiting on the endpoint
	// that was never told.
	h := &OID4VPHandler{BaseHandler: BaseHandler{Logger: zap.NewNop()}}
	authReq := &AuthorizationRequest{
		ResponseURI:  "https://verifier.example/response",
		RedirectURI:  "https://verifier.example/redirect",
		ResponseMode: ResponseModeQuery,
		State:        "state-123",
	}

	redirect := h.submitErrorResponse(context.Background(), authReq, "access_denied", "nothing to present")
	require.NotEmpty(t, redirect)

	u, err := url.Parse(redirect)
	require.NoError(t, err)
	assert.Equal(t, "/response", u.Path, "the error must go to the endpoint submitResponse would have used")
	assert.Equal(t, "access_denied", u.Query().Get("error"))

	// And redirect_uri is still the fallback when response_uri is absent.
	authReq.ResponseURI = ""
	redirect = h.submitErrorResponse(context.Background(), authReq, "access_denied", "")
	require.NotEmpty(t, redirect)
	u, err = url.Parse(redirect)
	require.NoError(t, err)
	assert.Equal(t, "/redirect", u.Path)
}

func TestRequestedCredentialTypes(t *testing.T) {
	tests := []struct {
		name string
		dcql string
		want []string
	}{
		{
			name: "sd-jwt vct values",
			dcql: `{"credentials":[{"id":"pid","meta":{"vct_values":["urn:eudi:pid:arf-1.8:1","urn:eudi:pid:arf-1.5:1"]}}]}`,
			want: []string{"urn:eudi:pid:arf-1.8:1", "urn:eudi:pid:arf-1.5:1"},
		},
		{
			name: "mdoc doctype",
			dcql: `{"credentials":[{"id":"mdl","meta":{"doctype_value":"org.iso.18013.5.1.mDL"}}]}`,
			want: []string{"org.iso.18013.5.1.mDL"},
		},
		{
			name: "falls back to the credential id when the query names no type",
			dcql: `{"credentials":[{"id":"some-credential","meta":{}}]}`,
			want: []string{"some-credential"},
		},
		{
			name: "deduplicates across credentials",
			dcql: `{"credentials":[{"id":"a","meta":{"vct_values":["urn:x"]}},{"id":"b","meta":{"vct_values":["urn:x"]}}]}`,
			want: []string{"urn:x"},
		},
		{name: "empty query", dcql: ``, want: nil},
		{name: "unparseable query", dcql: `not json`, want: nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, requestedCredentialTypes(json.RawMessage(tt.dcql)))
		})
	}
}
