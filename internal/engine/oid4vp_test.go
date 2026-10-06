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
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
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
	// (a response_uri host). fetchRequestFromURI used to classify body type
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

			authReq, err := h.fetchRequestFromURI(context.Background(), uri)
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
	assert.NoError(t, validateTransactionData(authReq, tdClient))
}

func TestValidateTransactionData_Valid(t *testing.T) {
	td := TransactionData{Type: "owf_payment_initiation", CredentialIDs: []string{"pay"}}
	tdJSON, _ := json.Marshal(td)
	encoded := base64.RawURLEncoding.EncodeToString(tdJSON)
	raw, _ := json.Marshal([]string{encoded})

	authReq := &AuthorizationRequest{TransactionDataRaw: raw}
	err := validateTransactionData(authReq, tdClient)
	assert.NoError(t, err)
	require.Len(t, authReq.TransactionData, 1)
	assert.Equal(t, "owf_payment_initiation", authReq.TransactionData[0].Type)
}

func TestValidateTransactionData_InvalidBase64(t *testing.T) {
	raw, _ := json.Marshal([]string{"not-valid-base64!!!"})
	authReq := &AuthorizationRequest{TransactionDataRaw: raw}
	err := validateTransactionData(authReq, tdClient)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid base64url encoding")
}

func TestValidateTransactionData_InvalidJSON(t *testing.T) {
	encoded := base64.RawURLEncoding.EncodeToString([]byte("{bad json"))
	raw, _ := json.Marshal([]string{encoded})
	authReq := &AuthorizationRequest{TransactionDataRaw: raw}
	err := validateTransactionData(authReq, tdClient)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid JSON")
}

// The engine does not judge whether a type is supported: that depends on the
// type metadata of the attestation the entry is bound to, which the wallet
// resolves. A well-formed entry of any type goes to a client that declared
// the feature, and the client refuses what it cannot handle.
func TestValidateTransactionData_EngineDoesNotJudgeTheType(t *testing.T) {
	td := TransactionData{Type: "some_type_the_engine_has_never_heard_of", CredentialIDs: []string{"pay"}}
	tdJSON, _ := json.Marshal(td)
	encoded := base64.RawURLEncoding.EncodeToString(tdJSON)
	raw, _ := json.Marshal([]string{encoded})

	authReq := &AuthorizationRequest{TransactionDataRaw: raw}
	require.NoError(t, validateTransactionData(authReq, tdClient))
	require.Len(t, authReq.TransactionData, 1)
}

func TestValidateTransactionData_NotStringArray(t *testing.T) {
	authReq := &AuthorizationRequest{TransactionDataRaw: json.RawMessage(`[123, 456]`)}
	err := validateTransactionData(authReq, tdClient)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expected array of base64url strings")
}

func TestValidateTransactionData_Null(t *testing.T) {
	authReq := &AuthorizationRequest{TransactionDataRaw: json.RawMessage(`null`)}
	err := validateTransactionData(authReq, tdClient)
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

// makeSignedJWTWithX5CAndTrustChain is makeSignedJWTWithX5C plus a
// "trust_chain" JWT header parameter, the way a JAR from an OpenID
// Federation entity carries one (OID4VP §5.9.3.6).
func makeSignedJWTWithX5CAndTrustChain(t *testing.T, trustChain []string) (string, *ecdsa.PrivateKey) {
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

	headerJSON, _ := json.Marshal(map[string]interface{}{
		"alg":         "ES256",
		"typ":         "JWT",
		"x5c":         []string{certB64},
		"trust_chain": trustChain,
	})
	header := base64.RawURLEncoding.EncodeToString(headerJSON)

	payloadJSON, _ := json.Marshal(map[string]interface{}{
		"iss": "verifier.example.com",
		"aud": "https://wallet.example.com",
		"iat": time.Now().Unix(),
	})
	payload := base64.RawURLEncoding.EncodeToString(payloadJSON)

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

// A missing RequestJWT is rejected here too, not just an invalid one (#405
// - mirrors the identical x509_san_uri fix from #401): otherwise an
// entirely unsigned x509_san_dns request could still reach
// evaluateVerifierTrust's unconditional client_metadata_uri fetch before
// being rejected.
func TestValidateAuthorizationRequest_X509SANDNS_NoJWTRejected(t *testing.T) {
	h := &OID4VPHandler{}
	authReq := &AuthorizationRequest{
		Nonce:          "abc",
		ResponseMode:   ResponseModeDirectPost,
		ResponseURI:    "https://verifier.example.com/response",
		ClientID:       "verifier.example.com",
		ClientIDScheme: ClientIDSchemeX509SANDNS,
		// No RequestJWT
	}
	err := h.validateAuthorizationRequest(authReq, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "x509_san_dns scheme requires a signed request JWT")
}

// x509_san_uri gets the same early, pre-metadata-fetch signature check as
// x509_san_dns/x509_hash - see the Copilot finding on PR #401
// (https://github.com/sirosfoundation/go-wallet-backend/pull/401#discussion_r4132050300):
// without it, evaluateVerifierTrust's unconditional client_metadata_uri
// fetch (which runs before its scheme switch verifies anything) could be
// triggered by a request whose signature never verifies.
func TestValidateAuthorizationRequest_X509SANURI_ValidJWT(t *testing.T) {
	jwtToken, _ := makeSignedJWTWithX5CURISAN(t, "https://verifier.example.com/id")
	h := &OID4VPHandler{}
	authReq := &AuthorizationRequest{
		Nonce:          "abc",
		ResponseMode:   ResponseModeDirectPost,
		ResponseURI:    "https://verifier.example.com/response",
		ClientID:       "https://verifier.example.com/id",
		ClientIDScheme: ClientIDSchemeX509SANURI,
		RequestJWT:     jwtToken,
	}
	err := h.validateAuthorizationRequest(authReq, nil)
	assert.NoError(t, err)
}

func TestValidateAuthorizationRequest_X509SANURI_InvalidJWT(t *testing.T) {
	h := &OID4VPHandler{}
	authReq := &AuthorizationRequest{
		Nonce:          "abc",
		ResponseMode:   ResponseModeDirectPost,
		ResponseURI:    "https://verifier.example.com/response",
		ClientID:       "https://verifier.example.com/id",
		ClientIDScheme: ClientIDSchemeX509SANURI,
		RequestJWT:     "invalid.jwt.token",
	}
	err := h.validateAuthorizationRequest(authReq, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "JWT signature verification failed")
}

// Unlike x509_san_dns/x509_hash (whose early checks only fire when a
// RequestJWT is present, deferring a missing one to evaluateVerifierTrust's
// scheme switch - by which point its unconditional client_metadata_uri
// fetch has already run), x509_san_uri rejects a missing RequestJWT here
// too - not just an invalid one - per the Copilot finding on PR #401
// (https://github.com/sirosfoundation/go-wallet-backend/pull/401#discussion_r4132142866).
func TestValidateAuthorizationRequest_X509SANURI_NoJWTRejected(t *testing.T) {
	h := &OID4VPHandler{}
	authReq := &AuthorizationRequest{
		Nonce:          "abc",
		ResponseMode:   ResponseModeDirectPost,
		ResponseURI:    "https://verifier.example.com/response",
		ClientID:       "https://verifier.example.com/id",
		ClientIDScheme: ClientIDSchemeX509SANURI,
		// No RequestJWT
	}
	err := h.validateAuthorizationRequest(authReq, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "x509_san_uri scheme requires a signed request JWT")
}

// runValidateThenEvaluate drives authReq through the same two-step sequence
// Execute() actually uses (validateAuthorizationRequest, then - only if
// that passes - evaluateVerifierTrust). The
// TestOID4VPFlow_*_NeverFetchesClientMetadataBeforeVerification tests below
// use this instead of calling validateAuthorizationRequest alone: calling
// only the first step can never actually observe a regression in it, since
// evaluateVerifierTrust - the only function that fetches client_metadata_uri
// at all - would then simply never run within the test either, making
// metadataFetches trivially zero regardless of whether the early rejection
// this test is supposed to guard still works.
func runValidateThenEvaluate(t *testing.T, h *OID4VPHandler, authReq *AuthorizationRequest) error {
	t.Helper()
	if err := h.validateAuthorizationRequest(authReq, nil); err != nil {
		return err
	}
	_, err := h.evaluateVerifierTrust(context.Background(), authReq)
	return err
}

// TestOID4VPFlow_X509SANURI_InvalidSignature_NeverFetchesClientMetadata is
// the end-to-end regression test for the Copilot finding above: driven the
// way Execute() actually calls these two functions in sequence via
// runValidateThenEvaluate, an x509_san_uri request whose signature doesn't
// verify must be rejected before ever reaching evaluateVerifierTrust's
// client_metadata_uri fetch, so the verifier-controlled metadata endpoint
// must see zero requests.
func TestOID4VPFlow_X509SANURI_NeverFetchesClientMetadataBeforeVerification(t *testing.T) {
	tests := []struct {
		name       string
		requestJWT string
		wantErrMsg string
	}{
		{
			name:       "invalid signature",
			requestJWT: "invalid.jwt.token",
			wantErrMsg: "JWT signature verification failed",
		},
		{
			// Per the Copilot finding on PR #401
			// (https://github.com/sirosfoundation/go-wallet-backend/pull/401#discussion_r4132142866):
			// a missing RequestJWT is exactly as unauthenticated as an
			// invalid one and must be rejected before any fetch too.
			name:       "missing request JWT",
			requestJWT: "",
			wantErrMsg: "requires a signed request JWT",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var metadataFetches int32
			metadataServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				atomic.AddInt32(&metadataFetches, 1)
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"client_name":"whatever"}`))
			}))
			defer metadataServer.Close()

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

			h := &OID4VPHandler{
				BaseHandler: BaseHandler{Flow: flow, Config: testConfig(), Logger: zap.NewNop()},
				httpClient:  metadataServer.Client(),
			}
			authReq := &AuthorizationRequest{
				Nonce:             "abc",
				ResponseMode:      ResponseModeDirectPost,
				ResponseURI:       "https://verifier.example.com/response",
				ClientID:          "https://verifier.example.com/id",
				ClientIDScheme:    ClientIDSchemeX509SANURI,
				RequestJWT:        tt.requestJWT,
				ClientMetadataURI: metadataServer.URL,
			}

			err := runValidateThenEvaluate(t, h, authReq)
			require.Error(t, err, "must be rejected before any metadata fetch")
			assert.Contains(t, err.Error(), tt.wantErrMsg)
			assert.Equal(t, int32(0), atomic.LoadInt32(&metadataFetches),
				"client_metadata_uri must never be fetched for an unauthenticated request")
		})
	}
}

// TestOID4VPFlow_X509SANDNSAndHash_NeverFetchesClientMetadataBeforeVerification
// is the regression test for #405: x509_san_dns and x509_hash had the same
// "unsigned/invalidly-signed request can still trigger evaluateVerifierTrust's
// unconditional client_metadata_uri fetch before verification" gap that
// TestOID4VPFlow_X509SANURI_NeverFetchesClientMetadataBeforeVerification
// above already covers for x509_san_uri (fixed in #401). Both schemes' early
// checks in validateAuthorizationRequest now reject a missing RequestJWT the
// same way, before either scheme's check even reaches the invalid-signature
// branch.
func TestOID4VPFlow_X509SANDNSAndHash_NeverFetchesClientMetadataBeforeVerification(t *testing.T) {
	schemeTests := []struct {
		scheme        string
		clientID      string
		wantSchemeErr string
	}{
		{scheme: ClientIDSchemeX509SANDNS, clientID: "verifier.example.com", wantSchemeErr: "x509_san_dns"},
		{scheme: ClientIDSchemeX509Hash, clientID: "deadbeef", wantSchemeErr: "x509_hash"},
	}
	jwtTests := []struct {
		name       string
		requestJWT string
		wantErrMsg string
	}{
		{
			name:       "invalid signature",
			requestJWT: "invalid.jwt.token",
			wantErrMsg: "JWT signature verification failed",
		},
		{
			name:       "missing request JWT",
			requestJWT: "",
			wantErrMsg: "requires a signed request JWT",
		},
	}

	for _, st := range schemeTests {
		for _, jt := range jwtTests {
			t.Run(st.scheme+"/"+jt.name, func(t *testing.T) {
				var metadataFetches int32
				metadataServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					atomic.AddInt32(&metadataFetches, 1)
					w.Header().Set("Content-Type", "application/json")
					_, _ = w.Write([]byte(`{"client_name":"whatever"}`))
				}))
				defer metadataServer.Close()

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

				h := &OID4VPHandler{
					BaseHandler: BaseHandler{Flow: flow, Config: testConfig(), Logger: zap.NewNop()},
					httpClient:  metadataServer.Client(),
				}
				authReq := &AuthorizationRequest{
					Nonce:             "abc",
					ResponseMode:      ResponseModeDirectPost,
					ResponseURI:       "https://verifier.example.com/response",
					ClientID:          st.clientID,
					ClientIDScheme:    st.scheme,
					RequestJWT:        jt.requestJWT,
					ClientMetadataURI: metadataServer.URL,
				}

				// runValidateThenEvaluate (not validateAuthorizationRequest
				// alone) drives the real Execute() sequence, so a
				// regression in the early rejection this test guards would
				// actually reach evaluateVerifierTrust's metadata fetch and
				// be caught below - see its doc comment.
				err := runValidateThenEvaluate(t, h, authReq)
				require.Error(t, err, "must be rejected before any metadata fetch")
				assert.Contains(t, err.Error(), st.wantSchemeErr)
				assert.Contains(t, err.Error(), jt.wantErrMsg)
				assert.Equal(t, int32(0), atomic.LoadInt32(&metadataFetches),
					"client_metadata_uri must never be fetched for an unauthenticated request")
			})
		}
	}
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

// --- #404: pdpSubjectID must preserve the client_id_scheme prefix
// go-trust's ParseClientIDScheme/VerifyLeafBinding require ---

// TestPDPSubjectID_PreservesClientIDSchemePrefix is the regression test for
// #404. go-trust's ParseClientIDScheme (pkg/registry/clientid.go) only
// recognizes an x509_san_dns/x509_san_uri/x509_hash client_id_scheme claim -
// and therefore only invokes VerifyLeafBinding to check the presented
// certificate is actually bound to it, rather than merely chained to a
// trusted CA - when Subject.ID itself carries the "<scheme>:" prefix (see
// go-trust's pkg/registry/static/whitelist.go's isCertificateArrayResourceType:
// "'x5c' is what real callers (e.g. go-wallet-backend) always send, encoding
// the client_id_scheme in Subject.ID instead").
//
// This wallet accepts client_id on the wire two ways: the prefix already
// embedded in client_id itself (OpenID4VP 1.0 final), or a bare client_id
// with client_id_scheme as a separate field (the earlier draft convention,
// still supported - and what this wallet's own test fixtures throughout
// this file use). Before this fix, pdpSubjectID's job was done by passing
// authReq.ClientID straight through: correct by accident for the first wire
// form, but for the second, the certificate's binding to its claimed
// SAN/hash was never actually checked by go-trust at all.
func TestPDPSubjectID_PreservesClientIDSchemePrefix(t *testing.T) {
	tests := []struct {
		name     string
		clientID string
		scheme   string
		want     string
	}{
		{
			name:     "x509_san_dns, bare client_id + separate scheme field",
			clientID: "verifier.example.com",
			scheme:   ClientIDSchemeX509SANDNS,
			want:     "x509_san_dns:verifier.example.com",
		},
		{
			name:     "x509_san_dns, prefix already embedded in client_id",
			clientID: "x509_san_dns:verifier.example.com",
			scheme:   ClientIDSchemeX509SANDNS,
			want:     "x509_san_dns:verifier.example.com", // must not double-prefix
		},
		{
			name:     "x509_san_uri, bare client_id + separate scheme field",
			clientID: "https://verifier.example.com/id",
			scheme:   ClientIDSchemeX509SANURI,
			want:     "x509_san_uri:https://verifier.example.com/id",
		},
		{
			name:     "x509_san_uri, prefix already embedded in client_id",
			clientID: "x509_san_uri:https://verifier.example.com/id",
			scheme:   ClientIDSchemeX509SANURI,
			want:     "x509_san_uri:https://verifier.example.com/id", // must not double-prefix
		},
		{
			name:     "x509_hash, bare client_id + separate scheme field",
			clientID: "deadbeef",
			scheme:   ClientIDSchemeX509Hash,
			want:     "x509_hash:deadbeef",
		},
		{
			name:     "x509_hash, prefix already embedded in client_id",
			clientID: "x509_hash:deadbeef",
			scheme:   ClientIDSchemeX509Hash,
			want:     "x509_hash:deadbeef", // must not double-prefix
		},
		{
			name:     "did scheme is untouched - no prefix to add",
			clientID: "did:web:verifier.example",
			scheme:   ClientIDSchemeDID,
			want:     "did:web:verifier.example",
		},
		{
			name:     "decentralized_identifier scheme is untouched here - a different, separate field (ResolutionSubjectID) handles its prefix",
			clientID: "decentralized_identifier:did:web:verifier.example",
			scheme:   ClientIDSchemeDecentralizedIdentifier,
			want:     "decentralized_identifier:did:web:verifier.example",
		},
		{
			name:     "redirect_uri scheme is untouched - no crypto binding claim to preserve",
			clientID: "https://verifier.example.com",
			scheme:   ClientIDSchemeRedirectURI,
			want:     "https://verifier.example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authReq := &AuthorizationRequest{ClientID: tt.clientID, ClientIDScheme: tt.scheme}
			assert.Equal(t, tt.want, pdpSubjectID(authReq))
		})
	}
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
			// Unlike the other schemes here, x509_san_dns/x509_san_uri
			// reject a missing RequestJWT outright (see
			// TestValidateAuthorizationRequest_X509SANDNS_NoJWTRejected /
			// _X509SANURI_NoJWTRejected) - give them a validly-signed one
			// so this table only exercises "is the scheme recognized at
			// all", the same as every other entry.
			switch scheme {
			case ClientIDSchemeX509SANURI:
				jwtToken, _ := makeSignedJWTWithX5CURISAN(t, authReq.ClientID)
				authReq.RequestJWT = jwtToken
			case ClientIDSchemeX509SANDNS:
				jwtToken, _ := makeSignedJWTWithX5C(t)
				authReq.RequestJWT = jwtToken
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
	jwtToken, _ := makeSignedJWTWithX5C(t)
	h := &OID4VPHandler{}
	authReq := &AuthorizationRequest{
		Nonce:          "abc",
		ResponseMode:   ResponseModeDirectPost,
		ResponseURI:    "https://evil.example.com/response",
		ClientID:       "verifier.example.com",
		ClientIDScheme: ClientIDSchemeX509SANDNS,
		RequestJWT:     jwtToken,
	}
	msg := &FlowStartMessage{
		RequestURI: "https://verifier.example.com/request",
	}
	err := h.validateAuthorizationRequest(authReq, msg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not match request_uri origin")
}

func TestValidateAuthorizationRequest_WithTransactionData(t *testing.T) {
	td := TransactionData{Type: "owf_payment_initiation", CredentialIDs: []string{"pay"}}
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
	err := h.validateAuthorizationRequest(authReq, tdClient)
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
// in for the AuthZEN PDP. It records every subject it is asked to resolve or
// evaluate, and lets a test control the evaluate decision.
type stubDIDResolver struct {
	didDoc      map[string]interface{}
	resolved    []string
	evaluated   []string
	decision    bool
	evalErr     error
	decisionOk  bool // if false, decision defaults to true (zero-value-safe for existing callers)
	lastContext map[string]interface{}
}

func (s *stubDIDResolver) Evaluate(_ context.Context, req *trust.EvaluationRequest) (*trust.EvaluationResponse, error) {
	s.evaluated = append(s.evaluated, req.SubjectID)
	s.lastContext = req.Context
	if s.evalErr != nil {
		return nil, s.evalErr
	}
	if !s.decisionOk {
		return &trust.EvaluationResponse{Decision: true}, nil
	}
	return &trust.EvaluationResponse{Decision: s.decision}, nil
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
	req := trustEvaluationRequest(t, messages)
	return req.SubjectID
}

// trustEvaluationRequest returns the full trust evaluation request the
// handler pushed to the frontend, from the progress messages the test's
// websocket peer collected.
func trustEvaluationRequest(t *testing.T, messages <-chan []byte) *TrustEvaluationRequest {
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
			return payload.Request
		case <-deadline:
			t.Fatal("no trust evaluation request was sent to the frontend")
			return nil
		}
	}
}

// makeSignedJWTWithX5CURISAN is makeSignedJWTWithX5C but the leaf
// certificate carries a URI SAN (x509_san_uri) instead of a DNS SAN
// (x509_san_dns).
func makeSignedJWTWithX5CURISAN(t *testing.T, sanURI string) (string, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	parsedURI, err := url.Parse(sanURI)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-verifier"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		URIs:         []*url.URL{parsedURI},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	certB64 := base64.StdEncoding.EncodeToString(certDER)

	headerJSON, _ := json.Marshal(map[string]interface{}{
		"alg": "ES256",
		"typ": "JWT",
		"x5c": []string{certB64},
	})
	header := base64.RawURLEncoding.EncodeToString(headerJSON)

	payloadJSON, _ := json.Marshal(map[string]interface{}{
		"iss": sanURI,
		"aud": "https://wallet.example.com",
		"iat": time.Now().Unix(),
	})
	payload := base64.RawURLEncoding.EncodeToString(payloadJSON)

	signingInput := header + "." + payload
	token := jwt.New(jwt.SigningMethodES256)
	sigBytes, err := token.Method.Sign(signingInput, key)
	require.NoError(t, err)

	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sigBytes), key
}

// TestEvaluateVerifierTrust_DecentralizedIdentifier drives the active DID
// trust path end to end with a PDP configured: cfg.Trust.PDPURL makes
// GetVerifierPDPURL() non-empty, so evaluateVerifierTrust must go straight to
// h.TrustSvc.EvaluateVerifier (the PDP-first path) rather than asking the
// frontend - the frontend fallback is reserved for the no-PDP case (see
// TestEvaluateVerifierTrust_DecentralizedIdentifier_NoPDPFallsBackToFrontend).
func TestEvaluateVerifierTrust_DecentralizedIdentifier(t *testing.T) {
	const (
		did      = "did:web:verifier.example"
		clientID = ClientIDSchemeDecentralizedIdentifier + ":" + did
		kid      = did + "#jwk-1"
	)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	stub := &stubDIDResolver{
		didDoc: map[string]interface{}{
			"id": did,
			"verificationMethod": []interface{}{
				map[string]interface{}{
					"id":           kid,
					"type":         "JsonWebKey2020",
					"controller":   did,
					"publicKeyJwk": ecPublicJWK(&key.PublicKey, kid),
				},
			},
		},
		decisionOk: true,
		decision:   true,
	}

	cfg := testConfig()
	cfg.Trust.PDPURL = "http://pdp.test"
	trustSvc := trust.NewService(cfg, zap.NewNop(),
		func(_ string, _ time.Duration) (trust.TrustEvaluator, error) { return stub, nil })

	// The websocket peer only drains progress messages and never answers a
	// trust_result action: if evaluateVerifierTrust mistakenly fell back to
	// the frontend here, WaitForActionWithTimeout would have nothing to
	// read and the test would hang/time out, failing loudly rather than
	// silently passing via the old fallback path.
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
	// Trust evaluation (the PDP call) sees the client_id exactly as the
	// verifier sent it.
	assert.Equal(t, []string{clientID}, stub.evaluated)
}

// TestEvaluateVerifierTrust_DecentralizedIdentifier_NoPDPFallsBackToFrontend
// is the regression guard for the intentional no-PDP dev-mode path: with no
// verifier PDP configured at all, evaluateVerifierTrust must still fall back
// to asking the frontend/client, exactly as before this change. DID
// resolution itself still requires *some* PDP endpoint (ResolveDID always
// goes through GetVerifierPDPURL()), so this test uses x509_san_dns instead,
// whose signature verification is entirely local.
func TestEvaluateVerifierTrust_NoPDPConfigured_FallsBackToFrontend(t *testing.T) {
	requestJWT, _ := makeSignedJWTWithX5C(t) // DNSNames: verifier.example.com

	cfg := testConfig() // no Trust.PDPURL / Verifier.PDPURL set at all

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

	result, err := json.Marshal(TrustResultPayload{Trusted: true, Framework: "eidas"})
	require.NoError(t, err)
	session.actionCh <- &FlowActionMessage{
		Message: Message{Type: TypeFlowAction, FlowID: flow.ID, Timestamp: Now()},
		Action:  ActionTrustResult,
		Payload: result,
	}

	h := &OID4VPHandler{BaseHandler: BaseHandler{
		Flow:   flow,
		Config: cfg,
		Logger: zap.NewNop(),
	}}
	authReq := &AuthorizationRequest{
		ClientID:       "verifier.example.com",
		ClientIDScheme: ClientIDSchemeX509SANDNS,
		Nonce:          "n",
		ResponseURI:    "https://verifier.example.com/response",
		RequestJWT:     requestJWT,
	}

	verifier, err := h.evaluateVerifierTrust(context.Background(), authReq)
	require.NoError(t, err)
	require.NotNil(t, verifier)
	assert.True(t, verifier.Trusted)
	// The frontend's own /v1/evaluate call needs the client_id_scheme
	// prefix present in Subject.ID for go-trust to invoke VerifyLeafBinding
	// (#404) - see pdpSubjectID's doc comment.
	assert.Equal(t, "x509_san_dns:verifier.example.com", trustEvaluationSubject(t, messages))
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

// --- M-3 (#375): PDP-first verifier trust, fail-closed, cache correctness ---

// A PDP call error must fail closed (untrusted) and must NEVER fall back to
// asking the client - the whole point of configuring a verifier PDP is that
// its unavailability isn't a trust bypass. This mirrors the corrected shape
// of OID4VCIHandler.evaluateTrust for issuers (#377).
func TestEvaluateVerifierTrust_PDPError_FailsClosed_NoFrontendFallback(t *testing.T) {
	requestJWT, _ := makeSignedJWTWithX5C(t) // client_id "verifier.example.com"

	cfg := testConfig()
	cfg.Trust.PDPURL = "http://pdp.test"
	// The evaluator factory itself fails (e.g. a malformed/unreachable PDP
	// endpoint) - this is EvaluateVerifier's true Go-error path, as opposed
	// to a request the PDP itself answers but denies (which already comes
	// back as Trusted:false, not an error, and was always handled).
	trustSvc := trust.NewService(cfg, zap.NewNop(),
		func(_ string, _ time.Duration) (trust.TrustEvaluator, error) {
			return nil, fmt.Errorf("pdp unreachable")
		})

	// The websocket peer only drains: it never answers a trust_result
	// action. If evaluateVerifierTrust wrongly fell back to the frontend
	// after the PDP error, WaitForActionWithTimeout would block on this and
	// the test would time out instead of returning promptly with an error.
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
	h := &OID4VPHandler{BaseHandler: BaseHandler{
		Flow: flow, Config: cfg, Logger: zap.NewNop(), TrustSvc: trustSvc,
	}}
	authReq := &AuthorizationRequest{
		ClientID:       "verifier.example.com",
		ClientIDScheme: ClientIDSchemeX509SANDNS,
		Nonce:          "n",
		ResponseURI:    "https://verifier.example.com/response",
		RequestJWT:     requestJWT,
	}

	verifier, err := h.evaluateVerifierTrust(context.Background(), authReq)
	require.Error(t, err)
	assert.Nil(t, verifier)
	assert.Contains(t, err.Error(), "untrusted verifier")
	assert.Contains(t, err.Error(), "trust evaluation error")
}

// Unlike a PDP call error (which never reaches a Trusted value at all), the
// PDP can answer normally and simply deny trust. That must still block the
// verifier, with no Go error from the evaluator itself.
func TestEvaluateVerifierTrust_PDPPath_DeniedWithoutError(t *testing.T) {
	requestJWT, _ := makeSignedJWTWithX5C(t)

	cfg := testConfig()
	cfg.Trust.PDPURL = "http://pdp.test"
	stub := &stubDIDResolver{decisionOk: true, decision: false}
	trustSvc := trust.NewService(cfg, zap.NewNop(),
		func(_ string, _ time.Duration) (trust.TrustEvaluator, error) { return stub, nil })
	trustCache := NewTrustCache(time.Hour)

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
	h := &OID4VPHandler{BaseHandler: BaseHandler{
		Flow: flow, Config: cfg, Logger: zap.NewNop(), TrustSvc: trustSvc, TrustCache: trustCache,
	}}
	authReq := &AuthorizationRequest{
		ClientID:       "verifier.example.com",
		ClientIDScheme: ClientIDSchemeX509SANDNS,
		Nonce:          "n",
		ResponseURI:    "https://verifier.example.com/response",
		RequestJWT:     requestJWT,
	}

	verifier, err := h.evaluateVerifierTrust(context.Background(), authReq)
	require.Error(t, err)
	assert.Nil(t, verifier)
	assert.Contains(t, err.Error(), "untrusted verifier")
	// A PDP-answered denial is still a PDP-backed result, so it's cached
	// (a repeat request against the same certificate shouldn't re-ask the
	// PDP a question it already answered within the TTL).
	assert.Equal(t, 1, trustCache.Len())
}

// A cache HIT on a trusted, PDP-backed verdict must return that verdict
// without a second PDP call.
func TestEvaluateVerifierTrust_PDPPath_CacheHit_Trusted_SkipsSecondPDPCall(t *testing.T) {
	requestJWT, _ := makeSignedJWTWithX5C(t)

	cfg := testConfig()
	cfg.Trust.PDPURL = "http://pdp.test"
	stub := &stubDIDResolver{decisionOk: true, decision: true}
	trustSvc := trust.NewService(cfg, zap.NewNop(),
		func(_ string, _ time.Duration) (trust.TrustEvaluator, error) { return stub, nil })
	trustCache := NewTrustCache(time.Hour)

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
	h := &OID4VPHandler{BaseHandler: BaseHandler{
		Flow: flow, Config: cfg, Logger: zap.NewNop(), TrustSvc: trustSvc, TrustCache: trustCache,
	}}
	authReq := &AuthorizationRequest{
		ClientID:       "verifier.example.com",
		ClientIDScheme: ClientIDSchemeX509SANDNS,
		Nonce:          "n",
		ResponseURI:    "https://verifier.example.com/response",
		RequestJWT:     requestJWT,
	}

	first, err := h.evaluateVerifierTrust(context.Background(), authReq)
	require.NoError(t, err)
	require.True(t, first.Trusted)
	require.Len(t, stub.evaluated, 1, "first call must reach the PDP")

	second, err := h.evaluateVerifierTrust(context.Background(), authReq)
	require.NoError(t, err)
	require.NotNil(t, second)
	assert.True(t, second.Trusted)
	assert.Len(t, stub.evaluated, 1, "second call for the same certificate must be served from cache, not the PDP again")
}

// A cache HIT on an untrusted, PDP-backed verdict must still block the
// verifier (and still without a second PDP call) - a cached denial is not
// silently forgiven.
func TestEvaluateVerifierTrust_PDPPath_CacheHit_Untrusted_SkipsSecondPDPCall(t *testing.T) {
	requestJWT, _ := makeSignedJWTWithX5C(t)

	cfg := testConfig()
	cfg.Trust.PDPURL = "http://pdp.test"
	stub := &stubDIDResolver{decisionOk: true, decision: false}
	trustSvc := trust.NewService(cfg, zap.NewNop(),
		func(_ string, _ time.Duration) (trust.TrustEvaluator, error) { return stub, nil })
	trustCache := NewTrustCache(time.Hour)

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
	h := &OID4VPHandler{BaseHandler: BaseHandler{
		Flow: flow, Config: cfg, Logger: zap.NewNop(), TrustSvc: trustSvc, TrustCache: trustCache,
	}}
	authReq := &AuthorizationRequest{
		ClientID:       "verifier.example.com",
		ClientIDScheme: ClientIDSchemeX509SANDNS,
		Nonce:          "n",
		ResponseURI:    "https://verifier.example.com/response",
		RequestJWT:     requestJWT,
	}

	_, err := h.evaluateVerifierTrust(context.Background(), authReq)
	require.Error(t, err)
	require.Len(t, stub.evaluated, 1, "first call must reach the PDP")

	_, err = h.evaluateVerifierTrust(context.Background(), authReq)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cached")
	assert.Len(t, stub.evaluated, 1, "second call for the same certificate must be served from cache, not the PDP again")
}

// A client-asserted verdict (the no-PDP frontend fallback) must never be
// written to the trust cache: caching it would let one attacker-controlled
// answer stand in as ground truth for every subsequent request against this
// identity for the whole cache TTL. The Trusted/Framework decision itself
// is still accepted from the frontend at face value here (that's the whole
// point of this permissive no-PDP dev mode - see the function-level comment
// on evaluateVerifierTrustViaFrontend), but the display name is not (#406):
// verifier.Name stays the identifier the evaluation was actually about
// (authReq.ClientID), never the frontend-asserted name, consistent with
// #398's fix to the PDP-backed path - this wallet-backend has no way to
// tell that name apart from the verifier's own unauthenticated
// client_metadata.client_name.
func TestEvaluateVerifierTrust_ClientAssertedVerdict_NeverCached(t *testing.T) {
	requestJWT, _ := makeSignedJWTWithX5C(t)

	cfg := testConfig() // no PDP configured at all
	trustCache := NewTrustCache(time.Hour)

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

	result, err := json.Marshal(TrustResultPayload{Trusted: true, Framework: "client-asserted", Name: "Attacker-Controlled Name"})
	require.NoError(t, err)
	session.actionCh <- &FlowActionMessage{
		Message: Message{Type: TypeFlowAction, FlowID: flow.ID, Timestamp: Now()},
		Action:  ActionTrustResult,
		Payload: result,
	}

	h := &OID4VPHandler{BaseHandler: BaseHandler{
		Flow: flow, Config: cfg, Logger: zap.NewNop(), TrustCache: trustCache,
	}}
	authReq := &AuthorizationRequest{
		ClientID:       "verifier.example.com",
		ClientIDScheme: ClientIDSchemeX509SANDNS,
		Nonce:          "n",
		ResponseURI:    "https://verifier.example.com/response",
		RequestJWT:     requestJWT,
	}

	verifier, err := h.evaluateVerifierTrust(context.Background(), authReq)
	require.NoError(t, err)
	require.NotNil(t, verifier)
	assert.True(t, verifier.Trusted)
	assert.Equal(t, authReq.ClientID, verifier.Name, "the displayed name must be the verified client_id, never the frontend-asserted name (#406)")
	assert.NotEqual(t, "Attacker-Controlled Name", verifier.Name)
	assert.Zero(t, trustCache.Len(), "a client-asserted (non-PDP-backed) verdict must never be cached")
}

// The trust cache must never let a request skip signature verification: a
// cache lookup only ever happens with the identity that scheme-bound
// signature verification produces, so an invalid/unverifiable signature
// fails before the cache is even consulted - regardless of what a
// previously-cached (and here, deliberately seeded) entry says.
func TestEvaluateVerifierTrust_CacheNeverBypassesSignatureVerification(t *testing.T) {
	cfg := testConfig()
	cfg.Trust.PDPURL = "http://pdp.test" // configured, but must never be reached
	stub := &stubDIDResolver{}
	trustSvc := trust.NewService(cfg, zap.NewNop(),
		func(_ string, _ time.Duration) (trust.TrustEvaluator, error) { return stub, nil })

	trustCache := NewTrustCache(time.Hour)
	// Seed a trusted verdict under the exact identity key the attacker will
	// claim, as if a legitimate prior request had earned it.
	trustCache.Set(domain.DefaultTenantID, "x509_san_dns:verifier.example.com", &TrustCacheRecord{
		Trusted:     true,
		TrustStatus: domain.TrustStatusTrusted,
		Name:        "Legit Verifier",
	})

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
	h := &OID4VPHandler{BaseHandler: BaseHandler{
		Flow: flow, Config: cfg, Logger: zap.NewNop(), TrustSvc: trustSvc, TrustCache: trustCache,
	}}
	authReq := &AuthorizationRequest{
		ClientID:       "verifier.example.com",
		ClientIDScheme: ClientIDSchemeX509SANDNS,
		Nonce:          "n",
		ResponseURI:    "https://verifier.example.com/response",
		RequestJWT:     "not-a.valid-signed.jwt", // fails signature verification
	}

	verifier, err := h.evaluateVerifierTrust(context.Background(), authReq)
	require.Error(t, err)
	assert.Nil(t, verifier)
	assert.Contains(t, err.Error(), "JWT verification failed")
	// The PDP (and therefore any cache read tied to a verified identity)
	// must never have been reached for this unverifiable request.
	assert.Empty(t, stub.evaluated)
}

// A cached verdict must be scoped to the authenticated identity that earned
// it, not to whatever URL/canonical delivery target a request happens to
// share with a previous one. Two different, independently-authenticated
// verifiers sharing the same response_uri must each get their own trust
// decision - one may never answer for the other.
func TestEvaluateVerifierTrust_CacheDoesNotLeakAcrossDifferentClaimedVerifier(t *testing.T) {
	const (
		sharedResponseURI = "https://shared.example/response"
		did               = "did:web:verifier-b.example"
		clientIDB         = ClientIDSchemeDecentralizedIdentifier + ":" + did
		kid               = did + "#jwk-1"
	)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	stub := &stubDIDResolver{
		didDoc: map[string]interface{}{
			"id": did,
			"verificationMethod": []interface{}{
				map[string]interface{}{
					"id":           kid,
					"type":         "JsonWebKey2020",
					"controller":   did,
					"publicKeyJwk": ecPublicJWK(&key.PublicKey, kid),
				},
			},
		},
		decisionOk: true,
		decision:   true,
	}
	cfg := testConfig()
	cfg.Trust.PDPURL = "http://pdp.test"
	trustSvc := trust.NewService(cfg, zap.NewNop(),
		func(_ string, _ time.Duration) (trust.TrustEvaluator, error) { return stub, nil })
	trustCache := NewTrustCache(time.Hour)

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
	h := &OID4VPHandler{BaseHandler: BaseHandler{
		Flow: flow, Config: cfg, Logger: zap.NewNop(), TrustSvc: trustSvc, TrustCache: trustCache,
	}}

	// Seed the cache for a completely different, x509_san_dns-identified
	// verifier that happens to share the same response_uri, with an
	// attacker-distinguishable name so a leak is obvious if it occurs.
	trustCache.Set(domain.TenantID(session.TenantID), "x509_san_dns:verifier-a.example.com", &TrustCacheRecord{
		Trusted:     true,
		TrustStatus: domain.TrustStatusTrusted,
		Name:        "Verifier A (should never be returned for B)",
	})

	authReqB := &AuthorizationRequest{
		ClientID:       clientIDB,
		ClientIDScheme: ClientIDSchemeDecentralizedIdentifier,
		Nonce:          "n",
		ResponseURI:    sharedResponseURI,
		RequestJWT:     buildKidSignedJWT(t, key, kid),
	}

	verifierB, err := h.evaluateVerifierTrust(context.Background(), authReqB)
	require.NoError(t, err)
	require.NotNil(t, verifierB)
	// B was independently resolved and evaluated - A's cache entry did not
	// short-circuit B's lookup merely because they share a response_uri.
	assert.Equal(t, []string{did}, stub.resolved)
	assert.Equal(t, []string{clientIDB}, stub.evaluated)
	assert.NotEqual(t, "Verifier A (should never be returned for B)", verifierB.Name)
}

// A x509_san_dns client_id (a SAN DNS name) can be presented by any
// certificate naming that domain - this handler verifies the request JWT's
// signature against whatever x5c it carries, but never itself checks that
// certificate against the one a PDP-backed cache entry was earned by. Two
// requests claiming the SAME client_id but signing with two DIFFERENT
// certificates must each reach the PDP independently: the cache key must
// include a fingerprint of the actual certificate, not just the claimed
// domain.
func TestEvaluateVerifierTrust_CacheKeyIncludesCertificateFingerprint(t *testing.T) {
	jwtA, _ := makeSignedJWTWithX5C(t) // fresh cert/key, client_id "verifier.example.com"
	jwtB, _ := makeSignedJWTWithX5C(t) // a DIFFERENT fresh cert/key, same claimed client_id

	cfg := testConfig()
	cfg.Trust.PDPURL = "http://pdp.test"
	stub := &stubDIDResolver{decisionOk: true, decision: true}
	trustSvc := trust.NewService(cfg, zap.NewNop(),
		func(_ string, _ time.Duration) (trust.TrustEvaluator, error) { return stub, nil })
	trustCache := NewTrustCache(time.Hour)

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
	h := &OID4VPHandler{BaseHandler: BaseHandler{
		Flow: flow, Config: cfg, Logger: zap.NewNop(), TrustSvc: trustSvc, TrustCache: trustCache,
	}}

	baseReq := &AuthorizationRequest{
		ClientID:       "verifier.example.com",
		ClientIDScheme: ClientIDSchemeX509SANDNS,
		Nonce:          "n",
		ResponseURI:    "https://verifier.example.com/response",
	}

	reqA := *baseReq
	reqA.RequestJWT = jwtA
	verifierA, err := h.evaluateVerifierTrust(context.Background(), &reqA)
	require.NoError(t, err)
	require.True(t, verifierA.Trusted)
	assert.Equal(t, 1, trustCache.Len(), "cert A's verdict should be cached once")

	reqB := *baseReq
	reqB.RequestJWT = jwtB
	verifierB, err := h.evaluateVerifierTrust(context.Background(), &reqB)
	require.NoError(t, err)
	require.True(t, verifierB.Trusted)

	// Cert B must have been independently evaluated by the PDP - not served
	// from cert A's cache entry merely because they share a client_id. The
	// PDP subject carries the x509_san_dns: prefix (#404) so go-trust can
	// actually invoke VerifyLeafBinding against it.
	assert.Equal(t, []string{"x509_san_dns:verifier.example.com", "x509_san_dns:verifier.example.com"}, stub.evaluated,
		"the PDP must be consulted separately for each distinct certificate")
	assert.Equal(t, 2, trustCache.Len(), "each certificate gets its own cache entry")
}

// When a verifier PDP is configured, the direct evaluation path must
// forward the same OIDF trust_chain context a frontend-mediated evaluation
// has always carried in TrustEvaluationRequest.Context - otherwise go-trust
// has no trust chain to validate a JAR-signing federation entity against.
func TestEvaluateVerifierTrust_PDPPath_ForwardsTrustChainContext(t *testing.T) {
	trustChain := []string{"chain-leaf", "chain-intermediate", "chain-anchor"}
	requestJWT, _ := makeSignedJWTWithX5CAndTrustChain(t, trustChain)

	cfg := testConfig()
	cfg.Trust.PDPURL = "http://pdp.test"
	stub := &stubDIDResolver{decisionOk: true, decision: true}
	trustSvc := trust.NewService(cfg, zap.NewNop(),
		func(_ string, _ time.Duration) (trust.TrustEvaluator, error) { return stub, nil })

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
	h := &OID4VPHandler{BaseHandler: BaseHandler{
		Flow: flow, Config: cfg, Logger: zap.NewNop(), TrustSvc: trustSvc,
	}}
	authReq := &AuthorizationRequest{
		ClientID:       "verifier.example.com",
		ClientIDScheme: ClientIDSchemeX509SANDNS,
		Nonce:          "n",
		ResponseURI:    "https://verifier.example.com/response",
		RequestJWT:     requestJWT,
	}

	verifier, err := h.evaluateVerifierTrust(context.Background(), authReq)
	require.NoError(t, err)
	require.NotNil(t, verifier)
	assert.True(t, verifier.Trusted)

	require.NotNil(t, stub.lastContext, "the PDP call must carry an evaluation context")
	gotChain, ok := stub.lastContext["trust_chain"].([]string)
	require.True(t, ok, "trust_chain must be forwarded as a []string, got %#v", stub.lastContext["trust_chain"])
	assert.Equal(t, trustChain, gotChain)
}

// TestKeyMaterialFingerprint exercises keyMaterialFingerprint directly
// across its key-type branches and failure paths, since most of these
// (invalid encodings, unparseable JWKs) are edge cases evaluateVerifierTrust
// itself can't organically reach - VerifyJWTWithEmbeddedKey already
// guarantees valid x5c/JWK material by the time keyMaterialFingerprint is
// called from the x509_san_dns/x509_hash/verifier_attestation cases.
func TestKeyMaterialFingerprint(t *testing.T) {
	t.Run("nil key material", func(t *testing.T) {
		assert.Equal(t, "", keyMaterialFingerprint(nil))
	})

	t.Run("x5c with no certificates", func(t *testing.T) {
		assert.Equal(t, "", keyMaterialFingerprint(&KeyMaterial{Type: "x5c"}))
	})

	t.Run("x5c invalid base64", func(t *testing.T) {
		assert.Equal(t, "", keyMaterialFingerprint(&KeyMaterial{Type: "x5c", X5C: []string{"!!!not-base64!!!"}}))
	})

	t.Run("x5c standard base64", func(t *testing.T) {
		der := []byte("fake-cert-der-bytes-for-fingerprint-test")
		fp := keyMaterialFingerprint(&KeyMaterial{Type: "x5c", X5C: []string{base64.StdEncoding.EncodeToString(der)}})
		assert.True(t, strings.HasPrefix(fp, "sha256:"), "got %q", fp)
	})

	t.Run("x5c falls back to raw-url base64", func(t *testing.T) {
		// 5 bytes (not a multiple of 3) so RawURLEncoding produces an
		// unpadded string base64.StdEncoding.DecodeString rejects outright,
		// forcing the RawURLEncoding fallback branch.
		der := []byte{1, 2, 3, 4, 5}
		fp := keyMaterialFingerprint(&KeyMaterial{Type: "x5c", X5C: []string{base64.RawURLEncoding.EncodeToString(der)}})
		assert.True(t, strings.HasPrefix(fp, "sha256:"), "got %q", fp)
	})

	t.Run("jwk valid", func(t *testing.T) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		fp := keyMaterialFingerprint(&KeyMaterial{Type: "jwk", JWK: ecPublicJWK(&key.PublicKey, "kid-1")})
		assert.True(t, strings.HasPrefix(fp, "jwk:"), "got %q", fp)
	})

	t.Run("jwk nil", func(t *testing.T) {
		assert.Equal(t, "", keyMaterialFingerprint(&KeyMaterial{Type: "jwk"}))
	})

	t.Run("jwk unparseable", func(t *testing.T) {
		assert.Equal(t, "", keyMaterialFingerprint(&KeyMaterial{Type: "jwk", JWK: map[string]interface{}{"not": "a jwk"}}))
	})

	t.Run("jwk unmarshalable", func(t *testing.T) {
		// A channel value can't be JSON-marshaled, exercising the
		// json.Marshal error branch specifically (distinct from the
		// UnmarshalJSON error case above).
		assert.Equal(t, "", keyMaterialFingerprint(&KeyMaterial{Type: "jwk", JWK: make(chan int)}))
	})

	t.Run("unknown type", func(t *testing.T) {
		assert.Equal(t, "", keyMaterialFingerprint(&KeyMaterial{Type: "unknown"}))
	})
}

// TestEvaluateVerifierTrust_X509Hash_PDPPath drives the x509_hash scheme end
// to end through the PDP-first path: it was entirely untested before (only
// x509_san_dns and did: had coverage), and shares keyMaterialFingerprint's
// x5c branch and the cacheable-cache-key wiring with x509_san_dns.
func TestEvaluateVerifierTrust_X509Hash_PDPPath(t *testing.T) {
	requestJWT, _ := makeSignedJWTWithX5C(t)

	cfg := testConfig()
	cfg.Trust.PDPURL = "http://pdp.test"
	stub := &stubDIDResolver{decisionOk: true, decision: true}
	trustSvc := trust.NewService(cfg, zap.NewNop(),
		func(_ string, _ time.Duration) (trust.TrustEvaluator, error) { return stub, nil })
	trustCache := NewTrustCache(time.Hour)

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
	h := &OID4VPHandler{BaseHandler: BaseHandler{
		Flow: flow, Config: cfg, Logger: zap.NewNop(), TrustSvc: trustSvc, TrustCache: trustCache,
	}}

	// The claimed client_id under x509_hash is supposed to be the cert's own
	// hash; this handler never checks that binding itself (the PDP does),
	// so any value exercises the code path under test.
	const claimedHash = "claimed-cert-hash-abc123"
	authReq := &AuthorizationRequest{
		ClientID:       claimedHash,
		ClientIDScheme: ClientIDSchemeX509Hash,
		Nonce:          "n",
		// RedirectURI (not ResponseURI) here so this also exercises
		// buildVerifierEvalContext's redirect_uri branch.
		RedirectURI: "https://verifier.example.com/redirect",
		RequestJWT:  requestJWT,
	}

	verifier, err := h.evaluateVerifierTrust(context.Background(), authReq)
	require.NoError(t, err)
	require.NotNil(t, verifier)
	assert.True(t, verifier.Trusted)
	// The x509_hash: prefix must be present in Subject.ID for go-trust's
	// ParseClientIDScheme/VerifyLeafBinding to run against it (#404).
	assert.Equal(t, []string{"x509_hash:" + claimedHash}, stub.evaluated)
	assert.Equal(t, 1, trustCache.Len(), "a fingerprinted x509_hash verdict is cacheable")
}

// buildVerifierAttestationRequestJWT builds a request JWT under the
// verifier_attestation scheme (OID4VP §5.9.3.4): an attestation JWT
// asserting {iss, sub, cnf.jwk}, embedded via the outer request JWT's "jwt"
// header parameter, with the outer JWT itself signed by cnfKey - the same
// shape trust.ExtractVerifierAttestation/VerifyJWTWithResolvedKeys expect.
// The attestation JWT's own signature is never verified by this handler
// (that's the PDP's job, given the forwarded attestation_jwt context), so it
// is signed by a throwaway key here.
func buildVerifierAttestationRequestJWT(t *testing.T, issuer, subject string, cnfKey *ecdsa.PrivateKey) string {
	t.Helper()

	attestKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	cnfJWK := ecPublicJWK(&cnfKey.PublicKey, "")
	attestationPayload, err := json.Marshal(map[string]interface{}{
		"iss": issuer,
		"sub": subject,
		"cnf": map[string]interface{}{"jwk": cnfJWK},
	})
	require.NoError(t, err)
	attestationJWT := signECDSAJWTForTest(t, attestKey, []byte(`{"alg":"ES256"}`), attestationPayload)

	reqHeader, err := json.Marshal(map[string]interface{}{
		"alg": "ES256",
		"jwt": attestationJWT,
	})
	require.NoError(t, err)
	reqPayload, err := json.Marshal(map[string]interface{}{"nonce": "n"})
	require.NoError(t, err)

	return signECDSAJWTForTest(t, cnfKey, reqHeader, reqPayload)
}

// signECDSAJWTForTest builds and signs a JWT from raw header/payload JSON
// with an ES256 key, the same manual construction buildKidSignedJWT uses.
func signECDSAJWTForTest(t *testing.T, key *ecdsa.PrivateKey, headerJSON, payloadJSON []byte) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString(headerJSON)
	payload := base64.RawURLEncoding.EncodeToString(payloadJSON)
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

// TestEvaluateVerifierTrust_VerifierAttestation_PDPPath drives the
// verifier_attestation scheme end to end through the PDP-first path: it was
// entirely untested before, and exercises keyMaterialFingerprint's jwk
// branch plus buildVerifierEvalContext's attestation-context forwarding
// into the direct PDP call (the "Direct PDP path drops trust and
// attestation context" review finding).
func TestEvaluateVerifierTrust_VerifierAttestation_PDPPath(t *testing.T) {
	const (
		subject = "verifier.example.com"
		issuer  = "https://attestation-issuer.example"
	)
	clientID := clientIDSchemeVerifierAttestationPrefix + subject

	cnfKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	requestJWT := buildVerifierAttestationRequestJWT(t, issuer, subject, cnfKey)

	cfg := testConfig()
	cfg.Trust.PDPURL = "http://pdp.test"
	stub := &stubDIDResolver{decisionOk: true, decision: true}
	trustSvc := trust.NewService(cfg, zap.NewNop(),
		func(_ string, _ time.Duration) (trust.TrustEvaluator, error) { return stub, nil })
	trustCache := NewTrustCache(time.Hour)

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
	h := &OID4VPHandler{BaseHandler: BaseHandler{
		Flow: flow, Config: cfg, Logger: zap.NewNop(), TrustSvc: trustSvc, TrustCache: trustCache,
	}}

	authReq := &AuthorizationRequest{
		ClientID:       clientID,
		ClientIDScheme: ClientIDSchemeVerifierAttestation,
		Nonce:          "n",
		ResponseURI:    "https://verifier.example.com/response",
		RequestJWT:     requestJWT,
	}

	verifier, err := h.evaluateVerifierTrust(context.Background(), authReq)
	require.NoError(t, err)
	require.NotNil(t, verifier)
	assert.True(t, verifier.Trusted)
	assert.Equal(t, []string{clientID}, stub.evaluated)
	assert.Equal(t, 1, trustCache.Len(), "a fingerprinted verifier_attestation verdict is cacheable")

	// The PDP call must have received the attestation context the frontend
	// path has always forwarded - not just subject and key material.
	require.NotNil(t, stub.lastContext)
	assert.Equal(t, issuer, stub.lastContext["attestation_issuer"])
	assert.Equal(t, subject, stub.lastContext["attestation_subject"])
	assert.NotEmpty(t, stub.lastContext["attestation_jwt"])
}

// redirect_uri (and other schemes with no scheme-bound signature
// verification) have no verifiedIdentity to key the cache by, so - unlike
// x509_san_dns/x509_hash/verifier_attestation - they fall back to the
// canonical verifier URL rather than being excluded from caching.
func TestEvaluateVerifierTrust_RedirectURIScheme_PDPPath_UsesCanonicalURLCacheKey(t *testing.T) {
	cfg := testConfig()
	cfg.Trust.PDPURL = "http://pdp.test"
	stub := &stubDIDResolver{decisionOk: true, decision: true}
	trustSvc := trust.NewService(cfg, zap.NewNop(),
		func(_ string, _ time.Duration) (trust.TrustEvaluator, error) { return stub, nil })
	trustCache := NewTrustCache(time.Hour)

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
	h := &OID4VPHandler{BaseHandler: BaseHandler{
		Flow: flow, Config: cfg, Logger: zap.NewNop(), TrustSvc: trustSvc, TrustCache: trustCache,
	}}
	authReq := &AuthorizationRequest{
		ClientID:       "https://verifier.example.com",
		ClientIDScheme: ClientIDSchemeRedirectURI,
		Nonce:          "n",
		ResponseURI:    "https://verifier.example.com/response",
		// No RequestJWT/ClientMetadata: redirect_uri's best-effort key
		// material extraction finds nothing, exactly the common case this
		// scheme is meant to still support (resolution-only evaluation).
	}

	verifier, err := h.evaluateVerifierTrust(context.Background(), authReq)
	require.NoError(t, err)
	require.NotNil(t, verifier)
	assert.True(t, verifier.Trusted)
	assert.Equal(t, 1, trustCache.Len())

	// An identical second request (same canonical URL and PDP-relevant
	// context) must hit the same cache entry rather than reaching the PDP
	// again - proving the canonical-URL-based key is being computed
	// consistently, without depending on its exact (now context-hash-
	// suffixed) string form.
	verifier2, err := h.evaluateVerifierTrust(context.Background(), authReq)
	require.NoError(t, err)
	require.NotNil(t, verifier2)
	assert.True(t, verifier2.Trusted)
	assert.Equal(t, 1, trustCache.Len())
	assert.Equal(t, []string{"https://verifier.example.com"}, stub.evaluated,
		"the second, identical request must be served from cache, not the PDP again")
}

// A DID document can list multiple active verification methods (key
// rotation overlap). The PDP evaluates trust against the SPECIFIC key that
// verified a request, so two requests for the same DID signed by two
// DIFFERENT resolved keys must each reach the PDP independently - one
// key's cached verdict must never answer for the other.
func TestEvaluateVerifierTrust_DIDCacheKeyIncludesMatchedKeyFingerprint(t *testing.T) {
	const (
		did      = "did:web:verifier.example"
		clientID = ClientIDSchemeDecentralizedIdentifier + ":" + did
		kidA     = did + "#jwk-a"
		kidB     = did + "#jwk-b"
	)

	keyA, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	keyB, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	stub := &stubDIDResolver{
		didDoc: map[string]interface{}{
			"id": did,
			"verificationMethod": []interface{}{
				map[string]interface{}{
					"id": kidA, "type": "JsonWebKey2020", "controller": did,
					"publicKeyJwk": ecPublicJWK(&keyA.PublicKey, kidA),
				},
				map[string]interface{}{
					"id": kidB, "type": "JsonWebKey2020", "controller": did,
					"publicKeyJwk": ecPublicJWK(&keyB.PublicKey, kidB),
				},
			},
		},
		decisionOk: true,
		decision:   true,
	}

	cfg := testConfig()
	cfg.Trust.PDPURL = "http://pdp.test"
	trustSvc := trust.NewService(cfg, zap.NewNop(),
		func(_ string, _ time.Duration) (trust.TrustEvaluator, error) { return stub, nil })
	trustCache := NewTrustCache(time.Hour)

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
	h := &OID4VPHandler{BaseHandler: BaseHandler{
		Flow: flow, Config: cfg, Logger: zap.NewNop(), TrustSvc: trustSvc, TrustCache: trustCache,
	}}

	reqA := &AuthorizationRequest{
		ClientID: clientID, ClientIDScheme: ClientIDSchemeDecentralizedIdentifier,
		Nonce: "n", ResponseURI: "https://verifier.example/response",
		RequestJWT: buildKidSignedJWT(t, keyA, kidA),
	}
	verifierA, err := h.evaluateVerifierTrust(context.Background(), reqA)
	require.NoError(t, err)
	require.True(t, verifierA.Trusted)
	assert.Equal(t, 1, trustCache.Len())

	reqB := &AuthorizationRequest{
		ClientID: clientID, ClientIDScheme: ClientIDSchemeDecentralizedIdentifier,
		Nonce: "n", ResponseURI: "https://verifier.example/response",
		RequestJWT: buildKidSignedJWT(t, keyB, kidB),
	}
	verifierB, err := h.evaluateVerifierTrust(context.Background(), reqB)
	require.NoError(t, err)
	require.True(t, verifierB.Trusted)

	// Both keys resolve to the same DID, but each must have been
	// independently evaluated by the PDP - key B must not have been served
	// from key A's cache entry.
	assert.Equal(t, []string{did, did}, stub.resolved)
	assert.Equal(t, []string{clientID, clientID}, stub.evaluated)
	assert.Equal(t, 2, trustCache.Len())
}

// The verifier_attestation trust decision depends on the whole attestation
// JWT the PDP validates (signature, issuer chain, expiry, redirect_uris),
// not just the subject/key it asserts. A new attestation JWT can share the
// same subject and cnf key as a previous, already-trusted one - two such
// requests must each reach the PDP independently.
func TestEvaluateVerifierTrust_AttestationCacheKeyIncludesRawJWTHash(t *testing.T) {
	const (
		subject = "verifier.example.com"
		issuer  = "https://attestation-issuer.example"
	)
	clientID := clientIDSchemeVerifierAttestationPrefix + subject

	cnfKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Same issuer/subject/cnf key both times - buildVerifierAttestationRequestJWT
	// signs the (unverified-by-us) attestation JWT itself with a fresh
	// throwaway key each call, so the two raw attestation JWTs differ even
	// though what they assert is identical.
	requestJWT1 := buildVerifierAttestationRequestJWT(t, issuer, subject, cnfKey)
	requestJWT2 := buildVerifierAttestationRequestJWT(t, issuer, subject, cnfKey)
	require.NotEqual(t, requestJWT1, requestJWT2, "test setup: the two request JWTs must actually differ")

	cfg := testConfig()
	cfg.Trust.PDPURL = "http://pdp.test"
	stub := &stubDIDResolver{decisionOk: true, decision: true}
	trustSvc := trust.NewService(cfg, zap.NewNop(),
		func(_ string, _ time.Duration) (trust.TrustEvaluator, error) { return stub, nil })
	trustCache := NewTrustCache(time.Hour)

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
	h := &OID4VPHandler{BaseHandler: BaseHandler{
		Flow: flow, Config: cfg, Logger: zap.NewNop(), TrustSvc: trustSvc, TrustCache: trustCache,
	}}

	authReq1 := &AuthorizationRequest{
		ClientID: clientID, ClientIDScheme: ClientIDSchemeVerifierAttestation,
		Nonce: "n", ResponseURI: "https://verifier.example.com/response",
		RequestJWT: requestJWT1,
	}
	v1, err := h.evaluateVerifierTrust(context.Background(), authReq1)
	require.NoError(t, err)
	require.True(t, v1.Trusted)
	assert.Equal(t, 1, trustCache.Len())

	authReq2 := &AuthorizationRequest{
		ClientID: clientID, ClientIDScheme: ClientIDSchemeVerifierAttestation,
		Nonce: "n", ResponseURI: "https://verifier.example.com/response",
		RequestJWT: requestJWT2,
	}
	v2, err := h.evaluateVerifierTrust(context.Background(), authReq2)
	require.NoError(t, err)
	require.True(t, v2.Trusted)

	// A second, different attestation JWT sharing the same subject and cnf
	// key must still reach the PDP independently - never served from the
	// first attestation's cache entry.
	assert.Equal(t, []string{clientID, clientID}, stub.evaluated)
	assert.Equal(t, 2, trustCache.Len())
}

// The verified identity (a certificate, a matched DID key, an attestation)
// only proves who signed a request - it says nothing about the OTHER
// PDP-relevant context of that request (response_uri/redirect_uri, an OIDF
// trust_chain). The SAME identity presenting a DIFFERENT response_uri must
// reach the PDP independently: a policy may only trust a verifier for a
// specific callback endpoint, and the cache must not let a verdict earned
// for one endpoint answer for another.
func TestEvaluateVerifierTrust_CacheKeyIncludesPDPContext(t *testing.T) {
	requestJWT, _ := makeSignedJWTWithX5C(t) // same certificate both times

	cfg := testConfig()
	cfg.Trust.PDPURL = "http://pdp.test"
	stub := &stubDIDResolver{decisionOk: true, decision: true}
	trustSvc := trust.NewService(cfg, zap.NewNop(),
		func(_ string, _ time.Duration) (trust.TrustEvaluator, error) { return stub, nil })
	trustCache := NewTrustCache(time.Hour)

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
	h := &OID4VPHandler{BaseHandler: BaseHandler{
		Flow: flow, Config: cfg, Logger: zap.NewNop(), TrustSvc: trustSvc, TrustCache: trustCache,
	}}

	baseReq := &AuthorizationRequest{
		ClientID:       "verifier.example.com",
		ClientIDScheme: ClientIDSchemeX509SANDNS,
		Nonce:          "n",
		RequestJWT:     requestJWT,
	}

	req1 := *baseReq
	req1.ResponseURI = "https://verifier.example.com/response-a"
	v1, err := h.evaluateVerifierTrust(context.Background(), &req1)
	require.NoError(t, err)
	require.True(t, v1.Trusted)
	assert.Equal(t, 1, trustCache.Len())

	req2 := *baseReq
	req2.ResponseURI = "https://verifier.example.com/response-b"
	v2, err := h.evaluateVerifierTrust(context.Background(), &req2)
	require.NoError(t, err)
	require.True(t, v2.Trusted)

	// Same certificate, different response_uri: the PDP must be consulted
	// again rather than reusing the first response_uri's cached verdict.
	// (Subject.ID carries the x509_san_dns: prefix per #404.)
	assert.Equal(t, []string{"x509_san_dns:verifier.example.com", "x509_san_dns:verifier.example.com"}, stub.evaluated)
	assert.Equal(t, 2, trustCache.Len())

	// A genuinely identical repeat (same cert, same response_uri) must
	// still hit the cache, proving this isn't simply caching turned off.
	req1Repeat := *baseReq
	req1Repeat.ResponseURI = "https://verifier.example.com/response-a"
	v1Repeat, err := h.evaluateVerifierTrust(context.Background(), &req1Repeat)
	require.NoError(t, err)
	require.True(t, v1Repeat.Trusted)
	assert.Equal(t, []string{"x509_san_dns:verifier.example.com", "x509_san_dns:verifier.example.com"}, stub.evaluated,
		"an identical repeat of the first request must be served from cache")
	assert.Equal(t, 2, trustCache.Len())
}

// For schemes with no scheme-bound signature verification at all (e.g.
// redirect_uri), the cache key falls back to canonicalURL - but
// canonicalURL prioritizes response_uri over client_id, so two unsigned
// requests sharing the same response_uri but claiming DIFFERENT client_ids
// must still reach the PDP independently: the fallback key must include
// client_id explicitly, not rely on canonicalURL alone.
func TestEvaluateVerifierTrust_FallbackCacheKeyIncludesClientID(t *testing.T) {
	cfg := testConfig()
	cfg.Trust.PDPURL = "http://pdp.test"
	stub := &stubDIDResolver{decisionOk: true, decision: true}
	trustSvc := trust.NewService(cfg, zap.NewNop(),
		func(_ string, _ time.Duration) (trust.TrustEvaluator, error) { return stub, nil })
	trustCache := NewTrustCache(time.Hour)

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
	h := &OID4VPHandler{BaseHandler: BaseHandler{
		Flow: flow, Config: cfg, Logger: zap.NewNop(), TrustSvc: trustSvc, TrustCache: trustCache,
	}}

	const sharedResponseURI = "https://shared.example/response"

	req1 := &AuthorizationRequest{
		ClientID:       "https://verifier-a.example.com",
		ClientIDScheme: ClientIDSchemeRedirectURI,
		Nonce:          "n",
		ResponseURI:    sharedResponseURI,
	}
	v1, err := h.evaluateVerifierTrust(context.Background(), req1)
	require.NoError(t, err)
	require.True(t, v1.Trusted)
	assert.Equal(t, 1, trustCache.Len())

	req2 := &AuthorizationRequest{
		ClientID:       "https://verifier-b.example.com",
		ClientIDScheme: ClientIDSchemeRedirectURI,
		Nonce:          "n",
		ResponseURI:    sharedResponseURI,
	}
	v2, err := h.evaluateVerifierTrust(context.Background(), req2)
	require.NoError(t, err)
	require.True(t, v2.Trusted)

	// Same response_uri, different claimed client_id: must not collide on
	// the same cache entry.
	assert.Equal(t, []string{"https://verifier-a.example.com", "https://verifier-b.example.com"}, stub.evaluated)
	assert.Equal(t, 2, trustCache.Len())
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

// --- #396: DID-scheme frontend fallback must set requires_resolution/request_jwt ---

// TestEvaluateVerifierTrust_DIDScheme_NoPDPConfigured_SetsResolutionFlags is
// the regression test for #396, driven end to end through
// evaluateVerifierTrust itself (not evaluateVerifierTrustViaFrontend
// directly - an earlier version of this test bypassed the DID case's own
// control flow, which a Copilot review round on this PR correctly flagged:
// https://github.com/sirosfoundation/go-wallet-backend/pull/401#discussion_r4132050371).
//
// Getting here for real required a second fix alongside the original
// requiresResolution/requestJWT assignments: the DID case used to call
// h.TrustSvc.ResolveDID unconditionally, which always resolves against the
// same h.Config.Trust.GetVerifierPDPURL() the top-level dispatch checks - so
// with no PDP configured, ResolveDID would always fail before the switch
// even finished, and with one configured, dispatch would always choose the
// PDP path instead. Either way, a did: request could never actually reach
// evaluateVerifierTrustViaFrontend. The DID case now checks
// GetVerifierPDPURL() itself and, when empty, skips local resolution
// entirely (mirroring OID4VCIHandler.evaluateTrustViaFrontend, which never
// attempts server-side resolution for a did: issuer either) - so this test
// now drives the real path.
//
// This exercises the OpenID4VP 1.0 final-spec decentralized_identifier:
// prefix specifically (not the "did" scheme, whose client_id is already
// the bare DID with nothing to strip): a third Copilot review round found
// that an earlier version of this test built its client_id as
// ClientIDSchemeDID + ":" + did ("did:did:web:...", a bogus double
// prefix - a copy/paste mistake, not a real wire form) and so never
// actually caught buildVerifierTrustRequest sending the full,
// still-prefixed client_id as SubjectID, when the frontend passes
// SubjectID straight to /v1/resolve when RequiresResolution is true,
// which needs the bare DID
// (https://github.com/sirosfoundation/go-wallet-backend/pull/401#discussion_r4132318509).
//
// A fourth review round then caught that the resulting fix was itself
// only half right: stripping the prefix from SubjectID fixes /v1/resolve
// but breaks /v1/evaluate, which - per docs/client-id-strategy.md - needs
// the ORIGINAL, unstripped client_id (matching evaluateVerifierTrustViaPDP,
// which evaluates authReq.ClientID unchanged); one field can't serve both
// needs. Fixed by leaving SubjectID as the original client_id and adding a
// separate ResolutionSubjectID field carrying the bare DID specifically
// for /v1/resolve
// (https://github.com/sirosfoundation/go-wallet-backend/pull/401#discussion_r4132423915).
// This test now asserts both: the eventual /v1/evaluate subject
// (SubjectID) matches the PDP path's unchanged authReq.ClientID, and the
// /v1/resolve subject (ResolutionSubjectID) gets the bare DID.
func TestEvaluateVerifierTrust_DIDScheme_NoPDPConfigured_SetsResolutionFlags(t *testing.T) {
	const (
		did      = "did:web:verifier.example"
		clientID = ClientIDSchemeDecentralizedIdentifier + ":" + did
	)
	requestJWT := "header.payload.sig"

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

	result, err := json.Marshal(TrustResultPayload{Trusted: true, Framework: "did-frontend-resolved"})
	require.NoError(t, err)
	session.actionCh <- &FlowActionMessage{
		Message: Message{Type: TypeFlowAction, FlowID: flow.ID, Timestamp: Now()},
		Action:  ActionTrustResult,
		Payload: result,
	}

	cfg := testConfig() // no Trust.PDPURL / Verifier.PDPURL set at all
	trustCache := NewTrustCache(time.Hour)
	h := &OID4VPHandler{BaseHandler: BaseHandler{
		Flow: flow, Config: cfg, Logger: zap.NewNop(), TrustCache: trustCache,
	}}
	authReq := &AuthorizationRequest{
		ClientID:       clientID,
		ClientIDScheme: ClientIDSchemeDecentralizedIdentifier,
		Nonce:          "n",
		ResponseURI:    "https://verifier.example/response",
		RequestJWT:     requestJWT,
	}

	verifier, err := h.evaluateVerifierTrust(context.Background(), authReq)
	require.NoError(t, err)
	require.NotNil(t, verifier)
	assert.True(t, verifier.Trusted)

	req := trustEvaluationRequest(t, messages)
	// SubjectID must stay the ORIGINAL, still-prefixed client_id: /v1/evaluate
	// needs the same subject the PDP path evaluates (authReq.ClientID,
	// unchanged - see TestEvaluateVerifierTrust_DecentralizedIdentifier).
	assert.Equal(t, clientID, req.SubjectID, "SubjectID must match the PDP path's unchanged authReq.ClientID - the wire-form client_id, prefix and all")
	// ResolutionSubjectID is the separate field carrying the bare DID
	// /v1/resolve actually needs.
	assert.Equal(t, did, req.ResolutionSubjectID, "ResolutionSubjectID must be the bare DID (with the decentralized_identifier: prefix stripped) - the frontend passes it to /v1/resolve")
	assert.True(t, req.RequiresResolution, "a did:-scheme verifier must ask the frontend to resolve it")
	assert.Equal(t, requestJWT, req.RequestJWT, "the frontend needs the signed request JWT to verify against the resolved DID")
	assert.Nil(t, req.KeyMaterial, "no key material was resolved locally - the frontend resolves it")
	require.NoError(t, req.Validate())

	// A client-asserted verdict from this path must never be cached either
	// (same rule as every other no-PDP frontend-fallback request).
	assert.Zero(t, trustCache.Len())
}

// --- #397: x509_san_uri must get the same mandatory-signature-verification
// and cache-scoping treatment as x509_san_dns/x509_hash ---

func TestEvaluateVerifierTrust_X509SANURI_RequiresSignedRequest(t *testing.T) {
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
	authReq := &AuthorizationRequest{
		ClientID:       "https://verifier.example.com/id",
		ClientIDScheme: ClientIDSchemeX509SANURI,
		Nonce:          "n",
		ResponseURI:    "https://verifier.example.com/response",
	}

	_, err := h.evaluateVerifierTrust(context.Background(), authReq)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "x509_san_uri scheme requires a signed request JWT")
}

// An x509_san_uri request whose JWT signature doesn't verify must fail
// before ever reaching the PDP - the same mandatory-verification-first
// guarantee x509_san_dns/x509_hash already have.
func TestEvaluateVerifierTrust_X509SANURI_InvalidSignature_NeverReachesPDP(t *testing.T) {
	cfg := testConfig()
	cfg.Trust.PDPURL = "http://pdp.test"
	stub := &stubDIDResolver{decisionOk: true, decision: true}
	trustSvc := trust.NewService(cfg, zap.NewNop(),
		func(_ string, _ time.Duration) (trust.TrustEvaluator, error) { return stub, nil })

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
	h := &OID4VPHandler{BaseHandler: BaseHandler{Flow: flow, Config: cfg, Logger: zap.NewNop(), TrustSvc: trustSvc}}
	authReq := &AuthorizationRequest{
		ClientID:       "https://verifier.example.com/id",
		ClientIDScheme: ClientIDSchemeX509SANURI,
		Nonce:          "n",
		ResponseURI:    "https://verifier.example.com/response",
		RequestJWT:     "not-a.valid-signed.jwt",
	}

	_, err := h.evaluateVerifierTrust(context.Background(), authReq)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "x509_san_uri JWT verification failed")
	assert.Empty(t, stub.evaluated, "the PDP must never be consulted for a request whose signature doesn't verify")
}

// A valid x509_san_uri request that the PDP approves (i.e. the certificate's
// SAN URI genuinely matches the claimed identity) must be trusted and its
// verdict cached under a key scoped to this scheme and this specific
// certificate's fingerprint - not the canonicalURL+client_id fallback a
// truly-unsigned scheme like redirect_uri would use.
func TestEvaluateVerifierTrust_X509SANURI_MatchingSAN_TrustedAndCached(t *testing.T) {
	const sanURI = "https://verifier.example.com/id"
	requestJWT, _ := makeSignedJWTWithX5CURISAN(t, sanURI)

	cfg := testConfig()
	cfg.Trust.PDPURL = "http://pdp.test"
	stub := &stubDIDResolver{decisionOk: true, decision: true}
	trustSvc := trust.NewService(cfg, zap.NewNop(),
		func(_ string, _ time.Duration) (trust.TrustEvaluator, error) { return stub, nil })
	trustCache := NewTrustCache(time.Hour)

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
	h := &OID4VPHandler{BaseHandler: BaseHandler{Flow: flow, Config: cfg, Logger: zap.NewNop(), TrustSvc: trustSvc, TrustCache: trustCache}}
	authReq := &AuthorizationRequest{
		ClientID:       sanURI,
		ClientIDScheme: ClientIDSchemeX509SANURI,
		Nonce:          "n",
		ResponseURI:    "https://verifier.example.com/response",
		RequestJWT:     requestJWT,
	}

	verifier, err := h.evaluateVerifierTrust(context.Background(), authReq)
	require.NoError(t, err)
	require.NotNil(t, verifier)
	assert.True(t, verifier.Trusted)
	// The x509_san_uri: prefix must be present in Subject.ID for
	// go-trust's ParseClientIDScheme/VerifyLeafBinding to run (#404).
	assert.Equal(t, []string{"x509_san_uri:" + sanURI}, stub.evaluated)
	require.Equal(t, 1, trustCache.Len())

	// A second request presenting a DIFFERENT certificate but claiming the
	// SAME client_id must reach the PDP again, not reuse this cache entry -
	// same fingerprint-scoping guarantee x509_san_dns has
	// (TestEvaluateVerifierTrust_CacheKeyIncludesCertificateFingerprint).
	requestJWT2, _ := makeSignedJWTWithX5CURISAN(t, sanURI)
	authReq2 := &AuthorizationRequest{
		ClientID:       sanURI,
		ClientIDScheme: ClientIDSchemeX509SANURI,
		Nonce:          "n",
		ResponseURI:    "https://verifier.example.com/response",
		RequestJWT:     requestJWT2,
	}
	verifier2, err := h.evaluateVerifierTrust(context.Background(), authReq2)
	require.NoError(t, err)
	require.NotNil(t, verifier2)
	assert.Equal(t, []string{"x509_san_uri:" + sanURI, "x509_san_uri:" + sanURI}, stub.evaluated,
		"a different certificate claiming the same client_id must be evaluated independently")
	assert.Equal(t, 2, trustCache.Len(), "each certificate gets its own cache entry")
}

// A validly-signed x509_san_uri request whose claimed identity the PDP
// denies (e.g. the certificate's SAN URI does not actually match) must be
// blocked, with no Go error from the evaluator itself.
func TestEvaluateVerifierTrust_X509SANURI_MismatchedSAN_Untrusted(t *testing.T) {
	const sanURI = "https://verifier.example.com/id"
	requestJWT, _ := makeSignedJWTWithX5CURISAN(t, sanURI)

	cfg := testConfig()
	cfg.Trust.PDPURL = "http://pdp.test"
	// decision=false simulates go-trust's PDP rejecting this request because
	// the presented certificate's SAN URI does not match the claimed
	// client_id.
	stub := &stubDIDResolver{decisionOk: true, decision: false}
	trustSvc := trust.NewService(cfg, zap.NewNop(),
		func(_ string, _ time.Duration) (trust.TrustEvaluator, error) { return stub, nil })

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
	h := &OID4VPHandler{BaseHandler: BaseHandler{Flow: flow, Config: cfg, Logger: zap.NewNop(), TrustSvc: trustSvc}}
	authReq := &AuthorizationRequest{
		ClientID:       sanURI,
		ClientIDScheme: ClientIDSchemeX509SANURI,
		Nonce:          "n",
		ResponseURI:    "https://verifier.example.com/response",
		RequestJWT:     requestJWT,
	}

	verifier, err := h.evaluateVerifierTrust(context.Background(), authReq)
	require.Error(t, err)
	assert.Nil(t, verifier)
	assert.Contains(t, err.Error(), "untrusted verifier")
	assert.Equal(t, []string{"x509_san_uri:" + sanURI}, stub.evaluated, "the PDP must still be consulted for a validly-signed request")
}

// --- #398: the trust cache/display must never persist an unvalidated,
// client-supplied display name ---

// A verifier can put anything it likes in client_metadata.client_name - it
// is sent before any trust evaluation runs, and go-trust's PDP response
// carries no validated display name to check it against (see
// pkg/trust/service.go's EvaluationResult: Framework/Reason/Certificates
// only). evaluateVerifierTrust must never show or cache that value: the
// name shown must be the identity the trust decision was actually made
// about (here, the client_id an x509_san_dns request's signature bound to),
// both on the PDP call that first trusts it and on every subsequent cache
// hit for the whole cache TTL.
func TestEvaluateVerifierTrust_DisplayName_IgnoresClientSuppliedName(t *testing.T) {
	const attackerName = "Totally Legit Bank"
	requestJWT, _ := makeSignedJWTWithX5C(t) // client_id "verifier.example.com"

	cfg := testConfig()
	cfg.Trust.PDPURL = "http://pdp.test"
	stub := &stubDIDResolver{decisionOk: true, decision: true}
	trustSvc := trust.NewService(cfg, zap.NewNop(),
		func(_ string, _ time.Duration) (trust.TrustEvaluator, error) { return stub, nil })
	trustCache := NewTrustCache(time.Hour)

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
	h := &OID4VPHandler{BaseHandler: BaseHandler{Flow: flow, Config: cfg, Logger: zap.NewNop(), TrustSvc: trustSvc, TrustCache: trustCache}}
	authReq := &AuthorizationRequest{
		ClientID:       "verifier.example.com",
		ClientIDScheme: ClientIDSchemeX509SANDNS,
		Nonce:          "n",
		ResponseURI:    "https://verifier.example.com/response",
		RequestJWT:     requestJWT,
		ClientMetadata: &ClientMetadata{
			ClientName: attackerName,
			LogoURI:    "https://verifier.example.com/logo.png",
		},
	}

	verifier, err := h.evaluateVerifierTrust(context.Background(), authReq)
	require.NoError(t, err)
	require.NotNil(t, verifier)
	assert.True(t, verifier.Trusted)
	assert.Equal(t, authReq.ClientID, verifier.Name, "the displayed name must be the verified client_id, never the unvalidated client_name")
	assert.NotEqual(t, attackerName, verifier.Name)
	// Unrelated to #398's scope: logo_uri is untouched by this fix.
	require.NotNil(t, verifier.Logo)
	assert.Equal(t, "https://verifier.example.com/logo.png", verifier.Logo.URI)

	// The cached record - what every subsequent request against this exact
	// certificate sees for the rest of the cache TTL - must carry the same
	// safe name, not the attacker-supplied one.
	require.Equal(t, 1, trustCache.Len())
	cached := h.getCachedVerifierTrust(cacheKeyForX509SANDNS(t, authReq, requestJWT))
	require.NotNil(t, cached)
	assert.Equal(t, authReq.ClientID, cached.Name)
	assert.NotEqual(t, attackerName, cached.Name)

	// A second request for the same certificate is served from cache and
	// must still show the safe name, even though this second request's
	// authReq is free to claim any client_name it likes.
	authReq2 := *authReq
	authReq2.ClientMetadata = &ClientMetadata{ClientName: "A Different Attacker Name"}
	verifier2, err := h.evaluateVerifierTrust(context.Background(), &authReq2)
	require.NoError(t, err)
	require.NotNil(t, verifier2)
	assert.Equal(t, authReq.ClientID, verifier2.Name)
	assert.Equal(t, []string{"x509_san_dns:verifier.example.com"}, stub.evaluated, "the second request must be served from cache, not re-evaluated")
}

// --- #406: the no-PDP frontend fallback must not display a
// frontend-asserted name either, consistent with #398's PDP-backed fix ---

// TestEvaluateVerifierTrust_NoPDPFrontendFallback_DisplayName_IgnoresFrontendAssertedName
// is the regression test for #406. evaluateVerifierTrustViaFrontend (the
// permissive no-PDP dev-mode path) still accepted the frontend's
// TrustResultPayload.Name and used it as the displayed verifier.Name -
// unlike the PDP-backed path, which #398 fixed to always show authReq.ClientID
// instead of an unvalidated client_metadata.client_name. This wallet-backend
// has no way to tell a frontend-asserted display name apart from one the
// frontend merely echoed back from the verifier's own unauthenticated
// client_metadata, so it must not be trusted here either, even though the
// Trusted/Framework decision itself genuinely is still accepted from the
// frontend at face value in this intentional, permissive mode.
func TestEvaluateVerifierTrust_NoPDPFrontendFallback_DisplayName_IgnoresFrontendAssertedName(t *testing.T) {
	const frontendAssertedName = "Totally Legit Bank (frontend-asserted)"
	requestJWT, _ := makeSignedJWTWithX5C(t) // client_id "verifier.example.com"

	cfg := testConfig() // no PDP configured at all

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

	result, err := json.Marshal(TrustResultPayload{Trusted: true, Framework: "client-asserted", Name: frontendAssertedName})
	require.NoError(t, err)
	session.actionCh <- &FlowActionMessage{
		Message: Message{Type: TypeFlowAction, FlowID: flow.ID, Timestamp: Now()},
		Action:  ActionTrustResult,
		Payload: result,
	}

	h := &OID4VPHandler{BaseHandler: BaseHandler{Flow: flow, Config: cfg, Logger: zap.NewNop()}}
	authReq := &AuthorizationRequest{
		ClientID:       "verifier.example.com",
		ClientIDScheme: ClientIDSchemeX509SANDNS,
		Nonce:          "n",
		ResponseURI:    "https://verifier.example.com/response",
		RequestJWT:     requestJWT,
	}

	verifier, err := h.evaluateVerifierTrust(context.Background(), authReq)
	require.NoError(t, err)
	require.NotNil(t, verifier)
	assert.True(t, verifier.Trusted, "the frontend's trust decision is still accepted at face value in this permissive mode")
	assert.Equal(t, authReq.ClientID, verifier.Name, "the displayed name must be the verified client_id, never a frontend-asserted name")
	assert.NotEqual(t, frontendAssertedName, verifier.Name)
}

// cacheKeyForX509SANDNS recomputes the cache key evaluateVerifierTrust would
// have used for an x509_san_dns request with the given request JWT, so the
// test above can look the cached entry up directly. Mirrors the
// "x509_san_dns:<client_id>:<fingerprint>|ctx:<hash>" construction in
// evaluateVerifierTrust.
func cacheKeyForX509SANDNS(t *testing.T, authReq *AuthorizationRequest, requestJWT string) string {
	t.Helper()
	km, err := trust.VerifyJWTWithEmbeddedKey(requestJWT)
	require.NoError(t, err)
	fp := keyMaterialFingerprint(km)
	require.NotEmpty(t, fp)
	authCtx := verifierAuthContext{keyMaterial: km}
	ctxHash := hashEvalContext(buildVerifierEvalContext(authReq, authCtx, zap.NewNop()))
	require.NotEmpty(t, ctxHash)
	return "x509_san_dns:" + authReq.ClientID + ":" + fp + "|ctx:" + ctxHash
}
