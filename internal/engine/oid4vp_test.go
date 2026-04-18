package engine

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
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

func TestBuildDCAPIResponse(t *testing.T) {
	h := &OID4VPHandler{}

	t.Run("basic dc_api response", func(t *testing.T) {
		authReq := &AuthorizationRequest{
			ResponseMode: "dc_api",
			State:        "test-state-123",
			PresentationDefinition: &PresentationDefinition{
				ID: "pd-1",
				InputDescriptors: []InputDescriptor{
					{ID: "id-card"},
				},
			},
		}

		result, err := h.buildDCAPIResponse(authReq, "eyJ.vp_token.sig")
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Empty(t, result.redirectURI, "dc_api should not produce a redirect URI")
		require.NotNil(t, result.vpResponse)

		assert.Equal(t, "eyJ.vp_token.sig", result.vpResponse["vp_token"])
		assert.Equal(t, "test-state-123", result.vpResponse["state"])

		// Verify presentation_submission is valid JSON string
		submissionStr, ok := result.vpResponse["presentation_submission"].(string)
		require.True(t, ok, "presentation_submission should be a JSON string")
		var submission map[string]interface{}
		err = json.Unmarshal([]byte(submissionStr), &submission)
		require.NoError(t, err)
		assert.Equal(t, "pd-1_submission", submission["id"])
		assert.Equal(t, "pd-1", submission["definition_id"])
	})

	t.Run("dc_api without state", func(t *testing.T) {
		authReq := &AuthorizationRequest{
			ResponseMode: "dc_api",
			PresentationDefinition: &PresentationDefinition{
				ID: "pd-2",
				InputDescriptors: []InputDescriptor{
					{ID: "diploma"},
				},
			},
		}

		result, err := h.buildDCAPIResponse(authReq, "vp-token-data")
		require.NoError(t, err)
		require.NotNil(t, result.vpResponse)
		assert.Equal(t, "vp-token-data", result.vpResponse["vp_token"])
		_, hasState := result.vpResponse["state"]
		assert.False(t, hasState, "state should not be set when empty")
	})

	t.Run("dc_api without presentation_definition", func(t *testing.T) {
		authReq := &AuthorizationRequest{
			ResponseMode: "dc_api",
			State:        "s1",
		}

		result, err := h.buildDCAPIResponse(authReq, "vp-token")
		require.NoError(t, err)
		require.NotNil(t, result.vpResponse)
		assert.Equal(t, "vp-token", result.vpResponse["vp_token"])
		_, hasSubmission := result.vpResponse["presentation_submission"]
		assert.False(t, hasSubmission, "no presentation_submission without presentation_definition")
	})
}

func TestBuildPresentationSubmission(t *testing.T) {
	h := &OID4VPHandler{}

	t.Run("multiple input descriptors", func(t *testing.T) {
		pd := &PresentationDefinition{
			ID: "multi-pd",
			InputDescriptors: []InputDescriptor{
				{ID: "id-card"},
				{ID: "diploma"},
				{ID: "employment"},
			},
		}
		submission := h.buildPresentationSubmission(pd)
		require.NotNil(t, submission)
		assert.Equal(t, "multi-pd_submission", submission["id"])
		assert.Equal(t, "multi-pd", submission["definition_id"])
		descriptors := submission["descriptor_map"].([]map[string]interface{})
		assert.Len(t, descriptors, 3)
		assert.Equal(t, "id-card", descriptors[0]["id"])
		assert.Equal(t, "diploma", descriptors[1]["id"])
	})

	t.Run("nil presentation definition", func(t *testing.T) {
		submission := h.buildPresentationSubmission(nil)
		assert.Nil(t, submission)
	})
}
