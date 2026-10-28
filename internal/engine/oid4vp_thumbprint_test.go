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
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// The verifier_jwk_thumbprint feeds the OpenID4VPHandover transcript, so it
// must be the RFC 7638 thumbprint of the very key the client encrypts to
// (response_encryption.jwk) in the same sign_request. Both are derived from
// extractVerifierEncryptionJWK; this guards against them drifting apart.
func TestRequestVPSignature_ThumbprintMatchesResponseEncryptionKey(t *testing.T) {
	sigKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	encKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "verifier"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &sigKey.PublicKey, sigKey)
	require.NoError(t, err)
	hdr, err := json.Marshal(map[string]any{"alg": "ES256", "x5c": []string{base64.StdEncoding.EncodeToString(certDER)}})
	require.NoError(t, err)
	x5cJWT := base64.RawURLEncoding.EncodeToString(hdr) + ".e30.sig"

	// The signing key comes first in the set so that picking the wrong entry
	// changes the thumbprint.
	jwks := makeJWKS(
		jose.JSONWebKey{Key: &sigKey.PublicKey, KeyID: "sig", Use: "sig"},
		jose.JSONWebKey{Key: &encKey.PublicKey, KeyID: "enc", Use: "enc"},
	)

	thumb := func(k *ecdsa.PublicKey) string {
		b, err := (&jose.JSONWebKey{Key: k}).Thumbprint(crypto.SHA256)
		require.NoError(t, err)
		return base64.RawURLEncoding.EncodeToString(b)
	}

	cases := []struct {
		name    string
		req     *AuthorizationRequest
		wantKey *ecdsa.PublicKey
	}{
		{"client_metadata.jwks use=enc", &AuthorizationRequest{ClientMetadata: &ClientMetadata{JWKS: jwks}}, &encKey.PublicKey},
		{"request JWT x5c", &AuthorizationRequest{RequestJWT: x5cJWT}, &sigKey.PublicKey},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, _, received, cleanup := newSelectionTestHandler(t)
			defer cleanup()
			ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
			defer cancel()
			tc.req.ResponseMode = ResponseModeDirectPostJWT
			tc.req.ClientID = "x"
			_, _ = h.requestVPSignature(ctx, tc.req, []ConsentSelection{{CredentialID: "c", CredentialQueryID: "q"}}, "")

			msg := awaitMessage(t, received, "sign_request")
			params, _ := msg["params"].(map[string]any)
			got, _ := params["verifier_jwk_thumbprint"].(string)
			require.NotEmpty(t, got)
			assert.NotContains(t, got, "=", "unpadded")

			re, ok := params["response_encryption"].(map[string]any)
			require.True(t, ok, "params: %v", params)
			raw, err := json.Marshal(re["jwk"])
			require.NoError(t, err)
			var sent jose.JSONWebKey
			require.NoError(t, sent.UnmarshalJSON(raw))
			sb, err := sent.Thumbprint(crypto.SHA256)
			require.NoError(t, err)

			assert.Equal(t, base64.RawURLEncoding.EncodeToString(sb), got, "thumbprint of response_encryption.jwk")
			assert.Equal(t, thumb(tc.wantKey), got, "thumbprint of the expected verifier key")
		})
	}
}

// The engine never sets the JWE protected-header cty (the client builds the
// JWE) and validateResponseJWE neither requires nor rejects it.
func TestValidateResponseJWE_CtyIsNeitherRequiredNorRejected(t *testing.T) {
	_, jwks := ecJWKS(t, "kid-1")
	h := &OID4VPHandler{BaseHandler: BaseHandler{Logger: zap.NewNop()}}
	want, err := h.resolveResponseEncryption(&AuthorizationRequest{ClientMetadata: &ClientMetadata{JWKS: jwks}})
	require.NoError(t, err)

	var params map[string]any
	b, _ := json.Marshal(SignRequestParams{ResponseEncryption: want})
	require.NoError(t, json.Unmarshal(b, &params))
	seg := strings.Split(clientEncryptJARM(t, params, "aud", blindSentinel), ".")
	withHeader := func(h string) string {
		return strings.Join([]string{base64.RawURLEncoding.EncodeToString([]byte(h)), seg[1], seg[2], seg[3], seg[4]}, ".")
	}
	assert.NoError(t, validateResponseJWE(withHeader(`{"alg":"ECDH-ES","enc":"A128GCM","kid":"kid-1"}`), want), "no cty")
	assert.NoError(t, validateResponseJWE(withHeader(`{"alg":"ECDH-ES","enc":"A128GCM","kid":"kid-1","cty":"JWT"}`), want), "cty JWT")
}
