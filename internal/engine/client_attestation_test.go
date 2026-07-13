package engine

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestComputeJWKThumbprint(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tp1, err := computeJWKThumbprint(&key.PublicKey)
	require.NoError(t, err)
	assert.NotEmpty(t, tp1)

	// Same key should produce same thumbprint
	tp2, err := computeJWKThumbprint(&key.PublicKey)
	require.NoError(t, err)
	assert.Equal(t, tp1, tp2)

	// Different key should produce different thumbprint
	key2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tp3, err := computeJWKThumbprint(&key2.PublicKey)
	require.NoError(t, err)
	assert.NotEqual(t, tp1, tp3)
}

func TestCreateAttestationPoP(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	signer := NewECDSAPoPSigner(key)

	clientID := "test-client-id"
	audience := "https://as.example.com"

	popJWT, err := createAttestationPoP(signer, clientID, audience)
	require.NoError(t, err)
	assert.NotEmpty(t, popJWT)

	// Parse and validate
	token, err := jwt.Parse(popJWT, func(t *jwt.Token) (interface{}, error) {
		return &key.PublicKey, nil
	}, jwt.WithValidMethods([]string{"ES256"}))
	require.NoError(t, err)
	assert.True(t, token.Valid)

	// Check typ header
	assert.Equal(t, "oauth-client-attestation-pop+jwt", token.Header["typ"])

	// Check jwk header is present
	jwk, ok := token.Header["jwk"].(map[string]interface{})
	assert.True(t, ok)
	assert.Equal(t, "EC", jwk["kty"])
	assert.Equal(t, "P-256", jwk["crv"])

	// Check claims
	claims, ok := token.Claims.(jwt.MapClaims)
	require.True(t, ok)
	assert.Equal(t, clientID, claims["iss"])
	assert.Contains(t, claims["aud"], audience)
	assert.NotEmpty(t, claims["jti"])
	assert.NotNil(t, claims["exp"])
	assert.NotNil(t, claims["iat"])
}

func TestPreSuppliedAttestation_Available(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	signer := NewECDSAPoPSigner(key)

	// nil provider
	var p *PreSuppliedAttestation
	assert.False(t, p.Available())

	// Empty WIA
	p = &PreSuppliedAttestation{Signer: signer, ID: "test"}
	assert.False(t, p.Available())

	// Complete
	p = &PreSuppliedAttestation{WIA: "test.wia.jwt", Signer: signer, ID: "test"}
	assert.True(t, p.Available())
}

func TestPreSuppliedAttestation_SetHeaders(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	signer := NewECDSAPoPSigner(key)
	tp, _ := computeJWKThumbprint(&key.PublicKey)

	provider := &PreSuppliedAttestation{
		WIA:    "eyJ0eXAiOiJvYXV0aC1jbGllbnQtYXR0ZXN0YXRpb24rand0In0.test.sig",
		Signer: signer,
		ID:     tp,
	}

	req, _ := http.NewRequest("POST", "https://as.example.com/token", nil)
	err := provider.SetHeaders(context.Background(), req, "https://as.example.com")
	require.NoError(t, err)

	// Verify headers are set
	assert.Equal(t, provider.WIA, req.Header.Get("OAuth-Client-Attestation"))
	assert.NotEmpty(t, req.Header.Get("OAuth-Client-Attestation-PoP"))

	// Verify PoP is a valid JWT signed by the instance key
	popJWT := req.Header.Get("OAuth-Client-Attestation-PoP")
	token, err := jwt.Parse(popJWT, func(t *jwt.Token) (interface{}, error) {
		return &key.PublicKey, nil
	}, jwt.WithValidMethods([]string{"ES256"}))
	require.NoError(t, err)
	assert.True(t, token.Valid)
	assert.Equal(t, "oauth-client-attestation-pop+jwt", token.Header["typ"])

	// Verify aud in PoP
	claims, _ := token.Claims.(jwt.MapClaims)
	assert.Contains(t, claims["aud"], "https://as.example.com")
}

func TestServerSideAttestation_Available(t *testing.T) {
	var s *ServerSideAttestation
	assert.False(t, s.Available())

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	signer := NewECDSAPoPSigner(key)
	s = &ServerSideAttestation{WIA: "wia.jwt", Signer: signer, ID: "id"}
	assert.True(t, s.Available())
}
