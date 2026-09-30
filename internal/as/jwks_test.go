package as

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJWKSHandler(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	dir := t.TempDir()
	path := writeKeyPEM(t, dir, "ec.pem", key, "EC PRIVATE KEY")

	km, err := NewKeyManager(path)
	require.NoError(t, err)

	gin.SetMode(gin.TestMode)
	r := gin.New()
	RegisterJWKSRoute(r, km)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/.well-known/jwks.json", nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "public, max-age=300", w.Header().Get("Cache-Control"))

	var jwks jose.JSONWebKeySet
	err = json.Unmarshal(w.Body.Bytes(), &jwks)
	require.NoError(t, err)

	require.Len(t, jwks.Keys, 1)
	assert.Equal(t, km.ActiveKey().Kid, jwks.Keys[0].KeyID)
	assert.Equal(t, string(jose.ES256), jwks.Keys[0].Algorithm)
	assert.Equal(t, "sig", jwks.Keys[0].Use)
}

func TestJWKSHandler_MultipleKeys(t *testing.T) {
	key1, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	dir := t.TempDir()
	path := writeKeyPEM(t, dir, "ec.pem", key1, "EC PRIVATE KEY")

	km, err := NewKeyManager(path)
	require.NoError(t, err)

	key2, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	sk2, err := newSigningKey(key2)
	require.NoError(t, err)

	km.AddKey(sk2, false)

	gin.SetMode(gin.TestMode)
	r := gin.New()
	RegisterJWKSRoute(r, km)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/.well-known/jwks.json", nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var jwks jose.JSONWebKeySet
	err = json.Unmarshal(w.Body.Bytes(), &jwks)
	require.NoError(t, err)

	assert.Len(t, jwks.Keys, 2)
}
