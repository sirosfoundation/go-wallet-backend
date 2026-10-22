package engine

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	gojose "github.com/go-jose/go-jose/v4"
	gojosejwt "github.com/go-jose/go-jose/v4/jwt"
	"github.com/sirosfoundation/go-tokenauth/claims"
	tokenvalidator "github.com/sirosfoundation/go-tokenauth/validator"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

// Shared helpers for the WMP HTTP tests.

const (
	testSecret = "test-secret-for-wmp"
	// Legacy tokens are only accepted when pinned to jwt.issuer.
	testIssuer = "test-issuer"
)

// The WMP tests authenticate with ES256 session tokens (the legacy HMAC token
// path no longer exists): one process-wide key and JWKS server back every
// testManager and every testToken.
var (
	testKeyOnce sync.Once
	testKey     *ecdsa.PrivateKey
	testJWKSURL string
)

func testSigningKey() *ecdsa.PrivateKey {
	testKeyOnce.Do(func() {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			panic(err)
		}
		testKey = k
		jwks := gojose.JSONWebKeySet{Keys: []gojose.JSONWebKey{{Key: &k.PublicKey, KeyID: "test-key", Algorithm: string(gojose.ES256)}}}
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(jwks)
		}))
		testJWKSURL = srv.URL // lives for the whole test binary
	})
	return testKey
}

func testManager() *Manager {
	cfg := &config.Config{
		JWT: config.JWTConfig{
			Secret: testSecret,
			Issuer: testIssuer,
		},
	}
	m := NewManager(cfg, zap.NewNop())
	testSigningKey()
	m.SetTokenValidator(tokenvalidator.New(tokenvalidator.Config{
		JWKSURL:   testJWKSURL,
		Issuer:    testIssuer,
		Audiences: []string{"wallet-registry", "wallet-backend"},
	}))
	return m
}

// signTestToken signs an ES256 session token expiring at exp.
func signTestToken(userID, tenantID string, exp time.Time) string {
	signer, err := gojose.NewSigner(
		gojose.SigningKey{Algorithm: gojose.ES256, Key: testSigningKey()},
		(&gojose.SignerOptions{}).WithType("JWT").WithHeader("kid", "test-key"),
	)
	if err != nil {
		panic(err)
	}
	now := time.Now()
	cl := claims.AccessTokenClaims{
		Claims: gojosejwt.Claims{
			Issuer:    testIssuer,
			Subject:   userID,
			Audience:  gojosejwt.Audience{"wallet-backend"},
			IssuedAt:  gojosejwt.NewNumericDate(now.Add(-2 * time.Hour)),
			NotBefore: gojosejwt.NewNumericDate(now.Add(-2 * time.Hour)),
			Expiry:    gojosejwt.NewNumericDate(exp),
		},
		TenantID: tenantID,
		TAC:      "ir", // every permission the engine gates on
		ACR:      "urn:siros:acr:passkey",
	}
	raw, err := gojosejwt.Signed(signer).Claims(cl).Serialize()
	if err != nil {
		panic(err)
	}
	return raw
}

func testToken(userID, tenantID string) string {
	return signTestToken(userID, tenantID, time.Now().Add(time.Hour))
}

func expiredToken(userID string) string {
	return signTestToken(userID, "", time.Now().Add(-time.Hour))
}

// --- HandleRPC tests ---

func TestWriteBodyReadError_Generic400(t *testing.T) {
	w := httptest.NewRecorder()
	writeBodyReadError(w, errors.New("boom"))
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// testBearerToken stands in for middleware.ExtractBearerToken (which the
// engine package cannot import: pkg/middleware depends on the engine).
func testBearerToken(r *http.Request) string {
	_, tok, _ := strings.Cut(r.Header.Get("Authorization"), " ")
	return strings.TrimSpace(tok)
}
