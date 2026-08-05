package service

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/go-jose/go-jose/v4"

	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

func TestRegisterWalletProviderJWKSRoute_Success(t *testing.T) {
	svc := newTestWalletProviderService(t)

	gin.SetMode(gin.TestMode)
	r := gin.New()
	RegisterWalletProviderJWKSRoute(r, svc)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}
	if got := w.Header().Get("Cache-Control"); got != "public, max-age=300" {
		t.Errorf("Cache-Control = %q, want %q", got, "public, max-age=300")
	}

	var jwks jose.JSONWebKeySet
	if err := json.Unmarshal(w.Body.Bytes(), &jwks); err != nil {
		t.Fatalf("unmarshal jwks: %v", err)
	}
	if len(jwks.Keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(jwks.Keys))
	}
	key := jwks.Keys[0]
	if key.KeyID != "wallet-provider" {
		t.Errorf("KeyID = %q, want %q", key.KeyID, "wallet-provider")
	}
	if key.Algorithm != string(jose.ES256) {
		t.Errorf("Algorithm = %q, want %q", key.Algorithm, jose.ES256)
	}
	if key.Use != "sig" {
		t.Errorf("Use = %q, want %q", key.Use, "sig")
	}
}

func TestRegisterWalletProviderJWKSRoute_OAuthMetadata(t *testing.T) {
	svc := newTestWalletProviderService(t)
	svc.cfg.WalletProvider.WIA.Issuer = "https://wallet-provider.example.com"

	gin.SetMode(gin.TestMode)
	r := gin.New()
	RegisterWalletProviderJWKSRoute(r, svc)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}
	if got := w.Header().Get("Cache-Control"); got != "public, max-age=300" {
		t.Errorf("Cache-Control = %q, want %q", got, "public, max-age=300")
	}

	var meta struct {
		Issuer  string `json:"issuer"`
		JWKSURI string `json:"jwks_uri"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &meta); err != nil {
		t.Fatalf("unmarshal metadata: %v", err)
	}
	if meta.Issuer != "https://wallet-provider.example.com" {
		t.Errorf("issuer = %q, want %q", meta.Issuer, "https://wallet-provider.example.com")
	}
	if want := meta.Issuer + "/.well-known/jwks.json"; meta.JWKSURI != want {
		t.Errorf("jwks_uri = %q, want %q", meta.JWKSURI, want)
	}
}

func TestRegisterWalletProviderJWKSRoute_OAuthMetadata_FallsBackToWalletProviderURI(t *testing.T) {
	svc := newTestWalletProviderService(t)
	svc.cfg.WalletProvider.WIA.WalletProviderURI = "https://fallback.example.com"

	gin.SetMode(gin.TestMode)
	r := gin.New()
	RegisterWalletProviderJWKSRoute(r, svc)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var meta struct {
		Issuer string `json:"issuer"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &meta); err != nil {
		t.Fatalf("unmarshal metadata: %v", err)
	}
	if meta.Issuer != "https://fallback.example.com" {
		t.Errorf("issuer = %q, want %q", meta.Issuer, "https://fallback.example.com")
	}
}

func TestRegisterWalletProviderJWKSRoute_OAuthMetadata_NoOpWhenNoIssuerConfigured(t *testing.T) {
	svc := newTestWalletProviderService(t)
	// Neither WIA.Issuer nor WIA.WalletProviderURI set.

	gin.SetMode(gin.TestMode)
	r := gin.New()
	RegisterWalletProviderJWKSRoute(r, svc)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d (route should not be registered)", w.Code, http.StatusNotFound)
	}
}

func TestRegisterWalletProviderJWKSRoute_NoOpWhenNoSigningKey(t *testing.T) {
	svc := &WalletProviderService{
		cfg: &config.Config{},
		// No signer configured.
	}

	gin.SetMode(gin.TestMode)
	r := gin.New()
	RegisterWalletProviderJWKSRoute(r, svc)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d (route should not be registered)", w.Code, http.StatusNotFound)
	}
}

func TestRegisterWalletProviderJWKSRoute_NoOpWhenNilService(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	RegisterWalletProviderJWKSRoute(r, nil)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d (route should not be registered)", w.Code, http.StatusNotFound)
	}
}
