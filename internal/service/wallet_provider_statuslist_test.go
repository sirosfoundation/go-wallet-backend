package service

import (
	"bytes"
	"compress/flate"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"

	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
	"github.com/sirosfoundation/go-wallet-backend/pkg/signing"
)

func TestRegisterWalletProviderStatusListRoute_NoOpWithoutSigner(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	RegisterWalletProviderStatusListRoute(router, nil)
	RegisterWalletProviderStatusListRoute(router, &WalletProviderService{})

	req := httptest.NewRequest(http.MethodGet, "/wallet-provider/status-list", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404 (route should not be registered)", rec.Code)
	}
}

// TestRegisterWalletProviderStatusListRoute_ServesAllValidList verifies the
// endpoint serves a well-formed, always-empty (all-VALID) Token Status List
// JWT — see RegisterWalletProviderStatusListRoute's doc comment: nothing this
// wallet provider issues references it, this is interop completeness only.
func TestRegisterWalletProviderStatusListRoute_ServesAllValidList(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwtSigner, err := signing.NewCryptoSignerES256(privKey)
	if err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{}
	cfg.Server.BaseURL = "https://wp.example.com"
	wp := &WalletProviderService{cfg: cfg, jwtSigner: jwtSigner}

	gin.SetMode(gin.TestMode)
	router := gin.New()
	RegisterWalletProviderStatusListRoute(router, wp)

	req := httptest.NewRequest(http.MethodGet, "/wallet-provider/status-list", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/statuslist+jwt" {
		t.Errorf("Content-Type = %q, want application/statuslist+jwt", ct)
	}

	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	token, _, err := parser.ParseUnverified(rec.Body.String(), jwt.MapClaims{})
	if err != nil {
		t.Fatalf("response is not a parseable JWT: %v", err)
	}
	if token.Header["typ"] != "statuslist+jwt" {
		t.Errorf("typ = %v, want statuslist+jwt", token.Header["typ"])
	}

	claims := token.Claims.(jwt.MapClaims)
	sl, ok := claims["status_list"].(map[string]interface{})
	if !ok {
		t.Fatal("status_list claim missing")
	}
	lstStr, ok := sl["lst"].(string)
	if !ok {
		t.Fatal("status_list.lst missing or not a string")
	}

	compressed, err := base64.RawURLEncoding.DecodeString(lstStr)
	if err != nil {
		t.Fatalf("lst is not valid base64url: %v", err)
	}
	r := flate.NewReader(bytes.NewReader(compressed))
	defer r.Close()
	raw, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("lst does not decompress: %v", err)
	}
	for i, b := range raw {
		if b != 0 {
			t.Errorf("byte %d = %#x, want 0 (every status must be VALID)", i, b)
		}
	}
}
