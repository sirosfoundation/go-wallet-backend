package api

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/service"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage/memory"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
	"github.com/sirosfoundation/go-wallet-backend/pkg/signing"
)

func setupWIATestHandlers(t *testing.T, wiaEnabled bool) (*Handlers, *gin.Engine) {
	t.Helper()
	logger := zap.NewNop()
	cfg := &config.Config{
		Server: config.ServerConfig{
			Host:     "localhost",
			Port:     8080,
			RPID:     "localhost",
			RPOrigin: "http://localhost:8080",
			RPName:   "Test Wallet",
		},
		JWT: config.JWTConfig{
			Secret:      "test-secret-that-is-at-least-32-bytes-long",
			ExpiryHours: 24,
			Issuer:      "test-wallet",
		},
	}
	cfg.WalletProvider.WIA = config.WIAConfig{
		Enabled:             wiaEnabled,
		WalletName:          "Test Wallet",
		WalletVersion:       "1.0.0",
		MaxExpirySeconds:    86400,
		ChallengeTTLSeconds: 300,
	}
	cfg.WalletProvider.Attestation = config.AttestationConfig{
		LifetimeSeconds: 3600,
		StatusListMode:  "never",
	}

	store := memory.NewStore()
	services := service.NewServices(store, cfg, logger)

	// If WIA is enabled but keys aren't configured, inject a test WIA service
	if wiaEnabled && services.WIA == nil {
		privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		certDER, _ := x509.CreateCertificate(rand.Reader, &x509.Certificate{
			SerialNumber: big.NewInt(1),
		}, &x509.Certificate{SerialNumber: big.NewInt(1)}, &privKey.PublicKey, privKey)
		certB64 := base64.StdEncoding.EncodeToString(certDER)
		jwtSigner, _ := signing.NewCryptoSignerES256(privKey)
		services.WIA = service.NewWIAService(cfg, logger, jwtSigner, []string{certB64}, store.WalletInstances(), nil, nil)
	}

	handlers := NewHandlers(services, cfg, logger, []string{"test"})

	router := gin.New()
	return handlers, router
}

func TestWIAChallenge_WIADisabled(t *testing.T) {
	handlers, router := setupWIATestHandlers(t, false)
	router.POST("/wia/challenge", handlers.WIAChallenge)

	req := httptest.NewRequest(http.MethodPost, "/wia/challenge", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", w.Code)
	}

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["error"] != "WIA_NOT_SUPPORTED" {
		t.Errorf("expected WIA_NOT_SUPPORTED error, got %v", resp["error"])
	}
}

func TestWIAGenerate_InvalidBody(t *testing.T) {
	handlers, router := setupWIATestHandlers(t, true)
	router.POST("/wia/generate", handlers.WIAGenerate)

	// Empty body
	req := httptest.NewRequest(http.MethodPost, "/wia/generate", bytes.NewBufferString("{}"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["error"] != "INVALID_REQUEST" {
		t.Errorf("expected INVALID_REQUEST error, got %v", resp["error"])
	}
}

func TestWIAGenerate_ExpiredChallenge(t *testing.T) {
	handlers, router := setupWIATestHandlers(t, true)
	router.POST("/wia/generate", handlers.WIAGenerate)

	// Use a challenge that was never issued
	body := map[string]string{
		"pop":       "dummy.jwt.token",
		"challenge": "nonexistent-challenge",
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/wia/generate", bytes.NewBuffer(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["error"] != "CHALLENGE_EXPIRED" {
		t.Errorf("expected CHALLENGE_EXPIRED error, got %v", resp["error"])
	}
}

func TestWIAChallenge_Success(t *testing.T) {
	handlers, router := setupWIATestHandlers(t, true)
	router.POST("/wia/challenge", handlers.WIAChallenge)

	req := httptest.NewRequest(http.MethodPost, "/wia/challenge", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["challenge"] == nil || resp["challenge"] == "" {
		t.Error("missing challenge in response")
	}
	if resp["expires_at"] == nil {
		t.Error("missing expires_at in response")
	}
}

func TestWIAGenerate_WIADisabled(t *testing.T) {
	handlers, router := setupWIATestHandlers(t, false)
	router.POST("/wia/generate", handlers.WIAGenerate)

	body := map[string]string{
		"pop":       "dummy.jwt.token",
		"challenge": "some-challenge",
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/wia/generate", bytes.NewBuffer(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", w.Code)
	}
}

func TestWIAGenerate_InvalidPopFormat(t *testing.T) {
	handlers, router := setupWIATestHandlers(t, true)
	router.POST("/wia/challenge", handlers.WIAChallenge)
	router.POST("/wia/generate", handlers.WIAGenerate)

	// First get a valid challenge
	req := httptest.NewRequest(http.MethodPost, "/wia/challenge", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	var challengeResp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &challengeResp)
	challenge := challengeResp["challenge"].(string)

	// Use an invalid JWT as PoP
	body := map[string]string{
		"pop":       "not.a.valid-jwt",
		"challenge": challenge,
	}
	bodyBytes, _ := json.Marshal(body)

	req = httptest.NewRequest(http.MethodPost, "/wia/generate", bytes.NewBuffer(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["error"] != "POP_INVALID" {
		t.Errorf("expected POP_INVALID error, got %v", resp["error"])
	}
}
