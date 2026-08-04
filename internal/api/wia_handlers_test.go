package api

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
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

// fakeWIAChallengeStore is a configurable service.WIAChallengeStore used to
// drive WIAChallenge/WIAGenerate down error branches that the real in-memory
// store can't easily produce (capacity exceeded without filling 10k entries,
// or an arbitrary backing-store failure).
type fakeWIAChallengeStore struct {
	putOK      bool
	putErr     error
	consumeOK  bool
	consumeErr error
}

func (f *fakeWIAChallengeStore) Put(_ context.Context, _ string, _ time.Time) (bool, error) {
	return f.putOK, f.putErr
}

func (f *fakeWIAChallengeStore) Consume(_ context.Context, _ string) (bool, error) {
	return f.consumeOK, f.consumeErr
}

func (f *fakeWIAChallengeStore) Len(_ context.Context) (int, error) {
	return 0, nil
}

// setupWIAHandlersWithChallengeStore builds handlers backed by a WIA service
// that uses the given challenge store, so tests can force store-level error
// conditions on the challenge/generate endpoints.
func setupWIAHandlersWithChallengeStore(t *testing.T, cs service.WIAChallengeStore) (*Handlers, *gin.Engine) {
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
	}
	cfg.WalletProvider.WIA = config.WIAConfig{
		Enabled:             true,
		WalletName:          "Test Wallet",
		MaxExpirySeconds:    86400,
		ChallengeTTLSeconds: 300,
	}
	cfg.WalletProvider.Attestation = config.AttestationConfig{
		LifetimeSeconds: 3600,
		StatusListMode:  "never",
	}

	store := memory.NewStore()
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(1),
	}, &x509.Certificate{SerialNumber: big.NewInt(1)}, &privKey.PublicKey, privKey)
	if err != nil {
		t.Fatal(err)
	}
	certB64 := base64.StdEncoding.EncodeToString(certDER)
	jwtSigner, err := signing.NewCryptoSignerES256(privKey)
	if err != nil {
		t.Fatal(err)
	}

	services := &service.Services{
		WIA: service.NewWIAService(cfg, logger, jwtSigner, []string{certB64}, store.WalletInstances(), nil, cs),
	}
	handlers := NewHandlers(services, cfg, logger, []string{"test"})

	router := gin.New()
	return handlers, router
}

func TestWIAChallenge_CapacityExceeded(t *testing.T) {
	handlers, router := setupWIAHandlersWithChallengeStore(t, &fakeWIAChallengeStore{putOK: false})
	router.POST("/wia/challenge", handlers.WIAChallenge)

	req := httptest.NewRequest(http.MethodPost, "/wia/challenge", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["error"] != "RATE_LIMIT_EXCEEDED" {
		t.Errorf("expected RATE_LIMIT_EXCEEDED error, got %v", resp["error"])
	}
}

func TestWIAChallenge_StoreError(t *testing.T) {
	handlers, router := setupWIAHandlersWithChallengeStore(t, &fakeWIAChallengeStore{putErr: errors.New("store unavailable")})
	router.POST("/wia/challenge", handlers.WIAChallenge)

	req := httptest.NewRequest(http.MethodPost, "/wia/challenge", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["error"] != "CHALLENGE_CREATION_FAILED" {
		t.Errorf("expected CHALLENGE_CREATION_FAILED error, got %v", resp["error"])
	}
}

func TestWIAGenerate_GenericServiceError(t *testing.T) {
	// A challenge-store failure during consumeChallenge surfaces as a plain
	// error that is neither ErrWIAChallengeExpired nor ErrWIAPopInvalid, so
	// WIAGenerate must fall through to the generic 500 branch.
	handlers, router := setupWIAHandlersWithChallengeStore(t, &fakeWIAChallengeStore{consumeErr: errors.New("store unavailable")})
	router.POST("/wia/generate", handlers.WIAGenerate)

	body := map[string]string{
		"pop":       "dummy.jwt.token",
		"challenge": "whatever",
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/wia/generate", bytes.NewBuffer(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["error"] != "WIA_GENERATION_FAILED" {
		t.Errorf("expected WIA_GENERATION_FAILED error, got %v", resp["error"])
	}
}

func TestWIAGenerate_Success(t *testing.T) {
	handlers, router := setupWIATestHandlers(t, true)
	router.POST("/wia/challenge", handlers.WIAChallenge)
	router.POST("/wia/generate", handlers.WIAGenerate)

	// Obtain a real challenge from the handler.
	req := httptest.NewRequest(http.MethodPost, "/wia/challenge", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("challenge request failed: %d: %s", w.Code, w.Body.String())
	}
	var challengeResp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &challengeResp); err != nil {
		t.Fatal(err)
	}
	challenge, _ := challengeResp["challenge"].(string)
	if challenge == "" {
		t.Fatal("missing challenge")
	}

	// Build a valid WIA-PoP JWT bound to that challenge.
	instanceKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	xBytes := instanceKey.PublicKey.X.Bytes()
	yBytes := instanceKey.PublicKey.Y.Bytes()
	for len(xBytes) < 32 {
		xBytes = append([]byte{0}, xBytes...)
	}
	for len(yBytes) < 32 {
		yBytes = append([]byte{0}, yBytes...)
	}
	jwk := map[string]interface{}{
		"kty": "EC",
		"crv": "P-256",
		"x":   base64.RawURLEncoding.EncodeToString(xBytes),
		"y":   base64.RawURLEncoding.EncodeToString(yBytes),
	}
	claims := &service.WIAPopClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "urn:wallet:instance:handler-test",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
		Nonce: challenge,
	}
	popToken := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	popToken.Header["typ"] = "oauth-client-attestation-pop+jwt"
	popToken.Header["jwk"] = jwk
	pop, err := popToken.SignedString(instanceKey)
	if err != nil {
		t.Fatal(err)
	}

	body := map[string]string{
		"pop":       pop,
		"challenge": challenge,
	}
	bodyBytes, _ := json.Marshal(body)

	req = httptest.NewRequest(http.MethodPost, "/wia/generate", bytes.NewBuffer(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	wia, _ := resp["wallet_instance_attestation"].(string)
	if wia == "" {
		t.Error("missing wallet_instance_attestation in response")
	}
}
