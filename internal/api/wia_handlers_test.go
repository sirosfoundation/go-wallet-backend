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
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/service"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage/memory"
	"github.com/sirosfoundation/go-wallet-backend/internal/tokengate"
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
			Secret: "test-secret-that-is-at-least-32-bytes-long",
			Issuer: "test-wallet",
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
		services.WIA = service.NewWIAService(cfg, logger, jwtSigner, []string{certB64}, store.WalletInstances(), store.Users(), nil, nil)
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
	if resp["error"] != "CHALLENGE_INVALID" {
		t.Errorf("expected CHALLENGE_INVALID error, got %v", resp["error"])
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

// kaVerifier is a key_attestation verifier test double.
type kaVerifier struct{ err error }

func (kaVerifier) Type() service.KeyAttestationType { return "android_key" }
func (v kaVerifier) Verify(context.Context, *service.InstanceKeyEvidenceInput) (*service.InstanceKeyEvidenceResult, error) {
	return &service.InstanceKeyEvidenceResult{}, v.err
}

func postWIAGenerate(t *testing.T, h *Handlers, router *gin.Engine, keyAttestation string) *httptest.ResponseRecorder {
	t.Helper()
	router.POST("/wia/generate", h.WIAGenerate)
	challenge, _, err := h.services.WIA.CreateChallenge(context.Background(), "default")
	if err != nil {
		t.Fatal(err)
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"iss": "urn:wallet:instance:t", "nonce": challenge,
		"iat": time.Now().Unix(), "exp": time.Now().Add(time.Minute).Unix(),
	})
	tok.Header["typ"] = "oauth-client-attestation-pop+jwt"
	tok.Header["jwk"] = map[string]any{
		"kty": "EC", "crv": "P-256",
		"x": base64.RawURLEncoding.EncodeToString(key.PublicKey.X.FillBytes(make([]byte, 32))),
		"y": base64.RawURLEncoding.EncodeToString(key.PublicKey.Y.FillBytes(make([]byte, 32))),
	}
	pop, err := tok.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	body := `{"pop":"` + pop + `","challenge":"` + challenge + `"` + keyAttestation + `}`
	req := httptest.NewRequest(http.MethodPost, "/wia/generate", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

func errCode(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	var resp map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	s, _ := resp["error"].(string)
	return s
}

func TestWIAGenerate_KeyAttestationErrorsMapToStatuses(t *testing.T) {
	for _, tc := range []struct {
		name   string
		ka     string
		err    error
		status int
		code   string
	}{
		{"unknown type", `,"key_attestation":{"type":"nope"}`, nil, http.StatusBadRequest, "KEY_ATTESTATION_TYPE_UNSUPPORTED"},
		{"missing type", `,"key_attestation":{}`, nil, http.StatusBadRequest, "KEY_ATTESTATION_TYPE_UNSUPPORTED"},
		{"invalid", `,"key_attestation":{"type":"android_key"}`, service.ErrWIAKeyAttestationInvalid, http.StatusBadRequest, "KEY_ATTESTATION_INVALID"},
		{"unavailable", `,"key_attestation":{"type":"android_key"}`, service.ErrWIAKeyAttestationUnavailable, http.StatusServiceUnavailable, "KEY_ATTESTATION_UNAVAILABLE"},
		{"valid, no home", `,"key_attestation":{"type":"android_key"}`, nil, http.StatusOK, ""},
		{"absent", ``, nil, http.StatusOK, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, router := setupWIATestHandlers(t, true)
			h.services.WIA.RegisterInstanceKeyVerifier(kaVerifier{err: tc.err})
			w := postWIAGenerate(t, h, router, tc.ka)
			if w.Code != tc.status || errCode(t, w) != tc.code {
				t.Fatalf("status %d code %q body %s", w.Code, errCode(t, w), w.Body.String())
			}
		})
	}
}

type nqVerifier struct{ reason string }

func (nqVerifier) Type() service.KeyAttestationType { return service.KeyAttestationAndroidKey }
func (v nqVerifier) Verify(context.Context, *service.InstanceKeyEvidenceInput) (*service.InstanceKeyEvidenceResult, error) {
	return nil, &service.KeyAttestationNotQualifyingError{Reason: v.reason}
}

// A reject-mode refusal is 400 KEY_ATTESTATION_NOT_QUALIFYING with the reason
// enum in details and nothing else from the evidence.
func TestWIAGenerate_NotQualifyingCarriesOnlyTheReasonEnum(t *testing.T) {
	for _, reason := range append(append([]string{}, service.NoHomeReasons...), "free text <script> from an evidence") {
		t.Run(reason, func(t *testing.T) {
			h, router := setupWIATestHandlers(t, true)
			h.services.WIA.RegisterInstanceKeyVerifier(nqVerifier{reason: reason})
			w := postWIAGenerate(t, h, router, `,"key_attestation":{"type":"android_key"}`)
			if w.Code != http.StatusBadRequest || errCode(t, w) != "KEY_ATTESTATION_NOT_QUALIFYING" {
				t.Fatalf("status %d body %s", w.Code, w.Body.String())
			}
			var resp struct {
				Details map[string]string `json:"details"`
				Message string            `json:"message"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
				t.Fatal(err)
			}
			want := reason
			if !strings.Contains(strings.Join(service.NoHomeReasons, ","), reason) {
				want = "other"
			}
			if len(resp.Details) != 1 || resp.Details["reason"] != want {
				t.Fatalf("details = %v, want reason %q", resp.Details, want)
			}
			if strings.Contains(w.Body.String(), "script") {
				t.Fatalf("evidence text leaked: %s", w.Body.String())
			}
		})
	}
}

// WIA refusals are a stable client contract: each service error keeps its status
// and code; an unknown error is 500.
func TestWIAFailure_MapsEveryServiceRefusal(t *testing.T) {
	cases := []struct {
		err    error
		status int
		code   string
	}{
		{service.ErrWIAChallengeExpired, http.StatusBadRequest, "CHALLENGE_INVALID"},
		{service.ErrWIACredentialNotOwned, http.StatusForbidden, "CREDENTIAL_NOT_OWNED"},
		{service.ErrWIAPopInvalid, http.StatusBadRequest, "POP_INVALID"},
		{tokengate.ErrRevoked, http.StatusUnauthorized, "TOKEN_REVOKED"},
		{service.ErrWIAUnknownUser, http.StatusForbidden, "UNKNOWN_USER"},
		{service.ErrWIAInstanceDeactivated, http.StatusForbidden, "INSTANCE_DEACTIVATED"},
		{service.ErrWIAInstanceNotOwned, http.StatusForbidden, "INSTANCE_NOT_OWNED"},
		{service.ErrWIARefusedByPolicy, http.StatusForbidden, "WIA_REFUSED_BY_POLICY"},
		{service.ErrAssuranceUnavailable, http.StatusServiceUnavailable, "ASSURANCE_UNAVAILABLE"},
		{service.ErrWIANativeAttestationUnavailable, http.StatusServiceUnavailable, "NATIVE_ATTESTATION_UNAVAILABLE"},
		{service.ErrWIAKeyAttestationTypeUnsupported, http.StatusBadRequest, "KEY_ATTESTATION_TYPE_UNSUPPORTED"},
		{service.ErrWIAKeyAttestationNotQualifying, http.StatusBadRequest, "KEY_ATTESTATION_NOT_QUALIFYING"},
		{service.ErrWIAKeyAttestationInvalid, http.StatusBadRequest, "KEY_ATTESTATION_INVALID"},
		{service.ErrWIAKeyAttestationUnavailable, http.StatusServiceUnavailable, "KEY_ATTESTATION_UNAVAILABLE"},
		{fmt.Errorf("wrapped: %w", service.ErrWIAInstanceDeactivated), http.StatusForbidden, "INSTANCE_DEACTIVATED"},
		{errors.New("storage exploded"), http.StatusInternalServerError, "WIA_GENERATION_FAILED"},
	}
	for _, tc := range cases {
		status, code, message := wiaFailure(tc.err)
		if status != tc.status || code != tc.code || message == "" {
			t.Errorf("wiaFailure(%v) = %d %s %q, want %d %s", tc.err, status, code, message, tc.status, tc.code)
		}
	}
}
