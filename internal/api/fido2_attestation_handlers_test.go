package api

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/service"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage/memory"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
	"github.com/sirosfoundation/go-wallet-backend/pkg/trust"
)

// stubFIDO2TrustEvaluator is a minimal trust.TrustEvaluator returning a
// fixed decision, mirroring the one used at the service layer (see
// internal/service/fido2_attestation_test.go) so these handler tests can
// exercise the full HTTP-to-verification pipeline without a real go-trust
// deployment.
type stubFIDO2TrustEvaluator struct{ decision bool }

func (s *stubFIDO2TrustEvaluator) Evaluate(_ context.Context, _ *trust.EvaluationRequest) (*trust.EvaluationResponse, error) {
	return &trust.EvaluationResponse{Decision: s.decision}, nil
}
func (s *stubFIDO2TrustEvaluator) Name() string { return "stub" }
func (s *stubFIDO2TrustEvaluator) SupportedResourceTypes() []trust.ResourceType {
	return []trust.ResourceType{trust.ResourceTypeX5C}
}
func (s *stubFIDO2TrustEvaluator) Healthy() bool { return true }

func setupFIDO2AttestationTestHandlers(t *testing.T, enabled bool, trustDecision bool) (*Handlers, *gin.Engine) {
	t.Helper()
	logger := zap.NewNop()
	cfg := &config.Config{}
	cfg.WalletProvider.Attestation.FIDO2Attestation = config.FIDO2AttestationConfig{Enabled: enabled}
	cfg.Trust.PDPURL = "http://pdp.invalid"

	store := memory.NewStore()
	trustSvc := trust.NewService(cfg, logger, func(endpoint string, timeout time.Duration) (trust.TrustEvaluator, error) {
		return &stubFIDO2TrustEvaluator{decision: trustDecision}, nil
	})
	fido2Svc := service.NewFIDO2AttestationService(cfg, store.WalletInstances(), trustSvc, logger)

	services := &service.Services{FIDO2Attestation: fido2Svc}
	handlers := NewHandlers(services, cfg, logger, []string{"test"})

	router := gin.New()
	router.POST("/wallet-provider/fido2-attestation/register", handlers.FIDO2AttestationRegister)
	return handlers, router
}

// buildFIDO2TestAttestationObject constructs a fully valid, self-contained
// "packed" Basic Attestation object - same construction as
// internal/service/fido2_attestation_test.go's buildTestAttestationObject,
// duplicated here since test helpers aren't exported across packages.
func buildFIDO2TestAttestationObject(t *testing.T, aaguid uuid.UUID, clientDataHash []byte) []byte {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Country:            []string{"US"},
			Organization:       []string{"Test Org"},
			OrganizationalUnit: []string{"Authenticator Attestation"},
			CommonName:         "test-authenticator",
		},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(time.Hour),
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, leafTmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create leaf cert: %v", err)
	}

	coseKey := webauthncose.EC2PublicKeyData{
		PublicKeyData: webauthncose.PublicKeyData{KeyType: 2, Algorithm: -7},
		Curve:         1,
		XCoord:        key.PublicKey.X.FillBytes(make([]byte, 32)),
		YCoord:        key.PublicKey.Y.FillBytes(make([]byte, 32)),
	}
	coseKeyBytes, err := webauthncbor.Marshal(coseKey)
	if err != nil {
		t.Fatalf("marshal COSE key: %v", err)
	}

	rpIDHash := sha256.Sum256([]byte("test-rp"))
	credentialID := []byte("test-credential-id")

	authData := make([]byte, 0, 128)
	authData = append(authData, rpIDHash[:]...)
	authData = append(authData, 0x40)
	authData = binary.BigEndian.AppendUint32(authData, 1)
	authData = append(authData, aaguid[:]...)
	authData = binary.BigEndian.AppendUint16(authData, uint16(len(credentialID)))
	authData = append(authData, credentialID...)
	authData = append(authData, coseKeyBytes...)

	signedData := append(append([]byte{}, authData...), clientDataHash...)
	digest := sha256.Sum256(signedData)
	sig, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	attObj := map[string]interface{}{
		"fmt": "packed",
		"attStmt": map[string]interface{}{
			"alg": int64(-7),
			"sig": sig,
			"x5c": []interface{}{leafDER},
		},
		"authData": authData,
	}
	attObjBytes, err := webauthncbor.Marshal(attObj)
	if err != nil {
		t.Fatalf("marshal attestation object: %v", err)
	}
	return attObjBytes
}

func doFIDO2AttestationRequest(router *gin.Engine, body interface{}) *httptest.ResponseRecorder {
	var buf bytes.Buffer
	_ = json.NewEncoder(&buf).Encode(body)
	req := httptest.NewRequest(http.MethodPost, "/wallet-provider/fido2-attestation/register", &buf)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

func TestFIDO2AttestationRegister_Disabled(t *testing.T) {
	_, router := setupFIDO2AttestationTestHandlers(t, false, true)

	w := doFIDO2AttestationRequest(router, map[string]string{
		"wallet_instance_id": "inst-1",
		"attestation_object": "AQ",
		"client_data_hash":   base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
	})

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", w.Code)
	}
	var resp map[string]interface{}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["error"] != "FIDO2_ATTESTATION_NOT_SUPPORTED" {
		t.Errorf("error = %v, want FIDO2_ATTESTATION_NOT_SUPPORTED", resp["error"])
	}
}

func TestFIDO2AttestationRegister_MissingFields(t *testing.T) {
	_, router := setupFIDO2AttestationTestHandlers(t, true, true)

	w := doFIDO2AttestationRequest(router, map[string]string{
		"wallet_instance_id": "inst-1",
		// attestation_object and client_data_hash omitted
	})

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
	var resp map[string]interface{}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["error"] != "INVALID_REQUEST" {
		t.Errorf("error = %v, want INVALID_REQUEST", resp["error"])
	}
}

func TestFIDO2AttestationRegister_InvalidAttestationObjectBase64(t *testing.T) {
	_, router := setupFIDO2AttestationTestHandlers(t, true, true)

	w := doFIDO2AttestationRequest(router, map[string]string{
		"wallet_instance_id": "inst-1",
		"attestation_object": "not-valid-base64url!!!",
		"client_data_hash":   base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
	})

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
	var resp map[string]interface{}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["error"] != "INVALID_ATTESTATION_OBJECT" {
		t.Errorf("error = %v, want INVALID_ATTESTATION_OBJECT", resp["error"])
	}
}

func TestFIDO2AttestationRegister_InvalidClientDataHashBase64(t *testing.T) {
	_, router := setupFIDO2AttestationTestHandlers(t, true, true)

	w := doFIDO2AttestationRequest(router, map[string]string{
		"wallet_instance_id": "inst-1",
		"attestation_object": base64.RawURLEncoding.EncodeToString([]byte{0x01}),
		"client_data_hash":   "not-valid-base64url!!!",
	})

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
	var resp map[string]interface{}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["error"] != "INVALID_CLIENT_DATA_HASH" {
		t.Errorf("error = %v, want INVALID_CLIENT_DATA_HASH", resp["error"])
	}
}

func TestFIDO2AttestationRegister_VerificationFailed(t *testing.T) {
	_, router := setupFIDO2AttestationTestHandlers(t, true, true)

	// Well-formed base64url, but not valid CBOR - Verify will fail with
	// ErrFIDO2AttestationInvalid.
	w := doFIDO2AttestationRequest(router, map[string]string{
		"wallet_instance_id": "inst-1",
		"attestation_object": base64.RawURLEncoding.EncodeToString([]byte("not cbor at all")),
		"client_data_hash":   base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
	})

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
	var resp map[string]interface{}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["error"] != "ATTESTATION_INVALID" {
		t.Errorf("error = %v, want ATTESTATION_INVALID", resp["error"])
	}
}

func TestFIDO2AttestationRegister_Success(t *testing.T) {
	instanceID := "inst-fido2-success"

	// Seed the wallet instance the attestation will be recorded against,
	// then wire handlers to a service backed by that same store.
	store := memory.NewStore()
	if err := store.WalletInstances().Upsert(context.Background(), &domain.WalletInstance{ID: instanceID}); err != nil {
		t.Fatalf("seed instance: %v", err)
	}
	cfg := &config.Config{}
	cfg.WalletProvider.Attestation.FIDO2Attestation = config.FIDO2AttestationConfig{Enabled: true}
	cfg.Trust.PDPURL = "http://pdp.invalid"
	logger := zap.NewNop()
	trustSvc := trust.NewService(cfg, logger, func(endpoint string, timeout time.Duration) (trust.TrustEvaluator, error) {
		return &stubFIDO2TrustEvaluator{decision: true}, nil
	})
	fido2Svc := service.NewFIDO2AttestationService(cfg, store.WalletInstances(), trustSvc, logger)
	handlers := NewHandlers(&service.Services{FIDO2Attestation: fido2Svc}, cfg, logger, []string{"test"})
	router := gin.New()
	router.POST("/wallet-provider/fido2-attestation/register", handlers.FIDO2AttestationRegister)

	aaguid := uuid.New()
	clientDataHash := make([]byte, 32)
	attObj := buildFIDO2TestAttestationObject(t, aaguid, clientDataHash)

	w := doFIDO2AttestationRequest(router, map[string]string{
		"wallet_instance_id": instanceID,
		"attestation_object": base64.RawURLEncoding.EncodeToString(attObj),
		"client_data_hash":   base64.RawURLEncoding.EncodeToString(clientDataHash),
	})

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", w.Code, w.Body.String())
	}
	var resp map[string]interface{}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["verified"] != true {
		t.Errorf("verified = %v, want true", resp["verified"])
	}

	got, err := store.WalletInstances().GetByID(context.Background(), instanceID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if !got.HardwareKeyAttested {
		t.Error("expected HardwareKeyAttested = true after a successful registration")
	}
}
