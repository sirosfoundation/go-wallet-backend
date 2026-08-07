package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage/memory"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
	"github.com/sirosfoundation/go-wallet-backend/pkg/jwk"
	"github.com/sirosfoundation/go-wallet-backend/pkg/trust"
)

func testFIDO2AttestationConfig(enabled bool) *config.Config {
	return &config.Config{
		WalletProvider: config.WalletProviderConfig{
			Attestation: config.AttestationConfig{
				FIDO2Attestation: config.FIDO2AttestationConfig{
					Enabled: enabled,
				},
			},
		},
	}
}

// stubEvaluator is a minimal trust.TrustEvaluator returning a fixed decision,
// used to test FIDO2AttestationService's AuthZEN wiring in isolation from a
// real go-trust/fidomds3 deployment (that registry's own trust-anchor logic
// is tested directly in go-trust's pkg/registry/fidomds3 package).
type stubEvaluator struct {
	decision      bool
	reason        string
	gotSubjectID  string
	gotResourceID string
	gotKeyType    trust.ResourceType
	gotAction     string
}

func (s *stubEvaluator) Evaluate(ctx context.Context, req *trust.EvaluationRequest) (*trust.EvaluationResponse, error) {
	s.gotSubjectID = req.GetSubjectID()
	s.gotResourceID = req.Resource.ID
	s.gotKeyType = req.GetKeyType()
	s.gotAction = req.GetAction()
	return &trust.EvaluationResponse{Decision: s.decision, Reason: s.reason}, nil
}
func (s *stubEvaluator) Name() string { return "stub" }
func (s *stubEvaluator) SupportedResourceTypes() []trust.ResourceType {
	return []trust.ResourceType{trust.ResourceTypeX5C}
}
func (s *stubEvaluator) Healthy() bool { return true }

func newTestTrustService(t *testing.T, eval *stubEvaluator) *trust.Service {
	t.Helper()
	cfg := &config.Config{}
	cfg.Trust.PDPURL = "http://pdp.invalid" // any non-empty value - factory below ignores it
	return trust.NewService(cfg, zap.NewNop(), func(endpoint string, timeout time.Duration) (trust.TrustEvaluator, error) {
		return eval, nil
	})
}

func TestFIDO2AttestationService_Disabled(t *testing.T) {
	cfg := testFIDO2AttestationConfig(false)
	store := memory.NewStore()
	svc := NewFIDO2AttestationService(cfg, store.WalletInstances(), store.KeyAttestations(), nil, zap.NewNop())

	err := svc.Verify(context.Background(), &FIDO2AttestationRequest{
		WalletInstanceID:  "test-instance",
		AttestationObject: []byte{0x01},
		ClientDataHash:    make([]byte, 32),
	})
	if err != ErrFIDO2AttestationDisabled {
		t.Errorf("err = %v, want ErrFIDO2AttestationDisabled", err)
	}
}

func TestFIDO2AttestationService_NilRequest(t *testing.T) {
	cfg := testFIDO2AttestationConfig(true)
	store := memory.NewStore()
	svc := NewFIDO2AttestationService(cfg, store.WalletInstances(), store.KeyAttestations(), nil, zap.NewNop())

	err := svc.Verify(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error for nil request, got nil")
	}
}

func TestFIDO2AttestationService_EmptyWalletInstanceID(t *testing.T) {
	cfg := testFIDO2AttestationConfig(true)
	store := memory.NewStore()
	svc := NewFIDO2AttestationService(cfg, store.WalletInstances(), store.KeyAttestations(), nil, zap.NewNop())

	err := svc.Verify(context.Background(), &FIDO2AttestationRequest{
		WalletInstanceID:  "",
		AttestationObject: []byte{0x01},
		ClientDataHash:    make([]byte, 32),
	})
	if err == nil {
		t.Fatal("expected error for empty wallet_instance_id")
	}
}

func TestFIDO2AttestationService_WrongClientDataHashLength(t *testing.T) {
	cfg := testFIDO2AttestationConfig(true)
	store := memory.NewStore()
	svc := NewFIDO2AttestationService(cfg, store.WalletInstances(), store.KeyAttestations(), nil, zap.NewNop())

	err := svc.Verify(context.Background(), &FIDO2AttestationRequest{
		WalletInstanceID:  "test-instance",
		AttestationObject: []byte{0x01},
		ClientDataHash:    []byte{0x01, 0x02}, // not 32 bytes
	})
	if err == nil {
		t.Fatal("expected error for wrong-length client_data_hash")
	}
}

func TestFIDO2AttestationService_InvalidCBOR(t *testing.T) {
	cfg := testFIDO2AttestationConfig(true)
	store := memory.NewStore()
	svc := NewFIDO2AttestationService(cfg, store.WalletInstances(), store.KeyAttestations(), nil, zap.NewNop())

	err := svc.Verify(context.Background(), &FIDO2AttestationRequest{
		WalletInstanceID:  "test-instance",
		AttestationObject: []byte("not cbor at all"),
		ClientDataHash:    make([]byte, 32),
	})
	if err == nil {
		t.Fatal("expected error for invalid CBOR attestation object")
	}
}

// buildTestAttestationObject constructs a fully valid, self-contained
// "packed" Basic Attestation object: a real EC P-256 keypair, a real
// self-signed x5c leaf cert for it, real authData bytes (with the given
// AAGUID), and a real ES256 signature over authData||clientDataHash - the
// same shape go-webauthn's own attestationFormatValidationHandlerPacked
// verifies. Used to exercise FIDO2AttestationService.Verify's full pipeline
// (CBOR decode, signature verification, AAGUID extraction, AuthZEN call)
// without needing a real YubiKey - the actual "is this AAGUID/chain
// trusted" decision is provided by a stub PDP, not real MDS3 data (that's
// covered by go-trust's own pkg/registry/fidomds3 tests).
func buildTestAttestationObject(t *testing.T, aaguid uuid.UUID, clientDataHash []byte) ([]byte, *ecdsa.PublicKey) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	// Per WebAuthn §8.2.1 (Packed Attestation Certificate Requirements),
	// the attestation cert must have Country/Organization set, an
	// OrganizationalUnit literally "Authenticator Attestation", and a
	// non-empty CommonName - all enforced by go-webauthn's
	// handleBasicAttestation.
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
		PublicKeyData: webauthncose.PublicKeyData{KeyType: 2, Algorithm: -7}, // EC2, ES256
		Curve:         1,                                                     // P-256
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
	authData = append(authData, 0x40) // flags: AT (attested credential data present)
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
	return attObjBytes, &key.PublicKey
}

// expectedThumbprint computes the same RFC 7638 JWK Thumbprint
// FIDO2AttestationService.Verify derives from an attestation object's
// embedded credential public key, so tests can assert the service stored
// evidence under the key the test actually used.
func expectedThumbprint(t *testing.T, pub *ecdsa.PublicKey) string {
	t.Helper()
	tp, err := jwk.Thumbprint(map[string]interface{}{
		"kty": "EC",
		"crv": "P-256",
		"x":   base64.RawURLEncoding.EncodeToString(pub.X.FillBytes(make([]byte, 32))),
		"y":   base64.RawURLEncoding.EncodeToString(pub.Y.FillBytes(make([]byte, 32))),
	})
	if err != nil {
		t.Fatalf("compute expected thumbprint: %v", err)
	}
	return tp
}

func TestFIDO2AttestationService_TrustedByPDP(t *testing.T) {
	cfg := testFIDO2AttestationConfig(true)
	store := memory.NewStore()
	if err := store.WalletInstances().Upsert(context.Background(), &domain.WalletInstance{ID: "test-instance"}); err != nil {
		t.Fatalf("seed instance: %v", err)
	}

	eval := &stubEvaluator{decision: true}
	trustSvc := newTestTrustService(t, eval)
	svc := NewFIDO2AttestationService(cfg, store.WalletInstances(), store.KeyAttestations(), trustSvc, zap.NewNop())

	aaguid := uuid.New()
	clientDataHash := make([]byte, 32)
	attObj, pub := buildTestAttestationObject(t, aaguid, clientDataHash)

	err := svc.Verify(context.Background(), &FIDO2AttestationRequest{
		WalletInstanceID:  "test-instance",
		AttestationObject: attObj,
		ClientDataHash:    clientDataHash,
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}

	if eval.gotSubjectID != aaguid.String() {
		t.Errorf("PDP request subject.id = %q, want %q (the AAGUID)", eval.gotSubjectID, aaguid.String())
	}
	if eval.gotKeyType != trust.ResourceTypeX5C {
		t.Errorf("PDP request resource.type = %q, want x5c", eval.gotKeyType)
	}
	if eval.gotAction != trust.FIDO2AttestationAction {
		t.Errorf("PDP request action.name = %q, want %q (so an operator can attach a dedicated go-trust policy to this call site)", eval.gotAction, trust.FIDO2AttestationAction)
	}

	// Evidence must be stored keyed by the attested CREDENTIAL key's own
	// thumbprint (not the wallet instance) - this is the regression test
	// for the bug where an instance-level flag incorrectly applied one
	// key's evidence to unrelated keys.
	thumbprint := expectedThumbprint(t, pub)
	rec, err := store.KeyAttestations().GetByKeyThumbprint(context.Background(), thumbprint)
	if err != nil {
		t.Fatalf("expected a stored key attestation record for the attested key, got: %v", err)
	}
	if rec.WalletInstanceID != "test-instance" {
		t.Errorf("rec.WalletInstanceID = %q, want %q", rec.WalletInstanceID, "test-instance")
	}
	if rec.AAGUID != aaguid.String() {
		t.Errorf("rec.AAGUID = %q, want %q", rec.AAGUID, aaguid.String())
	}
}

func TestFIDO2AttestationService_NotTrustedByPDP(t *testing.T) {
	cfg := testFIDO2AttestationConfig(true)
	store := memory.NewStore()
	if err := store.WalletInstances().Upsert(context.Background(), &domain.WalletInstance{ID: "test-instance"}); err != nil {
		t.Fatalf("seed instance: %v", err)
	}

	eval := &stubEvaluator{decision: false, reason: "no MDS3 entry for AAGUID"}
	trustSvc := newTestTrustService(t, eval)
	svc := NewFIDO2AttestationService(cfg, store.WalletInstances(), store.KeyAttestations(), trustSvc, zap.NewNop())

	aaguid := uuid.New()
	clientDataHash := make([]byte, 32)
	attObj, pub := buildTestAttestationObject(t, aaguid, clientDataHash)

	err := svc.Verify(context.Background(), &FIDO2AttestationRequest{
		WalletInstanceID:  "test-instance",
		AttestationObject: attObj,
		ClientDataHash:    clientDataHash,
	})
	if err == nil {
		t.Fatal("expected error when the PDP denies trust")
	}

	thumbprint := expectedThumbprint(t, pub)
	if _, getErr := store.KeyAttestations().GetByKeyThumbprint(context.Background(), thumbprint); !errors.Is(getErr, storage.ErrNotFound) {
		t.Errorf("expected no stored key attestation record when the PDP denies trust, got err=%v", getErr)
	}
}
