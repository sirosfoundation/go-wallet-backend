package service

import (
	"context"
	"testing"

	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/storage/memory"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
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

func TestFIDO2AttestationService_Disabled(t *testing.T) {
	cfg := testFIDO2AttestationConfig(false)
	instances := memory.NewStore().WalletInstances()
	svc := NewFIDO2AttestationService(cfg, instances, zap.NewNop())

	err := svc.Verify(context.Background(), &FIDO2AttestationRequest{
		WalletInstanceID:  "test-instance",
		AttestationObject: []byte{0x01},
		ClientDataHash:    make([]byte, 32),
	})
	if err != ErrFIDO2AttestationDisabled {
		t.Errorf("err = %v, want ErrFIDO2AttestationDisabled", err)
	}
}

func TestFIDO2AttestationService_EmptyWalletInstanceID(t *testing.T) {
	cfg := testFIDO2AttestationConfig(true)
	instances := memory.NewStore().WalletInstances()
	svc := NewFIDO2AttestationService(cfg, instances, zap.NewNop())

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
	instances := memory.NewStore().WalletInstances()
	svc := NewFIDO2AttestationService(cfg, instances, zap.NewNop())

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
	instances := memory.NewStore().WalletInstances()
	svc := NewFIDO2AttestationService(cfg, instances, zap.NewNop())

	err := svc.Verify(context.Background(), &FIDO2AttestationRequest{
		WalletInstanceID:  "test-instance",
		AttestationObject: []byte("not cbor at all"),
		ClientDataHash:    make([]byte, 32),
	})
	if err == nil {
		t.Fatal("expected error for invalid CBOR attestation object")
	}
}

// TestYubiKeyAttestationRootCAs_NotEmpty mirrors
// TestAppleAppAttestRootCAs_NotEmpty - confirms the embedded PEMs parse.
// The real x5c-chain-to-trusted-root happy path can only be meaningfully
// exercised against a real captured YubiKey attestation object (see the
// FIDO2 hardware-attestation trust plan's Phase 2) - same limitation the
// existing Apple App Attest tests already accept for their own real root.
func TestYubiKeyAttestationRootCAs_NotEmpty(t *testing.T) {
	pool := YubiKeyAttestationRootCAs()
	if pool == nil {
		t.Fatal("YubiKeyAttestationRootCAs returned nil")
	}
	// x509.CertPool doesn't expose a count directly pre-1.19-ish reflection
	// tricks; Subjects() (deprecated but still functional) is good enough
	// for a sanity check that both embedded certs actually parsed.
	subjects := pool.Subjects() //nolint:staticcheck // sanity check only
	if len(subjects) != 2 {
		t.Errorf("expected 2 root CAs in pool, got %d", len(subjects))
	}
}
