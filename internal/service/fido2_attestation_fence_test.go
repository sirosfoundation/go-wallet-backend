package service

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage/memory"
)

// A store failure is a server error, not an invalid attestation.
type failingMarkAttested struct{ storage.KeyAttestationStore }

func (failingMarkAttested) MarkKeyAttested(context.Context, *domain.KeyAttestationRecord) error {
	return storage.ErrDatabase
}

func TestFIDO2AttestationService_Verify_StoreFailureIsNotAnInvalidAttestation(t *testing.T) {
	ctx := context.Background()
	store := memory.NewStore()
	if err := store.WalletInstances().Upsert(ctx, &domain.WalletInstance{ID: "inst", Status: domain.InstanceStatusActive}); err != nil {
		t.Fatal(err)
	}
	svc := NewFIDO2AttestationService(testFIDO2AttestationConfig(true), store.WalletInstances(),
		failingMarkAttested{store.KeyAttestations()}, newTestTrustService(t, &stubEvaluator{decision: true}), zap.NewNop())
	clientDataHash := make([]byte, 32)
	attObj, _ := buildTestAttestationObject(t, uuid.New(), clientDataHash)

	err := svc.Verify(ctx, &FIDO2AttestationRequest{WalletInstanceID: "inst", AttestationObject: attObj, ClientDataHash: clientDataHash})
	if !errors.Is(err, storage.ErrDatabase) || errors.Is(err, ErrFIDO2AttestationInvalid) {
		t.Fatalf("Verify = %v, want a storage error that is not ErrFIDO2AttestationInvalid", err)
	}
}
