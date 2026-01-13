package service

import (
	"context"
	"testing"

	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage/memory"
)

func setupPresentationService(t *testing.T) (*PresentationService, storage.Store) {
	logger := zap.NewNop()
	store := memory.NewStore()
	return NewPresentationService(store, logger), store
}

func TestNewPresentationService(t *testing.T) {
	svc, _ := setupPresentationService(t)
	if svc == nil {
		t.Fatal("NewPresentationService() returned nil")
	}
	if svc.store == nil {
		t.Error("PresentationService.store is nil")
	}
}

func TestPresentationService_Store_Success(t *testing.T) {
	svc, _ := setupPresentationService(t)
	ctx := context.Background()

	pres := &domain.VerifiablePresentation{
		HolderDID:              "did:example:holder",
		PresentationIdentifier: "pres-001",
		Presentation:           `{"type": "VerifiablePresentation"}`,
	}

	err := svc.Store(ctx, domain.DefaultTenantID, pres)
	if err != nil {
		t.Fatalf("Store() error = %v", err)
	}

	retrieved, err := svc.Get(ctx, domain.DefaultTenantID, pres.HolderDID, pres.PresentationIdentifier)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}

	if retrieved.HolderDID != pres.HolderDID {
		t.Errorf("Expected HolderDID %q, got %q", pres.HolderDID, retrieved.HolderDID)
	}
}

func TestPresentationService_Store_MissingHolderDID(t *testing.T) {
	svc, _ := setupPresentationService(t)
	ctx := context.Background()

	pres := &domain.VerifiablePresentation{
		HolderDID:              "",
		PresentationIdentifier: "pres-001",
		Presentation:           `{"type": "VerifiablePresentation"}`,
	}

	err := svc.Store(ctx, domain.DefaultTenantID, pres)
	if err == nil {
		t.Error("Expected error for missing holder DID")
	}
}

func TestPresentationService_Store_MissingPresentationIdentifier(t *testing.T) {
	svc, _ := setupPresentationService(t)
	ctx := context.Background()

	pres := &domain.VerifiablePresentation{
		HolderDID:              "did:example:holder",
		PresentationIdentifier: "",
		Presentation:           `{"type": "VerifiablePresentation"}`,
	}

	err := svc.Store(ctx, domain.DefaultTenantID, pres)
	if err == nil {
		t.Error("Expected error for missing presentation identifier")
	}
}

func TestPresentationService_Store_Duplicate(t *testing.T) {
	svc, _ := setupPresentationService(t)
	ctx := context.Background()

	pres := &domain.VerifiablePresentation{
		HolderDID:              "did:example:holder",
		PresentationIdentifier: "pres-001",
		Presentation:           `{"type": "VerifiablePresentation"}`,
	}

	err := svc.Store(ctx, domain.DefaultTenantID, pres)
	if err != nil {
		t.Fatalf("First Store() error = %v", err)
	}

	err = svc.Store(ctx, domain.DefaultTenantID, pres)
	if err == nil {
		t.Error("Expected error for duplicate presentation")
	}
}

func TestPresentationService_Get_NotFound(t *testing.T) {
	svc, _ := setupPresentationService(t)
	ctx := context.Background()

	_, err := svc.Get(ctx, domain.DefaultTenantID, "did:example:holder", "non-existent")
	if err == nil {
		t.Error("Expected error for non-existent presentation")
	}
}

func TestPresentationService_GetAll_Empty(t *testing.T) {
	svc, _ := setupPresentationService(t)
	ctx := context.Background()

	presentations, err := svc.GetAll(ctx, domain.DefaultTenantID, "did:example:holder")
	if err != nil {
		t.Fatalf("GetAll() error = %v", err)
	}

	if len(presentations) != 0 {
		t.Errorf("Expected 0 presentations, got %d", len(presentations))
	}
}

func TestPresentationService_GetAll_MultiplePresentations(t *testing.T) {
	svc, _ := setupPresentationService(t)
	ctx := context.Background()
	holderDID := "did:example:holder"

	for i := 0; i < 3; i++ {
		pres := &domain.VerifiablePresentation{
			HolderDID:              holderDID,
			PresentationIdentifier: "pres-" + string(rune(48+i)),
			Presentation:           `{"type": "VerifiablePresentation"}`,
		}
		if err := svc.Store(ctx, domain.DefaultTenantID, pres); err != nil {
			t.Fatalf("Store() error = %v", err)
		}
	}

	presentations, err := svc.GetAll(ctx, domain.DefaultTenantID, holderDID)
	if err != nil {
		t.Fatalf("GetAll() error = %v", err)
	}

	if len(presentations) != 3 {
		t.Errorf("Expected 3 presentations, got %d", len(presentations))
	}
}

func TestPresentationService_Delete_Success(t *testing.T) {
	svc, _ := setupPresentationService(t)
	ctx := context.Background()

	pres := &domain.VerifiablePresentation{
		HolderDID:              "did:example:holder",
		PresentationIdentifier: "pres-001",
		Presentation:           `{"type": "VerifiablePresentation"}`,
	}

	if err := svc.Store(ctx, domain.DefaultTenantID, pres); err != nil {
		t.Fatalf("Store() error = %v", err)
	}

	err := svc.Delete(ctx, domain.DefaultTenantID, pres.HolderDID, pres.PresentationIdentifier)
	if err != nil {
		t.Fatalf("Delete() error = %v", err)
	}

	_, err = svc.Get(ctx, domain.DefaultTenantID, pres.HolderDID, pres.PresentationIdentifier)
	if err == nil {
		t.Error("Expected error for deleted presentation")
	}
}

func TestPresentationService_Delete_NotFound(t *testing.T) {
	svc, _ := setupPresentationService(t)
	ctx := context.Background()

	err := svc.Delete(ctx, domain.DefaultTenantID, "did:example:holder", "non-existent")
	if err == nil {
		t.Error("Expected error for deleting non-existent presentation")
	}
}

func TestPresentationService_DeleteByCredentialID(t *testing.T) {
	svc, _ := setupPresentationService(t)
	ctx := context.Background()
	holderDID := "did:example:holder"
	credentialID := "cred-123"

	pres1 := &domain.VerifiablePresentation{
		HolderDID:                               holderDID,
		PresentationIdentifier:                  "pres-001",
		Presentation:                            `{"type": "VerifiablePresentation"}`,
		IncludedVerifiableCredentialIdentifiers: []string{credentialID},
	}
	pres2 := &domain.VerifiablePresentation{
		HolderDID:                               holderDID,
		PresentationIdentifier:                  "pres-002",
		Presentation:                            `{"type": "VerifiablePresentation"}`,
		IncludedVerifiableCredentialIdentifiers: []string{"other-cred"},
	}

	if err := svc.Store(ctx, domain.DefaultTenantID, pres1); err != nil {
		t.Fatalf("Store() error = %v", err)
	}
	if err := svc.Store(ctx, domain.DefaultTenantID, pres2); err != nil {
		t.Fatalf("Store() error = %v", err)
	}

	err := svc.DeleteByCredentialID(ctx, domain.DefaultTenantID, holderDID, credentialID)
	if err != nil {
		t.Fatalf("DeleteByCredentialID() error = %v", err)
	}

	_, err = svc.Get(ctx, domain.DefaultTenantID, holderDID, "pres-001")
	if err == nil {
		t.Error("Expected pres-001 to be deleted")
	}

	_, err = svc.Get(ctx, domain.DefaultTenantID, holderDID, "pres-002")
	if err != nil {
		t.Error("Expected pres-002 to still exist")
	}
}
