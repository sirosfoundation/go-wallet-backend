package service

import (
	"context"
	"testing"

	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage/memory"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

func setupCredentialService(t *testing.T) *CredentialService {
	logger := zap.NewNop()
	cfg := &config.Config{
		JWT: config.JWTConfig{
			Secret:      "test-secret",
			ExpiryHours: 24,
		},
	}
	store := memory.NewStore()
	return NewCredentialService(store, cfg, logger)
}

func TestCredentialService_Store_Success(t *testing.T) {
	svc := setupCredentialService(t)
	ctx := context.Background()
	tenantID := domain.DefaultTenantID

	req := &domain.StoreCredentialRequest{
		HolderDID:            "did:example:holder",
		CredentialIdentifier: "cred-001",
		Credential:           `{"type": "VerifiableCredential"}`,
		Format:               domain.FormatJWTVC,
	}

	cred, err := svc.Store(ctx, tenantID, req)
	if err != nil {
		t.Fatalf("Store() error = %v", err)
	}

	if cred.HolderDID != req.HolderDID {
		t.Errorf("Expected HolderDID %q, got %q", req.HolderDID, cred.HolderDID)
	}
	if cred.CredentialIdentifier != req.CredentialIdentifier {
		t.Errorf("Expected CredentialIdentifier %q, got %q", req.CredentialIdentifier, cred.CredentialIdentifier)
	}
}

func TestCredentialService_Store_MissingHolderDID(t *testing.T) {
	svc := setupCredentialService(t)
	ctx := context.Background()
	tenantID := domain.DefaultTenantID

	req := &domain.StoreCredentialRequest{
		HolderDID:            "",
		CredentialIdentifier: "cred-001",
		Credential:           `{"type": "VerifiableCredential"}`,
		Format:               domain.FormatJWTVC,
	}

	_, err := svc.Store(ctx, tenantID, req)
	if err == nil {
		t.Error("Expected error for missing holder_did")
	}
}

func TestCredentialService_Store_MissingCredentialIdentifier(t *testing.T) {
	svc := setupCredentialService(t)
	ctx := context.Background()

	req := &domain.StoreCredentialRequest{
		HolderDID:            "did:example:holder",
		CredentialIdentifier: "",
		Credential:           `{"type": "VerifiableCredential"}`,
		Format:               domain.FormatJWTVC,
	}

	_, err := svc.Store(ctx, domain.DefaultTenantID, req)
	if err == nil {
		t.Error("Expected error for missing credential_identifier")
	}
}

func TestCredentialService_Store_MissingCredential(t *testing.T) {
	svc := setupCredentialService(t)
	ctx := context.Background()

	req := &domain.StoreCredentialRequest{
		HolderDID:            "did:example:holder",
		CredentialIdentifier: "cred-001",
		Credential:           "",
		Format:               domain.FormatJWTVC,
	}

	_, err := svc.Store(ctx, domain.DefaultTenantID, req)
	if err == nil {
		t.Error("Expected error for missing credential")
	}
}

func TestCredentialService_Store_MissingFormat(t *testing.T) {
	svc := setupCredentialService(t)
	ctx := context.Background()

	req := &domain.StoreCredentialRequest{
		HolderDID:            "did:example:holder",
		CredentialIdentifier: "cred-001",
		Credential:           `{"type": "VerifiableCredential"}`,
		Format:               "",
	}

	_, err := svc.Store(ctx, domain.DefaultTenantID, req)
	if err == nil {
		t.Error("Expected error for missing format")
	}
}

func TestCredentialService_GetAll_Success(t *testing.T) {
	svc := setupCredentialService(t)
	ctx := context.Background()

	// Store some credentials first
	holderDID := "did:example:holder"
	for i := 0; i < 3; i++ {
		req := &domain.StoreCredentialRequest{
			HolderDID:            holderDID,
			CredentialIdentifier: "cred-00" + string(rune('1'+i)),
			Credential:           `{"type": "VerifiableCredential"}`,
			Format:               domain.FormatJWTVC,
		}
		_, err := svc.Store(ctx, domain.DefaultTenantID, req)
		if err != nil {
			t.Fatalf("Store() error = %v", err)
		}
	}

	creds, err := svc.GetAll(ctx, domain.DefaultTenantID, holderDID)
	if err != nil {
		t.Fatalf("GetAll() error = %v", err)
	}

	if len(creds) != 3 {
		t.Errorf("Expected 3 credentials, got %d", len(creds))
	}
}

func TestCredentialService_GetAll_MissingHolderDID(t *testing.T) {
	svc := setupCredentialService(t)
	ctx := context.Background()

	_, err := svc.GetAll(ctx, domain.DefaultTenantID, "")
	if err == nil {
		t.Error("Expected error for missing holder_did")
	}
}

func TestCredentialService_GetByIdentifier_Success(t *testing.T) {
	svc := setupCredentialService(t)
	ctx := context.Background()

	// Store a credential first
	holderDID := "did:example:holder"
	credID := "cred-001"
	req := &domain.StoreCredentialRequest{
		HolderDID:            holderDID,
		CredentialIdentifier: credID,
		Credential:           `{"type": "VerifiableCredential"}`,
		Format:               domain.FormatJWTVC,
	}
	_, err := svc.Store(ctx, domain.DefaultTenantID, req)
	if err != nil {
		t.Fatalf("Store() error = %v", err)
	}

	cred, err := svc.GetByIdentifier(ctx, domain.DefaultTenantID, holderDID, credID)
	if err != nil {
		t.Fatalf("GetByIdentifier() error = %v", err)
	}

	if cred.CredentialIdentifier != credID {
		t.Errorf("Expected CredentialIdentifier %q, got %q", credID, cred.CredentialIdentifier)
	}
}

func TestCredentialService_GetByIdentifier_NotFound(t *testing.T) {
	svc := setupCredentialService(t)
	ctx := context.Background()

	_, err := svc.GetByIdentifier(ctx, domain.DefaultTenantID, "did:example:holder", "nonexistent")
	if err == nil {
		t.Error("Expected error for non-existent credential")
	}
}

func TestCredentialService_GetByIdentifier_MissingHolderDID(t *testing.T) {
	svc := setupCredentialService(t)
	ctx := context.Background()

	_, err := svc.GetByIdentifier(ctx, domain.DefaultTenantID, "", "cred-001")
	if err == nil {
		t.Error("Expected error for missing holder_did")
	}
}

func TestCredentialService_GetByIdentifier_MissingCredentialID(t *testing.T) {
	svc := setupCredentialService(t)
	ctx := context.Background()

	_, err := svc.GetByIdentifier(ctx, domain.DefaultTenantID, "did:example:holder", "")
	if err == nil {
		t.Error("Expected error for missing credential_identifier")
	}
}

func TestCredentialService_Update_Success(t *testing.T) {
	svc := setupCredentialService(t)
	ctx := context.Background()

	// Store a credential first
	holderDID := "did:example:holder"
	credID := "cred-001"
	req := &domain.StoreCredentialRequest{
		HolderDID:            holderDID,
		CredentialIdentifier: credID,
		Credential:           `{"type": "VerifiableCredential"}`,
		Format:               domain.FormatJWTVC,
	}
	_, err := svc.Store(ctx, domain.DefaultTenantID, req)
	if err != nil {
		t.Fatalf("Store() error = %v", err)
	}

	// Update the credential
	updateReq := &domain.UpdateCredentialRequest{
		CredentialIdentifier: credID,
		InstanceID:           42,
		SigCount:             5,
	}
	cred, err := svc.Update(ctx, domain.DefaultTenantID, holderDID, updateReq)
	if err != nil {
		t.Fatalf("Update() error = %v", err)
	}

	if cred.InstanceID != 42 {
		t.Errorf("Expected InstanceID 42, got %d", cred.InstanceID)
	}
	if cred.SigCount != 5 {
		t.Errorf("Expected SigCount 5, got %d", cred.SigCount)
	}
}

func TestCredentialService_Update_NotFound(t *testing.T) {
	svc := setupCredentialService(t)
	ctx := context.Background()

	updateReq := &domain.UpdateCredentialRequest{
		CredentialIdentifier: "nonexistent",
		InstanceID:           42,
	}
	_, err := svc.Update(ctx, domain.DefaultTenantID, "did:example:holder", updateReq)
	if err == nil {
		t.Error("Expected error for non-existent credential")
	}
}

func TestCredentialService_Update_MissingHolderDID(t *testing.T) {
	svc := setupCredentialService(t)
	ctx := context.Background()

	updateReq := &domain.UpdateCredentialRequest{
		CredentialIdentifier: "cred-001",
	}
	_, err := svc.Update(ctx, domain.DefaultTenantID, "", updateReq)
	if err == nil {
		t.Error("Expected error for missing holder_did")
	}
}

func TestCredentialService_Update_MissingCredentialID(t *testing.T) {
	svc := setupCredentialService(t)
	ctx := context.Background()

	updateReq := &domain.UpdateCredentialRequest{
		CredentialIdentifier: "",
	}
	_, err := svc.Update(ctx, domain.DefaultTenantID, "did:example:holder", updateReq)
	if err == nil {
		t.Error("Expected error for missing credential_identifier")
	}
}

func TestCredentialService_Delete_Success(t *testing.T) {
	svc := setupCredentialService(t)
	ctx := context.Background()

	// Store a credential first
	holderDID := "did:example:holder"
	credID := "cred-001"
	req := &domain.StoreCredentialRequest{
		HolderDID:            holderDID,
		CredentialIdentifier: credID,
		Credential:           `{"type": "VerifiableCredential"}`,
		Format:               domain.FormatJWTVC,
	}
	_, err := svc.Store(ctx, domain.DefaultTenantID, req)
	if err != nil {
		t.Fatalf("Store() error = %v", err)
	}

	// Delete the credential
	err = svc.Delete(ctx, domain.DefaultTenantID, holderDID, credID)
	if err != nil {
		t.Fatalf("Delete() error = %v", err)
	}

	// Verify it's gone
	_, err = svc.GetByIdentifier(ctx, domain.DefaultTenantID, holderDID, credID)
	if err == nil {
		t.Error("Expected error for deleted credential")
	}
}

func TestCredentialService_Delete_NotFound(t *testing.T) {
	svc := setupCredentialService(t)
	ctx := context.Background()

	err := svc.Delete(ctx, domain.DefaultTenantID, "did:example:holder", "nonexistent")
	if err == nil {
		t.Error("Expected error for non-existent credential")
	}
}

func TestCredentialService_Delete_MissingHolderDID(t *testing.T) {
	svc := setupCredentialService(t)
	ctx := context.Background()

	err := svc.Delete(ctx, domain.DefaultTenantID, "", "cred-001")
	if err == nil {
		t.Error("Expected error for missing holder_did")
	}
}

func TestCredentialService_Delete_MissingCredentialID(t *testing.T) {
	svc := setupCredentialService(t)
	ctx := context.Background()

	err := svc.Delete(ctx, domain.DefaultTenantID, "did:example:holder", "")
	if err == nil {
		t.Error("Expected error for missing credential_identifier")
	}
}
