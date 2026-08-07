package memory

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
)

func TestWalletInstanceStore_Upsert_New(t *testing.T) {
	ctx := context.Background()
	store := NewStore()
	wis := store.WalletInstances()

	inst := &domain.WalletInstance{
		ID:       "inst-new",
		TenantID: "acme",
		Status:   domain.InstanceStatusActive,
	}

	if err := wis.Upsert(ctx, inst); err != nil {
		t.Fatalf("Upsert new: %v", err)
	}

	got, err := wis.GetByID(ctx, "inst-new")
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.AttestationCount != 1 {
		t.Errorf("new instance attestation_count = %d, want 1", got.AttestationCount)
	}
}

func TestWalletInstanceStore_Upsert_Existing(t *testing.T) {
	ctx := context.Background()
	store := NewStore()
	wis := store.WalletInstances()

	inst := &domain.WalletInstance{
		ID:       "inst-up",
		TenantID: "acme",
		Status:   domain.InstanceStatusActive,
	}
	if err := wis.Upsert(ctx, inst); err != nil {
		t.Fatalf("Upsert first: %v", err)
	}

	// Upsert again with updated fields. Status is deliberately set to Suspended
	// here to verify Upsert does NOT apply it — lifecycle changes only happen
	// through UpdateStatus (see TestWalletInstanceStore_Upsert_NeverReactivatesDeactivated).
	uid := domain.UserIDFromString("user-1")
	inst2 := &domain.WalletInstance{
		ID:                "inst-up",
		TenantID:          "acme",
		Status:            domain.InstanceStatusSuspended,
		UserID:            &uid,
		AttestationSource: "backend_attested",
		DeviceInfo:        &domain.DeviceInfo{Platform: "web"},
	}
	if err := wis.Upsert(ctx, inst2); err != nil {
		t.Fatalf("Upsert second: %v", err)
	}

	got, err := wis.GetByID(ctx, "inst-up")
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.AttestationCount != 2 {
		t.Errorf("attestation_count = %d, want 2", got.AttestationCount)
	}
	if got.Status != domain.InstanceStatusActive {
		t.Errorf("status = %s, want active (Upsert must not change status of an existing instance)", got.Status)
	}
	if got.UserID == nil || *got.UserID != uid {
		t.Errorf("user_id not updated")
	}
	if got.DeviceInfo == nil || got.DeviceInfo.Platform != "web" {
		t.Errorf("device_info not updated")
	}
}

// TestWalletInstanceStore_Upsert_NeverReactivatesDeactivated is a regression test:
// a suspended/revoked instance must stay that way across subsequent Upsert calls
// (i.e. subsequent WIA re-attestations), since Upsert is what WIAService.signWIA
// calls on every successful attestation.
func TestWalletInstanceStore_Upsert_NeverReactivatesDeactivated(t *testing.T) {
	ctx := context.Background()
	store := NewStore()
	wis := store.WalletInstances()

	inst := &domain.WalletInstance{
		ID:       "inst-revoked",
		TenantID: "acme",
		Status:   domain.InstanceStatusActive,
	}
	if err := wis.Upsert(ctx, inst); err != nil {
		t.Fatalf("Upsert first: %v", err)
	}
	if err := wis.UpdateStatus(ctx, "inst-revoked", domain.InstanceStatusRevoked, "compromised"); err != nil {
		t.Fatalf("UpdateStatus: %v", err)
	}

	// Simulate a subsequent successful WIA re-attestation for the same instance key.
	reattest := &domain.WalletInstance{
		ID:                "inst-revoked",
		TenantID:          "acme",
		Status:            domain.InstanceStatusActive,
		AttestationSource: "backend_attested",
	}
	if err := wis.Upsert(ctx, reattest); err != nil {
		t.Fatalf("Upsert re-attestation: %v", err)
	}

	got, err := wis.GetByID(ctx, "inst-revoked")
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.Status != domain.InstanceStatusRevoked {
		t.Errorf("status = %s, want revoked (Upsert must not reactivate a revoked instance)", got.Status)
	}
}

func TestWalletInstanceStore_Upsert_ExistingNilOptionalFields(t *testing.T) {
	ctx := context.Background()
	store := NewStore()
	wis := store.WalletInstances()

	uid := domain.UserIDFromString("user-1")
	inst := &domain.WalletInstance{
		ID:         "inst-opt",
		TenantID:   "acme",
		Status:     domain.InstanceStatusActive,
		UserID:     &uid,
		DeviceInfo: &domain.DeviceInfo{Platform: "ios"},
	}
	if err := wis.Upsert(ctx, inst); err != nil {
		t.Fatalf("Upsert first: %v", err)
	}

	// Upsert with nil optional fields — should keep existing values
	inst2 := &domain.WalletInstance{
		ID:       "inst-opt",
		TenantID: "acme",
		Status:   domain.InstanceStatusActive,
	}
	if err := wis.Upsert(ctx, inst2); err != nil {
		t.Fatalf("Upsert second: %v", err)
	}

	got, err := wis.GetByID(ctx, "inst-opt")
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.UserID == nil || *got.UserID != uid {
		t.Errorf("user_id should be preserved when nil in update")
	}
	if got.DeviceInfo == nil || got.DeviceInfo.Platform != "ios" {
		t.Errorf("device_info should be preserved when nil in update")
	}
}

func TestWalletInstanceStore_IncrementAttestation(t *testing.T) {
	ctx := context.Background()
	store := NewStore()
	wis := store.WalletInstances()

	inst := &domain.WalletInstance{
		ID:       "inst-inc",
		TenantID: "acme",
		Status:   domain.InstanceStatusActive,
	}
	if err := wis.Upsert(ctx, inst); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	if err := wis.IncrementAttestation(ctx, "inst-inc"); err != nil {
		t.Fatalf("IncrementAttestation: %v", err)
	}

	got, err := wis.GetByID(ctx, "inst-inc")
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.AttestationCount != 2 {
		t.Errorf("attestation_count = %d, want 2", got.AttestationCount)
	}
	if got.LastAttestedAt.IsZero() {
		t.Error("last_attested_at should be set")
	}
}

func TestWalletInstanceStore_IncrementAttestation_NotFound(t *testing.T) {
	ctx := context.Background()
	store := NewStore()
	wis := store.WalletInstances()

	err := wis.IncrementAttestation(ctx, "nonexistent")
	if err != storage.ErrNotFound {
		t.Errorf("IncrementAttestation = %v, want ErrNotFound", err)
	}
}

func TestWalletInstanceStore_UpdateStatus_Suspend(t *testing.T) {
	ctx := context.Background()
	store := NewStore()
	wis := store.WalletInstances()

	inst := &domain.WalletInstance{
		ID:       "inst-sus",
		TenantID: "acme",
		Status:   domain.InstanceStatusActive,
	}
	if err := wis.Upsert(ctx, inst); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	if err := wis.UpdateStatus(ctx, "inst-sus", domain.InstanceStatusSuspended, "policy violation"); err != nil {
		t.Fatalf("UpdateStatus: %v", err)
	}

	got, err := wis.GetByID(ctx, "inst-sus")
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.Status != domain.InstanceStatusSuspended {
		t.Errorf("status = %s, want suspended", got.Status)
	}
	if got.DeactivatedAt == nil {
		t.Error("deactivated_at should be set for suspended")
	}
	if got.DeactivationReason != "policy violation" {
		t.Errorf("deactivation_reason = %q, want %q", got.DeactivationReason, "policy violation")
	}
}

func TestWalletInstanceStore_UpdateStatus_Reactivate(t *testing.T) {
	ctx := context.Background()
	store := NewStore()
	wis := store.WalletInstances()

	inst := &domain.WalletInstance{
		ID:       "inst-react",
		TenantID: "acme",
		Status:   domain.InstanceStatusActive,
	}
	if err := wis.Upsert(ctx, inst); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	// Suspend first
	if err := wis.UpdateStatus(ctx, "inst-react", domain.InstanceStatusSuspended, "temp"); err != nil {
		t.Fatalf("Suspend: %v", err)
	}

	// Reactivate
	if err := wis.UpdateStatus(ctx, "inst-react", domain.InstanceStatusActive, ""); err != nil {
		t.Fatalf("Reactivate: %v", err)
	}

	got, err := wis.GetByID(ctx, "inst-react")
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.Status != domain.InstanceStatusActive {
		t.Errorf("status = %s, want active", got.Status)
	}
	if got.DeactivatedAt != nil {
		t.Error("deactivated_at should be nil after reactivation")
	}
	if got.DeactivationReason != "" {
		t.Errorf("deactivation_reason should be empty, got %q", got.DeactivationReason)
	}
}

func TestWalletInstanceStore_MarkHardwareKeyAttested(t *testing.T) {
	ctx := context.Background()
	store := NewStore()
	wis := store.WalletInstances()

	inst := &domain.WalletInstance{
		ID:       "inst-fido2",
		TenantID: "acme",
		Status:   domain.InstanceStatusActive,
	}
	if err := wis.Upsert(ctx, inst); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	verifiedAt := time.Now().UTC()
	if err := wis.MarkHardwareKeyAttested(ctx, "inst-fido2", verifiedAt); err != nil {
		t.Fatalf("MarkHardwareKeyAttested: %v", err)
	}

	got, err := wis.GetByID(ctx, "inst-fido2")
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if !got.HardwareKeyAttested {
		t.Error("expected HardwareKeyAttested = true")
	}
	if got.HardwareAttestationVerifiedAt == nil || !got.HardwareAttestationVerifiedAt.Equal(verifiedAt) {
		t.Errorf("HardwareAttestationVerifiedAt = %v, want %v", got.HardwareAttestationVerifiedAt, verifiedAt)
	}
}

func TestWalletInstanceStore_MarkHardwareKeyAttested_NotFound(t *testing.T) {
	ctx := context.Background()
	store := NewStore()
	wis := store.WalletInstances()

	err := wis.MarkHardwareKeyAttested(ctx, "does-not-exist", time.Now().UTC())
	if !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("err = %v, want storage.ErrNotFound", err)
	}
}
