package memory

import (
	"context"
	"errors"
	"testing"

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

	// Upsert again with updated fields. Status is deliberately set to Revoked
	// here to verify Upsert does NOT apply it — lifecycle changes only happen
	// through UpdateStatus (see TestWalletInstanceStore_Upsert_NeverReactivatesDeactivated).
	uid := domain.UserIDFromString("user-1")
	inst2 := &domain.WalletInstance{
		ID:                "inst-up",
		TenantID:          "acme",
		Status:            domain.InstanceStatusRevoked,
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
// a revoked instance must stay that way across subsequent Upsert calls
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

func TestWalletInstanceStore_UpdateStatus_Revoke(t *testing.T) {
	ctx := context.Background()
	store := NewStore()
	wis := store.WalletInstances()

	inst := &domain.WalletInstance{
		ID:       "inst-rev",
		TenantID: "acme",
		Status:   domain.InstanceStatusActive,
	}
	if err := wis.Upsert(ctx, inst); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	if err := wis.UpdateStatus(ctx, "inst-rev", domain.InstanceStatusRevoked, "policy violation"); err != nil {
		t.Fatalf("UpdateStatus: %v", err)
	}

	got, err := wis.GetByID(ctx, "inst-rev")
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.Status != domain.InstanceStatusRevoked {
		t.Errorf("status = %s, want revoked", got.Status)
	}
	if got.DeactivatedAt == nil {
		t.Error("deactivated_at should be set for a revoked instance")
	}
	if got.DeactivationReason != "policy violation" {
		t.Errorf("deactivation_reason = %q, want %q", got.DeactivationReason, "policy violation")
	}
}

// TestWalletInstanceStore_UpdateStatus_RevocationIsTerminal pins the shape of
// the state machine: there is no way back from revoked, and "active" is not a
// status this method will write at all. An instance is active from the moment
// it is inserted, so accepting it here could only ever mean reactivation.
func TestWalletInstanceStore_UpdateStatus_RevocationIsTerminal(t *testing.T) {
	ctx := context.Background()
	store := NewStore()
	wis := store.WalletInstances()

	inst := &domain.WalletInstance{
		ID:       "inst-term",
		TenantID: "acme",
		Status:   domain.InstanceStatusActive,
	}
	if err := wis.Upsert(ctx, inst); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	// Reactivating an active instance is refused before it is even a
	// transition question.
	if err := wis.UpdateStatus(ctx, "inst-term", domain.InstanceStatusActive, ""); !errors.Is(err, domain.ErrInvalidStatusTransition) {
		t.Fatalf("UpdateStatus(active) on an active instance = %v, want ErrInvalidStatusTransition", err)
	}

	if err := wis.UpdateStatus(ctx, "inst-term", domain.InstanceStatusRevoked, "stolen"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	// And there is no way back out of revoked.
	if err := wis.UpdateStatus(ctx, "inst-term", domain.InstanceStatusActive, ""); !errors.Is(err, domain.ErrInvalidStatusTransition) {
		t.Fatalf("UpdateStatus(active) on a revoked instance = %v, want ErrInvalidStatusTransition", err)
	}

	got, err := wis.GetByID(ctx, "inst-term")
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.Status != domain.InstanceStatusRevoked {
		t.Errorf("status = %s, want revoked", got.Status)
	}
	if got.DeactivationReason != "stolen" {
		t.Errorf("deactivation_reason = %q, want %q", got.DeactivationReason, "stolen")
	}
}

func TestWalletInstanceStore_Upsert_RecordsCredentialIDWithoutTouchingStatus(t *testing.T) {
	store := NewStore()
	ctx := context.Background()
	inst := &domain.WalletInstance{ID: "inst-cred", TenantID: "acme", Status: domain.InstanceStatusActive}
	if err := store.WalletInstances().Upsert(ctx, inst); err != nil {
		t.Fatal(err)
	}
	if err := store.WalletInstances().UpdateStatus(ctx, "inst-cred", domain.InstanceStatusRevoked, "x"); err != nil {
		t.Fatal(err)
	}
	// A later attestation that now names the passkey records the link but
	// must not reactivate the instance.
	if err := store.WalletInstances().Upsert(ctx, &domain.WalletInstance{ID: "inst-cred", TenantID: "acme", Status: domain.InstanceStatusActive, CredentialID: "pk-1"}); err != nil {
		t.Fatal(err)
	}
	got, err := store.WalletInstances().GetByID(ctx, "inst-cred")
	if err != nil {
		t.Fatal(err)
	}
	if got.CredentialID != "pk-1" {
		t.Errorf("credential id not recorded: %q", got.CredentialID)
	}
	if got.Status != domain.InstanceStatusRevoked {
		t.Errorf("status must be untouched by upsert, got %s", got.Status)
	}
	// An attestation without the id keeps the recorded link.
	if err := store.WalletInstances().Upsert(ctx, &domain.WalletInstance{ID: "inst-cred", TenantID: "acme", Status: domain.InstanceStatusActive}); err != nil {
		t.Fatal(err)
	}
	got, _ = store.WalletInstances().GetByID(ctx, "inst-cred")
	if got.CredentialID != "pk-1" {
		t.Errorf("credential id must persist, got %q", got.CredentialID)
	}
}

// The first user binding of an anonymous instance wins; a later attestation
// by another user must not re-parent the record.
func TestWalletInstanceStore_Upsert_FirstUserBindingWins(t *testing.T) {
	store := NewStore().WalletInstances()
	ctx := context.Background()
	a, b := domain.UserIDFromString("user-a"), domain.UserIDFromString("user-b")
	if err := store.Upsert(ctx, &domain.WalletInstance{ID: "anon", TenantID: domain.DefaultTenantID, Status: domain.InstanceStatusActive}); err != nil {
		t.Fatal(err)
	}
	if err := store.Upsert(ctx, &domain.WalletInstance{ID: "anon", TenantID: domain.DefaultTenantID, Status: domain.InstanceStatusActive, UserID: &a}); err != nil {
		t.Fatal(err)
	}
	if err := store.Upsert(ctx, &domain.WalletInstance{ID: "anon", TenantID: domain.DefaultTenantID, Status: domain.InstanceStatusActive, UserID: &b}); err != nil {
		t.Fatal(err)
	}
	got, err := store.GetByID(ctx, "anon")
	if err != nil {
		t.Fatal(err)
	}
	if got.UserID == nil || *got.UserID != a {
		t.Fatalf("user binding must stay with the first user, got %v", got.UserID)
	}
	if got.AttestationCount != 3 {
		t.Fatalf("attestations still counted: %d", got.AttestationCount)
	}
}

// The instance key is global while the record belongs to one tenant, so an
// attestation from another tenant is refused outright rather than allowed to
// touch the record's metadata.
func TestWalletInstanceStore_Upsert_RefusesAnotherTenantsRecord(t *testing.T) {
	store := NewStore().WalletInstances()
	ctx := context.Background()
	if err := store.Upsert(ctx, &domain.WalletInstance{ID: "k", TenantID: "acme", Status: domain.InstanceStatusActive, AttestationSource: "first"}); err != nil {
		t.Fatal(err)
	}
	if err := store.Upsert(ctx, &domain.WalletInstance{ID: "k", TenantID: "other", Status: domain.InstanceStatusActive, AttestationSource: "intruder"}); err != storage.ErrAlreadyExists {
		t.Fatalf("expected ErrAlreadyExists, got %v", err)
	}
	got, _ := store.GetByID(ctx, "k")
	if got.TenantID != "acme" {
		t.Fatalf("tenant must not move on re-attestation, got %s", got.TenantID)
	}
	if got.AttestationSource != "first" || got.AttestationCount != 1 {
		t.Fatalf("no metadata of another tenant's record may be touched: %+v", got)
	}
}
