package memory

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

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
	if err := wis.UpdateStatus(ctx, "inst-revoked", "acme", domain.InstanceStatusRevoked, "compromised"); err != nil {
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

	if err := wis.UpdateStatus(ctx, "inst-rev", "acme", domain.InstanceStatusRevoked, "policy violation"); err != nil {
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
	if err := wis.UpdateStatus(ctx, "inst-term", "acme", domain.InstanceStatusActive, ""); !errors.Is(err, domain.ErrInvalidStatusTransition) {
		t.Fatalf("UpdateStatus(active) on an active instance = %v, want ErrInvalidStatusTransition", err)
	}

	if err := wis.UpdateStatus(ctx, "inst-term", "acme", domain.InstanceStatusRevoked, "stolen"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	// And there is no way back out of revoked.
	if err := wis.UpdateStatus(ctx, "inst-term", "acme", domain.InstanceStatusActive, ""); !errors.Is(err, domain.ErrInvalidStatusTransition) {
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
	if err := store.WalletInstances().UpdateStatus(ctx, "inst-cred", "acme", domain.InstanceStatusRevoked, "x"); err != nil {
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

// The memory store must agree with Mongo about legacy records: a "suspended"
// instance written by an earlier release can be revoked, and nothing else.
func TestWalletInstanceStore_UpdateStatus_LegacySuspendedIsRevocable(t *testing.T) {
	ctx := context.Background()
	store := NewStore()
	wis := store.WalletInstances()

	if err := wis.Upsert(ctx, &domain.WalletInstance{
		ID: "inst-legacy", TenantID: "acme", Status: domain.InstanceStatusLegacySuspended,
	}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	if err := wis.UpdateStatus(ctx, "inst-legacy", "acme", domain.InstanceStatusActive, ""); !errors.Is(err, domain.ErrInvalidStatusTransition) {
		t.Fatalf("UpdateStatus(active) = %v, want ErrInvalidStatusTransition", err)
	}
	if err := wis.UpdateStatus(ctx, "inst-legacy", "acme", domain.InstanceStatusRevoked, "cleanup"); err != nil {
		t.Fatalf("revoke a legacy suspended instance: %v", err)
	}
	got, err := wis.GetByID(ctx, "inst-legacy")
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.Status != domain.InstanceStatusRevoked {
		t.Errorf("status = %s, want revoked", got.Status)
	}
	if got.DeactivatedAt == nil {
		t.Error("deactivated_at should be set")
	}
}

func TestInstanceStatus_IsLive(t *testing.T) {
	for st, want := range map[domain.InstanceStatus]bool{
		domain.InstanceStatusActive:          true,
		domain.InstanceStatusRevoked:         false,
		domain.InstanceStatusLegacySuspended: false,
		domain.InstanceStatus("something-新"): false,
	} {
		if got := st.IsLive(); got != want {
			t.Errorf("InstanceStatus(%q).IsLive() = %v, want %v", st, got, want)
		}
	}
}

// A revocation can land between an admin's removability check and the delete
// itself. The tombstone it creates is the record that keeps login and new
// attestations refused, so the delete must carry its own condition rather
// than trust the caller's snapshot.
func TestWalletInstanceStore_DeleteIfRemovable(t *testing.T) {
	ctx := context.Background()
	store := NewStore()
	wis := store.WalletInstances()
	uid := domain.UserIDFromString("owner")

	// A live, user-owned instance is removable.
	if err := wis.Upsert(ctx, &domain.WalletInstance{
		ID: "inst-live", TenantID: "acme", UserID: &uid, Status: domain.InstanceStatusActive,
	}); err != nil {
		t.Fatal(err)
	}
	if err := wis.DeleteIfRemovable(ctx, "inst-live", "acme", bindingOf(t, wis, "inst-live")); err != nil {
		t.Fatalf("a live instance must be removable: %v", err)
	}

	// A revoked, user-owned instance is a tombstone and is not.
	if err := wis.Upsert(ctx, &domain.WalletInstance{
		ID: "inst-tomb", TenantID: "acme", UserID: &uid, Status: domain.InstanceStatusActive,
	}); err != nil {
		t.Fatal(err)
	}
	if err := wis.UpdateStatus(ctx, "inst-tomb", "acme", domain.InstanceStatusRevoked, "stolen"); err != nil {
		t.Fatal(err)
	}
	if err := wis.DeleteIfRemovable(ctx, "inst-tomb", "acme", bindingOf(t, wis, "inst-tomb")); !errors.Is(err, domain.ErrInvalidStatusTransition) {
		t.Fatalf("a tombstone must survive, got %v", err)
	}
	if _, err := wis.GetByID(ctx, "inst-tomb"); err != nil {
		t.Errorf("the tombstone must still be there, got %v", err)
	}

	// A stray record with no user is removable whatever its status.
	if err := wis.Upsert(ctx, &domain.WalletInstance{
		ID: "inst-stray", TenantID: "acme", Status: domain.InstanceStatusRevoked,
	}); err != nil {
		t.Fatal(err)
	}
	if err := wis.DeleteIfRemovable(ctx, "inst-stray", "acme", bindingOf(t, wis, "inst-stray")); err != nil {
		t.Fatalf("a record with no user must be removable: %v", err)
	}

	// Another tenant's record is not found.
	if err := wis.Upsert(ctx, &domain.WalletInstance{
		ID: "inst-other", TenantID: "other", UserID: &uid, Status: domain.InstanceStatusActive,
	}); err != nil {
		t.Fatal(err)
	}
	if err := wis.DeleteIfRemovable(ctx, "inst-other", "acme", bindingOf(t, wis, "inst-other")); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("another tenant's record must not be reachable, got %v", err)
	}
}

// The tenant is part of the write, not only of the caller's earlier read: the
// id is a global key, so a revocation issued for one tenant must not land on a
// record another tenant holds under the same id.
func TestWalletInstanceStore_UpdateStatus_WrongTenantIsNotFound(t *testing.T) {
	ctx := context.Background()
	wis := NewStore().WalletInstances()
	if err := wis.Upsert(ctx, &domain.WalletInstance{ID: "inst-tenant", TenantID: "acme", Status: domain.InstanceStatusActive}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	if err := wis.UpdateStatus(ctx, "inst-tenant", "other", domain.InstanceStatusRevoked, "x"); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("UpdateStatus in the wrong tenant = %v, want ErrNotFound", err)
	}
	got, err := wis.GetByID(ctx, "inst-tenant")
	if err != nil || got.Status != domain.InstanceStatusActive {
		t.Fatalf("record was touched by a revocation for another tenant: %v %v", got, err)
	}
}

// The id is a global key, so a delete or revocation issued for one user's
// record must not touch a replacement that took the same id under another
// tenant or user.
func TestWalletInstanceStore_OwnerCheckedWrites(t *testing.T) {
	ctx := context.Background()
	wis := NewStore().WalletInstances()
	owner := domain.UserIDFromString("owner")
	other := domain.UserIDFromString("other")

	seed := func(id string, tenant domain.TenantID, u *domain.UserID) {
		t.Helper()
		if err := wis.Upsert(ctx, &domain.WalletInstance{ID: id, TenantID: tenant, UserID: u, Status: domain.InstanceStatusActive}); err != nil {
			t.Fatal(err)
		}
	}

	seed("i1", "acme", &owner)
	if err := wis.DeleteForUser(ctx, "i1", "acme", other); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("other user's delete = %v, want ErrNotFound", err)
	}
	if err := wis.DeleteForUser(ctx, "i1", "elsewhere", owner); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("other tenant's delete = %v, want ErrNotFound", err)
	}
	if _, err := wis.GetByID(ctx, "i1"); err != nil {
		t.Fatalf("a mismatched delete must leave the record: %v", err)
	}
	if err := wis.UpdateStatusForUser(ctx, "i1", "acme", other, domain.InstanceStatusRevoked, "x"); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("other user's revoke = %v, want ErrNotFound", err)
	}
	if got, _ := wis.GetByID(ctx, "i1"); got.Status != domain.InstanceStatusActive {
		t.Fatalf("a mismatched revoke must leave the record active, got %q", got.Status)
	}
	if err := wis.UpdateStatusForUser(ctx, "i1", "acme", owner, domain.InstanceStatusRevoked, "x"); err != nil {
		t.Fatalf("owner revoke: %v", err)
	}
	if err := wis.DeleteForUser(ctx, "i1", "acme", owner); err != nil {
		t.Fatalf("owner delete: %v", err)
	}
	if err := wis.DeleteForUser(ctx, "i1", "acme", owner); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("second delete = %v, want ErrNotFound", err)
	}

	// A record with no user matches no owner.
	seed("i2", "acme", nil)
	if err := wis.DeleteForUser(ctx, "i2", "acme", owner); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("unowned delete = %v, want ErrNotFound", err)
	}
}

func TestWalletInstanceStore_ReturnedNestedDataIsACopy(t *testing.T) {
	ctx := context.Background()
	uid := domain.NewUserID()
	store := NewStore()
	wis := store.WalletInstances()
	in := &domain.WalletInstance{
		ID: "inst-nested", TenantID: "acme", UserID: &uid,
		DeviceInfo:         &domain.DeviceInfo{Platform: "ios", Model: "m1"},
		SecurityProperties: &domain.SecurityProperties{KeyStorage: []string{"high"}, UserAuthentication: []string{"pin"}, Certification: "c"},
	}
	if err := wis.Upsert(ctx, in); err != nil {
		t.Fatal(err)
	}
	// Mutating the caller's own input after the write must not reach the store.
	in.DeviceInfo.Model = "input-mutated"
	in.SecurityProperties.KeyStorage[0] = "input-mutated"

	mutate := func(i *domain.WalletInstance) {
		i.DeviceInfo.Platform = "hacked"
		i.SecurityProperties.KeyStorage[0] = "hacked"
		i.SecurityProperties.UserAuthentication[0] = "hacked"
		i.SecurityProperties.Certification = "hacked"
	}
	byID, err := wis.GetByID(ctx, "inst-nested")
	if err != nil {
		t.Fatal(err)
	}
	mutate(byID)
	byUser, err := wis.GetByUser(ctx, "acme", uid)
	if err != nil || len(byUser) != 1 {
		t.Fatalf("GetByUser: %v %d", err, len(byUser))
	}
	mutate(byUser[0])

	got, err := wis.GetByID(ctx, "inst-nested")
	if err != nil {
		t.Fatal(err)
	}
	if got.DeviceInfo.Platform != "ios" || got.DeviceInfo.Model != "m1" {
		t.Errorf("stored DeviceInfo changed: %+v", got.DeviceInfo)
	}
	sp := got.SecurityProperties
	if sp.KeyStorage[0] != "high" || sp.UserAuthentication[0] != "pin" || sp.Certification != "c" {
		t.Errorf("stored SecurityProperties changed: %+v", sp)
	}

	// An update through Upsert copies the incoming DeviceInfo as well.
	upd := &domain.DeviceInfo{Platform: "android"}
	if err := wis.Upsert(ctx, &domain.WalletInstance{ID: "inst-nested", TenantID: "acme", DeviceInfo: upd}); err != nil {
		t.Fatal(err)
	}
	upd.Platform = "later-mutation"
	got, _ = wis.GetByID(ctx, "inst-nested")
	if got.DeviceInfo.Platform != "android" {
		t.Errorf("stored DeviceInfo aliases the caller's struct: %+v", got.DeviceInfo)
	}
}

// bindingOf reads the binding of a stored record, as a caller that is about
// to make a conditional write would.
func bindingOf(t *testing.T, wis storage.WalletInstanceStore, id string) domain.InstanceBinding {
	t.Helper()
	inst, err := wis.GetByID(context.Background(), id)
	if err != nil {
		t.Fatalf("read %s: %v", id, err)
	}
	return inst.Binding()
}

// Every insert gets a generation of its own, and a record deleted and created
// again under the same id and tenant is a different record to a conditional
// write, whoever owns the replacement.
func TestWalletInstanceStore_Conditional_ReplacementIsNotTheRecordRead(t *testing.T) {
	ctx := context.Background()
	alice := domain.UserIDFromString("alice")
	bob := domain.UserIDFromString("bob")

	type write struct {
		name string
		do   func(wis storage.WalletInstanceStore, b domain.InstanceBinding) error
	}
	writes := []write{
		{"UpdateStatusIfUnchanged", func(wis storage.WalletInstanceStore, b domain.InstanceBinding) error {
			return wis.UpdateStatusIfUnchanged(ctx, "jkt", "acme", b, domain.InstanceStatusRevoked, "x")
		}},
		{"DeleteIfUnchanged", func(wis storage.WalletInstanceStore, b domain.InstanceBinding) error {
			return wis.DeleteIfUnchanged(ctx, "jkt", "acme", b)
		}},
		{"DeleteIfRemovable", func(wis storage.WalletInstanceStore, b domain.InstanceBinding) error {
			return wis.DeleteIfRemovable(ctx, "jkt", "acme", b)
		}},
	}
	// owners of the original and of the replacement; nil is unowned.
	cases := []struct {
		name         string
		first, again *domain.UserID
	}{
		{"replaced by another user", &alice, &bob},
		{"replaced by the same user", &alice, &alice},
		{"unowned replaced by an owned one", nil, &bob},
		{"owned replaced by an unowned one", &alice, nil},
		{"unowned replaced by an unowned one", nil, nil},
	}
	for _, w := range writes {
		for _, c := range cases {
			t.Run(w.name+"/"+c.name, func(t *testing.T) {
				wis := NewStore().WalletInstances()
				if err := wis.Upsert(ctx, &domain.WalletInstance{ID: "jkt", TenantID: "acme", UserID: c.first, Status: domain.InstanceStatusActive}); err != nil {
					t.Fatal(err)
				}
				read := bindingOf(t, wis, "jkt")
				if err := wis.DeleteIfUnchanged(ctx, "jkt", "acme", read); err != nil {
					t.Fatal(err)
				}
				if err := wis.Upsert(ctx, &domain.WalletInstance{ID: "jkt", TenantID: "acme", UserID: c.again, Status: domain.InstanceStatusActive}); err != nil {
					t.Fatal(err)
				}
				if err := w.do(wis, read); !errors.Is(err, storage.ErrBindingChanged) {
					t.Fatalf("a write from the stale binding must be refused with ErrBindingChanged, got %v", err)
				}
				got, err := wis.GetByID(ctx, "jkt")
				if err != nil {
					t.Fatalf("the replacement must survive: %v", err)
				}
				if got.Status != domain.InstanceStatusActive || got.DeactivatedAt != nil {
					t.Errorf("the replacement must be untouched, got %+v", got)
				}
				if got.Generation == "" || got.Generation == read.Generation {
					t.Errorf("the replacement needs a generation of its own, read %q replacement %q", read.Generation, got.Generation)
				}
			})
		}
	}
}

// The binding the caller read still works, and an owner bound after the read
// (the anonymous instance gaining its user) makes it stale.
func TestWalletInstanceStore_Conditional_MatchAndOwnerBind(t *testing.T) {
	ctx := context.Background()
	alice := domain.UserIDFromString("alice")
	wis := NewStore().WalletInstances()

	if err := wis.Upsert(ctx, &domain.WalletInstance{ID: "anon", TenantID: "acme", Status: domain.InstanceStatusActive}); err != nil {
		t.Fatal(err)
	}
	unowned := bindingOf(t, wis, "anon")
	// Another tenant's request does not see the record at all.
	if err := wis.UpdateStatusIfUnchanged(ctx, "anon", "other", unowned, domain.InstanceStatusRevoked, "x"); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("wrong tenant: want ErrNotFound, got %v", err)
	}
	if err := wis.Upsert(ctx, &domain.WalletInstance{ID: "anon", TenantID: "acme", UserID: &alice, Status: domain.InstanceStatusActive}); err != nil {
		t.Fatal(err)
	}
	if err := wis.UpdateStatusIfUnchanged(ctx, "anon", "acme", unowned, domain.InstanceStatusRevoked, "x"); !errors.Is(err, storage.ErrBindingChanged) {
		t.Fatalf("the unowned binding must be stale once the record is bound, got %v", err)
	}
	if err := wis.DeleteIfUnchanged(ctx, "anon", "acme", unowned); !errors.Is(err, storage.ErrBindingChanged) {
		t.Fatalf("want ErrBindingChanged, got %v", err)
	}
	fresh := bindingOf(t, wis, "anon")
	if fresh.Generation != unowned.Generation {
		t.Fatalf("binding an owner must not change the generation")
	}
	if err := wis.UpdateStatusIfUnchanged(ctx, "anon", "acme", fresh, domain.InstanceStatusRevoked, "x"); err != nil {
		t.Fatalf("the fresh binding must write: %v", err)
	}
	// Right record, already revoked: the transition error, not a binding one.
	if err := wis.UpdateStatusIfUnchanged(ctx, "anon", "acme", fresh, domain.InstanceStatusRevoked, "x"); !errors.Is(err, domain.ErrInvalidStatusTransition) {
		t.Fatalf("want ErrInvalidStatusTransition, got %v", err)
	}
	if err := wis.DeleteIfUnchanged(ctx, "anon", "acme", fresh); err != nil {
		t.Fatalf("the fresh binding must delete: %v", err)
	}
	if err := wis.DeleteIfUnchanged(ctx, "anon", "acme", fresh); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("a gone record is ErrNotFound, got %v", err)
	}
}

// A record written before generations existed has none and is matched by an
// expected binding with none.
func TestWalletInstanceStore_Conditional_LegacyRecordWithoutGeneration(t *testing.T) {
	ctx := context.Background()
	store := NewStore()
	wis := store.WalletInstances()
	store.walletInstances.data["legacy"] = &domain.WalletInstance{ID: "legacy", TenantID: "acme", Status: domain.InstanceStatusActive}
	b := bindingOf(t, wis, "legacy")
	if b.Generation != "" {
		t.Fatalf("setup: want no generation, got %q", b.Generation)
	}
	if err := wis.UpdateStatusIfUnchanged(ctx, "legacy", "acme", domain.InstanceBinding{Generation: "g"}, domain.InstanceStatusRevoked, "x"); !errors.Is(err, storage.ErrBindingChanged) {
		t.Fatalf("a binding with a generation must not match a record without one, got %v", err)
	}
	if err := wis.UpdateStatusIfUnchanged(ctx, "legacy", "acme", b, domain.InstanceStatusRevoked, "x"); err != nil {
		t.Fatal(err)
	}
}

// A corrupted or unknown stored status is not a legal source state: revoking
// it fails closed and leaves the record untouched.
func TestWalletInstanceStore_UpdateStatus_UnknownStatusCannotBeRevoked(t *testing.T) {
	ctx := context.Background()
	store := NewStore()
	wis := store.WalletInstances()

	if err := wis.Upsert(ctx, &domain.WalletInstance{
		ID: "inst-corrupt", TenantID: "acme", Status: domain.InstanceStatus("bogus"),
	}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	got, err := wis.GetByID(ctx, "inst-corrupt")
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if err := wis.UpdateStatus(ctx, "inst-corrupt", "acme", domain.InstanceStatusRevoked, "x"); !errors.Is(err, domain.ErrInvalidStatusTransition) {
		t.Fatalf("UpdateStatus = %v, want ErrInvalidStatusTransition", err)
	}
	if err := wis.UpdateStatusIfUnchanged(ctx, "inst-corrupt", "acme", got.Binding(), domain.InstanceStatusRevoked, "x"); !errors.Is(err, domain.ErrInvalidStatusTransition) {
		t.Fatalf("UpdateStatusIfUnchanged = %v, want ErrInvalidStatusTransition", err)
	}
	after, _ := wis.GetByID(ctx, "inst-corrupt")
	if after.Status != domain.InstanceStatus("bogus") || after.DeactivatedAt != nil {
		t.Fatalf("record must be untouched: %+v", after)
	}
}

// Upsert reports the generation of the record it applied to, for a new and
// for an existing record, and a record deleted and re-created gets another.
func TestWalletInstanceStore_Upsert_ReportsGeneration(t *testing.T) {
	ctx := context.Background()
	s := NewStore().WalletInstances()
	first := &domain.WalletInstance{ID: "g1", TenantID: "t", Status: domain.InstanceStatusActive}
	require.NoError(t, s.Upsert(ctx, first))
	require.NotEmpty(t, first.Generation)
	got, err := s.GetByID(ctx, "g1")
	require.NoError(t, err)
	require.Equal(t, got.Generation, first.Generation)

	again := &domain.WalletInstance{ID: "g1", TenantID: "t"}
	require.NoError(t, s.Upsert(ctx, again))
	require.Equal(t, first.Generation, again.Generation)

	require.NoError(t, s.DeleteIfUnchanged(ctx, "g1", "t", got.Binding()))
	re := &domain.WalletInstance{ID: "g1", TenantID: "t", Status: domain.InstanceStatusActive}
	require.NoError(t, s.Upsert(ctx, re))
	require.NotEqual(t, first.Generation, re.Generation)
}
