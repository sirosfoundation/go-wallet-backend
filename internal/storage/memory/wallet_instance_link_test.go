package memory

import (
	"context"
	"testing"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
)

// The passkey link (CredentialID) is supplied by the client at attestation.
// The first non-empty link must stick: a later attestation may fill in a
// missing link but must not move the instance to another passkey, or the
// original passkey would escape per-instance revocation login gating.
func TestWalletInstanceStore_Upsert_KeepsFirstCredentialLink(t *testing.T) {
	ctx := context.Background()
	wis := NewStore().WalletInstances()

	// First attestation without a link, second one supplies it.
	if err := wis.Upsert(ctx, &domain.WalletInstance{ID: "i1", TenantID: "acme", Status: domain.InstanceStatusActive}); err != nil {
		t.Fatalf("Upsert 1: %v", err)
	}
	if err := wis.Upsert(ctx, &domain.WalletInstance{ID: "i1", TenantID: "acme", Status: domain.InstanceStatusActive, CredentialID: "pk-1"}); err != nil {
		t.Fatalf("Upsert 2: %v", err)
	}
	got, err := wis.GetByID(ctx, "i1")
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.CredentialID != "pk-1" {
		t.Fatalf("CredentialID = %q, want pk-1 (a missing link may be filled in)", got.CredentialID)
	}

	// A later attestation presenting another passkey must not move the link.
	if err := wis.Upsert(ctx, &domain.WalletInstance{ID: "i1", TenantID: "acme", Status: domain.InstanceStatusActive, CredentialID: "pk-2"}); err != nil {
		t.Fatalf("Upsert 3: %v", err)
	}
	got, err = wis.GetByID(ctx, "i1")
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.CredentialID != "pk-1" {
		t.Errorf("CredentialID = %q, want pk-1 (first link wins)", got.CredentialID)
	}
	// An attestation without a link leaves it alone too.
	if err := wis.Upsert(ctx, &domain.WalletInstance{ID: "i1", TenantID: "acme", Status: domain.InstanceStatusActive}); err != nil {
		t.Fatalf("Upsert 4: %v", err)
	}
	got, _ = wis.GetByID(ctx, "i1")
	if got.CredentialID != "pk-1" {
		t.Errorf("CredentialID = %q after link-less attestation, want pk-1", got.CredentialID)
	}
}

// Mirror of the Mongo guards: a losing cross-tenant first attestation must not
// bind its user or link its passkey onto the winner's record, and within a
// tenant only the bound user may write the passkey link.
func TestWalletInstanceStore_Upsert_OwnershipWritesAreTenantScoped(t *testing.T) {
	ctx := context.Background()
	wis := NewStore().WalletInstances()
	winner, loser := domain.NewUserID(), domain.NewUserID()

	if err := wis.Upsert(ctx, &domain.WalletInstance{ID: "i2", TenantID: "acme", Status: domain.InstanceStatusActive}); err != nil {
		t.Fatalf("Upsert 1: %v", err)
	}
	if err := wis.Upsert(ctx, &domain.WalletInstance{ID: "i2", TenantID: "other", Status: domain.InstanceStatusActive, UserID: &loser, CredentialID: "pk-loser"}); err != storage.ErrAlreadyExists {
		t.Fatalf("Upsert 2 from another tenant: expected ErrAlreadyExists, got %v", err)
	}
	got, err := wis.GetByID(ctx, "i2")
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.TenantID != "acme" {
		t.Errorf("TenantID = %q, want acme (fixed at insert)", got.TenantID)
	}
	if got.UserID != nil {
		t.Errorf("a user of another tenant must not be bound, got %v", *got.UserID)
	}
	if got.CredentialID != "" {
		t.Errorf("a passkey of another tenant must not be linked, got %q", got.CredentialID)
	}

	// Same tenant, but the caller is not the bound user: no link.
	if err := wis.Upsert(ctx, &domain.WalletInstance{ID: "i2", TenantID: "acme", Status: domain.InstanceStatusActive, UserID: &winner}); err != nil {
		t.Fatalf("Upsert 3: %v", err)
	}
	if err := wis.Upsert(ctx, &domain.WalletInstance{ID: "i2", TenantID: "acme", Status: domain.InstanceStatusActive, UserID: &loser, CredentialID: "pk-loser"}); err != nil {
		t.Fatalf("Upsert 4: %v", err)
	}
	got, _ = wis.GetByID(ctx, "i2")
	if got.UserID == nil || *got.UserID != winner {
		t.Errorf("first user binding must win, got %v", got.UserID)
	}
	if got.CredentialID != "" {
		t.Errorf("only the bound user may link a passkey, got %q", got.CredentialID)
	}

	// The bound user links normally.
	if err := wis.Upsert(ctx, &domain.WalletInstance{ID: "i2", TenantID: "acme", Status: domain.InstanceStatusActive, UserID: &winner, CredentialID: "pk-winner"}); err != nil {
		t.Fatalf("Upsert 5: %v", err)
	}
	got, _ = wis.GetByID(ctx, "i2")
	if got.CredentialID != "pk-winner" {
		t.Errorf("CredentialID = %q, want pk-winner", got.CredentialID)
	}
}
