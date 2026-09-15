package memory

import (
	"context"
	"testing"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
)

// The passkey link (CredentialID) is supplied by the client at attestation.
// The first non-empty link must stick: a later attestation may fill in a
// missing link but must not move the instance to another passkey, or the
// original passkey would escape per-instance suspend/revoke login gating.
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
