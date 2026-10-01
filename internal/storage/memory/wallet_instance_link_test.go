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

func ownerPtr(s string) *domain.UserID { u := domain.UserIDFromString(s); return &u }

func TestWalletInstanceStore_NoAliasingThroughCaller(t *testing.T) {
	ctx := context.Background()
	wis := NewStore().WalletInstances()
	sp := &domain.SecurityProperties{KeyStorage: []string{"a"}, UserAuthentication: []string{"b"}}

	// Insert branch: mutate the caller's pointers afterwards.
	in := &domain.WalletInstance{ID: "i1", TenantID: "acme", Status: domain.InstanceStatusActive,
		UserID: ownerPtr("alice"), DeviceInfo: &domain.DeviceInfo{Model: "m"}, SecurityProperties: sp}
	if err := wis.Upsert(ctx, in); err != nil {
		t.Fatal(err)
	}
	*in.UserID = domain.UserIDFromString("mallory")
	in.DeviceInfo.Model = "x"
	sp.KeyStorage[0] = "x"
	got, _ := wis.GetByID(ctx, "i1")
	if got.UserID.String() != "alice" || got.DeviceInfo.Model != "m" || got.SecurityProperties.KeyStorage[0] != "a" {
		t.Fatalf("insert aliased caller memory: %v %v %v", got.UserID, got.DeviceInfo, got.SecurityProperties)
	}

	// Returned values: mutating them must not change the store.
	*got.UserID = domain.UserIDFromString("mallory")
	got.DeviceInfo.Model = "x"
	got.SecurityProperties.UserAuthentication[0] = "x"
	again, _ := wis.GetByID(ctx, "i1")
	if again.UserID.String() != "alice" || again.DeviceInfo.Model != "m" || again.SecurityProperties.UserAuthentication[0] != "b" {
		t.Fatal("GetByID result aliases the store")
	}
	for name, list := range map[string]func() ([]*domain.WalletInstance, error){
		"GetAllByTenant": func() ([]*domain.WalletInstance, error) { return wis.GetAllByTenant(ctx, "acme") },
		"GetByUser": func() ([]*domain.WalletInstance, error) {
			return wis.GetByUser(ctx, "acme", domain.UserIDFromString("alice"))
		},
		"GetAllByUser": func() ([]*domain.WalletInstance, error) {
			return wis.GetAllByUser(ctx, domain.UserIDFromString("alice"))
		},
	} {
		l, err := list()
		if err != nil || len(l) != 1 {
			t.Fatalf("%s: %v %d", name, err, len(l))
		}
		*l[0].UserID = domain.UserIDFromString("mallory")
		l[0].DeviceInfo.Model = "x"
		l[0].SecurityProperties.KeyStorage[0] = "x"
	}
	again, _ = wis.GetByID(ctx, "i1")
	if again.UserID.String() != "alice" || again.DeviceInfo.Model != "m" || again.SecurityProperties.KeyStorage[0] != "a" {
		t.Fatal("list result aliases the store")
	}

	// Update branch binding an existing unbound instance.
	if err := wis.Upsert(ctx, &domain.WalletInstance{ID: "i2", TenantID: "acme", Status: domain.InstanceStatusActive}); err != nil {
		t.Fatal(err)
	}
	bind := &domain.WalletInstance{ID: "i2", TenantID: "acme", UserID: ownerPtr("bob")}
	if err := wis.Upsert(ctx, bind); err != nil {
		t.Fatal(err)
	}
	*bind.UserID = domain.UserIDFromString("mallory")
	got2, _ := wis.GetByID(ctx, "i2")
	if got2.UserID == nil || got2.UserID.String() != "bob" {
		t.Fatalf("bind aliased caller pointer: %v", got2.UserID)
	}

	// Conditional operations: the binding's Owner pointer is not retained.
	b := got2.Binding()
	if err := wis.UpdateStatusIfUnchanged(ctx, "i2", "acme", b, domain.InstanceStatusRevoked, "r"); err != nil {
		t.Fatal(err)
	}
	*b.Owner = domain.UserIDFromString("mallory")
	got2, _ = wis.GetByID(ctx, "i2")
	if got2.UserID.String() != "bob" || got2.DeactivatedAt == nil {
		t.Fatal("UpdateStatusIfUnchanged aliased the binding or caller pointer")
	}
	dt := *got2.DeactivatedAt
	*got2.DeactivatedAt = dt.Add(1)
	got3, _ := wis.GetByID(ctx, "i2")
	if !got3.DeactivatedAt.Equal(dt) {
		t.Fatal("DeactivatedAt aliases the store")
	}
	// A binding mutated after the call still matches by value semantics.
	good := got3.Binding()
	if err := wis.DeleteIfUnchanged(ctx, "i2", "acme", domain.InstanceBinding{Owner: ownerPtr("mallory"), Generation: good.Generation}); err != storage.ErrBindingChanged {
		t.Fatalf("mutated owner must not match: %v", err)
	}
	if err := wis.DeleteIfUnchanged(ctx, "i2", "acme", good); err != nil {
		t.Fatal(err)
	}
}
