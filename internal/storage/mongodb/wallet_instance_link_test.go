package mongodb

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
)

// The passkey link (credential_id) is supplied by the client at attestation.
// The first non-empty link must stick: a later attestation may fill in a
// missing link but must not move the instance to another passkey, or the
// original passkey would escape per-instance suspend/revoke login gating.
func TestWalletInstanceStore_Upsert_KeepsFirstCredentialLink(t *testing.T) {
	store := skipIfNoMongo(t)
	ctx := context.Background()
	wis := store.WalletInstances()
	// The test database is shared between runs; a unique id keeps counts exact.
	id := "inst-first-link-" + strconv.FormatInt(time.Now().UnixNano(), 36)

	require.NoError(t, wis.Upsert(ctx, &domain.WalletInstance{ID: id, TenantID: "acme", Status: domain.InstanceStatusActive}))
	got, err := wis.GetByID(ctx, id)
	require.NoError(t, err)
	require.Empty(t, got.CredentialID)

	require.NoError(t, wis.Upsert(ctx, &domain.WalletInstance{ID: id, TenantID: "acme", Status: domain.InstanceStatusActive, CredentialID: "pk-1"}))
	got, err = wis.GetByID(ctx, id)
	require.NoError(t, err)
	require.Equal(t, "pk-1", got.CredentialID, "a missing link may be filled in")

	require.NoError(t, wis.Upsert(ctx, &domain.WalletInstance{ID: id, TenantID: "acme", Status: domain.InstanceStatusActive, CredentialID: "pk-2"}))
	got, err = wis.GetByID(ctx, id)
	require.NoError(t, err)
	require.Equal(t, "pk-1", got.CredentialID, "first link wins; a later attestation cannot move it")
	require.EqualValues(t, 3, got.AttestationCount, "the attestation itself is still recorded")

	// A brand-new instance that presents a link on its first attestation gets it.
	require.NoError(t, wis.Upsert(ctx, &domain.WalletInstance{ID: id + "-2", TenantID: "acme", Status: domain.InstanceStatusActive, CredentialID: "pk-9"}))
	got, err = wis.GetByID(ctx, id+"-2")
	require.NoError(t, err)
	require.Equal(t, "pk-9", got.CredentialID)
}

func TestWalletInstanceStore_Upsert_FirstUserBindingWins(t *testing.T) {
	store := skipIfNoMongo(t)
	ctx := context.Background()
	wis := store.WalletInstances()
	id := "inst-first-user-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	a, b := domain.NewUserID(), domain.NewUserID()

	require.NoError(t, wis.Upsert(ctx, &domain.WalletInstance{ID: id, TenantID: "acme", Status: domain.InstanceStatusActive}))
	require.NoError(t, wis.Upsert(ctx, &domain.WalletInstance{ID: id, TenantID: "acme", Status: domain.InstanceStatusActive, UserID: &a}))
	require.NoError(t, wis.Upsert(ctx, &domain.WalletInstance{ID: id, TenantID: "acme", Status: domain.InstanceStatusActive, UserID: &b}))
	got, err := wis.GetByID(ctx, id)
	require.NoError(t, err)
	require.NotNil(t, got.UserID)
	require.Equal(t, a, *got.UserID, "first user binding wins")
	require.EqualValues(t, 3, got.AttestationCount)

	// A record created with a user keeps it too.
	require.NoError(t, wis.Upsert(ctx, &domain.WalletInstance{ID: id + "-2", TenantID: "acme", Status: domain.InstanceStatusActive, UserID: &b}))
	require.NoError(t, wis.Upsert(ctx, &domain.WalletInstance{ID: id + "-2", TenantID: "acme", Status: domain.InstanceStatusActive, UserID: &a}))
	got, err = wis.GetByID(ctx, id+"-2")
	require.NoError(t, err)
	require.Equal(t, b, *got.UserID)
}

// The instance key is global while the record belongs to one tenant, so an
// attestation from another tenant is refused outright - it must not even
// bump the attestation metadata of the owning tenant's record.
func TestWalletInstanceStore_Upsert_RefusesAnotherTenantsRecord(t *testing.T) {
	store := skipIfNoMongo(t)
	ctx := context.Background()
	wis := store.WalletInstances()
	id := "inst-tenant-fixed-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	require.NoError(t, wis.Upsert(ctx, &domain.WalletInstance{ID: id, TenantID: "acme", Status: domain.InstanceStatusActive, AttestationSource: "first"}))
	require.ErrorIs(t, wis.Upsert(ctx, &domain.WalletInstance{ID: id, TenantID: "other", Status: domain.InstanceStatusActive, AttestationSource: "intruder"}), storage.ErrAlreadyExists)
	got, err := wis.GetByID(ctx, id)
	require.NoError(t, err)
	require.Equal(t, domain.TenantID("acme"), got.TenantID, "tenant is fixed at insert")
	require.Equal(t, "first", got.AttestationSource, "metadata untouched")
	require.EqualValues(t, 1, got.AttestationCount, "the refused attestation is not counted")
}

// A losing cross-tenant first attestation must not bind its user, or link its
// passkey, onto the record the winner inserted. tenant_id is fixed at insert,
// so the loser cannot move the record - but a bind or link that landed anyway
// would be permanent, and the read-back that refuses the loser's WIA cannot
// undo it.
func TestWalletInstanceStore_Upsert_OwnershipWritesAreTenantScoped(t *testing.T) {
	store := skipIfNoMongo(t)
	ctx := context.Background()
	wis := store.WalletInstances()
	id := "inst-tenant-own-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	winner, loser := domain.NewUserID(), domain.NewUserID()

	require.NoError(t, wis.Upsert(ctx, &domain.WalletInstance{ID: id, TenantID: "acme", Status: domain.InstanceStatusActive}))
	// The loser's attestation: same instance key, another tenant.
	require.ErrorIs(t, wis.Upsert(ctx, &domain.WalletInstance{ID: id, TenantID: "other", Status: domain.InstanceStatusActive, UserID: &loser, CredentialID: "pk-loser"}), storage.ErrAlreadyExists)
	got, err := wis.GetByID(ctx, id)
	require.NoError(t, err)
	require.Equal(t, domain.TenantID("acme"), got.TenantID)
	require.Nil(t, got.UserID, "a user of another tenant must not be bound")
	require.Empty(t, got.CredentialID, "a passkey of another tenant must not be linked")

	// The record's own tenant still binds and links normally.
	require.NoError(t, wis.Upsert(ctx, &domain.WalletInstance{ID: id, TenantID: "acme", Status: domain.InstanceStatusActive, UserID: &winner, CredentialID: "pk-winner"}))
	got, err = wis.GetByID(ctx, id)
	require.NoError(t, err)
	require.NotNil(t, got.UserID)
	require.Equal(t, winner, *got.UserID)
	require.Equal(t, "pk-winner", got.CredentialID)
}

// The passkey link may only be written by the user the record is actually
// bound to: a same-tenant racer whose own bind lost must not get its
// credential id onto the winner's record, where it would decide the
// per-instance login gate (SID-AUTH-06) for good.
func TestWalletInstanceStore_Upsert_CredentialLinkNeedsTheBoundUser(t *testing.T) {
	store := skipIfNoMongo(t)
	ctx := context.Background()
	wis := store.WalletInstances()
	id := "inst-link-owner-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	winner, loser := domain.NewUserID(), domain.NewUserID()

	require.NoError(t, wis.Upsert(ctx, &domain.WalletInstance{ID: id, TenantID: "acme", Status: domain.InstanceStatusActive, UserID: &winner}))
	require.NoError(t, wis.Upsert(ctx, &domain.WalletInstance{ID: id, TenantID: "acme", Status: domain.InstanceStatusActive, UserID: &loser, CredentialID: "pk-loser"}))
	got, err := wis.GetByID(ctx, id)
	require.NoError(t, err)
	require.Equal(t, winner, *got.UserID, "first user binding still wins")
	require.Empty(t, got.CredentialID, "only the bound user may link a passkey")

	require.NoError(t, wis.Upsert(ctx, &domain.WalletInstance{ID: id, TenantID: "acme", Status: domain.InstanceStatusActive, UserID: &winner, CredentialID: "pk-winner"}))
	got, err = wis.GetByID(ctx, id)
	require.NoError(t, err)
	require.Equal(t, "pk-winner", got.CredentialID)
}
