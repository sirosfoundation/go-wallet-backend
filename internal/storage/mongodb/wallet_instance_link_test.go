package mongodb

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
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

func TestWalletInstanceStore_Upsert_TenantIsFixedAtInsert(t *testing.T) {
	store := skipIfNoMongo(t)
	ctx := context.Background()
	wis := store.WalletInstances()
	id := "inst-tenant-fixed-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	require.NoError(t, wis.Upsert(ctx, &domain.WalletInstance{ID: id, TenantID: "acme", Status: domain.InstanceStatusActive}))
	require.NoError(t, wis.Upsert(ctx, &domain.WalletInstance{ID: id, TenantID: "other", Status: domain.InstanceStatusActive}))
	got, err := wis.GetByID(ctx, id)
	require.NoError(t, err)
	require.Equal(t, domain.TenantID("acme"), got.TenantID, "tenant is fixed at insert")
	require.EqualValues(t, 2, got.AttestationCount)
}
