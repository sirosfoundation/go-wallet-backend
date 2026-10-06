package service

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage/memory"
	jwkpkg "github.com/sirosfoundation/go-wallet-backend/pkg/jwk"
)

// racingCorruptInstances models the sibling instance ending up with an
// unrecognised status between GenerateWIA's check and the post-insert
// re-check: right after the first Upsert every other instance of the user is
// revoked and a sibling with unknownInstanceStatus appears.
type racingCorruptInstances struct {
	storage.WalletInstanceStore
	userID domain.UserID
	fired  bool
}

func (r *racingCorruptInstances) Upsert(ctx context.Context, inst *domain.WalletInstance) error {
	if err := r.WalletInstanceStore.Upsert(ctx, inst); err != nil {
		return err
	}
	if r.fired {
		return nil
	}
	r.fired = true
	others, err := r.WalletInstanceStore.GetByUser(ctx, inst.TenantID, r.userID)
	if err != nil {
		return err
	}
	for _, o := range others {
		if o.ID != inst.ID {
			if err := r.WalletInstanceStore.UpdateStatus(ctx, o.ID, domain.DefaultTenantID, domain.InstanceStatusRevoked, "raced"); err != nil {
				return err
			}
		}
	}
	// Upsert preserves the status of an existing record, so the corrupt
	// sibling arrives as a new record.
	return r.WalletInstanceStore.Upsert(ctx, &domain.WalletInstance{
		ID: "corrupt-sibling", TenantID: inst.TenantID, UserID: &r.userID, Status: unknownInstanceStatus,
	})
}

// An unrecognised sibling status is not evidence of deactivation: the racing
// first attestation is refused, the new instance is NOT revoked and nothing
// is erased.
func TestWIAService_GenerateWIA_UnknownStatusSiblingRefusesWithoutRevoking(t *testing.T) {
	uid := domain.UserIDFromString("user-unknown-sibling")
	base := memory.NewStore().WalletInstances()
	seedWIAInstance(t, base, "old-key", uid, domain.InstanceStatusActive)
	racing := &racingCorruptInstances{WalletInstanceStore: base, userID: uid}
	svc := newTestWIAServiceUsing(t, racing)
	ctx := context.Background()

	challenge, _, err := svc.CreateChallenge(ctx, domain.DefaultTenantID)
	require.NoError(t, err)
	pop, _ := createTestPop(t, challenge)
	wia, err := svc.GenerateWIA(ctx, domain.DefaultTenantID, &uid, &WIARequest{Pop: pop, Challenge: challenge})
	require.Error(t, err)
	assert.Empty(t, wia)
	assert.NotErrorIs(t, err, ErrWIAInstanceDeactivated, "no lifecycle state was established")
	assert.Contains(t, err.Error(), "unrecognized status")

	byUser, err := base.GetByUser(ctx, domain.DefaultTenantID, uid)
	require.NoError(t, err)
	require.Len(t, byUser, 3)
	for _, inst := range byUser {
		switch inst.ID {
		case "old-key": // revoked by the simulated race itself
		case "corrupt-sibling":
			assert.Equal(t, unknownInstanceStatus, inst.Status, "the corrupt record is left alone")
		default:
			assert.Equal(t, domain.InstanceStatusActive, inst.Status, "the new instance must not be revoked")
		}
	}
}

func TestWIAService_RevokeIfWalletDeactivatedMeanwhile_UnknownStatus(t *testing.T) {
	ctx := context.Background()

	t.Run("revoked + unknown sibling: refused, nothing revoked or erased", func(t *testing.T) {
		fs := newFailStore()
		svc := newTestWIAServiceUsingStores(t, fs.WalletInstances(), fs.Users())
		svc.SetLifecycle(NewWalletLifecycleService(fs, zap.NewNop(), nil))
		uid := seedWalletUser(t, fs.Store)
		require.NoError(t, fs.Store.WalletInstances().UpdateStatus(ctx, "inst-"+uid.String(), domain.DefaultTenantID, domain.InstanceStatusRevoked, "x"))
		seedRawInstance(t, fs.Store, domain.DefaultTenantID, "corrupt", uid, "", unknownInstanceStatus)
		require.NoError(t, fs.Store.WalletInstances().Upsert(ctx, &domain.WalletInstance{
			ID: "raced", TenantID: domain.DefaultTenantID, UserID: &uid, Status: domain.InstanceStatusActive,
		}))

		err := svc.revokeIfWalletDeactivatedMeanwhile(ctx, domain.DefaultTenantID, &uid, "raced")
		require.Error(t, err)
		assert.NotErrorIs(t, err, ErrWIAInstanceDeactivated)

		got, gerr := fs.Store.WalletInstances().GetByID(ctx, "raced")
		require.NoError(t, gerr)
		assert.Equal(t, domain.InstanceStatusActive, got.Status)
		u, gerr := fs.Store.Users().GetByID(ctx, uid)
		require.NoError(t, gerr)
		assert.NotEmpty(t, u.PrivateData, "the vault must not be erased")
		cutoff, _ := fs.Store.Users().GetAuthCutoff(ctx, uid)
		assert.True(t, cutoff.IsZero(), "tokens must not be cut off")
	})

	t.Run("revoked-only siblings: existing behaviour preserved", func(t *testing.T) {
		fs := newFailStore()
		svc := newTestWIAServiceUsingStores(t, fs.WalletInstances(), fs.Users())
		svc.SetLifecycle(NewWalletLifecycleService(fs, zap.NewNop(), nil))
		uid := seedWalletUser(t, fs.Store)
		require.NoError(t, fs.Store.WalletInstances().UpdateStatus(ctx, "inst-"+uid.String(), domain.DefaultTenantID, domain.InstanceStatusRevoked, "x"))
		require.NoError(t, fs.Store.WalletInstances().Upsert(ctx, &domain.WalletInstance{
			ID: "raced", TenantID: domain.DefaultTenantID, UserID: &uid, Status: domain.InstanceStatusActive,
		}))
		err := svc.revokeIfWalletDeactivatedMeanwhile(ctx, domain.DefaultTenantID, &uid, "raced")
		assert.ErrorIs(t, err, ErrWIAInstanceDeactivated)
		got, gerr := fs.Store.WalletInstances().GetByID(ctx, "raced")
		require.NoError(t, gerr)
		assert.Equal(t, domain.InstanceStatusRevoked, got.Status)
	})
}

// The pre-insert gate also fails closed on an unrecognised status without
// claiming the wallet is deactivated.
func TestWIAService_GenerateWIA_UnknownStatusSiblingRefusedBeforeInsert(t *testing.T) {
	svc, instances := newTestWIAServiceWithInstances(t)
	ctx := context.Background()
	uid := domain.UserIDFromString("user-unknown-pre")
	seedWIAInstance(t, instances, "old-key-1", uid, domain.InstanceStatusRevoked)
	require.NoError(t, instances.Upsert(ctx, &domain.WalletInstance{
		ID: "old-key-2", TenantID: domain.DefaultTenantID, UserID: &uid, Status: unknownInstanceStatus,
	}))

	challenge, _, err := svc.CreateChallenge(ctx, domain.DefaultTenantID)
	require.NoError(t, err)
	pop, _ := createTestPop(t, challenge)
	_, err = svc.GenerateWIA(ctx, domain.DefaultTenantID, &uid, &WIARequest{Pop: pop, Challenge: challenge})
	require.Error(t, err)
	assert.False(t, errors.Is(err, ErrWIAInstanceDeactivated))
	byUser, err := instances.GetByUser(ctx, domain.DefaultTenantID, uid)
	require.NoError(t, err)
	assert.Len(t, byUser, 2, "no new instance recorded")
}

// statusOverrideInstances reports unknownInstanceStatus for id once armed,
// modelling a record whose stored status this build does not recognize.
type statusOverrideInstances struct {
	storage.WalletInstanceStore
	id    string
	armed func() bool
}

func (o *statusOverrideInstances) GetByID(ctx context.Context, id string) (*domain.WalletInstance, error) {
	inst, err := o.WalletInstanceStore.GetByID(ctx, id)
	if err != nil || id != o.id || !o.armed() {
		return inst, err
	}
	cp := *inst
	cp.Status = unknownInstanceStatus
	return &cp, nil
}

// An unrecognized status on the attesting instance's own record is refused
// without INSTANCE_DEACTIVATED: nothing established a deactivation.
func TestWIAService_GenerateWIA_UnknownOwnStatusIsNotDeactivation(t *testing.T) {
	ctx := context.Background()
	base := memory.NewStore().WalletInstances()
	svc0 := newTestWIAServiceUsing(t, base)
	challenge, _, err := svc0.CreateChallenge(ctx, domain.DefaultTenantID)
	require.NoError(t, err)
	pop, key := createTestPop(t, challenge)
	_, err = svc0.GenerateWIA(ctx, domain.DefaultTenantID, nil, &WIARequest{Pop: pop, Challenge: challenge})
	require.NoError(t, err)
	jkt, err := jwkpkg.Thumbprint(map[string]interface{}{
		"kty": "EC", "crv": "P-256",
		"x": base64.RawURLEncoding.EncodeToString(key.PublicKey.X.FillBytes(make([]byte, 32))),
		"y": base64.RawURLEncoding.EncodeToString(key.PublicKey.Y.FillBytes(make([]byte, 32))),
	})
	require.NoError(t, err)

	t.Run("pre-write gate", func(t *testing.T) {
		svc := newTestWIAServiceUsing(t, &statusOverrideInstances{WalletInstanceStore: base, id: jkt, armed: func() bool { return true }})
		c, _, err := svc.CreateChallenge(ctx, domain.DefaultTenantID)
		require.NoError(t, err)
		_, err = svc.GenerateWIA(ctx, domain.DefaultTenantID, nil, &WIARequest{Pop: createTestPopWithKey(t, c, key), Challenge: c})
		require.Error(t, err)
		assert.NotErrorIs(t, err, ErrWIAInstanceDeactivated)
		assert.Contains(t, err.Error(), "unrecognized status")
	})

	t.Run("post-write re-check", func(t *testing.T) {
		fresh := memory.NewStore().WalletInstances()
		upserted := false
		o := &afterUpsertInstances{WalletInstanceStore: fresh, upserted: &upserted}
		svc := newTestWIAServiceUsing(t, &statusOverrideInstances{WalletInstanceStore: o, id: jkt, armed: func() bool { return upserted }})
		c, _, err := svc.CreateChallenge(ctx, domain.DefaultTenantID)
		require.NoError(t, err)
		_, err = svc.GenerateWIA(ctx, domain.DefaultTenantID, nil, &WIARequest{Pop: createTestPopWithKey(t, c, key), Challenge: c})
		require.Error(t, err)
		assert.NotErrorIs(t, err, ErrWIAInstanceDeactivated)
		assert.Contains(t, err.Error(), "unrecognized status")
	})
}

type afterUpsertInstances struct {
	storage.WalletInstanceStore
	upserted *bool
}

func (a *afterUpsertInstances) Upsert(ctx context.Context, inst *domain.WalletInstance) error {
	err := a.WalletInstanceStore.Upsert(ctx, inst)
	*a.upserted = true
	return err
}
