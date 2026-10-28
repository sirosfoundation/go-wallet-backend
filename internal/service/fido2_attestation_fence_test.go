package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage/memory"
	"github.com/sirosfoundation/go-wallet-backend/internal/tokengate"
)

// A store failure is a server error, not an invalid attestation.
type failingMarkAttested struct{ storage.KeyAttestationStore }

func (failingMarkAttested) MarkKeyAttested(context.Context, *domain.KeyAttestationRecord) error {
	return storage.ErrDatabase
}

func TestFIDO2AttestationService_Verify_StoreFailureIsNotAnInvalidAttestation(t *testing.T) {
	ctx := context.Background()
	store := memory.NewStore()
	if err := store.WalletInstances().Upsert(ctx, &domain.WalletInstance{ID: "inst", Status: domain.InstanceStatusActive}); err != nil {
		t.Fatal(err)
	}
	svc := NewFIDO2AttestationService(testFIDO2AttestationConfig(true), store.WalletInstances(),
		failingMarkAttested{store.KeyAttestations()}, newTestTrustService(t, &stubEvaluator{decision: true}), zap.NewNop())
	clientDataHash := make([]byte, 32)
	attObj, _ := buildTestAttestationObject(t, uuid.New(), clientDataHash)

	err := svc.Verify(ctx, &FIDO2AttestationRequest{WalletInstanceID: "inst", AttestationObject: attObj, ClientDataHash: clientDataHash})
	if !errors.Is(err, storage.ErrDatabase) || errors.Is(err, ErrFIDO2AttestationInvalid) {
		t.Fatalf("Verify = %v, want a storage error that is not ErrFIDO2AttestationInvalid", err)
	}
}

// A cut-off landing after the evidence write rolls it back: a new record is
// removed, an overwritten one is restored.
type cutoffAfterMark struct {
	storage.KeyAttestationStore
	users storage.UserStore
	uid   domain.UserID
	armed bool
}

func (c *cutoffAfterMark) MarkKeyAttested(ctx context.Context, rec *domain.KeyAttestationRecord) error {
	if err := c.KeyAttestationStore.MarkKeyAttested(ctx, rec); err != nil {
		return err
	}
	if c.armed {
		return c.users.InvalidateAuthBefore(ctx, c.uid, time.Now().Add(time.Minute))
	}
	return nil
}

func TestFIDO2AttestationService_Verify_CutoffRollsBackEvidence(t *testing.T) {
	for _, tc := range []struct {
		name      string
		preexists bool
	}{{"new evidence is removed", false}, {"overwritten evidence is restored", true}} {
		t.Run(tc.name, func(t *testing.T) {
			base := context.Background()
			store := memory.NewStore()
			uid := domain.NewUserID()
			require.NoError(t, store.Users().Create(base, &domain.User{UUID: uid}))
			require.NoError(t, store.WalletInstances().Upsert(base, &domain.WalletInstance{ID: "inst", TenantID: "acme", UserID: &uid, Status: domain.InstanceStatusActive}))
			kas := &cutoffAfterMark{KeyAttestationStore: store.KeyAttestations(), users: store.Users(), uid: uid}
			svc := NewFIDO2AttestationService(testFIDO2AttestationConfig(true), store.WalletInstances(), kas,
				newTestTrustService(t, &stubEvaluator{decision: true}), zap.NewNop())
			svc.SetUsers(store.Users())
			hash := make([]byte, 32)
			attObj, pub := buildTestAttestationObject(t, uuid.New(), hash)
			ctx := WithKeyAttestationTenant(tokengate.WithSubject(base, uid.String(), time.Now()), "acme")
			req := &FIDO2AttestationRequest{WalletInstanceID: "inst", AttestationObject: attObj, ClientDataHash: hash}
			thumb := expectedThumbprint(t, pub)

			var before *domain.KeyAttestationRecord
			if tc.preexists {
				require.NoError(t, svc.Verify(ctx, req))
				got, err := store.KeyAttestations().GetByKeyThumbprint(base, thumb)
				require.NoError(t, err)
				cp := *got
				before = &cp
			}
			kas.armed = true
			require.ErrorIs(t, svc.Verify(ctx, req), tokengate.ErrRevoked)

			got, err := store.KeyAttestations().GetByKeyThumbprint(base, thumb)
			if !tc.preexists {
				require.ErrorIs(t, err, storage.ErrNotFound)
				return
			}
			require.NoError(t, err, "the earlier evidence must survive the refused re-attestation")
			assert.Equal(t, before.VerifiedAt, got.VerifiedAt)
			assert.Equal(t, before.AAGUID, got.AAGUID)
			assert.Equal(t, before.CreatedAt, got.CreatedAt)
		})
	}
}

// revokeInstanceHook revokes the instance at a chosen point: after the nth
// GetByID of the instance (1 = the admission check, 2 = the pre-write check),
// or right after the evidence write.
type revokeInstanceHook struct {
	storage.WalletInstanceStore
	afterReads int
	reads      int
}

func (r *revokeInstanceHook) GetByID(ctx context.Context, id string) (*domain.WalletInstance, error) {
	inst, err := r.WalletInstanceStore.GetByID(ctx, id)
	r.reads++
	if err == nil && r.reads == r.afterReads {
		if uerr := r.WalletInstanceStore.UpdateStatus(ctx, id, inst.TenantID, domain.InstanceStatusRevoked, "raced"); uerr != nil {
			return nil, uerr
		}
	}
	return inst, err
}

type revokeAfterMark struct {
	storage.KeyAttestationStore
	revoke func()
}

func (r *revokeAfterMark) MarkKeyAttested(ctx context.Context, rec *domain.KeyAttestationRecord) error {
	if err := r.KeyAttestationStore.MarkKeyAttested(ctx, rec); err != nil {
		return err
	}
	r.revoke()
	return nil
}

// An instance revoked after the admission check, before or after the evidence
// write, must not keep evidence attached; an earlier record survives.
func TestFIDO2AttestationService_Verify_InstanceRevokedMidRequest(t *testing.T) {
	for _, tc := range []struct {
		name       string
		afterReads int // revoke after this GetByID; 0 = right after the write
		preexists  bool
	}{
		{"before the write", 1, false},
		{"after the write, new evidence", 0, false},
		{"after the write, overwrite", 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base := context.Background()
			store := memory.NewStore()
			uid := domain.NewUserID()
			require.NoError(t, store.Users().Create(base, &domain.User{UUID: uid}))
			require.NoError(t, store.WalletInstances().Upsert(base, &domain.WalletInstance{ID: "inst", TenantID: "acme", UserID: &uid, Status: domain.InstanceStatusActive}))
			hook := &revokeInstanceHook{WalletInstanceStore: store.WalletInstances()}
			var kas storage.KeyAttestationStore = store.KeyAttestations()
			svc := NewFIDO2AttestationService(testFIDO2AttestationConfig(true), hook, kas,
				newTestTrustService(t, &stubEvaluator{decision: true}), zap.NewNop())
			svc.SetUsers(store.Users())
			hash := make([]byte, 32)
			attObj, pub := buildTestAttestationObject(t, uuid.New(), hash)
			ctx := WithKeyAttestationTenant(tokengate.WithSubject(base, uid.String(), time.Now()), "acme")
			req := &FIDO2AttestationRequest{WalletInstanceID: "inst", AttestationObject: attObj, ClientDataHash: hash}
			thumb := expectedThumbprint(t, pub)

			var before domain.KeyAttestationRecord
			if tc.preexists {
				require.NoError(t, svc.Verify(ctx, req))
				got, err := store.KeyAttestations().GetByKeyThumbprint(base, thumb)
				require.NoError(t, err)
				before = *got
			}
			if tc.afterReads > 0 {
				hook.afterReads = hook.reads + tc.afterReads
			} else {
				svc.keyAttestations = &revokeAfterMark{KeyAttestationStore: kas, revoke: func() {
					require.NoError(t, store.WalletInstances().UpdateStatus(base, "inst", "acme", domain.InstanceStatusRevoked, "raced"))
				}}
			}
			require.ErrorIs(t, svc.Verify(ctx, req), tokengate.ErrRevoked)

			got, err := store.KeyAttestations().GetByKeyThumbprint(base, thumb)
			if !tc.preexists {
				require.ErrorIs(t, err, storage.ErrNotFound, "no evidence may stay attached to a revoked instance")
				return
			}
			require.NoError(t, err)
			assert.Equal(t, before.VerifiedAt, got.VerifiedAt)
		})
	}
}
