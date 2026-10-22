package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage/memory"
	"github.com/sirosfoundation/go-wallet-backend/internal/tokengate"
)

// fenceHookInstances runs a hook right after the instance write lands, to
// play an account deletion or revocation winning on another replica.
type fenceHookInstances struct {
	storage.WalletInstanceStore
	hook func()
}

func (a *fenceHookInstances) Upsert(ctx context.Context, inst *domain.WalletInstance) error {
	if err := a.WalletInstanceStore.Upsert(ctx, inst); err != nil {
		return err
	}
	a.hook()
	return nil
}

func deleteAccount(t *testing.T, store storage.Store, uid domain.UserID) func() {
	return func() {
		ctx := context.Background()
		if err := store.Users().Delete(ctx, uid); err != nil {
			t.Errorf("delete user: %v", err)
		}
		now := time.Now()
		if err := store.Users().PutDeletionTombstone(ctx, &domain.DeletionTombstone{
			UserID: uid.String(), DeletedAt: now, ExpiresAt: now.Add(time.Hour),
		}); err != nil {
			t.Errorf("tombstone: %v", err)
		}
	}
}

func advanceCutoff(t *testing.T, store storage.Store, uid domain.UserID) func() {
	return func() {
		ctx := context.Background()
		u, err := store.Users().GetByID(ctx, uid)
		if err != nil {
			t.Errorf("get user: %v", err)
			return
		}
		u.AuthInvalidBefore = time.Now().Add(time.Minute)
		if err := store.Users().Update(ctx, u); err != nil {
			t.Errorf("advance cut-off: %v", err)
		}
	}
}

// attestWithRace attests (first, or again when the key is passed) while hook
// runs right after the instance write. It returns the instance id and error.
func attestWithRace(t *testing.T, hook func(store storage.Store, uid domain.UserID) func(), preexisting bool) (storage.Store, string, error) {
	t.Helper()
	store := memory.NewStore()
	uid := domain.NewUserID()
	ctx := context.Background()
	if err := store.Users().Create(ctx, &domain.User{UUID: uid, DID: "did:key:" + uid.String()}); err != nil {
		t.Fatal(err)
	}
	wrapped := &fenceHookInstances{WalletInstanceStore: store.WalletInstances(), hook: func() {}}
	svc := newTestWIAServiceUsingStores(t, wrapped, store.Users())
	tok := tokengate.WithSubject(ctx, uid.String(), time.Now().Add(-time.Minute))

	challenge, _, err := svc.CreateChallenge(ctx, domain.DefaultTenantID)
	if err != nil {
		t.Fatal(err)
	}
	pop, key := createTestPop(t, challenge)
	jkt := expectedThumbprint(t, &key.PublicKey)
	if preexisting {
		if _, err := svc.GenerateWIA(tok, domain.DefaultTenantID, &uid, &WIARequest{Pop: pop, Challenge: challenge}); err != nil {
			t.Fatalf("seed attestation: %v", err)
		}
		challenge, _, err = svc.CreateChallenge(ctx, domain.DefaultTenantID)
		if err != nil {
			t.Fatal(err)
		}
		pop = createTestPopWithKey(t, challenge, key)
	}
	wrapped.hook = hook(store, uid)
	_, err = svc.GenerateWIA(tok, domain.DefaultTenantID, &uid, &WIARequest{Pop: pop, Challenge: challenge})
	return store, jkt, err
}

func TestWIAService_GenerateWIA_DeletionWinningAfterTheWriteRemovesTheNewInstance(t *testing.T) {
	store, jkt, err := attestWithRace(t, func(s storage.Store, u domain.UserID) func() { return deleteAccount(t, s, u) }, false)
	if !errors.Is(err, tokengate.ErrAccountDeleted) {
		t.Fatalf("err = %v, want ErrAccountDeleted", err)
	}
	if _, gerr := store.WalletInstances().GetByID(context.Background(), jkt); !errors.Is(gerr, storage.ErrNotFound) {
		t.Fatalf("the instance written for a deleted account must be rolled back, GetByID = %v", gerr)
	}
}

func TestWIAService_GenerateWIA_DeletionWinningAfterTheWriteRemovesARecreatedInstance(t *testing.T) {
	store, jkt, err := attestWithRace(t, func(s storage.Store, u domain.UserID) func() { return deleteAccount(t, s, u) }, true)
	if !errors.Is(err, tokengate.ErrAccountDeleted) {
		t.Fatalf("err = %v, want ErrAccountDeleted", err)
	}
	if _, gerr := store.WalletInstances().GetByID(context.Background(), jkt); !errors.Is(gerr, storage.ErrNotFound) {
		t.Fatalf("the instance must not outlive the deletion, GetByID = %v", gerr)
	}
}

func TestWIAService_GenerateWIA_CutoffAfterTheWriteRemovesOnlyANewInstance(t *testing.T) {
	cut := func(s storage.Store, u domain.UserID) func() { return advanceCutoff(t, s, u) }

	store, jkt, err := attestWithRace(t, cut, false)
	if !errors.Is(err, tokengate.ErrRevoked) {
		t.Fatalf("err = %v, want ErrRevoked", err)
	}
	if _, gerr := store.WalletInstances().GetByID(context.Background(), jkt); !errors.Is(gerr, storage.ErrNotFound) {
		t.Fatalf("a new instance must be rolled back, GetByID = %v", gerr)
	}

	store, jkt, err = attestWithRace(t, cut, true)
	if !errors.Is(err, tokengate.ErrRevoked) {
		t.Fatalf("err = %v, want ErrRevoked", err)
	}
	if _, gerr := store.WalletInstances().GetByID(context.Background(), jkt); gerr != nil {
		t.Fatalf("a pre-existing instance survives a plain revocation, GetByID = %v", gerr)
	}
}

// lateCutoffUsers advances the cut-off right after the first cut-off read that
// follows arm(): that read is the in-lock fence, so the final gate sees it.
type lateCutoffUsers struct {
	storage.UserStore
	armed   bool
	advance func()
}

func (u *lateCutoffUsers) GetAuthCutoff(ctx context.Context, id domain.UserID) (time.Time, error) {
	at, err := u.UserStore.GetAuthCutoff(ctx, id)
	if u.armed {
		u.armed = false
		u.advance()
	}
	return at, err
}

func TestWIAService_GenerateWIA_CutoffAfterTheFenceRemovesOnlyANewInstance(t *testing.T) {
	for _, preexisting := range []bool{false, true} {
		store := memory.NewStore()
		uid := domain.NewUserID()
		ctx := context.Background()
		if err := store.Users().Create(ctx, &domain.User{UUID: uid, DID: "did:key:" + uid.String()}); err != nil {
			t.Fatal(err)
		}
		users := &lateCutoffUsers{UserStore: store.Users(), advance: advanceCutoff(t, store, uid)}
		wrapped := &fenceHookInstances{WalletInstanceStore: store.WalletInstances(), hook: func() {}}
		svc := newTestWIAServiceUsingStores(t, wrapped, users)
		tok := tokengate.WithSubject(ctx, uid.String(), time.Now().Add(-time.Minute))

		challenge, _, err := svc.CreateChallenge(ctx, domain.DefaultTenantID)
		if err != nil {
			t.Fatal(err)
		}
		pop, key := createTestPop(t, challenge)
		jkt := expectedThumbprint(t, &key.PublicKey)
		if preexisting {
			if _, err := svc.GenerateWIA(tok, domain.DefaultTenantID, &uid, &WIARequest{Pop: pop, Challenge: challenge}); err != nil {
				t.Fatalf("seed attestation: %v", err)
			}
			if challenge, _, err = svc.CreateChallenge(ctx, domain.DefaultTenantID); err != nil {
				t.Fatal(err)
			}
			pop = createTestPopWithKey(t, challenge, key)
		}
		wrapped.hook = func() { users.armed = true }
		_, err = svc.GenerateWIA(tok, domain.DefaultTenantID, &uid, &WIARequest{Pop: pop, Challenge: challenge})
		if !errors.Is(err, tokengate.ErrRevoked) {
			t.Fatalf("preexisting=%v: err = %v, want ErrRevoked", preexisting, err)
		}
		_, gerr := store.WalletInstances().GetByID(ctx, jkt)
		if preexisting && gerr != nil {
			t.Fatalf("a pre-existing instance survives a plain revocation, GetByID = %v", gerr)
		}
		if !preexisting && !errors.Is(gerr, storage.ErrNotFound) {
			t.Fatalf("a new instance must be rolled back, GetByID = %v", gerr)
		}
	}
}

// raceInstances plays another replica creating the same instance after this
// request's GetByID returned not-found but before its Upsert runs.
type raceInstances struct {
	storage.WalletInstanceStore
	before func()
	after  func()
}

func (r *raceInstances) Upsert(ctx context.Context, inst *domain.WalletInstance) error {
	if r.before != nil {
		r.before()
	}
	if err := r.WalletInstanceStore.Upsert(ctx, inst); err != nil {
		return err
	}
	if r.after != nil {
		r.after()
	}
	return nil
}

// A record that another replica created between GetByID and Upsert is not this
// request's write: a cut-off landing during the write must not delete it.
func TestWIAService_GenerateWIA_CutoffDoesNotDeleteARecordAnotherReplicaCreatedFirst(t *testing.T) {
	store := memory.NewStore()
	uid := domain.NewUserID()
	ctx := context.Background()
	if err := store.Users().Create(ctx, &domain.User{UUID: uid, DID: "did:key:" + uid.String()}); err != nil {
		t.Fatal(err)
	}
	race := &raceInstances{WalletInstanceStore: store.WalletInstances()}
	svc := newTestWIAServiceUsingStores(t, race, store.Users())
	tok := tokengate.WithSubject(ctx, uid.String(), time.Now().Add(-time.Minute))

	challenge, _, err := svc.CreateChallenge(ctx, domain.DefaultTenantID)
	if err != nil {
		t.Fatal(err)
	}
	pop, key := createTestPop(t, challenge)
	jkt := expectedThumbprint(t, &key.PublicKey)

	race.before = func() {
		other := &domain.WalletInstance{ID: jkt, TenantID: domain.DefaultTenantID, UserID: &uid, Status: domain.InstanceStatusActive}
		if err := store.WalletInstances().Upsert(ctx, other); err != nil {
			t.Errorf("other replica: %v", err)
		}
		if !other.Inserted {
			t.Error("the other replica's Upsert must report the insert")
		}
	}
	race.after = advanceCutoff(t, store, uid)

	_, err = svc.GenerateWIA(tok, domain.DefaultTenantID, &uid, &WIARequest{Pop: pop, Challenge: challenge})
	if !errors.Is(err, tokengate.ErrRevoked) {
		t.Fatalf("err = %v, want ErrRevoked", err)
	}
	if _, gerr := store.WalletInstances().GetByID(ctx, jkt); gerr != nil {
		t.Fatalf("another replica's record must survive this request's cut-off, GetByID = %v", gerr)
	}
}

// A cut-off landing after the write must not leave a pre-existing anonymous
// instance bound to the refused caller, nor with the attestation counted.
func TestWIAService_GenerateWIA_CutoffAfterTheWriteRestoresAPreExistingInstance(t *testing.T) {
	store := memory.NewStore()
	uid := domain.NewUserID()
	ctx := context.Background()
	if err := store.Users().Create(ctx, &domain.User{UUID: uid, DID: "did:key:" + uid.String()}); err != nil {
		t.Fatal(err)
	}
	wrapped := &fenceHookInstances{WalletInstanceStore: store.WalletInstances(), hook: func() {}}
	svc := newTestWIAServiceUsingStores(t, wrapped, store.Users())
	tok := tokengate.WithSubject(ctx, uid.String(), time.Now().Add(-time.Minute))

	challenge, _, err := svc.CreateChallenge(ctx, domain.DefaultTenantID)
	if err != nil {
		t.Fatal(err)
	}
	pop, key := createTestPop(t, challenge)
	jkt := expectedThumbprint(t, &key.PublicKey)
	if _, err := svc.GenerateWIA(ctx, domain.DefaultTenantID, nil, &WIARequest{Pop: pop, Challenge: challenge}); err != nil {
		t.Fatalf("anonymous seed attestation: %v", err)
	}
	seeded, err := store.WalletInstances().GetByID(ctx, jkt)
	if err != nil || seeded.UserID != nil {
		t.Fatalf("seed must be an unowned instance: %v %+v", err, seeded)
	}
	if challenge, _, err = svc.CreateChallenge(ctx, domain.DefaultTenantID); err != nil {
		t.Fatal(err)
	}
	pop = createTestPopWithKey(t, challenge, key)
	wrapped.hook = advanceCutoff(t, store, uid)
	if _, err = svc.GenerateWIA(tok, domain.DefaultTenantID, &uid, &WIARequest{Pop: pop, Challenge: challenge}); !errors.Is(err, tokengate.ErrRevoked) {
		t.Fatalf("err = %v, want ErrRevoked", err)
	}
	got, err := store.WalletInstances().GetByID(ctx, jkt)
	if err != nil {
		t.Fatalf("the pre-existing instance must survive: %v", err)
	}
	if got.UserID != nil {
		t.Errorf("a refused request must not leave the instance bound to %v", *got.UserID)
	}
	if got.AttestationCount != seeded.AttestationCount {
		t.Errorf("attestation count = %d, want %d", got.AttestationCount, seeded.AttestationCount)
	}
	if !got.LastAttestedAt.Equal(seeded.LastAttestedAt) {
		t.Errorf("last attested at changed by a refused request")
	}
}

// A revocation landing after the write makes the post-write recheck refuse the
// request; the pre-existing record must not keep this request's owner bind or
// attestation count, and the revocation's status stays.
func TestWIAService_GenerateWIA_RecheckFailureRestoresAPreExistingInstance(t *testing.T) {
	store := memory.NewStore()
	uid := domain.NewUserID()
	ctx := context.Background()
	if err := store.Users().Create(ctx, &domain.User{UUID: uid, DID: "did:key:" + uid.String()}); err != nil {
		t.Fatal(err)
	}
	wrapped := &fenceHookInstances{WalletInstanceStore: store.WalletInstances(), hook: func() {}}
	svc := newTestWIAServiceUsingStores(t, wrapped, store.Users())
	tok := tokengate.WithSubject(ctx, uid.String(), time.Now().Add(-time.Minute))

	challenge, _, err := svc.CreateChallenge(ctx, domain.DefaultTenantID)
	if err != nil {
		t.Fatal(err)
	}
	pop, key := createTestPop(t, challenge)
	jkt := expectedThumbprint(t, &key.PublicKey)
	if _, err := svc.GenerateWIA(ctx, domain.DefaultTenantID, nil, &WIARequest{Pop: pop, Challenge: challenge}); err != nil {
		t.Fatalf("anonymous seed attestation: %v", err)
	}
	seeded, err := store.WalletInstances().GetByID(ctx, jkt)
	if err != nil {
		t.Fatal(err)
	}
	if challenge, _, err = svc.CreateChallenge(ctx, domain.DefaultTenantID); err != nil {
		t.Fatal(err)
	}
	pop = createTestPopWithKey(t, challenge, key)
	wrapped.hook = func() {
		if err := store.WalletInstances().UpdateStatus(ctx, jkt, domain.DefaultTenantID, domain.InstanceStatusRevoked, "revoked meanwhile"); err != nil {
			t.Errorf("revoke: %v", err)
		}
	}
	if _, err = svc.GenerateWIA(tok, domain.DefaultTenantID, &uid, &WIARequest{Pop: pop, Challenge: challenge}); !errors.Is(err, ErrWIAInstanceDeactivated) {
		t.Fatalf("err = %v, want ErrWIAInstanceDeactivated", err)
	}
	got, err := store.WalletInstances().GetByID(ctx, jkt)
	if err != nil {
		t.Fatalf("the record must survive: %v", err)
	}
	if got.Status != domain.InstanceStatusRevoked {
		t.Errorf("status = %s, the revocation must stand", got.Status)
	}
	if got.UserID != nil {
		t.Errorf("a refused request left the instance bound to %v", *got.UserID)
	}
	if got.AttestationCount != seeded.AttestationCount {
		t.Errorf("attestation count = %d, want %d", got.AttestationCount, seeded.AttestationCount)
	}
}
