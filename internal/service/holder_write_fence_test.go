package service

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage/memory"
	"github.com/sirosfoundation/go-wallet-backend/internal/tokengate"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

// Storage-level fence for holder writes (credential create/update,
// presentation create). Every test drives the real service over a store whose
// credential/presentation write is wrapped so an erasure can be interleaved at
// an exact point: between admission and the write, or between the write and the
// fence's re-read of the cut-off.

type raceStore struct {
	storage.Store
	beforeWrite func() // after admission, before the store write executes
	afterWrite  func() // after the store write persisted, before the re-read
	failDeletes atomic.Bool
}

type raceCreds struct {
	storage.CredentialStore
	s *raceStore
}

type racePres struct {
	storage.PresentationStore
	s *raceStore
}

func (s *raceStore) Credentials() storage.CredentialStore {
	return &raceCreds{s.Store.Credentials(), s}
}
func (s *raceStore) Presentations() storage.PresentationStore {
	return &racePres{s.Store.Presentations(), s}
}

func (c *raceCreds) Create(ctx context.Context, cred *domain.VerifiableCredential) error {
	if c.s.beforeWrite != nil {
		c.s.beforeWrite()
	}
	err := c.CredentialStore.Create(ctx, cred)
	if err == nil && c.s.afterWrite != nil {
		c.s.afterWrite()
	}
	return err
}

func (c *raceCreds) Update(ctx context.Context, cred *domain.VerifiableCredential) error {
	if c.s.beforeWrite != nil {
		c.s.beforeWrite()
	}
	err := c.CredentialStore.Update(ctx, cred)
	if err == nil && c.s.afterWrite != nil {
		c.s.afterWrite()
	}
	return err
}

func (c *raceCreds) Delete(ctx context.Context, t domain.TenantID, h, id string) error {
	if c.s.failDeletes.Load() {
		return errors.New("credential store delete is down")
	}
	return c.CredentialStore.Delete(ctx, t, h, id)
}

func (p *racePres) Create(ctx context.Context, pres *domain.VerifiablePresentation) error {
	if p.s.beforeWrite != nil {
		p.s.beforeWrite()
	}
	err := p.PresentationStore.Create(ctx, pres)
	if err == nil && p.s.afterWrite != nil {
		p.s.afterWrite()
	}
	return err
}

func (p *racePres) Delete(ctx context.Context, t domain.TenantID, h, id string) error {
	if p.s.failDeletes.Load() {
		return errors.New("presentation store delete is down")
	}
	return p.PresentationStore.Delete(ctx, t, h, id)
}

type fenceFixture struct {
	inner  *memory.Store
	rs     *raceStore
	creds  *CredentialService
	pres   *PresentationService
	uid    domain.UserID
	did    string
	tokCtx context.Context // request context carrying a token issued a minute ago
}

func newFenceFixture(t *testing.T) *fenceFixture {
	t.Helper()
	inner := memory.NewStore()
	rs := &raceStore{Store: inner}
	uid := seedWalletUser(t, inner)
	f := &fenceFixture{
		inner: inner, rs: rs, uid: uid, did: "did:example:" + uid.String(),
		creds: NewCredentialService(rs, &config.Config{}, zap.NewNop()),
		pres:  NewPresentationService(rs, zap.NewNop()),
	}
	f.tokCtx = tokengate.WithSubject(context.Background(), uid.String(), time.Now().Add(-time.Minute))
	return f
}

// lifecycleErase is the real lifecycle cascade: it advances the cut-off and
// sweeps holder data (RevokeAllForUser -> cascade -> eraseWalletData).
func (f *fenceFixture) lifecycleErase(t *testing.T) {
	t.Helper()
	svc := NewWalletLifecycleService(f.inner, zap.NewNop(), nil)
	_, err := svc.RevokeAllForUser(context.Background(), userActor(f.uid), domain.DefaultTenantID, f.uid, "test")
	require.NoError(t, err)
}

// cutoffThenSweep is the erasure's two steps in the order the invariant
// requires, without the rest of the cascade.
func (f *fenceFixture) cutoffThenSweep(t *testing.T) {
	t.Helper()
	require.NoError(t, f.inner.Users().InvalidateAuthBefore(context.Background(), f.uid, time.Now()))
	us := NewUserService(f.inner, testConfig(), zap.NewNop())
	require.Empty(t, us.eraseHolderData(context.Background(), domain.DefaultTenantID, f.did))
}

func (f *fenceFixture) holderData(t *testing.T) (int, int) {
	t.Helper()
	c, err := f.inner.Credentials().GetAllByHolder(context.Background(), domain.DefaultTenantID, f.did)
	if err != nil {
		require.ErrorIs(t, err, storage.ErrNotFound)
	}
	p, err := f.inner.Presentations().GetAllByHolder(context.Background(), domain.DefaultTenantID, f.did)
	if err != nil {
		require.ErrorIs(t, err, storage.ErrNotFound)
	}
	return len(c), len(p)
}

func (f *fenceFixture) storeCred(ctx context.Context, id string) error {
	_, err := f.creds.Store(ctx, domain.DefaultTenantID, &domain.StoreCredentialRequest{
		HolderDID: f.did, CredentialIdentifier: id, Credential: "jwt", Format: domain.FormatJWTVC,
	})
	return err
}

func (f *fenceFixture) storePres(ctx context.Context, id string) error {
	return f.pres.Store(ctx, domain.DefaultTenantID, &domain.VerifiablePresentation{
		HolderDID: f.did, PresentationIdentifier: id, Presentation: "jwt",
	})
}

// The three timings of an erasure relative to a holder write, for each creating
// write path.
func TestHolderWriteFence_CreateRacingAnErasure(t *testing.T) {
	writes := map[string]func(f *fenceFixture) error{
		"credential create":   func(f *fenceFixture) error { return f.storeCred(f.tokCtx, "late") },
		"presentation create": func(f *fenceFixture) error { return f.storePres(f.tokCtx, "late") },
	}
	erasers := map[string]func(t *testing.T, f *fenceFixture){
		"cut-off then sweep": func(t *testing.T, f *fenceFixture) { f.cutoffThenSweep(t) },
		"lifecycle cascade":  func(t *testing.T, f *fenceFixture) { f.lifecycleErase(t) },
	}
	for wname, write := range writes {
		for ename, erase := range erasers {
			t.Run(wname+"/"+ename+"/erasure between admission and write", func(t *testing.T) {
				f := newFenceFixture(t)
				f.rs.beforeWrite = func() { f.rs.beforeWrite = nil; erase(t, f) }

				err := write(f)

				require.ErrorIs(t, err, tokengate.ErrRevoked, "the caller learns the write was refused")
				assert.NotErrorIs(t, err, tokengate.ErrWriteNotRolledBack)
				c, p := f.holderData(t)
				assert.Zero(t, c+p, "the write landed after the sweep, so the fence must have rolled it back")
			})
			t.Run(wname+"/"+ename+"/erasure between write and re-read", func(t *testing.T) {
				f := newFenceFixture(t)
				f.rs.afterWrite = func() { f.rs.afterWrite = nil; erase(t, f) }

				err := write(f)

				require.ErrorIs(t, err, tokengate.ErrRevoked)
				c, p := f.holderData(t)
				assert.Zero(t, c+p, "the sweep removed the record; the fence's rollback finding it gone is fine")
			})
		}
	}
}

// A write landing between an erasure's cut-off advance and its sweep is
// removed by the sweep, even though the writer's own re-read happened first
// and passed (the cut-off had not advanced yet).
func TestHolderWriteFence_WriteBetweenCutoffAdvanceAndSweepIsSweptAway(t *testing.T) {
	f := newFenceFixture(t)
	// The write persists and its re-read passes; only then the erasure runs.
	require.NoError(t, f.storeCred(f.tokCtx, "kept-until-sweep"))
	require.NoError(t, f.storePres(f.tokCtx, "kept-until-sweep"))
	c, p := f.holderData(t)
	require.Equal(t, 1, c)
	require.Equal(t, 1, p)

	f.cutoffThenSweep(t)

	c, p = f.holderData(t)
	assert.Zero(t, c+p)
	// And the same token is refused from here on.
	assert.ErrorIs(t, f.storeCred(f.tokCtx, "after"), tokengate.ErrRevoked)
	assert.ErrorIs(t, f.storePres(f.tokCtx, "after"), tokengate.ErrRevoked)
}

// Credential update: a cut-off that is not an erasure (logout-everywhere) must
// not let the revoked token's change stand; an erasure leaves nothing.
func TestHolderWriteFence_UpdateRacingARevocation(t *testing.T) {
	seed := func(t *testing.T) *fenceFixture {
		f := newFenceFixture(t)
		require.NoError(t, f.storeCred(context.Background(), "c1"))
		return f
	}
	update := func(f *fenceFixture) error {
		_, err := f.creds.Update(f.tokCtx, domain.DefaultTenantID, f.did, &domain.UpdateCredentialRequest{
			CredentialIdentifier: "c1", InstanceID: 7, SigCount: 9,
		})
		return err
	}
	t.Run("cut-off without erasure restores the previous values", func(t *testing.T) {
		f := seed(t)
		f.rs.afterWrite = func() {
			f.rs.afterWrite = nil
			require.NoError(t, f.inner.Users().InvalidateAuthBefore(context.Background(), f.uid, time.Now()))
		}
		require.ErrorIs(t, update(f), tokengate.ErrRevoked)
		got, err := f.inner.Credentials().GetByIdentifier(context.Background(), domain.DefaultTenantID, f.did, "c1")
		require.NoError(t, err)
		assert.Zero(t, got.InstanceID)
		assert.Zero(t, got.SigCount)
	})
	t.Run("erasure between admission and write", func(t *testing.T) {
		f := seed(t)
		f.rs.beforeWrite = func() { f.rs.beforeWrite = nil; f.cutoffThenSweep(t) }
		err := update(f)
		require.Error(t, err, "an update of an erased record must not report success")
		c, _ := f.holderData(t)
		assert.Zero(t, c, "an update must not resurrect an erased record")
	})
	t.Run("erasure between write and re-read", func(t *testing.T) {
		f := seed(t)
		f.rs.afterWrite = func() { f.rs.afterWrite = nil; f.cutoffThenSweep(t) }
		require.ErrorIs(t, update(f), tokengate.ErrRevoked)
		c, _ := f.holderData(t)
		assert.Zero(t, c)
	})
}

// Happy paths are unchanged: no erasure, no token, a fresh token.
func TestHolderWriteFence_HappyPathsUnchanged(t *testing.T) {
	f := newFenceFixture(t)
	require.NoError(t, f.storeCred(f.tokCtx, "a"))
	require.NoError(t, f.storePres(f.tokCtx, "a"))
	require.NoError(t, f.storeCred(context.Background(), "no-token"), "an internal caller is not judged")
	_, err := f.creds.Update(f.tokCtx, domain.DefaultTenantID, f.did, &domain.UpdateCredentialRequest{CredentialIdentifier: "a", InstanceID: 3, SigCount: 4})
	require.NoError(t, err)
	got, err := f.inner.Credentials().GetByIdentifier(context.Background(), domain.DefaultTenantID, f.did, "a")
	require.NoError(t, err)
	assert.Equal(t, 3, int(got.InstanceID))
	assert.Equal(t, 4, int(got.SigCount))
	c, p := f.holderData(t)
	assert.Equal(t, 2, c)
	assert.Equal(t, 1, p)

	// A token issued after an earlier cut-off passes.
	require.NoError(t, f.inner.Users().InvalidateAuthBefore(context.Background(), f.uid, time.Now().Add(-time.Hour)))
	require.NoError(t, f.storeCred(f.tokCtx, "after-old-cutoff"))
}

// If the compensating delete fails the write stays, and the caller is told the
// operation failed, with the left-behind record identifiable from the error.
func TestHolderWriteFence_RollbackFailureFailsClosed(t *testing.T) {
	for name, write := range map[string]func(f *fenceFixture) error{
		"credential":   func(f *fenceFixture) error { return f.storeCred(f.tokCtx, "stuck") },
		"presentation": func(f *fenceFixture) error { return f.storePres(f.tokCtx, "stuck") },
	} {
		t.Run(name, func(t *testing.T) {
			f := newFenceFixture(t)
			f.rs.beforeWrite = func() {
				f.rs.beforeWrite = nil
				require.NoError(t, f.inner.Users().InvalidateAuthBefore(context.Background(), f.uid, time.Now()))
				f.rs.failDeletes.Store(true)
			}
			err := write(f)
			require.ErrorIs(t, err, tokengate.ErrRevoked, "still a refusal: the caller must treat it as failed (401)")
			require.ErrorIs(t, err, tokengate.ErrWriteNotRolledBack)
			c, p := f.holderData(t)
			assert.Equal(t, 1, c+p, "the record could not be removed and is left for the next sweep")

			// The next sweep (an erasure retry) removes it.
			f.rs.failDeletes.Store(false)
			f.cutoffThenSweep(t)
			c, p = f.holderData(t)
			assert.Zero(t, c+p)
		})
	}
}

// failingReadUsers fails the cut-off read once armed, to prove the fence fails
// closed when it cannot decide.
type failingReadUsers struct {
	storage.UserStore
	armed *atomic.Bool
}

func (u *failingReadUsers) GetAuthCutoff(ctx context.Context, id domain.UserID) (time.Time, error) {
	if u.armed.Load() {
		return time.Time{}, errors.New("user store is down")
	}
	return u.UserStore.GetAuthCutoff(ctx, id)
}

type failingReadStore struct {
	storage.Store
	armed atomic.Bool
}

func (s *failingReadStore) Users() storage.UserStore {
	return &failingReadUsers{s.Store.Users(), &s.armed}
}

func TestHolderWriteFence_UnreadableCutoffAfterTheWriteRollsBack(t *testing.T) {
	inner := memory.NewStore()
	fs := &failingReadStore{Store: inner}
	rs := &raceStore{Store: fs}
	uid := domain.NewUserID()
	did := "did:example:" + uid.String()
	require.NoError(t, inner.Users().Create(context.Background(), &domain.User{UUID: uid, DID: did}))
	svc := NewCredentialService(rs, &config.Config{}, zap.NewNop())
	rs.afterWrite = func() { fs.armed.Store(true) } // pre-check passed, re-read will fail

	ctx := tokengate.WithSubject(context.Background(), uid.String(), time.Now().Add(-time.Minute))
	_, err := svc.Store(ctx, domain.DefaultTenantID, &domain.StoreCredentialRequest{
		HolderDID: did, CredentialIdentifier: "x", Credential: "jwt", Format: domain.FormatJWTVC,
	})
	require.Error(t, err)
	assert.NotErrorIs(t, err, tokengate.ErrRevoked, "a read failure is a server error, not a revocation")
	got, gerr := inner.Credentials().GetAllByHolder(context.Background(), domain.DefaultTenantID, did)
	if gerr != nil {
		require.ErrorIs(t, gerr, storage.ErrNotFound)
	}
	assert.Empty(t, got, "when the fence cannot decide, the write is taken back")
}

// A token issued after the deletion's cut-off (a fresh login, allowed so a
// failed deletion can be retried) is not refused by the cut-off. A write of
// such a token that lands between the final sweep and the user's removal is
// removed by the sweep that follows the removal.
func TestDeleteUser_SweepsAFreshTokensWriteLandingBeforeTheUserIsRemoved(t *testing.T) {
	ctx := context.Background()
	inner := memory.NewStore()
	hs := &removeHookStore{Store: inner}
	svc := NewUserService(hs, testConfig(), zap.NewNop())
	base := time.Now().UTC().Truncate(time.Second)
	svc.now = func() time.Time { return base }
	uid := domain.NewUserID()
	did := "did:key:" + uid.String()
	require.NoError(t, inner.Users().Create(ctx, &domain.User{UUID: uid, DID: did}))

	creds := NewCredentialService(inner, &config.Config{}, zap.NewNop())
	fresh := tokengate.WithSubject(ctx, uid.String(), base.Add(5*time.Second))
	var wrote error
	hs.beforeRemove = func() {
		_, wrote = creds.Store(fresh, domain.DefaultTenantID, &domain.StoreCredentialRequest{
			HolderDID: did, CredentialIdentifier: "racing", Credential: "jwt", Format: domain.FormatJWTVC,
		})
	}

	require.NoError(t, svc.DeleteUser(tokengate.WithIssuedAt(ctx, base.Add(-time.Minute)), uid, uid.String()))
	require.NoError(t, wrote, "the fresh token was legitimately admitted")
	got, err := inner.Credentials().GetAllByHolder(ctx, domain.DefaultTenantID, did)
	if err != nil {
		require.ErrorIs(t, err, storage.ErrNotFound)
	}
	assert.Empty(t, got, "the sweep after the user's removal must take it")
}

type removeHookStore struct {
	storage.Store
	beforeRemove func()
}

type removeHookUsers struct {
	storage.UserStore
	s *removeHookStore
}

func (s *removeHookStore) Users() storage.UserStore { return &removeHookUsers{s.Store.Users(), s} }

func (u *removeHookUsers) Delete(ctx context.Context, id domain.UserID) error {
	if u.s.beforeRemove != nil {
		u.s.beforeRemove()
	}
	return u.UserStore.Delete(ctx, id)
}

// The invariant the fence relies on, on the lifecycle path: the cut-off is
// advanced before the first holder sweep, even when it was already set by the
// revocation (a token minted since must be fenced out before data is swept).
func TestLifecycleErase_AdvancesTheCutoffBeforeTheHolderSweep(t *testing.T) {
	inner := memory.NewStore()
	uid := seedWalletUser(t, inner, domain.DefaultTenantID)
	var fenceAtFirstDelete atomic.Int64
	fenceAtFirstDelete.Store(-1)
	hs := &sweepProbeStore{Store: inner, onDelete: func() {
		if fenceAtFirstDelete.Load() < 0 {
			u, err := inner.Users().GetByID(context.Background(), uid)
			require.NoError(t, err)
			fenceAtFirstDelete.Store(u.AuthFence)
		}
	}}
	svc := NewWalletLifecycleService(hs, zap.NewNop(), nil)
	// Revoke by hand, with an old cut-off already in place, so only the erase
	// path's own advance can be what the first delete observes.
	require.NoError(t, inner.WalletInstances().UpdateStatus(context.Background(), "inst-"+uid.String(), domain.DefaultTenantID, domain.InstanceStatusRevoked, "x"))
	before, _ := inner.Users().GetByID(context.Background(), uid)

	errs := svc.eraseWalletData(context.Background(), domain.DefaultTenantID, uid)
	require.Empty(t, errs)
	assert.Greater(t, fenceAtFirstDelete.Load(), before.AuthFence, "the cut-off advanced before the first holder record was deleted")
}

type sweepProbeStore struct {
	storage.Store
	onDelete func()
}

type sweepProbeCreds struct {
	storage.CredentialStore
	s *sweepProbeStore
}

func (s *sweepProbeStore) Credentials() storage.CredentialStore {
	return &sweepProbeCreds{s.Store.Credentials(), s}
}

func (c *sweepProbeCreds) Delete(ctx context.Context, t domain.TenantID, h, id string) error {
	c.s.onDelete()
	return c.CredentialStore.Delete(ctx, t, h, id)
}

// Real concurrency: writers using a token issued before the erasure race the
// eraser. Once the erasure has returned success and every writer has returned,
// no holder record may remain. Run with -race and -count.
func TestHolderWriteFence_ConcurrentWritersAgainstErasure(t *testing.T) {
	type eraser func(t *testing.T, store storage.Store, uid domain.UserID, iat time.Time)
	erasers := map[string]eraser{
		"DeleteUser": func(t *testing.T, store storage.Store, uid domain.UserID, iat time.Time) {
			us := NewUserService(store, testConfig(), zap.NewNop())
			require.NoError(t, us.DeleteUser(tokengate.WithIssuedAt(context.Background(), iat), uid, uid.String()))
		},
		"lifecycle cascade": func(t *testing.T, store storage.Store, uid domain.UserID, _ time.Time) {
			svc := NewWalletLifecycleService(store, zap.NewNop(), nil)
			_, err := svc.RevokeAllForUser(context.Background(), userActor(uid), domain.DefaultTenantID, uid, "test")
			require.NoError(t, err)
		},
	}
	for name, erase := range erasers {
		t.Run(name, func(t *testing.T) { runConcurrentWritersAgainst(t, erase) })
	}
}

func runConcurrentWritersAgainst(t *testing.T, erase func(t *testing.T, store storage.Store, uid domain.UserID, iat time.Time)) {
	ctx := context.Background()
	store := memory.NewStore()
	creds := NewCredentialService(store, &config.Config{}, zap.NewNop())
	pres := NewPresentationService(store, zap.NewNop())

	uid := seedWalletUser(t, store)
	did := "did:example:" + uid.String()
	iat := time.Now().Add(-time.Minute)
	wctx := tokengate.WithSubject(ctx, uid.String(), iat)

	const writers = 8
	var wg sync.WaitGroup
	stop := make(chan struct{})
	var started, accepted, refused atomic.Int64
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; ; i++ {
				select {
				case <-stop:
					return
				default:
				}
				id := fmt.Sprintf("w%d-%d", w, i)
				var err error
				if i%2 == 0 {
					_, err = creds.Store(wctx, domain.DefaultTenantID, &domain.StoreCredentialRequest{
						HolderDID: did, CredentialIdentifier: id, Credential: "jwt", Format: domain.FormatJWTVC,
					})
				} else {
					err = pres.Store(wctx, domain.DefaultTenantID, &domain.VerifiablePresentation{
						HolderDID: did, PresentationIdentifier: id, Presentation: "jwt",
					})
				}
				started.Add(1)
				switch {
				case err == nil:
					accepted.Add(1)
				case errors.Is(err, tokengate.ErrRevoked):
					refused.Add(1)
					return // refused for good: the token is cut off
				default:
					t.Errorf("unexpected writer error: %v", err)
					return
				}
			}
		}(w)
	}

	// Let the writers get going, then erase.
	for started.Load() < 50 {
		time.Sleep(time.Millisecond)
	}
	erase(t, store, uid, iat)
	close(stop)
	wg.Wait()

	c, err := store.Credentials().GetAllByHolder(ctx, domain.DefaultTenantID, did)
	if err != nil {
		require.ErrorIs(t, err, storage.ErrNotFound)
	}
	p, err := store.Presentations().GetAllByHolder(ctx, domain.DefaultTenantID, did)
	if err != nil {
		require.ErrorIs(t, err, storage.ErrNotFound)
	}
	assert.Empty(t, c, "credentials survived the erasure")
	assert.Empty(t, p, "presentations survived the erasure")
	assert.EqualValues(t, writers, refused.Load(), "every writer was eventually refused")
	assert.Positive(t, accepted.Load(), "some writes were admitted before the cut-off, so the race was real")
}

// vanishingStore makes every holder delete find its record already gone, as
// when an in-flight write rolls itself back between the sweep's listing and its
// delete.
type vanishingStore struct{ storage.Store }

type vanishingCreds struct{ storage.CredentialStore }
type vanishingPres struct{ storage.PresentationStore }

func (s *vanishingStore) Credentials() storage.CredentialStore {
	return &vanishingCreds{s.Store.Credentials()}
}
func (s *vanishingStore) Presentations() storage.PresentationStore {
	return &vanishingPres{s.Store.Presentations()}
}

func (c *vanishingCreds) Delete(ctx context.Context, t domain.TenantID, h, id string) error {
	_ = c.CredentialStore.Delete(ctx, t, h, id)
	return storage.ErrNotFound
}

func (p *vanishingPres) Delete(ctx context.Context, t domain.TenantID, h, id string) error {
	_ = p.PresentationStore.Delete(ctx, t, h, id)
	return storage.ErrNotFound
}

// A record that is gone by the time the sweep deletes it is the outcome the
// sweep wants, not an incomplete erasure.
func TestHolderSweeps_RecordAlreadyGoneIsNotAFailure(t *testing.T) {
	ctx := context.Background()
	for name, sweep := range map[string]func(s storage.Store, did string) []error{
		"DeleteUser": func(s storage.Store, did string) []error {
			return NewUserService(s, testConfig(), zap.NewNop()).eraseHolderData(ctx, domain.DefaultTenantID, did)
		},
		"lifecycle": func(s storage.Store, did string) []error {
			return NewWalletLifecycleService(s, zap.NewNop(), nil).eraseHolderData(ctx, domain.DefaultTenantID, did)
		},
	} {
		t.Run(name, func(t *testing.T) {
			inner := memory.NewStore()
			did := "did:example:h"
			require.NoError(t, inner.Credentials().Create(ctx, &domain.VerifiableCredential{TenantID: domain.DefaultTenantID, HolderDID: did, CredentialIdentifier: "c", Credential: "x", Format: domain.FormatJWTVC}))
			require.NoError(t, inner.Presentations().Create(ctx, &domain.VerifiablePresentation{TenantID: domain.DefaultTenantID, HolderDID: did, PresentationIdentifier: "p", Presentation: "x"}))
			assert.Empty(t, sweep(&vanishingStore{inner}, did))
		})
	}
}
