package memory

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
)

// fakeClock is a settable clock for the undo log's age pruning.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func newCredStore() (*CredentialStore, *fakeClock) {
	clk := &fakeClock{t: time.Unix(1_000_000, 0)}
	s := NewStore().Credentials().(*CredentialStore)
	s.now = clk.now
	return s, clk
}

// updateCred performs one service-style Update: read, change, write. It returns
// the written record (the rollback handle) and the record it read.
func updateCred(t *testing.T, s *CredentialStore, id string, sig int) (written, read domain.VerifiableCredential) {
	t.Helper()
	cur, err := s.GetByIdentifier(context.Background(), domain.DefaultTenantID, "did:h", id)
	require.NoError(t, err)
	read = *cur
	cur.SigCount = sig
	require.NoError(t, s.Update(context.Background(), cur))
	return *cur, read
}

func sigOf(t *testing.T, s *CredentialStore, id string) int {
	t.Helper()
	cur, err := s.GetByIdentifier(context.Background(), domain.DefaultTenantID, "did:h", id)
	require.NoError(t, err)
	return cur.SigCount
}

// Thread e of go-wallet-backend#319: B reads A's unconfirmed update, then a
// cut-off refuses both. Neither rollback order may leave A's values behind.
func TestCredentialStore_InterleavedRollbacksRestoreLastConfirmedValue(t *testing.T) {
	ctx := context.Background()
	for _, order := range []string{"B then A", "A then B"} {
		t.Run(order, func(t *testing.T) {
			s, _ := newCredStore()
			base := newCred("x")
			require.NoError(t, s.Create(ctx, base))
			writtenA, readA := updateCred(t, s, "x", 111)
			writtenB, readB := updateCred(t, s, "x", 222)
			if order == "B then A" {
				require.NoError(t, s.RestoreIfUnchanged(ctx, &writtenB, &readB))
				assert.Equal(t, 111, sigOf(t, s, "x"), "A's write is current again")
				require.NoError(t, s.RestoreIfUnchanged(ctx, &writtenA, &readA))
			} else {
				require.NoError(t, s.RestoreIfUnchanged(ctx, &writtenA, &readA))
				assert.Equal(t, 222, sigOf(t, s, "x"), "B's values stay while B is undecided")
				require.NoError(t, s.RestoreIfUnchanged(ctx, &writtenB, &readB))
			}
			assert.Equal(t, 0, sigOf(t, s, "x"), "both requests were refused: the pre-A value is back")
		})
	}
}

func TestCredentialStore_RollbackOfCreateDeletes(t *testing.T) {
	ctx := context.Background()
	s, _ := newCredStore()
	c := newCred("created")
	require.NoError(t, s.Create(ctx, c))
	require.NoError(t, s.DeleteIfUnchanged(ctx, domain.DefaultTenantID, c.ID, c.WriteToken))
	_, err := s.GetByIdentifier(ctx, domain.DefaultTenantID, "did:h", "created")
	assert.ErrorIs(t, err, storage.ErrNotFound)
	assert.ErrorIs(t, s.DeleteIfUnchanged(ctx, domain.DefaultTenantID, c.ID, c.WriteToken), storage.ErrNotFound)
}

func TestCredentialStore_ThreeInterleavedWritesSpliceCorrectly(t *testing.T) {
	ctx := context.Background()
	// Every order in which the three refused writes can be rolled back ends at the base.
	orders := [][]int{{0, 1, 2}, {0, 2, 1}, {1, 0, 2}, {1, 2, 0}, {2, 0, 1}, {2, 1, 0}}
	for _, order := range orders {
		t.Run(fmt.Sprint(order), func(t *testing.T) {
			s, _ := newCredStore()
			require.NoError(t, s.Create(ctx, newCred("x")))
			var w, r [3]domain.VerifiableCredential
			for i := range w {
				w[i], r[i] = updateCred(t, s, "x", 10*(i+1))
			}
			for _, i := range order {
				require.NoError(t, s.RestoreIfUnchanged(ctx, &w[i], &r[i]), "rollback of write %d", i)
			}
			assert.Equal(t, 0, sigOf(t, s, "x"))
		})
	}
	t.Run("a confirmed newest write survives the rollback of the ones below it", func(t *testing.T) {
		s, _ := newCredStore()
		require.NoError(t, s.Create(ctx, newCred("x")))
		w0, r0 := updateCred(t, s, "x", 10)
		w1, r1 := updateCred(t, s, "x", 20)
		_, _ = updateCred(t, s, "x", 30) // never rolled back: confirmed
		require.NoError(t, s.RestoreIfUnchanged(ctx, &w0, &r0))
		require.NoError(t, s.RestoreIfUnchanged(ctx, &w1, &r1))
		assert.Equal(t, 30, sigOf(t, s, "x"))
	})
}

func TestCredentialStore_UndoLogPrunesByAgeAndLength(t *testing.T) {
	ctx := context.Background()
	t.Run("age", func(t *testing.T) {
		s, clk := newCredStore()
		require.NoError(t, s.Create(ctx, newCred("x")))
		w, r := updateCred(t, s, "x", 5)
		clk.advance(storage.UndoLogMaxAge + time.Second)
		assert.ErrorIs(t, s.RestoreIfUnchanged(ctx, &w, &r), storage.ErrNotFound)
		assert.Equal(t, 5, sigOf(t, s, "x"))
	})
	t.Run("length", func(t *testing.T) {
		s, _ := newCredStore()
		c := newCred("x")
		require.NoError(t, s.Create(ctx, c))
		first, firstRead := updateCred(t, s, "x", 1)
		for i := 2; i <= storage.UndoLogMaxLen+1; i++ {
			updateCred(t, s, "x", i)
		}
		assert.ErrorIs(t, s.RestoreIfUnchanged(ctx, &first, &firstRead), storage.ErrNotFound)
		assert.Len(t, *s.undo[c.ID], storage.UndoLogMaxLen)
	})
}

func TestCredentialStore_ConcurrentRollbacksRace(t *testing.T) {
	ctx := context.Background()
	s, _ := newCredStore()
	require.NoError(t, s.Create(ctx, newCred("x")))
	const n = 8
	var w, r [n]domain.VerifiableCredential
	for i := 0; i < n; i++ {
		w[i], r[i] = updateCred(t, s, "x", i+1)
	}
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			assert.NoError(t, s.RestoreIfUnchanged(ctx, &w[i], &r[i]))
		}()
	}
	wg.Wait()
	assert.Equal(t, 0, sigOf(t, s, "x"))
}

// The undo log lives in the store: no domain record carries it, so it cannot
// reach a JSON response or export.
func TestUndoLogNeverSerialised(t *testing.T) {
	ctx := context.Background()
	s, _ := newCredStore()
	require.NoError(t, s.Create(ctx, newCred("x")))
	w, _ := updateCred(t, s, "x", 1)
	b, err := json.Marshal(w)
	require.NoError(t, err)
	assert.NotContains(t, string(b), "undo")
	all, err := s.GetAllByHolder(ctx, domain.DefaultTenantID, "did:h")
	require.NoError(t, err)
	b, err = json.Marshal(all)
	require.NoError(t, err)
	assert.NotContains(t, string(b), "undo")

	ks := NewStore().KeyAttestations()
	rec := &domain.KeyAttestationRecord{KeyThumbprint: "tp", Kind: domain.KeyEvidenceFIDO2, Home: domain.KeyHomeFIDO2Hardware, VerifiedAt: time.Now()}
	require.NoError(t, ks.MarkKeyAttested(ctx, rec))
	got, err := ks.GetByKeyThumbprint(ctx, "tp")
	require.NoError(t, err)
	b, err = json.Marshal(got)
	require.NoError(t, err)
	assert.NotContains(t, string(b), "undo")
}

// Thread f: FIDO2 registration evidence, same interleaving.
func TestKeyAttestationStore_InterleavedRollbacksRestoreLastConfirmedEvidence(t *testing.T) {
	ctx := context.Background()
	rec := func(aaguid string, uv bool) *domain.KeyAttestationRecord {
		return &domain.KeyAttestationRecord{KeyThumbprint: "tp", Kind: domain.KeyEvidenceFIDO2, Home: domain.KeyHomeFIDO2Hardware, AAGUID: aaguid, UV: uv, VerifiedAt: time.Now().UTC()}
	}
	for _, order := range []string{"B then A", "A then B"} {
		t.Run(order, func(t *testing.T) {
			ks := NewStore().KeyAttestations()
			base := rec("confirmed", false)
			require.NoError(t, ks.MarkKeyAttested(ctx, base))
			a := rec("a-unconfirmed", false)
			require.NoError(t, ks.MarkKeyAttested(ctx, a))
			b := rec("b-unconfirmed", true) // supersedes A (UV)
			require.NoError(t, ks.MarkKeyAttested(ctx, b))
			require.NotNil(t, b.Previous)
			aw, bw := *a, *b
			if order == "B then A" {
				require.NoError(t, ks.RestoreIfUnchanged(ctx, &bw, bw.Previous))
				got, _ := ks.GetByKeyThumbprint(ctx, "tp")
				assert.Equal(t, "a-unconfirmed", got.AAGUID)
				require.NoError(t, ks.RestoreIfUnchanged(ctx, &aw, aw.Previous))
			} else {
				require.NoError(t, ks.RestoreIfUnchanged(ctx, &aw, aw.Previous))
				got, _ := ks.GetByKeyThumbprint(ctx, "tp")
				assert.Equal(t, "b-unconfirmed", got.AAGUID)
				require.NoError(t, ks.RestoreIfUnchanged(ctx, &bw, bw.Previous))
			}
			got, err := ks.GetByKeyThumbprint(ctx, "tp")
			require.NoError(t, err)
			assert.Equal(t, "confirmed", got.AAGUID)
		})
	}
	t.Run("rollback of a first insert deletes", func(t *testing.T) {
		ks := NewStore().KeyAttestations()
		a := rec("a", false)
		require.NoError(t, ks.MarkKeyAttested(ctx, a))
		require.NoError(t, ks.DeleteIfUnchanged(ctx, "tp", a.WriteToken))
		_, err := ks.GetByKeyThumbprint(ctx, "tp")
		assert.ErrorIs(t, err, storage.ErrNotFound)
	})
	t.Run("prunes by age", func(t *testing.T) {
		clk := &fakeClock{t: time.Unix(1_000_000, 0)}
		ks := NewStore().KeyAttestations().(*KeyAttestationStore)
		ks.now = clk.now
		a := rec("a", false)
		require.NoError(t, ks.MarkKeyAttested(ctx, a))
		clk.advance(storage.UndoLogMaxAge + time.Second)
		assert.ErrorIs(t, ks.DeleteIfUnchanged(ctx, "tp", a.WriteToken), storage.ErrNotFound)
	})
}

func TestWalletInstanceStore_InterleavedAttestationRollbacks(t *testing.T) {
	ctx := context.Background()
	attest := func(store storage.WalletInstanceStore, src string, at int64) (written, before domain.WalletInstance) {
		cur, err := store.GetByID(ctx, "wi")
		require.NoError(t, err)
		before = *cur
		w := &domain.WalletInstance{ID: "wi", TenantID: "acme", Status: domain.InstanceStatusActive, AttestationSource: src, LastAttestedAt: time.Unix(at, 0), UpdatedAt: time.Unix(at, 0)}
		require.NoError(t, store.Upsert(ctx, w))
		return *w, before
	}
	for _, order := range []string{"B then A", "A then B"} {
		t.Run(order, func(t *testing.T) {
			store := NewStore().WalletInstances()
			require.NoError(t, store.Upsert(ctx, &domain.WalletInstance{ID: "wi", TenantID: "acme", Status: domain.InstanceStatusActive, AttestationSource: "confirmed", LastAttestedAt: time.Unix(1, 0), UpdatedAt: time.Unix(1, 0)}))
			base, _ := store.GetByID(ctx, "wi")
			aw, ab := attest(store, "a-unconfirmed", 2)
			bw, bb := attest(store, "b-unconfirmed", 3)
			if order == "B then A" {
				require.NoError(t, store.RestoreAttestation(ctx, &bb, &bw))
				got, _ := store.GetByID(ctx, "wi")
				assert.Equal(t, "a-unconfirmed", got.AttestationSource)
				require.NoError(t, store.RestoreAttestation(ctx, &ab, &aw))
			} else {
				require.NoError(t, store.RestoreAttestation(ctx, &ab, &aw))
				got, _ := store.GetByID(ctx, "wi")
				assert.Equal(t, "b-unconfirmed", got.AttestationSource)
				require.NoError(t, store.RestoreAttestation(ctx, &bb, &bw))
			}
			got, err := store.GetByID(ctx, "wi")
			require.NoError(t, err)
			assert.Equal(t, "confirmed", got.AttestationSource)
			assert.Equal(t, base.AttestationCount, got.AttestationCount)
			assert.True(t, got.LastAttestedAt.Equal(base.LastAttestedAt))
			assert.Equal(t, base.WriteToken, got.WriteToken, "the confirmed write's token is current again")
		})
	}
	t.Run("an insert has nothing to restore", func(t *testing.T) {
		store := NewStore().WalletInstances()
		w := &domain.WalletInstance{ID: "wi2", TenantID: "acme", Status: domain.InstanceStatusActive}
		require.NoError(t, store.Upsert(ctx, w))
		assert.ErrorIs(t, store.RestoreAttestation(ctx, &domain.WalletInstance{}, w), storage.ErrBindingChanged)
	})
	t.Run("prunes by age", func(t *testing.T) {
		clk := &fakeClock{t: time.Unix(1_000_000, 0)}
		store := NewStore().WalletInstances().(*WalletInstanceStore)
		store.now = clk.now
		require.NoError(t, store.Upsert(ctx, &domain.WalletInstance{ID: "wi", TenantID: "acme", Status: domain.InstanceStatusActive}))
		aw, ab := attest(store, "a", 2)
		clk.advance(storage.UndoLogMaxAge + time.Second)
		assert.ErrorIs(t, store.RestoreAttestation(ctx, &ab, &aw), storage.ErrBindingChanged)
	})
}
