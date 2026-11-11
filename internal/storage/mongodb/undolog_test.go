package mongodb

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/bson"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
)

// fakeClock is a settable clock for the undo log's age pruning. The first
// reading is the real time, so entries are never in the future of MongoDB's own
// clock-free comparisons (the log is compared against this clock only).
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock() *fakeClock { return &fakeClock{t: time.Now().UTC().Truncate(time.Millisecond)} }
func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}
func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func updateMongoCred(t *testing.T, s *CredentialStore, id string, sig int) (written, read domain.VerifiableCredential) {
	t.Helper()
	cur, err := s.GetByIdentifier(context.Background(), domain.DefaultTenantID, "did:h", id)
	require.NoError(t, err)
	read = *cur
	cur.SigCount = sig
	require.NoError(t, s.Update(context.Background(), cur))
	return *cur, read
}

func mongoSigOf(t *testing.T, s *CredentialStore, id string) int {
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
			s := skipIfNoMongo(t).credentials
			id := "interleave-" + order
			base := newMongoCred(id)
			require.NoError(t, s.Create(ctx, base))
			writtenA, readA := updateMongoCred(t, s, id, 111)
			writtenB, readB := updateMongoCred(t, s, id, 222)
			if order == "B then A" {
				require.NoError(t, s.RestoreIfUnchanged(ctx, &writtenB, &readB))
				assert.Equal(t, 111, mongoSigOf(t, s, id), "A's write is current again")
				require.NoError(t, s.RestoreIfUnchanged(ctx, &writtenA, &readA))
			} else {
				require.NoError(t, s.RestoreIfUnchanged(ctx, &writtenA, &readA))
				assert.Equal(t, 222, mongoSigOf(t, s, id), "B's values stay while B is undecided")
				require.NoError(t, s.RestoreIfUnchanged(ctx, &writtenB, &readB))
			}
			assert.Equal(t, 0, mongoSigOf(t, s, id), "both requests were refused: the pre-A value is back")
		})
	}
}

func TestCredentialStore_RollbackOfCreateDeletes(t *testing.T) {
	ctx := context.Background()
	s := skipIfNoMongo(t).credentials
	c := newMongoCred("created")
	require.NoError(t, s.Create(ctx, c))
	require.NoError(t, s.DeleteIfUnchanged(ctx, domain.DefaultTenantID, c.ID, c.WriteToken))
	_, err := s.GetByIdentifier(ctx, domain.DefaultTenantID, "did:h", "created")
	assert.ErrorIs(t, err, storage.ErrNotFound)
	assert.ErrorIs(t, s.DeleteIfUnchanged(ctx, domain.DefaultTenantID, c.ID, c.WriteToken), storage.ErrNotFound)
}

func TestCredentialStore_ThreeInterleavedWritesSpliceCorrectly(t *testing.T) {
	ctx := context.Background()
	orders := [][]int{{0, 1, 2}, {0, 2, 1}, {1, 0, 2}, {1, 2, 0}, {2, 0, 1}, {2, 1, 0}}
	for _, order := range orders {
		t.Run(fmt.Sprint(order), func(t *testing.T) {
			s := skipIfNoMongo(t).credentials
			require.NoError(t, s.Create(ctx, newMongoCred("x")))
			var w, r [3]domain.VerifiableCredential
			for i := range w {
				w[i], r[i] = updateMongoCred(t, s, "x", 10*(i+1))
			}
			for _, i := range order {
				require.NoError(t, s.RestoreIfUnchanged(ctx, &w[i], &r[i]), "rollback of write %d", i)
			}
			assert.Equal(t, 0, mongoSigOf(t, s, "x"))
		})
	}
	t.Run("a confirmed newest write survives the rollback of the ones below it", func(t *testing.T) {
		s := skipIfNoMongo(t).credentials
		require.NoError(t, s.Create(ctx, newMongoCred("x")))
		w0, r0 := updateMongoCred(t, s, "x", 10)
		w1, r1 := updateMongoCred(t, s, "x", 20)
		_, _ = updateMongoCred(t, s, "x", 30) // never rolled back: confirmed
		require.NoError(t, s.RestoreIfUnchanged(ctx, &w0, &r0))
		require.NoError(t, s.RestoreIfUnchanged(ctx, &w1, &r1))
		assert.Equal(t, 30, mongoSigOf(t, s, "x"))
	})
}

func TestCredentialStore_UndoLogPrunesByAgeAndLength(t *testing.T) {
	ctx := context.Background()
	t.Run("age", func(t *testing.T) {
		s := skipIfNoMongo(t).credentials
		clk := newFakeClock()
		s.now = clk.now
		require.NoError(t, s.Create(ctx, newMongoCred("x")))
		w, r := updateMongoCred(t, s, "x", 5)
		clk.advance(storage.UndoLogMaxAge + time.Second)
		assert.ErrorIs(t, s.RestoreIfUnchanged(ctx, &w, &r), storage.ErrNotFound)
		assert.Equal(t, 5, mongoSigOf(t, s, "x"))
	})
	t.Run("length", func(t *testing.T) {
		s := skipIfNoMongo(t).credentials
		c := newMongoCred("x")
		require.NoError(t, s.Create(ctx, c))
		first, firstRead := updateMongoCred(t, s, "x", 1)
		for i := 2; i <= storage.UndoLogMaxLen+1; i++ {
			updateMongoCred(t, s, "x", i)
		}
		assert.ErrorIs(t, s.RestoreIfUnchanged(ctx, &first, &firstRead), storage.ErrNotFound)
		var doc struct {
			Log []bson.M `bson:"undo_log"`
		}
		require.NoError(t, s.collection.FindOne(ctx, bson.M{"_id": c.ID}).Decode(&doc))
		assert.Len(t, doc.Log, storage.UndoLogMaxLen)
	})
}

func TestCredentialStore_ConcurrentRollbacksRace(t *testing.T) {
	ctx := context.Background()
	s := skipIfNoMongo(t).credentials
	require.NoError(t, s.Create(ctx, newMongoCred("x")))
	const n = 8
	var w, r [n]domain.VerifiableCredential
	for i := 0; i < n; i++ {
		w[i], r[i] = updateMongoCred(t, s, "x", i+1)
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
	assert.Equal(t, 0, mongoSigOf(t, s, "x"))
}

// A record written before the undo log existed has no undo_log field: the
// rollback keeps matching its current write token only.
func TestCredentialStore_RecordWithoutUndoLogBehavesAsBefore(t *testing.T) {
	ctx := context.Background()
	s := skipIfNoMongo(t).credentials
	c := newMongoCred("legacy")
	require.NoError(t, s.Create(ctx, c))
	_, err := s.collection.UpdateOne(ctx, bson.M{"_id": c.ID}, bson.M{"$unset": bson.M{undoField: ""}})
	require.NoError(t, err)

	assert.ErrorIs(t, s.DeleteIfUnchanged(ctx, domain.DefaultTenantID, c.ID, "stale"), storage.ErrNotFound)
	require.NoError(t, s.DeleteIfUnchanged(ctx, domain.DefaultTenantID, c.ID, c.WriteToken))
	_, err = s.GetByIdentifier(ctx, domain.DefaultTenantID, "did:h", "legacy")
	assert.ErrorIs(t, err, storage.ErrNotFound)

	// Restore on a legacy record uses the caller's previous.
	c2 := newMongoCred("legacy2")
	require.NoError(t, s.Create(ctx, c2))
	previous := *c2
	_, err = s.collection.UpdateOne(ctx, bson.M{"_id": c2.ID}, bson.M{"$unset": bson.M{undoField: ""}, "$set": bson.M{"sig_count": 9}})
	require.NoError(t, err)
	require.NoError(t, s.RestoreIfUnchanged(ctx, c2, &previous))
	assert.Equal(t, 0, mongoSigOf(t, s, "legacy2"))

	// A write on a legacy record starts its log: it can be undone back to the legacy state.
	c3 := newMongoCred("legacy3")
	require.NoError(t, s.Create(ctx, c3))
	_, err = s.collection.UpdateOne(ctx, bson.M{"_id": c3.ID}, bson.M{"$unset": bson.M{undoField: ""}})
	require.NoError(t, err)
	w, r := updateMongoCred(t, s, "legacy3", 4)
	require.NoError(t, s.RestoreIfUnchanged(ctx, &w, &r))
	assert.Equal(t, 0, mongoSigOf(t, s, "legacy3"))
}

// The undo log is stored beside the record but never decoded into a domain
// struct, so no JSON response or export carries it.
func TestUndoLogNeverSerialised(t *testing.T) {
	ctx := context.Background()
	store := skipIfNoMongo(t)
	s := store.credentials
	c := newMongoCred("x")
	require.NoError(t, s.Create(ctx, c))
	w, _ := updateMongoCred(t, s, "x", 1)

	var raw bson.M
	require.NoError(t, s.collection.FindOne(ctx, bson.M{"_id": c.ID}).Decode(&raw))
	require.Contains(t, raw, undoField, "the log is stored")

	b, err := json.Marshal(w)
	require.NoError(t, err)
	assert.NotContains(t, string(b), "undo")
	all, err := s.GetAllByHolder(ctx, domain.DefaultTenantID, "did:h")
	require.NoError(t, err)
	b, err = json.Marshal(all)
	require.NoError(t, err)
	assert.NotContains(t, string(b), "undo")

	ks := store.KeyAttestations()
	rec := &domain.KeyAttestationRecord{KeyThumbprint: "tp-json", Kind: domain.KeyEvidenceFIDO2, Home: domain.KeyHomeFIDO2Hardware, VerifiedAt: time.Now()}
	require.NoError(t, ks.MarkKeyAttested(ctx, rec))
	got, err := ks.GetByKeyThumbprint(ctx, "tp-json")
	require.NoError(t, err)
	b, err = json.Marshal(got)
	require.NoError(t, err)
	assert.NotContains(t, string(b), "undo")

	wis := store.WalletInstances()
	require.NoError(t, wis.Upsert(ctx, &domain.WalletInstance{ID: "wi-json", TenantID: "acme", Status: domain.InstanceStatusActive}))
	require.NoError(t, wis.Upsert(ctx, &domain.WalletInstance{ID: "wi-json", TenantID: "acme", Status: domain.InstanceStatusActive}))
	inst, err := wis.GetByID(ctx, "wi-json")
	require.NoError(t, err)
	b, err = json.Marshal(inst)
	require.NoError(t, err)
	assert.NotContains(t, string(b), "undo")
	var rawInst bson.M
	require.NoError(t, store.walletInstances.collection.FindOne(ctx, bson.M{"_id": "wi-json"}).Decode(&rawInst))
	assert.Contains(t, rawInst, undoField)
}

// Thread f: FIDO2 registration evidence, same interleaving.
func TestKeyAttestationStore_InterleavedRollbacksRestoreLastConfirmedEvidence(t *testing.T) {
	ctx := context.Background()
	rec := func(tp, aaguid string, uv bool) *domain.KeyAttestationRecord {
		return &domain.KeyAttestationRecord{KeyThumbprint: tp, Kind: domain.KeyEvidenceFIDO2, Home: domain.KeyHomeFIDO2Hardware, AAGUID: aaguid, UV: uv, VerifiedAt: time.Now().UTC()}
	}
	for _, order := range []string{"B then A", "A then B"} {
		t.Run(order, func(t *testing.T) {
			ks := skipIfNoMongo(t).KeyAttestations()
			tp := "tp-interleave"
			require.NoError(t, ks.MarkKeyAttested(ctx, rec(tp, "confirmed", false)))
			a := rec(tp, "a-unconfirmed", false)
			require.NoError(t, ks.MarkKeyAttested(ctx, a))
			b := rec(tp, "b-unconfirmed", true) // supersedes A (UV)
			require.NoError(t, ks.MarkKeyAttested(ctx, b))
			require.NotNil(t, b.Previous)
			aw, bw := *a, *b
			if order == "B then A" {
				require.NoError(t, ks.RestoreIfUnchanged(ctx, &bw, bw.Previous))
				got, _ := ks.GetByKeyThumbprint(ctx, tp)
				assert.Equal(t, "a-unconfirmed", got.AAGUID)
				require.NoError(t, ks.RestoreIfUnchanged(ctx, &aw, aw.Previous))
			} else {
				require.NoError(t, ks.RestoreIfUnchanged(ctx, &aw, aw.Previous))
				got, _ := ks.GetByKeyThumbprint(ctx, tp)
				assert.Equal(t, "b-unconfirmed", got.AAGUID)
				require.NoError(t, ks.RestoreIfUnchanged(ctx, &bw, bw.Previous))
			}
			got, err := ks.GetByKeyThumbprint(ctx, tp)
			require.NoError(t, err)
			assert.Equal(t, "confirmed", got.AAGUID)
		})
	}
	t.Run("rollback of a first insert deletes", func(t *testing.T) {
		ks := skipIfNoMongo(t).KeyAttestations()
		a := rec("tp-first", "a", false)
		require.NoError(t, ks.MarkKeyAttested(ctx, a))
		require.NoError(t, ks.DeleteIfUnchanged(ctx, "tp-first", a.WriteToken))
		_, err := ks.GetByKeyThumbprint(ctx, "tp-first")
		assert.ErrorIs(t, err, storage.ErrNotFound)
	})
	t.Run("prunes by age", func(t *testing.T) {
		store := skipIfNoMongo(t)
		clk := newFakeClock()
		store.keyAttestations.now = clk.now
		a := rec("tp-age", "a", false)
		require.NoError(t, store.keyAttestations.MarkKeyAttested(ctx, a))
		clk.advance(storage.UndoLogMaxAge + time.Second)
		assert.ErrorIs(t, store.keyAttestations.DeleteIfUnchanged(ctx, "tp-age", a.WriteToken), storage.ErrNotFound)
	})
	t.Run("a record without an undo log keeps the token-only rollback", func(t *testing.T) {
		store := skipIfNoMongo(t)
		a := rec("tp-legacy", "a", false)
		require.NoError(t, store.keyAttestations.MarkKeyAttested(ctx, a))
		_, err := store.keyAttestations.collection.UpdateOne(ctx, bson.M{"_id": "tp-legacy"}, bson.M{"$unset": bson.M{undoField: ""}})
		require.NoError(t, err)
		assert.ErrorIs(t, store.keyAttestations.DeleteIfUnchanged(ctx, "tp-legacy", "stale"), storage.ErrNotFound)
		require.NoError(t, store.keyAttestations.DeleteIfUnchanged(ctx, "tp-legacy", a.WriteToken))
	})
	t.Run("concurrent rollbacks", func(t *testing.T) {
		ks := skipIfNoMongo(t).KeyAttestations()
		tp := "tp-race"
		require.NoError(t, ks.MarkKeyAttested(ctx, rec(tp, "confirmed", false)))
		const n = 6
		var written [n]domain.KeyAttestationRecord
		for i := 0; i < n; i++ {
			r := rec(tp, fmt.Sprintf("w%d", i), i%2 == 1)
			r.Home = domain.KeyHomeFIDO2Hardware
			ok, err := ks.ReplaceKeyEvidence(ctx, r, "")
			require.NoError(t, err)
			require.True(t, ok)
			written[i] = *r
		}
		var wg sync.WaitGroup
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				assert.NoError(t, ks.RestoreIfUnchanged(ctx, &written[i], written[i].Previous))
			}()
		}
		wg.Wait()
		got, err := ks.GetByKeyThumbprint(ctx, tp)
		require.NoError(t, err)
		assert.Equal(t, "confirmed", got.AAGUID)
	})
}

func TestWalletInstanceStore_InterleavedAttestationRollbacks(t *testing.T) {
	ctx := context.Background()
	attest := func(store storage.WalletInstanceStore, id, src string, at int64) (written, before domain.WalletInstance) {
		cur, err := store.GetByID(ctx, id)
		require.NoError(t, err)
		before = *cur
		w := &domain.WalletInstance{ID: id, TenantID: "acme", Status: domain.InstanceStatusActive, AttestationSource: src, LastAttestedAt: time.Unix(at, 0), UpdatedAt: time.Unix(at, 0)}
		require.NoError(t, store.Upsert(ctx, w))
		return *w, before
	}
	for _, order := range []string{"B then A", "A then B"} {
		t.Run(order, func(t *testing.T) {
			store := skipIfNoMongo(t).WalletInstances()
			id := "wi-" + order
			require.NoError(t, store.Upsert(ctx, &domain.WalletInstance{ID: id, TenantID: "acme", Status: domain.InstanceStatusActive, AttestationSource: "confirmed", LastAttestedAt: time.Unix(1, 0), UpdatedAt: time.Unix(1, 0)}))
			base, _ := store.GetByID(ctx, id)
			aw, ab := attest(store, id, "a-unconfirmed", 2)
			bw, bb := attest(store, id, "b-unconfirmed", 3)
			if order == "B then A" {
				require.NoError(t, store.RestoreAttestation(ctx, &bb, &bw))
				got, _ := store.GetByID(ctx, id)
				assert.Equal(t, "a-unconfirmed", got.AttestationSource)
				require.NoError(t, store.RestoreAttestation(ctx, &ab, &aw))
			} else {
				require.NoError(t, store.RestoreAttestation(ctx, &ab, &aw))
				got, _ := store.GetByID(ctx, id)
				assert.Equal(t, "b-unconfirmed", got.AttestationSource)
				require.NoError(t, store.RestoreAttestation(ctx, &bb, &bw))
			}
			got, err := store.GetByID(ctx, id)
			require.NoError(t, err)
			assert.Equal(t, "confirmed", got.AttestationSource)
			assert.Equal(t, base.AttestationCount, got.AttestationCount)
			assert.True(t, got.LastAttestedAt.Equal(base.LastAttestedAt))
			assert.Equal(t, base.WriteToken, got.WriteToken, "the confirmed write's token is current again")
		})
	}
	t.Run("an owner and link the newest attestation set are cleared by its rollback only", func(t *testing.T) {
		store := skipIfNoMongo(t).WalletInstances()
		uid := domain.UserIDFromString("owner-undo")
		require.NoError(t, store.Upsert(ctx, &domain.WalletInstance{ID: "wi-own", TenantID: "acme", Status: domain.InstanceStatusActive}))
		w := &domain.WalletInstance{ID: "wi-own", TenantID: "acme", UserID: &uid, CredentialID: "cred", Status: domain.InstanceStatusActive, AttestationSource: "b"}
		require.NoError(t, store.Upsert(ctx, w))
		got, _ := store.GetByID(ctx, "wi-own")
		require.NotNil(t, got.UserID)
		require.NoError(t, store.RestoreAttestation(ctx, &domain.WalletInstance{}, w))
		got, _ = store.GetByID(ctx, "wi-own")
		assert.Nil(t, got.UserID)
		assert.Empty(t, got.CredentialID)
	})
	t.Run("an insert has nothing to restore", func(t *testing.T) {
		store := skipIfNoMongo(t).WalletInstances()
		w := &domain.WalletInstance{ID: "wi-ins", TenantID: "acme", Status: domain.InstanceStatusActive}
		require.NoError(t, store.Upsert(ctx, w))
		assert.ErrorIs(t, store.RestoreAttestation(ctx, &domain.WalletInstance{}, w), storage.ErrBindingChanged)
	})
	t.Run("prunes by age", func(t *testing.T) {
		s := skipIfNoMongo(t)
		clk := newFakeClock()
		s.walletInstances.now = clk.now
		store := s.WalletInstances()
		require.NoError(t, store.Upsert(ctx, &domain.WalletInstance{ID: "wi-age", TenantID: "acme", Status: domain.InstanceStatusActive}))
		aw, ab := attest(store, "wi-age", "a", 2)
		clk.advance(storage.UndoLogMaxAge + time.Second)
		assert.ErrorIs(t, store.RestoreAttestation(ctx, &ab, &aw), storage.ErrBindingChanged)
	})
	t.Run("concurrent rollbacks", func(t *testing.T) {
		store := skipIfNoMongo(t).WalletInstances()
		require.NoError(t, store.Upsert(ctx, &domain.WalletInstance{ID: "wi-race", TenantID: "acme", Status: domain.InstanceStatusActive, AttestationSource: "confirmed", LastAttestedAt: time.Unix(1, 0)}))
		base, _ := store.GetByID(ctx, "wi-race")
		const n = 6
		var w, b [n]domain.WalletInstance
		for i := 0; i < n; i++ {
			w[i], b[i] = attest(store, "wi-race", fmt.Sprintf("w%d", i), int64(10+i))
		}
		var wg sync.WaitGroup
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				assert.NoError(t, store.RestoreAttestation(ctx, &b[i], &w[i]))
			}()
		}
		wg.Wait()
		got, err := store.GetByID(ctx, "wi-race")
		require.NoError(t, err)
		assert.Equal(t, "confirmed", got.AttestationSource)
		assert.Equal(t, base.AttestationCount, got.AttestationCount)
	})
}
