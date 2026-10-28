package mongodb

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/bson"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
)

func mongoAppAttestRecord(id string) *domain.AppAttestKeyRecord {
	u := domain.UserIDFromString("u1")
	return &domain.AppAttestKeyRecord{
		KeyID: id, PublicKey: []byte{4, 1, 2, 3}, Environment: domain.AppAttestProduction,
		AppID: "T.b", ChainVerified: true, TenantID: "acme", UserID: &u,
		WalletInstanceID: "inst", Status: domain.AppAttestKeyActive,
	}
}

func TestAppAttestKeyStore_RoundTripAndNoReset(t *testing.T) {
	store := skipIfNoMongo(t)
	ctx := context.Background()
	s := store.AppAttestKeys()
	id := "aak-" + time.Now().Format("150405.000000")
	require.NoError(t, s.Create(ctx, mongoAppAttestRecord(id)))
	require.NoError(t, s.AdvanceCounter(ctx, id, 5))
	require.True(t, errors.Is(s.Create(ctx, mongoAppAttestRecord(id)), storage.ErrAlreadyExists))
	got, err := s.Get(ctx, id)
	require.NoError(t, err)
	require.Equal(t, uint32(5), got.Counter)
	require.Equal(t, []byte{4, 1, 2, 3}, got.PublicKey)
	require.True(t, got.BelongsTo("acme", &domain.UserID{ID: "u1"}))
	require.True(t, got.IsActive())
	_, err = s.Get(ctx, "aak-missing")
	require.True(t, errors.Is(err, storage.ErrNotFound))
}

func TestAppAttestKeyStore_CounterStrictAndRevoked(t *testing.T) {
	store := skipIfNoMongo(t)
	ctx := context.Background()
	s := store.AppAttestKeys()
	id := "aak-strict-" + time.Now().Format("150405.000000")
	require.NoError(t, s.Create(ctx, mongoAppAttestRecord(id)))
	require.NoError(t, s.AdvanceCounter(ctx, id, 3))
	for _, c := range []uint32{3, 2, 0} {
		require.True(t, errors.Is(s.AdvanceCounter(ctx, id, c), storage.ErrCounterNotAdvanced), "counter %d", c)
	}
	require.True(t, errors.Is(s.AdvanceCounter(ctx, "aak-missing", 1), storage.ErrNotFound))
	require.NoError(t, s.Revoke(ctx, id))
	require.True(t, errors.Is(s.AdvanceCounter(ctx, id, 99), storage.ErrCounterNotAdvanced))
	require.True(t, errors.Is(s.Revoke(ctx, "aak-missing"), storage.ErrNotFound))
	// The full uint32 range is representable.
	id2 := id + "-max"
	require.NoError(t, s.Create(ctx, mongoAppAttestRecord(id2)))
	require.NoError(t, s.AdvanceCounter(ctx, id2, ^uint32(0)))
	got, err := s.Get(ctx, id2)
	require.NoError(t, err)
	require.Equal(t, ^uint32(0), got.Counter)
}

func TestAppAttestKeyStore_ConcurrentAdvanceExactlyOneWins(t *testing.T) {
	store := skipIfNoMongo(t)
	ctx := context.Background()
	s := store.AppAttestKeys()
	id := "aak-race-" + time.Now().Format("150405.000000")
	require.NoError(t, s.Create(ctx, mongoAppAttestRecord(id)))
	var wins atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if s.AdvanceCounter(ctx, id, 7) == nil {
				wins.Add(1)
			}
		}()
	}
	wg.Wait()
	require.Equal(t, int32(1), wins.Load())
}

// A document written by another tool or version, with an int32 counter, no
// status and no user, decodes; and a missing status is NOT active (fail
// closed). Needs no database: it is the decoding Get does.
func TestAppAttestKeyDoc_LegacyShapeFailsClosed(t *testing.T) {
	raw, err := bson.Marshal(bson.M{
		"_id": "old", "public_key": []byte{4, 9}, "counter": int32(4),
		"environment": "production", "tenant_id": "t",
	})
	require.NoError(t, err)
	var doc appAttestKeyDoc
	require.NoError(t, bson.Unmarshal(raw, &doc))
	rec := doc.record()
	require.Equal(t, uint32(4), rec.Counter)
	require.Nil(t, rec.UserID)
	require.False(t, rec.IsActive(), "a record without status must not be usable")
	require.False(t, rec.VerifiedHomeEligible(), "no chain_verified field reads as not verified")
}
