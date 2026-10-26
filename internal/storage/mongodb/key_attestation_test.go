package mongodb

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/bson"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
)

func TestKeyAttestationStore_MarkAndGet(t *testing.T) {
	store := skipIfNoMongo(t)
	ctx := context.Background()
	kas := store.KeyAttestations()

	verifiedAt := time.Now().UTC().Truncate(time.Millisecond)
	rec := &domain.KeyAttestationRecord{
		KeyThumbprint:    "thumb-mongo-1",
		WalletInstanceID: "inst-mongo-1",
		TenantID:         "acme",
		AAGUID:           "aaguid-mongo-1",
		VerifiedAt:       verifiedAt,
	}
	require.NoError(t, kas.MarkKeyAttested(ctx, rec))

	got, err := kas.GetByKeyThumbprint(ctx, "thumb-mongo-1")
	require.NoError(t, err)
	require.Equal(t, "inst-mongo-1", got.WalletInstanceID)
	require.Equal(t, "aaguid-mongo-1", got.AAGUID)
	require.WithinDuration(t, verifiedAt, got.VerifiedAt, time.Second)
}

func TestKeyAttestationStore_GetByKeyThumbprint_NotFound(t *testing.T) {
	store := skipIfNoMongo(t)
	ctx := context.Background()
	kas := store.KeyAttestations()

	_, err := kas.GetByKeyThumbprint(ctx, "does-not-exist")
	require.Error(t, err)
	require.True(t, errors.Is(err, storage.ErrNotFound))
}

func TestKeyAttestationStore_DeleteIfUnchanged(t *testing.T) {
	store := skipIfNoMongo(t)
	ctx := context.Background()
	kas := store.KeyAttestations()

	first := &domain.KeyAttestationRecord{KeyThumbprint: "thumb-mongo-del", VerifiedAt: time.Now().UTC()}
	require.NoError(t, kas.MarkKeyAttested(ctx, first))
	stale := first.WriteToken
	second := &domain.KeyAttestationRecord{KeyThumbprint: "thumb-mongo-del", VerifiedAt: time.Now().UTC()}
	require.NoError(t, kas.MarkKeyAttested(ctx, second))

	require.ErrorIs(t, kas.DeleteIfUnchanged(ctx, "thumb-mongo-del", stale), storage.ErrNotFound)
	require.NoError(t, kas.DeleteIfUnchanged(ctx, "thumb-mongo-del", second.WriteToken))
	_, err := kas.GetByKeyThumbprint(ctx, "thumb-mongo-del")
	require.ErrorIs(t, err, storage.ErrNotFound)
}

func TestKeyAttestationStore_RestoreIfUnchanged(t *testing.T) {
	store := skipIfNoMongo(t)
	ctx := context.Background()
	kas := store.KeyAttestations()

	first := &domain.KeyAttestationRecord{KeyThumbprint: "thumb-mongo-restore", AAGUID: "old", VerifiedAt: time.Now().UTC(), CreatedAt: time.Now().UTC()}
	require.NoError(t, kas.MarkKeyAttested(ctx, first))
	require.Nil(t, first.Previous)
	second := &domain.KeyAttestationRecord{KeyThumbprint: "thumb-mongo-restore", AAGUID: "new", VerifiedAt: time.Now().UTC()}
	require.NoError(t, kas.MarkKeyAttested(ctx, second))
	require.NotNil(t, second.Previous)
	require.Equal(t, "old", second.Previous.AAGUID)

	stale := *first
	require.ErrorIs(t, kas.RestoreIfUnchanged(ctx, &stale, second.Previous), storage.ErrNotFound)
	written := *second
	require.NoError(t, kas.RestoreIfUnchanged(ctx, &written, second.Previous))
	got, err := kas.GetByKeyThumbprint(ctx, "thumb-mongo-restore")
	require.NoError(t, err)
	require.Equal(t, "old", got.AAGUID)
	require.ErrorIs(t, kas.RestoreIfUnchanged(ctx, &written, second.Previous), storage.ErrNotFound)
	require.NoError(t, kas.DeleteIfUnchanged(ctx, "thumb-mongo-restore", got.WriteToken))
}

func TestKeyAttestationStore_UVRoundTrip(t *testing.T) {
	store := skipIfNoMongo(t)
	ctx := context.Background()
	kas := store.KeyAttestations()

	require.NoError(t, kas.MarkKeyAttested(ctx, &domain.KeyAttestationRecord{KeyThumbprint: "thumb-mongo-uv", AAGUID: "a", UV: true, VerifiedAt: time.Now().UTC()}))
	got, err := kas.GetByKeyThumbprint(ctx, "thumb-mongo-uv")
	require.NoError(t, err)
	require.True(t, got.UV)

	require.NoError(t, kas.MarkKeyAttested(ctx, &domain.KeyAttestationRecord{KeyThumbprint: "thumb-mongo-uv", AAGUID: "a", UV: false, VerifiedAt: time.Now().UTC()}))
	got, err = kas.GetByKeyThumbprint(ctx, "thumb-mongo-uv")
	require.NoError(t, err)
	require.False(t, got.UV)
}

// Documents written before the uv field existed must decode with UV false.
// This needs no database: it is the same bson decoding GetByKeyThumbprint does.
func TestKeyAttestationRecord_LegacyDocumentReadsAsUVNone(t *testing.T) {
	legacy, err := bson.Marshal(bson.M{
		"_id": "thumb-old", "wallet_instance_id": "i", "tenant_id": "t",
		"aaguid": "a", "verified_at": time.Now().UTC(), "created_at": time.Now().UTC(),
	})
	require.NoError(t, err)
	var rec domain.KeyAttestationRecord
	require.NoError(t, bson.Unmarshal(legacy, &rec))
	require.Equal(t, "thumb-old", rec.KeyThumbprint)
	require.False(t, rec.UV)

	withUV, err := bson.Marshal(bson.M{"_id": "thumb-new", "aaguid": "a", "uv": true})
	require.NoError(t, err)
	require.NoError(t, bson.Unmarshal(withUV, &rec))
	require.True(t, rec.UV)
}
