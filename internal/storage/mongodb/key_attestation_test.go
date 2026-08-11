package mongodb

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

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
