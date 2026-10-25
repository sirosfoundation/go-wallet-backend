package mongodb

import (
	"context"
	"errors"
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

func TestKeyAttestationStore_UVRoundTripNoDowngrade(t *testing.T) {
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
	require.True(t, got.UV, "weaker evidence must not overwrite")
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
	rec.Normalize()
	require.Equal(t, domain.KeyEvidenceFIDO2, rec.Kind)
	require.Equal(t, domain.KeyHomeFIDO2Hardware, rec.Home)

	withUV, err := bson.Marshal(bson.M{"_id": "thumb-new", "aaguid": "a", "uv": true})
	require.NoError(t, err)
	require.NoError(t, bson.Unmarshal(withUV, &rec))
	require.True(t, rec.UV)
}

func TestKeyAttestationStore_NewFieldsRoundTripAndNoOverwrite(t *testing.T) {
	store := skipIfNoMongo(t)
	ctx := context.Background()
	kas := store.KeyAttestations()
	locked := true
	notAfter := time.Now().Add(time.Hour).UTC().Truncate(time.Millisecond)
	require.NoError(t, kas.MarkKeyAttested(ctx, &domain.KeyAttestationRecord{
		KeyThumbprint: "thumb-mongo-new", Kind: domain.KeyEvidenceAndroidKey, Home: domain.KeyHomeTEE,
		SecurityLevel: "trusted_environment", VerifiedBootState: "verified", DeviceLocked: &locked,
		PatchLevel: "2026-09", AppDigest: "dg", ChainFingerprint: "fp", ChainNotAfter: notAfter,
		VerifiedAt: time.Now().UTC(),
	}))
	got, err := kas.GetByKeyThumbprint(ctx, "thumb-mongo-new")
	require.NoError(t, err)
	require.Equal(t, domain.KeyHomeTEE, got.Home)
	require.Equal(t, "verified", got.VerifiedBootState)
	require.NotNil(t, got.DeviceLocked)
	require.True(t, *got.DeviceLocked)
	require.True(t, notAfter.Equal(got.ChainNotAfter))
	created := got.CreatedAt

	// Weaker: ignored.
	require.NoError(t, kas.MarkKeyAttested(ctx, &domain.KeyAttestationRecord{KeyThumbprint: "thumb-mongo-new", Kind: domain.KeyEvidenceAppAttestAssertion, Home: domain.KeyHomeSecureEnclaveAsserted}))
	got, _ = kas.GetByKeyThumbprint(ctx, "thumb-mongo-new")
	require.Equal(t, domain.KeyHomeTEE, got.Home)
	// Stronger: replaces, CreatedAt kept.
	require.NoError(t, kas.MarkKeyAttested(ctx, &domain.KeyAttestationRecord{KeyThumbprint: "thumb-mongo-new", Kind: domain.KeyEvidenceAndroidKey, Home: domain.KeyHomeStrongBox}))
	got, _ = kas.GetByKeyThumbprint(ctx, "thumb-mongo-new")
	require.Equal(t, domain.KeyHomeStrongBox, got.Home)
	require.True(t, created.Equal(got.CreatedAt))
}

// A document stored before Rev, Kind and Home existed decodes and is then
// replaceable by the first CAS (no database needed for the decode half).
func TestKeyAttestationDoc_LegacyDecodeNormalizes(t *testing.T) {
	legacy, err := bson.Marshal(bson.M{"_id": "x", "aaguid": "a", "uv": true})
	require.NoError(t, err)
	var doc keyAttestationDoc
	require.NoError(t, bson.Unmarshal(legacy, &doc))
	require.Zero(t, doc.Rev)
	doc.Normalize()
	require.Equal(t, domain.KeyHomeFIDO2Hardware, doc.Home)
	require.Equal(t, "x", doc.KeyThumbprint)
}

// A pre-existing document without rev/kind/home is read as a FIDO2 hardware
// record, is not displaced by weaker evidence, and is replaced by the CAS path
// when the new evidence is not weaker.
func TestKeyAttestationStore_LegacyStoredDocument(t *testing.T) {
	store := skipIfNoMongo(t)
	ctx := context.Background()
	kas := store.KeyAttestations().(*KeyAttestationStore)
	_, err := kas.collection.InsertOne(ctx, bson.M{"_id": "thumb-legacy-db", "aaguid": "a", "uv": true, "verified_at": time.Now().UTC(), "created_at": time.Now().UTC()})
	require.NoError(t, err)

	got, err := kas.GetByKeyThumbprint(ctx, "thumb-legacy-db")
	require.NoError(t, err)
	require.Equal(t, domain.KeyHomeFIDO2Hardware, got.Home)

	require.NoError(t, kas.MarkKeyAttested(ctx, &domain.KeyAttestationRecord{KeyThumbprint: "thumb-legacy-db", Kind: domain.KeyEvidenceAndroidKey, Home: domain.KeyHomeTEE}))
	got, _ = kas.GetByKeyThumbprint(ctx, "thumb-legacy-db")
	require.Equal(t, domain.KeyEvidenceFIDO2, got.Kind, "weaker evidence displaced a legacy record")

	require.NoError(t, kas.MarkKeyAttested(ctx, &domain.KeyAttestationRecord{KeyThumbprint: "thumb-legacy-db", AAGUID: "b", UV: true, VerifiedAt: time.Now().UTC()}))
	got, _ = kas.GetByKeyThumbprint(ctx, "thumb-legacy-db")
	require.Equal(t, "b", got.AAGUID)
}

// Competing writers: whatever the interleaving, the strongest evidence wins
// and created_at is the first insert's. This exercises both the duplicate-key
// retry (simultaneous first inserts) and the revision compare-and-set (writers
// that read a stale record). Dropping the revision condition from the
// replacement lets a stale weaker writer overwrite a stronger one.
func TestKeyAttestationStore_CompetingWritersKeepStrongestEvidence(t *testing.T) {
	store := skipIfNoMongo(t)
	ctx := context.Background()
	kas := store.KeyAttestations()
	homes := []domain.KeyHome{domain.KeyHomeSecureEnclaveAsserted, domain.KeyHomeTEE, domain.KeyHomeStrongBox}

	for round := 0; round < 25; round++ {
		tp := fmt.Sprintf("thumb-race-%d", round)
		preexisting := round%2 == 1 // odd rounds race against an existing weak record
		if preexisting {
			require.NoError(t, kas.MarkKeyAttested(ctx, &domain.KeyAttestationRecord{KeyThumbprint: tp, Kind: domain.KeyEvidenceAndroidKey, Home: domain.KeyHomeSecureEnclaveAsserted, VerifiedAt: time.Now().UTC()}))
		}

		start := make(chan struct{})
		var wg sync.WaitGroup
		for i := 0; i < 24; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				<-start
				rec := &domain.KeyAttestationRecord{KeyThumbprint: tp, Kind: domain.KeyEvidenceAndroidKey, Home: homes[i%3], AppDigest: fmt.Sprintf("w%d", i), VerifiedAt: time.Now().UTC()}
				assert.NoError(t, kas.MarkKeyAttested(ctx, rec))
			}(i)
		}
		close(start)
		wg.Wait()

		got, err := kas.GetByKeyThumbprint(ctx, tp)
		require.NoError(t, err)
		require.Equal(t, domain.KeyHomeStrongBox, got.Home, "round %d: a weaker writer overwrote stronger evidence", round)
		require.False(t, got.CreatedAt.IsZero())

		// created_at survives a later replacement of the same rank.
		created := got.CreatedAt
		require.NoError(t, kas.MarkKeyAttested(ctx, &domain.KeyAttestationRecord{KeyThumbprint: tp, Kind: domain.KeyEvidenceAndroidKey, Home: domain.KeyHomeStrongBox, AppDigest: "later", VerifiedAt: time.Now().UTC()}))
		got, _ = kas.GetByKeyThumbprint(ctx, tp)
		require.Equal(t, "later", got.AppDigest)
		require.True(t, created.Equal(got.CreatedAt), "round %d: created_at changed", round)
	}
}

func TestKeyAttestationStore_CertSerialsAndRevocationMark(t *testing.T) {
	store := skipIfNoMongo(t)
	ctx := context.Background()
	kas := store.KeyAttestations()
	id := fmt.Sprintf("thumb-revoke-%d", time.Now().UnixNano())

	rec := &domain.KeyAttestationRecord{
		KeyThumbprint: id, Kind: domain.KeyEvidenceAndroidKey, Home: domain.KeyHomeStrongBox,
		ChainFingerprint: "fp1", CertSerials: []string{"a1", "b2"}, VerifiedAt: time.Now().UTC(),
	}
	require.NoError(t, kas.MarkKeyAttested(ctx, rec))
	got, err := kas.GetByKeyThumbprint(ctx, id)
	require.NoError(t, err)
	require.Equal(t, []string{"a1", "b2"}, got.CertSerials)
	require.False(t, got.Revoked())

	at := time.Now().UTC().Truncate(time.Millisecond)
	ok, err := kas.MarkKeyRevoked(ctx, id, "other-fingerprint", "r", at)
	require.NoError(t, err)
	require.False(t, ok, "marked a record whose chain was not the one checked")
	ok, err = kas.MarkKeyRevoked(ctx, "no-such-key", "fp1", "r", at)
	require.NoError(t, err)
	require.False(t, ok)

	ok, err = kas.MarkKeyRevoked(ctx, id, "fp1", "status_list_revoked", at)
	require.NoError(t, err)
	require.True(t, ok)
	ok, err = kas.MarkKeyRevoked(ctx, id, "fp1", "again", at)
	require.NoError(t, err)
	require.False(t, ok, "marked twice")

	got, err = kas.GetByKeyThumbprint(ctx, id)
	require.NoError(t, err)
	require.True(t, got.Revoked())
	require.Equal(t, "status_list_revoked", got.RevokedReason)
	require.Equal(t, domain.KeyHomeStrongBox, got.Home, "the record is kept, not deleted")

	// The mark bumped the revision: a fresh weaker record still replaces a
	// revoked one, through the compare-and-set.
	fresh := &domain.KeyAttestationRecord{KeyThumbprint: id, Kind: domain.KeyEvidenceAndroidKey, Home: domain.KeyHomeTEE, ChainFingerprint: "fp2", CertSerials: []string{"c3"}}
	require.NoError(t, kas.MarkKeyAttested(ctx, fresh))
	got, err = kas.GetByKeyThumbprint(ctx, id)
	require.NoError(t, err)
	require.False(t, got.Revoked())
	require.Equal(t, "fp2", got.ChainFingerprint)
	require.Equal(t, domain.KeyHomeTEE, got.Home)

	// Live stronger evidence is still protected from weaker evidence.
	require.NoError(t, kas.MarkKeyAttested(ctx, &domain.KeyAttestationRecord{KeyThumbprint: id, Kind: domain.KeyEvidenceAndroidKey, Home: domain.KeyHomeStrongBox, ChainFingerprint: "fp3"}))
	require.NoError(t, kas.MarkKeyAttested(ctx, &domain.KeyAttestationRecord{KeyThumbprint: id, Kind: domain.KeyEvidenceAndroidKey, Home: domain.KeyHomeTEE, ChainFingerprint: "fp4"}))
	got, _ = kas.GetByKeyThumbprint(ctx, id)
	require.Equal(t, "fp3", got.ChainFingerprint)

	// A document written before the new fields existed reads as legacy.
	legacyID := id + "-legacy"
	_, err = store.keyAttestations.collection.InsertOne(ctx, bson.M{"_id": legacyID, "kind": "android_key", "home": "tee", "tenant_id": "t", "chain_fingerprint": "legacy-fp"})
	require.NoError(t, err)
	got, err = kas.GetByKeyThumbprint(ctx, legacyID)
	require.NoError(t, err)
	require.Empty(t, got.CertSerials)
	require.False(t, got.Revoked())
	ok, err = kas.MarkKeyRevoked(ctx, legacyID, "legacy-fp", "r", at)
	require.NoError(t, err)
	require.True(t, ok, "a legacy document without a rev field must be markable")
	require.NoError(t, kas.MarkKeyAttested(ctx, &domain.KeyAttestationRecord{KeyThumbprint: legacyID, Kind: domain.KeyEvidenceAndroidKey, Home: domain.KeyHomeTEE, ChainFingerprint: "n"}))
}
