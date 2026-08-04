package service

import (
	"context"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
)

// mongoWIAChallengeStore implements WIAChallengeStore using MongoDB.
// It uses a TTL index for automatic expiry of challenges and
// FindOneAndDelete for atomic single-use consumption.
type mongoWIAChallengeStore struct {
	collection       *mongo.Collection
	maxSize          int
	maxSizePerTenant int
}

type wiaChallengeDoc struct {
	Challenge string          `bson:"_id"`
	TenantID  domain.TenantID `bson:"tenant_id"`
	ExpiresAt time.Time       `bson:"expires_at"`
}

// NewMongoWIAChallengeStore creates a MongoDB-backed WIA challenge store.
// It creates the required TTL and tenant_id indexes on initialization.
func NewMongoWIAChallengeStore(ctx context.Context, db *mongo.Database, maxSize, maxSizePerTenant int) (*mongoWIAChallengeStore, error) {
	collection := db.Collection("wia_challenges")

	// Create TTL index for automatic expiry (MongoDB background thread runs every 60s).
	_, err := collection.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{Key: "expires_at", Value: 1}},
		Options: options.Index().SetExpireAfterSeconds(0),
	})
	if err != nil {
		return nil, err
	}

	// Index for efficient per-tenant capacity checks (issue #224: "bounded
	// capacity per tenant to prevent abuse").
	_, err = collection.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys: bson.D{{Key: "tenant_id", Value: 1}},
	})
	if err != nil {
		return nil, err
	}

	return &mongoWIAChallengeStore{
		collection:       collection,
		maxSize:          maxSize,
		maxSizePerTenant: maxSizePerTenant,
	}, nil
}

func (s *mongoWIAChallengeStore) Put(ctx context.Context, tenantID domain.TenantID, challenge string, expiresAt time.Time) (bool, error) {
	// Check global capacity. MongoDB's TTL monitor sweeps expired documents
	// only periodically (~every 60s), so counting all documents would let
	// already-expired-but-not-yet-swept challenges falsely exhaust capacity.
	// Count only unexpired ones instead.
	notExpired := bson.M{"expires_at": bson.M{"$gt": time.Now()}}
	count, err := s.collection.CountDocuments(ctx, notExpired)
	if err != nil {
		return false, err
	}
	if count >= int64(s.maxSize) {
		return false, nil
	}

	// Check per-tenant capacity — without this, a single tenant can exhaust
	// the entire global pool and deny challenge creation for every other
	// tenant, even though horizontal scaling and global capacity are fine.
	if s.maxSizePerTenant > 0 {
		tenantFilter := bson.M{"tenant_id": tenantID, "expires_at": bson.M{"$gt": time.Now()}}
		tenantCount, err := s.collection.CountDocuments(ctx, tenantFilter)
		if err != nil {
			return false, err
		}
		if tenantCount >= int64(s.maxSizePerTenant) {
			return false, nil
		}
	}

	doc := wiaChallengeDoc{
		Challenge: challenge,
		TenantID:  tenantID,
		ExpiresAt: expiresAt,
	}
	_, err = s.collection.InsertOne(ctx, doc)
	if err != nil {
		if mongo.IsDuplicateKeyError(err) {
			// Challenge already exists (extremely unlikely with 32-byte random nonces)
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func (s *mongoWIAChallengeStore) Consume(ctx context.Context, challenge string) (bool, error) {
	// Atomically find and delete: guarantees single-use even across multiple pods.
	result := s.collection.FindOneAndDelete(ctx, bson.M{
		"_id":        challenge,
		"expires_at": bson.M{"$gt": time.Now()},
	})

	if result.Err() != nil {
		if result.Err() == mongo.ErrNoDocuments {
			return false, nil
		}
		return false, result.Err()
	}
	return true, nil
}

func (s *mongoWIAChallengeStore) Len(ctx context.Context) (int, error) {
	count, err := s.collection.EstimatedDocumentCount(ctx)
	return int(count), err
}
