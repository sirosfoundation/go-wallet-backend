package service

import (
	"context"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// mongoWIAChallengeStore implements WIAChallengeStore using MongoDB.
// It uses a TTL index for automatic expiry of challenges and
// FindOneAndDelete for atomic single-use consumption.
type mongoWIAChallengeStore struct {
	collection *mongo.Collection
	maxSize    int
}

type wiaChallengeDoc struct {
	Challenge string    `bson:"_id"`
	ExpiresAt time.Time `bson:"expires_at"`
}

// NewMongoWIAChallengeStore creates a MongoDB-backed WIA challenge store.
// It creates the required TTL index on initialization.
func NewMongoWIAChallengeStore(ctx context.Context, db *mongo.Database, maxSize int) (*mongoWIAChallengeStore, error) {
	collection := db.Collection("wia_challenges")

	// Create TTL index for automatic expiry (MongoDB background thread runs every 60s).
	_, err := collection.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{Key: "expires_at", Value: 1}},
		Options: options.Index().SetExpireAfterSeconds(0),
	})
	if err != nil {
		return nil, err
	}

	return &mongoWIAChallengeStore{
		collection: collection,
		maxSize:    maxSize,
	}, nil
}

func (s *mongoWIAChallengeStore) Put(ctx context.Context, challenge string, expiresAt time.Time) (bool, error) {
	// Check capacity (estimated count is fast — O(1) via collection stats).
	count, err := s.collection.EstimatedDocumentCount(ctx)
	if err != nil {
		return false, err
	}
	if count >= int64(s.maxSize) {
		return false, nil
	}

	doc := wiaChallengeDoc{
		Challenge: challenge,
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
