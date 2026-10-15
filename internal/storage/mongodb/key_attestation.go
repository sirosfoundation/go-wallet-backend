package mongodb

import (
	"context"
	"fmt"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
)

// KeyAttestationStore implements storage.KeyAttestationStore using MongoDB.
type KeyAttestationStore struct {
	collection *mongo.Collection
}

func (s *KeyAttestationStore) MarkKeyAttested(ctx context.Context, rec *domain.KeyAttestationRecord) error {
	filter := bson.M{"_id": rec.KeyThumbprint}
	rec.WriteToken = storage.NewWriteToken()
	update := bson.M{
		"$set": bson.M{
			"wallet_instance_id": rec.WalletInstanceID,
			"tenant_id":          rec.TenantID,
			"aaguid":             rec.AAGUID,
			"verified_at":        rec.VerifiedAt,
			"write_token":        rec.WriteToken,
		},
		"$setOnInsert": bson.M{
			"created_at": rec.CreatedAt,
		},
	}
	opts := options.Update().SetUpsert(true)
	_, err := s.collection.UpdateOne(ctx, filter, update, opts)
	if err != nil {
		return fmt.Errorf("%w: mark key attested: %v", storage.ErrDatabase, err)
	}
	return nil
}

func (s *KeyAttestationStore) GetByKeyThumbprint(ctx context.Context, thumbprint string) (*domain.KeyAttestationRecord, error) {
	var rec domain.KeyAttestationRecord
	err := s.collection.FindOne(ctx, bson.M{"_id": thumbprint}).Decode(&rec)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, storage.ErrNotFound
		}
		return nil, fmt.Errorf("%w: get key attestation: %v", storage.ErrDatabase, err)
	}
	return &rec, nil
}

// DeleteIfUnchanged is one atomic filtered DeleteOne on the write token.
func (s *KeyAttestationStore) DeleteIfUnchanged(ctx context.Context, thumbprint, writeToken string) error {
	if writeToken == "" {
		return storage.ErrNotFound
	}
	result, err := s.collection.DeleteOne(ctx, bson.M{"_id": thumbprint, "write_token": writeToken})
	if err != nil {
		return fmt.Errorf("%w: delete key attestation: %v", storage.ErrDatabase, err)
	}
	if result.DeletedCount == 0 {
		return storage.ErrNotFound
	}
	return nil
}
