package mongodb

import (
	"context"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
)

// WalletInstanceStore implements storage.WalletInstanceStore using MongoDB.
type WalletInstanceStore struct {
	collection *mongo.Collection
}

func (s *WalletInstanceStore) Upsert(ctx context.Context, instance *domain.WalletInstance) error {
	filter := bson.M{"_id": instance.ID}
	update := bson.M{
		"$set": bson.M{
			"tenant_id":          instance.TenantID,
			"status":             instance.Status,
			"attestation_source": instance.AttestationSource,
			"last_attested_at":   instance.LastAttestedAt,
			"updated_at":         instance.UpdatedAt,
		},
		"$setOnInsert": bson.M{
			"created_at": instance.CreatedAt,
		},
		"$inc": bson.M{
			"attestation_count": 1,
		},
	}
	if instance.UserID != nil {
		update["$set"].(bson.M)["user_id"] = instance.UserID
	}
	if instance.DeviceInfo != nil {
		update["$set"].(bson.M)["device_info"] = instance.DeviceInfo
	}

	opts := options.Update().SetUpsert(true)
	_, err := s.collection.UpdateOne(ctx, filter, update, opts)
	if err != nil {
		return fmt.Errorf("%w: upsert wallet instance: %v", storage.ErrDatabase, err)
	}
	return nil
}

func (s *WalletInstanceStore) GetByID(ctx context.Context, id string) (*domain.WalletInstance, error) {
	var instance domain.WalletInstance
	err := s.collection.FindOne(ctx, bson.M{"_id": id}).Decode(&instance)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, storage.ErrNotFound
		}
		return nil, fmt.Errorf("%w: get wallet instance: %v", storage.ErrDatabase, err)
	}
	return &instance, nil
}

func (s *WalletInstanceStore) GetAllByTenant(ctx context.Context, tenantID domain.TenantID) ([]*domain.WalletInstance, error) {
	cursor, err := s.collection.Find(ctx, bson.M{"tenant_id": tenantID})
	if err != nil {
		return nil, fmt.Errorf("%w: list wallet instances: %v", storage.ErrDatabase, err)
	}
	defer func() { _ = cursor.Close(ctx) }()

	var instances []*domain.WalletInstance
	if err := cursor.All(ctx, &instances); err != nil {
		return nil, fmt.Errorf("%w: decode wallet instances: %v", storage.ErrDatabase, err)
	}
	return instances, nil
}

func (s *WalletInstanceStore) GetByUser(ctx context.Context, tenantID domain.TenantID, userID domain.UserID) ([]*domain.WalletInstance, error) {
	filter := bson.M{
		"tenant_id": tenantID,
		"user_id":   userID,
	}
	cursor, err := s.collection.Find(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("%w: list wallet instances by user: %v", storage.ErrDatabase, err)
	}
	defer func() { _ = cursor.Close(ctx) }()

	var instances []*domain.WalletInstance
	if err := cursor.All(ctx, &instances); err != nil {
		return nil, fmt.Errorf("%w: decode wallet instances: %v", storage.ErrDatabase, err)
	}
	return instances, nil
}

func (s *WalletInstanceStore) UpdateStatus(ctx context.Context, id string, status domain.InstanceStatus, reason string) error {
	now := time.Now().UTC()

	// Use a conditional filter to enforce valid state transitions atomically.
	// Revoked instances cannot transition to any other state.
	filter := bson.M{"_id": id}
	switch status {
	case domain.InstanceStatusActive:
		// Only suspended → active is allowed (not revoked → active).
		filter["status"] = domain.InstanceStatusSuspended
	case domain.InstanceStatusSuspended:
		// Only active → suspended is allowed.
		filter["status"] = domain.InstanceStatusActive
	case domain.InstanceStatusRevoked:
		// active → revoked and suspended → revoked are both allowed.
		filter["status"] = bson.M{"$in": []domain.InstanceStatus{domain.InstanceStatusActive, domain.InstanceStatusSuspended}}
	}

	update := bson.M{
		"$set": bson.M{
			"status":              status,
			"deactivation_reason": reason,
			"updated_at":          now,
		},
	}
	if status == domain.InstanceStatusSuspended || status == domain.InstanceStatusRevoked {
		update["$set"].(bson.M)["deactivated_at"] = now
	} else {
		update["$unset"] = bson.M{"deactivated_at": "", "deactivation_reason": ""}
	}

	res, err := s.collection.UpdateOne(ctx, filter, update)
	if err != nil {
		return fmt.Errorf("%w: update wallet instance status: %v", storage.ErrDatabase, err)
	}
	if res.MatchedCount == 0 {
		// Distinguish "not found" from "invalid transition" by checking existence.
		count, cerr := s.collection.CountDocuments(ctx, bson.M{"_id": id})
		if cerr != nil || count == 0 {
			return storage.ErrNotFound
		}
		return domain.ErrInvalidStatusTransition
	}
	return nil
}

func (s *WalletInstanceStore) IncrementAttestation(ctx context.Context, id string) error {
	now := time.Now().UTC()
	update := bson.M{
		"$inc": bson.M{"attestation_count": 1},
		"$set": bson.M{
			"last_attested_at": now,
			"updated_at":       now,
		},
	}
	res, err := s.collection.UpdateByID(ctx, id, update)
	if err != nil {
		return fmt.Errorf("%w: increment attestation: %v", storage.ErrDatabase, err)
	}
	if res.MatchedCount == 0 {
		return storage.ErrNotFound
	}
	return nil
}

func (s *WalletInstanceStore) Delete(ctx context.Context, id string) error {
	res, err := s.collection.DeleteOne(ctx, bson.M{"_id": id})
	if err != nil {
		return fmt.Errorf("%w: delete wallet instance: %v", storage.ErrDatabase, err)
	}
	if res.DeletedCount == 0 {
		return storage.ErrNotFound
	}
	return nil
}
