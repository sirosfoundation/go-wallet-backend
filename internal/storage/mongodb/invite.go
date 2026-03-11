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

// InviteStore implements MongoDB storage for invite codes
type InviteStore struct {
	collection *mongo.Collection
}

func (s *InviteStore) Create(ctx context.Context, invite *domain.Invite) error {
	_, err := s.collection.InsertOne(ctx, invite)
	if err != nil {
		if mongo.IsDuplicateKeyError(err) {
			return storage.ErrAlreadyExists
		}
		return fmt.Errorf("failed to create invite: %w", err)
	}
	return nil
}

func (s *InviteStore) GetByCode(ctx context.Context, tenantID domain.TenantID, code string) (*domain.Invite, error) {
	var invite domain.Invite
	err := s.collection.FindOne(ctx, bson.M{
		"tenant_id": tenantID,
		"code":      code,
	}).Decode(&invite)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, storage.ErrNotFound
		}
		return nil, fmt.Errorf("failed to get invite by code: %w", err)
	}
	return &invite, nil
}

func (s *InviteStore) GetByID(ctx context.Context, id string) (*domain.Invite, error) {
	var invite domain.Invite
	err := s.collection.FindOne(ctx, bson.M{"_id": id}).Decode(&invite)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, storage.ErrNotFound
		}
		return nil, fmt.Errorf("failed to get invite by ID: %w", err)
	}
	return &invite, nil
}

func (s *InviteStore) GetAllByTenant(ctx context.Context, tenantID domain.TenantID) ([]*domain.Invite, error) {
	cursor, err := s.collection.Find(ctx, bson.M{"tenant_id": tenantID},
		options.Find().SetSort(bson.D{{Key: "created_at", Value: -1}}))
	if err != nil {
		return nil, fmt.Errorf("failed to list invites: %w", err)
	}
	defer cursor.Close(ctx) //nolint:errcheck

	var invites []*domain.Invite
	if err := cursor.All(ctx, &invites); err != nil {
		return nil, fmt.Errorf("failed to decode invites: %w", err)
	}
	return invites, nil
}

func (s *InviteStore) MarkCompleted(ctx context.Context, tenantID domain.TenantID, code string, usedBy domain.UserID) error {
	now := time.Now()
	result, err := s.collection.UpdateOne(ctx,
		bson.M{
			"tenant_id": tenantID,
			"code":      code,
			"status":    domain.InviteStatusActive,
		},
		bson.M{
			"$set": bson.M{
				"status":     domain.InviteStatusCompleted,
				"used_by":    usedBy,
				"updated_at": now,
			},
		},
	)
	if err != nil {
		return fmt.Errorf("failed to mark invite completed: %w", err)
	}
	if result.MatchedCount == 0 {
		return storage.ErrNotFound
	}
	return nil
}

func (s *InviteStore) Update(ctx context.Context, invite *domain.Invite) error {
	invite.UpdatedAt = time.Now()
	result, err := s.collection.ReplaceOne(ctx, bson.M{"_id": invite.ID}, invite)
	if err != nil {
		return fmt.Errorf("failed to update invite: %w", err)
	}
	if result.MatchedCount == 0 {
		return storage.ErrNotFound
	}
	return nil
}

func (s *InviteStore) Delete(ctx context.Context, id string) error {
	result, err := s.collection.DeleteOne(ctx, bson.M{"_id": id})
	if err != nil {
		return fmt.Errorf("failed to delete invite: %w", err)
	}
	if result.DeletedCount == 0 {
		return storage.ErrNotFound
	}
	return nil
}
