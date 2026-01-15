package mongodb

import (
	"context"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
)

// TenantStore implements MongoDB tenant storage
type TenantStore struct {
	collection *mongo.Collection
}

func (s *TenantStore) Create(ctx context.Context, tenant *domain.Tenant) error {
	tenant.CreatedAt = time.Now()
	tenant.UpdatedAt = time.Now()

	_, err := s.collection.InsertOne(ctx, tenant)
	if err != nil {
		if mongo.IsDuplicateKeyError(err) {
			return storage.ErrAlreadyExists
		}
		return fmt.Errorf("failed to create tenant: %w", err)
	}
	return nil
}

func (s *TenantStore) GetByID(ctx context.Context, id domain.TenantID) (*domain.Tenant, error) {
	var tenant domain.Tenant
	err := s.collection.FindOne(ctx, bson.M{"_id": string(id)}).Decode(&tenant)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, storage.ErrNotFound
		}
		return nil, fmt.Errorf("failed to get tenant: %w", err)
	}
	return &tenant, nil
}

func (s *TenantStore) GetAll(ctx context.Context) ([]*domain.Tenant, error) {
	cursor, err := s.collection.Find(ctx, bson.M{})
	if err != nil {
		return nil, fmt.Errorf("failed to get tenants: %w", err)
	}
	defer func() { _ = cursor.Close(ctx) }()

	var tenants []*domain.Tenant
	if err := cursor.All(ctx, &tenants); err != nil {
		return nil, fmt.Errorf("failed to decode tenants: %w", err)
	}
	return tenants, nil
}

func (s *TenantStore) GetAllEnabled(ctx context.Context) ([]*domain.Tenant, error) {
	cursor, err := s.collection.Find(ctx, bson.M{"enabled": true})
	if err != nil {
		return nil, fmt.Errorf("failed to get enabled tenants: %w", err)
	}
	defer func() { _ = cursor.Close(ctx) }()

	var tenants []*domain.Tenant
	if err := cursor.All(ctx, &tenants); err != nil {
		return nil, fmt.Errorf("failed to decode tenants: %w", err)
	}
	return tenants, nil
}

func (s *TenantStore) Update(ctx context.Context, tenant *domain.Tenant) error {
	tenant.UpdatedAt = time.Now()
	result, err := s.collection.ReplaceOne(ctx, bson.M{"_id": string(tenant.ID)}, tenant)
	if err != nil {
		return fmt.Errorf("failed to update tenant: %w", err)
	}
	if result.MatchedCount == 0 {
		return storage.ErrNotFound
	}
	return nil
}

func (s *TenantStore) Delete(ctx context.Context, id domain.TenantID) error {
	result, err := s.collection.DeleteOne(ctx, bson.M{"_id": string(id)})
	if err != nil {
		return fmt.Errorf("failed to delete tenant: %w", err)
	}
	if result.DeletedCount == 0 {
		return storage.ErrNotFound
	}
	return nil
}

// UserTenantStore implements MongoDB user-tenant membership storage
type UserTenantStore struct {
	collection *mongo.Collection
}

func (s *UserTenantStore) AddMembership(ctx context.Context, membership *domain.UserTenantMembership) error {
	membership.CreatedAt = time.Now()

	_, err := s.collection.InsertOne(ctx, membership)
	if err != nil {
		if mongo.IsDuplicateKeyError(err) {
			return storage.ErrAlreadyExists
		}
		return fmt.Errorf("failed to add membership: %w", err)
	}
	return nil
}

func (s *UserTenantStore) RemoveMembership(ctx context.Context, userID domain.UserID, tenantID domain.TenantID) error {
	result, err := s.collection.DeleteOne(ctx, bson.M{
		"user_id":   userID.String(),
		"tenant_id": string(tenantID),
	})
	if err != nil {
		return fmt.Errorf("failed to remove membership: %w", err)
	}
	if result.DeletedCount == 0 {
		return storage.ErrNotFound
	}
	return nil
}

func (s *UserTenantStore) GetUserTenants(ctx context.Context, userID domain.UserID) ([]domain.TenantID, error) {
	cursor, err := s.collection.Find(ctx, bson.M{"user_id": userID.String()})
	if err != nil {
		return nil, fmt.Errorf("failed to get user tenants: %w", err)
	}
	defer func() { _ = cursor.Close(ctx) }()

	var memberships []domain.UserTenantMembership
	if err := cursor.All(ctx, &memberships); err != nil {
		return nil, fmt.Errorf("failed to decode memberships: %w", err)
	}

	tenantIDs := make([]domain.TenantID, len(memberships))
	for i, m := range memberships {
		tenantIDs[i] = m.TenantID
	}
	return tenantIDs, nil
}

func (s *UserTenantStore) GetTenantUsers(ctx context.Context, tenantID domain.TenantID) ([]domain.UserID, error) {
	cursor, err := s.collection.Find(ctx, bson.M{"tenant_id": string(tenantID)})
	if err != nil {
		return nil, fmt.Errorf("failed to get tenant users: %w", err)
	}
	defer func() { _ = cursor.Close(ctx) }()

	var memberships []domain.UserTenantMembership
	if err := cursor.All(ctx, &memberships); err != nil {
		return nil, fmt.Errorf("failed to decode memberships: %w", err)
	}

	userIDs := make([]domain.UserID, len(memberships))
	for i, m := range memberships {
		userIDs[i] = m.UserID
	}
	return userIDs, nil
}

func (s *UserTenantStore) IsMember(ctx context.Context, userID domain.UserID, tenantID domain.TenantID) (bool, error) {
	count, err := s.collection.CountDocuments(ctx, bson.M{
		"user_id":   userID.String(),
		"tenant_id": string(tenantID),
	})
	if err != nil {
		return false, fmt.Errorf("failed to check membership: %w", err)
	}
	return count > 0, nil
}

func (s *UserTenantStore) GetMembership(ctx context.Context, userID domain.UserID, tenantID domain.TenantID) (*domain.UserTenantMembership, error) {
	var membership domain.UserTenantMembership
	err := s.collection.FindOne(ctx, bson.M{
		"user_id":   userID.String(),
		"tenant_id": string(tenantID),
	}).Decode(&membership)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, storage.ErrNotFound
		}
		return nil, fmt.Errorf("failed to get membership: %w", err)
	}
	return &membership, nil
}
