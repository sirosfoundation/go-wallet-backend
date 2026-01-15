package service

import (
	"context"

	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
)

// TenantService provides tenant management operations
type TenantService struct {
	store  storage.Store
	logger *zap.Logger
}

// NewTenantService creates a new tenant service
func NewTenantService(store storage.Store, logger *zap.Logger) *TenantService {
	return &TenantService{
		store:  store,
		logger: logger,
	}
}

// Create creates a new tenant
func (s *TenantService) Create(ctx context.Context, tenant *domain.Tenant) error {
	if err := s.store.Tenants().Create(ctx, tenant); err != nil {
		s.logger.Error("Failed to create tenant",
			zap.String("tenant_id", string(tenant.ID)),
			zap.Error(err))
		return err
	}

	s.logger.Info("Created tenant",
		zap.String("tenant_id", string(tenant.ID)),
		zap.String("name", tenant.Name))

	return nil
}

// GetByID retrieves a tenant by ID
func (s *TenantService) GetByID(ctx context.Context, id domain.TenantID) (*domain.Tenant, error) {
	return s.store.Tenants().GetByID(ctx, id)
}

// GetAll retrieves all tenants
func (s *TenantService) GetAll(ctx context.Context) ([]*domain.Tenant, error) {
	return s.store.Tenants().GetAll(ctx)
}

// GetAllEnabled retrieves all enabled tenants
func (s *TenantService) GetAllEnabled(ctx context.Context) ([]*domain.Tenant, error) {
	return s.store.Tenants().GetAllEnabled(ctx)
}

// Update updates a tenant
func (s *TenantService) Update(ctx context.Context, tenant *domain.Tenant) error {
	if err := s.store.Tenants().Update(ctx, tenant); err != nil {
		s.logger.Error("Failed to update tenant",
			zap.String("tenant_id", string(tenant.ID)),
			zap.Error(err))
		return err
	}

	s.logger.Info("Updated tenant", zap.String("tenant_id", string(tenant.ID)))
	return nil
}

// Delete deletes a tenant
func (s *TenantService) Delete(ctx context.Context, id domain.TenantID) error {
	if err := s.store.Tenants().Delete(ctx, id); err != nil {
		s.logger.Error("Failed to delete tenant",
			zap.String("tenant_id", string(id)),
			zap.Error(err))
		return err
	}

	s.logger.Info("Deleted tenant", zap.String("tenant_id", string(id)))
	return nil
}

// UserTenantService provides user-tenant membership operations
type UserTenantService struct {
	store  storage.Store
	logger *zap.Logger
}

// NewUserTenantService creates a new user-tenant service
func NewUserTenantService(store storage.Store, logger *zap.Logger) *UserTenantService {
	return &UserTenantService{
		store:  store,
		logger: logger,
	}
}

// AddUserToTenant adds a user to a tenant
func (s *UserTenantService) AddUserToTenant(ctx context.Context, userID domain.UserID, tenantID domain.TenantID, role string) error {
	if role == "" {
		role = domain.TenantRoleUser
	}

	membership := &domain.UserTenantMembership{
		UserID:   userID,
		TenantID: tenantID,
		Role:     role,
	}

	if err := s.store.UserTenants().AddMembership(ctx, membership); err != nil {
		s.logger.Error("Failed to add user to tenant",
			zap.String("user_id", userID.String()),
			zap.String("tenant_id", string(tenantID)),
			zap.Error(err))
		return err
	}

	s.logger.Info("Added user to tenant",
		zap.String("user_id", userID.String()),
		zap.String("tenant_id", string(tenantID)),
		zap.String("role", role))

	return nil
}

// RemoveUserFromTenant removes a user from a tenant
func (s *UserTenantService) RemoveUserFromTenant(ctx context.Context, userID domain.UserID, tenantID domain.TenantID) error {
	if err := s.store.UserTenants().RemoveMembership(ctx, userID, tenantID); err != nil {
		s.logger.Error("Failed to remove user from tenant",
			zap.String("user_id", userID.String()),
			zap.String("tenant_id", string(tenantID)),
			zap.Error(err))
		return err
	}

	s.logger.Info("Removed user from tenant",
		zap.String("user_id", userID.String()),
		zap.String("tenant_id", string(tenantID)))

	return nil
}

// GetUserTenants returns all tenants a user belongs to
func (s *UserTenantService) GetUserTenants(ctx context.Context, userID domain.UserID) ([]domain.TenantID, error) {
	return s.store.UserTenants().GetUserTenants(ctx, userID)
}

// GetTenantUsers returns all users in a tenant
func (s *UserTenantService) GetTenantUsers(ctx context.Context, tenantID domain.TenantID) ([]domain.UserID, error) {
	return s.store.UserTenants().GetTenantUsers(ctx, tenantID)
}

// IsMember checks if a user is a member of a tenant
func (s *UserTenantService) IsMember(ctx context.Context, userID domain.UserID, tenantID domain.TenantID) (bool, error) {
	return s.store.UserTenants().IsMember(ctx, userID, tenantID)
}

// GetMembership gets the membership details
func (s *UserTenantService) GetMembership(ctx context.Context, userID domain.UserID, tenantID domain.TenantID) (*domain.UserTenantMembership, error) {
	return s.store.UserTenants().GetMembership(ctx, userID, tenantID)
}
