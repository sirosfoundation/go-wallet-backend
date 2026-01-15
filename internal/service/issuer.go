package service

import (
	"context"
	"errors"
	"fmt"

	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
)

// IssuerService handles credential issuer operations
type IssuerService struct {
	store  storage.Store
	logger *zap.Logger
}

// NewIssuerService creates a new IssuerService
func NewIssuerService(store storage.Store, logger *zap.Logger) *IssuerService {
	return &IssuerService{
		store:  store,
		logger: logger.Named("issuer-service"),
	}
}

// Create creates a new credential issuer
func (s *IssuerService) Create(ctx context.Context, tenantID domain.TenantID, issuer *domain.CredentialIssuer) error {
	// Validate required fields
	if issuer.CredentialIssuerIdentifier == "" {
		return fmt.Errorf("credential issuer identifier is required")
	}

	// Set tenant ID
	issuer.TenantID = tenantID

	// Check if issuer already exists in this tenant
	existing, err := s.store.Issuers().GetByIdentifier(ctx, tenantID, issuer.CredentialIssuerIdentifier)
	if err == nil && existing != nil {
		return storage.ErrAlreadyExists
	}
	if err != nil && !errors.Is(err, storage.ErrNotFound) {
		return fmt.Errorf("failed to check existing issuer: %w", err)
	}

	if err := s.store.Issuers().Create(ctx, issuer); err != nil {
		return fmt.Errorf("failed to create issuer: %w", err)
	}

	s.logger.Info("Issuer created",
		zap.String("tenant_id", string(tenantID)),
		zap.String("identifier", issuer.CredentialIssuerIdentifier))

	return nil
}

// Get retrieves an issuer by identifier within a tenant
func (s *IssuerService) Get(ctx context.Context, tenantID domain.TenantID, identifier string) (*domain.CredentialIssuer, error) {
	issuer, err := s.store.Issuers().GetByIdentifier(ctx, tenantID, identifier)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, storage.ErrNotFound
		}
		return nil, fmt.Errorf("failed to get issuer: %w", err)
	}
	return issuer, nil
}

// GetByID retrieves an issuer by ID within a tenant
func (s *IssuerService) GetByID(ctx context.Context, tenantID domain.TenantID, id int64) (*domain.CredentialIssuer, error) {
	issuer, err := s.store.Issuers().GetByID(ctx, tenantID, id)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, storage.ErrNotFound
		}
		return nil, fmt.Errorf("failed to get issuer: %w", err)
	}
	return issuer, nil
}

// GetAll retrieves all issuers for a tenant
func (s *IssuerService) GetAll(ctx context.Context, tenantID domain.TenantID) ([]*domain.CredentialIssuer, error) {
	issuers, err := s.store.Issuers().GetAll(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get issuers: %w", err)
	}
	return issuers, nil
}

// Update updates an existing issuer
func (s *IssuerService) Update(ctx context.Context, issuer *domain.CredentialIssuer) error {
	if err := s.store.Issuers().Update(ctx, issuer); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return storage.ErrNotFound
		}
		return fmt.Errorf("failed to update issuer: %w", err)
	}

	s.logger.Info("Issuer updated",
		zap.Int64("id", issuer.ID),
		zap.String("identifier", issuer.CredentialIssuerIdentifier))

	return nil
}

// Delete removes an issuer
func (s *IssuerService) Delete(ctx context.Context, tenantID domain.TenantID, id int64) error {
	if err := s.store.Issuers().Delete(ctx, tenantID, id); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return storage.ErrNotFound
		}
		return fmt.Errorf("failed to delete issuer: %w", err)
	}

	s.logger.Info("Issuer deleted",
		zap.String("tenant_id", string(tenantID)),
		zap.Int64("id", id))

	return nil
}
