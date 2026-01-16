package service

import (
	"context"
	"errors"
	"fmt"

	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
)

// VerifierService handles verifier operations
type VerifierService struct {
	store  storage.Store
	logger *zap.Logger
}

// NewVerifierService creates a new VerifierService
func NewVerifierService(store storage.Store, logger *zap.Logger) *VerifierService {
	return &VerifierService{
		store:  store,
		logger: logger.Named("verifier-service"),
	}
}

// Create creates a new verifier
func (s *VerifierService) Create(ctx context.Context, tenantID domain.TenantID, verifier *domain.Verifier) error {
	// Validate required fields
	if verifier.Name == "" {
		return fmt.Errorf("verifier name is required")
	}
	if verifier.URL == "" {
		return fmt.Errorf("verifier URL is required")
	}

	// Set tenant ID
	verifier.TenantID = tenantID

	if err := s.store.Verifiers().Create(ctx, verifier); err != nil {
		return fmt.Errorf("failed to create verifier: %w", err)
	}

	s.logger.Info("Verifier created",
		zap.String("tenant_id", string(tenantID)),
		zap.String("name", verifier.Name))

	return nil
}

// GetByID retrieves a verifier by ID within a tenant
func (s *VerifierService) GetByID(ctx context.Context, tenantID domain.TenantID, id int64) (*domain.Verifier, error) {
	verifier, err := s.store.Verifiers().GetByID(ctx, tenantID, id)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, storage.ErrNotFound
		}
		return nil, fmt.Errorf("failed to get verifier: %w", err)
	}
	return verifier, nil
}

// GetAll retrieves all verifiers for a tenant
func (s *VerifierService) GetAll(ctx context.Context, tenantID domain.TenantID) ([]*domain.Verifier, error) {
	verifiers, err := s.store.Verifiers().GetAll(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get verifiers: %w", err)
	}
	return verifiers, nil
}

// Update updates an existing verifier
func (s *VerifierService) Update(ctx context.Context, verifier *domain.Verifier) error {
	if err := s.store.Verifiers().Update(ctx, verifier); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return storage.ErrNotFound
		}
		return fmt.Errorf("failed to update verifier: %w", err)
	}

	s.logger.Info("Verifier updated",
		zap.Int64("id", verifier.ID),
		zap.String("name", verifier.Name))

	return nil
}

// Delete removes a verifier
func (s *VerifierService) Delete(ctx context.Context, tenantID domain.TenantID, id int64) error {
	if err := s.store.Verifiers().Delete(ctx, tenantID, id); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return storage.ErrNotFound
		}
		return fmt.Errorf("failed to delete verifier: %w", err)
	}

	s.logger.Info("Verifier deleted",
		zap.String("tenant_id", string(tenantID)),
		zap.Int64("id", id))

	return nil
}
