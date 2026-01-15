package service

import (
	"context"
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

// GetAll retrieves all verifiers for a tenant
func (s *VerifierService) GetAll(ctx context.Context, tenantID domain.TenantID) ([]*domain.Verifier, error) {
	verifiers, err := s.store.Verifiers().GetAll(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get verifiers: %w", err)
	}
	return verifiers, nil
}
