package service

import (
	"context"
	"errors"

	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

// CredentialService handles credential operations
type CredentialService struct {
	store  storage.Store
	cfg    *config.Config
	logger *zap.Logger
}

// NewCredentialService creates a new CredentialService
func NewCredentialService(store storage.Store, cfg *config.Config, logger *zap.Logger) *CredentialService {
	return &CredentialService{
		store:  store,
		cfg:    cfg,
		logger: logger.Named("credential-service"),
	}
}

// Store stores a new credential
func (s *CredentialService) Store(ctx context.Context, tenantID domain.TenantID, req *domain.StoreCredentialRequest) (*domain.VerifiableCredential, error) {
	if req.HolderDID == "" {
		return nil, errors.New("holder_did is required")
	}
	if req.CredentialIdentifier == "" {
		return nil, errors.New("credential_identifier is required")
	}
	if req.Credential == "" {
		return nil, errors.New("credential is required")
	}
	if req.Format == "" {
		return nil, errors.New("format is required")
	}

	credential := &domain.VerifiableCredential{
		TenantID:                   tenantID,
		HolderDID:                  req.HolderDID,
		CredentialIdentifier:       req.CredentialIdentifier,
		Credential:                 req.Credential,
		Format:                     req.Format,
		CredentialConfigurationID:  req.CredentialConfigurationID,
		CredentialIssuerIdentifier: req.CredentialIssuerIdentifier,
		InstanceID:                 req.InstanceID,
		SigCount:                   0,
	}

	if err := s.store.Credentials().Create(ctx, credential); err != nil {
		s.logger.Error("Failed to store credential", zap.Error(err))
		return nil, err
	}

	s.logger.Info("Stored credential",
		zap.String("tenant_id", string(tenantID)),
		zap.String("holder_did", req.HolderDID),
		zap.String("credential_id", req.CredentialIdentifier))

	return credential, nil
}

// GetAll retrieves all credentials for a holder in a tenant
func (s *CredentialService) GetAll(ctx context.Context, tenantID domain.TenantID, holderDID string) ([]*domain.VerifiableCredential, error) {
	if holderDID == "" {
		return nil, errors.New("holder_did is required")
	}

	credentials, err := s.store.Credentials().GetAllByHolder(ctx, tenantID, holderDID)
	if err != nil {
		s.logger.Error("Failed to get credentials", zap.Error(err),
			zap.String("tenant_id", string(tenantID)),
			zap.String("holder_did", holderDID))
		return nil, err
	}

	return credentials, nil
}

// GetByIdentifier retrieves a credential by identifier
func (s *CredentialService) GetByIdentifier(ctx context.Context, tenantID domain.TenantID, holderDID, credentialIdentifier string) (*domain.VerifiableCredential, error) {
	if holderDID == "" {
		return nil, errors.New("holder_did is required")
	}
	if credentialIdentifier == "" {
		return nil, errors.New("credential_identifier is required")
	}

	credential, err := s.store.Credentials().GetByIdentifier(ctx, tenantID, holderDID, credentialIdentifier)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, err
		}
		s.logger.Error("Failed to get credential", zap.Error(err),
			zap.String("tenant_id", string(tenantID)),
			zap.String("holder_did", holderDID),
			zap.String("credential_id", credentialIdentifier))
		return nil, err
	}

	return credential, nil
}

// Update updates a credential
func (s *CredentialService) Update(ctx context.Context, tenantID domain.TenantID, holderDID string, req *domain.UpdateCredentialRequest) (*domain.VerifiableCredential, error) {
	if holderDID == "" {
		return nil, errors.New("holder_did is required")
	}
	if req.CredentialIdentifier == "" {
		return nil, errors.New("credential_identifier is required")
	}

	// Get existing credential
	credential, err := s.store.Credentials().GetByIdentifier(ctx, tenantID, holderDID, req.CredentialIdentifier)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, err
		}
		s.logger.Error("Failed to get credential for update", zap.Error(err))
		return nil, err
	}

	// Update fields
	credential.InstanceID = req.InstanceID
	credential.SigCount = req.SigCount

	if err := s.store.Credentials().Update(ctx, credential); err != nil {
		s.logger.Error("Failed to update credential", zap.Error(err))
		return nil, err
	}

	s.logger.Info("Updated credential",
		zap.String("tenant_id", string(tenantID)),
		zap.String("holder_did", holderDID),
		zap.String("credential_id", req.CredentialIdentifier))

	return credential, nil
}

// Delete deletes a credential
func (s *CredentialService) Delete(ctx context.Context, tenantID domain.TenantID, holderDID, credentialIdentifier string) error {
	if holderDID == "" {
		return errors.New("holder_did is required")
	}
	if credentialIdentifier == "" {
		return errors.New("credential_identifier is required")
	}

	if err := s.store.Credentials().Delete(ctx, tenantID, holderDID, credentialIdentifier); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return err
		}
		s.logger.Error("Failed to delete credential", zap.Error(err))
		return err
	}

	s.logger.Info("Deleted credential",
		zap.String("tenant_id", string(tenantID)),
		zap.String("holder_did", holderDID),
		zap.String("credential_id", credentialIdentifier))

	return nil
}
