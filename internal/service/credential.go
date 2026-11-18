package service

import (
	"context"
	"errors"

	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
	"github.com/sirosfoundation/go-wallet-backend/internal/tokengate"
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

	if err := tokengate.RefuseNow(ctx, s.store.Users()); err != nil {
		return nil, err
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

	// Storage-level fence: the admission check above cannot stop an erasure
	// advancing the cut-off and sweeping between it and the Create, which would
	// resurrect erased data. Re-read the cut-off now (tokengate.ConfirmWrite) and
	// roll back if refused. The rollback is conditional on this record's id and
	// write token, not the business key, so a recreated record is left alone;
	// both are captured now because the memory store hands out the stored pointer.
	createdID, createdToken := credential.ID, credential.WriteToken
	if err := tokengate.ConfirmWrite(ctx, s.store.Users(), func(rctx context.Context) error {
		return s.store.Credentials().DeleteIfUnchanged(rctx, tenantID, createdID, createdToken)
	}); err != nil {
		s.logger.Error("Credential write fenced out by a concurrent revocation", zap.Error(err),
			zap.String("tenant_id", string(tenantID)), zap.Bool("left_behind", errors.Is(err, tokengate.ErrWriteNotRolledBack)))
		return nil, err
	}

	s.logger.Info("Stored credential",
		zap.String("tenant_id", string(tenantID)),
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
			zap.String("tenant_id", string(tenantID)))
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

	if err := tokengate.RefuseNow(ctx, s.store.Users()); err != nil {
		return nil, err
	}

	// Copy for the fence's rollback, taken before the fields change.
	previous := *credential

	// Update fields
	credential.InstanceID = req.InstanceID
	credential.SigCount = req.SigCount

	if err := s.store.Credentials().Update(ctx, credential); err != nil {
		s.logger.Error("Failed to update credential", zap.Error(err))
		return nil, err
	}

	// Storage-level fence, as in Store. An update cannot resurrect an erased
	// record, but a revoked token must not change what it no longer may touch:
	// restore the previous values, conditional on this update's write token so a
	// recreated or re-updated record is not overwritten.
	written := *credential
	if err := tokengate.ConfirmWrite(ctx, s.store.Users(), func(rctx context.Context) error {
		return s.store.Credentials().RestoreIfUnchanged(rctx, &written, &previous)
	}); err != nil {
		s.logger.Error("Credential update fenced out by a concurrent revocation", zap.Error(err),
			zap.String("tenant_id", string(tenantID)), zap.Bool("not_restored", errors.Is(err, tokengate.ErrWriteNotRolledBack)))
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

	if err := tokengate.RefuseNow(ctx, s.store.Users()); err != nil {
		return err
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
