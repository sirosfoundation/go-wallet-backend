package service

import (
	"context"
	"errors"
	"fmt"

	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
)

// PresentationService handles presentation operations
type PresentationService struct {
	store  storage.Store
	logger *zap.Logger
}

// NewPresentationService creates a new PresentationService
func NewPresentationService(store storage.Store, logger *zap.Logger) *PresentationService {
	return &PresentationService{
		store:  store,
		logger: logger.Named("presentation-service"),
	}
}

// Store creates a new presentation
func (s *PresentationService) Store(ctx context.Context, presentation *domain.VerifiablePresentation) error {
	// Validate required fields
	if presentation.HolderDID == "" {
		return fmt.Errorf("holder DID is required")
	}
	if presentation.PresentationIdentifier == "" {
		return fmt.Errorf("presentation identifier is required")
	}

	// Check if presentation already exists
	existing, err := s.store.Presentations().GetByIdentifier(ctx, presentation.HolderDID, presentation.PresentationIdentifier)
	if err == nil && existing != nil {
		return storage.ErrAlreadyExists
	}
	if err != nil && !errors.Is(err, storage.ErrNotFound) {
		return fmt.Errorf("failed to check existing presentation: %w", err)
	}

	if err := s.store.Presentations().Create(ctx, presentation); err != nil {
		return fmt.Errorf("failed to create presentation: %w", err)
	}

	s.logger.Info("Presentation stored",
		zap.String("holder_did", presentation.HolderDID),
		zap.String("presentation_id", presentation.PresentationIdentifier))

	return nil
}

// Get retrieves a presentation by identifier
func (s *PresentationService) Get(ctx context.Context, holderDID, presentationIdentifier string) (*domain.VerifiablePresentation, error) {
	presentation, err := s.store.Presentations().GetByIdentifier(ctx, holderDID, presentationIdentifier)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, storage.ErrNotFound
		}
		return nil, fmt.Errorf("failed to get presentation: %w", err)
	}
	return presentation, nil
}

// GetAll retrieves all presentations for a holder
func (s *PresentationService) GetAll(ctx context.Context, holderDID string) ([]*domain.VerifiablePresentation, error) {
	presentations, err := s.store.Presentations().GetAllByHolder(ctx, holderDID)
	if err != nil {
		return nil, fmt.Errorf("failed to get presentations: %w", err)
	}
	return presentations, nil
}

// Delete removes a presentation
func (s *PresentationService) Delete(ctx context.Context, holderDID, presentationIdentifier string) error {
	if err := s.store.Presentations().Delete(ctx, holderDID, presentationIdentifier); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return storage.ErrNotFound
		}
		return fmt.Errorf("failed to delete presentation: %w", err)
	}

	s.logger.Info("Presentation deleted",
		zap.String("holder_did", holderDID),
		zap.String("presentation_id", presentationIdentifier))

	return nil
}

// DeleteByCredentialID removes all presentations containing a specific credential
func (s *PresentationService) DeleteByCredentialID(ctx context.Context, holderDID, credentialID string) error {
	if err := s.store.Presentations().DeleteByCredentialID(ctx, holderDID, credentialID); err != nil {
		return fmt.Errorf("failed to delete presentations by credential: %w", err)
	}

	s.logger.Info("Presentations deleted by credential",
		zap.String("holder_did", holderDID),
		zap.String("credential_id", credentialID))

	return nil
}
