package storage

import (
	"context"
	"errors"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
)

// Common errors
var (
	ErrNotFound      = errors.New("not found")
	ErrAlreadyExists = errors.New("already exists")
	ErrInvalidInput  = errors.New("invalid input")
	ErrDatabase      = errors.New("database error")
)

// UserStore defines the interface for user storage operations
type UserStore interface {
	// Create creates a new user
	Create(ctx context.Context, user *domain.User) error

	// GetByID retrieves a user by ID
	GetByID(ctx context.Context, id domain.UserID) (*domain.User, error)

	// GetByUsername retrieves a user by username
	GetByUsername(ctx context.Context, username string) (*domain.User, error)

	// GetByDID retrieves a user by DID
	GetByDID(ctx context.Context, did string) (*domain.User, error)

	// Update updates a user
	Update(ctx context.Context, user *domain.User) error

	// Delete deletes a user
	Delete(ctx context.Context, id domain.UserID) error

	// UpdatePrivateData updates user's private data with optimistic locking
	UpdatePrivateData(ctx context.Context, id domain.UserID, data []byte, ifMatch string) error
}

// CredentialStore defines the interface for credential storage operations
type CredentialStore interface {
	// Create creates a new credential
	Create(ctx context.Context, credential *domain.VerifiableCredential) error

	// GetByID retrieves a credential by ID
	GetByID(ctx context.Context, id int64) (*domain.VerifiableCredential, error)

	// GetByIdentifier retrieves a credential by credential identifier
	GetByIdentifier(ctx context.Context, holderDID, credentialIdentifier string) (*domain.VerifiableCredential, error)

	// GetAllByHolder retrieves all credentials for a holder
	GetAllByHolder(ctx context.Context, holderDID string) ([]*domain.VerifiableCredential, error)

	// Update updates a credential
	Update(ctx context.Context, credential *domain.VerifiableCredential) error

	// Delete deletes a credential
	Delete(ctx context.Context, holderDID, credentialIdentifier string) error
}

// PresentationStore defines the interface for presentation storage operations
type PresentationStore interface {
	// Create creates a new presentation
	Create(ctx context.Context, presentation *domain.VerifiablePresentation) error

	// GetByID retrieves a presentation by ID
	GetByID(ctx context.Context, id int64) (*domain.VerifiablePresentation, error)

	// GetByIdentifier retrieves a presentation by presentation identifier
	GetByIdentifier(ctx context.Context, holderDID, presentationIdentifier string) (*domain.VerifiablePresentation, error)

	// GetAllByHolder retrieves all presentations for a holder
	GetAllByHolder(ctx context.Context, holderDID string) ([]*domain.VerifiablePresentation, error)

	// DeleteByCredentialID deletes all presentations containing a specific credential
	DeleteByCredentialID(ctx context.Context, holderDID, credentialID string) error

	// Delete deletes a presentation
	Delete(ctx context.Context, holderDID, presentationIdentifier string) error
}

// ChallengeStore defines the interface for WebAuthn challenge storage
type ChallengeStore interface {
	// Create creates a new challenge
	Create(ctx context.Context, challenge *domain.WebauthnChallenge) error

	// GetByID retrieves a challenge by ID
	GetByID(ctx context.Context, id string) (*domain.WebauthnChallenge, error)

	// Delete deletes a challenge
	Delete(ctx context.Context, id string) error

	// DeleteExpired deletes all expired challenges
	DeleteExpired(ctx context.Context) error
}

// IssuerStore defines the interface for credential issuer storage
type IssuerStore interface {
	// Create creates a new issuer
	Create(ctx context.Context, issuer *domain.CredentialIssuer) error

	// GetByID retrieves an issuer by ID
	GetByID(ctx context.Context, id int64) (*domain.CredentialIssuer, error)

	// GetByIdentifier retrieves an issuer by identifier
	GetByIdentifier(ctx context.Context, identifier string) (*domain.CredentialIssuer, error)

	// GetAll retrieves all issuers
	GetAll(ctx context.Context) ([]*domain.CredentialIssuer, error)

	// Update updates an issuer
	Update(ctx context.Context, issuer *domain.CredentialIssuer) error

	// Delete deletes an issuer
	Delete(ctx context.Context, id int64) error
}

// VerifierStore defines the interface for verifier storage
type VerifierStore interface {
	// Create creates a new verifier
	Create(ctx context.Context, verifier *domain.Verifier) error

	// GetByID retrieves a verifier by ID
	GetByID(ctx context.Context, id int64) (*domain.Verifier, error)

	// GetAll retrieves all verifiers
	GetAll(ctx context.Context) ([]*domain.Verifier, error)

	// Update updates a verifier
	Update(ctx context.Context, verifier *domain.Verifier) error

	// Delete deletes a verifier
	Delete(ctx context.Context, id int64) error
}

// Store aggregates all storage interfaces
type Store interface {
	Users() UserStore
	Credentials() CredentialStore
	Presentations() PresentationStore
	Challenges() ChallengeStore
	Issuers() IssuerStore
	Verifiers() VerifierStore

	// Close closes the storage connection
	Close() error

	// Ping checks if the storage is alive
	Ping(ctx context.Context) error
}
