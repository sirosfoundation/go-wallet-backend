package backend

import (
	"context"
	"fmt"

	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage/memory"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage/mongodb"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

// Type defines the type of storage backend
type Type string

const (
	// TypeMemory uses in-memory storage (for testing/development)
	TypeMemory Type = "memory"
	// TypeMongoDB uses MongoDB storage (for production)
	TypeMongoDB Type = "mongodb"
)

// Backend wraps storage stores with a common interface for lifecycle management
type Backend interface {
	// Users returns the user store
	Users() storage.UserStore
	// Tenants returns the tenant store
	Tenants() storage.TenantStore
	// UserTenants returns the user-tenant membership store
	UserTenants() storage.UserTenantStore
	// Credentials returns the credential store
	Credentials() storage.CredentialStore
	// Presentations returns the presentation store
	Presentations() storage.PresentationStore
	// Challenges returns the challenge store
	Challenges() storage.ChallengeStore
	// Issuers returns the issuer store
	Issuers() storage.IssuerStore
	// Verifiers returns the verifier store
	Verifiers() storage.VerifierStore
	// Ping checks if the storage is alive
	Ping(ctx context.Context) error
	// Close closes the storage connection
	Close() error
}

// memoryBackend wraps the memory store to implement Backend
type memoryBackend struct {
	store *memory.Store
}

func (b *memoryBackend) Users() storage.UserStore                 { return b.store.Users() }
func (b *memoryBackend) Tenants() storage.TenantStore             { return b.store.Tenants() }
func (b *memoryBackend) UserTenants() storage.UserTenantStore     { return b.store.UserTenants() }
func (b *memoryBackend) Credentials() storage.CredentialStore     { return b.store.Credentials() }
func (b *memoryBackend) Presentations() storage.PresentationStore { return b.store.Presentations() }
func (b *memoryBackend) Challenges() storage.ChallengeStore       { return b.store.Challenges() }
func (b *memoryBackend) Issuers() storage.IssuerStore             { return b.store.Issuers() }
func (b *memoryBackend) Verifiers() storage.VerifierStore         { return b.store.Verifiers() }
func (b *memoryBackend) Ping(ctx context.Context) error           { return b.store.Ping(ctx) }
func (b *memoryBackend) Close() error                             { return nil }

// mongoBackend wraps the MongoDB store to implement Backend
type mongoBackend struct {
	store *mongodb.Store
}

func (b *mongoBackend) Users() storage.UserStore                 { return b.store.Users() }
func (b *mongoBackend) Tenants() storage.TenantStore             { return b.store.Tenants() }
func (b *mongoBackend) UserTenants() storage.UserTenantStore     { return b.store.UserTenants() }
func (b *mongoBackend) Credentials() storage.CredentialStore     { return b.store.Credentials() }
func (b *mongoBackend) Presentations() storage.PresentationStore { return b.store.Presentations() }
func (b *mongoBackend) Challenges() storage.ChallengeStore       { return b.store.Challenges() }
func (b *mongoBackend) Issuers() storage.IssuerStore             { return b.store.Issuers() }
func (b *mongoBackend) Verifiers() storage.VerifierStore         { return b.store.Verifiers() }
func (b *mongoBackend) Ping(ctx context.Context) error           { return b.store.Ping(ctx) }
func (b *mongoBackend) Close() error                             { return b.store.Close() }

// New creates a storage backend based on the configuration
func New(ctx context.Context, cfg *config.Config) (Backend, error) {
	storageType := Type(cfg.Storage.Type)

	switch storageType {
	case TypeMemory, "":
		// Default to memory if not specified
		store := memory.NewStore()
		return &memoryBackend{store: store}, nil

	case TypeMongoDB:
		store, err := mongodb.NewStore(ctx, &cfg.Storage.MongoDB)
		if err != nil {
			return nil, fmt.Errorf("failed to create MongoDB backend: %w", err)
		}
		return &mongoBackend{store: store}, nil

	default:
		return nil, fmt.Errorf("unsupported storage type: %s", storageType)
	}
}
