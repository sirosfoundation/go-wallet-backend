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

// TenantStore defines the interface for tenant storage operations
type TenantStore interface {
	// Create creates a new tenant
	Create(ctx context.Context, tenant *domain.Tenant) error

	// GetByID retrieves a tenant by ID
	GetByID(ctx context.Context, id domain.TenantID) (*domain.Tenant, error)

	// GetAll retrieves all tenants
	GetAll(ctx context.Context) ([]*domain.Tenant, error)

	// GetAllEnabled retrieves all enabled tenants
	GetAllEnabled(ctx context.Context) ([]*domain.Tenant, error)

	// Update updates a tenant
	Update(ctx context.Context, tenant *domain.Tenant) error

	// Delete deletes a tenant
	Delete(ctx context.Context, id domain.TenantID) error
}

// UserTenantStore defines the interface for user-tenant membership storage
type UserTenantStore interface {
	// AddMembership adds a user to a tenant
	AddMembership(ctx context.Context, membership *domain.UserTenantMembership) error

	// RemoveMembership removes a user from a tenant
	RemoveMembership(ctx context.Context, userID domain.UserID, tenantID domain.TenantID) error

	// GetUserTenants returns all tenants a user belongs to
	GetUserTenants(ctx context.Context, userID domain.UserID) ([]domain.TenantID, error)

	// GetTenantUsers returns all users in a tenant
	GetTenantUsers(ctx context.Context, tenantID domain.TenantID) ([]domain.UserID, error)

	// IsMember checks if a user is a member of a tenant
	IsMember(ctx context.Context, userID domain.UserID, tenantID domain.TenantID) (bool, error)

	// GetMembership gets the membership details
	GetMembership(ctx context.Context, userID domain.UserID, tenantID domain.TenantID) (*domain.UserTenantMembership, error)
}

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

	// UpdateCredentialAuthenticator atomically persists a single WebAuthn
	// credential's SignCount and CloneWarning, identified by the
	// credential's ID (the base64url string, domain.WebauthnCredential.ID),
	// without a whole-document read-modify-write. This exists because
	// Update above replaces the entire document (Mongo: ReplaceOne): two
	// concurrent logins that each read the user before either persisted
	// would otherwise race on a last-writer-wins basis, and a "clean" login
	// racing after a "clone detected" login could silently clobber the
	// latter's CloneWarning=true back to false. CloneWarning is OR-only
	// here — the underlying implementations must never let this method
	// write false over an existing true — so it can only ever gain the
	// signal, never lose it to a race, however the two calls interleave.
	// SignCount is monotonic non-decreasing (Mongo: $max; memory: only
	// assigned when greater), not a plain overwrite: concurrent logins can
	// persist out of order, and letting a later write lower the stored
	// counter would both falsely flag a subsequent legitimate assertion as
	// a clone regression and let an actually-regressing counter slip
	// through as non-regressing against an artificially-lowered baseline.
	// Returns storage.ErrNotFound if the user doesn't exist. If the user exists but
	// has no credential with that ID, this is a silent no-op success in
	// both backends (MongoDB's arrayFilter update can't distinguish
	// "matched the document but zero array elements" from "document not
	// found", so this is a deliberate, matching behavior rather than an
	// accidental divergence) — callers must only call this with a
	// credentialID they've just matched on that same user.
	//
	// transitioned reports whether THIS call is the one that actually
	// flipped CloneWarning from false to true in storage — a genuine
	// compare-and-set outcome from the atomic write itself (MongoDB:
	// FindOneAndUpdate returning the pre-image so the prior stored value
	// can be inspected; memory: checked under the same mutex acquisition as
	// the write), not something callers should try to infer from a
	// separately-read snapshot. Two concurrent callers that both pass
	// cloneWarning=true can both observe a stale "not yet latched" view
	// before either persists; only relying on this return value (rather
	// than a local pre-check) ensures exactly one of them sees
	// transitioned=true, so a caller gating a one-time side effect (e.g. a
	// security-event log line) on this value can't duplicate it under a
	// race. Always false when cloneWarning is false.
	UpdateCredentialAuthenticator(ctx context.Context, id domain.UserID, credentialID string, signCount uint32, cloneWarning bool) (transitioned bool, err error)
}

// CredentialStore defines the interface for credential storage operations
type CredentialStore interface {
	// Create creates a new credential
	Create(ctx context.Context, credential *domain.VerifiableCredential) error

	// GetByID retrieves a credential by ID (tenant scoped via credential's TenantID)
	GetByID(ctx context.Context, tenantID domain.TenantID, id int64) (*domain.VerifiableCredential, error)

	// GetByIdentifier retrieves a credential by credential identifier
	GetByIdentifier(ctx context.Context, tenantID domain.TenantID, holderDID, credentialIdentifier string) (*domain.VerifiableCredential, error)

	// GetAllByHolder retrieves all credentials for a holder within a tenant
	GetAllByHolder(ctx context.Context, tenantID domain.TenantID, holderDID string) ([]*domain.VerifiableCredential, error)

	// Update updates a credential
	Update(ctx context.Context, credential *domain.VerifiableCredential) error

	// Delete deletes a credential
	Delete(ctx context.Context, tenantID domain.TenantID, holderDID, credentialIdentifier string) error
}

// PresentationStore defines the interface for presentation storage operations
type PresentationStore interface {
	// Create creates a new presentation
	Create(ctx context.Context, presentation *domain.VerifiablePresentation) error

	// GetByID retrieves a presentation by ID (tenant scoped via presentation's TenantID)
	GetByID(ctx context.Context, tenantID domain.TenantID, id int64) (*domain.VerifiablePresentation, error)

	// GetByIdentifier retrieves a presentation by presentation identifier
	GetByIdentifier(ctx context.Context, tenantID domain.TenantID, holderDID, presentationIdentifier string) (*domain.VerifiablePresentation, error)

	// GetAllByHolder retrieves all presentations for a holder within a tenant
	GetAllByHolder(ctx context.Context, tenantID domain.TenantID, holderDID string) ([]*domain.VerifiablePresentation, error)

	// DeleteByCredentialID deletes all presentations containing a specific credential
	DeleteByCredentialID(ctx context.Context, tenantID domain.TenantID, holderDID, credentialID string) error

	// Delete deletes a presentation
	Delete(ctx context.Context, tenantID domain.TenantID, holderDID, presentationIdentifier string) error
}

// ChallengeStore defines the interface for WebAuthn challenge storage
type ChallengeStore interface {
	// Create creates a new challenge
	Create(ctx context.Context, challenge *domain.WebauthnChallenge) error

	// GetByID retrieves a challenge by ID
	GetByID(ctx context.Context, id string) (*domain.WebauthnChallenge, error)

	// ConsumeByID atomically retrieves and deletes a challenge by ID in a
	// single operation (Mongo: FindOneAndDelete; memory: mutex-protected
	// delete-and-return). Callers MUST use this instead of GetByID+Delete to
	// consume a one-time challenge: two concurrent calls racing on the same
	// ID can never both receive a non-nil challenge back. Returns
	// ErrNotFound if the challenge doesn't exist or was already consumed by
	// another caller.
	ConsumeByID(ctx context.Context, id string) (*domain.WebauthnChallenge, error)

	// ConsumeByIDForUser atomically retrieves and deletes a challenge by ID,
	// but ONLY if it also belongs to the given userID — the ownership check
	// is part of the same atomic find-and-delete, not a separate check
	// performed after consuming. This is what an authenticated, per-user
	// operation (e.g. FinishAddCredential) must use instead of plain
	// ConsumeByID: a caller presenting a DIFFERENT user's challenge ID gets
	// an atomic ErrNotFound without ever touching that other user's real,
	// still-pending challenge — a mismatched-owner call must never be able
	// to burn someone else's ceremony. Returns ErrNotFound if the challenge
	// doesn't exist, was already consumed, or belongs to a different user
	// (deliberately indistinguishable, so a caller can't probe which).
	ConsumeByIDForUser(ctx context.Context, id string, userID string) (*domain.WebauthnChallenge, error)

	// Delete deletes a challenge
	Delete(ctx context.Context, id string) error

	// DeleteExpired deletes all expired challenges
	DeleteExpired(ctx context.Context) error

	// DeleteByUserID deletes all challenges for a given user
	DeleteByUserID(ctx context.Context, userID string) error
}

// IssuerStore defines the interface for credential issuer storage
type IssuerStore interface {
	// Create creates a new issuer
	Create(ctx context.Context, issuer *domain.CredentialIssuer) error

	// GetByID retrieves an issuer by ID
	GetByID(ctx context.Context, tenantID domain.TenantID, id int64) (*domain.CredentialIssuer, error)

	// GetByIdentifier retrieves an issuer by identifier within a tenant
	GetByIdentifier(ctx context.Context, tenantID domain.TenantID, identifier string) (*domain.CredentialIssuer, error)

	// GetAll retrieves all issuers for a tenant
	GetAll(ctx context.Context, tenantID domain.TenantID) ([]*domain.CredentialIssuer, error)

	// Update updates an issuer
	Update(ctx context.Context, issuer *domain.CredentialIssuer) error

	// Delete deletes an issuer
	Delete(ctx context.Context, tenantID domain.TenantID, id int64) error
}

// VerifierStore defines the interface for verifier storage
type VerifierStore interface {
	// Create creates a new verifier
	Create(ctx context.Context, verifier *domain.Verifier) error

	// GetByID retrieves a verifier by ID
	GetByID(ctx context.Context, tenantID domain.TenantID, id int64) (*domain.Verifier, error)

	// GetByClientID retrieves a verifier by client_id within a tenant
	GetByClientID(ctx context.Context, tenantID domain.TenantID, clientID string) (*domain.Verifier, error)

	// GetByURL retrieves a verifier by its URL within a tenant
	GetByURL(ctx context.Context, tenantID domain.TenantID, url string) (*domain.Verifier, error)

	// GetAll retrieves all verifiers for a tenant
	GetAll(ctx context.Context, tenantID domain.TenantID) ([]*domain.Verifier, error)

	// Update updates a verifier
	Update(ctx context.Context, verifier *domain.Verifier) error

	// Delete deletes a verifier
	Delete(ctx context.Context, tenantID domain.TenantID, id int64) error

	// Upsert creates or updates a verifier by (tenantID, clientID)
	Upsert(ctx context.Context, verifier *domain.Verifier) error
}

// Store aggregates all storage interfaces
type Store interface {
	Users() UserStore
	Tenants() TenantStore
	UserTenants() UserTenantStore
	Credentials() CredentialStore
	Presentations() PresentationStore
	Challenges() ChallengeStore
	Issuers() IssuerStore
	Verifiers() VerifierStore
	Invites() InviteStore
	WalletInstances() WalletInstanceStore
	KeyAttestations() KeyAttestationStore

	// Close closes the storage connection
	Close() error

	// Ping checks if the storage is alive
	Ping(ctx context.Context) error
}

// InviteStore defines the interface for invite code storage
type InviteStore interface {
	// Create creates a new invite
	Create(ctx context.Context, invite *domain.Invite) error

	// GetByCode retrieves an invite by its code within a tenant
	GetByCode(ctx context.Context, tenantID domain.TenantID, code string) (*domain.Invite, error)

	// GetByID retrieves an invite by its ID
	GetByID(ctx context.Context, id string) (*domain.Invite, error)

	// GetAllByTenant retrieves all invites for a tenant
	GetAllByTenant(ctx context.Context, tenantID domain.TenantID) ([]*domain.Invite, error)

	// MarkCompleted atomically marks an invite as completed, but only if it
	// is currently active AND not expired — both conditions are checked as
	// part of the same atomic operation (Mongo: a single filtered UpdateOne;
	// memory: under one mutex acquisition). This closes a narrower TOCTOU
	// than the active/completed race MarkCompleted itself already prevents:
	// without the expiry check being atomic too, an invite that passed an
	// earlier IsUsable() check could tick over its expiry while a slow
	// caller (e.g. WebAuthn verification) is still in flight, and this call
	// would otherwise still succeed. Returns storage.ErrNotFound if the
	// invite isn't active, is expired, or doesn't exist.
	MarkCompleted(ctx context.Context, tenantID domain.TenantID, code string, usedBy domain.UserID) error

	// Update updates an invite (for renew/revoke)
	Update(ctx context.Context, invite *domain.Invite) error

	// Delete hard-deletes an invite within a tenant
	Delete(ctx context.Context, tenantID domain.TenantID, id string) error

	// ClearUsedBy removes the user reference from any invites consumed by the given user
	ClearUsedBy(ctx context.Context, userID domain.UserID) error
}

// WalletInstanceStore defines the interface for wallet instance storage
type WalletInstanceStore interface {
	// Upsert creates a new instance or updates an existing one (idempotent on first attestation).
	Upsert(ctx context.Context, instance *domain.WalletInstance) error

	// GetByID retrieves a wallet instance by its JWK Thumbprint ID.
	GetByID(ctx context.Context, id string) (*domain.WalletInstance, error)

	// GetAllByTenant retrieves all wallet instances for a tenant.
	GetAllByTenant(ctx context.Context, tenantID domain.TenantID) ([]*domain.WalletInstance, error)

	// GetByUser retrieves all wallet instances belonging to a specific user.
	GetByUser(ctx context.Context, tenantID domain.TenantID, userID domain.UserID) ([]*domain.WalletInstance, error)

	// UpdateStatus updates the status of a wallet instance (activate, suspend, revoke).
	UpdateStatus(ctx context.Context, id string, status domain.InstanceStatus, reason string) error

	// IncrementAttestation atomically increments the attestation count and updates last_attested_at.
	IncrementAttestation(ctx context.Context, id string) error

	// Delete hard-deletes a wallet instance.
	Delete(ctx context.Context, id string) error
}

// KeyAttestationStore defines the interface for per-credential-key FIDO2
// attestation evidence storage (see domain.KeyAttestationRecord's doc for
// why this is keyed by key thumbprint, not wallet instance).
type KeyAttestationStore interface {
	// MarkKeyAttested durably records that a real FIDO2/CTAP2 attestation
	// object was verified for the credential key identified by
	// rec.KeyThumbprint.
	MarkKeyAttested(ctx context.Context, rec *domain.KeyAttestationRecord) error

	// GetByKeyThumbprint retrieves a key attestation record by its JWK
	// Thumbprint. Returns ErrNotFound if no evidence is on file for that key.
	GetByKeyThumbprint(ctx context.Context, thumbprint string) (*domain.KeyAttestationRecord, error)
}
