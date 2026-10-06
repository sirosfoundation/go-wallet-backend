package storage

import (
	"context"
	"errors"
	"time"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
)

// Common errors
var (
	ErrNotFound      = errors.New("not found")
	ErrAlreadyExists = errors.New("already exists")
	ErrInvalidInput  = errors.New("invalid input")
	ErrDatabase      = errors.New("database error")
	// ErrBindingChanged is returned by the conditional wallet-instance writes
	// when a record with that id exists in the tenant but is no longer the one
	// the caller read: it was bound to another owner, or deleted and created
	// again (a different generation). Nothing was written. A record that does
	// not exist, or belongs to another tenant, still answers ErrNotFound.
	ErrBindingChanged = errors.New("wallet instance binding changed")
	// ErrStaleWrite is returned by UserStore.Update (and by
	// UserStore.InvalidateAuthBeforeForToken) when the stored record's
	// lifecycle cut-off (User.AuthInvalidBefore) advanced after the caller
	// loaded the record: writing the stale copy back would undo a wallet
	// suspension/revocation. Callers reload and re-check the lifecycle state.
	ErrStaleWrite = errors.New("stale write: the user's authorization changed since the record was loaded")
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

// DeletionTombstoneStore keeps the record DeleteUser leaves behind so that a
// deleted user's tokens stay refused (see domain.DeletionTombstone). It is part
// of UserStore, so anything that can look up a user's token cut-off can also
// tell that the user was deleted.
type DeletionTombstoneStore interface {
	// PutDeletionTombstone records a deletion. It is idempotent, so a retried
	// deletion can repeat it: an existing tombstone keeps its earliest
	// DeletedAt, its expiry only moves later, and tenant ids are merged.
	PutDeletionTombstone(ctx context.Context, t *domain.DeletionTombstone) error

	// GetDeletionTombstone returns the tombstone for the user id, or
	// ErrNotFound. A tombstone past its ExpiresAt that has not been swept yet
	// is still returned: it can only outlive the tokens it covers, and
	// refusing too long is the safe direction.
	GetDeletionTombstone(ctx context.Context, userID string) (*domain.DeletionTombstone, error)

	// DeleteExpiredDeletionTombstones removes tombstones whose ExpiresAt is
	// at or before now and returns how many it removed. MongoDB also expires
	// them with a TTL index; this is what expires them on backends without
	// one, and the backstop where the TTL monitor lags.
	DeleteExpiredDeletionTombstones(ctx context.Context, now time.Time) (int, error)
}

// UserStore defines the interface for user storage operations
type UserStore interface {
	DeletionTombstoneStore

	// Create creates a new user
	Create(ctx context.Context, user *domain.User) error

	// GetByID retrieves a user by ID
	GetByID(ctx context.Context, id domain.UserID) (*domain.User, error)

	// GetByUsername retrieves a user by username
	GetByUsername(ctx context.Context, username string) (*domain.User, error)

	// GetByDID retrieves a user by DID
	GetByDID(ctx context.Context, did string) (*domain.User, error)

	// Update updates a user. It refuses (ErrStaleWrite) a record whose
	// AuthFence is behind the stored one, so a copy loaded before a
	// suspension, revocation or erasure cannot roll back the cut-off or
	// restore erased wallet data.
	Update(ctx context.Context, user *domain.User) error

	// Delete deletes a user
	Delete(ctx context.Context, id domain.UserID) error

	// UpdatePrivateData updates user's private data with optimistic locking
	UpdatePrivateData(ctx context.Context, id domain.UserID, data []byte, ifMatch string) error

	// InvalidateAuthBefore records that bearer tokens issued before t are no
	// longer accepted for the user (see internal/tokengate). The cut-off only
	// moves forward, so a delayed older event cannot roll it back. Touches no
	// other field.
	InvalidateAuthBefore(ctx context.Context, id domain.UserID, t time.Time) error

	// InvalidateAuthBeforeForToken is InvalidateAuthBefore made conditional on
	// the token it acts for: a compare-and-set, atomic in the store. It
	// advances the cut-off to t only while the stored cut-off does not already
	// refuse a token issued at tokenIssuedAt (stored cut-off, in whole seconds,
	// earlier than tokenIssuedAt's second - the comparison tokengate
	// .IssuedBeforeCutoff makes). Otherwise an independent revocation has
	// landed since the caller's token was admitted: nothing is written and
	// ErrStaleWrite is returned. A zero tokenIssuedAt means the caller has no
	// token to judge (an internal caller) and the call is unconditional. A
	// cut-off left by an earlier attempt of the same operation belongs to a
	// token the caller has since replaced, so a fresh token passes.
	InvalidateAuthBeforeForToken(ctx context.Context, id domain.UserID, t time.Time, tokenIssuedAt time.Time) error

	// EraseWalletData erases the user's wallet key material - PrivateData,
	// PrivateDataETag and Keys - and, in the same write, advances the auth
	// cut-off to fence (see Update). Field-scoped, so a concurrent change to
	// other fields (e.g. a passkey registration) is not overwritten, and
	// atomic, so no record loaded before the erasure can pass the fence
	// afterwards.
	EraseWalletData(ctx context.Context, id domain.UserID, fence time.Time) error

	// GetAuthCutoff returns only the user's token cut-off, for the
	// per-request gate check (a narrow read, not the whole record).
	GetAuthCutoff(ctx context.Context, id domain.UserID) (time.Time, error)

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

	// ConsumeByIDForTenant atomically retrieves and deletes a challenge by
	// ID, additionally constrained to expectedTenantID as part of the SAME
	// atomic find-and-delete — unless expectedTenantID is empty, in which
	// case this behaves exactly like plain ConsumeByID with no extra
	// constraint. This is what FinishRegistration must use when it has a
	// validated tenant context (e.g. from the X-Tenant-ID header) to check
	// against the challenge's own tenant: a caller who knows a challenge ID
	// but names the wrong tenant must not be able to burn that challenge
	// via a mismatch check performed only AFTER a separate, unconstrained
	// consume. Returns ErrNotFound if the challenge doesn't exist, was
	// already consumed, or (when expectedTenantID is non-empty) belongs to
	// a different tenant (deliberately indistinguishable from the other
	// cases, so a caller can't probe which).
	ConsumeByIDForTenant(ctx context.Context, id string, expectedTenantID string) (*domain.WebauthnChallenge, error)

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
	// An existing instance keeps its Status (only UpdateStatus changes it) and its first
	// non-empty CredentialID (the passkey link is client-supplied and must not be moved).
	// On success instance.Generation is set to the generation of the record the
	// write applied to. The owner bind and credential link are conditional on that
	// generation, so a record deleted and re-created mid-call is never bound to
	// this caller: Upsert then returns ErrBindingChanged and the callers must
	// refuse the attestation.
	Upsert(ctx context.Context, instance *domain.WalletInstance) error

	// GetByID retrieves a wallet instance by its JWK Thumbprint ID.
	GetByID(ctx context.Context, id string) (*domain.WalletInstance, error)

	// GetAllByTenant retrieves all wallet instances for a tenant.
	GetAllByTenant(ctx context.Context, tenantID domain.TenantID) ([]*domain.WalletInstance, error)

	// GetByUser retrieves all wallet instances belonging to a specific user.
	GetByUser(ctx context.Context, tenantID domain.TenantID, userID domain.UserID) ([]*domain.WalletInstance, error)

	// GetAllByUser retrieves every wallet instance of a user, in every
	// tenant, without being told which tenants to look in.
	//
	// Account deletion needs this. Deriving the tenants from the user's
	// memberships misses any tenant whose membership was removed while an
	// instance of it was left behind - which the admin API does, since
	// DELETE /admin/tenants/{id}/users/{user_id} removes a membership and
	// nothing else. A missed instance is permanent: records are keyed by
	// instance-key thumbprint and the passkey link is write-once, so
	// re-enrolling that device would be refused for good.
	GetAllByUser(ctx context.Context, userID domain.UserID) ([]*domain.WalletInstance, error)

	// UpdateStatus revokes a wallet instance. Revocation is the only status
	// change there is, and it is terminal (domain.ValidateStatusTransition).
	//
	// The tenant is part of the write's filter, not only of the caller's
	// earlier read. The id is a global key (the instance-key thumbprint), so
	// a record that was deleted and attested again in another tenant between
	// the caller's check and this write would otherwise be revoked under the
	// first tenant's request. A record that is not in tenantID answers
	// storage.ErrNotFound, the same as one that does not exist.
	UpdateStatus(ctx context.Context, id string, tenantID domain.TenantID, status domain.InstanceStatus, reason string) error

	// UpdateStatusForUser is UpdateStatus with the owner in the write's
	// filter as well: the record is revoked only while it is still in
	// tenantID AND bound to userID. A sweep that works from a per-user
	// listing (revoke-all) must use this rather than UpdateStatus, because
	// the id is a global key and a record that was deleted and attested
	// again for another user of the same tenant between the listing and the
	// write would otherwise be revoked under the first user's request. A
	// record that is not that user's answers storage.ErrNotFound.
	UpdateStatusForUser(ctx context.Context, id string, tenantID domain.TenantID, userID domain.UserID, status domain.InstanceStatus, reason string) error

	// UpdateStatusIfUnchanged is UpdateStatus with the expected binding in
	// the write's filter: the record is revoked only while it is still in
	// tenantID, owned by expected.Owner (nil meaning unowned) AND of
	// generation expected.Generation, all in one atomic predicate. A read
	// followed by a write keyed only by id and tenant can land on a
	// replacement record - the id is a global key, so the same thumbprint can
	// be deleted and attested again by another user of the same tenant in
	// between. Returns storage.ErrBindingChanged when the record exists in the
	// tenant but is not the one described, storage.ErrNotFound when it is gone
	// or another tenant's, and domain.ErrInvalidStatusTransition when it is
	// the right record but already revoked.
	UpdateStatusIfUnchanged(ctx context.Context, id string, tenantID domain.TenantID, expected domain.InstanceBinding, status domain.InstanceStatus, reason string) error

	// DeleteIfUnchanged hard-deletes a wallet instance only while it is still
	// in tenantID and matches expected (owner and generation), atomically.
	// Same errors as UpdateStatusIfUnchanged, minus the transition one.
	DeleteIfUnchanged(ctx context.Context, id string, tenantID domain.TenantID, expected domain.InstanceBinding) error

	// IncrementAttestation atomically increments the attestation count and updates last_attested_at.
	IncrementAttestation(ctx context.Context, id string) error

	// Delete hard-deletes a wallet instance.
	Delete(ctx context.Context, id string) error

	// DeleteForUser hard-deletes a wallet instance only while it is still in
	// tenantID and bound to userID, in one atomic ID+tenant+owner predicate.
	// Account deletion works from a listing, and the id is a global key (the
	// instance-key thumbprint): if the listed record was removed and the same
	// thumbprint attested again under another tenant or user before the
	// delete, a delete by id alone would remove that replacement. A record
	// that does not match answers storage.ErrNotFound, the same as one that
	// does not exist; callers treat it as an incomplete cleanup.
	DeleteForUser(ctx context.Context, id string, tenantID domain.TenantID, userID domain.UserID) error

	// DeleteIfRemovable hard-deletes a wallet instance only while it is
	// still removable (status active; ownership is irrelevant, every
	// non-live record is a tombstone) AND still the record the
	// caller read (expected owner and generation). It returns
	// storage.ErrBindingChanged when the record was replaced, and
	// domain.ErrInvalidStatusTransition when the record exists but has
	// become a lifecycle tombstone, and storage.ErrNotFound when it is gone
	// or belongs to another tenant.
	//
	// The admin delete checks removability and then deletes, and a
	// revocation landing between the two would otherwise have its fresh
	// tombstone deleted - which is the record that keeps login and new
	// attestations refused, so that device would look never-enrolled on its
	// next attestation. The condition travels with the delete instead.
	DeleteIfRemovable(ctx context.Context, id string, tenantID domain.TenantID, expected domain.InstanceBinding) error
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
