package service

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
	"github.com/sirosfoundation/go-wallet-backend/internal/tokengate"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

var (
	ErrUserExists             = errors.New("user already exists")
	ErrPrivateDataConflict    = errors.New("private data conflict")
	ErrLastWebAuthnCredential = errors.New("cannot delete last webauthn credential")
)

// SessionCleaner can remove sessions for a user.
// Implemented by engine.Manager (which also closes the live WebSocket),
// engine.SessionStore, and as.SessionStore.
type SessionCleaner interface {
	DeleteByUser(ctx context.Context, userID string) error
}

// MultiSessionCleaner fans DeleteByUser out to several cleaners (engine
// WebSocket sessions and AS cookie sessions), so one wiring point drops
// every kind of session a user holds. Every cleaner is called even if an
// earlier one fails; the first error is returned.
type MultiSessionCleaner []SessionCleaner

// DeleteByUser implements SessionCleaner.
func (m MultiSessionCleaner) DeleteByUser(ctx context.Context, userID string) error {
	var first error
	for _, c := range m {
		if c == nil {
			continue
		}
		if err := c.DeleteByUser(ctx, userID); err != nil && first == nil {
			first = err
		}
	}
	return first
}

// TokenRevoker is the subset of *TokenBlacklist that DeleteUser needs to
// revoke every previously-issued token for a deleted user. Narrowing the
// field to this interface (rather than the concrete *TokenBlacklist type)
// lets tests exercise DeleteUser's error-handling around RevokeUser
// failing - something the production TokenBlacklist implementation itself
// never actually does today (RevokeUser only ever returns nil, defensively
// coded for a future implementation - e.g. a persistent store - that
// might not), so that path would otherwise be untestable dead code.
type TokenRevoker interface {
	RevokeUser(ctx context.Context, userID string) error
}

// UserRevoker permanently bars a deleted user from token-independent session
// holders (engine Manager.RevokeUser); unlike SessionCleaner, which leaves the
// user free to log in again.
type UserRevoker interface {
	RevokeUser(userID string)
}

// UserLocker is the per-user lock WIAService holds from its instance write to
// its post-write checks; deletion takes it so an attestation finishes before the
// final sweep or finds the user gone.
type UserLocker interface {
	LockUser(userID domain.UserID) func()
}

// UserService handles user-related operations
type UserService struct {
	store          storage.Store
	cfg            *config.Config
	logger         *zap.Logger
	sessionCleaner SessionCleaner
	tokenBlacklist TokenRevoker
	userRevokers   []UserRevoker
	// locker serializes the final sweep and user removal with WIA instance
	// writes. Nil without a lifecycle service.
	locker UserLocker
	// now is the clock for tombstone timestamps (replaced in tests).
	now func() time.Time
}

// NewUserService creates a new UserService
func NewUserService(store storage.Store, cfg *config.Config, logger *zap.Logger) *UserService {
	return &UserService{
		store:  store,
		cfg:    cfg,
		logger: logger.Named("user-service"),
		now:    time.Now,
	}
}

// SetClock replaces the clock used to stamp deletion tombstones (tests).
func (s *UserService) SetClock(now func() time.Time) { s.now = now }

// SetUserLocker wires the per-user lock shared with WIA generation. Taken last;
// DeleteUser never calls the lifecycle service while holding it.
func (s *UserService) SetUserLocker(l UserLocker) { s.locker = l }

// SetSessionCleaner sets the session cleanup implementation.
// When set, DeleteUser will purge active sessions for the deleted user.
func (s *UserService) SetSessionCleaner(sc SessionCleaner) {
	s.sessionCleaner = sc
}

// AddUserRevoker registers a component that permanently rejects the deleted
// user; called before sessions are purged.
func (s *UserService) AddUserRevoker(r UserRevoker) {
	s.userRevokers = append(s.userRevokers, r)
}

// SetTokenBlacklist sets the token revoker (in production, always the
// shared *TokenBlacklist - see TokenRevoker's doc comment for why the
// parameter is the narrower interface). When set, DeleteUser revokes
// every previously-issued token for the deleted user (not just the single
// token used to authenticate the deletion request), so they stop working
// immediately instead of remaining valid until they naturally expire (#383).
func (s *UserService) SetTokenBlacklist(b TokenRevoker) {
	s.tokenBlacklist = b
}

// Register registers a new user
func (s *UserService) Register(ctx context.Context, req *domain.RegisterRequest) (*domain.User, error) {
	// Check if username is already taken
	if req.Username != nil {
		existing, err := s.store.Users().GetByUsername(ctx, *req.Username)
		if err == nil && existing != nil {
			return nil, ErrUserExists
		}
	}

	user := &domain.User{
		UUID:        domain.NewUserID(),
		Username:    req.Username,
		DisplayName: &req.DisplayName,
		WalletType:  req.WalletType,
		Keys:        req.Keys,
		PrivateData: req.PrivateData,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	// Generate DID
	// TODO: Implement proper DID generation based on key material
	user.DID = domain.HolderDID(user.UUID.String())

	// Compute private data ETag
	if len(user.PrivateData) > 0 {
		user.PrivateDataETag = domain.ComputePrivateDataETag(user.PrivateData)
	}

	// Store user
	if err := s.store.Users().Create(ctx, user); err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	s.logger.Debug("User registered", zap.String("user_id", user.UUID.String()))
	return user, nil
}

// GetUserByID retrieves a user by ID
func (s *UserService) GetUserByID(ctx context.Context, id domain.UserID) (*domain.User, error) {
	return s.store.Users().GetByID(ctx, id)
}

// ValidateToken validates a JWT token and returns the user ID
func (s *UserService) ValidateToken(tokenString string) (domain.UserID, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(s.cfg.JWT.Secret), nil
	})

	if err != nil {
		return domain.UserID{}, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		userID, ok := claims["user_id"].(string)
		if !ok {
			return domain.UserID{}, errors.New("invalid token claims")
		}
		return domain.UserIDFromString(userID), nil
	}

	return domain.UserID{}, errors.New("invalid token")
}

func (s *UserService) generateToken(user *domain.User, tenantID domain.TenantID) (string, error) {
	// Default to "default" tenant for backward compatibility
	tid := string(tenantID)
	if tid == "" {
		tid = string(domain.DefaultTenantID)
	}

	now := time.Now()
	jti := generateJTI() // Generate unique token ID

	claims := jwt.MapClaims{
		"user_id":   user.UUID.String(),
		"did":       user.DID,
		"tenant_id": tid,
		"iss":       s.cfg.JWT.Issuer,
		"aud":       s.cfg.Server.RPID,                                                // Audience: the RP ID
		"exp":       now.Add(time.Duration(s.cfg.JWT.ExpiryHours) * time.Hour).Unix(), // Expiry
		"iat":       now.Unix(),
		"nbf":       now.Unix(), // Not Before: token valid from now
		"jti":       jti,        // JWT ID: unique identifier for revocation
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(s.cfg.JWT.Secret))
}

// generateJTI generates a unique JWT ID
func generateJTI() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// GenerateTokenForUser generates a JWT token for a user (used after WebAuthn auth)
// The tenantID is included in the JWT claims for tenant-scoped authorization
func (s *UserService) GenerateTokenForUser(user *domain.User, tenantID domain.TenantID) (string, error) {
	return s.generateToken(user, tenantID)
}

// GetPrivateData retrieves user's private data
func (s *UserService) GetPrivateData(ctx context.Context, userID domain.UserID) ([]byte, string, error) {
	user, err := s.store.Users().GetByID(ctx, userID)
	if err != nil {
		return nil, "", err
	}
	return user.PrivateData, user.PrivateDataETag, nil
}

// refuseIfCutOff judges the request token against the freshly loaded record
// (SID-AUTH-06), catching a revocation after the middleware check.
func refuseIfCutOff(ctx context.Context, user *domain.User) error {
	return tokengate.RefuseLoaded(ctx, user.AuthInvalidBefore)
}

// requestIssuedAt is the request token's iat, or zero for an internal caller.
func requestIssuedAt(ctx context.Context) time.Time {
	t, _ := tokengate.IssuedAtFrom(ctx)
	return t
}

// UpdatePrivateData updates user's private data with optimistic locking
func (s *UserService) UpdatePrivateData(ctx context.Context, userID domain.UserID, data []byte, ifMatch string) (string, error) {
	user, err := s.store.Users().GetByID(ctx, userID)
	if err != nil {
		return "", err
	}
	if err := refuseIfCutOff(ctx, user); err != nil {
		return "", err
	}

	// Check ETag for optimistic locking
	if ifMatch != "" && ifMatch != user.PrivateDataETag {
		return user.PrivateDataETag, ErrPrivateDataConflict
	}

	// Update private data
	user.UpdatePrivateData(data)

	if err := s.store.Users().Update(ctx, user); err != nil {
		return "", fmt.Errorf("failed to update user: %w", err)
	}

	s.logger.Debug("Private data updated", zap.String("user_id", userID.String()))
	return user.PrivateDataETag, nil
}

// LogoutEverywhere ends all sessions and refuses already-issued bearer tokens,
// the caller's included (SID-AUTH-06); logging in again undoes it.
func (s *UserService) LogoutEverywhere(ctx context.Context, userID domain.UserID) error {
	user, err := s.store.Users().GetByID(ctx, userID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return ErrUserNotFound
		}
		return fmt.Errorf("failed to load user: %w", err)
	}
	// A token already cut off must not advance the cut-off again.
	if err := refuseIfCutOff(ctx, user); err != nil {
		return err
	}
	// Cut-off first; compare-and-set against the request's token so a concurrent
	// lifecycle event is not overwritten.
	if err := s.store.Users().InvalidateAuthBeforeForToken(ctx, userID, time.Now(), requestIssuedAt(ctx)); err != nil {
		if errors.Is(err, storage.ErrStaleWrite) {
			return fmt.Errorf("%w: a lifecycle revocation landed during the logout", tokengate.ErrRevoked)
		}
		if errors.Is(err, storage.ErrNotFound) {
			return ErrUserNotFound
		}
		return fmt.Errorf("failed to cut off issued tokens: %w", err)
	}
	if s.sessionCleaner != nil {
		if err := s.sessionCleaner.DeleteByUser(ctx, userID.String()); err != nil {
			return fmt.Errorf("failed to drop sessions: %w", err)
		}
	}
	s.logger.Info("User logged out everywhere", zap.String("user_id", userID.String()))
	return nil
}

// ErrDeletionIncomplete is returned when an instance could not be removed; the
// record is kept so the request can be repeated (an orphan instance blocks re-
// enrolment).
var ErrDeletionIncomplete = errors.New("account deletion incomplete")

// ErrDeletionCleanupPending is returned when the account was deleted but the
// final sweep could not confirm no holder data remains; the caller must not
// retry, an operator clears the rest.
var ErrDeletionCleanupPending = errors.New("account deleted, cleanup of data written during the deletion incomplete")

// ErrDeletionOperatorRequired is returned when deletion stopped after the
// permanent token revocation, so even a fresh login is refused; only an operator
// or restart can finish it.
var ErrDeletionOperatorRequired = errors.New("account deletion stalled after the user's tokens were revoked, an operator must finish it")

// DeleteUser removes a user and all their data in every tenant, finally the
// record itself.
//
// Failure semantics:
//   - ErrDeletionIncomplete (record kept, safe to repeat): the tombstone write,
//     instance or holder-data removal, a lookup, or the first session-cleaner run
//     failed before any permanent revocation.
//   - ErrDeletionOperatorRequired: the second cleaner run or final holder sweep
//     failed after the blacklist revocation took effect; without it these stay
//     ErrDeletionIncomplete.
//   - The cut-off (User.AuthInvalidBefore) advances durably before the
//     revocations, by compare-and-set against the request's token
//     (UserStore.InvalidateAuthBeforeForToken); a concurrent revocation answers
//     tokengate.ErrRevoked with nothing irreversible done.
//   - The sweeps after the advance and after the record's removal pair with
//     tokengate.ConfirmWrite; failure of the latter is ErrDeletionCleanupPending.
//   - Best-effort, logged only: pending challenges, invite used_by, membership
//     removal, blacklist RevokeUser. A failing final Users().Delete answers a
//     plain error.
func (s *UserService) DeleteUser(ctx context.Context, userID domain.UserID, holderDID string) error {
	var instanceErrs []error
	// dataErrs collects failures that must not answer 200.
	var dataErrs []error

	// Credentials are stored under User.DID, not the bare uuid the handler
	// passes.
	if user, err := s.store.Users().GetByID(ctx, userID); err == nil {
		// Cut-off check (SID-AUTH-06): a request admitted before a logout must
		// not erase the account.
		if err := refuseIfCutOff(ctx, user); err != nil {
			return err
		}
		if user.DID != "" {
			holderDID = user.DID
		} else {
			holderDID = userID.String()
		}
	} else if !errors.Is(err, storage.ErrNotFound) {
		return fmt.Errorf("%w: load user: %w", ErrDeletionIncomplete, err)
	} else if _, terr := s.store.Users().GetDeletionTombstone(ctx, userID.String()); errors.Is(terr, storage.ErrNotFound) {
		// No record and no tombstone: nothing was deleted, and a tombstone for
		// an unknown identity would let any caller poison the table.
		return ErrUserNotFound
	} else if terr != nil {
		return fmt.Errorf("%w: look up deletion tombstone: %w", ErrDeletionIncomplete, terr)
	}
	// A failed membership lookup is fatal: an undiscovered tenant could hold
	// instances.
	memberships, err := s.store.UserTenants().GetUserTenants(ctx, userID)
	if err != nil {
		return fmt.Errorf("%w: list tenant memberships: %w", ErrDeletionIncomplete, err)
	}
	// Always sweep the default tenant, plus the instances' tenants (a membership
	// can be removed while an instance remains).
	instances, err := s.store.WalletInstances().GetAllByUser(ctx, userID)
	if err != nil && !errors.Is(err, storage.ErrNotFound) {
		return fmt.Errorf("%w: list wallet instances: %w", ErrDeletionIncomplete, err)
	}
	seen := map[domain.TenantID]bool{}
	tenantIDs := make([]domain.TenantID, 0, len(memberships)+len(instances)+1)
	for _, tid := range append([]domain.TenantID{domain.DefaultTenantID}, memberships...) {
		if !seen[tid] {
			seen[tid] = true
			tenantIDs = append(tenantIDs, tid)
		}
	}
	for _, inst := range instances {
		if !seen[inst.TenantID] {
			seen[inst.TenantID] = true
			tenantIDs = append(tenantIDs, inst.TenantID)
		}
	}

	// Write the deletion tombstone before the first irreversible step: the gate
	// refuses a deleted account's tokens only through it. Failure removes
	// nothing; retries rewrite it idempotently.
	deletedAt := s.now().UTC()
	putTombstone := func() error {
		if err := s.store.Users().PutDeletionTombstone(ctx, &domain.DeletionTombstone{
			UserID:    userID.String(),
			TenantIDs: tenantIDs,
			DeletedAt: deletedAt,
			ExpiresAt: deletedAt.Add(s.cfg.DeletionTombstoneRetention()),
		}); err != nil {
			s.logger.Error("Account deletion incomplete: deletion tombstone could not be written",
				zap.Error(err), zap.String("user_id", userID.String()))
			return fmt.Errorf("%w: write deletion tombstone: %w", ErrDeletionIncomplete, err)
		}
		return nil
	}
	if err := putTombstone(); err != nil {
		return err
	}

	// Delete legacy credentials and presentations per tenant; failures count.
	for _, tenantID := range tenantIDs {
		dataErrs = append(dataErrs, s.eraseHolderData(ctx, tenantID, holderDID)...)
	}

	// Remove the user's wallet instances; failures keep the record for a retry
	// (residue blocks re-enrolment).
	instanceErrs = s.deleteWalletInstances(ctx, userID)

	// Delete pending WebAuthn challenges (defense-in-depth; TTL handles expiry)
	if err := s.store.Challenges().DeleteByUserID(ctx, userID.String()); err != nil {
		s.logger.Warn("Failed to delete challenges for user", zap.Error(err))
	}

	// Clear user reference from consumed invites
	if err := s.store.Invites().ClearUsedBy(ctx, userID); err != nil {
		s.logger.Warn("Failed to clear invite used_by references", zap.Error(err))
	}

	// Re-list before deleting the record: an attestation may have bound an
	// instance since the first sweep. Not a lock (go-wallet-backend#330); this
	// pass decides on its own.
	if len(instanceErrs) > 0 {
		s.logger.Warn("wallet instance cleanup failed on the first pass, retrying before the user record is removed",
			zap.Error(errors.Join(instanceErrs...)), zap.String("user_id", userID.String()))
	}
	// Serialize with attestation until the record is removed, so a WIA write
	// cannot bind an orphan instance to a deleted user. WIAService takes the
	// same lock; it is per process, replicas rely on the WIA-side refusal after
	// the write.
	if s.locker != nil {
		defer s.locker.LockUser(userID)()
	}
	late, lateErrs := s.listWalletInstances(ctx, userID)
	instanceErrs = lateErrs
	var lateTenants []domain.TenantID
	for _, inst := range late {
		if seen[inst.TenantID] {
			continue
		}
		seen[inst.TenantID] = true
		tenantIDs = append(tenantIDs, inst.TenantID)
		lateTenants = append(lateTenants, inst.TenantID)
	}
	if len(lateTenants) > 0 {
		// Record the new tenants on the tombstone before erasing in them.
		if err := putTombstone(); err != nil {
			return err
		}
	}
	for _, tid := range lateTenants {
		dataErrs = append(dataErrs, s.eraseHolderData(ctx, tid, holderDID)...)
	}
	instanceErrs = append(instanceErrs, s.deleteWalletInstances(ctx, userID)...)

	outstanding := append(append([]error{}, instanceErrs...), dataErrs...)
	if len(outstanding) > 0 {
		s.logger.Error("Account deletion incomplete",
			zap.Error(errors.Join(outstanding...)), zap.String("user_id", userID.String()))
		return fmt.Errorf("%w: %w", ErrDeletionIncomplete, errors.Join(outstanding...))
	}

	// Everything below is irreversible; applying the permanent revocations
	// earlier would lock the caller out of an ErrDeletionIncomplete retry. The
	// session cleaner runs before them (retryable) and after.
	if s.sessionCleaner != nil {
		if err := s.sessionCleaner.DeleteByUser(ctx, userID.String()); err != nil {
			s.logger.Error("Account deletion incomplete: sessions could not be dropped",
				zap.Error(err), zap.String("user_id", userID.String()))
			return fmt.Errorf("%w: drop sessions: %w", ErrDeletionIncomplete, err)
		}
	}

	// Advance the token cut-off durably before the first irreversible step; the
	// tombstone cannot, since the gate reads only the record's cut-off while it
	// exists. Compare-and-set against the request's token, so a concurrent
	// revocation answers 401 with nothing irreversible done.
	if err := s.store.Users().InvalidateAuthBeforeForToken(ctx, userID, s.now().UTC(), requestIssuedAt(ctx)); err != nil && !errors.Is(err, storage.ErrNotFound) {
		if errors.Is(err, storage.ErrStaleWrite) {
			return fmt.Errorf("%w: a lifecycle revocation landed during the deletion", tokengate.ErrRevoked)
		}
		s.logger.Error("Account deletion incomplete: token cut-off could not be advanced",
			zap.Error(err), zap.String("user_id", userID.String()))
		return fmt.Errorf("%w: advance token cut-off: %w", ErrDeletionIncomplete, err)
	}

	// Revoke all previously-issued tokens for this user (#383) BEFORE
	// purging sessions below - not after. Logout only ever blacklists the
	// single token used for that request; without this, any of the deleted
	// user's other still-valid tokens (a different device, a token minted
	// before this request's) would keep working until they naturally
	// expire.
	//
	// The ordering matters for engine (WebSocket) sessions specifically
	// (#393 review): a handshake can pass the engine's own IsUserRevoked
	// check and then only finish registering itself in
	// engine.Manager.sessions *after* the cleaner below has already
	// scanned it. Revoking first means engine.Manager.registerSession's own
	// recheck (done under the same lock the scan uses) will already see
	// this user as revoked for any such late registration, and any
	// registration that instead completed *before* this revocation is
	// still guaranteed to be present in m.sessions by the time the scan
	// below runs. Reversing this order would reopen that gap.
	// lockedOut: only a successful blacklist revocation refuses a fresh login's
	// token.
	lockedOut := false
	if s.tokenBlacklist != nil {
		if err := s.tokenBlacklist.RevokeUser(ctx, userID.String()); err != nil {
			s.logger.Warn("Failed to revoke tokens for deleted user", zap.Error(err))
		} else {
			lockedOut = true
		}
	}

	for _, r := range s.userRevokers {
		r.RevokeUser(userID.String())
	}

	// Purge active WebSocket sessions (Redis or memory)
	if s.sessionCleaner != nil {
		if err := s.sessionCleaner.DeleteByUser(ctx, userID.String()); err != nil {
			// Blacklist in force: the user cannot retry; keep the record for an
			// operator.
			s.logger.Error("Account deletion incomplete: sessions could not be dropped after the user was revoked",
				zap.Error(err), zap.String("user_id", userID.String()))
			return fmt.Errorf("%w: drop sessions: %w", deletionStallErr(lockedOut), err)
		}
	}

	// Final holder sweep, after the cut-off advance: a write persisted earlier
	// is found here, a later one rolls itself back (tokengate.ConfirmWrite).
	// Fails closed.
	var finalErrs []error
	for _, tenantID := range tenantIDs {
		finalErrs = append(finalErrs, s.eraseHolderData(ctx, tenantID, holderDID)...)
	}
	if len(finalErrs) > 0 {
		s.logger.Error("Account deletion incomplete: holder data could not be removed after the token cut-off",
			zap.Error(errors.Join(finalErrs...)), zap.String("user_id", userID.String()))
		return fmt.Errorf("%w: final holder-data sweep: %w", deletionStallErr(lockedOut), errors.Join(finalErrs...))
	}

	// Memberships last: a retry rebuilds its tenant list from them.
	for _, tenantID := range tenantIDs {
		if err := s.store.UserTenants().RemoveMembership(ctx, userID, tenantID); err != nil {
			s.logger.Warn("Failed to remove tenant membership", zap.Error(err), zap.String("tenant_id", string(tenantID)))
		}
	}

	// Delete the user
	// An already-removed record is the wanted outcome.
	if err := s.store.Users().Delete(ctx, userID); err != nil && !errors.Is(err, storage.ErrNotFound) {
		return fmt.Errorf("failed to delete user: %w", err)
	}

	// Last sweep, after the record is gone: the tombstone now refuses writes, so
	// this removes anything a fresh login persisted since. Not retryable by the
	// user, hence ErrDeletionCleanupPending.
	var lastErrs []error
	for _, tenantID := range tenantIDs {
		lastErrs = append(lastErrs, s.eraseHolderData(ctx, tenantID, holderDID)...)
	}
	if len(lastErrs) > 0 {
		s.logger.Error("Account deleted but holder data written during the deletion could not be removed",
			zap.Error(errors.Join(lastErrs...)), zap.String("user_id", userID.String()))
		return fmt.Errorf("%w: sweep after user removal: %w", ErrDeletionCleanupPending, errors.Join(lastErrs...))
	}

	s.logger.Info("User deleted")
	return nil
}

// deletionStallErr picks ErrDeletionIncomplete while a fresh login still passes
// the token gate, else ErrDeletionOperatorRequired.
func deletionStallErr(lockedOut bool) error {
	if lockedOut {
		return ErrDeletionOperatorRequired
	}
	return ErrDeletionIncomplete
}

// listWalletInstances lists the user's wallet instances across all tenants.
func (s *UserService) listWalletInstances(ctx context.Context, userID domain.UserID) ([]*domain.WalletInstance, []error) {
	instances, err := s.store.WalletInstances().GetAllByUser(ctx, userID)
	if err != nil && !errors.Is(err, storage.ErrNotFound) {
		return nil, []error{fmt.Errorf("list wallet instances: %w", err)}
	}
	return instances, nil
}

// eraseHolderData removes the holder's credentials and presentations in one
// tenant, logging failures.
func (s *UserService) eraseHolderData(ctx context.Context, tenantID domain.TenantID, holderDID string) []error {
	var errs []error
	credentials, err := s.store.Credentials().GetAllByHolder(ctx, tenantID, holderDID)
	if err != nil && !errors.Is(err, storage.ErrNotFound) {
		errs = append(errs, fmt.Errorf("list credentials in tenant %s: %w", tenantID, err))
	}
	for _, cred := range credentials {
		if err := s.store.Credentials().Delete(ctx, tenantID, holderDID, cred.CredentialIdentifier); err != nil && !errors.Is(err, storage.ErrNotFound) {
			errs = append(errs, fmt.Errorf("delete credential %s: %w", cred.CredentialIdentifier, err))
		}
	}
	presentations, err := s.store.Presentations().GetAllByHolder(ctx, tenantID, holderDID)
	if err != nil && !errors.Is(err, storage.ErrNotFound) {
		errs = append(errs, fmt.Errorf("list presentations in tenant %s: %w", tenantID, err))
	}
	for _, pres := range presentations {
		if err := s.store.Presentations().Delete(ctx, tenantID, holderDID, pres.PresentationIdentifier); err != nil && !errors.Is(err, storage.ErrNotFound) {
			errs = append(errs, fmt.Errorf("delete presentation %s: %w", pres.PresentationIdentifier, err))
		}
	}
	return errs
}

// deleteWalletInstances removes the user's wallet instances in every tenant and
// returns what it could not do.
func (s *UserService) deleteWalletInstances(ctx context.Context, userID domain.UserID) []error {
	instances, errs := s.listWalletInstances(ctx, userID)
	if len(errs) > 0 {
		return errs
	}
	for _, inst := range instances {
		// Keyed by id, tenant and owner so a replacement bound after the listing
		// is not removed; a mismatch counts as incomplete.
		if err := s.store.WalletInstances().DeleteIfUnchanged(ctx, inst.ID, inst.TenantID, inst.Binding()); err != nil {
			if errors.Is(err, storage.ErrNotFound) || errors.Is(err, storage.ErrBindingChanged) {
				err = fmt.Errorf("record is gone or no longer this user's in tenant %s: %w", inst.TenantID, err)
			}
			errs = append(errs, fmt.Errorf("delete wallet instance %s: %w", inst.ID, err))
		}
	}
	return errs
}

// DeleteWebAuthnCredential deletes a WebAuthn credential
func (s *UserService) DeleteWebAuthnCredential(ctx context.Context, userID domain.UserID, credentialID string, privateData []byte, ifMatch string) (string, error) {
	user, err := s.store.Users().GetByID(ctx, userID)
	if err != nil {
		return "", err
	}
	if err := refuseIfCutOff(ctx, user); err != nil {
		return "", err
	}

	// Check that there's more than one credential
	if len(user.WebauthnCredentials) <= 1 {
		return "", ErrLastWebAuthnCredential
	}

	// Check ETag for optimistic locking
	if ifMatch != "" && ifMatch != user.PrivateDataETag {
		return user.PrivateDataETag, ErrPrivateDataConflict
	}

	// Find and remove the credential
	found := false
	newCredentials := make([]domain.WebauthnCredential, 0, len(user.WebauthnCredentials)-1)
	for _, cred := range user.WebauthnCredentials {
		if cred.ID == credentialID {
			found = true
			continue
		}
		newCredentials = append(newCredentials, cred)
	}

	if !found {
		return "", storage.ErrNotFound
	}

	user.WebauthnCredentials = newCredentials
	user.UpdatePrivateData(privateData)

	if err := s.store.Users().Update(ctx, user); err != nil {
		return "", fmt.Errorf("failed to update user: %w", err)
	}

	s.logger.Info("WebAuthn credential deleted",
		zap.String("user_id", userID.String()),
		zap.String("credential_id", credentialID))

	return user.PrivateDataETag, nil
}

// RenameWebAuthnCredential renames a WebAuthn credential
func (s *UserService) RenameWebAuthnCredential(ctx context.Context, userID domain.UserID, credentialID string, nickname string) error {
	user, err := s.store.Users().GetByID(ctx, userID)
	if err != nil {
		return err
	}
	if err := refuseIfCutOff(ctx, user); err != nil {
		return err
	}

	// Find and update the credential
	found := false
	for i := range user.WebauthnCredentials {
		if user.WebauthnCredentials[i].ID == credentialID {
			user.WebauthnCredentials[i].Nickname = &nickname
			found = true
			break
		}
	}

	if !found {
		return storage.ErrNotFound
	}

	if err := s.store.Users().Update(ctx, user); err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}

	s.logger.Debug("WebAuthn credential renamed",
		zap.String("user_id", userID.String()),
		zap.String("credential_id", credentialID))

	return nil
}

// UpdateUser updates a user
func (s *UserService) UpdateUser(ctx context.Context, user *domain.User) error {
	if err := refuseIfCutOff(ctx, user); err != nil {
		return err
	}
	user.UpdatedAt = time.Now()
	if err := s.store.Users().Update(ctx, user); err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}
	return nil
}
