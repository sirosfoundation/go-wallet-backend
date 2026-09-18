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
	"golang.org/x/crypto/bcrypt"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

var (
	ErrInvalidCredentials     = errors.New("invalid credentials")
	ErrUserExists             = errors.New("user already exists")
	ErrPrivateDataConflict    = errors.New("private data conflict")
	ErrLastWebAuthnCredential = errors.New("cannot delete last webauthn credential")
)

// SessionCleaner can remove sessions for a user.
// Implemented by engine.Manager (which also closes the live WebSocket),
// engine.SessionStore (memory or Redis) for the persisted record alone, and
// as.SessionStore for AS cookie sessions.
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

// UserService handles user-related operations
type UserService struct {
	store          storage.Store
	cfg            *config.Config
	logger         *zap.Logger
	sessionCleaner SessionCleaner
}

// NewUserService creates a new UserService
func NewUserService(store storage.Store, cfg *config.Config, logger *zap.Logger) *UserService {
	return &UserService{
		store:  store,
		cfg:    cfg,
		logger: logger.Named("user-service"),
	}
}

// SetSessionCleaner sets the session cleanup implementation.
// When set, DeleteUser will purge active sessions for the deleted user.
func (s *UserService) SetSessionCleaner(sc SessionCleaner) {
	s.sessionCleaner = sc
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

	// Hash password if provided
	if req.Password != nil {
		hash, err := bcrypt.GenerateFromPassword([]byte(*req.Password), bcrypt.DefaultCost)
		if err != nil {
			return nil, fmt.Errorf("failed to hash password: %w", err)
		}
		hashStr := string(hash)
		user.PasswordHash = &hashStr
	}

	// Generate DID
	// TODO: Implement proper DID generation based on key material
	user.DID = fmt.Sprintf("did:key:%s", user.UUID.String())

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

// Login authenticates a user with username/password
// Deprecated: Use WebAuthn authentication instead.
// Password-based authentication will be removed in a future version.
func (s *UserService) Login(ctx context.Context, username, password string) (*domain.User, string, error) {
	user, err := s.store.Users().GetByUsername(ctx, username)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, "", ErrInvalidCredentials
		}
		return nil, "", fmt.Errorf("failed to get user: %w", err)
	}

	// Verify password
	if user.PasswordHash == nil {
		return nil, "", ErrInvalidCredentials
	}

	if err := bcrypt.CompareHashAndPassword([]byte(*user.PasswordHash), []byte(password)); err != nil {
		return nil, "", ErrInvalidCredentials
	}

	// Generate JWT token (default tenant for deprecated password login)
	token, err := s.generateToken(user, domain.DefaultTenantID)
	if err != nil {
		return nil, "", fmt.Errorf("failed to generate token: %w", err)
	}

	s.logger.Info("User logged in")
	return user, token, nil
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

// UpdatePrivateData updates user's private data with optimistic locking
func (s *UserService) UpdatePrivateData(ctx context.Context, userID domain.UserID, data []byte, ifMatch string) (string, error) {
	user, err := s.store.Users().GetByID(ctx, userID)
	if err != nil {
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

// LogoutEverywhere ends every session the user has, on the device that asked
// and on any other, and refuses the bearer tokens already issued to them
// (SID-AUTH-06). The caller's own token is refused too, which is what "log
// out everywhere" means. Nothing is erased: this is the destructive-looking
// thing a user can safely do to themselves, because logging in again undoes
// all of it.
func (s *UserService) LogoutEverywhere(ctx context.Context, userID domain.UserID) error {
	if _, err := s.store.Users().GetByID(ctx, userID); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return ErrUserNotFound
		}
		return fmt.Errorf("failed to load user: %w", err)
	}
	// The cut-off first: if it fails nothing has changed, whereas dropping
	// the sessions first would leave the already-issued tokens working while
	// reporting an error.
	if err := s.store.Users().InvalidateAuthBefore(ctx, userID, time.Now()); err != nil {
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

// ErrDeletionIncomplete is returned when account deletion could not remove
// every wallet instance of the user. The user record is deliberately left in
// place: an instance that outlives its account is permanent damage - the
// records are keyed by instance-key thumbprint and the passkey link is
// write-once, so re-enrolling on that device would be refused for good - and
// keeping the account means the caller can still authenticate and repeat the
// request. Repeating it is the documented recovery, as for
// WalletLifecycleService's ErrErasureIncomplete.
var ErrDeletionIncomplete = errors.New("account deletion incomplete")

// DeleteUser removes a user and everything of theirs, in every tenant: stored
// credentials and presentations, wallet instances, pending challenges, live
// sessions, tenant memberships, and finally the user record with its
// passkeys.
//
// It is not best-effort about the wallet instances. An instance that outlives
// its account is permanent damage rather than residue, so a failure to remove
// one answers ErrDeletionIncomplete and leaves the account in place, which is
// what lets the caller authenticate and repeat the request. A failure to read
// the user's tenant memberships is fatal for the same reason: sweeping on a
// guess could leave an instance in a tenant this never looked at.
//
// The instances themselves say which tenants to sweep, rather than the
// memberships, because a membership can be gone while an instance of that
// tenant is not.
func (s *UserService) DeleteUser(ctx context.Context, userID domain.UserID, holderDID string) error {
	var instanceErrs []error
	// dataErrs collects failures that must not be papered over with a 200:
	// holder data left behind, and sessions that could not be dropped.
	var dataErrs []error

	// Resolve the holder key from the user record rather than trusting the
	// argument. Credentials and presentations are stored under User.DID,
	// which registration sets to "did:key:<uuid>", while the wallet API's
	// handler passes the bare uuid. Deleting under the uuid matches nothing,
	// so the account went and the user's credentials stayed - reported as a
	// success. WalletLifecycleService.eraseWalletData resolves it the same
	// way, including the fallback for users that have no DID.
	if user, err := s.store.Users().GetByID(ctx, userID); err == nil {
		if user.DID != "" {
			holderDID = user.DID
		} else {
			holderDID = userID.String()
		}
	} else if !errors.Is(err, storage.ErrNotFound) {
		return fmt.Errorf("%w: load user: %w", ErrDeletionIncomplete, err)
	}
	// Get all tenants the user belongs to
	// A failed membership lookup is fatal to the request rather than a
	// warning to sweep past. Deleting the user record while instances in an
	// undiscovered tenant keep pointing at them is not partial cleanup, it
	// is permanent damage: the record survives, the caller can no longer
	// authenticate to ask again, and the write-once binding blocks
	// re-enrolment on that device for good.
	memberships, err := s.store.UserTenants().GetUserTenants(ctx, userID)
	if err != nil {
		return fmt.Errorf("%w: list tenant memberships: %w", ErrDeletionIncomplete, err)
	}
	// The default tenant is always swept, not only when the membership list
	// is empty. A user registered there before any explicit membership
	// existed keeps data and wallet instances in it, and an instance that
	// outlives the account is permanent: records are keyed by instance-key
	// thumbprint and the passkey link is write-once, so re-enrolling on the
	// same device would be refused for good. WalletLifecycleService.userTenants
	// sweeps the same set for the same reason.
	//
	// The instances themselves are asked too, and their tenants added. A
	// membership can be gone while an instance of that tenant is not - the
	// admin DELETE /admin/tenants/{id}/users/{user_id} removes a membership
	// and nothing else - and the holder data in such a tenant would
	// otherwise be missed along with the instance.
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

	// Delete any legacy server-side stored credentials and presentations from
	// each tenant, regardless of whether credential/VC endpoints are currently enabled.
	// Holder-data failures count too. Reporting an account deleted while the
	// user's credentials are still there is the failure this endpoint exists
	// to avoid.
	for _, tenantID := range tenantIDs {
		dataErrs = append(dataErrs, s.eraseHolderData(ctx, tenantID, holderDID)...)
	}

	// Remove the user's wallet instances, in every tenant at once. Without
	// this they outlive the account: the records are keyed by instance-key
	// thumbprint and keep pointing at a user that no longer exists, so
	// re-enrolling on the same device finds an instance bound to someone
	// else and is refused for good (WIAService.checkInstanceBinding).
	//
	// A failure here is collected rather than logged and forgotten. It is
	// the one step of this cleanup whose residue is permanent, and the user
	// record is not deleted while any of it is outstanding, so the caller
	// can still authenticate and repeat the request.
	instanceErrs = s.deleteWalletInstances(ctx, userID)

	// Delete pending WebAuthn challenges (defense-in-depth; TTL handles expiry)
	if err := s.store.Challenges().DeleteByUserID(ctx, userID.String()); err != nil {
		s.logger.Warn("Failed to delete challenges for user", zap.Error(err))
	}

	// Clear user reference from consumed invites
	if err := s.store.Invites().ClearUsedBy(ctx, userID); err != nil {
		s.logger.Warn("Failed to clear invite used_by references", zap.Error(err))
	}

	// Purge active WebSocket sessions (Redis or memory)
	// A surviving session is not a cosmetic failure here. Deleting the user
	// record takes the token cut-off with it - it is a field on that record -
	// and internal/tokengate deliberately passes a token whose user it
	// cannot find. So a session that outlives this call could go on minting
	// bearer tokens for an account that is supposed to be gone.
	if s.sessionCleaner != nil {
		if err := s.sessionCleaner.DeleteByUser(ctx, userID.String()); err != nil {
			dataErrs = append(dataErrs, fmt.Errorf("drop sessions: %w", err))
		}
	}

	// Stop short of deleting the user record when a wallet instance was left
	// behind. Removing it now would strand that instance for good and take
	// away the caller's only way to ask again; leaving it means the request
	// can simply be repeated, the way an incomplete lifecycle cascade is.
	// Re-list before committing. The sweep above works from a snapshot and
	// is not serialized with WIA generation, so an attestation that was
	// already in flight can bind a new instance to this user between the
	// listing and here. Deleting the account on top of that would strand the
	// new record exactly as a failed delete would. One more pass is not a
	// lock - an attestation landing after this check still gets through, and
	// serializing lifecycle work with attestation is go-wallet-backend#330 -
	// but it closes the window that a slow sweep leaves wide.
	//
	// The second pass decides, and does not inherit the first. A delete that
	// failed once and succeeded now leaves nothing behind, so answering
	// DELETION_INCOMPLETE over a stale error would cost the caller a request
	// for work that is already done. The first pass's failures are logged
	// so a transient storage problem is still visible.
	if len(instanceErrs) > 0 {
		s.logger.Warn("wallet instance cleanup failed on the first pass, retrying before the user record is removed",
			zap.Error(errors.Join(instanceErrs...)), zap.String("user_id", userID.String()))
	}
	late, lateErrs := s.listWalletInstances(ctx, userID)
	instanceErrs = lateErrs
	// An instance discovered only now can be in a tenant the holder-data
	// loop never visited, so that tenant's credentials and presentations
	// would survive the account. Sweep those tenants before committing.
	for _, inst := range late {
		if seen[inst.TenantID] {
			continue
		}
		seen[inst.TenantID] = true
		// Into tenantIDs as well, so the membership-removal pass at the end
		// covers this tenant instead of leaving it orphaned.
		tenantIDs = append(tenantIDs, inst.TenantID)
		dataErrs = append(dataErrs, s.eraseHolderData(ctx, inst.TenantID, holderDID)...)
	}
	instanceErrs = append(instanceErrs, s.deleteWalletInstances(ctx, userID)...)

	outstanding := append(append([]error{}, instanceErrs...), dataErrs...)
	if len(outstanding) > 0 {
		s.logger.Error("Account deletion incomplete",
			zap.Error(errors.Join(outstanding...)), zap.String("user_id", userID.String()))
		return fmt.Errorf("%w: %w", ErrDeletionIncomplete, errors.Join(outstanding...))
	}

	// Memberships come last, once nothing is outstanding anywhere. They are
	// what makes a non-default tenant findable at all: the retry after a
	// DELETION_INCOMPLETE rebuilds its tenant list from them, so a
	// membership dropped while any instance is unaccounted for - including
	// one the final re-list above only just discovered in a different
	// tenant - would hide that tenant from every later attempt, and the next
	// call would find nothing outstanding and delete the account over the
	// top of the orphan.
	for _, tenantID := range tenantIDs {
		if err := s.store.UserTenants().RemoveMembership(ctx, userID, tenantID); err != nil {
			s.logger.Warn("Failed to remove tenant membership", zap.Error(err), zap.String("tenant_id", string(tenantID)))
		}
	}

	// Delete the user
	if err := s.store.Users().Delete(ctx, userID); err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}

	s.logger.Info("User deleted")
	return nil
}

// listWalletInstances lists every wallet instance of the user across all
// tenants. Split out so account deletion can look at what it found - a late
// instance may be in a tenant whose holder data was never swept - rather than
// only at what it failed to delete.
func (s *UserService) listWalletInstances(ctx context.Context, userID domain.UserID) ([]*domain.WalletInstance, []error) {
	instances, err := s.store.WalletInstances().GetAllByUser(ctx, userID)
	if err != nil && !errors.Is(err, storage.ErrNotFound) {
		return nil, []error{fmt.Errorf("list wallet instances: %w", err)}
	}
	return instances, nil
}

// eraseHolderData removes the holder's credentials and presentations in one
// tenant, logging what it could not remove. Used by the account-deletion
// sweep, including for a tenant discovered late.
func (s *UserService) eraseHolderData(ctx context.Context, tenantID domain.TenantID, holderDID string) []error {
	var errs []error
	credentials, err := s.store.Credentials().GetAllByHolder(ctx, tenantID, holderDID)
	if err != nil && !errors.Is(err, storage.ErrNotFound) {
		errs = append(errs, fmt.Errorf("list credentials in tenant %s: %w", tenantID, err))
	}
	for _, cred := range credentials {
		if err := s.store.Credentials().Delete(ctx, tenantID, holderDID, cred.CredentialIdentifier); err != nil {
			errs = append(errs, fmt.Errorf("delete credential %s: %w", cred.CredentialIdentifier, err))
		}
	}
	presentations, err := s.store.Presentations().GetAllByHolder(ctx, tenantID, holderDID)
	if err != nil && !errors.Is(err, storage.ErrNotFound) {
		errs = append(errs, fmt.Errorf("list presentations in tenant %s: %w", tenantID, err))
	}
	for _, pres := range presentations {
		if err := s.store.Presentations().Delete(ctx, tenantID, holderDID, pres.PresentationIdentifier); err != nil {
			errs = append(errs, fmt.Errorf("delete presentation %s: %w", pres.PresentationIdentifier, err))
		}
	}
	return errs
}

// deleteWalletInstances removes every wallet instance of the user, in every
// tenant, and returns what it could not do. Used twice by DeleteUser: once
// with the rest of the cleanup, and once more just before the user record is
// removed, to catch an attestation that bound an instance meanwhile.
func (s *UserService) deleteWalletInstances(ctx context.Context, userID domain.UserID) []error {
	instances, errs := s.listWalletInstances(ctx, userID)
	if len(errs) > 0 {
		return errs
	}
	for _, inst := range instances {
		if err := s.store.WalletInstances().Delete(ctx, inst.ID); err != nil {
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
	user.UpdatedAt = time.Now()
	if err := s.store.Users().Update(ctx, user); err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}
	return nil
}
