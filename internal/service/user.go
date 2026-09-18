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

// DeleteUser deletes a user and all associated data across ALL tenants.
// Note: If GetUserTenants fails, deletion proceeds with only the default tenant,
// which may leave orphaned data in other tenants. This is a best-effort cleanup
// that prioritizes completing the user deletion over strict data consistency.
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

func (s *UserService) DeleteUser(ctx context.Context, userID domain.UserID, holderDID string) error {
	var instanceErrs []error
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
	seen := map[domain.TenantID]bool{}
	tenantIDs := make([]domain.TenantID, 0, len(memberships)+1)
	for _, tid := range append([]domain.TenantID{domain.DefaultTenantID}, memberships...) {
		if !seen[tid] {
			seen[tid] = true
			tenantIDs = append(tenantIDs, tid)
		}
	}

	// Delete any legacy server-side stored credentials and presentations from
	// each tenant, regardless of whether credential/VC endpoints are currently enabled.
	for _, tenantID := range tenantIDs {
		credentials, err := s.store.Credentials().GetAllByHolder(ctx, tenantID, holderDID)
		if err != nil && !errors.Is(err, storage.ErrNotFound) {
			s.logger.Warn("Failed to get credentials for tenant", zap.Error(err), zap.String("tenant_id", string(tenantID)))
		}
		for _, cred := range credentials {
			if err := s.store.Credentials().Delete(ctx, tenantID, holderDID, cred.CredentialIdentifier); err != nil {
				s.logger.Warn("Failed to delete credential", zap.Error(err))
			}
		}

		// Delete any server-side stored presentations (VPs) for GDPR compliance
		presentations, err := s.store.Presentations().GetAllByHolder(ctx, tenantID, holderDID)
		if err != nil && !errors.Is(err, storage.ErrNotFound) {
			s.logger.Warn("Failed to get presentations for tenant", zap.Error(err), zap.String("tenant_id", string(tenantID)))
		}
		for _, pres := range presentations {
			if err := s.store.Presentations().Delete(ctx, tenantID, holderDID, pres.PresentationIdentifier); err != nil {
				s.logger.Warn("Failed to delete presentation", zap.Error(err))
			}
		}

		// Remove the user's wallet instances. Without this they outlive the
		// account: the records are keyed by instance-key thumbprint and keep
		// pointing at a user that no longer exists, so re-enrolling on the
		// same device finds an instance bound to someone else and is refused
		// for good (WIAService.checkInstanceBinding).
		//
		// A failure here is collected rather than logged and forgotten. It is
		// the one step of this cleanup whose residue is permanent, and the
		// user record is not deleted while any of it is outstanding, so the
		// caller can still authenticate and repeat the request.
		instances, err := s.store.WalletInstances().GetByUser(ctx, tenantID, userID)
		if err != nil && !errors.Is(err, storage.ErrNotFound) {
			instanceErrs = append(instanceErrs, fmt.Errorf("list wallet instances in tenant %s: %w", tenantID, err))
		}
		for _, inst := range instances {
			if err := s.store.WalletInstances().Delete(ctx, inst.ID); err != nil {
				instanceErrs = append(instanceErrs, fmt.Errorf("delete wallet instance %s: %w", inst.ID, err))
			}
		}

		// Remove tenant membership
		if err := s.store.UserTenants().RemoveMembership(ctx, userID, tenantID); err != nil {
			s.logger.Warn("Failed to remove tenant membership", zap.Error(err), zap.String("tenant_id", string(tenantID)))
		}
	}

	// Delete pending WebAuthn challenges (defense-in-depth; TTL handles expiry)
	if err := s.store.Challenges().DeleteByUserID(ctx, userID.String()); err != nil {
		s.logger.Warn("Failed to delete challenges for user", zap.Error(err))
	}

	// Clear user reference from consumed invites
	if err := s.store.Invites().ClearUsedBy(ctx, userID); err != nil {
		s.logger.Warn("Failed to clear invite used_by references", zap.Error(err))
	}

	// Purge active WebSocket sessions (Redis or memory)
	if s.sessionCleaner != nil {
		if err := s.sessionCleaner.DeleteByUser(ctx, userID.String()); err != nil {
			s.logger.Warn("Failed to delete sessions for user", zap.Error(err))
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
	// but it closes the window that a slow multi-tenant sweep leaves wide.
	for _, tenantID := range tenantIDs {
		remaining, err := s.store.WalletInstances().GetByUser(ctx, tenantID, userID)
		if err != nil && !errors.Is(err, storage.ErrNotFound) {
			instanceErrs = append(instanceErrs, fmt.Errorf("re-list wallet instances in tenant %s: %w", tenantID, err))
			continue
		}
		for _, inst := range remaining {
			if err := s.store.WalletInstances().Delete(ctx, inst.ID); err != nil {
				instanceErrs = append(instanceErrs, fmt.Errorf("delete wallet instance %s on the second pass: %w", inst.ID, err))
			}
		}
	}

	if len(instanceErrs) > 0 {
		s.logger.Error("Account deletion incomplete: wallet instances remain",
			zap.Error(errors.Join(instanceErrs...)), zap.String("user_id", userID.String()))
		return fmt.Errorf("%w: %w", ErrDeletionIncomplete, errors.Join(instanceErrs...))
	}

	// Delete the user
	if err := s.store.Users().Delete(ctx, userID); err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}

	s.logger.Info("User deleted")
	return nil
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
