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
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

var (
	ErrUserExists             = errors.New("user already exists")
	ErrPrivateDataConflict    = errors.New("private data conflict")
	ErrLastWebAuthnCredential = errors.New("cannot delete last webauthn credential")
)

// SessionCleaner can remove sessions for a user.
// Implemented by engine.SessionStore (memory or Redis) and as.SessionStore.
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

// UserService handles user-related operations
type UserService struct {
	store          storage.Store
	cfg            *config.Config
	logger         *zap.Logger
	sessionCleaner SessionCleaner
	tokenBlacklist TokenRevoker
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
func (s *UserService) DeleteUser(ctx context.Context, userID domain.UserID, holderDID string) error {
	// Get all tenants the user belongs to
	tenantIDs, err := s.store.UserTenants().GetUserTenants(ctx, userID)
	if err != nil {
		s.logger.Warn("Failed to get user tenants for cleanup", zap.Error(err))
		// Continue with user deletion even if we can't get tenants
		tenantIDs = []domain.TenantID{domain.DefaultTenantID}
	}
	if len(tenantIDs) == 0 {
		// User may have been registered without an explicit tenant membership;
		// always clean up the default tenant as a fallback.
		tenantIDs = []domain.TenantID{domain.DefaultTenantID}
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
	if s.tokenBlacklist != nil {
		if err := s.tokenBlacklist.RevokeUser(ctx, userID.String()); err != nil {
			s.logger.Warn("Failed to revoke tokens for deleted user", zap.Error(err))
		}
	}

	// Purge active WebSocket sessions (Redis or memory)
	if s.sessionCleaner != nil {
		if err := s.sessionCleaner.DeleteByUser(ctx, userID.String()); err != nil {
			s.logger.Warn("Failed to delete sessions for user", zap.Error(err))
		}
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
