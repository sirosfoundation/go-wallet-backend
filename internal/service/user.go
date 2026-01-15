package service

import (
	"context"
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

// UserService handles user-related operations
type UserService struct {
	store  storage.Store
	cfg    *config.Config
	logger *zap.Logger
}

// NewUserService creates a new UserService
func NewUserService(store storage.Store, cfg *config.Config, logger *zap.Logger) *UserService {
	return &UserService{
		store:  store,
		cfg:    cfg,
		logger: logger.Named("user-service"),
	}
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

	s.logger.Info("User registered", zap.String("user_id", user.UUID.String()))
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

	// Generate JWT token
	token, err := s.generateToken(user)
	if err != nil {
		return nil, "", fmt.Errorf("failed to generate token: %w", err)
	}

	s.logger.Info("User logged in", zap.String("user_id", user.UUID.String()))
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

func (s *UserService) generateToken(user *domain.User) (string, error) {
	claims := jwt.MapClaims{
		"user_id": user.UUID.String(),
		"did":     user.DID,
		"iss":     s.cfg.JWT.Issuer,
		"exp":     time.Now().Add(time.Duration(s.cfg.JWT.ExpiryHours) * time.Hour).Unix(),
		"iat":     time.Now().Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(s.cfg.JWT.Secret))
}

// GenerateTokenForUser generates a JWT token for a user (used after WebAuthn auth)
func (s *UserService) GenerateTokenForUser(user *domain.User) (string, error) {
	return s.generateToken(user)
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

	// Delete credentials and presentations from each tenant
	for _, tenantID := range tenantIDs {
		// Delete all credentials in this tenant
		credentials, err := s.store.Credentials().GetAllByHolder(ctx, tenantID, holderDID)
		if err != nil && !errors.Is(err, storage.ErrNotFound) {
			s.logger.Warn("Failed to get credentials for tenant", zap.Error(err), zap.String("tenant_id", string(tenantID)))
		}
		for _, cred := range credentials {
			if err := s.store.Credentials().Delete(ctx, tenantID, holderDID, cred.CredentialIdentifier); err != nil {
				s.logger.Warn("Failed to delete credential", zap.Error(err))
			}
		}

		// Delete all presentations in this tenant
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

	// Delete the user
	if err := s.store.Users().Delete(ctx, userID); err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}

	s.logger.Info("User deleted", zap.String("user_id", userID.String()))
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
