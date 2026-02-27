package service

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
	"github.com/sirosfoundation/go-wallet-backend/pkg/taggedbinary"
)

var (
	ErrChallengeNotFound  = errors.New("challenge not found")
	ErrChallengeExpired   = errors.New("challenge expired")
	ErrUserNotFound       = errors.New("user not found")
	ErrCredentialNotFound = errors.New("credential not found")
	ErrVerificationFailed = errors.New("verification failed")
	ErrTenantMismatch     = errors.New("tenant mismatch")
	ErrTenantAccessDenied = errors.New("tenant user must use tenant-scoped login endpoint")
	ErrTenantNotFound     = errors.New("tenant not found")
)

// TenantRedirectError indicates the user should be redirected to a different tenant
type TenantRedirectError struct {
	CorrectTenantID domain.TenantID
	UserID          domain.UserID
}

func (e *TenantRedirectError) Error() string {
	return fmt.Sprintf("user belongs to tenant %s, redirect required", e.CorrectTenantID)
}

// IsTenantRedirectError checks if an error is a TenantRedirectError
func IsTenantRedirectError(err error) (*TenantRedirectError, bool) {
	var redirectErr *TenantRedirectError
	if errors.As(err, &redirectErr) {
		return redirectErr, true
	}
	return nil, false
}

// WebAuthnService handles WebAuthn authentication
type WebAuthnService struct {
	store    storage.Store
	cfg      *config.Config
	logger   *zap.Logger
	webauthn *webauthn.WebAuthn
}

// NewWebAuthnService creates a new WebAuthnService
func NewWebAuthnService(store storage.Store, cfg *config.Config, logger *zap.Logger) (*WebAuthnService, error) {
	wconfig := &webauthn.Config{
		RPDisplayName: cfg.Server.RPName,
		RPID:          cfg.Server.RPID,
		RPOrigins:     []string{cfg.Server.RPOrigin},
	}

	wa, err := webauthn.New(wconfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create webauthn: %w", err)
	}

	return &WebAuthnService{
		store:    store,
		cfg:      cfg,
		logger:   logger.Named("webauthn-service"),
		webauthn: wa,
	}, nil
}

// WebAuthnUser implements webauthn.User interface
type WebAuthnUser struct {
	user *domain.User
}

func (u *WebAuthnUser) WebAuthnID() []byte {
	return u.user.UUID.AsUserHandle()
}

func (u *WebAuthnUser) WebAuthnName() string {
	if u.user.Username != nil {
		return *u.user.Username
	}
	return u.user.UUID.String()
}

func (u *WebAuthnUser) WebAuthnDisplayName() string {
	if u.user.DisplayName != nil {
		return *u.user.DisplayName
	}
	return u.WebAuthnName()
}

func (u *WebAuthnUser) WebAuthnCredentials() []webauthn.Credential {
	creds := make([]webauthn.Credential, 0, len(u.user.WebauthnCredentials))
	for _, c := range u.user.WebauthnCredentials {
		creds = append(creds, webauthn.Credential{
			ID:              c.CredentialID, // Use raw bytes, not base64url string
			PublicKey:       c.PublicKey,
			AttestationType: c.AttestationType,
			Transport:       parseTransports(c.Transport),
			Flags: webauthn.CredentialFlags{
				UserPresent:    c.Flags&0x01 != 0,
				UserVerified:   c.Flags&0x04 != 0,
				BackupEligible: c.Flags&0x08 != 0,
				BackupState:    c.Flags&0x10 != 0,
			},
			Authenticator: webauthn.Authenticator{
				AAGUID:       c.Authenticator.AAGUID,
				SignCount:    c.Authenticator.SignCount,
				CloneWarning: c.Authenticator.CloneWarning,
			},
		})
	}
	return creds
}

func parseTransports(transports []string) []protocol.AuthenticatorTransport {
	result := make([]protocol.AuthenticatorTransport, 0, len(transports))
	for _, t := range transports {
		result = append(result, protocol.AuthenticatorTransport(t))
	}
	return result
}

// parseTransportsToProtocol converts string transports to protocol type
func parseTransportsToProtocol(transports []string) []protocol.AuthenticatorTransport {
	return parseTransports(transports)
}

// WebAuthn response types that match the TypeScript wallet-backend-server format
// The key differences from go-webauthn's default types:
// 1. Binary fields (challenge, user.id) use {$b64u: "..."} tagged format
// 2. Single publicKey wrapper (not double-wrapped)
// 3. Includes userVerification, attestation, and extensions

// PublicKeyCredentialRpEntity matches the TS format
type PublicKeyCredentialRpEntity struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// PublicKeyCredentialUserEntity matches the TS format with tagged binary ID
type PublicKeyCredentialUserEntity struct {
	ID          taggedbinary.TaggedBytes `json:"id"`
	Name        string                   `json:"name"`
	DisplayName string                   `json:"displayName"`
}

// PublicKeyCredentialParameters matches the TS format
type PublicKeyCredentialParameters struct {
	Type string `json:"type"`
	Alg  int64  `json:"alg"`
}

// PublicKeyCredentialDescriptor matches the TS format
type PublicKeyCredentialDescriptor struct {
	Type       string                            `json:"type"`
	ID         taggedbinary.TaggedBytes          `json:"id"`
	Transports []protocol.AuthenticatorTransport `json:"transports,omitempty"`
}

// AuthenticatorSelectionCriteria matches the TS format
type AuthenticatorSelectionCriteria struct {
	RequireResidentKey bool                                 `json:"requireResidentKey"`
	ResidentKey        protocol.ResidentKeyRequirement      `json:"residentKey"`
	UserVerification   protocol.UserVerificationRequirement `json:"userVerification"`
}

// PRFExtension for WebAuthn PRF extension
type PRFExtension struct {
	Eval *PRFEvalExtension `json:"eval,omitempty"`
}

// PRFEvalExtension for PRF eval
type PRFEvalExtension struct {
	First taggedbinary.TaggedBytes `json:"first,omitempty"`
}

// AuthenticationExtensions matches the TS format
type AuthenticationExtensions struct {
	CredProps bool          `json:"credProps"`
	PRF       *PRFExtension `json:"prf,omitempty"`
}

// PublicKeyCredentialCreationOptions matches the TS format exactly
type PublicKeyCredentialCreationOptions struct {
	RP                     PublicKeyCredentialRpEntity     `json:"rp"`
	User                   PublicKeyCredentialUserEntity   `json:"user"`
	Challenge              taggedbinary.TaggedBytes        `json:"challenge"`
	PubKeyCredParams       []PublicKeyCredentialParameters `json:"pubKeyCredParams"`
	ExcludeCredentials     []PublicKeyCredentialDescriptor `json:"excludeCredentials"`
	AuthenticatorSelection AuthenticatorSelectionCriteria  `json:"authenticatorSelection"`
	Attestation            protocol.ConveyancePreference   `json:"attestation"`
	Extensions             AuthenticationExtensions        `json:"extensions"`
}

// CreateOptionsResponse wraps the creation options in publicKey (single level)
type CreateOptionsResponse struct {
	PublicKey PublicKeyCredentialCreationOptions `json:"publicKey"`
}

// BeginRegistrationResponse contains the registration options
type BeginRegistrationResponse struct {
	ChallengeID   string                `json:"challengeId"`
	CreateOptions CreateOptionsResponse `json:"createOptions"`
}

// BeginRegistrationRequest contains the optional tenant ID for registration
type BeginRegistrationRequest struct {
	DisplayName string `json:"displayName,omitempty"`
	TenantID    string `json:"tenantId,omitempty"`
}

// BeginRegistration starts WebAuthn registration for a new user
// If tenantId is provided, the user will be registered in that tenant
func (s *WebAuthnService) BeginRegistration(ctx context.Context, req *BeginRegistrationRequest) (*BeginRegistrationResponse, error) {
	// Validate tenant exists if provided
	var tenantID domain.TenantID
	if req.TenantID != "" {
		tenantID = domain.TenantID(req.TenantID)
		if _, err := s.store.Tenants().GetByID(ctx, tenantID); err != nil {
			if errors.Is(err, storage.ErrNotFound) {
				return nil, ErrTenantNotFound
			}
			return nil, fmt.Errorf("failed to verify tenant: %w", err)
		}
	}

	// Generate a new user ID
	userID := domain.NewUserID()

	// Create user handle - tenant-scoped if tenantId provided
	var userHandle []byte
	var waUser webauthn.User
	displayName := req.DisplayName
	if displayName == "" {
		displayName = "User"
	}
	tempUser := &domain.User{
		UUID:        userID,
		DisplayName: &displayName,
	}

	if tenantID != "" {
		userHandle = domain.EncodeUserHandle(tenantID, userID)
		waUser = &TenantWebAuthnUser{user: tempUser, userHandle: userHandle}
	} else {
		userHandle = userID.AsUserHandle()
		waUser = &WebAuthnUser{user: tempUser}
	}

	// Debug: log the userHandle being sent to the browser
	s.logger.Info("Registration: generated userHandle",
		zap.String("user_id", userID.String()),
		zap.String("tenant_id", string(tenantID)),
		zap.Int("handle_length", len(userHandle)),
		zap.Binary("handle_bytes", userHandle),
		zap.String("handle_as_string", string(userHandle)))

	// Generate creation options
	_, session, err := s.webauthn.BeginRegistration(waUser,
		webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementRequired),
	)
	if err != nil {
		s.logger.Error("Failed to begin registration", zap.Error(err))
		return nil, fmt.Errorf("failed to begin registration: %w", err)
	}

	// Store the challenge - session.Challenge is already a string (base64url encoded)
	challengeID := generateChallengeID()
	challenge := &domain.WebauthnChallenge{
		ID:        challengeID,
		UserID:    userID.String(),
		TenantID:  string(tenantID),  // Empty string for global registration
		Challenge: session.Challenge, // Already base64url encoded
		Action:    "register",
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}

	if err := s.store.Challenges().Create(ctx, challenge); err != nil {
		s.logger.Error("Failed to store challenge", zap.Error(err))
		return nil, fmt.Errorf("failed to store challenge: %w", err)
	}

	s.logger.Info("Started registration",
		zap.String("user_id", userID.String()),
		zap.String("tenant_id", string(tenantID)))

	// Build response matching TypeScript wallet-backend-server format
	// Decode challenge from base64url to raw bytes for TaggedBytes
	challengeBytes, err := base64.RawURLEncoding.DecodeString(session.Challenge)
	if err != nil {
		return nil, fmt.Errorf("failed to decode challenge: %w", err)
	}

	createOptions := CreateOptionsResponse{
		PublicKey: PublicKeyCredentialCreationOptions{
			RP: PublicKeyCredentialRpEntity{
				ID:   s.cfg.Server.RPID,
				Name: s.cfg.Server.RPName,
			},
			User: PublicKeyCredentialUserEntity{
				ID:          userHandle, // Tenant-scoped if tenantId provided
				Name:        waUser.WebAuthnName(),
				DisplayName: waUser.WebAuthnDisplayName(),
			},
			Challenge: challengeBytes,
			PubKeyCredParams: []PublicKeyCredentialParameters{
				{Type: "public-key", Alg: -7},   // ES256
				{Type: "public-key", Alg: -8},   // EdDSA
				{Type: "public-key", Alg: -257}, // RS256
			},
			ExcludeCredentials: []PublicKeyCredentialDescriptor{},
			AuthenticatorSelection: AuthenticatorSelectionCriteria{
				RequireResidentKey: true,
				ResidentKey:        protocol.ResidentKeyRequirementRequired,
				UserVerification:   protocol.VerificationRequired,
			},
			Attestation: protocol.PreferDirectAttestation,
			Extensions: AuthenticationExtensions{
				CredProps: true,
				PRF:       &PRFExtension{},
			},
		},
	}

	return &BeginRegistrationResponse{
		ChallengeID:   challengeID,
		CreateOptions: createOptions,
	}, nil
}

// FinishRegistrationRequest contains the registration response from the client
type FinishRegistrationRequest struct {
	ChallengeID string                   `json:"challengeId"`
	Credential  json.RawMessage          `json:"credential"`
	DisplayName string                   `json:"displayName,omitempty"`
	Nickname    string                   `json:"nickname,omitempty"`
	Keys        taggedbinary.TaggedBytes `json:"keys,omitempty"`
	PrivateData taggedbinary.TaggedBytes `json:"privateData,omitempty"`
}

// FinishRegistrationResponse contains the result of registration
type FinishRegistrationResponse struct {
	UUID              string                   `json:"uuid"`
	Token             string                   `json:"appToken"`
	DisplayName       string                   `json:"displayName"`
	Username          string                   `json:"username,omitempty"`
	PrivateData       taggedbinary.TaggedBytes `json:"privateData,omitempty"`
	WebauthnRpId      string                   `json:"webauthnRpId"`
	TenantID          string                   `json:"tenantId,omitempty"`
	TenantDisplayName string                   `json:"tenantDisplayName,omitempty"`
}

// FinishRegistration completes WebAuthn registration
func (s *WebAuthnService) FinishRegistration(ctx context.Context, req *FinishRegistrationRequest) (*FinishRegistrationResponse, error) {
	// Get and validate challenge
	challenge, err := s.store.Challenges().GetByID(ctx, req.ChallengeID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, ErrChallengeNotFound
		}
		return nil, fmt.Errorf("failed to get challenge: %w", err)
	}

	if challenge.IsExpired() {
		_ = s.store.Challenges().Delete(ctx, req.ChallengeID)
		return nil, ErrChallengeExpired
	}

	if challenge.Action != "register" {
		return nil, errors.New("invalid challenge action")
	}

	// Delete challenge (one-time use)
	_ = s.store.Challenges().Delete(ctx, req.ChallengeID)

	// Check if this is a tenant-scoped registration
	tenantID := domain.TenantID(challenge.TenantID)

	// Create user for verification
	userID := domain.UserIDFromString(challenge.UserID)
	displayName := req.DisplayName
	if displayName == "" {
		displayName = "User"
	}

	tempUser := &domain.User{
		UUID:        userID,
		DisplayName: &displayName,
	}

	// Create the appropriate user handle for verification
	var userHandle []byte
	var waUser webauthn.User
	if tenantID != "" {
		userHandle = domain.EncodeUserHandle(tenantID, userID)
		waUser = &TenantWebAuthnUser{user: tempUser, userHandle: userHandle}
	} else {
		userHandle = userID.AsUserHandle()
		waUser = &WebAuthnUser{user: tempUser}
	}

	// Create session data for verification
	sessionData := webauthn.SessionData{
		Challenge:        challenge.Challenge, // Already base64url encoded
		RelyingPartyID:   s.cfg.Server.RPID,
		UserID:           userHandle,
		UserVerification: protocol.VerificationRequired,
		// CredParams must match what was sent to the client in BeginRegistration
		CredParams: []protocol.CredentialParameter{
			{Type: protocol.PublicKeyCredentialType, Algorithm: webauthncose.AlgES256},
			{Type: protocol.PublicKeyCredentialType, Algorithm: webauthncose.AlgEdDSA},
			{Type: protocol.PublicKeyCredentialType, Algorithm: webauthncose.AlgRS256},
		},
	}

	// Parse the credential creation response
	// Debug: log the credential data being parsed
	credData := taggedbinary.MustDecodeJSON(req.Credential)
	s.logger.Debug("Parsing credential response",
		zap.Int("original_len", len(req.Credential)),
		zap.Int("decoded_len", len(credData)),
		zap.ByteString("decoded_preview", credData[:min(500, len(credData))]),
	)

	parsedResponse, err := protocol.ParseCredentialCreationResponseBody(
		newCredentialReader(req.Credential),
	)
	if err != nil {
		s.logger.Error("Failed to parse credential response",
			zap.Error(err),
			zap.String("error_type", fmt.Sprintf("%T", err)),
		)
		return nil, ErrVerificationFailed
	}

	// Verify the registration using CreateCredential
	credential, err := s.webauthn.CreateCredential(waUser, sessionData, parsedResponse)
	if err != nil {
		s.logger.Error("Failed to verify registration", zap.Error(err))
		return nil, ErrVerificationFailed
	}

	// Create the user with the credential
	credNickname := req.Nickname
	if credNickname == "" {
		credNickname = "Primary Passkey"
	}

	transports := make([]string, 0)
	for _, t := range credential.Transport {
		transports = append(transports, string(t))
	}

	now := time.Now()
	user := &domain.User{
		UUID:        userID,
		DisplayName: &displayName,
		DID:         fmt.Sprintf("did:key:%s", userID.String()),
		WalletType:  domain.WalletTypeClient,
		Keys:        req.Keys,
		PrivateData: req.PrivateData,
		WebauthnCredentials: []domain.WebauthnCredential{
			{
				ID:              base64.RawURLEncoding.EncodeToString(credential.ID),
				TenantID:        tenantID, // Store credential's tenant for isolation
				CredentialID:    credential.ID,
				PublicKey:       credential.PublicKey,
				AttestationType: credential.AttestationType,
				Transport:       transports,
				Flags:           encodeFlags(credential.Flags),
				Authenticator: domain.Authenticator{
					AAGUID:       credential.Authenticator.AAGUID,
					SignCount:    credential.Authenticator.SignCount,
					CloneWarning: credential.Authenticator.CloneWarning,
				},
				Nickname:  &credNickname,
				CreatedAt: now,
			},
		},
		CreatedAt: now,
		UpdatedAt: now,
	}

	if len(user.PrivateData) > 0 {
		user.PrivateDataETag = domain.ComputePrivateDataETag(user.PrivateData)
	}

	// Store the user
	if err := s.store.Users().Create(ctx, user); err != nil {
		s.logger.Error("Failed to create user", zap.Error(err))
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	// Add user to tenant if tenant-scoped registration
	var tenantDisplayName string
	if tenantID != "" {
		membership := &domain.UserTenantMembership{
			UserID:    userID,
			TenantID:  tenantID,
			Role:      domain.TenantRoleUser,
			CreatedAt: now,
		}
		if err := s.store.UserTenants().AddMembership(ctx, membership); err != nil {
			s.logger.Warn("Failed to add user to tenant membership",
				zap.Error(err),
				zap.String("user_id", userID.String()),
				zap.String("tenant_id", string(tenantID)))
		}
		// Get tenant display name for response
		if tenant, err := s.store.Tenants().GetByID(ctx, tenantID); err == nil {
			tenantDisplayName = tenant.DisplayName
		}
	}

	// Generate JWT token with tenant_id included for security boundary
	token, err := s.generateToken(user, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to generate token: %w", err)
	}

	s.logger.Info("User registered via WebAuthn",
		zap.String("user_id", userID.String()),
		zap.String("tenant_id", string(tenantID)))

	var username string
	if user.Username != nil {
		username = *user.Username
	}

	return &FinishRegistrationResponse{
		UUID:              userID.String(),
		Token:             token,
		DisplayName:       displayName,
		Username:          username,
		PrivateData:       user.PrivateData,
		WebauthnRpId:      s.cfg.Server.RPID,
		TenantID:          string(tenantID),
		TenantDisplayName: tenantDisplayName,
	}, nil
}

// GetOptionsWrapper wraps WebAuthn assertion options in a publicKey property (matches reference impl)
// PublicKeyCredentialRequestOptions matches the TS format exactly
type PublicKeyCredentialRequestOptions struct {
	RPId             string                               `json:"rpId"`
	Challenge        taggedbinary.TaggedBytes             `json:"challenge"`
	AllowCredentials []PublicKeyCredentialDescriptor      `json:"allowCredentials"`
	UserVerification protocol.UserVerificationRequirement `json:"userVerification"`
}

// GetOptionsResponse wraps the assertion options in publicKey (single level)
type GetOptionsResponse struct {
	PublicKey PublicKeyCredentialRequestOptions `json:"publicKey"`
}

// BeginLoginResponse contains the login options
type BeginLoginResponse struct {
	ChallengeID string             `json:"challengeId"`
	GetOptions  GetOptionsResponse `json:"getOptions"`
}

// BeginLogin starts WebAuthn authentication (discoverable credentials flow)
func (s *WebAuthnService) BeginLogin(ctx context.Context) (*BeginLoginResponse, error) {
	// For discoverable credentials, we don't need a specific user
	_, session, err := s.webauthn.BeginDiscoverableLogin(
		webauthn.WithUserVerification(protocol.VerificationRequired),
	)
	if err != nil {
		s.logger.Error("Failed to begin login", zap.Error(err))
		return nil, fmt.Errorf("failed to begin login: %w", err)
	}

	// Store the challenge
	challengeID := generateChallengeID()
	challenge := &domain.WebauthnChallenge{
		ID:        challengeID,
		UserID:    "", // No user yet for discoverable credentials
		Challenge: session.Challenge,
		Action:    "login",
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}

	if err := s.store.Challenges().Create(ctx, challenge); err != nil {
		s.logger.Error("Failed to store challenge", zap.Error(err))
		return nil, fmt.Errorf("failed to store challenge: %w", err)
	}

	s.logger.Info("Started login")

	// Decode challenge from base64url to raw bytes for TaggedBytes
	challengeBytes, err := base64.RawURLEncoding.DecodeString(session.Challenge)
	if err != nil {
		return nil, fmt.Errorf("failed to decode challenge: %w", err)
	}

	getOptions := GetOptionsResponse{
		PublicKey: PublicKeyCredentialRequestOptions{
			RPId:             s.cfg.Server.RPID,
			Challenge:        challengeBytes,
			AllowCredentials: []PublicKeyCredentialDescriptor{},
			UserVerification: protocol.VerificationRequired,
		},
	}

	return &BeginLoginResponse{
		ChallengeID: challengeID,
		GetOptions:  getOptions,
	}, nil
}

// FinishLoginRequest contains the authentication response from the client
type FinishLoginRequest struct {
	ChallengeID string          `json:"challengeId"`
	Credential  json.RawMessage `json:"credential"`
}

// FinishLoginResponse contains the result of login
type FinishLoginResponse struct {
	UUID              string                   `json:"uuid"`
	Token             string                   `json:"appToken"`
	DisplayName       string                   `json:"displayName"`
	Username          string                   `json:"username,omitempty"`
	PrivateData       taggedbinary.TaggedBytes `json:"privateData,omitempty"`
	WebauthnRpId      string                   `json:"webauthnRpId"`
	TenantID          string                   `json:"tenantId,omitempty"`
	TenantDisplayName string                   `json:"tenantDisplayName,omitempty"`
}

// FinishLogin completes WebAuthn authentication
func (s *WebAuthnService) FinishLogin(ctx context.Context, req *FinishLoginRequest) (*FinishLoginResponse, error) {
	// Get and validate challenge
	challenge, err := s.store.Challenges().GetByID(ctx, req.ChallengeID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, ErrChallengeNotFound
		}
		return nil, fmt.Errorf("failed to get challenge: %w", err)
	}

	if challenge.IsExpired() {
		_ = s.store.Challenges().Delete(ctx, req.ChallengeID)
		return nil, ErrChallengeExpired
	}

	if challenge.Action != "login" {
		return nil, errors.New("invalid challenge action")
	}

	// Delete challenge (one-time use)
	_ = s.store.Challenges().Delete(ctx, req.ChallengeID)

	// Parse the credential assertion response
	parsedResponse, err := protocol.ParseCredentialRequestResponseBody(
		newCredentialReader(req.Credential),
	)
	if err != nil {
		s.logger.Error("Failed to parse credential response", zap.Error(err))
		return nil, ErrVerificationFailed
	}

	// Get user from the credential's userHandle
	if len(parsedResponse.Response.UserHandle) == 0 {
		return nil, errors.New("user handle required for discoverable credentials")
	}

	// Try to decode user ID from the user handle
	// Note: With the new binary format (v1), we can't directly extract the tenant ID
	// from its hash. We need to look up the user and check their tenant membership.
	var userID domain.UserID
	var tenantID domain.TenantID
	userHandle := parsedResponse.Response.UserHandle

	// Debug: log the raw userHandle bytes to diagnose login failures
	s.logger.Info("Login: received userHandle",
		zap.Int("length", len(userHandle)),
		zap.Binary("bytes", userHandle),
		zap.String("as_string", string(userHandle)))

	// Try v1 binary format first, then legacy string format
	if uid, err := domain.UserIDFromHandle(userHandle); err == nil {
		userID = uid
		s.logger.Info("Login: decoded user ID from v1 binary handle",
			zap.String("user_id", userID.String()))
	} else {
		// Legacy user without proper format
		userID = domain.UserIDFromUserHandle(userHandle)
		s.logger.Info("Login: using legacy string handle format",
			zap.String("user_id", userID.String()),
			zap.Error(err))
	}

	// Look up the user first to determine their tenant
	user, err := s.store.Users().GetByID(ctx, userID)
	if err != nil {
		s.logger.Error("Login: user lookup failed",
			zap.String("user_id", userID.String()),
			zap.Error(err))
		if errors.Is(err, storage.ErrNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("failed to retrieve user: %w", err)
	}

	// Check the user's tenant membership to determine their primary tenant
	// This enables tenant discovery from the passkey credential
	userTenants, err := s.store.UserTenants().GetUserTenants(ctx, userID)
	if err != nil {
		s.logger.Warn("Failed to get user tenant memberships", zap.Error(err))
		// Default to treating as default tenant user for backward compatibility
		tenantID = domain.DefaultTenantID
	} else if len(userTenants) == 0 {
		// No memberships - treat as default tenant (legacy user)
		tenantID = domain.DefaultTenantID
	} else {
		// Use the first tenant membership as the user's primary tenant
		// This enables tenant discovery from the passkey without requiring redirect
		tenantID = userTenants[0]
	}

	// Find the credential
	// Encode RawID to base64url to match the format used during credential storage
	credentialID := base64.RawURLEncoding.EncodeToString(parsedResponse.RawID)
	var matchedCred *domain.WebauthnCredential
	for i, c := range user.WebauthnCredentials {
		if c.ID == credentialID {
			matchedCred = &user.WebauthnCredentials[i]
			break
		}
	}

	if matchedCred == nil {
		return nil, ErrCredentialNotFound
	}

	// SECURITY: Validate tenant isolation
	// The tenant hash in the userHandle must match the credential's tenant
	// This prevents cross-tenant login attacks
	handleTenantHash, isV1Handle := domain.TenantHashFromHandle(userHandle)
	if isV1Handle == nil {
		// V1 handle: verify tenant hash matches the credential's tenant
		credTenantID := domain.TenantID(matchedCred.TenantID)
		if credTenantID == "" {
			credTenantID = domain.DefaultTenantID
		}
		expectedTenantHash := domain.ComputeTenantHash(credTenantID)
		if !bytes.Equal(handleTenantHash, expectedTenantHash) {
			s.logger.Warn("Tenant hash mismatch in userHandle",
				zap.String("user_id", userID.String()),
				zap.String("credential_tenant", string(credTenantID)),
				zap.Binary("handle_tenant_hash", handleTenantHash),
				zap.Binary("expected_tenant_hash", expectedTenantHash))
			return nil, ErrTenantAccessDenied
		}
		// Use the credential's tenant as the authoritative tenant
		tenantID = credTenantID
		s.logger.Info("Login: validated tenant from v1 handle",
			zap.String("user_id", userID.String()),
			zap.String("tenant_id", string(tenantID)))
	} else {
		// Legacy handle: only allow default tenant access
		if tenantID != domain.DefaultTenantID {
			s.logger.Warn("Legacy handle cannot access non-default tenant",
				zap.String("user_id", userID.String()),
				zap.String("attempted_tenant", string(tenantID)))
			return nil, ErrTenantAccessDenied
		}
	}

	// Create session data for verification
	// Note: For discoverable login, UserID MUST be empty
	sessionData := webauthn.SessionData{
		Challenge:        challenge.Challenge,
		RelyingPartyID:   s.cfg.Server.RPID,
		UserVerification: protocol.VerificationRequired,
		// UserID intentionally left empty for discoverable login
	}

	// Verify the authentication using ValidateDiscoverableLogin
	credential, err := s.webauthn.ValidateDiscoverableLogin(
		func(rawID, userHandle []byte) (webauthn.User, error) {
			// Try to decode tenant-scoped user handle (format: "tenantId:userId")
			// Fall back to treating handle as just userId for legacy users
			var uid domain.UserID
			var isTenantUser bool
			if _, parsedUID, err := domain.DecodeUserHandle(userHandle); err == nil {
				uid = parsedUID
				isTenantUser = true
			} else {
				uid = domain.UserIDFromUserHandle(userHandle)
				isTenantUser = false
			}
			u, err := s.store.Users().GetByID(ctx, uid)
			if err != nil {
				return nil, err
			}
			// Return the appropriate user type so WebAuthnID() returns the correct handle
			if isTenantUser {
				return &TenantWebAuthnUser{user: u, userHandle: userHandle}, nil
			}
			return &WebAuthnUser{user: u}, nil
		},
		sessionData,
		parsedResponse,
	)
	if err != nil {
		s.logger.Error("Failed to verify login", zap.Error(err))
		return nil, ErrVerificationFailed
	}

	// Update the credential's signature count
	matchedCred.Authenticator.SignCount = credential.Authenticator.SignCount
	user.UpdatedAt = time.Now()

	if err := s.store.Users().Update(ctx, user); err != nil {
		s.logger.Error("Failed to update user", zap.Error(err))
		// Don't fail login for this
	}

	// Generate JWT token with tenant_id included for security boundary
	token, err := s.generateToken(user, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to generate token: %w", err)
	}

	displayName := ""
	if user.DisplayName != nil {
		displayName = *user.DisplayName
	}

	var username string
	if user.Username != nil {
		username = *user.Username
	}

	// Get tenant display name for the response
	var tenantDisplayName string
	if tenant, err := s.store.Tenants().GetByID(ctx, tenantID); err == nil {
		tenantDisplayName = tenant.DisplayName
	}

	s.logger.Info("User logged in via WebAuthn",
		zap.String("user_id", userID.String()),
		zap.String("tenant_id", string(tenantID)))

	return &FinishLoginResponse{
		UUID:              userID.String(),
		Token:             token,
		DisplayName:       displayName,
		Username:          username,
		PrivateData:       user.PrivateData,
		WebauthnRpId:      s.cfg.Server.RPID,
		TenantID:          string(tenantID),
		TenantDisplayName: tenantDisplayName,
	}, nil
}

func (s *WebAuthnService) generateToken(user *domain.User, tenantID domain.TenantID) (string, error) {
	// For backward compatibility, default to "default" tenant if not specified
	if tenantID == "" {
		tenantID = domain.DefaultTenantID
	}

	claims := jwt.MapClaims{
		"user_id":   user.UUID.String(),
		"did":       user.DID,
		"tenant_id": string(tenantID),
		"iat":       time.Now().Unix(),
		"exp":       time.Now().Add(time.Duration(s.cfg.JWT.ExpiryHours) * time.Hour).Unix(),
		"iss":       s.cfg.JWT.Issuer,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(s.cfg.JWT.Secret))
}

func generateChallengeID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func encodeFlags(flags webauthn.CredentialFlags) uint8 {
	var result uint8
	if flags.UserPresent {
		result |= 0x01
	}
	if flags.UserVerified {
		result |= 0x04
	}
	if flags.BackupEligible {
		result |= 0x08
	}
	if flags.BackupState {
		result |= 0x10
	}
	return result
}

// BeginAddCredentialResponse contains the response for adding a credential
type BeginAddCredentialResponse struct {
	Username      string                `json:"username,omitempty"`
	ChallengeID   string                `json:"challengeId"`
	CreateOptions CreateOptionsResponse `json:"createOptions"`
}

// BeginAddCredential starts the process of adding a new credential to an existing user
func (s *WebAuthnService) BeginAddCredential(ctx context.Context, userID domain.UserID) (*BeginAddCredentialResponse, error) {
	// Get the existing user
	user, err := s.store.Users().GetByID(ctx, userID)
	if err != nil {
		return nil, err
	}

	waUser := &WebAuthnUser{user: user}

	// Generate creation options
	_, session, err := s.webauthn.BeginRegistration(waUser,
		webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementRequired),
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			ResidentKey:      protocol.ResidentKeyRequirementRequired,
			UserVerification: protocol.VerificationRequired,
		}),
	)
	if err != nil {
		s.logger.Error("Failed to begin registration", zap.Error(err))
		return nil, fmt.Errorf("failed to begin registration: %w", err)
	}

	// Store the challenge
	challengeID := generateChallengeID()
	challenge := &domain.WebauthnChallenge{
		ID:        challengeID,
		Challenge: session.Challenge,
		UserID:    userID.String(),
		Action:    "add_credential",
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}

	if err := s.store.Challenges().Create(ctx, challenge); err != nil {
		return nil, fmt.Errorf("failed to store challenge: %w", err)
	}

	var username string
	if user.Username != nil {
		username = *user.Username
	}

	// Decode challenge from base64url to raw bytes for TaggedBytes
	challengeBytes, err := base64.RawURLEncoding.DecodeString(session.Challenge)
	if err != nil {
		return nil, fmt.Errorf("failed to decode challenge: %w", err)
	}

	// Build excludeCredentials from existing credentials
	excludeCredentials := make([]PublicKeyCredentialDescriptor, 0, len(user.WebauthnCredentials))
	for _, cred := range user.WebauthnCredentials {
		excludeCredentials = append(excludeCredentials, PublicKeyCredentialDescriptor{
			Type:       "public-key",
			ID:         cred.CredentialID,
			Transports: parseTransportsToProtocol(cred.Transport),
		})
	}

	createOptions := CreateOptionsResponse{
		PublicKey: PublicKeyCredentialCreationOptions{
			RP: PublicKeyCredentialRpEntity{
				ID:   s.cfg.Server.RPID,
				Name: s.cfg.Server.RPName,
			},
			User: PublicKeyCredentialUserEntity{
				ID:          userID.AsUserHandle(),
				Name:        waUser.WebAuthnName(),
				DisplayName: waUser.WebAuthnDisplayName(),
			},
			Challenge: challengeBytes,
			PubKeyCredParams: []PublicKeyCredentialParameters{
				{Type: "public-key", Alg: -7},   // ES256
				{Type: "public-key", Alg: -8},   // EdDSA
				{Type: "public-key", Alg: -257}, // RS256
			},
			ExcludeCredentials: excludeCredentials,
			AuthenticatorSelection: AuthenticatorSelectionCriteria{
				RequireResidentKey: true,
				ResidentKey:        protocol.ResidentKeyRequirementRequired,
				UserVerification:   protocol.VerificationRequired,
			},
			Attestation: protocol.PreferDirectAttestation,
			Extensions: AuthenticationExtensions{
				CredProps: true,
				PRF:       &PRFExtension{},
			},
		},
	}

	return &BeginAddCredentialResponse{
		Username:      username,
		ChallengeID:   challengeID,
		CreateOptions: createOptions,
	}, nil
}

// FinishAddCredentialRequest contains the request for finishing adding a credential
type FinishAddCredentialRequest struct {
	ChallengeID string                   `json:"challengeId"`
	Credential  json.RawMessage          `json:"credential"`
	Nickname    string                   `json:"nickname,omitempty"`
	PrivateData taggedbinary.TaggedBytes `json:"privateData,omitempty"`
}

// FinishAddCredentialResponse contains the response for finishing adding a credential
type FinishAddCredentialResponse struct {
	CredentialID    string `json:"credentialId"`
	PrivateDataETag string `json:"privateDataETag"`
}

// FinishAddCredential completes adding a new credential to an existing user
func (s *WebAuthnService) FinishAddCredential(ctx context.Context, userID domain.UserID, req *FinishAddCredentialRequest, ifMatch string) (*FinishAddCredentialResponse, error) {
	// Get the user
	user, err := s.store.Users().GetByID(ctx, userID)
	if err != nil {
		return nil, err
	}

	// Get and validate challenge
	challenge, err := s.store.Challenges().GetByID(ctx, req.ChallengeID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, ErrChallengeNotFound
		}
		return nil, fmt.Errorf("failed to get challenge: %w", err)
	}

	if challenge.IsExpired() {
		_ = s.store.Challenges().Delete(ctx, req.ChallengeID)
		return nil, ErrChallengeExpired
	}

	if challenge.Action != "add_credential" {
		return nil, errors.New("invalid challenge action")
	}

	if challenge.UserID != userID.String() {
		return nil, errors.New("challenge user mismatch")
	}

	// Delete challenge (one-time use)
	_ = s.store.Challenges().Delete(ctx, req.ChallengeID)

	waUser := &WebAuthnUser{user: user}

	// Create session data for verification
	sessionData := webauthn.SessionData{
		Challenge:        challenge.Challenge,
		RelyingPartyID:   s.cfg.Server.RPID,
		UserID:           userID.AsUserHandle(),
		UserVerification: protocol.VerificationRequired,
		// CredParams must match what was sent to the client in BeginAddCredential
		CredParams: []protocol.CredentialParameter{
			{Type: protocol.PublicKeyCredentialType, Algorithm: webauthncose.AlgES256},
			{Type: protocol.PublicKeyCredentialType, Algorithm: webauthncose.AlgEdDSA},
			{Type: protocol.PublicKeyCredentialType, Algorithm: webauthncose.AlgRS256},
		},
	}

	// Parse the credential creation response
	parsedResponse, err := protocol.ParseCredentialCreationResponseBody(
		newCredentialReader(req.Credential),
	)
	if err != nil {
		s.logger.Error("Failed to parse credential response", zap.Error(err))
		return nil, ErrVerificationFailed
	}

	// Verify the registration
	credential, err := s.webauthn.CreateCredential(waUser, sessionData, parsedResponse)
	if err != nil {
		s.logger.Error("Failed to verify registration", zap.Error(err))
		return nil, ErrVerificationFailed
	}

	// Check private data ETag if updating
	if len(req.PrivateData) > 0 && ifMatch != "" {
		if user.PrivateDataETag != ifMatch {
			return nil, ErrPrivateDataConflict
		}
	}

	// Add the new credential
	nickname := req.Nickname
	if nickname == "" {
		nickname = "Passkey"
	}

	transports := make([]string, 0)
	for _, t := range credential.Transport {
		transports = append(transports, string(t))
	}

	now := time.Now()
	newCred := domain.WebauthnCredential{
		ID:              base64.RawURLEncoding.EncodeToString(credential.ID),
		TenantID:        domain.TenantID(challenge.TenantID), // Store credential's tenant for isolation
		CredentialID:    credential.ID,
		PublicKey:       credential.PublicKey,
		AttestationType: credential.AttestationType,
		Transport:       transports,
		Flags:           encodeFlags(credential.Flags),
		Authenticator: domain.Authenticator{
			AAGUID:       credential.Authenticator.AAGUID,
			SignCount:    credential.Authenticator.SignCount,
			CloneWarning: credential.Authenticator.CloneWarning,
		},
		Nickname:  &nickname,
		CreatedAt: now,
	}

	user.WebauthnCredentials = append(user.WebauthnCredentials, newCred)

	// Update private data if provided
	if len(req.PrivateData) > 0 {
		user.PrivateData = req.PrivateData
		user.PrivateDataETag = domain.ComputePrivateDataETag(req.PrivateData)
	}

	user.UpdatedAt = now

	if err := s.store.Users().Update(ctx, user); err != nil {
		return nil, fmt.Errorf("failed to update user: %w", err)
	}

	s.logger.Info("Added WebAuthn credential to user", zap.String("user_id", userID.String()))

	return &FinishAddCredentialResponse{
		// Return base64url encoded ID to match the stored format
		CredentialID:    base64.RawURLEncoding.EncodeToString(credential.ID),
		PrivateDataETag: user.PrivateDataETag,
	}, nil
}

// credentialReader implements io.Reader for parsing credential responses.
// It decodes tagged binary format ({"$b64u": "..."}) to plain base64url strings
// to be compatible with the go-webauthn library's URLEncodedBase64 type.
type credentialReader struct {
	data   []byte
	offset int
}

// newCredentialReader creates a new credentialReader, decoding tagged binary if present.
func newCredentialReader(data []byte) *credentialReader {
	// Decode tagged binary format if present
	decoded := taggedbinary.MustDecodeJSON(data)
	return &credentialReader{data: decoded}
}

func (r *credentialReader) Read(p []byte) (n int, err error) {
	if r.offset >= len(r.data) {
		return 0, io.EOF
	}
	n = copy(p, r.data[r.offset:])
	r.offset += n
	return n, nil
}

// TenantWebAuthnUser wraps a user with a tenant-scoped user handle
type TenantWebAuthnUser struct {
	user       *domain.User
	userHandle []byte
}

func (u *TenantWebAuthnUser) WebAuthnID() []byte {
	return u.userHandle
}

func (u *TenantWebAuthnUser) WebAuthnName() string {
	if u.user.Username != nil {
		return *u.user.Username
	}
	return u.user.UUID.String()
}

func (u *TenantWebAuthnUser) WebAuthnDisplayName() string {
	if u.user.DisplayName != nil {
		return *u.user.DisplayName
	}
	return u.WebAuthnName()
}

func (u *TenantWebAuthnUser) WebAuthnCredentials() []webauthn.Credential {
	creds := make([]webauthn.Credential, len(u.user.WebauthnCredentials))
	for i, c := range u.user.WebauthnCredentials {
		creds[i] = webauthn.Credential{
			ID:              c.CredentialID, // Use raw bytes, not base64url string
			PublicKey:       c.PublicKey,
			AttestationType: c.AttestationType,
			Transport:       parseTransports(c.Transport),
			Flags: webauthn.CredentialFlags{
				UserPresent:    c.Flags&0x01 != 0,
				UserVerified:   c.Flags&0x04 != 0,
				BackupEligible: c.Flags&0x08 != 0,
				BackupState:    c.Flags&0x10 != 0,
			},
			Authenticator: webauthn.Authenticator{
				AAGUID:       c.Authenticator.AAGUID,
				SignCount:    c.Authenticator.SignCount,
				CloneWarning: c.Authenticator.CloneWarning,
			},
		}
	}
	return creds
}
