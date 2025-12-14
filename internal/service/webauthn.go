package service

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
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
)

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
			ID:              []byte(c.ID),
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

// CreateOptionsWrapper wraps WebAuthn options in a publicKey property (matches reference impl)
type CreateOptionsWrapper struct {
	PublicKey *protocol.CredentialCreation `json:"publicKey"`
}

// BeginRegistrationResponse contains the registration options
type BeginRegistrationResponse struct {
	ChallengeID   string               `json:"challengeId"`
	CreateOptions CreateOptionsWrapper `json:"createOptions"`
}

// BeginRegistration starts WebAuthn registration for a new user
func (s *WebAuthnService) BeginRegistration(ctx context.Context, displayName string) (*BeginRegistrationResponse, error) {
	// Generate a new user ID
	userID := domain.NewUserID()

	// Create a temporary user for the ceremony
	tempUser := &domain.User{
		UUID:        userID,
		DisplayName: &displayName,
	}

	waUser := &WebAuthnUser{user: tempUser}

	// Generate creation options
	options, session, err := s.webauthn.BeginRegistration(waUser,
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
		Challenge: session.Challenge, // Already base64url encoded
		Action:    "register",
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}

	if err := s.store.Challenges().Create(ctx, challenge); err != nil {
		s.logger.Error("Failed to store challenge", zap.Error(err))
		return nil, fmt.Errorf("failed to store challenge: %w", err)
	}

	s.logger.Info("Started registration", zap.String("user_id", userID.String()))

	return &BeginRegistrationResponse{
		ChallengeID:   challengeID,
		CreateOptions: CreateOptionsWrapper{PublicKey: options},
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
	UUID         string                   `json:"uuid"`
	Token        string                   `json:"appToken"`
	DisplayName  string                   `json:"displayName"`
	Username     string                   `json:"username,omitempty"`
	PrivateData  taggedbinary.TaggedBytes `json:"privateData,omitempty"`
	WebauthnRpId string                   `json:"webauthnRpId"`
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
	waUser := &WebAuthnUser{user: tempUser}

	// Create session data for verification
	sessionData := webauthn.SessionData{
		Challenge:        challenge.Challenge, // Already base64url encoded
		UserID:           userID.AsUserHandle(),
		UserVerification: protocol.VerificationRequired,
	}

	// Parse the credential creation response
	parsedResponse, err := protocol.ParseCredentialCreationResponseBody(
		newCredentialReader(req.Credential),
	)
	if err != nil {
		s.logger.Error("Failed to parse credential response", zap.Error(err))
		return nil, ErrVerificationFailed
	}

	// Verify the registration using CreateCredential
	credential, err := s.webauthn.CreateCredential(waUser, sessionData, parsedResponse)
	if err != nil {
		s.logger.Error("Failed to verify registration", zap.Error(err))
		return nil, ErrVerificationFailed
	}

	// Create the user with the credential
	nickname := req.Nickname
	if nickname == "" {
		nickname = "Primary Passkey"
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
				ID:              string(credential.ID),
				PublicKey:       credential.PublicKey,
				AttestationType: credential.AttestationType,
				Transport:       transports,
				Flags:           encodeFlags(credential.Flags),
				Authenticator: domain.Authenticator{
					AAGUID:       credential.Authenticator.AAGUID,
					SignCount:    credential.Authenticator.SignCount,
					CloneWarning: credential.Authenticator.CloneWarning,
				},
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

	// Generate JWT token
	token, err := s.generateToken(user)
	if err != nil {
		return nil, fmt.Errorf("failed to generate token: %w", err)
	}

	s.logger.Info("User registered via WebAuthn", zap.String("user_id", userID.String()))

	var username string
	if user.Username != nil {
		username = *user.Username
	}

	return &FinishRegistrationResponse{
		UUID:         userID.String(),
		Token:        token,
		DisplayName:  displayName,
		Username:     username,
		PrivateData:  user.PrivateData,
		WebauthnRpId: s.cfg.Server.RPID,
	}, nil
}

// GetOptionsWrapper wraps WebAuthn assertion options in a publicKey property (matches reference impl)
type GetOptionsWrapper struct {
	PublicKey *protocol.CredentialAssertion `json:"publicKey"`
}

// BeginLoginResponse contains the login options
type BeginLoginResponse struct {
	ChallengeID string            `json:"challengeId"`
	GetOptions  GetOptionsWrapper `json:"getOptions"`
}

// BeginLogin starts WebAuthn authentication (discoverable credentials flow)
func (s *WebAuthnService) BeginLogin(ctx context.Context) (*BeginLoginResponse, error) {
	// For discoverable credentials, we don't need a specific user
	options, session, err := s.webauthn.BeginDiscoverableLogin(
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

	return &BeginLoginResponse{
		ChallengeID: challengeID,
		GetOptions:  GetOptionsWrapper{PublicKey: options},
	}, nil
}

// FinishLoginRequest contains the authentication response from the client
type FinishLoginRequest struct {
	ChallengeID string          `json:"challengeId"`
	Credential  json.RawMessage `json:"credential"`
}

// FinishLoginResponse contains the result of login
type FinishLoginResponse struct {
	UUID         string                   `json:"uuid"`
	Token        string                   `json:"appToken"`
	DisplayName  string                   `json:"displayName"`
	Username     string                   `json:"username,omitempty"`
	PrivateData  taggedbinary.TaggedBytes `json:"privateData,omitempty"`
	WebauthnRpId string                   `json:"webauthnRpId"`
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

	userID := domain.UserIDFromUserHandle(parsedResponse.Response.UserHandle)
	user, err := s.store.Users().GetByID(ctx, userID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	// Find the credential
	credentialID := parsedResponse.RawID
	var matchedCred *domain.WebauthnCredential
	for i, c := range user.WebauthnCredentials {
		if c.ID == string(credentialID) {
			matchedCred = &user.WebauthnCredentials[i]
			break
		}
	}

	if matchedCred == nil {
		return nil, ErrCredentialNotFound
	}

	// Create session data for verification
	sessionData := webauthn.SessionData{
		Challenge:        challenge.Challenge,
		UserID:           userID.AsUserHandle(),
		UserVerification: protocol.VerificationRequired,
	}

	// Verify the authentication using ValidateDiscoverableLogin
	credential, err := s.webauthn.ValidateDiscoverableLogin(
		func(rawID, userHandle []byte) (webauthn.User, error) {
			uid := domain.UserIDFromUserHandle(userHandle)
			u, err := s.store.Users().GetByID(ctx, uid)
			if err != nil {
				return nil, err
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

	// Generate JWT token
	token, err := s.generateToken(user)
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

	s.logger.Info("User logged in via WebAuthn", zap.String("user_id", userID.String()))

	return &FinishLoginResponse{
		UUID:         userID.String(),
		Token:        token,
		DisplayName:  displayName,
		Username:     username,
		PrivateData:  user.PrivateData,
		WebauthnRpId: s.cfg.Server.RPID,
	}, nil
}

func (s *WebAuthnService) generateToken(user *domain.User) (string, error) {
	claims := jwt.MapClaims{
		"user_id": user.UUID.String(),
		"did":     user.DID,
		"iat":     time.Now().Unix(),
		"exp":     time.Now().Add(time.Duration(s.cfg.JWT.ExpiryHours) * time.Hour).Unix(),
		"iss":     s.cfg.JWT.Issuer,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(s.cfg.JWT.Secret))
}

func generateChallengeID() string {
	b := make([]byte, 16)
	rand.Read(b)
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
	Username      string               `json:"username,omitempty"`
	ChallengeID   string               `json:"challengeId"`
	CreateOptions CreateOptionsWrapper `json:"createOptions"`
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
	options, session, err := s.webauthn.BeginRegistration(waUser,
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

	return &BeginAddCredentialResponse{
		Username:      username,
		ChallengeID:   challengeID,
		CreateOptions: CreateOptionsWrapper{PublicKey: options},
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
		UserID:           userID.AsUserHandle(),
		UserVerification: protocol.VerificationRequired,
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
		ID:              string(credential.ID),
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
		CredentialID:    string(credential.ID),
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
		return 0, errors.New("EOF")
	}
	n = copy(p, r.data[r.offset:])
	r.offset += n
	return n, nil
}
