package service

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/golang-jwt/jwt/v5"
	cryptoutil "github.com/sirosfoundation/go-cryptoutil"
	"github.com/sirosfoundation/go-siros-set/set"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
	"github.com/sirosfoundation/go-wallet-backend/internal/tokengate"
	"github.com/sirosfoundation/go-wallet-backend/pkg/audit"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
	"github.com/sirosfoundation/go-wallet-backend/pkg/oidc"
	"github.com/sirosfoundation/go-wallet-backend/pkg/taggedbinary"
)

// EventWebAuthnCloneWarning is emitted when go-webauthn detects that an
// authenticator's signature counter regressed — the classic signal that
// credential key material has been cloned onto a second authenticator. Not
// part of go-siros-set's predefined event catalog, so it's declared locally
// the same way WIAService declares its own issuance-failure event.
const EventWebAuthnCloneWarning = set.EventURI("urn:siros:audit:webauthn:clone_warning")

// Enterprise-identity (OIDC gate) audit events (#66). Which of them are
// emitted is selected by AuditConfig.IdentityEvents; none are by default.
const (
	EventIdentityBound      = set.EventURI("urn:siros:audit:identity:bound")
	EventIdentityVerified   = set.EventURI("urn:siros:audit:identity:verified")
	EventIdentityMismatch   = set.EventURI("urn:siros:audit:identity:mismatch")
	EventIdentityGateBypass = set.EventURI("urn:siros:audit:identity:gate_bypass")
)

var (
	ErrChallengeNotFound       = errors.New("challenge not found")
	ErrChallengeExpired        = errors.New("challenge expired")
	ErrUserNotFound            = errors.New("user not found")
	ErrCredentialNotFound      = errors.New("credential not found")
	ErrVerificationFailed      = errors.New("verification failed")
	ErrTenantMismatch          = errors.New("tenant mismatch")
	ErrTenantAccessDenied      = errors.New("tenant user must use tenant-scoped login endpoint")
	ErrTenantNotFound          = errors.New("tenant not found")
	ErrInviteRequired          = errors.New("invite code required")
	ErrInvalidInvite           = errors.New("invalid or expired invite code")
	ErrIdentityNotBound        = errors.New("no enterprise identity bound for this tenant")
	ErrIdentityBindingMismatch = errors.New("enterprise identity does not match bound identity")
	ErrOIDCGateRequired        = errors.New("OIDC authentication required for this tenant")
)

// WebAuthnService handles WebAuthn authentication
type WebAuthnService struct {
	store           storage.Store
	cfg             *config.Config
	logger          *zap.Logger
	webauthn        *webauthn.WebAuthn
	aaguidValidator *AAGUIDValidator
	tokenBlacklist  *TokenBlacklist
	audit           *audit.Emitter
	auditCfg        config.AuditConfig
}

// SetAuditEmitter attaches a SET audit emitter to the service, used to record
// security-relevant events (currently: clone-authenticator warnings) in the
// shared audit trail. Safe to call with nil, which leaves auditing disabled
// (Emit/EmitWithSubject are no-ops on a nil *audit.Emitter).
func (s *WebAuthnService) SetAuditEmitter(a *audit.Emitter) {
	s.audit = a
}

// SetAuditIdentityConfig selects which enterprise-identity audit events are
// emitted (see config.AuditConfig.IdentityEvents). The zero value emits none.
func (s *WebAuthnService) SetAuditIdentityConfig(cfg config.AuditConfig) {
	s.auditCfg = cfg
}

// auditIdentity emits an enterprise-identity audit event if that event is
// selected in config. The subject is never emitted in the clear: it is
// identified by a hash over issuer and subject.
func (s *WebAuthnService) auditIdentity(name string, event set.EventURI, userID string, tenantID domain.TenantID, issuer, subject string, extra map[string]any) {
	if s.audit == nil || !s.auditCfg.IdentityEventEnabled(name) {
		return
	}
	data := map[string]any{
		"user_id":   userID,
		"tenant_id": string(tenantID),
		"issuer":    issuer,
	}
	for k, v := range extra {
		data[k] = v
	}
	subjectID := "user:" + userID
	if subject != "" {
		subjectID = subjectHash(issuer, subject)
	}
	s.audit.EmitWithSubject(event, subjectID, data)
}

// subjectHash returns a stable, non-reversible identifier for an OIDC subject.
func subjectHash(issuer, subject string) string {
	h := sha256.Sum256([]byte(issuer + "\x00" + subject))
	return "sha256:" + hex.EncodeToString(h[:])
}

// ErrAAGUIDBlacklisted indicates the authenticator's AAGUID is blocked
var ErrAAGUIDBlacklisted = errors.New("authenticator not allowed")

// ErrWalletInstanceRevoked refuses a login whose passkey belongs to a revoked
// wallet instance - SID-AUTH-06 login gate, see checkWalletLifecycle and
// WalletLifecycleService.
//
// ErrWalletDeactivated refuses every passkey of a wallet whose instances have
// all been revoked (the wallet data has been erased and a new enrollment is
// required). It wraps ErrWalletInstanceRevoked, so a caller that only needs
// to know the login was refused for lifecycle reasons matches the one error;
// a caller that wants to tell the user whether other devices can still log in
// checks for ErrWalletDeactivated first.
var (
	ErrWalletInstanceRevoked = errors.New("wallet instance revoked")
	ErrWalletDeactivated     = fmt.Errorf("wallet deactivated: %w", ErrWalletInstanceRevoked)
)

// LifecycleScopeInstance and LifecycleScopeWallet are the values of the
// `scope` field of a SID-AUTH-06 login refusal: whether the refusal is about
// this one wallet instance, or about the whole wallet the login was for.
//
// The distinction decides what a client does next, so it must be readable
// without parsing prose: with scope "instance" the wallet still exists and
// the user's other devices answer for themselves at their own login, while
// with scope "wallet" no instance of it is left to reactivate and a new
// enrollment is required. The error codes cannot carry it - WALLET_REVOKED
// has meant both since the first release - so it is exposed alongside them.
//
// Both scopes are about the tenant the login was for, because that is what
// checkWalletLifecycle looks at (WalletInstanceStore.GetByUser is per
// tenant) and what the refusal governs. For a user who belongs to more than
// one tenant, scope "wallet" therefore says this wallet cannot be opened
// here and not that nothing of the user's is left anywhere: the data shared
// across tenants - the private data that holds the wallet's keys, and the
// pending challenges - is erased only when no live instance remains in any
// of the user's tenants, see WalletLifecycleService.eraseWalletData.
const (
	LifecycleScopeInstance = "instance"
	LifecycleScopeWallet   = "wallet"
)

// LifecycleRefusalDetail is one SID-AUTH-06 login refusal as it appears on
// the wire: the stable error code clients switch on, the scope that says
// whether the wallet still exists, and a user-facing message.
type LifecycleRefusalDetail struct {
	// Code is WALLET_REVOKED.
	Code string
	// Scope is LifecycleScopeInstance or LifecycleScopeWallet, and is
	// about the tenant the refused login was for.
	Scope string
	// Message is the user-facing explanation. It is for display only:
	// nothing a client decides may depend on reading it.
	Message string
}

// LifecycleRefusalDetails maps a SID-AUTH-06 login refusal to its wire form.
// The code says the wallet was revoked (that is what existing clients switch
// on) and the scope says whether one instance or the whole wallet is refused;
// the message says the same thing for a human. ErrWalletDeactivated wraps
// ErrWalletInstanceRevoked, so it is matched first.
//
// Every login handler answers with this, so the wallet API and the AS passkey
// endpoint cannot disagree about what a refusal means.
func LifecycleRefusalDetails(err error) LifecycleRefusalDetail {
	switch {
	case errors.Is(err, ErrWalletDeactivated):
		return LifecycleRefusalDetail{
			Code:    "WALLET_REVOKED",
			Scope:   LifecycleScopeWallet,
			Message: "This wallet has been deactivated; a new enrollment is required",
		}
	default:
		// Not "other devices are not affected": this refusal is about this
		// instance, and another device may well be revoked in its own right. It says what this revocation did, and leaves the
		// others to answer for themselves at their own login.
		return LifecycleRefusalDetail{
			Code:    "WALLET_REVOKED",
			Scope:   LifecycleScopeInstance,
			Message: "This wallet instance has been revoked; other devices enrolled to this wallet keep their own status",
		}
	}
}

// NewWebAuthnService creates a new WebAuthnService
func NewWebAuthnService(store storage.Store, cfg *config.Config, logger *zap.Logger) (*WebAuthnService, error) {
	return NewWebAuthnServiceWithValidator(store, cfg, logger, nil)
}

// NewWebAuthnServiceWithValidator creates a new WebAuthnService with an AAGUID validator
func NewWebAuthnServiceWithValidator(store storage.Store, cfg *config.Config, logger *zap.Logger, validator *AAGUIDValidator) (*WebAuthnService, error) {
	wconfig := &webauthn.Config{
		RPDisplayName: cfg.Server.RPName,
		RPID:          cfg.Server.RPID,
		RPOrigins:     cfg.Server.GetRPOrigins(),
		// go-webauthn >= 0.18 rejects client extension outputs that were not
		// listed in the session's requested extensions. Our clients add the PRF
		// eval input themselves (the wallet-frontend and the native SDKs derive
		// the keystore key from the PRF output on both registration and login),
		// so the backend cannot know the full set of extensions a client will
		// return. Unsolicited outputs carry no security weight; ignore them.
		ExtensionsUnsolicitedOutputPolicy: protocol.UnsolicitedOutputPolicyIgnore,
	}

	wa, err := webauthn.New(wconfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create webauthn: %w", err)
	}

	return &WebAuthnService{
		store:           store,
		cfg:             cfg,
		logger:          logger.Named("webauthn-service"),
		webauthn:        wa,
		aaguidValidator: validator,
	}, nil
}

// SetTokenBlacklist sets the token blacklist. When set, RefreshAccessToken
// consumes (blacklists) the presented refresh token's own jti once it has
// been exchanged, so the same refresh token can't be replayed to mint
// another access/refresh token pair indefinitely - see RefreshAccessToken's
// doc comment (Copilot review on #400: RefreshAccessToken only rotated
// tokens and never invalidated the one just used).
func (s *WebAuthnService) SetTokenBlacklist(b *TokenBlacklist) {
	s.tokenBlacklist = b
}

// getAttestationPreference returns the configured attestation conveyance preference
func (s *WebAuthnService) getAttestationPreference() protocol.ConveyancePreference {
	pref := s.cfg.Security.WebAuthn.GetAttestationConveyance()
	switch pref {
	case "direct":
		return protocol.PreferDirectAttestation
	case "indirect":
		return protocol.PreferIndirectAttestation
	case "enterprise":
		return protocol.PreferEnterpriseAttestation
	default:
		return protocol.PreferNoAttestation
	}
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
	InviteCode  string `json:"inviteCode,omitempty"`
}

// BeginRegistration starts WebAuthn registration for a new user
// If tenantId is provided, the user will be registered in that tenant
func (s *WebAuthnService) BeginRegistration(ctx context.Context, req *BeginRegistrationRequest) (*BeginRegistrationResponse, error) {
	// Invite codes are tenant-scoped (Invites().GetByCode requires a
	// tenantID) and FinishRegistration's atomic invite claim is likewise
	// only reachable when the challenge carries a tenantID. Without this
	// guard, an invite code supplied alongside an empty tenantID would
	// never be validated OR consumed at all: BeginRegistration's invite
	// checks live entirely inside the `req.TenantID != ""` branch below, and
	// FinishRegistration's completion-time claim is gated the same way — so
	// that combination would silently create a global (non-tenant) account
	// while leaving the referenced invite untouched, instead of being
	// rejected. Fail closed here instead.
	if req.InviteCode != "" && req.TenantID == "" {
		return nil, ErrInvalidInvite
	}

	// Validate tenant exists if provided
	var tenantID domain.TenantID
	if req.TenantID != "" {
		tenantID = domain.TenantID(req.TenantID)
		tenant, err := s.store.Tenants().GetByID(ctx, tenantID)
		if err != nil {
			if errors.Is(err, storage.ErrNotFound) {
				return nil, ErrTenantNotFound
			}
			return nil, fmt.Errorf("failed to verify tenant: %w", err)
		}

		// Validate invite code if tenant requires it or if one was provided
		if tenant.RequireInvite || req.InviteCode != "" {
			if req.InviteCode == "" {
				return nil, ErrInviteRequired
			}
			invite, err := s.store.Invites().GetByCode(ctx, tenantID, req.InviteCode)
			if err != nil {
				if errors.Is(err, storage.ErrNotFound) {
					return nil, ErrInvalidInvite
				}
				return nil, fmt.Errorf("failed to verify invite: %w", err)
			}
			if !invite.IsUsable() {
				return nil, ErrInvalidInvite
			}
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
		ID:         challengeID,
		UserID:     userID.String(),
		TenantID:   string(tenantID),  // Empty string for global registration
		Challenge:  session.Challenge, // Already base64url encoded
		Action:     "register",
		InviteCode: req.InviteCode, // Stored for completion in FinishRegistration
		ExpiresAt:  time.Now().Add(5 * time.Minute),
	}

	if err := s.store.Challenges().Create(ctx, challenge); err != nil {
		s.logger.Error("Failed to store challenge", zap.Error(err))
		return nil, fmt.Errorf("failed to store challenge: %w", err)
	}

	s.logger.Info("Started registration",
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
			Attestation: s.getAttestationPreference(),
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

	// OIDCGateBinding contains optional OIDC identity binding info (set by handler)
	// This is populated from the OIDC gate middleware result when bind_identity is true
	OIDCGateBinding *OIDCGateBinding `json:"-"` // Do not bind from JSON

	// ExpectedTenantID, when set by the handler, must match the tenant
	// BeginRegistration recorded on the challenge (challenge.TenantID).
	// Handlers set this from their own validated tenant context (e.g. the
	// X-Tenant-ID header, or the JWT tenant_id claim for an authenticated
	// caller) so that a caller can't run BeginRegistration under one tenant
	// and FinishRegistration under a different one - which would otherwise
	// let tenant-scoped policy decisions the handler makes (e.g.
	// bind_identity enforcement) run against the wrong tenant's config while
	// the registration itself is still written under whatever tenant the
	// challenge actually belongs to. Left empty, no check is performed (for
	// callers that don't have this context). See issue #374/#395.
	ExpectedTenantID string `json:"-"` // Do not bind from JSON
}

// OIDCGateBinding contains OIDC identity info for binding
type OIDCGateBinding struct {
	Issuer      string
	Subject     string
	Email       string
	BindingType string // "registration" or "login"

	// Audience, when set, is the audience the presented token was actually
	// validated against (the tenant whose gate the caller passed - see
	// AS PasskeyHandlers.LoginFinish, and internal/api/handlers.go's
	// FinishWebAuthnLogin, which sets it the same way for /user/*).
	// FinishLogin compares it against the CREDENTIAL's real tenant's LoginOP
	// audience: without this, two tenants that share an OIDC issuer but use
	// different client IDs/audiences could have a token valid for tenant A's
	// app satisfy tenant B's login gate, since only Issuer was previously
	// compared. Left empty (the default for any caller that doesn't set it),
	// no audience check is performed - purely opt-in.
	Audience string

	// Claims, when set, are the full validated token claims (the same map
	// the OIDC gate middleware itself checked against the HEADER tenant's
	// OIDCGate.RequiredClaims). Set by both AS PasskeyHandlers.LoginFinish
	// and internal/api/handlers.go's FinishWebAuthnLogin. FinishLogin
	// re-checks them against the CREDENTIAL's real tenant's own
	// RequiredClaims: Issuer and Audience matching isn't enough if two
	// tenants share both but configure different RequiredClaims - a token
	// accepted for a permissive tenant could otherwise satisfy a stricter
	// tenant's login gate purely because the gate middleware only ever
	// validated it against the header tenant's policy. Left nil (the
	// default for any caller that doesn't set it), no claims re-check is
	// performed - purely opt-in, like Audience above.
	Claims jwt.MapClaims
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
	// Atomically consume the challenge (single find-and-delete), constrained
	// to the caller's validated tenant context (set by the handler) as part
	// of the SAME atomic operation when one was given — see
	// ExpectedTenantID's doc comment. This closes two TOCTOU windows at
	// once: a separate GetByID+Delete lets concurrent callers presenting
	// the same challengeId+assertion all read the challenge before any of
	// them deletes it, and all pass verification (issue #379); and a
	// tenant-mismatch check performed only AFTER an unconstrained consume
	// would let a caller who merely knows a valid challenge ID submit it
	// with the wrong tenant purely to burn the one-time challenge, denying
	// the legitimate caller (with the matching tenant) the ability to ever
	// finish it. ConsumeByIDForTenant guarantees at most one caller ever
	// gets a non-nil challenge back for a given ID, and a tenant mismatch
	// never touches the real challenge at all.
	challenge, err := s.store.Challenges().ConsumeByIDForTenant(ctx, req.ChallengeID, req.ExpectedTenantID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			if req.ExpectedTenantID != "" {
				// Distinguish "doesn't exist" from "tenant mismatch" only
				// for the caller-facing error code, not the storage query
				// itself (which is deliberately a single atomic op either
				// way) — a non-existent challenge and a same-tenant lookup
				// both already return ErrChallengeNotFound; we only need
				// ErrTenantMismatch when a tenant context was actually
				// supplied, matching the error this replaces.
				if _, getErr := s.store.Challenges().GetByID(ctx, req.ChallengeID); getErr == nil {
					return nil, ErrTenantMismatch
				}
			}
			return nil, ErrChallengeNotFound
		}
		return nil, fmt.Errorf("failed to consume challenge: %w", err)
	}

	if challenge.IsExpired() {
		return nil, ErrChallengeExpired
	}

	if challenge.Action != "register" {
		return nil, errors.New("invalid challenge action")
	}

	// Check if this is a tenant-scoped registration
	tenantID := domain.TenantID(challenge.TenantID)

	// Re-validate invite if one was used at BeginRegistration time.
	// The invite may have been revoked or expired during the challenge window.
	if challenge.InviteCode != "" && tenantID != "" {
		invite, err := s.store.Invites().GetByCode(ctx, tenantID, challenge.InviteCode)
		if err != nil {
			if errors.Is(err, storage.ErrNotFound) {
				return nil, ErrInvalidInvite
			}
			return nil, fmt.Errorf("failed to re-validate invite: %w", err)
		}
		if !invite.IsUsable() {
			return nil, ErrInvalidInvite
		}
	}

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
		// Extensions must record what was sent to the client in BeginRegistration
		Extensions: protocol.SessionExtensions{
			Requested: []string{protocol.ExtensionCredProps, protocol.ExtensionPRF},
		},
	}

	// Parse the credential creation response
	// Debug: log the credential data being parsed
	credData := taggedbinary.MustDecodeJSON(req.Credential)
	s.logger.Debug("Parsing credential response",
		zap.Int("original_len", len(req.Credential)),
		zap.Int("decoded_len", len(credData)),
		zap.ByteString("decoded_preview", credData[:min(1000, len(credData))]),
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
		// Log failure at error level
		s.logger.Error("Failed to verify registration",
			zap.Error(err),
			zap.String("error_type", fmt.Sprintf("%T", err)),
		)

		// Log detailed diagnostics at debug level for troubleshooting
		// Guard with level check to avoid expensive hashing when debug is disabled
		if s.logger.Core().Enabled(zap.DebugLevel) {
			sigLen, sigHash, normalizedChanged, normalizeErr := attestationSignatureDiagnostics(parsedResponse.Response.AttestationObject)
			leafCertHash, leafCertLen := attestationLeafCertDiagnostics(parsedResponse.Response.AttestationObject)
			signatureInputHash := attestationSignatureInputHash(
				parsedResponse.Response.AttestationObject.RawAuthData,
				parsedResponse.Raw.AttestationResponse.ClientDataJSON,
			)

			s.logger.Debug("Registration verification fingerprints",
				zap.Error(err),
				zap.String("attestation_format", parsedResponse.Response.AttestationObject.Format),
				zap.String("auth_data_sha256", sha256Hex(parsedResponse.Response.AttestationObject.RawAuthData)),
				zap.String("client_data_json_sha256", sha256Hex(parsedResponse.Raw.AttestationResponse.ClientDataJSON)),
				zap.String("signature_input_sha256", signatureInputHash),
				zap.Int("signature_len", sigLen),
				zap.String("signature_sha256", sigHash),
				zap.Bool("signature_normalized_changed", normalizedChanged),
				zap.String("signature_normalize_error", normalizeErr),
				zap.Int("x5c_leaf_len", leafCertLen),
				zap.String("x5c_leaf_sha256", leafCertHash),
			)

			attObj := parsedResponse.Response.AttestationObject
			s.logger.Debug("Attestation object details",
				zap.String("format", attObj.Format),
				zap.Int("auth_data_len", len(attObj.RawAuthData)),
				zap.String("auth_data_hex", fmt.Sprintf("%x", attObj.RawAuthData)),
			)

			// Log attestation statement contents
			for key, val := range attObj.AttStatement {
				switch v := val.(type) {
				case []byte:
					s.logger.Debug("AttStatement field (bytes)",
						zap.String("key", key),
						zap.Int("length", len(v)),
						zap.String("base64", base64.StdEncoding.EncodeToString(v)),
						zap.String("hex_preview", fmt.Sprintf("%x", v[:min(64, len(v))])),
					)
				case []any:
					// This is likely x5c certificate chain
					if key == "x5c" {
						for i, cert := range v {
							if certBytes, ok := cert.([]byte); ok {
								s.logger.Debug("x5c certificate",
									zap.Int("index", i),
									zap.Int("length", len(certBytes)),
									zap.String("base64_der", base64.StdEncoding.EncodeToString(certBytes)),
								)
							}
						}
					} else {
						s.logger.Debug("AttStatement field (array)",
							zap.String("key", key),
							zap.Int("length", len(v)),
						)
					}
				case int64:
					s.logger.Debug("AttStatement field (int64)",
						zap.String("key", key),
						zap.Int64("value", v),
					)
				default:
					s.logger.Debug("AttStatement field (other)",
						zap.String("key", key),
						zap.String("type", fmt.Sprintf("%T", v)),
					)
				}
			}

			// Log the raw credential JSON for complete reproduction data
			s.logger.Debug("Raw credential JSON for reproduction",
				zap.ByteString("credential_json", req.Credential),
			)
		}

		return nil, ErrVerificationFailed
	}

	// Validate AAGUID if validator is configured
	if s.aaguidValidator != nil {
		result := s.aaguidValidator.Validate(credential.Authenticator.AAGUID)
		if !result.Allowed {
			s.logger.Warn("Registration blocked by AAGUID policy",
				zap.String("aaguid", result.AAGUID),
				zap.String("reason", result.Reason()),
				zap.Bool("is_zero", result.IsZero),
				zap.Bool("is_blacklisted", result.IsBlacklisted),
			)
			return nil, ErrAAGUIDBlacklisted
		}
		s.logger.Debug("AAGUID validation passed",
			zap.String("aaguid", result.AAGUID),
		)
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
		DID:         domain.HolderDID(userID.String()),
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

	// Log public key diagnostics for registration
	if s.logger.Core().Enabled(zap.DebugLevel) {
		publicKeyHash := sha256Hex(credential.PublicKey)
		s.logger.Debug("Registration: storing credential with public key",
			zap.String("user_id", userID.String()),
			zap.String("stored_public_key_sha256", publicKeyHash),
			zap.Int("stored_public_key_len", len(credential.PublicKey)),
			zap.String("attestation_type", credential.AttestationType),
			zap.String("credential_id", base64.RawURLEncoding.EncodeToString(credential.ID)),
		)
	}

	// Bind enterprise identity if OIDC gate binding was provided
	if req.OIDCGateBinding != nil && tenantID != "" {
		user.AddEnterpriseIdentity(domain.EnterpriseIdentity{
			TenantID:    tenantID,
			Issuer:      req.OIDCGateBinding.Issuer,
			Subject:     req.OIDCGateBinding.Subject,
			Email:       req.OIDCGateBinding.Email,
			BindingType: req.OIDCGateBinding.BindingType,
			BoundAt:     now,
		})
		s.logger.Info("Bound enterprise identity to user",
			zap.String("tenant_id", string(tenantID)),
			zap.String("issuer", req.OIDCGateBinding.Issuer))
	}

	// Atomically consume the invite BEFORE creating the user account. The
	// early IsUsable() check above and this atomic MarkCompleted are not
	// atomic with each other, so a concurrent loser can still pass that
	// early check while a winner's MarkCompleted has already committed; by
	// gating user creation on MarkCompleted succeeding here, the loser is
	// rejected before Users().Create()/AddMembership ever run, instead of
	// after an account has already been committed (issue #378 — the invite
	// single-use TOCTOU). MarkCompleted is a single atomic
	// find-and-update-if-active operation in both storage backends, so only
	// one concurrent caller can ever win it.
	//
	// A non-empty InviteCode with an empty tenantID is rejected up front in
	// BeginRegistration and should therefore never reach a stored challenge,
	// but fail closed here too as defense-in-depth: an invite code must
	// always resolve to a real atomic claim, never be silently skipped.
	if challenge.InviteCode != "" {
		if tenantID == "" {
			s.logger.Warn("Challenge carries an invite code but no tenant; rejecting registration",
				zap.String("user_id", userID.String()))
			return nil, ErrInvalidInvite
		}
		if err := s.store.Invites().MarkCompleted(ctx, tenantID, challenge.InviteCode, userID); err != nil {
			invitePrefix := challenge.InviteCode
			if len(invitePrefix) > 8 {
				invitePrefix = invitePrefix[:8]
			}
			s.logger.Warn("Invite could not be atomically claimed; rejecting registration",
				zap.Error(err),
				zap.String("invite_code_prefix", invitePrefix),
				zap.String("user_id", userID.String()))
			return nil, ErrInvalidInvite
		}
	}

	// Store the user
	if err := s.store.Users().Create(ctx, user); err != nil {
		s.logger.Error("Failed to create user", zap.Error(err))
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	// Audit the binding only now that the user, and with it the bound
	// identity, is persisted: an invite claim or Create failure above must
	// not leave an immutable "bound" record for an identity that was never
	// bound.
	if req.OIDCGateBinding != nil && tenantID != "" {
		s.auditIdentity(config.AuditIdentityBound, EventIdentityBound, userID.String(), tenantID,
			req.OIDCGateBinding.Issuer, req.OIDCGateBinding.Subject,
			map[string]any{"binding_type": req.OIDCGateBinding.BindingType})
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

	// Generate JWT token with tenant_id included for security boundary. No
	// refresh token is minted for a fresh registration, so there is no
	// family to track (sid: "").
	token, err := s.generateToken(user, tenantID, "")
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
	ChallengeID     string           `json:"challengeId"`
	Credential      json.RawMessage  `json:"credential"`
	OIDCGateBinding *OIDCGateBinding `json:"-"` // Set by handler when OIDC gate is active with bind_identity
}

// FinishLoginResponse contains the result of login
type FinishLoginResponse struct {
	UUID              string                   `json:"uuid"`
	Token             string                   `json:"appToken"`
	RefreshToken      string                   `json:"refreshToken,omitempty"` // Optional refresh token
	DisplayName       string                   `json:"displayName"`
	Username          string                   `json:"username,omitempty"`
	PrivateData       taggedbinary.TaggedBytes `json:"privateData,omitempty"`
	WebauthnRpId      string                   `json:"webauthnRpId"`
	TenantID          string                   `json:"tenantId,omitempty"`
	TenantDisplayName string                   `json:"tenantDisplayName,omitempty"`

	// SID is the refresh-token family/session id (#402) shared by Token and
	// RefreshToken. Never serialized: it is for server-side callers (the AS
	// passkey login records it on its session so AS logout can revoke the
	// family).
	SID string `json:"-"`
}

// FinishLogin completes WebAuthn authentication
func (s *WebAuthnService) FinishLogin(ctx context.Context, req *FinishLoginRequest) (*FinishLoginResponse, error) {
	// Atomically consume the challenge (single find-and-delete). Without
	// this, N concurrent FinishLogin calls presenting the same
	// challengeId+assertion could all read the challenge via GetByID before
	// any of them called Delete, and all pass verification — confirmed on
	// production as 16 parallel login_finish calls on one challenge
	// producing 14 valid appTokens (issue #379). ConsumeByID guarantees at
	// most one caller ever gets a non-nil challenge back for a given ID.
	challenge, err := s.store.Challenges().ConsumeByID(ctx, req.ChallengeID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, ErrChallengeNotFound
		}
		return nil, fmt.Errorf("failed to consume challenge: %w", err)
	}

	if challenge.IsExpired() {
		return nil, ErrChallengeExpired
	}

	if challenge.Action != "login" {
		return nil, errors.New("invalid challenge action")
	}

	// Debug: log the credential data being parsed
	credData := taggedbinary.MustDecodeJSON(req.Credential)
	s.logger.Debug("Parsing credential assertion response",
		zap.Int("original_len", len(req.Credential)),
		zap.Int("decoded_len", len(credData)),
		zap.ByteString("decoded_preview", credData[:min(1000, len(credData))]),
	)

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
		credTenantID := domain.TenantID(matchedCred.TenantID) //nolint:unconvert
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
		s.logger.Error("Failed to verify login",
			zap.Error(err),
			zap.String("error_type", fmt.Sprintf("%T", err)),
		)

		// Log detailed diagnostics at debug level for troubleshooting
		if s.logger.Core().Enabled(zap.DebugLevel) {
			sigLen, sigHash, normalizedChanged, normalizeErr := assertionSignatureDiagnostics(parsedResponse.Response.Signature)
			signatureInputHash := attestationSignatureInputHash(
				parsedResponse.Raw.AssertionResponse.AuthenticatorData,
				parsedResponse.Raw.AssertionResponse.ClientDataJSON,
			)

			// Diagnostic info about stored public key
			storedPublicKeyHash := sha256Hex(matchedCred.PublicKey)
			storedPublicKeyLen := len(matchedCred.PublicKey)

			s.logger.Debug("Login verification fingerprints",
				zap.Error(err),
				zap.String("auth_data_sha256", sha256Hex(parsedResponse.Raw.AssertionResponse.AuthenticatorData)),
				zap.String("client_data_json_sha256", sha256Hex(parsedResponse.Raw.AssertionResponse.ClientDataJSON)),
				zap.String("signature_input_sha256", signatureInputHash),
				zap.Int("signature_len", sigLen),
				zap.String("signature_sha256", sigHash),
				zap.Bool("signature_normalized_changed", normalizedChanged),
				zap.String("signature_normalize_error", normalizeErr),
				zap.Uint32("sign_count", parsedResponse.Response.AuthenticatorData.Counter),
				zap.String("credential_id", credentialID),
				zap.String("stored_public_key_sha256", storedPublicKeyHash),
				zap.Int("stored_public_key_len", storedPublicKeyLen),
			)
		}

		return nil, ErrVerificationFailed
	}

	// SID-AUTH-06 login gate: a revoked wallet instance must not
	// be able to log in, and a deactivated wallet (all instances revoked) must
	// require a fresh enrollment. Checked only after the assertion verified,
	// so an attacker cannot probe lifecycle state with a forged assertion.
	if err := s.checkWalletLifecycle(ctx, tenantID, userID, matchedCred.ID); err != nil {
		return nil, err
	}

	// Keep the assertion's reported counter in a LOCAL value for
	// logging/the atomic persist call below, rather than mutating
	// matchedCred/the stored user object directly. This is the same
	// aliasing hazard already documented (and fixed) for CloneWarning a few
	// lines below: the memory store's GetByID returns the same pointer it
	// holds internally rather than a copy (unlike MongoDB, which always
	// decodes a fresh struct), so writing straight into matchedCred here
	// would mutate the LIVE stored credential before
	// UpdateCredentialAuthenticator's max-under-lock update ever runs — if
	// 20 is stored and this assertion reports a regression to 10, the
	// stored value would already be lowered to 10 by this line alone,
	// defeating the monotonic $max/max-under-lock guarantee entirely (and
	// racing unsynchronized against any other concurrent access to the same
	// in-memory object). See go-wallet-backend#411.
	newSignCount := credential.Authenticator.SignCount

	// Log public key diagnostics for successful login
	if s.logger.Core().Enabled(zap.DebugLevel) {
		storedPublicKeyHash := sha256Hex(matchedCred.PublicKey)
		storedPublicKeyLen := len(matchedCred.PublicKey)
		s.logger.Debug("Login verification succeeded",
			zap.String("user_id", userID.String()),
			zap.String("stored_public_key_sha256", storedPublicKeyHash),
			zap.Int("stored_public_key_len", storedPublicKeyLen),
			zap.Uint32("sign_count", newSignCount),
		)
	}

	// SECURITY: persist SignCount/CloneWarning via a single atomic,
	// field-scoped update rather than the whole-document Update()/ReplaceOne
	// used elsewhere. A read-then-write mitigation (re-reading the stored
	// CloneWarning immediately before a ReplaceOne and OR-ing it in) was
	// tried here first and was correctly flagged in review as still racy:
	// two concurrent logins can both observe CloneWarning==false, and
	// whichever one's ReplaceOne lands last — even if it's the "clean" one
	// that read before the "clone detected" one wrote — clobbers the whole
	// document with its own stale, false snapshot. There is no read-then-write
	// window that closes that: it needs the storage layer itself to make
	// the write conditional/OR-only in one round trip.
	// UpdateCredentialAuthenticator does exactly that (MongoDB: a single
	// UpdateOne with an arrayFilter that only ever includes clone_warning in
	// its $set when true, never explicitly writing false — omitting the
	// field leaves whatever is currently stored untouched; memory: the same
	// OR-only assignment under one mutex acquisition). No concurrent
	// ordering of two such calls can ever result in a true being overwritten
	// by a false.
	//
	// It also reports whether THIS call is the one that actually flipped
	// CloneWarning from false to true — a real compare-and-set outcome from
	// the storage layer, not a locally precomputed guess. That distinction
	// matters under concurrency: two logins on separate challenges can both
	// read a stale CloneWarning=false before either persists, so a local
	// "was it already true when I read it" check (as an earlier version of
	// this fix used) would let both independently conclude "newly
	// detected" and both emit the security event — a duplicate. Gating the
	// emission on the atomic transition result instead means only the one
	// call that actually won the race reports it.
	transitioned, err := s.store.Users().UpdateCredentialAuthenticator(ctx, userID, credentialID, newSignCount, credential.Authenticator.CloneWarning)
	if err != nil {
		s.logger.Error("Failed to update credential authenticator", zap.Error(err))
		// Don't fail login for this — but if a clone was genuinely detected
		// on THIS assertion, the persistence failure must not also silently
		// swallow the security signal itself. transitioned is unreliable
		// here (the atomic call never got to compare-and-set), so this is a
		// distinct, separately-greppable event from the normal
		// "webauthn_clone_warning" line below — it says "detected, but we
		// don't know if this made it into storage", not "confirmed newly
		// latched". See go-wallet-backend#411.
		if credential.Authenticator.CloneWarning {
			s.logger.Error("possible cloned authenticator detected but the warning failed to persist",
				zap.String("security_event", "webauthn_clone_warning_persist_failed"),
				zap.String("user_id", userID.String()),
				zap.String("tenant_id", string(tenantID)),
				zap.String("credential_id", credentialID),
				zap.Uint32("sign_count", newSignCount),
				zap.Error(err),
			)
			s.audit.EmitWithSubject(EventWebAuthnCloneWarning, credentialID, map[string]any{
				"user_id":    userID.String(),
				"tenant_id":  string(tenantID),
				"sign_count": newSignCount,
				"persisted":  false,
			})
		}
	}

	// SECURITY: go-webauthn sets CloneWarning when the authenticator's
	// signature counter regressed relative to what we have stored — the
	// standard signal that this credential's private key has been cloned
	// onto a second authenticator. We deliberately still let the login
	// through (a single stateful counter is a weak signal in isolation, and
	// some legitimate authenticators never increment it), but the warning
	// must never be silently swallowed: log it as a distinct, greppable
	// security-event line and, when audit is enabled, record it in the
	// shared SET audit trail so it can be alerted on and investigated
	// (issue #380). Gated on the atomic false-to-true transition reported by
	// UpdateCredentialAuthenticator above, not the raw flag, so this fires
	// exactly once per actual detection — even under concurrent logins —
	// rather than on every subsequent login or being duplicated by a race.
	if transitioned {
		s.logger.Warn("possible cloned authenticator detected",
			zap.String("security_event", "webauthn_clone_warning"),
			zap.String("user_id", userID.String()),
			zap.String("tenant_id", string(tenantID)),
			zap.String("credential_id", credentialID),
			zap.Uint32("sign_count", newSignCount),
		)
		s.audit.EmitWithSubject(EventWebAuthnCloneWarning, credentialID, map[string]any{
			"user_id":    userID.String(),
			"tenant_id":  string(tenantID),
			"sign_count": newSignCount,
		})
	}

	// SECURITY: Enforce OIDC gate based on the credential's tenant (not header tenant)
	// This prevents bypass via X-Tenant-ID header spoofing
	tenant, err := s.store.Tenants().GetByID(ctx, tenantID)
	if err != nil {
		s.logger.Error("Failed to get tenant for OIDC gate check", zap.Error(err))
		return nil, fmt.Errorf("failed to verify tenant config: %w", err)
	}

	// Check if this tenant requires OIDC gate for login
	if tenant.OIDCGate.RequiresGateForLogin() {
		// Gate is required - verify OIDC binding was provided
		if req.OIDCGateBinding == nil {
			s.logger.Warn("Login gate required but no OIDC binding provided",
				zap.String("user_id", userID.String()),
				zap.String("tenant_id", string(tenantID)))
			s.auditIdentity(config.AuditIdentityGateBypass, EventIdentityGateBypass, userID.String(), tenantID, "", "", nil)
			return nil, ErrOIDCGateRequired
		}

		// SECURITY: Always verify issuer matches tenant's configured LoginOP
		// This prevents bypass via tokens from other tenants' OPs
		loginOP := tenant.OIDCGate.GetLoginOP()
		if loginOP == nil {
			s.logger.Error("Login gate enabled but no LoginOP configured",
				zap.String("tenant_id", string(tenantID)))
			return nil, fmt.Errorf("login gate misconfigured: no LoginOP")
		}
		if req.OIDCGateBinding.Issuer != loginOP.Issuer {
			s.logger.Warn("OIDC binding issuer mismatch",
				zap.String("user_id", userID.String()),
				zap.String("tenant_id", string(tenantID)),
				zap.String("expected_issuer", loginOP.Issuer),
				zap.String("actual_issuer", req.OIDCGateBinding.Issuer))
			s.auditIdentity(config.AuditIdentityMismatch, EventIdentityMismatch, userID.String(), tenantID,
				req.OIDCGateBinding.Issuer, req.OIDCGateBinding.Subject,
				map[string]any{"reason": "issuer", "expected_issuer": loginOP.Issuer})
			return nil, ErrOIDCGateRequired // Reject with gate required - token was for wrong OP
		}

		// SECURITY: when the caller recorded which audience the token was
		// actually validated against (see OIDCGateBinding.Audience's doc
		// comment), it must match this tenant's own configured audience too.
		// Two tenants can share an issuer (e.g. a shared multi-tenant IdP
		// domain) while using different client IDs/audiences per app; issuer
		// alone isn't enough to prove the token was meant for THIS tenant.
		if req.OIDCGateBinding.Audience != "" && req.OIDCGateBinding.Audience != loginOP.EffectiveAudience() {
			s.logger.Warn("OIDC binding audience mismatch",
				zap.String("user_id", userID.String()),
				zap.String("tenant_id", string(tenantID)),
				zap.String("expected_audience", loginOP.EffectiveAudience()),
				zap.String("actual_audience", req.OIDCGateBinding.Audience))
			s.auditIdentity(config.AuditIdentityMismatch, EventIdentityMismatch, userID.String(), tenantID,
				req.OIDCGateBinding.Issuer, req.OIDCGateBinding.Subject,
				map[string]any{"reason": "audience"})
			return nil, ErrOIDCGateRequired // Reject with gate required - token was for the wrong app
		}

		// SECURITY: when the caller recorded the token's full validated
		// claims (see OIDCGateBinding.Claims's doc comment), re-check them
		// against THIS tenant's own RequiredClaims. Issuer and Audience
		// matching alone isn't enough: two tenants can share both while
		// configuring different RequiredClaims, and the OIDC gate middleware
		// only ever validated the token against the HEADER tenant's
		// RequiredClaims - not the credential's real tenant's.
		if req.OIDCGateBinding.Claims != nil && len(tenant.OIDCGate.RequiredClaims) > 0 {
			for key, expected := range tenant.OIDCGate.RequiredClaims {
				actual, exists := req.OIDCGateBinding.Claims[key]
				if !exists || !oidc.ClaimsMatch(expected, actual) {
					s.logger.Warn("OIDC binding required-claims mismatch",
						zap.String("user_id", userID.String()),
						zap.String("tenant_id", string(tenantID)),
						zap.String("claim", key))
					s.auditIdentity(config.AuditIdentityMismatch, EventIdentityMismatch, userID.String(), tenantID,
						req.OIDCGateBinding.Issuer, req.OIDCGateBinding.Subject,
						map[string]any{"reason": "required_claims", "claim": key})
					return nil, ErrOIDCGateRequired
				}
			}
		}

		// If bind_identity is enabled, verify the enterprise identity matches
		if tenant.OIDCGate.BindIdentity {
			existingIdentity := user.GetEnterpriseIdentityForTenant(tenantID)
			if existingIdentity == nil {
				s.logger.Warn("User has no bound enterprise identity for tenant",
					zap.String("user_id", userID.String()),
					zap.String("tenant_id", string(tenantID)))
				s.auditIdentity(config.AuditIdentityMismatch, EventIdentityMismatch, userID.String(), tenantID,
					req.OIDCGateBinding.Issuer, req.OIDCGateBinding.Subject,
					map[string]any{"reason": "not_bound"})
				return nil, ErrIdentityNotBound
			}

			// Verify issuer and subject match
			if existingIdentity.Issuer != req.OIDCGateBinding.Issuer ||
				existingIdentity.Subject != req.OIDCGateBinding.Subject {
				s.logger.Warn("Enterprise identity mismatch during login",
					zap.String("user_id", userID.String()),
					zap.String("tenant_id", string(tenantID)),
					zap.String("expected_issuer", existingIdentity.Issuer),
					zap.String("actual_issuer", req.OIDCGateBinding.Issuer),
					zap.String("expected_subject", existingIdentity.Subject),
					zap.String("actual_subject", req.OIDCGateBinding.Subject))
				s.auditIdentity(config.AuditIdentityMismatch, EventIdentityMismatch, userID.String(), tenantID,
					req.OIDCGateBinding.Issuer, req.OIDCGateBinding.Subject,
					map[string]any{
						"reason":          "identity",
						"expected_issuer": existingIdentity.Issuer,
						// Hash of the bound identity, so the two can be compared
						// without either subject appearing in the audit trail.
						"expected_subject_hash": subjectHash(existingIdentity.Issuer, existingIdentity.Subject),
					})
				return nil, ErrIdentityBindingMismatch
			}

			s.logger.Info("Enterprise identity verified during login",
				zap.String("user_id", userID.String()),
				zap.String("tenant_id", string(tenantID)),
				zap.String("issuer", req.OIDCGateBinding.Issuer))
			s.auditIdentity(config.AuditIdentityVerified, EventIdentityVerified, userID.String(), tenantID,
				req.OIDCGateBinding.Issuer, req.OIDCGateBinding.Subject, nil)
		}
	}

	// A fresh sid (refresh-token family/session id) ties this access token
	// to the refresh token minted alongside it (and to every token
	// produced by rotating that refresh token - see RefreshAccessToken),
	// so Logout can revoke the whole family in one call (#402).
	// No refresh token means no family to revoke beyond the access token's
	// own jti, so no sid is minted or exposed then (avoids year-long
	// revocation markers for nothing).
	sid := ""
	if s.cfg.JWT.RefreshDays > 0 {
		sid = generateChallengeID()
	}

	// Generate JWT token (and refresh token, if enabled) with tenant_id
	// included for security boundary. SID-AUTH-06: minted and then checked
	// against the user's token cut-off, see mintTokens.
	token, refreshToken, err := s.mintTokens(ctx, user, tenantID, sid, func() error {
		return s.checkWalletLifecycle(ctx, tenantID, userID, matchedCred.ID)
	}, ErrVerificationFailed)
	if err != nil {
		return nil, err
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
	// Note: tenant was already fetched above for OIDC gate check
	tenantDisplayName := tenant.DisplayName

	s.logger.Info("User logged in via WebAuthn",
		zap.String("user_id", userID.String()),
		zap.String("tenant_id", string(tenantID)))

	return &FinishLoginResponse{
		UUID:              userID.String(),
		Token:             token,
		RefreshToken:      refreshToken,
		DisplayName:       displayName,
		Username:          username,
		PrivateData:       user.PrivateData,
		WebauthnRpId:      s.cfg.Server.RPID,
		TenantID:          string(tenantID),
		TenantDisplayName: tenantDisplayName,
		SID:               sid,
	}, nil
}

// generateToken mints an access token. sid, when non-empty, is the
// refresh-token family/session id (see generateRefreshToken) this access
// token was issued alongside - carried in the "sid" claim so
// pkg/middleware.AuthMiddlewareWithBlacklist can reject it if that family is
// later revoked via TokenBlacklist.RevokeFamily on logout (#402). Pass "" for
// an access token issued without a paired refresh token (e.g.
// FinishRegistration): there is no family to track, and the claim is simply
// omitted, exactly matching every pre-#402 token.
func (s *WebAuthnService) generateToken(user *domain.User, tenantID domain.TenantID, sid string) (string, error) {
	// For backward compatibility, default to "default" tenant if not specified
	if tenantID == "" {
		tenantID = domain.DefaultTenantID
	}

	now := time.Now()
	jti := generateChallengeID() // Generate unique token ID

	claims := jwt.MapClaims{
		"user_id":   user.UUID.String(),
		"did":       user.DID,
		"tenant_id": string(tenantID),
		"iat":       now.Unix(),
		"nbf":       now.Unix(),                                                       // Not Before: token valid from now
		"exp":       now.Add(time.Duration(s.cfg.JWT.ExpiryHours) * time.Hour).Unix(), // Expiry
		"iss":       s.cfg.JWT.Issuer,
		"aud":       s.cfg.Server.RPID, // Audience: the RP ID
		"jti":       jti,               // JWT ID: unique identifier for revocation
	}
	if sid != "" {
		claims["sid"] = sid
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(s.cfg.JWT.Secret))
}

// generateRefreshToken creates a long-lived refresh token for token renewal.
// sid is the refresh-token family/session id (see generateToken's doc
// comment) - the same value must be passed to the paired generateToken call
// at initial issuance, and to both calls again on every subsequent rotation
// (RefreshAccessToken), so that revoking it once (TokenBlacklist.
// RevokeFamily, on logout - #402) invalidates every token ever derived from
// this login, not just the one currently held.
func (s *WebAuthnService) generateRefreshToken(user *domain.User, tenantID domain.TenantID, sid string) (string, error) {
	if s.cfg.JWT.RefreshDays <= 0 {
		// Refresh tokens disabled
		return "", nil
	}

	if tenantID == "" {
		tenantID = domain.DefaultTenantID
	}

	now := time.Now()
	jti := generateChallengeID()

	claims := jwt.MapClaims{
		"user_id":   user.UUID.String(),
		"tenant_id": string(tenantID),
		"type":      "refresh", // Mark as refresh token
		"iat":       now.Unix(),
		"nbf":       now.Unix(),
		"exp":       now.AddDate(0, 0, s.cfg.JWT.RefreshDays).Unix(), // Expires in RefreshDays
		"iss":       s.cfg.JWT.Issuer,
		"aud":       s.cfg.Server.RPID,
		"jti":       jti,
	}
	if sid != "" {
		claims["sid"] = sid
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(s.cfg.JWT.Secret))
}

// ErrInvalidRefreshToken indicates the refresh token is invalid or expired
var ErrInvalidRefreshToken = errors.New("invalid or expired refresh token")

// ErrRefreshDisabled indicates refresh tokens are turned off by config
// (JWT.RefreshDays <= 0). This is an expected, admin-controlled state, not
// a server malfunction - callers must map it to a non-5xx response rather
// than treating it like an unexpected internal error (Copilot review on
// #400: mounting the route unconditionally turned this config choice into
// a 500 response).
var ErrRefreshDisabled = errors.New("refresh tokens are disabled")

// RefreshTokenRequest contains the request for refreshing an access token
type RefreshTokenRequest struct {
	RefreshToken string `json:"refreshToken"`
}

// RefreshTokenResponse contains the new tokens
type RefreshTokenResponse struct {
	Token        string `json:"appToken"`
	RefreshToken string `json:"refreshToken,omitempty"`
}

// RefreshAccessToken exchanges a valid refresh token for a new access token.
//
// SECURITY: the presented refresh token is single-use, ENFORCED
// UNCONDITIONALLY whenever a TokenBlacklist is wired in via
// SetTokenBlacklist (which services.go always does) - deliberately not
// gated by TokenBlacklistConfig.Enabled, unlike Add/IsBlacklisted's general
// opt-in revocation feature. Without this, the "checked-in"/default
// configuration (blacklist disabled) would leave refresh tokens replayable
// indefinitely, every replay minting another full-lived access/refresh
// pair, despite this method appearing to enforce single-use - Copilot
// review on #400 ("wiring this object does not consume refresh tokens for
// standard configurations"). The check-and-consume step itself
// (TokenBlacklist.ConsumeOnce) is atomic under one lock, so two concurrent
// requests replaying the same refresh token cannot both win the race
// (Copilot review on #400, second round: "the check-and-consume sequence
// is not atomic"). Logout can now revoke this refresh token's whole family
// in one call via its "sid" claim (TokenBlacklist.RevokeFamily, checked
// below via IsFamilyRevoked) - closing #402, which tracked that Logout
// used to only ever blacklist the caller's current access token, leaving
// any refresh token issued alongside it fully valid until it naturally
// expired. Rotation still issues a new refresh token each call, exactly as
// before; single-use consumption only closes the reuse window on the
// token being replaced.
func (s *WebAuthnService) RefreshAccessToken(ctx context.Context, req *RefreshTokenRequest) (*RefreshTokenResponse, error) {
	if s.cfg.JWT.RefreshDays <= 0 {
		return nil, ErrRefreshDisabled
	}

	// Parse the refresh token
	token, err := jwt.Parse(req.RefreshToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, jwt.ErrSignatureInvalid
		}
		return []byte(s.cfg.JWT.Secret), nil
	})

	if err != nil || !token.Valid {
		return nil, ErrInvalidRefreshToken
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, ErrInvalidRefreshToken
	}

	// Verify this is a refresh token
	tokenType, _ := claims["type"].(string)
	if tokenType != "refresh" {
		return nil, ErrInvalidRefreshToken
	}

	// Extract user and tenant info
	userIDStr, ok := claims["user_id"].(string)
	if !ok {
		return nil, ErrInvalidRefreshToken
	}
	userID := domain.UserIDFromString(userIDStr)

	tenantIDStr, _ := claims["tenant_id"].(string)
	tenantID := domain.TenantID(tenantIDStr)
	if tenantID == "" {
		// Matches pkg/middleware.AuthMiddleware's own "no tenant_id claim ->
		// default tenant" backward-compatibility fallback for older tokens.
		tenantID = domain.DefaultTenantID
	}

	// Get the user (verify they still exist)
	user, err := s.store.Users().GetByID(ctx, userID)
	if err != nil {
		s.logger.Warn("Refresh token for non-existent user",
			zap.String("user_id", userIDStr),
		)
		return nil, ErrInvalidRefreshToken
	}

	// SID-AUTH-06: a refresh token issued before the wallet was revoked
	// must not mint new access tokens.
	srcIssuedAt := tokengate.IssuedAtFromClaims(claims)
	if err := s.refuseIfSourceCutOff(ctx, userID, srcIssuedAt); err != nil {
		return nil, err
	}

	// SECURITY: re-validate the tenant itself (exists and is enabled) before
	// rotating - not just the user's membership in it (below). Both
	// authenticated-request paths (pkg/middleware.AuthMiddleware,
	// TokenAuthMiddleware) already reject a request whose tenant no longer
	// exists or has been disabled; RefreshAccessToken didn't, so a stolen
	// refresh token for a since-disabled tenant could keep rotating
	// indefinitely and regain full access the moment that tenant was
	// re-enabled (Copilot review on #400, fifth round). Checked
	// unconditionally, including for the default tenant - unlike the
	// membership check below - since even the default tenant's own record
	// could be disabled.
	tenant, err := s.store.Tenants().GetByID(ctx, tenantID)
	if err != nil {
		s.logger.Warn("Refresh token for a nonexistent tenant",
			zap.String("user_id", userIDStr),
			zap.String("tenant_id", tenantIDStr),
		)
		return nil, ErrInvalidRefreshToken
	}
	if !tenant.Enabled {
		s.logger.Warn("Refresh token for a disabled tenant",
			zap.String("user_id", userIDStr),
			zap.String("tenant_id", tenantIDStr),
		)
		return nil, ErrInvalidRefreshToken
	}

	// SECURITY: re-validate tenant membership for non-default tenants
	// before rotating. FinishLogin derives tenantID fresh from the user's
	// CURRENT membership records (store.UserTenants().GetUserTenants) every
	// time someone logs in, so removing a user's tenant membership takes
	// effect at their very next login - but until now, RefreshAccessToken
	// simply trusted whatever tenant_id claim the presented refresh token
	// already carried, forever, with no per-refresh membership check (and
	// no route in this stack mounts TenantMembershipMiddleware either).
	// That let a removed user keep refreshing indefinitely instead of
	// losing access within one access-token lifetime, the whole point of
	// short-lived access tokens (Copilot review on #400, fourth round). The
	// default tenant is exempt, matching FinishLogin/GetUserTenants'
	// existing "no memberships recorded -> legacy default-tenant user"
	// fallback (domain.DefaultTenantID) elsewhere in this file.
	if tenantID != domain.DefaultTenantID {
		isMember, err := s.store.UserTenants().IsMember(ctx, userID, tenantID)
		if err != nil {
			return nil, fmt.Errorf("failed to verify tenant membership: %w", err)
		}
		if !isMember {
			s.logger.Warn("Refresh token for a tenant the user is no longer a member of",
				zap.String("user_id", userIDStr),
				zap.String("tenant_id", tenantIDStr),
			)
			return nil, ErrInvalidRefreshToken
		}
	}

	// sid is the refresh-token family/session id this token was minted
	// with (see generateToken/generateRefreshToken's doc comments) - absent
	// on a token minted before #402. SECURITY: reject outright if Logout
	// has since revoked this family (TokenBlacklist.RevokeFamily) - without
	// this, logging out never actually stopped a still-valid refresh token
	// issued alongside the logged-out access token (or any token from a
	// later rotation of it) from continuing to mint fresh access tokens
	// indefinitely (#402).
	sid, _ := claims["sid"].(string)
	if sid != "" && s.tokenBlacklist != nil && s.tokenBlacklist.IsFamilyRevoked(ctx, sid) {
		s.logger.Warn("Refresh token for a revoked family used",
			zap.String("user_id", userIDStr),
			zap.String("sid", sid),
		)
		return nil, ErrInvalidRefreshToken
	}

	// Atomically consume the refresh token's jti - see the doc comment
	// above. Deliberately placed here: AFTER every non-mutating validation
	// above (signature, type, user existence) has already succeeded, and
	// IMMEDIATELY BEFORE minting the replacement pair below. Consuming any
	// earlier - e.g. right after parsing the token - would irreversibly
	// burn a legitimate refresh token on a transient failure below it (a
	// storage hiccup on the user lookup, say), forcing a valid client to
	// re-authenticate from scratch instead of simply retrying (Copilot
	// review on #400, third round). This ordering doesn't reopen the
	// concurrency race ConsumeOnce's atomicity closes: it's still a single
	// atomic check-and-mark-used call, so of two requests racing on the
	// same refresh token, only the one that wins it proceeds to mint
	// tokens - the loser is rejected here regardless of timing, wherever
	// in the function this call sits.
	//
	// Both jti and exp are REQUIRED here (Copilot review on #400, fifth
	// round): every token this service actually issues
	// (generateRefreshToken) always sets both, so this only ever rejects a
	// malformed/hand-crafted token. Without this check, an omitted jti
	// would reach ConsumeOnce, which deliberately treats an empty jti as
	// always "first use" (see its own doc comment - meant for a
	// hypothetical jti-less token this service issued, not as a bypass),
	// letting such a token replay freely; and an omitted exp would fall
	// back to RefreshDays for the blacklist entry's OWN expiry while the
	// underlying JWT itself never expires, so once that blacklist entry
	// aged out the same non-expiring token would become usable again.
	jti, _ := claims["jti"].(string)
	expFloat, hasExp := claims["exp"].(float64)
	if jti == "" || !hasExp {
		s.logger.Warn("Refresh token missing required jti/exp claims")
		return nil, ErrInvalidRefreshToken
	}
	expiry := time.Unix(int64(expFloat), 0)

	if s.tokenBlacklist != nil {
		firstUse, err := s.tokenBlacklist.ConsumeOnce(ctx, jti, expiry)
		if err != nil {
			return nil, fmt.Errorf("failed to consume refresh token: %w", err)
		}
		if !firstUse {
			s.logger.Warn("Refresh token reuse detected", zap.String("jti", jti))
			return nil, ErrInvalidRefreshToken
		}
	}

	// Carry the family forward unchanged across rotation, so a later Logout
	// can still revoke it (#402). A token minted before #402 carries no sid
	// at all; start tracking a family for it from this rotation onward
	// rather than leaving it (and every further rotation downstream of it)
	// permanently outside Logout's reach.
	if sid == "" && s.cfg.JWT.RefreshDays > 0 {
		sid = generateChallengeID()
	}

	// Generate the new access token and the rotated refresh token, checked
	// against the user's token cut-off after minting (SID-AUTH-06).
	accessToken, newRefreshToken, err := s.mintTokens(ctx, user, tenantID, sid, nil, ErrInvalidRefreshToken)
	if err != nil {
		return nil, err
	}
	// The minted tokens are necessarily fresh, so only the refresh token
	// behind them can still be judged: a revocation that landed while this
	// request ran must not be outrun by the new timestamps.
	if err := s.refuseIfSourceCutOff(ctx, userID, srcIssuedAt); err != nil {
		return nil, err
	}

	s.logger.Info("Access token refreshed",
		zap.String("user_id", userIDStr),
		zap.String("tenant_id", tenantIDStr),
	)

	return &RefreshTokenResponse{
		Token:        accessToken,
		RefreshToken: newRefreshToken,
	}, nil
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
	// Token-authenticated, and it stores a challenge and hands out creation
	// options: a token the user's cut-off already predates gets neither.
	if err := refuseIfCutOff(ctx, user); err != nil {
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
			Attestation: s.getAttestationPreference(),
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
	if err := refuseIfCutOff(ctx, user); err != nil {
		return nil, err
	}

	// Atomically consume the challenge, constrained to this authenticated
	// caller's own userID as part of the SAME atomic find-and-delete (not a
	// separate check performed after consuming). This path is unlike
	// FinishRegistration/FinishLogin: the caller here is already
	// authenticated, and the challenge additionally carries an owning
	// userID that must match. Plain ConsumeByID would let a caller who
	// somehow obtains another user's add-credential challenge ID
	// permanently burn that user's pending ceremony — it would consume
	// (delete) the real owner's challenge before the ownership mismatch was
	// ever checked. ConsumeByIDForUser folds the ownership check into the
	// atomic filter itself, so a mismatched caller gets ErrNotFound without
	// ever touching the real owner's challenge.
	challenge, err := s.store.Challenges().ConsumeByIDForUser(ctx, req.ChallengeID, userID.String())
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, ErrChallengeNotFound
		}
		return nil, fmt.Errorf("failed to consume challenge: %w", err)
	}

	if challenge.IsExpired() {
		return nil, ErrChallengeExpired
	}

	if challenge.Action != "add_credential" {
		return nil, errors.New("invalid challenge action")
	}

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
		// Extensions must record what was sent to the client in BeginAddCredential
		Extensions: protocol.SessionExtensions{
			Requested: []string{protocol.ExtensionCredProps, protocol.ExtensionPRF},
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

	// Validate AAGUID if validator is configured
	if s.aaguidValidator != nil {
		result := s.aaguidValidator.Validate(credential.Authenticator.AAGUID)
		if !result.Allowed {
			s.logger.Warn("Add credential blocked by AAGUID policy",
				zap.String("aaguid", result.AAGUID),
				zap.String("reason", result.Reason()),
				zap.String("user_id", userID.String()),
			)
			return nil, ErrAAGUIDBlacklisted
		}
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

func sha256Hex(data []byte) string {
	if len(data) == 0 {
		return ""
	}

	h := sha256.Sum256(data)
	return fmt.Sprintf("%x", h[:])
}

func attestationSignatureInputHash(authData, clientDataJSON []byte) string {
	if len(authData) == 0 || len(clientDataJSON) == 0 {
		return ""
	}

	clientHash := sha256.Sum256(clientDataJSON)
	data := make([]byte, 0, len(authData)+len(clientHash))
	data = append(data, authData...)
	data = append(data, clientHash[:]...)

	return sha256Hex(data)
}

func attestationSignatureDiagnostics(att protocol.AttestationObject) (sigLen int, sigHash string, normalizedChanged bool, normalizeErr string) {
	rawSig, ok := att.AttStatement["sig"].([]byte)
	if !ok || len(rawSig) == 0 {
		return 0, "", false, "signature-not-present"
	}

	sigLen = len(rawSig)
	sigHash = sha256Hex(rawSig)

	normalized, err := cryptoutil.NormalizeECDSASignature(rawSig)
	if err != nil {
		return sigLen, sigHash, false, err.Error()
	}

	return sigLen, sigHash, !bytes.Equal(rawSig, normalized), ""
}

func assertionSignatureDiagnostics(rawSig []byte) (sigLen int, sigHash string, normalizedChanged bool, normalizeErr string) {
	if len(rawSig) == 0 {
		return 0, "", false, "signature-not-present"
	}

	sigLen = len(rawSig)
	sigHash = sha256Hex(rawSig)

	normalized, err := cryptoutil.NormalizeECDSASignature(rawSig)
	if err != nil {
		return sigLen, sigHash, false, err.Error()
	}

	return sigLen, sigHash, !bytes.Equal(rawSig, normalized), ""
}

func attestationLeafCertDiagnostics(att protocol.AttestationObject) (leafCertHash string, leafCertLen int) {
	x5c, ok := att.AttStatement["x5c"].([]any)
	if !ok || len(x5c) == 0 {
		return "", 0
	}

	leaf, ok := x5c[0].([]byte)
	if !ok || len(leaf) == 0 {
		return "", 0
	}

	return sha256Hex(leaf), len(leaf)
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

// refuseIfSourceCutOff rejects a refresh token that does not survive the
// user's current SID-AUTH-06 cut-off. Called before and after minting, so a
// revocation landing mid-request cannot be beaten by the freshly minted
// timestamps.
//
// The source token is judged, not the minted ones: the access and refresh
// tokens this mints carry fresh iats, so they would sail past the cut-off on
// their own. Judging the token that asked is what stops a pre-cut-off refresh
// token laundering itself into unrestricted ones. Refreshing after a
// lifecycle change requires a new login.
func (s *WebAuthnService) refuseIfSourceCutOff(ctx context.Context, userID domain.UserID, issuedAt time.Time) error {
	cutoff, err := s.store.Users().GetAuthCutoff(ctx, userID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return ErrInvalidRefreshToken
		}
		return fmt.Errorf("check token cut-off: %w", err)
	}
	if !tokengate.IssuedBeforeCutoff(issuedAt, cutoff) {
		return nil
	}
	s.logger.Warn("Refresh token predates the authorization cut-off", zap.String("user_id", userID.String()))
	return ErrInvalidRefreshToken
}

// mintTokens issues the access token and, when enabled, the refresh token,
// then checks both against the user's token cut-off (SID-AUTH-06) by taking
// the decision on the earliest of them, and runs recheck (when given) over
// the post-mint state either way. A suspension or revocation that lands after
// the login gate ran - during the sign-count save, the OIDC checks, or
// between the two mints - must not hand out a token that the token gate would
// then refuse, nor one it would accept for an instance that is no longer
// active.
//
// The comparison is at whole seconds (tokengate.IssuedBeforeCutoff), so a
// token minted in the same second as a cut-off is refused too. When that is
// the only problem (recheck passes) the tokens are minted again in the next
// second, so a second device logging in right after revoking another is
// not turned away. If the cut-off is older, recheck (when given) supplies
// the precise lifecycle refusal; otherwise the request fails with refusal
// and the client simply tries again.
func (s *WebAuthnService) mintTokens(ctx context.Context, user *domain.User, tenantID domain.TenantID, sid string, recheck func() error, refusal error) (string, string, error) {
	for attempt := 0; ; attempt++ {
		access, err := s.generateToken(user, tenantID, sid)
		if err != nil {
			return "", "", fmt.Errorf("failed to generate token: %w", err)
		}
		refresh, _ := s.generateRefreshToken(user, tenantID, sid) // refresh is optional
		cutoff, err := s.store.Users().GetAuthCutoff(ctx, user.UUID)
		if err != nil {
			return "", "", fmt.Errorf("re-check user after token issuance: %w", err)
		}
		// Both minted tokens have to survive the cut-off, so the decision is
		// taken on the earliest of them. The access token is minted first, so
		// a cut-off landing between the two mints - or on the second boundary
		// they straddle - leaves it at or before the cut-off while the
		// refresh token is past it; gating on the refresh token alone would
		// hand out an access token the token gate refuses on first use. An
		// unreadable iat parses as the zero time and is refused here too.
		earliest := tokengate.IssuedAt(access)
		if refresh != "" {
			if r := tokengate.IssuedAt(refresh); r.Before(earliest) {
				earliest = r
			}
		}
		if !tokengate.IssuedBeforeCutoff(earliest, cutoff) {
			// Clearing the cut-off is not enough on its own. ChangeStatus
			// records the cut-off before it persists the new status, so a
			// login that passed its lifecycle check earlier in the flow
			// (WebAuthn verification, sign-count save, OIDC checks) mints a
			// token whose fresh iat is past that cut-off while the instance
			// is being revoked. Running the caller's check once more, on
			// the state as it is after the mint, cuts the exposure down to
			// the gap between those two writes (go-wallet-backend#330).
			if recheck != nil {
				if err := recheck(); err != nil {
					return "", "", err
				}
			}
			return access, refresh, nil
		}
		if recheck != nil {
			if err := recheck(); err != nil {
				return "", "", err
			}
		}
		if attempt == 0 && earliest.Unix() == cutoff.Unix() {
			// Same second as the cut-off: wait for the next one and mint again.
			time.Sleep(time.Until(cutoff.Truncate(time.Second).Add(time.Second)))
			continue
		}
		return "", "", fmt.Errorf("%w: authorization changed during login, please log in again", refusal)
	}
}

// checkWalletLifecycle enforces wallet instance status at login (SID-AUTH-06).
//
// Two rules. The instance linked to this passkey (WalletInstance.CredentialID,
// recorded when the wallet supplies credential_id at WIA generation) must not
// be revoked. And if the user has instances at all, at least one must be
// non-revoked: when every instance is revoked the wallet has been deactivated
// and WalletLifecycleService already erased its data, so every passkey of the
// user is refused until a new enrollment. A revoked instance that is not
// linked to this passkey does not block login - the user must be able to log
// in from another device. A user with no instances yet is unaffected.
//
// This gate is load-bearing, not a second copy of the WIA gate, and it is
// worth saying why before someone removes it as redundant. It is the only
// check in the backend that knows which wallet instance is acting: the
// instance is identified by its key, and after login nothing carries that
// identity - an access token carries the user, the tenant, an iat and a jti,
// and an engine session carries the user, the tenant and the handshake
// token's iat. The WIA gate refuses a blocked instance an attestation, which
// external parties that require client attestation will act on, but this
// backend never requires a WIA of its own: a token is enough to open a
// WebSocket and start an issuance or presentation flow, and no flow checks
// instance status. So a blocked instance that could log in could still issue
// and present here.
//
// ARF v3 would have a revoked Wallet Unit keep reading what it holds and
// lose only issuance and presentation, which would mean refusing at login
// only for a deactivated wallet. Narrowing this gate to that is the right
// shape, and it needs the instance identity to survive login first - the
// same prerequisite as scoping the token cut-off (see
// WalletLifecycleService.cutOffTokens) - so that issuance and presentation
// can be refused where they happen. Until then this is where a blocked
// instance is stopped, and the cost is the one the ARF would not pay: the
// user cannot log in to look at what that device holds.
func (s *WebAuthnService) checkWalletLifecycle(ctx context.Context, tenantID domain.TenantID, userID domain.UserID, credentialID string) error {
	instances, err := s.store.WalletInstances().GetByUser(ctx, tenantID, userID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil
		}
		return fmt.Errorf("check wallet lifecycle: %w", err)
	}
	if len(instances) == 0 {
		return nil
	}
	// Decide deactivation first: when nothing live remains, the answer is
	// "wallet deactivated" for every passkey, including one linked to a
	// revoked instance - telling that user "use another device" would be
	// wrong, since no device can log in any more.
	//
	// The store does not enforce that a passkey is linked to at most one
	// instance, so every instance linked to this passkey is considered and
	// the most restrictive status wins: a passkey that is also linked to a
	// revoked instance is refused even if an active duplicate exists, rather
	// than letting store ordering decide.
	anyLive := false
	linkedRevoked := false
	var unknown *domain.WalletInstance
	for _, inst := range instances {
		if inst.Status.IsLive() {
			anyLive = true
		} else if !inst.Status.IsKnownNonLive() {
			unknown = inst
			continue
		}
		if inst.CredentialID == "" || inst.CredentialID != credentialID {
			continue
		}
		// Only a status that positively means "cannot be used" counts.
		if inst.Status.IsKnownNonLive() {
			linkedRevoked = true
		}
	}
	if unknown != nil {
		// An unrecognized status is not evidence that the wallet is
		// deactivated or that this passkey is revoked, and it is not
		// evidence that it is fine either: refuse the login whichever
		// sibling is live, without claiming a lifecycle state nobody
		// established.
		return fmt.Errorf("check wallet lifecycle: instance %s has unrecognized status %q", unknown.ID, unknown.Status)
	}
	if !anyLive {
		return ErrWalletDeactivated
	}
	if linkedRevoked {
		return ErrWalletInstanceRevoked
	}
	return nil
}
