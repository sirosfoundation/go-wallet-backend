package service

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
)

// ChallengeActionDeleteAccount is the Action of a challenge minted for the
// account-deletion step-up.
const ChallengeActionDeleteAccount = "delete-account"

// DeleteAccountChallengeTTL is how long a step-up assertion stays valid.
const DeleteAccountChallengeTTL = 120 * time.Second

// deleteAccountChallengeGrace is how long an expired challenge is kept so that
// a late assertion is answered as expired rather than unknown.
const deleteAccountChallengeGrace = 10 * time.Minute

// ErrStepUpFailed refuses a step-up assertion that is missing, unknown,
// already used, minted for someone or something else, or does not verify.
var ErrStepUpFailed = errors.New("step-up assertion failed")

// BeginStepUpResponse carries WebAuthn assertion options restricted to the
// caller's own credentials.
type BeginStepUpResponse struct {
	ChallengeID string                            `json:"challengeId"`
	PublicKey   PublicKeyCredentialRequestOptions `json:"publicKey"`
}

// BeginDeleteAccountStepUp mints an assertion challenge for userID that can
// authorise one account deletion.
func (s *WebAuthnService) BeginDeleteAccountStepUp(ctx context.Context, userID domain.UserID) (*BeginStepUpResponse, error) {
	user, err := s.store.Users().GetByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	if err := refuseIfCutOff(ctx, user); err != nil {
		return nil, err
	}
	if len(user.WebauthnCredentials) == 0 {
		return nil, ErrCredentialNotFound
	}

	waUser := &WebAuthnUser{user: user}
	creds := waUser.WebAuthnCredentials()
	allowed := make([]protocol.CredentialDescriptor, 0, len(creds))
	descriptors := make([]PublicKeyCredentialDescriptor, 0, len(creds))
	for _, c := range creds {
		allowed = append(allowed, c.Descriptor())
		descriptors = append(descriptors, PublicKeyCredentialDescriptor{
			Type:       "public-key",
			ID:         c.ID,
			Transports: c.Transport,
		})
	}

	_, session, err := s.webauthn.BeginLogin(waUser,
		webauthn.WithUserVerification(protocol.VerificationRequired),
		webauthn.WithAllowedCredentials(allowed),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to begin step-up: %w", err)
	}
	challengeBytes, err := base64.RawURLEncoding.DecodeString(session.Challenge)
	if err != nil {
		return nil, fmt.Errorf("failed to decode challenge: %w", err)
	}

	challengeID := generateChallengeID()
	validUntil := time.Now().Add(DeleteAccountChallengeTTL)
	if err := s.store.Challenges().Create(ctx, &domain.WebauthnChallenge{
		ID:         challengeID,
		UserID:     userID.String(),
		Challenge:  session.Challenge,
		Action:     ChallengeActionDeleteAccount,
		ValidUntil: validUntil,
		ExpiresAt:  validUntil.Add(deleteAccountChallengeGrace),
	}); err != nil {
		return nil, fmt.Errorf("failed to store challenge: %w", err)
	}

	return &BeginStepUpResponse{
		ChallengeID: challengeID,
		PublicKey: PublicKeyCredentialRequestOptions{
			RPId:             s.cfg.Server.RPID,
			Challenge:        challengeBytes,
			AllowCredentials: descriptors,
			UserVerification: protocol.VerificationRequired,
		},
	}, nil
}

// VerifyDeleteAccountStepUp consumes the challenge and verifies the assertion
// against userID's own credentials. It mints no session or token.
//
// The challenge is consumed only if it belongs to userID (the ownership test is
// part of the atomic consume, so another user's challenge is neither accepted
// nor burned), is unexpired, and was minted for ChallengeActionDeleteAccount.
// The credential is then looked up in the caller's own credential list and
// listed as the only allowed set, so an assertion from any other user's
// credential cannot pass; unlike FinishLogin, the user is never derived from
// the assertion's userHandle. Returns ErrChallengeExpired, ErrStepUpFailed,
// or an error for a storage failure.
func (s *WebAuthnService) VerifyDeleteAccountStepUp(ctx context.Context, userID domain.UserID, challengeID string, credential json.RawMessage) error {
	if challengeID == "" || len(credential) == 0 {
		return ErrStepUpFailed
	}
	challenge, err := s.store.Challenges().ConsumeByIDForUser(ctx, challengeID, userID.String())
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return ErrStepUpFailed
		}
		return fmt.Errorf("failed to consume challenge: %w", err)
	}
	if challenge.IsExpired() {
		return ErrChallengeExpired
	}
	if challenge.Action != ChallengeActionDeleteAccount {
		return ErrStepUpFailed
	}

	user, err := s.store.Users().GetByID(ctx, userID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return ErrStepUpFailed
		}
		return fmt.Errorf("failed to load user: %w", err)
	}

	parsed, err := protocol.ParseCredentialRequestResponseBody(newCredentialReader(credential))
	if err != nil {
		return ErrStepUpFailed
	}

	// The handle the authenticator returns is the one stored at registration
	// (tenant-scoped or not); it must name the caller.
	handle := userID.AsUserHandle()
	if h := parsed.Response.UserHandle; len(h) > 0 {
		if !userHandleNames(h, userID) {
			return ErrStepUpFailed
		}
		handle = h
	}
	waUser := &TenantWebAuthnUser{user: user, userHandle: handle}
	creds := waUser.WebAuthnCredentials()
	allowed := make([][]byte, 0, len(creds))
	for _, c := range creds {
		allowed = append(allowed, c.ID)
	}

	verified, err := s.webauthn.ValidateLogin(waUser, webauthn.SessionData{
		Challenge:            challenge.Challenge,
		RelyingPartyID:       s.cfg.Server.RPID,
		UserID:               handle,
		AllowedCredentialIDs: allowed,
		UserVerification:     protocol.VerificationRequired,
	}, parsed)
	if err != nil {
		s.logger.Warn("Step-up assertion did not verify", zap.Error(err))
		return ErrStepUpFailed
	}

	credID := base64.RawURLEncoding.EncodeToString(verified.ID)
	tenantID := domain.DefaultTenantID
	for _, c := range user.WebauthnCredentials {
		if c.ID == credID && c.TenantID != "" {
			tenantID = domain.TenantID(c.TenantID) //nolint:unconvert
		}
	}
	// Like login, a clone warning does not refuse the assertion.
	s.recordAuthenticatorUse(ctx, userID, tenantID, credID, verified.Authenticator.SignCount, verified.Authenticator.CloneWarning)
	return nil
}

// userHandleNames reports whether a stored user handle (v1 binary, legacy
// "tenant:user" or the bare user id) identifies userID.
func userHandleNames(handle []byte, userID domain.UserID) bool {
	if uid, err := domain.UserIDFromHandle(handle); err == nil && uid == userID {
		return true
	}
	return domain.UserIDFromUserHandle(handle) == userID
}
