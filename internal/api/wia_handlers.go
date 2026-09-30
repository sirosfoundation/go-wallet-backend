package api

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/service"
)

// WIAChallenge handles POST /wallet-provider/wia/challenge
// Returns a single-use nonce for WIA-PoP construction.
func (h *Handlers) WIAChallenge(c *gin.Context) {
	if h.services.WIA == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error":   "WIA_NOT_SUPPORTED",
			"message": "Wallet Instance Attestation is not configured",
		})
		return
	}

	tenantID, _ := h.getTenantID(c)
	challenge, expiresAt, err := h.services.WIA.CreateChallenge(c.Request.Context(), tenantID)
	if err != nil {
		if errors.Is(err, service.ErrWIAChallengeCapacityMax) {
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error":   "RATE_LIMIT_EXCEEDED",
				"message": "Too many pending challenges, please retry later",
			})
			return
		}
		h.logger.Error("Failed to create WIA challenge", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "CHALLENGE_CREATION_FAILED",
			"message": "Failed to create challenge",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"challenge":  challenge,
		"expires_at": expiresAt.Unix(),
	})
}

// WIAGenerateRequest is the request body for POST /wallet-provider/wia/generate
type WIAGenerateRequest struct {
	// Pop is the WIA-PoP JWT (typ: oauth-client-attestation-pop+jwt)
	Pop string `json:"pop" binding:"required"`
	// Challenge is the nonce from the challenge endpoint
	Challenge string `json:"challenge" binding:"required"`
	// ClientID is the OAuth client_id this wallet instance uses in OID4VCI/OID4VP
	// flows (defaults to its redirect_uri, per OID4VCI's unregistered-client
	// convention - see OID4VCIHandler.clientID). Embedded as the WIA JWT's
	// `sub` claim: draft-ietf-oauth-attestation-based-client-auth-10 requires
	// "the sub claim MUST specify client_id value of the OAuth Client".
	ClientID string `json:"client_id,omitempty"`
	// NativeAttestation is optional platform attestation evidence (App Attest / Play Integrity)
	NativeAttestation *service.NativeAttestationRequest `json:"native_attestation,omitempty"`
	// CredentialID is the base64url WebAuthn credential id of the passkey this
	// wallet instance logs in with, so that revoking the instance also
	// refuses login with that passkey (SID-AUTH-06). Optional.
	CredentialID string `json:"credential_id,omitempty"`
}

// WIAGenerate handles POST /wallet-provider/wia/generate
// Validates the WIA-PoP and returns a signed WIA JWT.
func (h *Handlers) WIAGenerate(c *gin.Context) {
	if h.services.WIA == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error":   "WIA_NOT_SUPPORTED",
			"message": "Wallet Instance Attestation is not configured",
		})
		return
	}

	var req WIAGenerateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "INVALID_REQUEST",
			"message": "Request body must contain 'pop' and 'challenge' fields",
		})
		return
	}

	tenantID, _ := h.getTenantID(c)
	var userID *domain.UserID
	if uid := c.GetString("user_id"); uid != "" {
		id := domain.UserIDFromString(uid)
		userID = &id
	}
	wia, err := h.services.WIA.GenerateWIA(c.Request.Context(), tenantID, userID, &service.WIARequest{
		Pop:               req.Pop,
		Challenge:         req.Challenge,
		ClientID:          req.ClientID,
		NativeAttestation: req.NativeAttestation,
		CredentialID:      req.CredentialID,
	})
	if err != nil {
		status, code, message := wiaFailure(err)
		switch code {
		case "POP_INVALID":
			h.logger.Debug("WIA-PoP validation failed", zap.Error(err))
		case "WIA_GENERATION_FAILED":
			h.logger.Error("Failed to generate WIA", zap.Error(err))
		default:
			h.logger.Warn("WIA generation refused", zap.String("code", code), zap.Error(err))
		}
		c.JSON(status, gin.H{"error": code, "message": message})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"wallet_instance_attestation": wia,
	})
}

// wiaFailure maps an error from WIAService.GenerateWIA to the HTTP status and
// the stable error code and message the client sees. Anything it does not
// recognise is a 500 WIA_GENERATION_FAILED.
func wiaFailure(err error) (status int, code, message string) {
	switch {
	case errors.Is(err, service.ErrWIAChallengeExpired):
		return http.StatusBadRequest, "CHALLENGE_INVALID", "Challenge is invalid"
	case errors.Is(err, service.ErrWIACredentialNotOwned):
		return http.StatusForbidden, "CREDENTIAL_NOT_OWNED", "credential_id must be one of your own registered passkeys"
	case errors.Is(err, service.ErrWIAPopInvalid):
		return http.StatusBadRequest, "POP_INVALID", "WIA-PoP validation failed"
	case errors.Is(err, service.ErrWIAUnknownUser):
		return http.StatusForbidden, "UNKNOWN_USER", "This account no longer exists"
	case errors.Is(err, service.ErrWIAInstanceDeactivated):
		return http.StatusForbidden, "INSTANCE_DEACTIVATED", "This wallet instance is not active"
	case errors.Is(err, service.ErrWIAInstanceNotOwned):
		return http.StatusForbidden, "INSTANCE_NOT_OWNED", "This wallet instance is registered to another tenant or user"
	default:
		return http.StatusInternalServerError, "WIA_GENERATION_FAILED", "Failed to generate Wallet Instance Attestation"
	}
}
