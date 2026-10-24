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
	// KeyAttestation is optional evidence about the instance (PoP) key:
	// {"type": "android_key" | "app_attest_assertion", ...}. See
	// service.KeyAttestation.
	KeyAttestation *service.KeyAttestation `json:"key_attestation,omitempty"`
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
		KeyAttestation:    req.KeyAttestation,
	})
	if err != nil {
		switch {
		case errors.Is(err, service.ErrWIAChallengeExpired):
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "CHALLENGE_INVALID",
				"message": "Challenge is invalid",
			})
		case errors.Is(err, service.ErrWIAPopInvalid):
			h.logger.Debug("WIA-PoP validation failed", zap.Error(err))
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "POP_INVALID",
				"message": "WIA-PoP validation failed",
			})
		case errors.Is(err, service.ErrWIAKeyAttestationTypeUnsupported):
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "KEY_ATTESTATION_TYPE_UNSUPPORTED",
				"message": "The key_attestation type is not supported",
			})
		case errors.Is(err, service.ErrWIAKeyAttestationInvalid):
			h.logger.Debug("key attestation rejected", zap.Error(err))
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "KEY_ATTESTATION_INVALID",
				"message": "The key_attestation evidence is invalid",
			})
		case errors.Is(err, service.ErrWIAKeyAttestationUnavailable):
			h.logger.Warn("key attestation cannot be verified", zap.Error(err))
			c.JSON(http.StatusServiceUnavailable, gin.H{
				"error":   "KEY_ATTESTATION_UNAVAILABLE",
				"message": "The key_attestation evidence cannot be verified right now, retry later",
			})
		case errors.Is(err, service.ErrWIAInstanceDeactivated):
			h.logger.Warn("WIA generation refused for deactivated instance", zap.Error(err))
			c.JSON(http.StatusForbidden, gin.H{
				"error":   "INSTANCE_DEACTIVATED",
				"message": "This wallet instance has been suspended or revoked",
			})
		case errors.Is(err, service.ErrWIARefusedByPolicy):
			h.logger.Warn("WIA refused by assurance policy", zap.Error(err))
			c.JSON(http.StatusForbidden, gin.H{
				"error":   "WIA_REFUSED_BY_POLICY",
				"message": "The wallet provider's assurance policy does not permit a Wallet Instance Attestation for this request",
			})
		case errors.Is(err, service.ErrAssuranceUnavailable):
			h.logger.Error("WIA assurance policy unavailable", zap.Error(err))
			c.JSON(http.StatusServiceUnavailable, gin.H{
				"error":   "ASSURANCE_UNAVAILABLE",
				"message": "The assurance policy is enabled but not loaded",
			})
		default:
			h.logger.Error("Failed to generate WIA", zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":   "WIA_GENERATION_FAILED",
				"message": "Failed to generate Wallet Instance Attestation",
			})
		}
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"wallet_instance_attestation": wia,
	})
}
