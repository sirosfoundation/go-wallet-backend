package api

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

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

	challenge, expiresAt, err := h.services.WIA.CreateChallenge(c.Request.Context())
	if err != nil {
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

	wia, err := h.services.WIA.GenerateWIA(c.Request.Context(), &service.WIARequest{
		Pop:       req.Pop,
		Challenge: req.Challenge,
	})
	if err != nil {
		switch {
		case errors.Is(err, service.ErrWIAChallengeExpired):
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "CHALLENGE_EXPIRED",
				"message": "Challenge is expired or has already been used",
			})
		case errors.Is(err, service.ErrWIAPopInvalid):
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "POP_INVALID",
				"message": err.Error(),
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
