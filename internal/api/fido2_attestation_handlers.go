package api

import (
	"encoding/base64"
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/service"
)

// FIDO2AttestationRegisterRequest is the request body for
// POST /wallet-provider/fido2-attestation/register.
type FIDO2AttestationRegisterRequest struct {
	// WalletInstanceID is the JWK Thumbprint of the instance the FIDO2 key
	// belongs to.
	WalletInstanceID string `json:"wallet_instance_id" binding:"required"`
	// AttestationObject is the base64url (unpadded) raw CTAP2 makeCredential
	// attestation object (see siros-wscd-manager's AttestationChain.certificates[0]).
	AttestationObject string `json:"attestation_object" binding:"required"`
	// ClientDataHash is the base64url (unpadded) 32-byte hash the
	// attestation signature was computed over (AttestationChain.client_data_hash).
	ClientDataHash string `json:"client_data_hash" binding:"required"`
}

// FIDO2AttestationRegister handles POST /wallet-provider/fido2-attestation/register
// Verifies a FIDO2/CTAP2 hardware-key attestation object once, at
// key-registration time, and durably marks the wallet instance as
// hardware-key-attested on success (see FIDO2AttestationService).
func (h *Handlers) FIDO2AttestationRegister(c *gin.Context) {
	if h.services.FIDO2Attestation == nil || !h.services.FIDO2Attestation.IsEnabled() {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error":   "FIDO2_ATTESTATION_NOT_SUPPORTED",
			"message": "FIDO2 hardware-key attestation is not configured",
		})
		return
	}

	var req FIDO2AttestationRegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "INVALID_REQUEST",
			"message": "Request body must contain 'wallet_instance_id', 'attestation_object', and 'client_data_hash'",
		})
		return
	}

	attestationObject, err := base64.RawURLEncoding.DecodeString(req.AttestationObject)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "INVALID_ATTESTATION_OBJECT",
			"message": "attestation_object must be base64url (unpadded)",
		})
		return
	}
	clientDataHash, err := base64.RawURLEncoding.DecodeString(req.ClientDataHash)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "INVALID_CLIENT_DATA_HASH",
			"message": "client_data_hash must be base64url (unpadded)",
		})
		return
	}

	err = h.services.FIDO2Attestation.Verify(c.Request.Context(), &service.FIDO2AttestationRequest{
		WalletInstanceID:  req.WalletInstanceID,
		AttestationObject: attestationObject,
		ClientDataHash:    clientDataHash,
	})
	if err != nil {
		switch {
		case errors.Is(err, service.ErrFIDO2AttestationDisabled):
			c.JSON(http.StatusServiceUnavailable, gin.H{
				"error":   "FIDO2_ATTESTATION_NOT_SUPPORTED",
				"message": "FIDO2 hardware-key attestation is not configured",
			})
		case errors.Is(err, service.ErrFIDO2AttestationInvalid):
			h.logger.Debug("FIDO2 attestation verification failed", zap.Error(err))
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "ATTESTATION_INVALID",
				"message": "FIDO2 attestation verification failed",
			})
		default:
			h.logger.Error("Failed to verify FIDO2 attestation", zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":   "ATTESTATION_VERIFICATION_FAILED",
				"message": "Failed to verify FIDO2 attestation",
			})
		}
		return
	}

	c.JSON(http.StatusOK, gin.H{"verified": true})
}
