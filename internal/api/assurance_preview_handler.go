package api

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/service"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
)

// maxPreviewAttestationBytes bounds the decoded FIDO2 attestation object a
// preview accepts. Real CTAP2 attestation objects are a few KiB.
const maxPreviewAttestationBytes = 32 * 1024

// AssurancePreviewRequest is the body of POST /wallet-provider/assurance-preview.
type AssurancePreviewRequest struct {
	// WalletInstanceID optionally names the caller's own wallet instance,
	// whose verified platform attestation then counts as evidence.
	WalletInstanceID string `json:"wallet_instance_id,omitempty"`
	// JWKS are the keys the wallet would attest. Optional.
	JWKS []map[string]interface{} `json:"jwks,omitempty"`
	// SecurityProperties are the claimed fields, as in a key attestation
	// request. Claims are never treated as verified.
	SecurityProperties *SecurityPropertiesRequest `json:"security_properties,omitempty"`
	// FIDO2Attestation is the attestation the wallet would submit to
	// /fido2-attestation/register. It is verified but not stored.
	FIDO2Attestation *struct {
		// AttestationObject is the base64url (unpadded) CTAP2 attestation object.
		AttestationObject string `json:"attestation_object"`
		// ClientDataHash is the base64url (unpadded) 32-byte hash it covers.
		ClientDataHash string `json:"client_data_hash"`
	} `json:"fido2_attestation,omitempty"`
}

// AssurancePreview handles POST /wallet-provider/assurance-preview. It tells a
// wallet what its Key Attestation and Wallet Instance Attestation would carry,
// by running the real verifier and assessor in dry-run mode: nothing is
// stored and nothing is issued. No rules are returned.
func (h *Handlers) AssurancePreview(c *gin.Context) {
	if h.services.WalletProvider == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error": "ASSURANCE_PREVIEW_NOT_SUPPORTED", "message": "wallet provider is not configured",
		})
		return
	}
	var req AssurancePreviewRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "INVALID_REQUEST", "message": "Invalid request body"})
		return
	}
	if len(req.JWKS) > service.MaxJWKSPerRequest {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "INVALID_JWKS",
			"message": fmt.Sprintf("too many JWKs: %d exceeds maximum of %d", len(req.JWKS), service.MaxJWKSPerRequest),
		})
		return
	}
	for i, j := range req.JWKS {
		if j == nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "INVALID_JWKS", "message": fmt.Sprintf("jwks[%d] is null", i)})
			return
		}
	}

	svcReq := &service.AssurancePreviewRequest{
		WalletInstanceID:   req.WalletInstanceID,
		JWKS:               req.JWKS,
		SecurityProperties: req.SecurityProperties.toService(),
	}
	if f := req.FIDO2Attestation; f != nil {
		obj, err := base64.RawURLEncoding.DecodeString(f.AttestationObject)
		if err != nil || len(obj) == 0 || len(obj) > maxPreviewAttestationBytes {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "INVALID_ATTESTATION_OBJECT", "message": "attestation_object must be base64url (unpadded) and at most 32 KiB",
			})
			return
		}
		hash, err := base64.RawURLEncoding.DecodeString(f.ClientDataHash)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "INVALID_CLIENT_DATA_HASH", "message": "client_data_hash must be base64url (unpadded)",
			})
			return
		}
		svcReq.FIDO2 = &service.FIDO2AttestationRequest{AttestationObject: obj, ClientDataHash: hash}
	}

	// Bind the preview to the authenticated caller: only the caller's own
	// wallet instance can lend platform evidence.
	tenantID, _ := h.getTenantID(c)
	callerUser, _ := contextUserID(c)
	ctx := service.WithKeyAttestationCaller(service.WithKeyAttestationTenant(c.Request.Context(), tenantID), service.KeyAttestationCaller{
		TenantID: tenantID,
		UserID:   callerUser,
	})

	out, err := h.services.WalletProvider.PreviewAssurance(ctx, svcReq)
	if err != nil {
		switch {
		case errors.Is(err, storage.ErrNotFound):
			c.JSON(http.StatusNotFound, gin.H{"error": "WALLET_INSTANCE_NOT_FOUND", "message": "wallet instance not found"})
		case errors.Is(err, service.ErrFIDO2AttestationInvalid):
			h.logger.Debug("assurance preview: FIDO2 attestation verification failed", zap.Error(err))
			c.JSON(http.StatusBadRequest, gin.H{"error": "ATTESTATION_INVALID", "message": "FIDO2 attestation verification failed"})
		case errors.Is(err, service.ErrAssuranceUnavailable):
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "ASSURANCE_UNAVAILABLE", "message": "The assurance policy is enabled but not loaded"})
		default:
			h.logger.Error("assurance preview failed", zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "ASSURANCE_PREVIEW_FAILED", "message": "Failed to compute the assurance preview"})
		}
		return
	}
	c.JSON(http.StatusOK, out)
}
