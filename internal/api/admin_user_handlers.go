package api

import (
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
)

// UserDetailResponse contains user information visible to admin.
// Only non-PII fields are exposed: UUID (opaque), did:key (public key), passkeys.
type UserDetailResponse struct {
	UUID       string        `json:"uuid"`
	DID        string        `json:"did,omitempty"`
	WalletType string        `json:"wallet_type"`
	Passkeys   []PasskeyInfo `json:"passkeys"`
	CreatedAt  time.Time     `json:"created_at"`
	UpdatedAt  time.Time     `json:"updated_at"`
}

// PasskeyInfo is the admin-visible summary of a WebAuthn credential.
// Only non-PII fields are exposed; user-provided text (e.g. nickname) is omitted.
type PasskeyInfo struct {
	ID              string     `json:"id"`
	CredentialID    string     `json:"credential_id"` // base64url
	TenantID        string     `json:"tenant_id"`
	AttestationType string     `json:"attestation_type"`
	Transport       []string   `json:"transport,omitempty"`
	PRFCapable      bool       `json:"prf_capable"`
	SignCount       uint32     `json:"sign_count"`
	CreatedAt       time.Time  `json:"created_at"`
	LastUseTime     *time.Time `json:"last_use_time,omitempty"`
}

// GetUserDetail returns detailed user information for admin.
// GET /admin/tenants/:id/users/:user_id/detail
func (h *AdminHandlers) GetUserDetail(c *gin.Context) {
	tenantID := domain.TenantID(c.Param("id"))
	userID := domain.UserIDFromString(c.Param("user_id"))

	// Verify tenant exists
	_, err := h.store.Tenants().GetByID(c.Request.Context(), tenantID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "tenant not found"})
			return
		}
		h.logger.Error("failed to get tenant", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get tenant"})
		return
	}

	// Verify user is a member of this tenant
	isMember, err := h.store.UserTenants().IsMember(c.Request.Context(), userID, tenantID)
	if err != nil {
		h.logger.Error("failed to check tenant membership", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to check membership"})
		return
	}
	if !isMember {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found in tenant"})
		return
	}

	user, err := h.store.Users().GetByID(c.Request.Context(), userID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
			return
		}
		h.logger.Error("failed to get user", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get user"})
		return
	}

	resp := UserDetailResponse{
		UUID:       user.UUID.String(),
		WalletType: string(user.WalletType),
		CreatedAt:  user.CreatedAt,
		UpdatedAt:  user.UpdatedAt,
	}

	// Only expose DID if it's a did:key (public key encoding, not PII).
	if strings.HasPrefix(user.DID, "did:key:") {
		resp.DID = user.DID
	}

	// Convert passkeys (filter to this tenant)
	resp.Passkeys = make([]PasskeyInfo, 0)
	for _, cred := range user.WebauthnCredentials {
		if cred.TenantID != tenantID {
			continue
		}
		resp.Passkeys = append(resp.Passkeys, PasskeyInfo{
			ID:              cred.ID,
			CredentialID:    base64.RawURLEncoding.EncodeToString(cred.CredentialID),
			TenantID:        string(cred.TenantID),
			AttestationType: cred.AttestationType,
			Transport:       cred.Transport,
			PRFCapable:      cred.PRFCapable,
			SignCount:       cred.Authenticator.SignCount,
			CreatedAt:       cred.CreatedAt,
			LastUseTime:     cred.LastUseTime,
		})
	}

	c.JSON(http.StatusOK, resp)
}

// GetTenantStats returns aggregate statistics for a tenant.
// GET /admin/tenants/:id/stats
//
// TODO: This endpoint requires dedicated statistics counters to avoid
// full-table scans. See https://github.com/sirosfoundation/go-wallet-backend/issues/223
func (h *AdminHandlers) GetTenantStats(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{
		"error": "tenant statistics not yet implemented; requires dedicated counters",
	})
}
