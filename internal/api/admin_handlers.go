package api

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
)

// AdminHandlers contains handlers for internal admin API endpoints
type AdminHandlers struct {
	store  storage.Store
	logger *zap.Logger
}

// NewAdminHandlers creates a new AdminHandlers instance
func NewAdminHandlers(store storage.Store, logger *zap.Logger) *AdminHandlers {
	return &AdminHandlers{
		store:  store,
		logger: logger,
	}
}

// TenantRequest represents the request body for creating/updating a tenant
type TenantRequest struct {
	ID          string              `json:"id" binding:"required"`
	Name        string              `json:"name" binding:"required"`
	DisplayName string              `json:"display_name,omitempty"`
	Enabled     *bool               `json:"enabled,omitempty"`
	TrustConfig *TrustConfigRequest `json:"trust_config,omitempty"`
}

// TrustConfigRequest represents the trust configuration in API requests
type TrustConfigRequest struct {
	TrustEndpoint string `json:"trust_endpoint,omitempty"`
	TrustTTL      *int   `json:"trust_ttl,omitempty"` // seconds
}

// TenantResponse represents a tenant in API responses
type TenantResponse struct {
	ID          string               `json:"id"`
	Name        string               `json:"name"`
	DisplayName string               `json:"display_name,omitempty"`
	Enabled     bool                 `json:"enabled"`
	CreatedAt   time.Time            `json:"created_at"`
	UpdatedAt   time.Time            `json:"updated_at"`
	TrustConfig *TrustConfigResponse `json:"trust_config,omitempty"`
}

// TrustConfigResponse represents the trust configuration in API responses
type TrustConfigResponse struct {
	TrustEndpoint string `json:"trust_endpoint,omitempty"`
	TrustTTL      int    `json:"trust_ttl"` // seconds
}

func tenantToResponse(t *domain.Tenant) *TenantResponse {
	resp := &TenantResponse{
		ID:          string(t.ID),
		Name:        t.Name,
		DisplayName: t.DisplayName,
		Enabled:     t.Enabled,
		CreatedAt:   t.CreatedAt,
		UpdatedAt:   t.UpdatedAt,
	}
	// Include trust config if any non-default values are set
	if t.TrustConfig.TrustEndpoint != "" || t.TrustConfig.TrustTTL != 0 {
		resp.TrustConfig = &TrustConfigResponse{
			TrustEndpoint: t.TrustConfig.TrustEndpoint,
			TrustTTL:      t.TrustConfig.TrustTTL,
		}
	}
	return resp
}

// ListTenants returns all tenants
// GET /admin/tenants
func (h *AdminHandlers) ListTenants(c *gin.Context) {
	tenants, err := h.store.Tenants().GetAll(c.Request.Context())
	if err != nil {
		h.logger.Error("Failed to list tenants", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list tenants"})
		return
	}

	response := make([]*TenantResponse, len(tenants))
	for i, t := range tenants {
		response[i] = tenantToResponse(t)
	}

	c.JSON(http.StatusOK, gin.H{"tenants": response})
}

// GetTenant returns a specific tenant
// GET /admin/tenants/:id
func (h *AdminHandlers) GetTenant(c *gin.Context) {
	tenantID := domain.TenantID(c.Param("id"))

	tenant, err := h.store.Tenants().GetByID(c.Request.Context(), tenantID)
	if err != nil {
		if err == storage.ErrNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "Tenant not found"})
			return
		}
		h.logger.Error("Failed to get tenant", zap.Error(err), zap.String("tenant_id", string(tenantID)))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get tenant"})
		return
	}

	c.JSON(http.StatusOK, tenantToResponse(tenant))
}

// CreateTenant creates a new tenant
// POST /admin/tenants
func (h *AdminHandlers) CreateTenant(c *gin.Context) {
	var req TenantRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	tenantID := domain.TenantID(req.ID)
	if err := domain.ValidateTenantID(tenantID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Check if tenant already exists
	existing, err := h.store.Tenants().GetByID(c.Request.Context(), tenantID)
	if err == nil && existing != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "Tenant already exists"})
		return
	}

	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}

	// Default DisplayName to Name if not provided
	displayName := req.DisplayName
	if displayName == "" {
		displayName = req.Name
	}

	tenant := &domain.Tenant{
		ID:          tenantID,
		Name:        req.Name,
		DisplayName: displayName,
		Enabled:     enabled,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	// Apply trust config if provided
	if req.TrustConfig != nil {
		tenant.TrustConfig.TrustEndpoint = req.TrustConfig.TrustEndpoint
		if req.TrustConfig.TrustTTL != nil {
			tenant.TrustConfig.TrustTTL = *req.TrustConfig.TrustTTL
		}
	}

	if err := h.store.Tenants().Create(c.Request.Context(), tenant); err != nil {
		h.logger.Error("Failed to create tenant", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create tenant"})
		return
	}

	h.logger.Info("Tenant created", zap.String("tenant_id", string(tenantID)))
	c.JSON(http.StatusCreated, tenantToResponse(tenant))
}

// UpdateTenant updates an existing tenant
// PUT /admin/tenants/:id
func (h *AdminHandlers) UpdateTenant(c *gin.Context) {
	tenantID := domain.TenantID(c.Param("id"))

	var req TenantRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Get existing tenant
	tenant, err := h.store.Tenants().GetByID(c.Request.Context(), tenantID)
	if err != nil {
		if err == storage.ErrNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "Tenant not found"})
			return
		}
		h.logger.Error("Failed to get tenant", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get tenant"})
		return
	}

	// Update fields
	tenant.Name = req.Name
	tenant.DisplayName = req.DisplayName
	if req.Enabled != nil {
		tenant.Enabled = *req.Enabled
	}
	// Update trust config if provided
	if req.TrustConfig != nil {
		tenant.TrustConfig.TrustEndpoint = req.TrustConfig.TrustEndpoint
		if req.TrustConfig.TrustTTL != nil {
			tenant.TrustConfig.TrustTTL = *req.TrustConfig.TrustTTL
		}
	}
	tenant.UpdatedAt = time.Now()

	if err := h.store.Tenants().Update(c.Request.Context(), tenant); err != nil {
		h.logger.Error("Failed to update tenant", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update tenant"})
		return
	}

	h.logger.Info("Tenant updated", zap.String("tenant_id", string(tenantID)))
	c.JSON(http.StatusOK, tenantToResponse(tenant))
}

// DeleteTenant deletes a tenant
// DELETE /admin/tenants/:id
func (h *AdminHandlers) DeleteTenant(c *gin.Context) {
	tenantID := domain.TenantID(c.Param("id"))

	// Prevent deleting the default tenant
	if tenantID == domain.DefaultTenantID {
		c.JSON(http.StatusForbidden, gin.H{"error": "Cannot delete the default tenant"})
		return
	}

	// Check if tenant exists
	_, err := h.store.Tenants().GetByID(c.Request.Context(), tenantID)
	if err != nil {
		if err == storage.ErrNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "Tenant not found"})
			return
		}
		h.logger.Error("Failed to get tenant", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get tenant"})
		return
	}

	if err := h.store.Tenants().Delete(c.Request.Context(), tenantID); err != nil {
		h.logger.Error("Failed to delete tenant", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete tenant"})
		return
	}

	h.logger.Info("Tenant deleted", zap.String("tenant_id", string(tenantID)))
	c.JSON(http.StatusOK, gin.H{"message": "Tenant deleted"})
}

// AddUserToTenant adds a user to a tenant
// POST /admin/tenants/:id/users
func (h *AdminHandlers) AddUserToTenant(c *gin.Context) {
	tenantID := domain.TenantID(c.Param("id"))

	var req struct {
		UserID string `json:"user_id" binding:"required"`
		Role   string `json:"role,omitempty"` // user, admin
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Verify tenant exists
	_, err := h.store.Tenants().GetByID(c.Request.Context(), tenantID)
	if err != nil {
		if err == storage.ErrNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "Tenant not found"})
			return
		}
		h.logger.Error("Failed to get tenant", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get tenant"})
		return
	}

	userID := domain.UserIDFromString(req.UserID)
	role := req.Role
	if role == "" {
		role = domain.TenantRoleUser
	}

	membership := &domain.UserTenantMembership{
		UserID:    userID,
		TenantID:  tenantID,
		Role:      role,
		CreatedAt: time.Now(),
	}

	if err := h.store.UserTenants().AddMembership(c.Request.Context(), membership); err != nil {
		h.logger.Error("Failed to add user to tenant", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to add user to tenant"})
		return
	}

	h.logger.Info("User added to tenant",
		zap.String("tenant_id", string(tenantID)),
		zap.String("user_id", req.UserID),
		zap.String("role", role),
	)
	c.JSON(http.StatusOK, gin.H{"message": "User added to tenant"})
}

// RemoveUserFromTenant removes a user from a tenant
// DELETE /admin/tenants/:id/users/:user_id
func (h *AdminHandlers) RemoveUserFromTenant(c *gin.Context) {
	tenantID := domain.TenantID(c.Param("id"))
	userID := domain.UserIDFromString(c.Param("user_id"))

	if err := h.store.UserTenants().RemoveMembership(c.Request.Context(), userID, tenantID); err != nil {
		h.logger.Error("Failed to remove user from tenant", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to remove user from tenant"})
		return
	}

	h.logger.Info("User removed from tenant",
		zap.String("tenant_id", string(tenantID)),
		zap.String("user_id", userID.String()),
	)
	c.JSON(http.StatusOK, gin.H{"message": "User removed from tenant"})
}

// GetTenantUsers returns all users in a tenant
// GET /admin/tenants/:id/users
func (h *AdminHandlers) GetTenantUsers(c *gin.Context) {
	tenantID := domain.TenantID(c.Param("id"))

	// Verify tenant exists
	_, err := h.store.Tenants().GetByID(c.Request.Context(), tenantID)
	if err != nil {
		if err == storage.ErrNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "Tenant not found"})
			return
		}
		h.logger.Error("Failed to get tenant", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get tenant"})
		return
	}

	userIDs, err := h.store.UserTenants().GetTenantUsers(c.Request.Context(), tenantID)
	if err != nil {
		h.logger.Error("Failed to get tenant users", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get tenant users"})
		return
	}

	// Convert to strings
	users := make([]string, len(userIDs))
	for i, id := range userIDs {
		users[i] = id.String()
	}

	c.JSON(http.StatusOK, gin.H{"users": users})
}

// AdminStatus returns the admin server status
// GET /admin/status
func (h *AdminHandlers) AdminStatus(c *gin.Context) {
	c.JSON(http.StatusOK, StatusResponse{
		Status:       "ok",
		Service:      "wallet-backend-admin",
		APIVersion:   CurrentAPIVersion,
		Capabilities: APICapabilities[CurrentAPIVersion],
	})
}

// IssuerRequest represents the request body for creating/updating an issuer
type IssuerRequest struct {
	CredentialIssuerIdentifier string `json:"credential_issuer_identifier" binding:"required"`
	ClientID                   string `json:"client_id,omitempty"`
	Visible                    *bool  `json:"visible,omitempty"`
}

// IssuerResponse represents an issuer in API responses
type IssuerResponse struct {
	ID                         int64   `json:"id"`
	TenantID                   string  `json:"tenant_id"`
	CredentialIssuerIdentifier string  `json:"credential_issuer_identifier"`
	ClientID                   string  `json:"client_id,omitempty"`
	Visible                    bool    `json:"visible"`
	TrustStatus                string  `json:"trust_status,omitempty"`
	TrustFramework             string  `json:"trust_framework,omitempty"`
	TrustEvaluatedAt           *string `json:"trust_evaluated_at,omitempty"`
}

func issuerToResponse(i *domain.CredentialIssuer) *IssuerResponse {
	resp := &IssuerResponse{
		ID:                         i.ID,
		TenantID:                   string(i.TenantID),
		CredentialIssuerIdentifier: i.CredentialIssuerIdentifier,
		ClientID:                   i.ClientID,
		Visible:                    i.Visible,
		TrustStatus:                string(i.TrustStatus),
		TrustFramework:             i.TrustFramework,
	}
	if i.TrustEvaluatedAt != nil {
		t := i.TrustEvaluatedAt.Format(time.RFC3339)
		resp.TrustEvaluatedAt = &t
	}
	return resp
}

// ListIssuers returns all issuers for a tenant
// GET /admin/tenants/:id/issuers
func (h *AdminHandlers) ListIssuers(c *gin.Context) {
	tenantID := domain.TenantID(c.Param("id"))

	// Verify tenant exists
	_, err := h.store.Tenants().GetByID(c.Request.Context(), tenantID)
	if err != nil {
		if err == storage.ErrNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "Tenant not found"})
			return
		}
		h.logger.Error("Failed to get tenant", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get tenant"})
		return
	}

	issuers, err := h.store.Issuers().GetAll(c.Request.Context(), tenantID)
	if err != nil {
		h.logger.Error("Failed to list issuers", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list issuers"})
		return
	}

	response := make([]*IssuerResponse, len(issuers))
	for i, issuer := range issuers {
		response[i] = issuerToResponse(issuer)
	}

	c.JSON(http.StatusOK, gin.H{"issuers": response})
}

// GetIssuer returns a specific issuer
// GET /admin/tenants/:id/issuers/:issuer_id
func (h *AdminHandlers) GetIssuer(c *gin.Context) {
	tenantID := domain.TenantID(c.Param("id"))
	issuerIDStr := c.Param("issuer_id")

	var issuerID int64
	if _, err := fmt.Sscanf(issuerIDStr, "%d", &issuerID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid issuer ID"})
		return
	}

	issuer, err := h.store.Issuers().GetByID(c.Request.Context(), tenantID, issuerID)
	if err != nil {
		if err == storage.ErrNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "Issuer not found"})
			return
		}
		h.logger.Error("Failed to get issuer", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get issuer"})
		return
	}

	c.JSON(http.StatusOK, issuerToResponse(issuer))
}

// CreateIssuer creates a new issuer for a tenant
// POST /admin/tenants/:id/issuers
func (h *AdminHandlers) CreateIssuer(c *gin.Context) {
	tenantID := domain.TenantID(c.Param("id"))

	// Verify tenant exists
	_, err := h.store.Tenants().GetByID(c.Request.Context(), tenantID)
	if err != nil {
		if err == storage.ErrNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "Tenant not found"})
			return
		}
		h.logger.Error("Failed to get tenant", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get tenant"})
		return
	}

	var req IssuerRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Check if issuer with same identifier already exists in tenant
	existing, err := h.store.Issuers().GetByIdentifier(c.Request.Context(), tenantID, req.CredentialIssuerIdentifier)
	if err == nil && existing != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "Issuer with this identifier already exists in tenant"})
		return
	}

	visible := true
	if req.Visible != nil {
		visible = *req.Visible
	}

	issuer := &domain.CredentialIssuer{
		TenantID:                   tenantID,
		CredentialIssuerIdentifier: req.CredentialIssuerIdentifier,
		ClientID:                   req.ClientID,
		Visible:                    visible,
	}

	if err := h.store.Issuers().Create(c.Request.Context(), issuer); err != nil {
		h.logger.Error("Failed to create issuer", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create issuer"})
		return
	}

	h.logger.Info("Issuer created",
		zap.String("tenant_id", string(tenantID)),
		zap.String("identifier", req.CredentialIssuerIdentifier))
	c.JSON(http.StatusCreated, issuerToResponse(issuer))
}

// UpdateIssuer updates an existing issuer
// PUT /admin/tenants/:id/issuers/:issuer_id
func (h *AdminHandlers) UpdateIssuer(c *gin.Context) {
	tenantID := domain.TenantID(c.Param("id"))
	issuerIDStr := c.Param("issuer_id")

	var issuerID int64
	if _, err := fmt.Sscanf(issuerIDStr, "%d", &issuerID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid issuer ID"})
		return
	}

	// Get existing issuer
	issuer, err := h.store.Issuers().GetByID(c.Request.Context(), tenantID, issuerID)
	if err != nil {
		if err == storage.ErrNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "Issuer not found"})
			return
		}
		h.logger.Error("Failed to get issuer", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get issuer"})
		return
	}

	var req IssuerRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Update fields
	issuer.CredentialIssuerIdentifier = req.CredentialIssuerIdentifier
	issuer.ClientID = req.ClientID
	if req.Visible != nil {
		issuer.Visible = *req.Visible
	}

	if err := h.store.Issuers().Update(c.Request.Context(), issuer); err != nil {
		h.logger.Error("Failed to update issuer", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update issuer"})
		return
	}

	h.logger.Info("Issuer updated",
		zap.String("tenant_id", string(tenantID)),
		zap.Int64("issuer_id", issuerID))
	c.JSON(http.StatusOK, issuerToResponse(issuer))
}

// DeleteIssuer deletes an issuer
// DELETE /admin/tenants/:id/issuers/:issuer_id
func (h *AdminHandlers) DeleteIssuer(c *gin.Context) {
	tenantID := domain.TenantID(c.Param("id"))
	issuerIDStr := c.Param("issuer_id")

	var issuerID int64
	if _, err := fmt.Sscanf(issuerIDStr, "%d", &issuerID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid issuer ID"})
		return
	}

	// Check if issuer exists
	_, err := h.store.Issuers().GetByID(c.Request.Context(), tenantID, issuerID)
	if err != nil {
		if err == storage.ErrNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "Issuer not found"})
			return
		}
		h.logger.Error("Failed to get issuer", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get issuer"})
		return
	}

	if err := h.store.Issuers().Delete(c.Request.Context(), tenantID, issuerID); err != nil {
		h.logger.Error("Failed to delete issuer", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete issuer"})
		return
	}

	h.logger.Info("Issuer deleted",
		zap.String("tenant_id", string(tenantID)),
		zap.Int64("issuer_id", issuerID))
	c.JSON(http.StatusOK, gin.H{"message": "Issuer deleted"})
}

// VerifierRequest represents the request body for creating/updating a verifier
type VerifierRequest struct {
	Name string `json:"name" binding:"required"`
	URL  string `json:"url" binding:"required"`
}

// VerifierResponse represents a verifier in API responses
type VerifierResponse struct {
	ID       int64  `json:"id"`
	TenantID string `json:"tenant_id"`
	Name     string `json:"name"`
	URL      string `json:"url"`
}

func verifierToResponse(v *domain.Verifier) *VerifierResponse {
	return &VerifierResponse{
		ID:       v.ID,
		TenantID: string(v.TenantID),
		Name:     v.Name,
		URL:      v.URL,
	}
}

// ListVerifiers returns all verifiers for a tenant
// GET /admin/tenants/:id/verifiers
func (h *AdminHandlers) ListVerifiers(c *gin.Context) {
	tenantID := domain.TenantID(c.Param("id"))

	// Verify tenant exists
	_, err := h.store.Tenants().GetByID(c.Request.Context(), tenantID)
	if err != nil {
		if err == storage.ErrNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "Tenant not found"})
			return
		}
		h.logger.Error("Failed to get tenant", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get tenant"})
		return
	}

	verifiers, err := h.store.Verifiers().GetAll(c.Request.Context(), tenantID)
	if err != nil {
		h.logger.Error("Failed to list verifiers", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list verifiers"})
		return
	}

	response := make([]*VerifierResponse, len(verifiers))
	for i, verifier := range verifiers {
		response[i] = verifierToResponse(verifier)
	}

	c.JSON(http.StatusOK, gin.H{"verifiers": response})
}

// GetVerifier returns a specific verifier
// GET /admin/tenants/:id/verifiers/:verifier_id
func (h *AdminHandlers) GetVerifier(c *gin.Context) {
	tenantID := domain.TenantID(c.Param("id"))
	verifierIDStr := c.Param("verifier_id")

	var verifierID int64
	if _, err := fmt.Sscanf(verifierIDStr, "%d", &verifierID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid verifier ID"})
		return
	}

	verifier, err := h.store.Verifiers().GetByID(c.Request.Context(), tenantID, verifierID)
	if err != nil {
		if err == storage.ErrNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "Verifier not found"})
			return
		}
		h.logger.Error("Failed to get verifier", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get verifier"})
		return
	}

	c.JSON(http.StatusOK, verifierToResponse(verifier))
}

// CreateVerifier creates a new verifier for a tenant
// POST /admin/tenants/:id/verifiers
func (h *AdminHandlers) CreateVerifier(c *gin.Context) {
	tenantID := domain.TenantID(c.Param("id"))

	// Verify tenant exists
	_, err := h.store.Tenants().GetByID(c.Request.Context(), tenantID)
	if err != nil {
		if err == storage.ErrNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "Tenant not found"})
			return
		}
		h.logger.Error("Failed to get tenant", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get tenant"})
		return
	}

	var req VerifierRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	verifier := &domain.Verifier{
		TenantID: tenantID,
		Name:     req.Name,
		URL:      req.URL,
	}

	if err := h.store.Verifiers().Create(c.Request.Context(), verifier); err != nil {
		if errors.Is(err, storage.ErrAlreadyExists) {
			c.JSON(http.StatusConflict, gin.H{"error": "Verifier with this URL already exists in tenant"})
			return
		}
		h.logger.Error("Failed to create verifier", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create verifier"})
		return
	}

	h.logger.Info("Verifier created",
		zap.String("tenant_id", string(tenantID)),
		zap.String("name", req.Name))
	c.JSON(http.StatusCreated, verifierToResponse(verifier))
}

// UpdateVerifier updates an existing verifier
// PUT /admin/tenants/:id/verifiers/:verifier_id
func (h *AdminHandlers) UpdateVerifier(c *gin.Context) {
	tenantID := domain.TenantID(c.Param("id"))
	verifierIDStr := c.Param("verifier_id")

	var verifierID int64
	if _, err := fmt.Sscanf(verifierIDStr, "%d", &verifierID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid verifier ID"})
		return
	}

	// Get existing verifier
	verifier, err := h.store.Verifiers().GetByID(c.Request.Context(), tenantID, verifierID)
	if err != nil {
		if err == storage.ErrNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "Verifier not found"})
			return
		}
		h.logger.Error("Failed to get verifier", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get verifier"})
		return
	}

	var req VerifierRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Update fields
	verifier.Name = req.Name
	verifier.URL = req.URL

	if err := h.store.Verifiers().Update(c.Request.Context(), verifier); err != nil {
		h.logger.Error("Failed to update verifier", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update verifier"})
		return
	}

	h.logger.Info("Verifier updated",
		zap.String("tenant_id", string(tenantID)),
		zap.Int64("verifier_id", verifierID))
	c.JSON(http.StatusOK, verifierToResponse(verifier))
}

// DeleteVerifier deletes a verifier
// DELETE /admin/tenants/:id/verifiers/:verifier_id
func (h *AdminHandlers) DeleteVerifier(c *gin.Context) {
	tenantID := domain.TenantID(c.Param("id"))
	verifierIDStr := c.Param("verifier_id")

	var verifierID int64
	if _, err := fmt.Sscanf(verifierIDStr, "%d", &verifierID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid verifier ID"})
		return
	}

	// Check if verifier exists
	_, err := h.store.Verifiers().GetByID(c.Request.Context(), tenantID, verifierID)
	if err != nil {
		if err == storage.ErrNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "Verifier not found"})
			return
		}
		h.logger.Error("Failed to get verifier", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get verifier"})
		return
	}

	if err := h.store.Verifiers().Delete(c.Request.Context(), tenantID, verifierID); err != nil {
		h.logger.Error("Failed to delete verifier", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete verifier"})
		return
	}

	h.logger.Info("Verifier deleted",
		zap.String("tenant_id", string(tenantID)),
		zap.Int64("verifier_id", verifierID))
	c.JSON(http.StatusOK, gin.H{"message": "Verifier deleted"})
}
