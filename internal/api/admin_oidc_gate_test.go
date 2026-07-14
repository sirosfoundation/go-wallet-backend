package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage/memory"
)

func TestCreateTenant_WithOIDCGate(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store := memory.NewStore()
	h := NewAdminHandlers(store, zap.NewNop(), nil)
	router := gin.New()
	router.POST("/admin/tenants", h.CreateTenant)

	body := `{
		"id": "oidc-tenant",
		"name": "OIDC Tenant",
		"oidc_gate": {
			"mode": "both",
			"registration_op": {
				"display_name": "Test IdP",
				"issuer": "https://idp.example.com",
				"client_id": "client-123",
				"jwks_uri": "https://idp.example.com/.well-known/jwks.json",
				"audience": "wallet",
				"scopes": "openid profile"
			},
			"login_op": {
				"display_name": "Login IdP",
				"issuer": "https://login.example.com",
				"client_id": "client-456"
			},
			"required_claims": {"email_verified": true},
			"bind_identity": true
		}
	}`
	req := httptest.NewRequest(http.MethodPost, "/admin/tenants", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	var resp TenantResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if resp.OIDCGate == nil {
		t.Fatal("expected oidc_gate in response")
	}
	if resp.OIDCGate.Mode != "both" {
		t.Errorf("mode = %q, want both", resp.OIDCGate.Mode)
	}
	if resp.OIDCGate.RegistrationOP == nil {
		t.Fatal("expected registration_op")
	}
	if resp.OIDCGate.RegistrationOP.Issuer != "https://idp.example.com" {
		t.Errorf("registration_op issuer = %q", resp.OIDCGate.RegistrationOP.Issuer)
	}
	if resp.OIDCGate.RegistrationOP.DisplayName != "Test IdP" {
		t.Errorf("registration_op display_name = %q", resp.OIDCGate.RegistrationOP.DisplayName)
	}
	if resp.OIDCGate.RegistrationOP.JWKSURI != "https://idp.example.com/.well-known/jwks.json" {
		t.Errorf("registration_op jwks_uri = %q", resp.OIDCGate.RegistrationOP.JWKSURI)
	}
	if resp.OIDCGate.RegistrationOP.Scopes != "openid profile" {
		t.Errorf("registration_op scopes = %q", resp.OIDCGate.RegistrationOP.Scopes)
	}
	if resp.OIDCGate.LoginOP == nil {
		t.Fatal("expected login_op")
	}
	if resp.OIDCGate.LoginOP.Issuer != "https://login.example.com" {
		t.Errorf("login_op issuer = %q", resp.OIDCGate.LoginOP.Issuer)
	}
	if !resp.OIDCGate.BindIdentity {
		t.Error("expected bind_identity = true")
	}
}

func TestCreateTenant_OIDCGate_InvalidMode(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store := memory.NewStore()
	h := NewAdminHandlers(store, zap.NewNop(), nil)
	router := gin.New()
	router.POST("/admin/tenants", h.CreateTenant)

	body := `{
		"id": "bad-mode",
		"name": "Bad Mode Tenant",
		"oidc_gate": {"mode": "invalid"}
	}`
	req := httptest.NewRequest(http.MethodPost, "/admin/tenants", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCreateTenant_OIDCGate_BindIdentityLoginOnly(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store := memory.NewStore()
	h := NewAdminHandlers(store, zap.NewNop(), nil)
	router := gin.New()
	router.POST("/admin/tenants", h.CreateTenant)

	bindTrue := true
	body, _ := json.Marshal(TenantRequest{
		ID:   "bind-login",
		Name: "Bind Login Tenant",
		OIDCGate: &OIDCGateRequest{
			Mode:         "login",
			BindIdentity: &bindTrue,
			LoginOP: &OIDCProviderConfigRequest{
				Issuer:   "https://idp.example.com",
				ClientID: "client-1",
			},
		},
	})

	req := httptest.NewRequest(http.MethodPost, "/admin/tenants", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 (bind_identity with login-only), got %d: %s", w.Code, w.Body.String())
	}
}

func TestUpdateTenant_WithOIDCGate(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store := memory.NewStore()
	h := NewAdminHandlers(store, zap.NewNop(), nil)
	router := gin.New()
	router.PUT("/admin/tenants/:id", h.UpdateTenant)

	// Seed tenant
	seedTenant(t, store, "update-gate")

	body := `{
		"id": "update-gate",
		"name": "Updated Tenant",
		"oidc_gate": {
			"mode": "registration",
			"registration_op": {
				"issuer": "https://idp.example.com",
				"client_id": "client-789"
			}
		}
	}`
	req := httptest.NewRequest(http.MethodPut, "/admin/tenants/update-gate", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp TenantResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.OIDCGate == nil {
		t.Fatal("expected oidc_gate in response")
	}
	if resp.OIDCGate.Mode != "registration" {
		t.Errorf("mode = %q, want registration", resp.OIDCGate.Mode)
	}
}

func TestGetTenant_WithOIDCGate(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store := memory.NewStore()
	h := NewAdminHandlers(store, zap.NewNop(), nil)
	router := gin.New()
	router.POST("/admin/tenants", h.CreateTenant)
	router.GET("/admin/tenants/:id", h.GetTenant)

	// Create tenant with OIDC gate
	createBody := `{
		"id": "get-gate",
		"name": "Get Gate Tenant",
		"oidc_gate": {
			"mode": "registration",
			"registration_op": {
				"issuer": "https://idp.example.com",
				"client_id": "client-get",
				"audience": "wallet-app"
			}
		}
	}`
	createReq := httptest.NewRequest(http.MethodPost, "/admin/tenants", bytes.NewBufferString(createBody))
	createReq.Header.Set("Content-Type", "application/json")
	cw := httptest.NewRecorder()
	router.ServeHTTP(cw, createReq)

	if cw.Code != http.StatusCreated {
		t.Fatalf("create: expected 201, got %d", cw.Code)
	}

	// Get the tenant and verify OIDC gate in response
	getReq := httptest.NewRequest(http.MethodGet, "/admin/tenants/get-gate", nil)
	gw := httptest.NewRecorder()
	router.ServeHTTP(gw, getReq)

	if gw.Code != http.StatusOK {
		t.Fatalf("get: expected 200, got %d", gw.Code)
	}

	var resp TenantResponse
	if err := json.Unmarshal(gw.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.OIDCGate == nil {
		t.Fatal("expected oidc_gate in GET response")
	}
	if resp.OIDCGate.RegistrationOP == nil {
		t.Fatal("expected registration_op in GET response")
	}
	if resp.OIDCGate.RegistrationOP.Audience != "wallet-app" {
		t.Errorf("audience = %q, want wallet-app", resp.OIDCGate.RegistrationOP.Audience)
	}
}

func TestApplyOIDCGateRequest_NilInputs(t *testing.T) {
	// nil request, nil gate — should return nil error
	if err := applyOIDCGateRequest(nil, nil); err != nil {
		t.Errorf("nil req + nil gate: %v", err)
	}

	// nil request, valid gate — no-op
	gate := &domain.OIDCGateConfig{}
	if err := applyOIDCGateRequest(nil, gate); err != nil {
		t.Errorf("nil req: %v", err)
	}

	// valid request, nil gate — no-op
	req := &OIDCGateRequest{Mode: "none"}
	if err := applyOIDCGateRequest(req, nil); err != nil {
		t.Errorf("nil gate: %v", err)
	}
}

func TestApplyOIDCGateRequest_RequiredClaims(t *testing.T) {
	gate := &domain.OIDCGateConfig{}
	req := &OIDCGateRequest{
		Mode:           "registration",
		RequiredClaims: map[string]interface{}{"email_verified": true, "groups": "admins"},
		RegistrationOP: &OIDCProviderConfigRequest{
			Issuer:   "https://idp.example.com",
			ClientID: "client-1",
		},
	}

	if err := applyOIDCGateRequest(req, gate); err != nil {
		t.Fatalf("applyOIDCGateRequest: %v", err)
	}

	if len(gate.RequiredClaims) != 2 {
		t.Errorf("required_claims len = %d, want 2", len(gate.RequiredClaims))
	}
	if gate.RequiredClaims["email_verified"] != true {
		t.Error("expected email_verified = true")
	}
}
