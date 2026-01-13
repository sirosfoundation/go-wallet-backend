package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage/memory"
)

func init() {
	gin.SetMode(gin.TestMode)
}

func TestTenantPathMiddleware(t *testing.T) {
	store := memory.NewStore()

	// Create a test tenant
	testTenant := &domain.Tenant{
		ID:          "test-tenant",
		Name:        "test-tenant",
		DisplayName: "Test Tenant",
		Enabled:     true,
	}
	if err := store.Tenants().Create(t.Context(), testTenant); err != nil {
		t.Fatalf("Failed to create test tenant: %v", err)
	}

	// Create a disabled tenant
	disabledTenant := &domain.Tenant{
		ID:          "disabled-tenant",
		Name:        "disabled",
		DisplayName: "Disabled Tenant",
		Enabled:     false,
	}
	if err := store.Tenants().Create(t.Context(), disabledTenant); err != nil {
		t.Fatalf("Failed to create disabled tenant: %v", err)
	}

	tests := []struct {
		name           string
		tenantID       string
		expectedStatus int
		checkContext   bool
	}{
		{
			name:           "valid tenant returns 200",
			tenantID:       "test-tenant",
			expectedStatus: http.StatusOK,
			checkContext:   true,
		},
		{
			name:           "default tenant returns 200",
			tenantID:       string(domain.DefaultTenantID),
			expectedStatus: http.StatusOK,
			checkContext:   true,
		},
		{
			name:           "missing tenant ID returns 400",
			tenantID:       "",
			expectedStatus: http.StatusBadRequest,
			checkContext:   false,
		},
		{
			name:           "nonexistent tenant returns 404",
			tenantID:       "nonexistent",
			expectedStatus: http.StatusNotFound,
			checkContext:   false,
		},
		{
			name:           "disabled tenant returns 403",
			tenantID:       "disabled-tenant",
			expectedStatus: http.StatusForbidden,
			checkContext:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router := gin.New()
			router.Use(TenantPathMiddleware(store))
			
			var contextTenantID domain.TenantID
			var contextTenant *domain.Tenant
			
			router.GET("/:tenantID/test", func(c *gin.Context) {
				contextTenantID, _ = GetTenantID(c)
				contextTenant, _ = GetTenant(c)
				c.JSON(http.StatusOK, gin.H{"status": "ok"})
			})

			req := httptest.NewRequest(http.MethodGet, "/"+tt.tenantID+"/test", nil)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, w.Code)
			}

			if tt.checkContext {
				if contextTenantID == "" {
					t.Error("Expected tenant ID in context")
				}
				if contextTenant == nil {
					t.Error("Expected tenant in context")
				}
			}
		})
	}
}

func TestTenantMembershipMiddleware(t *testing.T) {
	store := memory.NewStore()

	// Create a test tenant
	testTenant := &domain.Tenant{
		ID:          "test-tenant",
		Name:        "test-tenant",
		DisplayName: "Test Tenant",
		Enabled:     true,
	}
	if err := store.Tenants().Create(t.Context(), testTenant); err != nil {
		t.Fatalf("Failed to create test tenant: %v", err)
	}

	// Create test users
	memberUser := domain.NewUserID()
	nonMemberUser := domain.NewUserID()

	// Add membership for member user
	membership := &domain.UserTenantMembership{
		UserID:   memberUser,
		TenantID: "test-tenant",
		Role:     domain.TenantRoleUser,
	}
	if err := store.UserTenants().AddMembership(t.Context(), membership); err != nil {
		t.Fatalf("Failed to add membership: %v", err)
	}

	tests := []struct {
		name           string
		setupContext   func(*gin.Context)
		expectedStatus int
	}{
		{
			name: "member user returns 200",
			setupContext: func(c *gin.Context) {
				c.Set("user_id", memberUser.String())
				c.Set("tenant_id", domain.TenantID("test-tenant"))
			},
			expectedStatus: http.StatusOK,
		},
		{
			name: "non-member user returns 403",
			setupContext: func(c *gin.Context) {
				c.Set("user_id", nonMemberUser.String())
				c.Set("tenant_id", domain.TenantID("test-tenant"))
			},
			expectedStatus: http.StatusForbidden,
		},
		{
			name: "missing user_id returns 401",
			setupContext: func(c *gin.Context) {
				c.Set("tenant_id", domain.TenantID("test-tenant"))
			},
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name: "missing tenant_id returns 500",
			setupContext: func(c *gin.Context) {
				c.Set("user_id", memberUser.String())
			},
			expectedStatus: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router := gin.New()
			
			// Setup context middleware
			router.Use(func(c *gin.Context) {
				tt.setupContext(c)
				c.Next()
			})
			
			router.Use(TenantMembershipMiddleware(store))
			
			router.GET("/test", func(c *gin.Context) {
				c.JSON(http.StatusOK, gin.H{"status": "ok"})
			})

			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, w.Code)
			}
		})
	}
}

func TestGetTenantID(t *testing.T) {
	t.Run("returns tenant ID when set", func(t *testing.T) {
		gin.SetMode(gin.TestMode)
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		
		expectedID := domain.TenantID("test-tenant")
		c.Set("tenant_id", expectedID)
		
		id, ok := GetTenantID(c)
		if !ok {
			t.Error("Expected GetTenantID to return true")
		}
		if id != expectedID {
			t.Errorf("Expected tenant ID %s, got %s", expectedID, id)
		}
	})

	t.Run("returns false when not set", func(t *testing.T) {
		gin.SetMode(gin.TestMode)
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		
		_, ok := GetTenantID(c)
		if ok {
			t.Error("Expected GetTenantID to return false")
		}
	})
}

func TestGetTenant(t *testing.T) {
	t.Run("returns tenant when set", func(t *testing.T) {
		gin.SetMode(gin.TestMode)
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		
		expectedTenant := &domain.Tenant{
			ID:   "test-tenant",
			Name: "Test",
		}
		c.Set("tenant", expectedTenant)
		
		tenant, ok := GetTenant(c)
		if !ok {
			t.Error("Expected GetTenant to return true")
		}
		if tenant.ID != expectedTenant.ID {
			t.Errorf("Expected tenant ID %s, got %s", expectedTenant.ID, tenant.ID)
		}
	})

	t.Run("returns false when not set", func(t *testing.T) {
		gin.SetMode(gin.TestMode)
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		
		_, ok := GetTenant(c)
		if ok {
			t.Error("Expected GetTenant to return false")
		}
	})
}
