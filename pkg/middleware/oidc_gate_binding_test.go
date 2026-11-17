package middleware

import (
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/pkg/oidc"
)

func TestBuildLoginOIDCGateBinding_NoGateResult(t *testing.T) {
	c, _ := gin.CreateTestContext(httptest.NewRecorder())

	binding := BuildLoginOIDCGateBinding(c)

	assert.Nil(t, binding, "no OIDC gate result in context should yield a nil binding")
}

func TestBuildLoginOIDCGateBinding_PopulatesFromContext(t *testing.T) {
	c, _ := gin.CreateTestContext(httptest.NewRecorder())

	tenant := &domain.Tenant{
		ID: "tenant-a",
		OIDCGate: domain.OIDCGateConfig{
			Mode:    domain.OIDCGateModeLogin,
			LoginOP: &domain.OIDCProviderConfig{Issuer: "https://idp.example.com", ClientID: "tenant-a-client"},
		},
	}
	c.Set("tenant", tenant)
	c.Set(OIDCGateContextKey, &oidc.ValidationResult{
		Issuer:  "https://idp.example.com",
		Subject: "user-1",
		Claims: map[string]interface{}{
			"email": "user@example.com",
			"role":  "admin",
		},
	})

	binding := BuildLoginOIDCGateBinding(c)

	require.NotNil(t, binding)
	assert.Equal(t, "https://idp.example.com", binding.Issuer)
	assert.Equal(t, "user-1", binding.Subject)
	assert.Equal(t, "user@example.com", binding.Email)
	assert.Equal(t, "tenant-a-client", binding.Audience, "audience should come from the tenant's LoginOP.EffectiveAudience()")
	require.NotNil(t, binding.Claims)
	assert.Equal(t, "admin", binding.Claims["role"])
}

func TestBuildLoginOIDCGateBinding_NoTenantInContext(t *testing.T) {
	c, _ := gin.CreateTestContext(httptest.NewRecorder())

	c.Set(OIDCGateContextKey, &oidc.ValidationResult{
		Issuer:  "https://idp.example.com",
		Subject: "user-1",
	})

	binding := BuildLoginOIDCGateBinding(c)

	require.NotNil(t, binding)
	assert.Equal(t, "https://idp.example.com", binding.Issuer)
	assert.Empty(t, binding.Audience, "no tenant in context means no audience can be recorded")
}

func TestBuildLoginOIDCGateBinding_TenantWithoutLoginOP(t *testing.T) {
	c, _ := gin.CreateTestContext(httptest.NewRecorder())

	tenant := &domain.Tenant{ID: "tenant-no-op"}
	c.Set("tenant", tenant)
	c.Set(OIDCGateContextKey, &oidc.ValidationResult{
		Issuer:  "https://idp.example.com",
		Subject: "user-1",
	})

	binding := BuildLoginOIDCGateBinding(c)

	require.NotNil(t, binding)
	assert.Empty(t, binding.Audience, "a tenant with no LoginOP configured means no audience can be recorded")
}
