package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
)

// The add-passkey endpoints take the tenant from the caller's token (#560).
func TestHandlers_StartAddCredential_UsesTheTokenTenant(t *testing.T) {
	h, router, user := setupTestHandlersWithUser(t)
	tenant := func(id string) gin.HandlerFunc {
		return func(c *gin.Context) { c.Set("tenant_id", id); c.Next() }
	}
	router.POST("/add/acme", authMiddlewareForUser(user), tenant("acme"), h.StartAddWebAuthnCredential)
	router.POST("/add/default", authMiddlewareForUser(user), tenant("default"), h.StartAddWebAuthnCredential)

	t.Run("a tenant the user is not a member of is 403", func(t *testing.T) {
		w := postJSON(router, "/add/acme", nil, nil)
		assert.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
	})

	t.Run("a member gets a tenant-scoped user handle", func(t *testing.T) {
		require.NoError(t, h.store.Tenants().Create(t.Context(), &domain.Tenant{ID: "acme", Name: "acme", Enabled: true}))
		require.NoError(t, h.store.UserTenants().AddMembership(t.Context(), &domain.UserTenantMembership{UserID: user.UUID, TenantID: "acme", Role: "user"}))
		w := postJSON(router, "/add/acme", nil, nil)
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		var resp struct {
			CreateOptions struct {
				PublicKey struct {
					User struct {
						ID json.RawMessage `json:"id"`
					} `json:"user"`
				} `json:"publicKey"`
			} `json:"createOptions"`
		}
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		plain, _ := json.Marshal(user.UUID.AsUserHandle())
		assert.NotEqual(t, string(plain), string(resp.CreateOptions.PublicKey.User.ID), "not the bare handle")
	})

	t.Run("the default tenant keeps working", func(t *testing.T) {
		var w *httptest.ResponseRecorder = postJSON(router, "/add/default", nil, nil)
		assert.Equal(t, http.StatusOK, w.Code, w.Body.String())
	})
}
