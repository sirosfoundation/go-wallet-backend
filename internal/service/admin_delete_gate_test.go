package service_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/api"
	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/service"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage/memory"
)

// An admin cannot hard-delete a live instance into a state the login gate reads
// as initial enrollment: the passkey stays gated after revocation and the delete
// that would empty the listing is refused before and after.
func TestAdminDelete_LastInstanceKeepsPasskeysGated(t *testing.T) {
	gin.SetMode(gin.TestMode)
	ctx := context.Background()
	store := memory.NewStore()
	tenant := domain.TenantID("acme")
	user := domain.NewUserID()
	require.NoError(t, store.Users().Create(ctx, &domain.User{UUID: user}))
	require.NoError(t, store.WalletInstances().Upsert(ctx, &domain.WalletInstance{
		ID: "only", TenantID: tenant, UserID: &user, CredentialID: "pk-1", Status: domain.InstanceStatusActive,
	}))

	h := api.NewAdminHandlers(store, zap.NewNop(), nil)
	h.SetLifecycle(service.NewWalletLifecycleService(store, zap.NewNop(), nil))
	r := gin.New()
	r.DELETE("/admin/tenants/:id/instances/:instance_id", h.DeleteWalletInstance)
	r.PUT("/admin/tenants/:id/instances/:instance_id/status", h.UpdateWalletInstanceStatus)

	del := func() *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodDelete, "/admin/tenants/acme/instances/only", nil))
		return w
	}

	w := del()
	require.Equal(t, http.StatusConflict, w.Code, w.Body.String())
	assert.Contains(t, w.Body.String(), "INSTANCE_OWNED")
	_, err := store.WalletInstances().GetByID(ctx, "only")
	require.NoError(t, err, "the live instance must survive the refused delete")

	// Revoke via the lifecycle; the delete is still refused and every passkey stays
	// refused at login.
	w = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/admin/tenants/acme/instances/only/status", strings.NewReader(`{"status":"revoked"}`))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	w = del()
	require.Equal(t, http.StatusConflict, w.Code, w.Body.String())
	for _, pk := range []string{"pk-1", "pk-other"} {
		assert.ErrorIs(t, service.CheckWalletLifecycleForTest(ctx, store, tenant, user, pk), service.ErrWalletDeactivated, pk)
	}
}
