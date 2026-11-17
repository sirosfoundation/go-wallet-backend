package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
)

const leakProbeJWK = `{"kty":"EC","crv":"P-256","x":"dummy","y":"dummy","d":"DUMMY-PRIVATE-LEAK-PROBE"}`

// The issuer's client JWK carries the private key the backend signs
// private_key_jwt client assertions with. No user-facing response may contain it.
func TestIssuerRoutes_DoNotExposeClientJWK(t *testing.T) {
	handlers, router, user := setupTestHandlersWithUser(t)
	issuer := &domain.CredentialIssuer{
		TenantID:                   domain.DefaultTenantID,
		CredentialIssuerIdentifier: "https://leak-test.example",
		ClientID:                   "leak-test",
		ClientJWK:                  leakProbeJWK,
		Visible:                    true,
	}
	require.NoError(t, handlers.store.Issuers().Create(context.Background(), issuer))

	router.GET("/issuer/all", authMiddlewareForUser(user), handlers.GetAllIssuers)
	router.GET("/issuer/:id", authMiddlewareForUser(user), handlers.GetIssuerByID)

	for _, path := range []string{"/issuer/all", "/issuer/" + strconv.FormatInt(issuer.ID, 10)} {
		t.Run(path, func(t *testing.T) {
			w := httptest.NewRecorder()
			router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
			require.Equal(t, http.StatusOK, w.Code, w.Body.String())

			body := w.Body.String()
			assert.Contains(t, body, "leak-test", "the public client_id is still served")
			assert.NotContains(t, strings.ToLower(body), "clientjwk")
			assert.NotContains(t, body, "DUMMY-PRIVATE-LEAK-PROBE")
		})
	}
}

// The in-process reader (the engine's PAR signer) must still see the key.
func TestIssuerStore_StillHoldsClientJWK(t *testing.T) {
	handlers, _, _ := setupTestHandlersWithUser(t)
	issuer := &domain.CredentialIssuer{
		TenantID:                   domain.DefaultTenantID,
		CredentialIssuerIdentifier: "https://keep-test.example",
		ClientJWK:                  leakProbeJWK,
	}
	require.NoError(t, handlers.store.Issuers().Create(context.Background(), issuer))

	got, err := handlers.store.Issuers().GetByIdentifier(context.Background(), domain.DefaultTenantID, "https://keep-test.example")
	require.NoError(t, err)
	assert.Equal(t, leakProbeJWK, got.ClientJWK)
}
