package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/descope/virtualwebauthn"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/service"
	"github.com/sirosfoundation/go-wallet-backend/pkg/taggedbinary"
)

func postJSON(router *gin.Engine, path string, body []byte, hdr map[string]string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	router.ServeHTTP(w, req)
	return w
}

func assertOwnership422(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	require.Equal(t, http.StatusUnprocessableEntity, w.Code, w.Body.String())
	var resp map[string]string
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, service.PrivateDataOwnershipErrorCode, resp["error"])
}

func storedPrivateData(t *testing.T, h *Handlers, u *domain.User) ([]byte, string) {
	t.Helper()
	d, etag, err := h.services.User.GetPrivateData(context.Background(), u.UUID)
	require.NoError(t, err)
	return d, etag
}

func TestHandlers_UpdatePrivateData_Ownership(t *testing.T) {
	post := func(t *testing.T, body []byte, hdr map[string]string) (*httptest.ResponseRecorder, *Handlers, *domain.User) {
		h, router, user := setupTestHandlersWithUser(t)
		router.POST("/private-data", authMiddlewareForUser(user), h.UpdatePrivateData)
		return postJSON(router, "/private-data", body, hdr), h, user
	}
	tagged := func(b []byte) []byte { out, _ := json.Marshal(taggedbinary.TaggedBytes(b)); return out }

	t.Run("foreign container (tagged body) is 422 and stored data and ETag unchanged", func(t *testing.T) {
		h, router, user := setupTestHandlersWithUser(t)
		router.POST("/private-data", authMiddlewareForUser(user), h.UpdatePrivateData)
		beforeData, beforeEtag := storedPrivateData(t, h, user)

		w := postJSON(router, "/private-data", tagged(testPrivateDataContainer(testCredID("x"))), nil)
		assertOwnership422(t, w)
		assert.Empty(t, w.Header().Get("X-Private-Data-ETag"))

		afterData, afterEtag := storedPrivateData(t, h, user)
		assert.Equal(t, beforeData, afterData)
		assert.Equal(t, beforeEtag, afterEtag)
	})

	t.Run("foreign container (raw body) is 422", func(t *testing.T) {
		w, _, _ := post(t, testPrivateDataContainer(testCredID("x")), nil)
		assertOwnership422(t, w)
	})

	t.Run("partial overlap (raw body) accepted", func(t *testing.T) {
		w, _, _ := post(t, testPrivateDataContainer(testCredID("1"), testCredID("x")), nil)
		assert.Equal(t, http.StatusNoContent, w.Code, w.Body.String())
	})

	t.Run("empty prfKeys, garbage, null are 422", func(t *testing.T) {
		for _, body := range [][]byte{
			tagged(testPrivateDataContainer()),
			[]byte("test-private-data"),
			[]byte("null"),
			tagged([]byte("null")),
			tagged([]byte(`{"prfKeys":null}`)),
		} {
			w, _, _ := post(t, body, nil)
			assertOwnership422(t, w)
		}
	})

	t.Run("ETag conflict stays 412", func(t *testing.T) {
		w, _, _ := post(t, tagged(testPrivateDataContainer(testCredID("1"))), map[string]string{"X-Private-Data-If-Match": "wrong"})
		assert.Equal(t, http.StatusPreconditionFailed, w.Code)
	})
}

func TestHandlers_DeleteWebAuthnCredential_Ownership(t *testing.T) {
	setup := func(t *testing.T) (*Handlers, *gin.Engine, *domain.User) {
		h, router, user := setupTestHandlersWithUser(t)
		user.WebauthnCredentials = append(user.WebauthnCredentials, domain.WebauthnCredential{ID: testCredID("2"), CredentialID: []byte("cred-2")})
		require.NoError(t, h.services.User.UpdateUser(context.Background(), user))
		router.POST("/webauthn/credential/:id/delete", authMiddlewareForUser(user), h.DeleteWebAuthnCredential)
		return h, router, user
	}
	body := func(c []byte) []byte {
		b, _ := json.Marshal(map[string]any{"privateData": taggedbinary.TaggedBytes(c)})
		return b
	}
	path := "/webauthn/credential/" + testCredID("1") + "/delete"

	t.Run("foreign container is 422, nothing changes", func(t *testing.T) {
		h, router, user := setup(t)
		beforeData, beforeEtag := storedPrivateData(t, h, user)
		w := postJSON(router, path, body(testPrivateDataContainer(testCredID("x"))), nil)
		assertOwnership422(t, w)
		afterData, afterEtag := storedPrivateData(t, h, user)
		assert.Equal(t, beforeData, afterData)
		assert.Equal(t, beforeEtag, afterEtag)
		u, _ := h.services.User.GetUserByID(context.Background(), user.UUID)
		assert.Len(t, u.WebauthnCredentials, 2)
	})

	t.Run("container without the deleted credential accepted", func(t *testing.T) {
		_, router, _ := setup(t)
		w := postJSON(router, path, body(testPrivateDataContainer(testCredID("2"))), nil)
		assert.Equal(t, http.StatusNoContent, w.Code, w.Body.String())
	})

	t.Run("missing private data is 422", func(t *testing.T) {
		_, router, _ := setup(t)
		w := postJSON(router, path, []byte(`{}`), nil)
		assertOwnership422(t, w)
	})

	t.Run("empty body is 422, nothing changes", func(t *testing.T) {
		h, router, user := setup(t)
		beforeData, beforeEtag := storedPrivateData(t, h, user)
		w := postJSON(router, path, nil, nil)
		assertOwnership422(t, w)
		afterData, afterEtag := storedPrivateData(t, h, user)
		assert.Equal(t, beforeData, afterData)
		assert.Equal(t, beforeEtag, afterEtag)
		u, _ := h.services.User.GetUserByID(context.Background(), user.UUID)
		assert.Len(t, u.WebauthnCredentials, 2)
	})

	t.Run("malformed body is 400, nothing changes", func(t *testing.T) {
		h, router, user := setup(t)
		beforeData, beforeEtag := storedPrivateData(t, h, user)
		w := postJSON(router, path, []byte(`{"privateData":`), nil)
		assert.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
		afterData, afterEtag := storedPrivateData(t, h, user)
		assert.Equal(t, beforeData, afterData)
		assert.Equal(t, beforeEtag, afterEtag)
		u, _ := h.services.User.GetUserByID(context.Background(), user.UUID)
		assert.Len(t, u.WebauthnCredentials, 2)
	})
}

func TestHandlers_FinishAddCredential_Ownership(t *testing.T) {
	prepare := func(t *testing.T) (*Handlers, *gin.Engine, *domain.User, virtualwebauthn.Credential, virtualwebauthn.AttestationOptions, string) {
		h, router, user := setupTestHandlersWithUser(t)
		router.POST("/webauthn/add/finish", authMiddlewareForUser(user), h.FinishAddWebAuthnCredential)
		begin, err := h.services.WebAuthn.BeginAddCredential(context.Background(), user.UUID)
		require.NoError(t, err)
		raw, err := json.Marshal(begin.CreateOptions)
		require.NoError(t, err)
		opts, err := virtualwebauthn.ParseAttestationOptions(string(raw))
		require.NoError(t, err)
		return h, router, user, virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2), *opts, begin.ChallengeID
	}
	finish := func(router *gin.Engine, cred virtualwebauthn.Credential, opts virtualwebauthn.AttestationOptions, cid string, pd []byte) *httptest.ResponseRecorder {
		rp := virtualwebauthn.RelyingParty{ID: "localhost", Name: "Test Wallet", Origin: "http://localhost:8080"}
		auth := virtualwebauthn.NewAuthenticatorWithOptions(virtualwebauthn.AuthenticatorOptions{})
		resp := virtualwebauthn.CreateAttestationResponse(rp, auth, cred, opts)
		body, _ := json.Marshal(map[string]any{
			"challengeId": cid,
			"credential":  json.RawMessage(resp),
			"privateData": taggedbinary.TaggedBytes(pd),
		})
		return postJSON(router, "/webauthn/add/finish", body, nil)
	}

	t.Run("foreign container is 422, nothing stored", func(t *testing.T) {
		h, router, user, cred, opts, cid := prepare(t)
		beforeData, beforeEtag := storedPrivateData(t, h, user)
		w := finish(router, cred, opts, cid, testPrivateDataContainer(testCredID("x")))
		assertOwnership422(t, w)
		afterData, afterEtag := storedPrivateData(t, h, user)
		assert.Equal(t, beforeData, afterData)
		assert.Equal(t, beforeEtag, afterEtag)
		u, _ := h.services.User.GetUserByID(context.Background(), user.UUID)
		assert.Len(t, u.WebauthnCredentials, 1)
	})

	t.Run("container carrying the new credential accepted", func(t *testing.T) {
		_, router, _, cred, opts, cid := prepare(t)
		w := finish(router, cred, opts, cid, testPrivateDataContainer(base64url(cred.ID)))
		assert.Equal(t, http.StatusOK, w.Code, w.Body.String())
	})
}

func base64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
