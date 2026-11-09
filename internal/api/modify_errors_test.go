package api

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/service"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage/memory"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

// failingModifyUsers makes every Modify fail with err, as the Mongo store does
// when retries are exhausted or the request context ends.
type failingModifyUsers struct {
	storage.UserStore
	err error
}

func (f failingModifyUsers) Modify(context.Context, domain.UserID, storage.UserModifier) (*domain.User, error) {
	return nil, f.err
}

type failingModifyStore struct {
	storage.Store
	users storage.UserStore
}

func (s failingModifyStore) Users() storage.UserStore { return s.users }

func setupFailingModify(t *testing.T, modifyErr error) (*gin.Engine, *domain.User) {
	t.Helper()
	base := memory.NewStore()
	user := &domain.User{
		UUID: domain.NewUserID(),
		DID:  "did:key:modify-errors",
		WebauthnCredentials: []domain.WebauthnCredential{
			{ID: "cred-1", CredentialID: []byte("a")},
			{ID: "cred-2", CredentialID: []byte("b")},
		},
	}
	if err := base.Users().Create(context.Background(), user); err != nil {
		t.Fatal(err)
	}
	store := failingModifyStore{Store: base, users: failingModifyUsers{UserStore: base.Users(), err: modifyErr}}
	cfg := &config.Config{Server: config.ServerConfig{Host: "localhost", Port: 8080, RPID: "localhost", RPOrigin: "http://localhost:8080", RPName: "T"}, JWT: config.JWTConfig{Secret: "s", Issuer: "i"}}
	logger := zap.NewNop()
	h := NewHandlersWithStore(service.NewServices(store, cfg, logger), store, cfg, logger, []string{"test"})

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(authMiddlewareForUser(user))
	r.POST("/private-data", h.UpdatePrivateData)
	r.POST("/settings", h.UpdateSettings)
	r.POST("/webauthn/credential/:id/delete", h.DeleteWebAuthnCredential)
	r.POST("/webauthn/credential/:id/rename", h.RenameWebAuthnCredential)
	return r, user
}

// TestModifyErrorsAreNotInternalServerErrors checks that every handler that
// writes through UserStore.Modify maps a retry-exhausted conflict to a
// retryable 503 (with Retry-After), a deadline to 504 and a cancelled request
// to 503 instead of a generic 500.
func TestModifyErrorsAreNotInternalServerErrors(t *testing.T) {
	cases := []struct {
		name       string
		err        error
		wantStatus int
		retryAfter bool
	}{
		{"conflict", fmt.Errorf("failed: %w", storage.ErrConflict), http.StatusServiceUnavailable, true},
		{"deadline", fmt.Errorf("failed: %w", context.DeadlineExceeded), http.StatusGatewayTimeout, false},
		{"canceled", fmt.Errorf("failed: %w", context.Canceled), http.StatusServiceUnavailable, false},
		{"other stays 500", errors.New("boom"), http.StatusInternalServerError, false},
	}
	endpoints := []struct{ name, path, body string }{
		{"private-data", "/private-data", `{"$b64u":"AQID"}`},
		{"settings", "/settings", `{"openidRefreshTokenMaxAgeInSeconds":5}`},
		{"delete", "/webauthn/credential/cred-2/delete", ``},
		{"rename", "/webauthn/credential/cred-2/rename", `{"nickname":"x"}`},
	}
	for _, tc := range cases {
		for _, ep := range endpoints {
			t.Run(tc.name+"/"+ep.name, func(t *testing.T) {
				router, _ := setupFailingModify(t, tc.err)
				w := httptest.NewRecorder()
				req := httptest.NewRequest(http.MethodPost, ep.path, bytes.NewReader([]byte(ep.body)))
				req.Header.Set("Content-Type", "application/json")
				router.ServeHTTP(w, req)
				if w.Code != tc.wantStatus {
					t.Fatalf("status = %d, want %d: %s", w.Code, tc.wantStatus, w.Body.String())
				}
				if got := w.Header().Get("Retry-After") != ""; got != tc.retryAfter {
					t.Errorf("Retry-After present = %v, want %v", got, tc.retryAfter)
				}
			})
		}
	}
}

func TestRespondStorageUnavailable_NilAndUnrelated(t *testing.T) {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	if respondStorageUnavailable(c, errors.New("x")) {
		t.Error("unrelated error must not be handled")
	}
}

// TestDeleteWebAuthnCredential_EmptyTaggedValueSameAsEmptyBody: a tagged
// empty value ({"$b64u":""}) must be treated like an absent privateData and
// must not wipe the stored container. (Current PR behaviour; the contested
// no-privateData semantics are owned by PR 536.)
func TestDeleteWebAuthnCredential_EmptyTaggedValueSameAsEmptyBody(t *testing.T) {
	for _, body := range []string{``, `{}`, `{"privateData":null}`, `{"privateData":{"$b64u":""}}`} {
		t.Run(strings.ReplaceAll(body, `"`, "'"), func(t *testing.T) {
			handlers, router, user := setupTestHandlersWithUser(t)
			addSecondCredential(t, handlers, user)
			router.POST("/webauthn/credential/:id/delete", authMiddlewareForUser(user), handlers.DeleteWebAuthnCredential)
			before, beforeETag, _ := handlers.services.User.GetPrivateData(context.Background(), user.UUID)

			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/webauthn/credential/cred-2/delete", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			router.ServeHTTP(w, req)
			if w.Code != http.StatusNoContent {
				t.Fatalf("status = %d: %s", w.Code, w.Body.String())
			}
			after, afterETag, _ := handlers.services.User.GetPrivateData(context.Background(), user.UUID)
			if !bytes.Equal(before, after) || beforeETag != afterETag {
				t.Errorf("private data changed for body %q", body)
			}
		})
	}
}
