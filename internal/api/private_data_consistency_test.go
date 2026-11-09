package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/pkg/taggedbinary"
)

// Tests in this file guard against the private-data consistency issues that
// surfaced as ?sync=fail in the wallet frontend (see sync_fail_backend.md).

// mutateUser applies fn to the stored user directly via the store.
func mutateUser(t *testing.T, h *Handlers, id domain.UserID, fn func(u *domain.User)) {
	t.Helper()
	if _, err := h.store.Users().Modify(context.Background(), id, func(u *domain.User) error {
		fn(u)
		return nil
	}); err != nil {
		t.Fatalf("failed to mutate user: %v", err)
	}
}

func addSecondCredential(t *testing.T, h *Handlers, user *domain.User) {
	t.Helper()
	mutateUser(t, h, user.UUID, func(u *domain.User) {
		u.WebauthnCredentials = append(u.WebauthnCredentials, domain.WebauthnCredential{
			ID:           "cred-2",
			CredentialID: []byte("credential-id-bytes-2"),
			PublicKey:    []byte("public-key-bytes-2"),
			CreatedAt:    time.Now(),
		})
	})
}

func postPrivateData(router *gin.Engine, data []byte, ifMatch string) *httptest.ResponseRecorder {
	body, _ := json.Marshal(taggedbinary.TaggedBytes(data))
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/private-data", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if ifMatch != "" {
		req.Header.Set("X-Private-Data-If-Match", ifMatch)
	}
	router.ServeHTTP(w, req)
	return w
}

func TestPrivateData_ConcurrentPostsSameIfMatch(t *testing.T) {
	handlers, router, user := setupTestHandlersWithUser(t)
	router.POST("/private-data", authMiddlewareForUser(user), handlers.UpdatePrivateData)

	_, etag, err := handlers.services.User.GetPrivateData(context.Background(), user.UUID)
	if err != nil {
		t.Fatalf("GetPrivateData() error = %v", err)
	}

	const n = 20
	codes := make([]int, n)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			w := postPrivateData(router, []byte{byte('a' + i)}, etag)
			codes[i] = w.Code
		}(i)
	}
	close(start)
	wg.Wait()

	ok, conflict := 0, 0
	for _, c := range codes {
		switch c {
		case http.StatusNoContent:
			ok++
		case http.StatusPreconditionFailed:
			conflict++
		default:
			t.Errorf("unexpected status %d", c)
		}
	}
	if ok != 1 || conflict != n-1 {
		t.Errorf("expected exactly 1 success and %d conflicts, got %d successes and %d conflicts", n-1, ok, conflict)
	}
}

func TestPrivateData_ConflictReturnsCurrentETag(t *testing.T) {
	handlers, router, user := setupTestHandlersWithUser(t)
	router.POST("/private-data", authMiddlewareForUser(user), handlers.UpdatePrivateData)

	w := postPrivateData(router, []byte("x"), `"stale"`)
	if w.Code != http.StatusPreconditionFailed {
		t.Fatalf("expected 412, got %d", w.Code)
	}
	_, current, _ := handlers.services.User.GetPrivateData(context.Background(), user.UUID)
	if got := w.Header().Get("X-Private-Data-ETag"); got != current {
		t.Errorf("412 ETag = %q, want current %q", got, current)
	}
}

// Non-private-data writers running concurrently with a chain of private-data
// updates must never roll back private data. With the old full-document
// snapshot writes this produced spurious 412s in the chain.
func TestPrivateData_NotRolledBackByConcurrentWriters(t *testing.T) {
	handlers, router, user := setupTestHandlersWithUser(t)
	auth := authMiddlewareForUser(user)
	router.POST("/private-data", auth, handlers.UpdatePrivateData)
	router.POST("/settings", auth, handlers.UpdateSettings)
	router.POST("/webauthn/credential/:id/rename", auth, handlers.RenameWebAuthnCredential)

	_, etag, _ := handlers.services.User.GetPrivateData(context.Background(), user.UUID)

	const iterations = 100
	done := make(chan struct{})
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-done:
				return
			default:
			}
			body := `{"openidRefreshTokenMaxAgeInSeconds": ` + string(rune('1'+i%9)) + `}`
			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/settings", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			router.ServeHTTP(w, req)

			w = httptest.NewRecorder()
			req = httptest.NewRequest(http.MethodPost, "/webauthn/credential/cred-1/rename", strings.NewReader(`{"nickname":"n"}`))
			req.Header.Set("Content-Type", "application/json")
			router.ServeHTTP(w, req)
		}
	}()

	var last []byte
	for i := 0; i < iterations; i++ {
		last = []byte{byte(i), byte(i >> 8), 'p'}
		w := postPrivateData(router, last, etag)
		if w.Code != http.StatusNoContent {
			close(done)
			wg.Wait()
			t.Fatalf("iteration %d: expected 204, got %d (private data rolled back by a concurrent writer?)", i, w.Code)
		}
		etag = w.Header().Get("X-Private-Data-ETag")
	}
	close(done)
	wg.Wait()

	data, finalETag, _ := handlers.services.User.GetPrivateData(context.Background(), user.UUID)
	if !bytes.Equal(data, last) || finalETag != etag {
		t.Errorf("final private data/etag do not match last successful POST")
	}
}

func TestUpdateSettings_PreservesPrivateData(t *testing.T) {
	handlers, router, user := setupTestHandlersWithUser(t)
	router.POST("/settings", authMiddlewareForUser(user), handlers.UpdateSettings)

	before, beforeETag, _ := handlers.services.User.GetPrivateData(context.Background(), user.UUID)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/settings", strings.NewReader(`{"openidRefreshTokenMaxAgeInSeconds": 42}`))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	after, afterETag, _ := handlers.services.User.GetPrivateData(context.Background(), user.UUID)
	if !bytes.Equal(before, after) || beforeETag != afterETag {
		t.Error("UpdateSettings must not modify private data")
	}
	u, _ := handlers.services.User.GetUserByID(context.Background(), user.UUID)
	if u.OpenIDRefreshTokenMaxAge != 42 {
		t.Errorf("OpenIDRefreshTokenMaxAge = %d, want 42", u.OpenIDRefreshTokenMaxAge)
	}
}

func TestDeleteWebAuthnCredential_EmptyBodyPreservesPrivateData(t *testing.T) {
	handlers, router, user := setupTestHandlersWithUser(t)
	addSecondCredential(t, handlers, user)
	router.POST("/webauthn/credential/:id/delete", authMiddlewareForUser(user), handlers.DeleteWebAuthnCredential)

	before, beforeETag, _ := handlers.services.User.GetPrivateData(context.Background(), user.UUID)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/webauthn/credential/cred-2/delete", nil)
	router.ServeHTTP(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", w.Code, w.Body.String())
	}
	if got := w.Header().Get("X-Private-Data-ETag"); got != beforeETag {
		t.Errorf("response ETag = %q, want unchanged %q", got, beforeETag)
	}

	after, afterETag, _ := handlers.services.User.GetPrivateData(context.Background(), user.UUID)
	if !bytes.Equal(before, after) || beforeETag != afterETag {
		t.Error("deleting a passkey without privateData must not modify private data")
	}
	u, _ := handlers.services.User.GetUserByID(context.Background(), user.UUID)
	if len(u.WebauthnCredentials) != 1 {
		t.Errorf("expected 1 credential left, got %d", len(u.WebauthnCredentials))
	}
}

func TestDeleteWebAuthnCredential_MalformedBodyRejected(t *testing.T) {
	handlers, router, user := setupTestHandlersWithUser(t)
	addSecondCredential(t, handlers, user)
	router.POST("/webauthn/credential/:id/delete", authMiddlewareForUser(user), handlers.DeleteWebAuthnCredential)

	before, _, _ := handlers.services.User.GetPrivateData(context.Background(), user.UUID)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/webauthn/credential/cred-2/delete", strings.NewReader(`{not json`))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}

	after, _, _ := handlers.services.User.GetPrivateData(context.Background(), user.UUID)
	if !bytes.Equal(before, after) {
		t.Error("malformed body must not modify private data")
	}
	u, _ := handlers.services.User.GetUserByID(context.Background(), user.UUID)
	if len(u.WebauthnCredentials) != 2 {
		t.Errorf("malformed body must not delete the credential; have %d", len(u.WebauthnCredentials))
	}
}

func TestDeleteWebAuthnCredential_WithPrivateDataUpdatesIt(t *testing.T) {
	handlers, router, user := setupTestHandlersWithUser(t)
	addSecondCredential(t, handlers, user)
	router.POST("/webauthn/credential/:id/delete", authMiddlewareForUser(user), handlers.DeleteWebAuthnCredential)

	_, etag, _ := handlers.services.User.GetPrivateData(context.Background(), user.UUID)
	newData := []byte(`{"after":"delete"}`)
	body, _ := json.Marshal(map[string]any{"privateData": taggedbinary.TaggedBytes(newData)})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/webauthn/credential/cred-2/delete", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Private-Data-If-Match", etag)
	router.ServeHTTP(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", w.Code, w.Body.String())
	}

	data, newETag, _ := handlers.services.User.GetPrivateData(context.Background(), user.UUID)
	if !bytes.Equal(data, newData) {
		t.Errorf("private data = %q, want %q", data, newData)
	}
	if got := w.Header().Get("X-Private-Data-ETag"); got != newETag || newETag != domain.ComputePrivateDataETag(newData) {
		t.Errorf("ETag mismatch: header %q, stored %q", got, newETag)
	}
}

func TestGetPrivateData_EmptyStoredETag(t *testing.T) {
	handlers, router, user := setupTestHandlersWithUser(t)
	router.GET("/private-data", authMiddlewareForUser(user), handlers.GetPrivateData)
	router.POST("/private-data", authMiddlewareForUser(user), handlers.UpdatePrivateData)

	// Simulate a legacy/imported record with no stored ETag.
	var data []byte
	mutateUser(t, handlers, user.UUID, func(u *domain.User) {
		u.PrivateDataETag = ""
		data = u.PrivateData
	})
	wantETag := domain.ComputePrivateDataETag(data)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/private-data", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 with no If-None-Match, got %d", w.Code)
	}
	if got := w.Header().Get("X-Private-Data-ETag"); got != wantETag {
		t.Errorf("ETag = %q, want computed %q", got, wantETag)
	}

	// The computed ETag must be usable for a conditional POST.
	if w := postPrivateData(router, []byte("next"), wantETag); w.Code != http.StatusNoContent {
		t.Errorf("conditional POST with computed ETag: expected 204, got %d", w.Code)
	}
}
