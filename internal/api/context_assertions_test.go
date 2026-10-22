package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

// TestHandlers_NonStringUserID_FailsClosed proves every handler that reads
// "user_id" from the gin context answers 401 - rather than panicking on an
// unchecked type assertion - when the value is present but is not a string.
// The router deliberately has no Recovery middleware, so a panic fails the
// test.
func TestHandlers_NonStringUserID_FailsClosed(t *testing.T) {
	handlers, router := setupLogoutTestHandlers(t)

	router.Use(func(c *gin.Context) {
		c.Set("user_id", 12345) // wrong type
		c.Next()
	})
	routes := []struct {
		method  string
		path    string
		handler gin.HandlerFunc
	}{
		{http.MethodGet, "/private-data", handlers.GetPrivateData},
		{http.MethodPut, "/private-data", handlers.UpdatePrivateData},
		{http.MethodDelete, "/user", handlers.DeleteUser},
		{http.MethodGet, "/account-info", handlers.GetAccountInfo},
		{http.MethodPost, "/settings", handlers.UpdateSettings},
		{http.MethodPost, "/webauthn/add/start", handlers.StartAddWebAuthnCredential},
		{http.MethodPost, "/webauthn/add/finish", handlers.FinishAddWebAuthnCredential},
		{http.MethodDelete, "/webauthn/credential/:id", handlers.DeleteWebAuthnCredential},
		{http.MethodPatch, "/webauthn/credential/:id", handlers.RenameWebAuthnCredential},
		{http.MethodGet, "/keystore/status", handlers.KeystoreStatus},
	}
	for _, r := range routes {
		router.Handle(r.method, r.path, r.handler)
	}

	for _, r := range routes {
		t.Run(r.method+" "+r.path, func(t *testing.T) {
			w := httptest.NewRecorder()
			req := httptest.NewRequest(r.method, r.path, nil)
			router.ServeHTTP(w, req)
			if w.Code != http.StatusUnauthorized {
				t.Errorf("expected 401, got %d: %s", w.Code, w.Body.String())
			}
		})
	}
}

func TestHandlers_getHolderDID_NonStringUserID(t *testing.T) {
	handlers, _ := setupLogoutTestHandlers(t)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Set("user_id", 12345)
	if did, ok := handlers.getHolderDID(c); ok || did != "" {
		t.Errorf("expected (\"\", false), got (%q, %v)", did, ok)
	}
}

// TestHandlers_Logout_NonStringToken proves a non-string "token" context
// value is ignored by Logout (the legacy HMAC token path is gone): it neither
// panics nor fails the request.
func TestHandlers_Logout_NonStringToken(t *testing.T) {
	handlers, router := setupLogoutTestHandlers(t)
	router.POST("/logout", func(c *gin.Context) {
		c.Set("token", 42)
		handlers.Logout(c)
	})

	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/logout", nil))
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}
