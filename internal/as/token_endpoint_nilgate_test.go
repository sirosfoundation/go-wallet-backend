package as

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestTokenEndpoint_NilGate pins that TokenEndpointConfig.Gate is optional:
// every path mints without dereferencing a nil gate (Check is a no-op on nil).
func TestTokenEndpoint_NilGate(t *testing.T) {
	router, store, issuer := setupTokenEndpoint(t)
	_ = store.Create(context.Background(), &Session{
		JTI: "s-nilgate", UserID: "user-1", TenantID: "tenant-1",
		ACR: "urn:siros:acr:passkey", MaxTAC: TAC("rwlk"),
		CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour),
	})
	parent, err := issuer.Issue("user-1", "api", "tenant-1", TAC("rwlk"), "urn:siros:acr:passkey")
	if err != nil {
		t.Fatal(err)
	}

	post := func(name string, req TokenRequest, configure func(*http.Request)) {
		t.Helper()
		body, _ := json.Marshal(req)
		r := httptest.NewRequest(http.MethodPost, "/auth/token", bytes.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		configure(r)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("%s with a nil gate: expected 200, got %d: %s", name, w.Code, w.Body.String())
		}
	}
	withCookie := func(r *http.Request) {
		r.AddCookie(&http.Cookie{Name: sessionCookieInsecure, Value: "s-nilgate"})
	}
	post("session", TokenRequest{Audience: "api", TAC: "r"}, withCookie)
	post("anonymous", TokenRequest{Audience: "api", Anonymous: true}, withCookie)
	post("delegation", TokenRequest{Audience: "api", TAC: "r"}, func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer "+parent)
	})
}
