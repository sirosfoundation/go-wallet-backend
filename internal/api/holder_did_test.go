package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/service"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage/memory"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

// legacyAuthContext sets both "did" (== domain.HolderDID(userID)) and "user_id";
// credentials stored under that did must stay reachable via user_id alone.
func legacyAuthContext(userID string) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set("user_id", userID)
		c.Set("did", domain.HolderDID(userID))
		c.Next()
	}
}

// asAuthContext mimics pkg/middleware.TokenAuthMiddleware authenticating an
// AS-issued access token (internal/as/token.go's AccessTokenClaims): only
// "user_id" is ever set - AS tokens carry no "did" claim at all.
func asAuthContext(userID string) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set("user_id", userID)
		c.Next()
	}
}

// TestGetHolderDID_ConsistentAcrossTokenTypes: the same user gets the same holder DID with a token
// that sets "did" or an AS-issued token (which only sets "user_id").
// ever sets "user_id").
func TestGetHolderDID_ConsistentAcrossTokenTypes(t *testing.T) {
	handlers, _ := setupTestHandlers(t)
	const userID = "user-abc-123"
	want := domain.HolderDID(userID)

	t.Run("legacy token (did + user_id both set)", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		legacyAuthContext(userID)(c)

		got, ok := handlers.getHolderDID(c)
		if !ok {
			t.Fatal("expected getHolderDID to succeed")
		}
		if got != want {
			t.Errorf("legacy: got holder DID %q, want %q", got, want)
		}
	})

	t.Run("AS token (only user_id set)", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		asAuthContext(userID)(c)

		got, ok := handlers.getHolderDID(c)
		if !ok {
			t.Fatal("expected getHolderDID to succeed")
		}
		if got != want {
			t.Errorf("AS: got holder DID %q, want %q", got, want)
		}
	})

	t.Run("no identity at all", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)

		if _, ok := handlers.getHolderDID(c); ok {
			t.Error("expected getHolderDID to fail with no user_id in context")
		}
	})
}

// TestCredentialVisibleAcrossTokenTypes proves the practical consequence of
// #384: a credential stored while authenticated with one token type is
// still visible when the same user later authenticates with the other
// token type.
func TestCredentialVisibleAcrossTokenTypes(t *testing.T) {
	handlers, router := setupTestHandlers(t)
	const userID = "user-cross-token"

	router.POST("/credentials", legacyAuthContext(userID), handlers.StoreCredential)
	router.GET("/credentials", asAuthContext(userID), handlers.GetAllCredentials)

	reqBody := struct {
		Credentials []domain.StoreCredentialRequest `json:"credentials"`
	}{
		Credentials: []domain.StoreCredentialRequest{
			{
				CredentialIdentifier: "cred-cross-token-1",
				Credential:           `{"type": "VerifiableCredential"}`,
				Format:               domain.FormatJWTVC,
			},
		},
	}
	body, _ := json.Marshal(reqBody)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/credentials", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("store: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Fetch as if authenticated by an AS-issued token instead - must still
	// find the credential stored above under the legacy token.
	w = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/credentials", nil)
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("list: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp struct {
		VCList []domain.VerifiableCredential `json:"vc_list"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(resp.VCList) != 1 {
		t.Fatalf("expected 1 credential visible across token types, got %d", len(resp.VCList))
	}
	if resp.VCList[0].CredentialIdentifier != "cred-cross-token-1" {
		t.Errorf("unexpected credential: %+v", resp.VCList[0])
	}
}

// TestDeleteUser_UsesCanonicalHolderDID proves the DeleteUser handler
// resolves the same holder DID that credential storage used, rather than
// the raw user_id claim (#384) - otherwise account deletion silently fails
// to remove a user's stored credentials.
func TestDeleteUser_UsesCanonicalHolderDID(t *testing.T) {
	logger := zap.NewNop()
	cfg := &config.Config{
		Server: config.ServerConfig{RPID: "localhost", RPOrigin: "http://localhost:8080"},
		JWT:    config.JWTConfig{Secret: "test-secret", Issuer: "test-wallet"},
	}
	store := memory.NewStore()
	const userID = "user-delete-me"
	// DeleteUser's final step deletes the user row itself, which must
	// already exist for that to succeed.
	if err := store.Users().Create(context.Background(), &domain.User{
		UUID: domain.UserIDFromString(userID),
		DID:  domain.HolderDID(userID),
	}); err != nil {
		t.Fatalf("create test user: %v", err)
	}
	services := service.NewServices(store, cfg, logger)
	handlers := NewHandlers(services, cfg, logger, []string{"test"})
	router := gin.New()

	router.POST("/credentials", legacyAuthContext(userID), handlers.StoreCredential)
	router.GET("/credentials", legacyAuthContext(userID), handlers.GetAllCredentials)
	router.DELETE("/user", legacyAuthContext(userID), handlers.DeleteUser)

	reqBody := struct {
		Credentials []domain.StoreCredentialRequest `json:"credentials"`
	}{
		Credentials: []domain.StoreCredentialRequest{
			{
				CredentialIdentifier: "cred-to-be-deleted",
				Credential:           `{"type": "VerifiableCredential"}`,
				Format:               domain.FormatJWTVC,
			},
		},
	}
	body, _ := json.Marshal(reqBody)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/credentials", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("store: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	w = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodDelete, "/user", nil)
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("delete: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	w = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/credentials", nil)
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("list after delete: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp struct {
		VCList []domain.VerifiableCredential `json:"vc_list"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(resp.VCList) != 0 {
		t.Fatalf("expected credentials to be deleted, still found %d", len(resp.VCList))
	}
}
