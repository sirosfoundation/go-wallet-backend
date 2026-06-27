package as

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

func TestExchangeCode_Success(t *testing.T) {
	// Mock token endpoint.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		ct := r.Header.Get("Content-Type")
		if ct != "application/x-www-form-urlencoded" {
			t.Errorf("expected form content type, got %s", ct)
		}
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		if r.Form.Get("grant_type") != "authorization_code" {
			t.Errorf("expected grant_type=authorization_code, got %s", r.Form.Get("grant_type"))
		}
		if r.Form.Get("code") != "test-code" {
			t.Errorf("expected code=test-code, got %s", r.Form.Get("code"))
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "at-123",
			"token_type":   "Bearer",
			"id_token":     "eyJ.test.token",
			"expires_in":   3600,
		})
	}))
	defer ts.Close()

	resp, err := exchangeCode(t.Context(), ts.URL, "test-code", "client-1", "https://example.com/callback")
	if err != nil {
		t.Fatalf("exchangeCode: %v", err)
	}
	if resp.IDToken != "eyJ.test.token" {
		t.Errorf("expected id_token eyJ.test.token, got %s", resp.IDToken)
	}
	if resp.AccessToken != "at-123" {
		t.Errorf("expected access_token at-123, got %s", resp.AccessToken)
	}
}

func TestExchangeCode_MissingIDToken(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "at-123",
			"token_type":   "Bearer",
		})
	}))
	defer ts.Close()

	_, err := exchangeCode(t.Context(), ts.URL, "code", "client", "https://example.com/cb")
	if err == nil {
		t.Fatal("expected error for missing id_token")
	}
}

func TestExchangeCode_ErrorResponse(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
	}))
	defer ts.Close()

	_, err := exchangeCode(t.Context(), ts.URL, "bad-code", "client", "https://example.com/cb")
	if err == nil {
		t.Fatal("expected error for bad status")
	}
}

func TestHasAdminClaim(t *testing.T) {
	tests := []struct {
		name   string
		claims map[string]interface{}
		want   bool
	}{
		{
			name:   "groups with admin",
			claims: map[string]interface{}{"groups": []interface{}{"users", "admin"}},
			want:   true,
		},
		{
			name:   "roles with admin",
			claims: map[string]interface{}{"roles": []interface{}{"admin"}},
			want:   true,
		},
		{
			name:   "no admin",
			claims: map[string]interface{}{"groups": []interface{}{"users"}},
			want:   false,
		},
		{
			name:   "empty claims",
			claims: map[string]interface{}{},
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hasAdminClaim(tt.claims)
			if got != tt.want {
				t.Errorf("hasAdminClaim() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRedirectURI(t *testing.T) {
	h := &OIDCHandlers{
		cfg: &config.ASConfig{
			ExternalURL: "https://auth.example.com",
		},
	}
	expected := "https://auth.example.com/auth/oidc/callback"
	if got := h.redirectURI(); got != expected {
		t.Errorf("expected %s, got %s", expected, got)
	}

	// Trailing slash in config should be stripped.
	h.cfg.ExternalURL = "https://auth.example.com/"
	if got := h.redirectURI(); got != expected {
		t.Errorf("expected %s, got %s (trailing slash)", expected, got)
	}
}

func TestHashNonce(t *testing.T) {
	nonce := "test-nonce-value"
	hash1 := hashNonce(nonce)
	hash2 := hashNonce(nonce)
	if hash1 != hash2 {
		t.Error("hashNonce should be deterministic")
	}
	if hashNonce("different") == hash1 {
		t.Error("different nonces should produce different hashes")
	}
}
