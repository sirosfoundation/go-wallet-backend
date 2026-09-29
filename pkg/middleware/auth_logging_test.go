package middleware

import (
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
)

// Rejections must be logged server-side with a machine-readable reason (#301),
// and must never include the presented token.
func TestAuthRejectionsAreLogged(t *testing.T) {
	v, _, _ := setupTokenAuthTest(t)
	tenants := &stubTenantStore{tenants: map[domain.TenantID]*domain.Tenant{}}

	cases := []struct {
		name, header, reason string
	}{
		{"missing", "", "missing_or_malformed_bearer_token"},
		{"wrong scheme", "Basic abc", "missing_or_malformed_bearer_token"},
		{"invalid token", "Bearer secret.token.value", "token_validation_failed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			core, logs := observer.New(zap.WarnLevel)
			w := httptest.NewRecorder()
			_, r := gin.CreateTestContext(w)
			r.Use(TokenAuthMiddleware(v, tenants, nil, zap.New(core)))
			r.GET("/test", func(c *gin.Context) { c.Status(200) })

			req := httptest.NewRequest("GET", "/test", nil)
			if tc.header != "" {
				req.Header.Set("Authorization", tc.header)
			}
			r.ServeHTTP(w, req)

			if w.Code != 401 {
				t.Fatalf("expected 401, got %d", w.Code)
			}
			entries := logs.FilterMessage("Authentication rejected").All()
			if len(entries) != 1 {
				t.Fatalf("expected 1 rejection log, got %d", len(entries))
			}
			m := entries[0].ContextMap()
			if m["reason"] != tc.reason {
				t.Errorf("reason = %v, want %s", m["reason"], tc.reason)
			}
			if m["method"] != "GET" {
				t.Errorf("method = %v", m["method"])
			}
			for k, val := range m {
				if s, ok := val.(string); ok && s == "secret.token.value" {
					t.Errorf("token leaked into log field %s", k)
				}
			}
		})
	}
}
