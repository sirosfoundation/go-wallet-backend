package middleware

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
)

const leakProbe = "secret.token.value"

// Rejections must be logged server-side with a machine-readable reason (#301),
// and must never include the presented token.
func TestAuthRejectionsAreLogged(t *testing.T) {
	v, _, _ := setupTokenAuthTest(t)
	tenants := &stubTenantStore{tenants: map[domain.TenantID]*domain.Tenant{}}
	cfg := createTestConfig("test-secret")
	store := createTestStore()

	type mw func(*zap.Logger) gin.HandlerFunc
	middlewares := map[string]mw{
		"tokenauth": func(l *zap.Logger) gin.HandlerFunc { return TokenAuthMiddleware(v, tenants, nil, l) },
		"legacy":    func(l *zap.Logger) gin.HandlerFunc { return AuthMiddlewareWithBlacklist(cfg, store, nil, l) },
		"admin":     func(l *zap.Logger) gin.HandlerFunc { return AdminAuthMiddleware("admin-secret", l) },
	}

	cases := []struct {
		name, header string
		reasons      map[string]string // middleware -> expected reason
	}{
		{"missing header", "", map[string]string{
			"tokenauth": "missing_or_malformed_bearer_token",
			"legacy":    "missing_authorization_header",
			"admin":     "missing_authorization_header",
		}},
		{"wrong scheme", "Basic " + leakProbe, map[string]string{
			"tokenauth": "missing_or_malformed_bearer_token",
			"legacy":    "malformed_authorization_header",
			"admin":     "malformed_authorization_header",
		}},
		{"empty token", "Bearer ", map[string]string{
			"tokenauth": "missing_or_malformed_bearer_token",
			"legacy":    "empty_bearer_token",
			"admin":     "empty_bearer_token",
		}},
		{"invalid token", "Bearer " + leakProbe, map[string]string{
			"tokenauth": "token_validation_failed",
			"legacy":    "invalid_token",
			"admin":     "invalid_admin_token",
		}},
	}
	for name, build := range middlewares {
		for _, tc := range cases {
			t.Run(name+"/"+tc.name, func(t *testing.T) {
				core, logs := observer.New(zap.WarnLevel)
				w := httptest.NewRecorder()
				_, r := gin.CreateTestContext(w)
				r.Use(build(zap.New(core)))
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
					t.Fatalf("expected 1 rejection log, got %d (all: %v)", len(entries), logs.All())
				}
				m := entries[0].ContextMap()
				if m["reason"] != tc.reasons[name] {
					t.Errorf("reason = %v, want %s", m["reason"], tc.reasons[name])
				}
				if m["method"] != "GET" {
					t.Errorf("method = %v", m["method"])
				}
				// The token must appear nowhere: not in the message, not in
				// any field, not embedded in an error string.
				for _, e := range logs.All() {
					if strings.Contains(e.Message, leakProbe) {
						t.Errorf("token leaked into log message %q", e.Message)
					}
					for k, val := range e.ContextMap() {
						if s, ok := val.(string); ok && strings.Contains(s, leakProbe) {
							t.Errorf("token leaked into log field %s=%q", k, s)
						}
					}
				}
			})
		}
	}
}
