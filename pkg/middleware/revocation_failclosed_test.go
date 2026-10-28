package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/sirosfoundation/go-tokenauth/claims"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/service"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

// errStore is a RevocationStore whose every call fails, like an unreachable
// database.
type errStore struct{}

var errStoreDown = errors.New("store down")

func (errStore) Add(context.Context, string, time.Time) error { return errStoreDown }
func (errStore) Has(context.Context, string) (bool, error)    { return false, errStoreDown }
func (errStore) RevokeUser(context.Context, string) error     { return errStoreDown }
func (errStore) IsUserRevoked(context.Context, string) (bool, error) {
	return false, errStoreDown
}

// failingChecker fails only the selected lookup.
type failingChecker struct{ jti, user bool }

func (f failingChecker) IsBlacklisted(context.Context, string) (bool, error) {
	if f.jti {
		return false, errStoreDown
	}
	return false, nil
}

func (f failingChecker) IsUserRevoked(context.Context, string) (bool, error) {
	if f.user {
		return false, errStoreDown
	}
	return false, nil
}

func TestTokenAuthMiddleware_StoreErrorRefuses(t *testing.T) {
	v, key, issuer := setupTokenAuthTest(t)
	tenants := &stubTenantStore{tenants: map[domain.TenantID]*domain.Tenant{
		"test-tenant": {ID: "test-tenant", Enabled: true},
	}}
	token := signToken(t, key, issuer, claims.AccessTokenClaims{
		Claims:   jwt.Claims{Subject: "user-1", Audience: jwt.Audience{testTokenAudience}},
		TenantID: "test-tenant",
		TAC:      "rwl",
	})

	for name, bl := range map[string]TokenBlacklistChecker{
		"user lookup fails": failingChecker{user: true},
		"real blacklist over an unreachable store": service.NewTokenBlacklistWithStore(
			config.TokenBlacklistConfig{Enabled: true}, zap.NewNop(), errStore{}),
	} {
		t.Run(name, func(t *testing.T) {
			w := httptest.NewRecorder()
			_, r := gin.CreateTestContext(w)
			r.Use(TokenAuthMiddleware(v, tenants, bl, emptyUsers(), zap.NewNop()))
			r.GET("/test", func(c *gin.Context) { c.Status(200) })
			req := httptest.NewRequest("GET", "/test", nil)
			req.Header.Set("Authorization", "Bearer "+token)
			r.ServeHTTP(w, req)

			if w.Code != http.StatusServiceUnavailable {
				t.Fatalf("expected 503 when the user revocation check fails, got %d: %s", w.Code, w.Body.String())
			}
			if strings.Contains(w.Body.String(), token) {
				t.Error("response must not contain token content")
			}
		})
	}
}
