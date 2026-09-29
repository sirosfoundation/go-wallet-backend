package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

func gateLimitRouter(cfg config.OIDCGateRateLimitConfig, status int) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	rl := NewOIDCGateRateLimiter(cfg, zap.NewNop())
	r.Use(func(c *gin.Context) {
		if t := c.GetHeader("X-Tenant-ID"); t != "" {
			c.Set("tenant_id", domain.TenantID(t))
		}
		c.Next()
	})
	r.Use(rl.Middleware())
	r.POST("/gate", func(c *gin.Context) {
		if status == http.StatusUnauthorized {
			c.AbortWithStatusJSON(status, gin.H{"error": "invalid token"})
			return
		}
		c.Status(status)
	})
	return r
}

func gateCall(r *gin.Engine, ip, tenant string, bearer bool) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/gate", nil)
	req.RemoteAddr = ip + ":1234"
	req.Header.Set("X-Tenant-ID", tenant)
	if bearer {
		req.Header.Set("Authorization", "Bearer x")
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func limitCfg(perIP, perTenant int) config.OIDCGateRateLimitConfig {
	return config.OIDCGateRateLimitConfig{
		PerIP:     config.AuthRateLimitConfig{Enabled: true, MaxAttempts: perIP, WindowSeconds: 60, LockoutSeconds: 60},
		PerTenant: config.AuthRateLimitConfig{Enabled: true, MaxAttempts: perTenant, WindowSeconds: 60, LockoutSeconds: 60},
	}
}

func TestOIDCGateRateLimit_PerIPRefusesWithRetryAfter(t *testing.T) {
	r := gateLimitRouter(limitCfg(2, 1000), http.StatusOK)
	var refused *httptest.ResponseRecorder
	for i := 0; i < 10 && refused == nil; i++ {
		if w := gateCall(r, "10.0.0.1", "t1", true); w.Code == http.StatusTooManyRequests {
			refused = w
		}
	}
	if refused == nil {
		t.Fatal("a single IP must be refused after its burst")
	}
	if refused.Header().Get("Retry-After") != "60" {
		t.Errorf("Retry-After = %q, want 60", refused.Header().Get("Retry-After"))
	}
	// A different IP on the same tenant is unaffected by the first one's lockout.
	if w := gateCall(r, "10.0.0.2", "t1", true); w.Code != http.StatusOK {
		t.Errorf("another IP must still be served, got %d", w.Code)
	}
}

func TestOIDCGateRateLimit_PerTenantBucketIsSharedAcrossIPs(t *testing.T) {
	r := gateLimitRouter(limitCfg(1000, 2), http.StatusOK)
	limited := false
	for i := 0; i < 10; i++ {
		ip := "10.0.1." + string(rune('1'+i))
		if gateCall(r, ip, "t1", true).Code == http.StatusTooManyRequests {
			limited = true
			break
		}
	}
	if !limited {
		t.Fatal("many IPs on one tenant must exhaust the tenant bucket")
	}
	if w := gateCall(r, "10.0.9.9", "t2", true); w.Code != http.StatusOK {
		t.Errorf("another tenant must be unaffected, got %d", w.Code)
	}
}

func TestOIDCGateRateLimit_RequestsWithoutTokenAreNotCounted(t *testing.T) {
	r := gateLimitRouter(limitCfg(2, 2), http.StatusOK)
	for i := 0; i < 50; i++ {
		if w := gateCall(r, "10.0.0.1", "t1", false); w.Code != http.StatusOK {
			t.Fatalf("token-less request %d was limited (%d)", i, w.Code)
		}
	}
	if w := gateCall(r, "10.0.0.1", "t1", true); w.Code != http.StatusOK {
		t.Errorf("first tokened request must pass after token-less traffic, got %d", w.Code)
	}
}

// A refused token costs two tokens, so failing clients hit the limit sooner
// than succeeding ones.
func TestOIDCGateRateLimit_FailuresCostMore(t *testing.T) {
	served := func(status int) int {
		r := gateLimitRouter(limitCfg(10, 1000), status)
		n := 0
		for i := 0; i < 50; i++ {
			if gateCall(r, "10.0.0.1", "t1", true).Code == http.StatusTooManyRequests {
				break
			}
			n++
		}
		return n
	}
	ok, failing := served(http.StatusOK), served(http.StatusUnauthorized)
	if failing >= ok {
		t.Errorf("failures must exhaust the limit sooner: ok=%d failing=%d", ok, failing)
	}
}

func TestOIDCGateRateLimit_DisabledPassesEverything(t *testing.T) {
	cfg := limitCfg(1, 1)
	cfg.PerIP.Enabled, cfg.PerTenant.Enabled = false, false
	r := gateLimitRouter(cfg, http.StatusOK)
	for i := 0; i < 30; i++ {
		if w := gateCall(r, "10.0.0.1", "t1", true); w.Code != http.StatusOK {
			t.Fatalf("disabled limiter refused request %d", i)
		}
	}
}
