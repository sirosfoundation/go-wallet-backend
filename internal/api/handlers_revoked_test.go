package api

import (
	"context"
	"strings"
	"sync/atomic"
	"time"

	"fmt"
	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"

	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
	"github.com/sirosfoundation/go-wallet-backend/internal/tokengate"
)

// A write refused because the lifecycle fence won the race (ErrStaleWrite,
// possibly wrapped by a service) is answered like any other revoked token.
func TestAbortIfTokenRevoked_MapsStaleWriteTo401(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cases := map[string]error{
		"revoked":        tokengate.ErrRevoked,
		"stale":          storage.ErrStaleWrite,
		"wrapped stale":  fmt.Errorf("update user: %w", storage.ErrStaleWrite),
		"double wrapped": fmt.Errorf("svc: %w", fmt.Errorf("store: %w", storage.ErrStaleWrite)),
	}
	for name, err := range cases {
		t.Run(name, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			assert.True(t, abortIfTokenRevoked(c, err))
			assert.Equal(t, http.StatusUnauthorized, w.Code)
			assert.Contains(t, w.Body.String(), "Token has been revoked")
		})
	}
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	assert.False(t, abortIfTokenRevoked(c, fmt.Errorf("boom")))
}

// advancingUsers reports no cut-off for the first `after` reads and the given
// cut-off afterwards: a revocation landing while a request is in flight.
type advancingUsers struct {
	storage.UserStore
	after  int
	cutoff time.Time
	reads  int
}

func (u *advancingUsers) GetAuthCutoff(_ context.Context, _ domain.UserID) (time.Time, error) {
	u.reads++
	if u.reads <= u.after {
		return time.Time{}, nil
	}
	return u.cutoff, nil
}

// A cut-off landing between the proxy's early check and its dispatch is
// answered 401 and nothing is sent to the third party.
func TestProxyRequest_CutoffBeforeDispatchIs401(t *testing.T) {
	var hits atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	defer target.Close()

	handlers, router := setupTestHandlers(t)
	cutoff := time.Now().Truncate(time.Second)
	handlers.services.Proxy.SetUsers(&advancingUsers{after: 1, cutoff: cutoff})
	router.POST("/proxy", func(c *gin.Context) {
		c.Request = c.Request.WithContext(tokengate.WithSubject(c.Request.Context(), "u1", cutoff.Add(-time.Minute)))
		handlers.ProxyRequest(c)
	}, func(c *gin.Context) {})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/proxy", strings.NewReader(fmt.Sprintf(`{"url":%q,"method":"GET"}`, target.URL)))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code, w.Body.String())
	assert.Zero(t, hits.Load())
}
