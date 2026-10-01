package api

import (
	"fmt"
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
