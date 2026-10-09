package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	wsengine "github.com/sirosfoundation/go-wallet-backend/internal/engine"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
	"github.com/sirosfoundation/go-wallet-backend/pkg/middleware"
)

// EngineProvider.Close must stop the WMP adapter's cleanup goroutine, observed via
// the adapter's own lifecycle signals.
func TestEngineProvider_Close_StopsWMPAdapter(t *testing.T) {
	logger := zap.NewNop()
	cfg := &config.Config{}
	manager := wsengine.NewManager(cfg, logger)

	adapter := wsengine.NewWMPAdapter(manager, logger, middleware.ExtractBearerToken)
	select {
	case <-adapter.CleanupStarted():
	case <-time.After(5 * time.Second):
		t.Fatal("expected the adapter to start its cleanup goroutine")
	}

	provider := &EngineProvider{cfg: cfg, logger: logger, manager: manager, wmpAdapter: adapter}
	provider.Close()

	select {
	case <-adapter.CleanupStopped():
	case <-time.After(5 * time.Second):
		t.Fatal("WMP cleanup goroutine still running after Close")
	}
}

// Closing the provider drains the WMP routes first: new RPC and SSE requests get 503.
func TestEngineProvider_Close_RejectsNewWMPRequests(t *testing.T) {
	logger := zap.NewNop()
	cfg := &config.Config{}
	manager := wsengine.NewManager(cfg, logger)
	adapter := wsengine.NewWMPAdapter(manager, logger, middleware.ExtractBearerToken)
	provider := &EngineProvider{cfg: cfg, logger: logger, manager: manager, wmpAdapter: adapter}

	gin.SetMode(gin.TestMode)
	r := gin.New()
	provider.RegisterRoutes(r)
	provider.Close()

	for _, tc := range []struct{ method, path string }{
		{http.MethodPost, wsengine.WMPRPCPath},
		{http.MethodGet, wsengine.WMPEventsPath + "?session_id=x"},
	} {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(tc.method, tc.path, nil))
		if w.Code != http.StatusServiceUnavailable {
			t.Fatalf("%s %s = %d, want 503", tc.method, tc.path, w.Code)
		}
	}
}
