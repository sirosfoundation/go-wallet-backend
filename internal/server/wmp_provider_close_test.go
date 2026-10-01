package server

import (
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	wsengine "github.com/sirosfoundation/go-wallet-backend/internal/engine"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
	"github.com/sirosfoundation/go-wallet-backend/pkg/middleware"
)

// cleanupLoops counts live WMP adapter cleanup goroutines, by looking for them
// in a full goroutine dump. Counting goroutines with
// runtime.NumGoroutine is racy: unrelated goroutines from earlier tests exit
// concurrently and skew the count in either direction.
func cleanupLoops() int {
	buf := make([]byte, 1<<20)
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			return strings.Count(string(buf[:n]), "(*WMPAdapter).cleanupLoop")
		}
		buf = make([]byte, 2*len(buf))
	}
}

// EngineProvider.Close must stop the WMP adapter's cleanup goroutine.
func TestEngineProvider_Close_StopsWMPAdapter(t *testing.T) {
	logger := zap.NewNop()
	cfg := &config.Config{}
	manager := wsengine.NewManager(cfg, logger)

	// Tests running concurrently in this package may hold live adapters of
	// their own, so compare against the baseline rather than expecting zero.
	before := cleanupLoops()
	adapter := wsengine.NewWMPAdapter(manager, logger, middleware.ExtractBearerToken)
	if cleanupLoops() != before+1 {
		t.Fatal("expected the adapter to start its cleanup goroutine")
	}

	provider := &EngineProvider{cfg: cfg, logger: logger, manager: manager, wmpAdapter: adapter}
	provider.Close()

	deadline := time.Now().Add(2 * time.Second)
	for cleanupLoops() > before && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if cleanupLoops() > before {
		t.Fatal("WMP cleanup goroutine still running after Close")
	}
}

// Closing the provider drains the WMP routes before sessions are closed: new
// RPC and SSE requests are refused with 503.
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
