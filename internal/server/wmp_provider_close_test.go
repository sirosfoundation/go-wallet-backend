package server

import (
	"runtime"
	"testing"
	"time"

	"go.uber.org/zap"

	wsengine "github.com/sirosfoundation/go-wallet-backend/internal/engine"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

// EngineProvider.Close must stop the WMP adapter's cleanup goroutine.
func TestEngineProvider_Close_StopsWMPAdapter(t *testing.T) {
	logger := zap.NewNop()
	cfg := &config.Config{}
	manager := wsengine.NewManager(cfg, logger)

	before := runtime.NumGoroutine()
	adapter := wsengine.NewWMPAdapter(manager, logger)
	if runtime.NumGoroutine() <= before {
		t.Fatal("expected the adapter to start a goroutine")
	}

	provider := &EngineProvider{cfg: cfg, logger: logger, manager: manager, wmpAdapter: adapter}
	provider.Close()

	deadline := time.Now().Add(2 * time.Second)
	for runtime.NumGoroutine() > before && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := runtime.NumGoroutine(); got > before {
		t.Fatalf("goroutine leaked after Close: before=%d after=%d", before, got)
	}
}
