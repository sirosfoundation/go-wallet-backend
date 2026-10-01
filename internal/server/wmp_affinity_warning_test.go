package server

import (
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	wsengine "github.com/sirosfoundation/go-wallet-backend/internal/engine"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
	"github.com/sirosfoundation/go-wallet-backend/pkg/middleware"
)

// Mounting the WMP routes warns, exactly once, that WMP session state is
// process-local and multi-replica deployments need session-ID affinity (#432).
func TestEngineProvider_RegisterRoutes_WarnsAboutWMPSessionAffinity(t *testing.T) {
	gin.SetMode(gin.TestMode)
	core, logs := observer.New(zapcore.WarnLevel)
	logger := zap.New(core)

	cfg := &config.Config{}
	manager := wsengine.NewManager(cfg, zap.NewNop())
	adapter := wsengine.NewWMPAdapter(manager, zap.NewNop(), middleware.ExtractBearerToken)
	provider := &EngineProvider{cfg: cfg, logger: logger, manager: manager, wmpAdapter: adapter}
	defer provider.Close()

	provider.RegisterRoutes(gin.New())
	provider.RegisterRoutes(gin.New()) // a second mount must not repeat the warning

	var found []observer.LoggedEntry
	for _, e := range logs.All() {
		if strings.Contains(e.Message, "WMP session state is process-local") {
			found = append(found, e)
		}
	}
	if len(found) != 1 {
		t.Fatalf("expected exactly one affinity warning, got %d (all logs: %v)", len(found), logs.All())
	}
	if found[0].Level != zapcore.WarnLevel {
		t.Errorf("expected Warn level, got %s", found[0].Level)
	}
	for _, want := range []string{"Authorization", "Wmp-Session-Id", "params.wmp.session_id", "session_id query", "refreshed token", "issues/432"} {
		if !strings.Contains(found[0].Message, want) {
			t.Errorf("warning does not mention %q: %s", want, found[0].Message)
		}
	}
}
