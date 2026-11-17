package server

import (
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

func TestWarnIfMemoryStorage(t *testing.T) {
	for _, tc := range []struct {
		typ  string
		warn bool
	}{{"memory", true}, {"", true}, {"mongodb", false}} {
		core, logs := observer.New(zap.WarnLevel)
		cfg := &config.Config{}
		cfg.Storage.Type = tc.typ
		warnIfMemoryStorage(cfg, zap.New(core))
		if got := logs.Len() == 1; got != tc.warn {
			t.Errorf("type %q: warned = %v, want %v", tc.typ, got, tc.warn)
		}
	}
}
