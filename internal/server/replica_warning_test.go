package server

import (
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

func TestWarnProcessLocalState(t *testing.T) {
	mk := func(asEnabled bool, asStore string, blEnabled bool, blBackend string) *config.Config {
		cfg := &config.Config{}
		cfg.Storage.Type = "mongodb"
		cfg.AS.Enabled = asEnabled
		cfg.AS.SessionStore = asStore
		cfg.Security.TokenBlacklist = config.TokenBlacklistConfig{Enabled: blEnabled, Backend: blBackend}
		return cfg
	}
	memoryStorage := mk(true, "memory", true, "memory")
	memoryStorage.Storage.Type = "memory"

	tests := []struct {
		name string
		cfg  *config.Config
		noAS bool // role without AS sessions
		want int
	}{
		{"memory storage: single process, no warning", memoryStorage, false, 0},
		{"mongodb, shared defaults", mk(true, "", true, ""), false, 0},
		{"mongodb, AS sessions in memory", mk(true, "memory", true, ""), false, 1},
		{"mongodb, AS disabled", mk(false, "memory", true, ""), false, 0},
		{"mongodb, revocations in memory", mk(true, "", true, "memory"), false, 1},
		{"mongodb, blacklist disabled", mk(true, "", false, "memory"), false, 0},
		{"mongodb, both in memory", mk(true, "memory", true, "memory"), false, 2},
		{"mongodb, both in memory, role without AS sessions", mk(true, "memory", true, "memory"), true, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			core, logs := observer.New(zap.WarnLevel)
			warnProcessLocalState(tt.cfg, zap.New(core), !tt.noAS)
			if got := logs.Len(); got != tt.want {
				t.Errorf("got %d warnings, want %d: %v", got, tt.want, logs.All())
			}
		})
	}
}
