package server

import (
	"testing"

	"go.mongodb.org/mongo-driver/mongo"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage/memory"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

type mongoLikeStore struct{ storage.Store }

func (mongoLikeStore) Database() *mongo.Database { return nil }

func TestWarnProcessLocalState(t *testing.T) {
	mk := func(asEnabled bool, asStore string, blEnabled bool, blBackend string) *config.Config {
		cfg := &config.Config{}
		cfg.AS.Enabled = asEnabled
		cfg.AS.SessionStore = asStore
		cfg.Security.TokenBlacklist = config.TokenBlacklistConfig{Enabled: blEnabled, Backend: blBackend}
		return cfg
	}
	mongoStore := mongoLikeStore{memory.NewStore()}

	tests := []struct {
		name  string
		cfg   *config.Config
		store storage.Store
		want  int
	}{
		{"memory storage: single process, no warning", mk(true, "memory", true, "memory"), memory.NewStore(), 0},
		{"mongodb, shared defaults", mk(true, "", true, ""), mongoStore, 0},
		{"mongodb, AS sessions in memory", mk(true, "memory", true, ""), mongoStore, 1},
		{"mongodb, AS disabled", mk(false, "memory", true, ""), mongoStore, 0},
		{"mongodb, revocations in memory", mk(true, "", true, "memory"), mongoStore, 1},
		{"mongodb, blacklist disabled", mk(true, "", false, "memory"), mongoStore, 0},
		{"mongodb, both in memory", mk(true, "memory", true, "memory"), mongoStore, 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			core, logs := observer.New(zap.WarnLevel)
			warnProcessLocalState(tt.cfg, tt.store, zap.New(core))
			if got := logs.Len(); got != tt.want {
				t.Errorf("got %d warnings, want %d: %v", got, tt.want, logs.All())
			}
		})
	}
}
