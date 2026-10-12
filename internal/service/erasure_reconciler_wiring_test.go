package service

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/storage/memory"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

func TestServices_ReconcilerIsWiredAndStoppable(t *testing.T) {
	cfg := testConfig()
	cfg.Lifecycle.Reconciler = config.ErasureReconcilerConfig{Enabled: true, IntervalSeconds: 60, GracePeriodSeconds: 60, BatchSize: 5}
	svcs := NewServices(memory.NewStore(), cfg, zap.NewNop())
	require.NotNil(t, svcs.Reconciler)
	svcs.Start()
	svcs.Stop()

	cfg.Lifecycle.Reconciler.Enabled = false
	assert.Nil(t, NewServices(memory.NewStore(), cfg, zap.NewNop()).Reconciler)
}
