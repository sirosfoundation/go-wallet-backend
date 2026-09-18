package server

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

// Without persistent storage there is no user record to consult, so a
// standalone engine gets no gate (and main logs a warning).
func TestNewStandaloneTokenGate_NoPersistentStorage(t *testing.T) {
	for _, typ := range []string{"", "memory"} {
		gate, closer, err := NewStandaloneTokenGate(context.Background(), &config.Config{Storage: config.StorageConfig{Type: typ}})
		require.NoError(t, err, typ)
		assert.Nil(t, gate, typ)
		assert.Nil(t, closer, typ)
	}
	gate, closer, err := NewStandaloneTokenGate(context.Background(), nil)
	require.NoError(t, err)
	assert.Nil(t, gate)
	assert.Nil(t, closer)
}
