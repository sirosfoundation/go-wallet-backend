package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

func TestLogLegacyStatus_OncePerProcess(t *testing.T) {
	cases := map[string]config.ASConfig{
		"backend without AS":          {},
		"AS enabled":                  {Enabled: true},
		"standalone engine/wallet-pr": {Enabled: false},
	}
	for name, as := range cases {
		t.Run(name, func(t *testing.T) {
			core, logs := observer.New(zap.InfoLevel)
			logLegacyStatus(&config.Config{AS: as}, nil, zap.New(core))
			assert.Equal(t, 1, logs.Len())
		})
	}
}

func TestLogLegacyStatus_NilConfigLogsNothing(t *testing.T) {
	core, logs := observer.New(zap.InfoLevel)
	logLegacyStatus(nil, nil, zap.New(core))
	assert.Equal(t, 0, logs.Len())
}

// A registry-only process has no legacy AS to report on, but still warns about
// leftover removed settings it was given (once each).
func TestLogLegacyStatus_RegistryOnly(t *testing.T) {
	no := false
	core, logs := observer.New(zap.InfoLevel)
	logLegacyStatus(nil, &config.Config{AS: config.ASConfig{Legacy: config.ASLegacyConfig{Enabled: &no, SunsetDate: "2027-01-01"}}}, zap.New(core))
	assert.Equal(t, 2, logs.Len())

	core, logs = observer.New(zap.InfoLevel)
	logLegacyStatus(nil, &config.Config{}, zap.New(core))
	assert.Equal(t, 0, logs.Len())
}
