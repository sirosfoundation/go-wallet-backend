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
			logLegacyStatus(&config.Config{AS: as}, zap.New(core))
			assert.Equal(t, 1, logs.Len())
		})
	}
}

func TestLogLegacyStatus_NilConfigLogsNothing(t *testing.T) {
	core, logs := observer.New(zap.InfoLevel)
	logLegacyStatus(nil, zap.New(core))
	assert.Equal(t, 0, logs.Len())
}
