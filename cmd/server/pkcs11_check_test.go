package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
	"github.com/sirosfoundation/go-wallet-backend/pkg/signing"
)

func TestPKCS11Problems(t *testing.T) {
	asHSM := &config.Config{AS: config.ASConfig{Enabled: true, SigningKeyPKCS11: &config.PKCS11SigningConfig{ModulePath: "/m.so"}}}
	wpWithFallback := &config.Config{WalletProvider: config.WalletProviderConfig{
		PKCS11: &config.PKCS11SigningConfig{ModulePath: "/m.so"}, PrivateKeyPath: "/k.pem"}}
	wpNoFallback := &config.Config{WalletProvider: config.WalletProviderConfig{PKCS11: &config.PKCS11SigningConfig{ModulePath: "/m.so"}}}
	asDisabled := &config.Config{AS: config.ASConfig{SigningKeyPKCS11: &config.PKCS11SigningConfig{ModulePath: "/m.so"}}}

	t.Run("supported build reports nothing", func(t *testing.T) {
		f, w := pkcs11Problems(asHSM, true)
		assert.Empty(t, f)
		assert.Empty(t, w)
	})
	t.Run("AS key is fatal", func(t *testing.T) {
		f, w := pkcs11Problems(asHSM, false)
		assert.Len(t, f, 1)
		assert.Contains(t, f[0], "as.signing_key_pkcs11")
		assert.Empty(t, w)
	})
	t.Run("AS disabled is ignored", func(t *testing.T) {
		f, w := pkcs11Problems(asDisabled, false)
		assert.Empty(t, f)
		assert.Empty(t, w)
	})
	t.Run("wallet provider with fallback warns about the fallback", func(t *testing.T) {
		f, w := pkcs11Problems(wpWithFallback, false)
		assert.Empty(t, f)
		assert.Len(t, w, 1)
		assert.Contains(t, w[0], "falls back to wallet_provider.private_key_path")
	})
	t.Run("wallet provider without fallback warns it has no key", func(t *testing.T) {
		_, w := pkcs11Problems(wpNoFallback, false)
		assert.Len(t, w, 1)
		assert.Contains(t, w[0], "no signing key")
	})
	t.Run("nil and empty config", func(t *testing.T) {
		f, w := pkcs11Problems(nil, false)
		assert.Empty(t, f)
		assert.Empty(t, w)
		f, w = pkcs11Problems(&config.Config{}, false)
		assert.Empty(t, f)
		assert.Empty(t, w)
	})
}

func TestCheckPKCS11Support_WarnsLoudlyWithHint(t *testing.T) {
	if signing.PKCS11Supported {
		t.Skip("PKCS#11 build: nothing to warn about")
	}
	core, logs := observer.New(zap.ErrorLevel)
	cfg := &config.Config{WalletProvider: config.WalletProviderConfig{
		PKCS11: &config.PKCS11SigningConfig{ModulePath: "/m.so"}, PrivateKeyPath: "/k.pem"}}
	checkPKCS11Support(cfg, zap.New(core))
	if assert.Equal(t, 1, logs.Len()) {
		e := logs.All()[0]
		assert.Contains(t, e.Message, "HSM key configured but not usable")
		assert.Equal(t, signing.PKCS11Hint, e.ContextMap()["hint"])
		assert.Contains(t, signing.PKCS11Hint, "go-wallet-backend-pkcs11")
	}
}
