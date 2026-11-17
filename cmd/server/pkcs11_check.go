package main

import (
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
	"github.com/sirosfoundation/go-wallet-backend/pkg/signing"
)

// pkcs11Problems lists configured HSM keys this binary cannot use because it
// was built without PKCS#11 support. fatal entries would stop startup anyway;
// warn entries would otherwise degrade silently.
func pkcs11Problems(cfg *config.Config, supported bool) (fatal, warn []string) {
	if cfg == nil || supported {
		return nil, nil
	}
	if cfg.AS.Enabled && cfg.AS.SigningKeyPKCS11 != nil {
		fatal = append(fatal, "as.signing_key_pkcs11 is configured")
	}
	if wp := cfg.WalletProvider.PKCS11; wp != nil && wp.ModulePath != "" {
		if cfg.WalletProvider.PrivateKeyPath != "" {
			warn = append(warn, "wallet_provider.pkcs11 is configured; the HSM key will NOT be used and signing falls back to wallet_provider.private_key_path")
		} else {
			warn = append(warn, "wallet_provider.pkcs11 is configured and there is no private_key_path fallback; the wallet provider will have no signing key")
		}
	}
	return fatal, warn
}

// checkPKCS11Support turns pkcs11Problems into startup messages (fatal without
// a stack trace, or loud errors).
func checkPKCS11Support(cfg *config.Config, logger *zap.Logger) {
	fatal, warn := pkcs11Problems(cfg, signing.PKCS11Supported)
	for _, w := range warn {
		logger.Error("HSM key configured but not usable: "+w, zap.String("hint", signing.PKCS11Hint))
	}
	if len(fatal) > 0 {
		logger.WithOptions(zap.AddStacktrace(zapcore.FatalLevel+1)).Fatal(
			"HSM key configured but this build cannot use it: "+fatal[0],
			zap.String("hint", signing.PKCS11Hint))
	}
}
