package service

import (
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

// Services aggregates all application services
type Services struct {
	User           *UserService
	Tenant         *TenantService
	UserTenant     *UserTenantService
	WebAuthn       *WebAuthnService
	Credential     *CredentialService
	Presentation   *PresentationService
	Issuer         *IssuerService
	Verifier       *VerifierService
	Keystore       *KeystoreService
	Proxy          *ProxyService
	Helper         *HelperService
	WalletProvider *WalletProviderService
	Trust          *TrustService
}

// NewServices creates a new Services instance
func NewServices(store storage.Store, cfg *config.Config, logger *zap.Logger) *Services {
	webauthnSvc, err := NewWebAuthnService(store, cfg, logger)
	if err != nil {
		logger.Warn("Failed to create WebAuthn service", zap.Error(err))
		// Continue without WebAuthn - it will be nil
	}

	return &Services{
		User:           NewUserService(store, cfg, logger),
		Tenant:         NewTenantService(store, logger),
		UserTenant:     NewUserTenantService(store, logger),
		WebAuthn:       webauthnSvc,
		Credential:     NewCredentialService(store, cfg, logger),
		Presentation:   NewPresentationService(store, logger),
		Issuer:         NewIssuerService(store, logger),
		Verifier:       NewVerifierService(store, logger),
		Keystore:       NewKeystoreService(store, cfg, logger),
		Proxy:          NewProxyService(cfg, logger),
		Helper:         NewHelperService(logger),
		WalletProvider: NewWalletProviderService(cfg, logger),
		Trust:          NewTrustService(cfg, logger),
	}
}
