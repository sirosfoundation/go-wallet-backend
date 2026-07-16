package service

import (
	"context"

	"go.mongodb.org/mongo-driver/mongo"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

// Services aggregates all application services
type Services struct {
	User             *UserService
	Tenant           *TenantService
	UserTenant       *UserTenantService
	WebAuthn         *WebAuthnService
	Credential       *CredentialService
	Issuer           *IssuerService
	Verifier         *VerifierService
	Keystore         *KeystoreService
	Proxy            *ProxyService
	Helper           *HelperService
	WalletProvider   *WalletProviderService
	WIA              *WIAService
	TokenBlacklist   *TokenBlacklist
	ChallengeCleanup *ChallengeCleanupWorker
	AAGUIDValidator  *AAGUIDValidator
}

// NewServices creates a new Services instance
func NewServices(store storage.Store, cfg *config.Config, logger *zap.Logger) *Services {
	// Create AAGUID validator first since WebAuthn service needs it
	aaguidValidator := NewAAGUIDValidator(cfg.Security.AAGUIDBlacklist, logger)

	webauthnSvc, err := NewWebAuthnServiceWithValidator(store, cfg, logger, aaguidValidator)
	if err != nil {
		logger.Warn("Failed to create WebAuthn service", zap.Error(err))
		// Continue without WebAuthn - it will be nil
	}

	wpSvc := NewWalletProviderService(cfg, logger)

	// WIA shares the same signing key as the wallet provider
	var wiaSvc *WIAService
	if cfg.WalletProvider.WIA.Enabled && wpSvc.IsSupported() {
		var challengeStore WIAChallengeStore
		// Use MongoDB-backed challenge store if the underlying storage is MongoDB.
		type databaseProvider interface {
			Database() *mongo.Database
		}
		if dbp, ok := store.(databaseProvider); ok {
			cs, err := NewMongoWIAChallengeStore(context.Background(), dbp.Database(), maxChallenges)
			if err != nil {
				logger.Warn("Failed to create MongoDB WIA challenge store, falling back to memory", zap.Error(err))
			} else {
				challengeStore = cs
			}
		}
		wiaSvc = NewWIAService(cfg, logger, wpSvc.jwtSigner, wpSvc.certChain, store.WalletInstances(), nil, challengeStore)
	}

	return &Services{
		User:             NewUserService(store, cfg, logger),
		Tenant:           NewTenantService(store, logger),
		UserTenant:       NewUserTenantService(store, logger),
		WebAuthn:         webauthnSvc,
		Credential:       NewCredentialService(store, cfg, logger),
		Issuer:           NewIssuerService(store, logger),
		Verifier:         NewVerifierService(store, logger),
		Keystore:         NewKeystoreService(store, cfg, logger),
		Proxy:            NewProxyService(cfg, logger),
		Helper:           NewHelperService(logger),
		WalletProvider:   wpSvc,
		WIA:              wiaSvc,
		TokenBlacklist:   NewTokenBlacklist(cfg.Security.TokenBlacklist, logger),
		ChallengeCleanup: NewChallengeCleanupWorker(cfg.Security.ChallengeCleanup, store, logger),
		AAGUIDValidator:  aaguidValidator,
	}
}

// Start starts background workers
func (s *Services) Start() {
	if s.TokenBlacklist != nil {
		s.TokenBlacklist.Start()
	}
	if s.ChallengeCleanup != nil {
		s.ChallengeCleanup.Start()
	}
	if s.WIA != nil {
		s.WIA.Start()
	}
}

// Stop gracefully stops background workers
func (s *Services) Stop() {
	if s.WIA != nil {
		s.WIA.Stop()
	}
	if s.ChallengeCleanup != nil {
		s.ChallengeCleanup.Stop()
	}
	if s.TokenBlacklist != nil {
		s.TokenBlacklist.Stop()
	}
	if s.WalletProvider != nil {
		s.WalletProvider.Close()
	}
}
