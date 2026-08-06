package service

import (
	"context"

	"go.mongodb.org/mongo-driver/mongo"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
	"github.com/sirosfoundation/go-wallet-backend/pkg/audit"
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
	FIDO2Attestation *FIDO2AttestationService
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

	wpSvc := NewWalletProviderService(cfg, logger, store.WalletInstances())

	// WIA shares the same signing key as the wallet provider. Uses
	// HasSigningKey (not IsSupported) because "ietf"-mode WIA only needs a
	// signing key, not a certificate — IsSupported additionally requires a
	// certificate chain, which is only mandatory for Key Attestation and
	// "etsi"-mode WIA.
	var wiaSvc *WIAService
	if cfg.WalletProvider.WIA.Enabled && wpSvc.HasSigningKey() {
		var challengeStore WIAChallengeStore
		// Use MongoDB-backed challenge store if the underlying storage is MongoDB.
		type databaseProvider interface {
			Database() *mongo.Database
		}
		if dbp, ok := store.(databaseProvider); ok {
			cs, err := NewMongoWIAChallengeStore(context.Background(), dbp.Database(), maxChallenges, maxChallengesPerTenant)
			if err != nil {
				logger.Warn("Failed to create MongoDB WIA challenge store, falling back to memory", zap.Error(err))
			} else {
				challengeStore = cs
			}
		}
		// Use the shared SET audit emitter constructor so WIA issuance events are
		// audited whenever cfg.Audit is enabled, consistent with admin-API auditing.
		wiaAuditor := audit.NewFromConfig(cfg, logger)
		wiaSvc = NewWIAService(cfg, logger, wpSvc.jwtSigner, wpSvc.certChain, store.WalletInstances(), wiaAuditor, challengeStore)
		// A signing key alone is enough to construct WIAService, but "etsi"
		// mode additionally requires a certificate chain (see IsSupported).
		// Leaving wiaSvc non-nil here would register the WIA routes, but
		// every actual call would fail with ErrWIANotSupported, which the
		// handlers map to a generic 500 rather than the clean 503
		// WIA_NOT_SUPPORTED they already return for services.WIA == nil -
		// nil it out here so that existing check covers this case too.
		if !wiaSvc.IsSupported() {
			wiaSvc = nil
		}
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
		FIDO2Attestation: NewFIDO2AttestationService(cfg, store.WalletInstances(), logger),
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
