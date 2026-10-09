package as

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/mongo"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/service"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
	"github.com/sirosfoundation/go-wallet-backend/pkg/middleware"
	"github.com/sirosfoundation/go-wallet-backend/pkg/signing"
)

// ASModule is the top-level authorization server module that wires together
// all AS components and registers routes.
type ASModule struct {
	KeyManager     *KeyManager
	TokenIssuer    *TokenIssuer
	Sessions       SessionStore
	Policy         PolicyEngine
	PasskeyHandler *PasskeyHandlers
	OIDCHandler    *OIDCHandlers
	// Blacklist checks whether a token has been revoked (via Logout/user
	// deletion - see #382/#383). Used by the delegation-exchange path in
	// TokenEndpointHandler so a revoked parent token can't be re-delegated
	// into a fresh one (#381). Nil if the caller didn't wire one.
	Blacklist TokenBlacklistChecker
	Logger    *zap.Logger
	Config    *config.ASConfig
	// store and validatorCache back the tenant-header and OIDC-gate
	// middleware mounted on /auth/passkey/* (see RegisterRoutes). This is the
	// only AS route group that operates on tenant-scoped data before the
	// caller has a session, so it needs the same tenant perimeter as the
	// /user/* routes (see pkg/middleware.TenantHeaderMiddleware and
	// OIDCGateMiddleware, wired identically in internal/server/providers.go).
	store          storage.Store
	validatorCache *middleware.ValidatorCache
	// cancel stops the module's background goroutines (session cleanup).
	cancel context.CancelFunc
	// gateLimit, when set, rate limits token-bearing requests to the passkey
	// OIDC gates (see SetOIDCGateRateLimiter). nil means unlimited.
	gateLimit gin.HandlerFunc
}

// NewASModule creates and initializes the AS module.
// The ctx parameter controls the lifecycle of background goroutines (session cleanup).
// httpClient is used for every request to an OIDC identity provider: the
// login flow's discovery and token exchange, and the passkey OIDC gate's
// issuer discovery and JWKS fetches (see RegisterRoutes) - callers should
// pass a configured, SSRF-guarded client (cfg.HTTPClient.NewIdPHTTPClient(0)),
// not nil, or those unauthenticated fetches bypass the private-IP/HTTPS
// guards the rest of the codebase applies. A nil value still works (falls
// back to a bare client with a short default timeout) for callers that
// genuinely have no such client (e.g. tests).
// Returns an error if the signing key cannot be loaded.
func NewASModule(
	ctx context.Context,
	cfg *config.ASConfig,
	jwtCfg *config.JWTConfig,
	webauthnSvc *service.WebAuthnService,
	store storage.Store,
	blacklist TokenBlacklistChecker,
	httpClient *http.Client,
	logger *zap.Logger,
) (module *ASModule, err error) {
	// Key manager.
	km, err := newConfiguredKeyManager(cfg)
	if err != nil {
		return nil, err
	}
	// Child context so Close or a failed construction can stop the goroutines.
	ctx, cancel := context.WithCancel(ctx)
	// Release HSM sessions and goroutines on any later failure.
	defer func() {
		if err != nil {
			cancel()
			_ = km.Close()
		}
	}()

	// Token issuer.
	issuer := cfg.Issuer
	if issuer == "" {
		issuer = jwtCfg.Issuer
	}
	tokenIssuer := NewTokenIssuer(km, issuer, func(aud string) time.Duration {
		return cfg.GetTokenTTL(aud)
	})

	// Session store: MongoDB when the storage backend is MongoDB (sessions
	// survive restarts and are shared across instances, #324), memory
	// otherwise, unless as.session_store says which.
	sessions, err := newSessionStore(ctx, cfg, store, logger)
	if err != nil {
		return nil, err
	}

	// Policy engine.
	var policy PolicyEngine
	if cfg.RulesDir != "" {
		pe := NewSPOCPEngine(logger)
		if err := pe.LoadRulesFromDir(cfg.RulesDir); err != nil {
			return nil, err
		}
		policy = pe
	} else {
		policy = AllowAllPolicy{}
	}

	// Passkey handlers.
	passkeyHandler := NewPasskeyHandlers(webauthnSvc, sessions, cfg, logger)

	// OIDC handlers. The state-binding cookie (go-wallet-backend#385) is keyed
	// by jwt.secret (its only use now that legacy HMAC tokens are gone);
	// pkg/config.Config.Validate already requires it to be present and >=32
	// bytes.
	oidcHandler := NewOIDCHandlers(store, sessions, cfg, []byte(jwtCfg.Secret), httpClient, logger)

	// Shared cache of OIDC validators for the passkey gate (see
	// RegisterRoutes). See httpClient's doc comment above for why this must
	// be the caller's configured client, not nil, in production.
	validatorCache := middleware.NewValidatorCache(httpClient, logger)

	return &ASModule{
		KeyManager:     km,
		TokenIssuer:    tokenIssuer,
		Sessions:       sessions,
		Policy:         policy,
		PasskeyHandler: passkeyHandler,
		OIDCHandler:    oidcHandler,
		Blacklist:      blacklist,
		Logger:         logger,
		Config:         cfg,
		store:          store,
		validatorCache: validatorCache,
		cancel:         cancel,
	}, nil
}

// SetOIDCGateRateLimiter installs the rate limiter that runs in front of the
// passkey OIDC gates. Call it before RegisterRoutes; the same limiter is
// meant to be shared with the /user/* gates so both draw from one set of
// buckets.
func (m *ASModule) SetOIDCGateRateLimiter(l *middleware.OIDCGateRateLimiter) {
	if l != nil {
		m.gateLimit = l.Middleware()
	}
}

// gateLimitMiddleware returns the installed limiter, or a pass-through.
func (m *ASModule) gateLimitMiddleware() gin.HandlerFunc {
	if m.gateLimit != nil {
		return m.gateLimit
	}
	return func(c *gin.Context) { c.Next() }
}

// RegisterRoutes registers all AS endpoints on the given router group.
// The group should be mounted at /auth.
func (m *ASModule) RegisterRoutes(auth *gin.RouterGroup) {
	// JWKS endpoint (public, no auth).
	RegisterJWKSRoute(auth.Group(""), m.KeyManager)

	// Passkey authentication (public, no auth — but tenant-scoped).
	// Tenant comes from the validated X-Tenant-ID header, never from the
	// request body, mirroring the /user/* routes (see providers.go's
	// AuthProvider.RegisterRoutes). Without this, a caller could pick any
	// tenant's data via a body field with no validation at all (issue #374).
	passkey := auth.Group("/passkey")
	passkey.Use(middleware.TenantHeaderMiddleware(m.store))
	{
		// Registration routes (with OIDC registration gate).
		registration := passkey.Group("")
		registration.Use(m.gateLimitMiddleware(), sessionModeGate(), middleware.OIDCGateMiddleware(m.validatorCache, middleware.GateTypeRegistration, m.Logger))
		{
			registration.POST("/register/begin", m.PasskeyHandler.RegisterBegin)
			registration.POST("/register/finish", m.PasskeyHandler.RegisterFinish)
		}

		// Login routes (with OIDC login gate).
		login := passkey.Group("")
		login.Use(m.gateLimitMiddleware(), sessionModeGate(), middleware.OIDCGateMiddleware(m.validatorCache, middleware.GateTypeLogin, m.Logger))
		{
			login.POST("/login/begin", m.PasskeyHandler.LoginBegin)
			login.POST("/login/finish", m.PasskeyHandler.LoginFinish)
		}
	}

	// OIDC authentication (public, no auth — redirects to IdP).
	oidcGroup := auth.Group("/oidc")
	{
		oidcGroup.GET("/login", m.OIDCHandler.Login)
		oidcGroup.GET("/callback", m.OIDCHandler.Callback)
	}

	// Token endpoint (requires session cookie).
	RegisterTokenEndpoint(auth, TokenEndpointConfig{
		Store:           m.Sessions,
		Issuer:          m.TokenIssuer,
		Policy:          m.Policy,
		TTLFunc:         func(aud string) time.Duration { return m.Config.GetTokenTTL(aud) },
		Audiences:       m.Config.Audiences,
		Blacklist:       m.Blacklist,
		InsecureCookies: m.Config.InsecureCookies,
		Logger:          m.Logger,
	})

	// Logout (requires session cookie).
	auth.DELETE("/session", LogoutHandler(m.Sessions, m.TokenIssuer, m.Blacklist, m.Config.InsecureCookies, m.Logger))
}

// mongoDatabaseProvider is implemented by the MongoDB storage backend.
type mongoDatabaseProvider interface {
	Database() *mongo.Database
}

// newSessionStore picks the SessionStore for cfg.SessionStore: "memory",
// "mongodb", or "auto" (the default when empty) for "mongodb when the backend
// is MongoDB, else memory".
func newSessionStore(ctx context.Context, cfg *config.ASConfig, store storage.Store, logger *zap.Logger) (SessionStore, error) {
	dbp, hasMongo := store.(mongoDatabaseProvider)
	switch cfg.SessionStore {
	case "", "auto":
		if !hasMongo {
			logger.Info("AS sessions: in-memory store (storage backend is not MongoDB; sessions do not survive restarts)")
			return newMemorySessionStoreWithCleanup(ctx), nil
		}
	case "memory":
		logger.Info("AS sessions: in-memory store (as.session_store=memory; sessions do not survive restarts)")
		return newMemorySessionStoreWithCleanup(ctx), nil
	case "mongodb":
		if !hasMongo {
			return nil, fmt.Errorf("as.session_store=mongodb requires the MongoDB storage backend")
		}
	default:
		return nil, fmt.Errorf("as.session_store: unknown value %q (memory, mongodb, or auto)", cfg.SessionStore)
	}
	mongoStore, err := NewMongoSessionStore(ctx, dbp.Database())
	if err != nil {
		return nil, fmt.Errorf("as.session_store: %w", err)
	}
	logger.Info("AS sessions: MongoDB store")
	return mongoStore, nil
}

func newMemorySessionStoreWithCleanup(ctx context.Context) *MemorySessionStore {
	sessions := NewMemorySessionStore()
	sessions.StartCleanup(ctx, 5*time.Minute)
	return sessions
}

// newConfiguredKeyManager builds the KeyManager from the PEM key file or the
// PKCS#11 key; exactly one must be configured.
func newConfiguredKeyManager(cfg *config.ASConfig) (*KeyManager, error) {
	switch {
	case cfg.SigningKeyPath != "" && cfg.SigningKeyPKCS11 != nil:
		return nil, fmt.Errorf("as: signing_key_path and signing_key_pkcs11 are mutually exclusive")
	case cfg.SigningKeyPKCS11 != nil:
		p := cfg.SigningKeyPKCS11
		// Read here, not in config.Load: standalone engines sharing the config
		// need not have the file.
		pin, err := p.ResolvePIN()
		if err != nil {
			return nil, fmt.Errorf("as: signing_key_pkcs11: %w", err)
		}
		signer, err := newPKCS11Signer(&signing.PKCS11Config{
			ModulePath: p.ModulePath,
			SlotID:     p.SlotID,
			PIN:        pin,
			KeyLabel:   p.KeyLabel,
			PoolSize:   p.PoolSize,
		})
		if err != nil {
			return nil, fmt.Errorf("as: pkcs11 signing key: %w", err)
		}
		km, err := newPKCS11KeyManager(signer)
		if err != nil {
			if c, ok := signer.(interface{ Close() error }); ok {
				_ = c.Close()
			}
			return nil, err
		}
		return km, nil
	default:
		return NewKeyManager(cfg.SigningKeyPath)
	}
}

// newPKCS11Signer is a seam so tests can inject a fake HSM signer.
var newPKCS11Signer = func(cfg *signing.PKCS11Config) (crypto.Signer, error) {
	return signing.NewPKCS11Signer(cfg)
}

// Close releases resources held by the module (HSM sessions).
func (m *ASModule) Close() error {
	if m == nil {
		return nil
	}
	if m.cancel != nil {
		m.cancel()
	}
	if m.KeyManager == nil {
		return nil
	}
	return m.KeyManager.Close()
}

// newPKCS11KeyManager builds a KeyManager from an HSM signer, refusing key
// types the PKCS#11 backend cannot sign with. The pinned pkcs11pool signer
// handles only CKK_EC (P-256/P-384 here) and CKK_RSA; Ed25519 tokens use
// CKK_EC_EDWARDS and RSA is not an AS algorithm, so only ECDSA is accepted.
// This is checked on the key's actual type (the config carries no algorithm).
func newPKCS11KeyManager(signer crypto.Signer) (*KeyManager, error) {
	if signer == nil {
		return nil, fmt.Errorf("as: pkcs11 signing key: nil signer")
	}
	if _, ok := signer.Public().(*ecdsa.PublicKey); !ok {
		return nil, fmt.Errorf("as: signing_key_pkcs11 supports only ECDSA P-256/P-384 keys, got %T (Ed25519 and RSA are not supported for PKCS#11; use signing_key_path for Ed25519)", signer.Public())
	}
	return NewKeyManagerFromSigner(signer)
}
