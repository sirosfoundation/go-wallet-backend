package as

import (
	"context"
	"fmt"
	"time"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/mongo"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/service"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

// ASModule is the top-level authorization server module that wires together
// all AS components and registers routes.
type ASModule struct {
	KeyManager     *KeyManager
	TokenIssuer    *TokenIssuer
	LegacyIssuer   *LegacyTokenIssuer
	Sessions       SessionStore
	Policy         PolicyEngine
	PasskeyHandler *PasskeyHandlers
	OIDCHandler    *OIDCHandlers
	Logger         *zap.Logger
	Config         *config.ASConfig
}

// NewASModule creates and initializes the AS module.
// The ctx parameter controls the lifecycle of background goroutines (session cleanup).
// Returns an error if the signing key cannot be loaded.
func NewASModule(
	ctx context.Context,
	cfg *config.ASConfig,
	jwtCfg *config.JWTConfig,
	webauthnSvc *service.WebAuthnService,
	store storage.Store,
	logger *zap.Logger,
) (*ASModule, error) {
	// Key manager.
	km, err := NewKeyManager(cfg.SigningKeyPath)
	if err != nil {
		return nil, err
	}

	// Token issuer.
	issuer := cfg.Issuer
	if issuer == "" {
		issuer = jwtCfg.Issuer
	}
	tokenIssuer := NewTokenIssuer(km, issuer, func(aud string) time.Duration {
		return cfg.GetTokenTTL(aud)
	})

	// Legacy issuer (uses existing HMAC secret).
	var legacyIssuer *LegacyTokenIssuer
	if cfg.Legacy.Enabled {
		legacyIssuer = NewLegacyTokenIssuer(
			[]byte(jwtCfg.Secret),
			issuer,
			time.Duration(jwtCfg.ExpiryHours)*time.Hour,
		)
	}

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
	passkeyHandler := NewPasskeyHandlers(webauthnSvc, sessions, legacyIssuer, cfg, logger)

	// OIDC handlers.
	oidcHandler := NewOIDCHandlers(store, sessions, cfg, logger)

	return &ASModule{
		KeyManager:     km,
		TokenIssuer:    tokenIssuer,
		LegacyIssuer:   legacyIssuer,
		Sessions:       sessions,
		Policy:         policy,
		PasskeyHandler: passkeyHandler,
		OIDCHandler:    oidcHandler,
		Logger:         logger,
		Config:         cfg,
	}, nil
}

// RegisterRoutes registers all AS endpoints on the given router group.
// The group should be mounted at /auth.
func (m *ASModule) RegisterRoutes(auth *gin.RouterGroup) {
	// JWKS endpoint (public, no auth).
	RegisterJWKSRoute(auth.Group(""), m.KeyManager)

	// Passkey authentication (public, no auth).
	passkey := auth.Group("/passkey")
	{
		passkey.POST("/login/begin", m.PasskeyHandler.LoginBegin)
		passkey.POST("/login/finish", m.PasskeyHandler.LoginFinish)
		passkey.POST("/register/begin", m.PasskeyHandler.RegisterBegin)
		passkey.POST("/register/finish", m.PasskeyHandler.RegisterFinish)
	}

	// OIDC authentication (public, no auth — redirects to IdP).
	oidcGroup := auth.Group("/oidc")
	{
		oidcGroup.GET("/login", m.OIDCHandler.Login)
		oidcGroup.GET("/callback", m.OIDCHandler.Callback)
	}

	// Token endpoint (requires session cookie).
	RegisterTokenEndpoint(auth, m.Sessions, m.TokenIssuer, m.Policy,
		func(aud string) time.Duration { return m.Config.GetTokenTTL(aud) },
		m.Config.InsecureCookies,
		m.Logger,
	)

	// Logout (requires session cookie).
	auth.DELETE("/session", LogoutHandler(m.Sessions, m.Config.InsecureCookies, m.Logger))
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
