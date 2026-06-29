package as

import (
	"context"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirosfoundation/go-wallet-backend/internal/service"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
	"go.uber.org/zap"
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

	// Session store.
	sessions := NewMemorySessionStore()
	sessions.StartCleanup(ctx, 5*time.Minute)

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
		m.Logger,
	)

	// Logout (requires session cookie).
	auth.DELETE("/session", LogoutHandler(m.Sessions, m.Logger))
}
