package service

import (
	"context"
	"net/http"

	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
	"github.com/sirosfoundation/go-wallet-backend/internal/websocket"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

// KeystoreService handles keystore operations via WebSocket connections to clients
// The wallet-backend-server implements a "client keystore" model where cryptographic
// keys are held by the client (browser/mobile app) and the server requests signatures
// via WebSocket when needed.
type KeystoreService struct {
	store     storage.Store
	cfg       *config.Config
	logger    *zap.Logger
	wsManager *websocket.Manager
}

// NewKeystoreService creates a new KeystoreService
func NewKeystoreService(store storage.Store, cfg *config.Config, logger *zap.Logger) *KeystoreService {
	return &KeystoreService{
		store:     store,
		cfg:       cfg,
		logger:    logger.Named("keystore-service"),
		wsManager: websocket.NewManager(cfg, logger),
	}
}

// HandleWebSocket handles incoming WebSocket connections
func (s *KeystoreService) HandleWebSocket(w http.ResponseWriter, r *http.Request) {
	s.wsManager.HandleConnection(w, r)
}

// IsClientConnected checks if a user's client keystore is connected
func (s *KeystoreService) IsClientConnected(userID string) bool {
	return s.wsManager.IsConnected(userID)
}

// GenerateOpenid4vciProof requests the connected client to generate an OpenID4VCI proof JWT
// This is used during credential issuance to prove possession of the key
func (s *KeystoreService) GenerateOpenid4vciProof(ctx context.Context, userID, audience, nonce string) (string, error) {
	s.logger.Debug("Requesting OpenID4VCI proof generation",
		zap.String("user_id", userID),
		zap.String("audience", audience),
	)

	proof, err := s.wsManager.GenerateOpenid4vciProof(ctx, userID, audience, nonce)
	if err != nil {
		s.logger.Error("Failed to generate OpenID4VCI proof",
			zap.String("user_id", userID),
			zap.Error(err),
		)
		return "", err
	}

	return proof, nil
}

// SignJwtPresentation requests the connected client to sign a JWT Verifiable Presentation
// This is used during credential presentation to prove possession of credentials
func (s *KeystoreService) SignJwtPresentation(ctx context.Context, userID, nonce, audience string, verifiableCredentials []interface{}) (string, error) {
	s.logger.Debug("Requesting JWT presentation signing",
		zap.String("user_id", userID),
		zap.String("audience", audience),
		zap.Int("credentials", len(verifiableCredentials)),
	)

	vpJWT, err := s.wsManager.SignJwtPresentation(ctx, userID, nonce, audience, verifiableCredentials)
	if err != nil {
		s.logger.Error("Failed to sign JWT presentation",
			zap.String("user_id", userID),
			zap.Error(err),
		)
		return "", err
	}

	return vpJWT, nil
}

// Close closes the WebSocket manager
func (s *KeystoreService) Close() {
	s.wsManager.Close()
}
