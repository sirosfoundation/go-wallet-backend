package websocket

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

var (
	ErrUserNotConnected    = errors.New("user not connected")
	ErrWrongMessageID      = errors.New("wrong message id")
	ErrWrongAction         = errors.New("wrong action")
	ErrFailedToReceive     = errors.New("failed to receive message")
	ErrRemoteSigningFailed = errors.New("remote signing failed")
	ErrTimeout             = errors.New("operation timed out")
)

// SignatureAction defines the type of signing operation
type SignatureAction string

const (
	ActionGenerateOpenid4vciProof SignatureAction = "generateOpenid4vciProof"
	ActionSignJwtPresentation     SignatureAction = "signJwtPresentation"
)

// ServerMessage represents a message sent from server to client
type ServerMessage struct {
	MessageID string          `json:"message_id"`
	Request   *SigningRequest `json:"request,omitempty"`
	Type      string          `json:"type,omitempty"` // For control messages like "FIN_INIT"
}

// SigningRequest represents a request for the client to sign something
type SigningRequest struct {
	Action                SignatureAction `json:"action"`
	Nonce                 string          `json:"nonce"`
	Audience              string          `json:"audience"`
	VerifiableCredentials []interface{}   `json:"verifiableCredentials,omitempty"`
}

// ClientMessage represents a message received from client
type ClientMessage struct {
	MessageID string           `json:"message_id"`
	AppToken  string           `json:"appToken,omitempty"` // For handshake
	Response  *SigningResponse `json:"response,omitempty"`
}

// SigningResponse represents the client's response to a signing request
type SigningResponse struct {
	Action   SignatureAction `json:"action"`
	ProofJWT string          `json:"proof_jwt,omitempty"`
	VPJWT    string          `json:"vpjwt,omitempty"`
}

// pendingRequest tracks an outstanding signing request
type pendingRequest struct {
	messageID  string
	action     SignatureAction
	responseCh chan *SigningResponse
	errorCh    chan error
}

// clientConnection represents a connected WebSocket client
type clientConnection struct {
	conn           *websocket.Conn
	userID         string
	pendingMu      sync.Mutex
	pendingRequest *pendingRequest
}

// Manager handles WebSocket connections for wallet keystores
type Manager struct {
	cfg      *config.Config
	logger   *zap.Logger
	upgrader websocket.Upgrader

	clientsMu sync.RWMutex
	clients   map[string]*clientConnection // userID -> connection
}

// NewManager creates a new WebSocket manager
func NewManager(cfg *config.Config, logger *zap.Logger) *Manager {
	return &Manager{
		cfg:    cfg,
		logger: logger.Named("websocket-manager"),
		upgrader: websocket.Upgrader{
			ReadBufferSize:  1024,
			WriteBufferSize: 1024,
			CheckOrigin: func(r *http.Request) bool {
				// TODO: Make configurable for production
				return true
			},
		},
		clients: make(map[string]*clientConnection),
	}
}

// HandleConnection handles a new WebSocket connection
func (m *Manager) HandleConnection(w http.ResponseWriter, r *http.Request) {
	conn, err := m.upgrader.Upgrade(w, r, nil)
	if err != nil {
		m.logger.Error("Failed to upgrade connection", zap.Error(err))
		return
	}

	m.logger.Info("WebSocket client connected")

	// Read the first message which should be the handshake with appToken
	go m.handleClient(conn)
}

func (m *Manager) handleClient(conn *websocket.Conn) {
	defer conn.Close()

	var client *clientConnection

	for {
		_, message, err := conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				m.logger.Error("WebSocket read error", zap.Error(err))
			}
			break
		}

		var msg ClientMessage
		if err := json.Unmarshal(message, &msg); err != nil {
			m.logger.Error("Failed to parse message", zap.Error(err))
			continue
		}

		// Handle handshake
		if msg.AppToken != "" {
			userID, err := m.validateToken(msg.AppToken)
			if err != nil {
				m.logger.Error("Handshake failed - invalid token", zap.Error(err))
				conn.WriteJSON(ServerMessage{Type: "ERROR", MessageID: "auth_failed"})
				continue
			}

			// Register the client
			client = &clientConnection{
				conn:   conn,
				userID: userID,
			}

			m.clientsMu.Lock()
			// Close any existing connection for this user
			if existing, ok := m.clients[userID]; ok {
				existing.conn.Close()
			}
			m.clients[userID] = client
			m.clientsMu.Unlock()

			m.logger.Info("WebSocket handshake established", zap.String("user_id", userID))
			conn.WriteJSON(ServerMessage{Type: "FIN_INIT"})
			continue
		}

		// Handle signing response
		if client != nil && msg.Response != nil {
			client.pendingMu.Lock()
			if client.pendingRequest != nil && client.pendingRequest.messageID == msg.MessageID {
				if msg.Response.Action == client.pendingRequest.action {
					client.pendingRequest.responseCh <- msg.Response
				} else {
					client.pendingRequest.errorCh <- ErrWrongAction
				}
			}
			client.pendingMu.Unlock()
		}
	}

	// Clean up on disconnect
	if client != nil {
		m.clientsMu.Lock()
		if existing, ok := m.clients[client.userID]; ok && existing == client {
			delete(m.clients, client.userID)
		}
		m.clientsMu.Unlock()
		m.logger.Info("WebSocket client disconnected", zap.String("user_id", client.userID))
	}
}

func (m *Manager) validateToken(tokenString string) (string, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return []byte(m.cfg.JWT.Secret), nil
	})

	if err != nil {
		return "", err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		userID, ok := claims["user_id"].(string)
		if !ok {
			return "", errors.New("invalid token claims")
		}
		return userID, nil
	}

	return "", errors.New("invalid token")
}

// IsConnected checks if a user is currently connected
func (m *Manager) IsConnected(userID string) bool {
	m.clientsMu.RLock()
	defer m.clientsMu.RUnlock()
	_, ok := m.clients[userID]
	return ok
}

// SendSigningRequest sends a signing request to a connected client and waits for response
func (m *Manager) SendSigningRequest(ctx context.Context, userID string, request *SigningRequest) (*SigningResponse, error) {
	m.clientsMu.RLock()
	client, ok := m.clients[userID]
	m.clientsMu.RUnlock()

	if !ok {
		return nil, ErrUserNotConnected
	}

	messageID := uuid.New().String()
	msg := ServerMessage{
		MessageID: messageID,
		Request:   request,
	}

	// Set up pending request
	pending := &pendingRequest{
		messageID:  messageID,
		action:     request.Action,
		responseCh: make(chan *SigningResponse, 1),
		errorCh:    make(chan error, 1),
	}

	client.pendingMu.Lock()
	client.pendingRequest = pending
	client.pendingMu.Unlock()

	defer func() {
		client.pendingMu.Lock()
		client.pendingRequest = nil
		client.pendingMu.Unlock()
	}()

	// Send the message
	if err := client.conn.WriteJSON(msg); err != nil {
		return nil, err
	}

	m.logger.Debug("Sent signing request",
		zap.String("user_id", userID),
		zap.String("message_id", messageID),
		zap.String("action", string(request.Action)),
	)

	// Wait for response with timeout
	timeout := time.After(30 * time.Second)
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-timeout:
		return nil, ErrTimeout
	case err := <-pending.errorCh:
		return nil, err
	case resp := <-pending.responseCh:
		return resp, nil
	}
}

// GenerateOpenid4vciProof requests the client to generate an OpenID4VCI proof
func (m *Manager) GenerateOpenid4vciProof(ctx context.Context, userID, audience, nonce string) (string, error) {
	resp, err := m.SendSigningRequest(ctx, userID, &SigningRequest{
		Action:   ActionGenerateOpenid4vciProof,
		Audience: audience,
		Nonce:    nonce,
	})
	if err != nil {
		return "", err
	}

	if resp.Action != ActionGenerateOpenid4vciProof {
		return "", ErrWrongAction
	}

	return resp.ProofJWT, nil
}

// SignJwtPresentation requests the client to sign a JWT presentation
func (m *Manager) SignJwtPresentation(ctx context.Context, userID, nonce, audience string, verifiableCredentials []interface{}) (string, error) {
	resp, err := m.SendSigningRequest(ctx, userID, &SigningRequest{
		Action:                ActionSignJwtPresentation,
		Nonce:                 nonce,
		Audience:              audience,
		VerifiableCredentials: verifiableCredentials,
	})
	if err != nil {
		return "", err
	}

	if resp.Action != ActionSignJwtPresentation {
		return "", ErrWrongAction
	}

	return resp.VPJWT, nil
}

// Close closes all connections
func (m *Manager) Close() {
	m.clientsMu.Lock()
	defer m.clientsMu.Unlock()

	for _, client := range m.clients {
		client.conn.Close()
	}
	m.clients = make(map[string]*clientConnection)
}
