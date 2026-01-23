package ohttp

import (
	"io"
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

const (
	// ContentTypeOHTTPRequest is the MIME type for OHTTP encapsulated requests.
	ContentTypeOHTTPRequest = "message/ohttp-req"

	// ContentTypeOHTTPResponse is the MIME type for OHTTP encapsulated responses.
	ContentTypeOHTTPResponse = "message/ohttp-res"

	// ContentTypeOHTTPKeys is the MIME type for OHTTP key configurations.
	ContentTypeOHTTPKeys = "application/ohttp-keys"
)

// Handler provides HTTP handlers for OHTTP endpoints.
type Handler struct {
	gateway *Gateway
	logger  *zap.Logger

	// MaxRequestSize limits the size of OHTTP requests (default: 1MB)
	MaxRequestSize int64
}

// HandlerOption configures a Handler.
type HandlerOption func(*Handler)

// WithMaxRequestSize sets the maximum request size.
func WithMaxRequestSize(size int64) HandlerOption {
	return func(h *Handler) {
		h.MaxRequestSize = size
	}
}

// NewHandler creates an OHTTP handler.
func NewHandler(gateway *Gateway, logger *zap.Logger, opts ...HandlerOption) *Handler {
	h := &Handler{
		gateway:        gateway,
		logger:         logger.Named("ohttp-handler"),
		MaxRequestSize: 1 << 20, // 1 MB default
	}

	for _, opt := range opts {
		opt(h)
	}

	return h
}

// KeysHandler returns the gateway's key configuration.
//
// Endpoint: GET /.well-known/ohttp-keys
//
// Response:
//   - Content-Type: application/ohttp-keys
//   - Body: Binary key configuration per RFC 9458 §3
func (h *Handler) KeysHandler(c *gin.Context) {
	keys, err := h.gateway.KeyConfig().MarshalBinary()
	if err != nil {
		h.logger.Error("Failed to marshal key config", zap.Error(err))
		c.Status(http.StatusInternalServerError)
		return
	}

	h.logger.Debug("Serving OHTTP key config",
		zap.Uint8("keyID", h.gateway.KeyConfig().KeyID),
		zap.String("publicKey", h.gateway.KeyConfig().PublicKeyHex()[:16]+"..."))

	c.Data(http.StatusOK, ContentTypeOHTTPKeys, keys)
}

// GatewayHandler decapsulates requests and encapsulates responses.
// This is the main OHTTP gateway endpoint.
//
// Endpoint: POST /ohttp/gateway
//
// Request:
//   - Content-Type: message/ohttp-req
//   - Body: Encapsulated Request per RFC 9458 §4.1
//
// Response:
//   - Content-Type: message/ohttp-res
//   - Body: Encapsulated Response per RFC 9458 §4.2
//
// Error responses intentionally don't leak details to prevent oracle attacks.
func (h *Handler) GatewayHandler(c *gin.Context) {
	// Validate content type
	contentType := c.GetHeader("Content-Type")
	if contentType != ContentTypeOHTTPRequest {
		h.logger.Debug("Invalid content type", zap.String("contentType", contentType))
		c.Status(http.StatusBadRequest)
		return
	}

	// Read request body with size limit
	body := io.LimitReader(c.Request.Body, h.MaxRequestSize+1)
	encapsulated, err := io.ReadAll(body)
	if err != nil {
		h.logger.Debug("Failed to read request body", zap.Error(err))
		c.Status(http.StatusBadRequest)
		return
	}

	if int64(len(encapsulated)) > h.MaxRequestSize {
		h.logger.Debug("Request too large", zap.Int("size", len(encapsulated)))
		c.Status(http.StatusRequestEntityTooLarge)
		return
	}

	// Process through gateway
	response, err := h.gateway.HandleRequest(c.Request.Context(), encapsulated)
	if err != nil {
		// Log the error but don't leak details to the client
		// This prevents oracle attacks on the decryption
		h.logger.Debug("Gateway request failed", zap.Error(err))
		c.Status(http.StatusBadGateway)
		return
	}

	c.Data(http.StatusOK, ContentTypeOHTTPResponse, response)
}

// RelayHandler acts as an integrated relay for when no external relay is used.
// This endpoint requires authentication and forwards to the gateway.
//
// Endpoint: POST /api/relay
//
// This provides a convenience endpoint for the frontend when operating without
// an external relay. The frontend sends OHTTP requests here, and this handler
// forwards them to the gateway internally.
//
// While this doesn't provide the full privacy benefits of an external relay
// (since the backend sees both the wallet's IP and the decrypted request),
// it still hides the wallet's IP from the target server.
//
// Request:
//   - Authorization: Bearer <token> (handled by auth middleware)
//   - Content-Type: message/ohttp-req
//   - Body: Encapsulated Request
//
// Response:
//   - Content-Type: message/ohttp-res
//   - Body: Encapsulated Response
func (h *Handler) RelayHandler(c *gin.Context) {
	// Auth is handled by middleware before this handler
	// This handler is identical to GatewayHandler but sits behind auth

	contentType := c.GetHeader("Content-Type")
	if contentType != ContentTypeOHTTPRequest {
		h.logger.Debug("Invalid content type for relay", zap.String("contentType", contentType))
		c.Status(http.StatusBadRequest)
		return
	}

	body := io.LimitReader(c.Request.Body, h.MaxRequestSize+1)
	encapsulated, err := io.ReadAll(body)
	if err != nil {
		h.logger.Debug("Failed to read relay request body", zap.Error(err))
		c.Status(http.StatusBadRequest)
		return
	}

	if int64(len(encapsulated)) > h.MaxRequestSize {
		h.logger.Debug("Relay request too large", zap.Int("size", len(encapsulated)))
		c.Status(http.StatusRequestEntityTooLarge)
		return
	}

	response, err := h.gateway.HandleRequest(c.Request.Context(), encapsulated)
	if err != nil {
		h.logger.Debug("Relay gateway request failed", zap.Error(err))
		c.Status(http.StatusBadGateway)
		return
	}

	c.Data(http.StatusOK, ContentTypeOHTTPResponse, response)
}

// RegisterRoutes registers OHTTP routes on a gin router.
// This is a convenience method for setting up all OHTTP endpoints.
//
// Routes registered:
//   - GET /.well-known/ohttp-keys - Public key configuration
//   - POST /ohttp/gateway - OHTTP gateway (no auth)
//   - POST /api/relay - Integrated relay (requires auth middleware)
func (h *Handler) RegisterRoutes(r *gin.Engine, authMiddleware gin.HandlerFunc, integratedRelay bool) {
	// Key configuration endpoint (public)
	r.GET("/.well-known/ohttp-keys", h.KeysHandler)

	// Gateway endpoint (no auth - OHTTP encrypts the auth)
	// External relays forward here
	r.POST("/ohttp/gateway", h.GatewayHandler)

	if integratedRelay {
		// Integrated relay endpoint (requires auth)
		// Frontend uses this when no external relay is configured
		api := r.Group("/api")
		if authMiddleware != nil {
			api.Use(authMiddleware)
		}
		api.POST("/relay", h.RelayHandler)
	}
}
