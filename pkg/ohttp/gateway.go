package ohttp

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/cloudflare/circl/hpke"
	"go.uber.org/zap"
)

// ProxyFilterer is the interface to the proxy security filter.
// The gateway validates all decrypted target URLs through this filter.
type ProxyFilterer interface {
	IsAllowed(rawURL string) (bool, string)
}

// Gateway decapsulates OHTTP requests and encapsulates responses.
// It acts as the OHTTP Gateway per RFC 9458.
type Gateway struct {
	keyConfig   *KeyConfig
	proxyFilter ProxyFilterer
	httpClient  *http.Client
	logger      *zap.Logger
}

// GatewayConfig configures the OHTTP gateway.
type GatewayConfig struct {
	// Timeout for target requests
	Timeout time.Duration

	// MaxRequestSize limits the size of encapsulated requests
	MaxRequestSize int64

	// MaxResponseSize limits the size of target responses
	MaxResponseSize int64
}

// DefaultGatewayConfig returns sensible defaults.
func DefaultGatewayConfig() GatewayConfig {
	return GatewayConfig{
		Timeout:         30 * time.Second,
		MaxRequestSize:  1 << 20,  // 1 MB
		MaxResponseSize: 10 << 20, // 10 MB
	}
}

// NewGateway creates an OHTTP gateway.
func NewGateway(keyConfig *KeyConfig, filter ProxyFilterer, client *http.Client, logger *zap.Logger) *Gateway {
	if client == nil {
		client = &http.Client{
			Timeout: 30 * time.Second,
		}
	}

	return &Gateway{
		keyConfig:   keyConfig,
		proxyFilter: filter,
		httpClient:  client,
		logger:      logger.Named("ohttp-gateway"),
	}
}

// requestContext holds state needed for response encapsulation.
type requestContext struct {
	opener hpke.Opener
	enc    []byte // ephemeral public key from request
}

// HandleRequest processes a complete OHTTP request.
// Returns the encapsulated response or an error.
func (g *Gateway) HandleRequest(ctx context.Context, encapsulated []byte) ([]byte, error) {
	// Decapsulate request
	req, rctx, err := g.decapsulateRequest(encapsulated)
	if err != nil {
		g.logger.Debug("Decapsulation failed", zap.Error(err))
		return nil, fmt.Errorf("decapsulation failed: %w", err)
	}

	// Validate target URL via proxy filter
	targetURL := req.URL.String()
	if allowed, reason := g.proxyFilter.IsAllowed(targetURL); !allowed {
		g.logger.Warn("Target URL blocked by proxy filter",
			zap.String("url", targetURL),
			zap.String("reason", reason))
		return nil, fmt.Errorf("target URL blocked: %s", reason)
	}

	// Forward request with context
	req = req.WithContext(ctx)

	g.logger.Debug("Forwarding OHTTP request",
		zap.String("method", req.Method),
		zap.String("url", targetURL))

	resp, err := g.httpClient.Do(req)
	if err != nil {
		g.logger.Debug("Target request failed", zap.Error(err))
		return nil, fmt.Errorf("target request failed: %w", err)
	}
	defer resp.Body.Close()

	// Encapsulate response
	encResponse, err := g.encapsulateResponse(resp, rctx)
	if err != nil {
		g.logger.Debug("Encapsulation failed", zap.Error(err))
		return nil, fmt.Errorf("encapsulation failed: %w", err)
	}

	return encResponse, nil
}

// decapsulateRequest decrypts an OHTTP request.
// Returns the plaintext HTTP request and context needed for response encryption.
func (g *Gateway) decapsulateRequest(encapsulated []byte) (*http.Request, *requestContext, error) {
	// Parse encapsulated request header (RFC 9458 §4.1)
	// Format: keyID(1) || kemID(2) || kdfID(2) || aeadID(2) || enc(Npk) || ct
	if len(encapsulated) < 7 {
		return nil, nil, fmt.Errorf("encapsulated request too short: %d bytes", len(encapsulated))
	}

	keyID := encapsulated[0]
	if keyID != g.keyConfig.KeyID {
		return nil, nil, fmt.Errorf("unknown key ID: %d (expected %d)", keyID, g.keyConfig.KeyID)
	}

	kemID := binary.BigEndian.Uint16(encapsulated[1:3])
	kdfID := binary.BigEndian.Uint16(encapsulated[3:5])
	aeadID := binary.BigEndian.Uint16(encapsulated[5:7])

	// Verify algorithms match our configuration
	if kemID != uint16(KemID) || kdfID != uint16(KdfID) || aeadID != uint16(AeadID) {
		return nil, nil, fmt.Errorf("unsupported algorithms: KEM=0x%04x KDF=0x%04x AEAD=0x%04x",
			kemID, kdfID, aeadID)
	}

	// X25519 encapsulated key is 32 bytes
	encLen := 32
	if len(encapsulated) < 7+encLen {
		return nil, nil, fmt.Errorf("encapsulated request missing enc")
	}

	enc := encapsulated[7 : 7+encLen]
	ciphertext := encapsulated[7+encLen:]

	// Build HPKE info for request decryption
	// info = "message/bhttp request" || 0x00 || header
	header := encapsulated[0:7]
	info := append([]byte("message/bhttp request\x00"), header...)

	// Setup HPKE receiver
	receiver, err := g.keyConfig.Suite.NewReceiver(g.keyConfig.PrivateKey, info)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create HPKE receiver: %w", err)
	}

	opener, err := receiver.Setup(enc)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to setup HPKE opener: %w", err)
	}

	// Decrypt the ciphertext
	plaintext, err := opener.Open(ciphertext, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("HPKE decryption failed: %w", err)
	}

	// Parse Binary HTTP request
	req, err := DecodeBinaryHTTPRequest(plaintext)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse Binary HTTP request: %w", err)
	}

	return req, &requestContext{
		opener: opener,
		enc:    enc,
	}, nil
}

// encapsulateResponse encrypts an HTTP response for the client.
func (g *Gateway) encapsulateResponse(resp *http.Response, rctx *requestContext) ([]byte, error) {
	// Encode response as Binary HTTP
	bhttpResp, err := EncodeBinaryHTTPResponse(resp)
	if err != nil {
		return nil, fmt.Errorf("failed to encode Binary HTTP response: %w", err)
	}

	// Get AEAD parameters
	// AES-128-GCM: Nk=16, Nn=12
	Nk := uint(AeadID.KeySize())
	Nn := uint(AeadID.NonceSize())
	secretLen := Nk
	if Nn > secretLen {
		secretLen = Nn
	}

	// Generate response nonce (L bytes where L = max(Nk, Nn))
	responseNonce := make([]byte, secretLen)
	if _, err := rand.Read(responseNonce); err != nil {
		return nil, fmt.Errorf("failed to generate response nonce: %w", err)
	}

	// Export secret for response encryption (RFC 9458 §4.2)
	// secret = context.Export("message/bhttp response", L)
	secret := rctx.opener.Export([]byte("message/bhttp response"), secretLen)

	// Derive key and nonce using HKDF (RFC 9458 §4.2)
	// salt = enc || response_nonce
	salt := make([]byte, len(rctx.enc)+len(responseNonce))
	copy(salt, rctx.enc)
	copy(salt[len(rctx.enc):], responseNonce)

	// prk = Extract(salt, secret)
	prk := KdfID.Extract(secret, salt)

	// aead_key = Expand(prk, "key", Nk)
	aeadKey := KdfID.Expand(prk, []byte("key"), Nk)

	// aead_nonce = Expand(prk, "nonce", Nn)
	aeadNonce := KdfID.Expand(prk, []byte("nonce"), Nn)

	// Encrypt response using AEAD
	aead, err := AeadID.New(aeadKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create AEAD cipher: %w", err)
	}

	ciphertext := aead.Seal(nil, aeadNonce, bhttpResp, nil)

	// Encapsulated Response = response_nonce || ct (RFC 9458 §4.2)
	result := make([]byte, len(responseNonce)+len(ciphertext))
	copy(result, responseNonce)
	copy(result[len(responseNonce):], ciphertext)

	return result, nil
}

// KeyConfig returns the gateway's key configuration.
func (g *Gateway) KeyConfig() *KeyConfig {
	return g.keyConfig
}

// EncapsulateRequest creates an OHTTP encapsulated request.
// This is primarily for testing - clients should use the frontend implementation.
func EncapsulateRequest(keyConfig *KeyConfig, method, targetURL string, headers http.Header, body []byte) ([]byte, hpke.Sealer, error) {
	// Parse URL
	parsed, err := parseURL(targetURL)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid URL: %w", err)
	}

	// Encode as Binary HTTP
	path := parsed.Path
	if parsed.RawQuery != "" {
		path += "?" + parsed.RawQuery
	}
	if path == "" {
		path = "/"
	}

	bhttp, err := EncodeBinaryHTTPRequest(method, parsed.Scheme, parsed.Host, path, headers, body)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encode Binary HTTP: %w", err)
	}

	// Build HPKE info
	// header = keyID(1) || kemID(2) || kdfID(2) || aeadID(2)
	header := make([]byte, 7)
	header[0] = keyConfig.KeyID
	binary.BigEndian.PutUint16(header[1:3], uint16(KemID))
	binary.BigEndian.PutUint16(header[3:5], uint16(KdfID))
	binary.BigEndian.PutUint16(header[5:7], uint16(AeadID))

	// info = "message/bhttp request" || 0x00 || header
	info := append([]byte("message/bhttp request\x00"), header...)

	// Setup HPKE sender
	sender, err := keyConfig.Suite.NewSender(keyConfig.PublicKey, info)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create HPKE sender: %w", err)
	}

	enc, sealer, err := sender.Setup(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to setup HPKE sender: %w", err)
	}

	// Encrypt
	ciphertext, err := sealer.Seal(bhttp, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("HPKE encryption failed: %w", err)
	}

	// Encapsulated Request = header || enc || ct
	var buf bytes.Buffer
	buf.Write(header)
	buf.Write(enc)
	buf.Write(ciphertext)

	return buf.Bytes(), sealer, nil
}

// DecapsulateResponse decrypts an OHTTP response.
// This is primarily for testing - clients should use the frontend implementation.
func DecapsulateResponse(encResponse []byte, enc []byte, sealer hpke.Sealer) (*http.Response, error) {
	// Get AEAD parameters
	Nk := uint(AeadID.KeySize())
	Nn := uint(AeadID.NonceSize())
	secretLen := Nk
	if Nn > secretLen {
		secretLen = Nn
	}

	if len(encResponse) < int(secretLen) {
		return nil, fmt.Errorf("encapsulated response too short")
	}

	responseNonce := encResponse[:secretLen]
	ciphertext := encResponse[secretLen:]

	// Export secret
	secret := sealer.Export([]byte("message/bhttp response"), secretLen)

	// Derive key and nonce
	salt := make([]byte, len(enc)+len(responseNonce))
	copy(salt, enc)
	copy(salt[len(enc):], responseNonce)

	prk := KdfID.Extract(secret, salt)
	aeadKey := KdfID.Expand(prk, []byte("key"), Nk)
	aeadNonce := KdfID.Expand(prk, []byte("nonce"), Nn)

	// Decrypt
	aead, err := AeadID.New(aeadKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create AEAD: %w", err)
	}

	plaintext, err := aead.Open(nil, aeadNonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("AEAD decryption failed: %w", err)
	}

	// Parse Binary HTTP response
	return decodeBinaryHTTPResponse(plaintext)
}

// decodeBinaryHTTPResponse parses a Binary HTTP response.
func decodeBinaryHTTPResponse(data []byte) (*http.Response, error) {
	r := bytes.NewReader(data)

	// Framing indicator
	framing, err := readVarint(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read framing: %w", err)
	}
	if framing != 0 {
		return nil, fmt.Errorf("unsupported framing: %d", framing)
	}

	// Status code
	statusCode, err := readVarint(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read status: %w", err)
	}

	// Headers
	headers, err := readFieldSection(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read headers: %w", err)
	}

	// Body
	body, err := readContent(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read body: %w", err)
	}

	return &http.Response{
		StatusCode: int(statusCode),
		Status:     fmt.Sprintf("%d", statusCode),
		Header:     headers,
		Body:       io.NopCloser(bytes.NewReader(body)),
	}, nil
}

// parseURL is a helper to parse URLs.
func parseURL(rawURL string) (*struct {
	Scheme   string
	Host     string
	Path     string
	RawQuery string
}, error) {
	// Simple URL parsing
	result := &struct {
		Scheme   string
		Host     string
		Path     string
		RawQuery string
	}{}

	// Find scheme
	schemeEnd := bytes.Index([]byte(rawURL), []byte("://"))
	if schemeEnd == -1 {
		return nil, fmt.Errorf("missing scheme")
	}
	result.Scheme = rawURL[:schemeEnd]
	rest := rawURL[schemeEnd+3:]

	// Find host/path boundary
	pathStart := bytes.IndexByte([]byte(rest), '/')
	if pathStart == -1 {
		result.Host = rest
		result.Path = "/"
	} else {
		result.Host = rest[:pathStart]
		pathAndQuery := rest[pathStart:]

		// Separate path and query
		queryStart := bytes.IndexByte([]byte(pathAndQuery), '?')
		if queryStart == -1 {
			result.Path = pathAndQuery
		} else {
			result.Path = pathAndQuery[:queryStart]
			result.RawQuery = pathAndQuery[queryStart+1:]
		}
	}

	return result, nil
}
