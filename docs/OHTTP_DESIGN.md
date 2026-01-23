# Oblivious HTTP (OHTTP) Implementation Design

## Overview

This document proposes an implementation of RFC 9458 Oblivious HTTP (OHTTP) for the go-wallet-backend that:
1. Is compatible with the existing wallet-frontend OHTTP implementation
2. Works both with and without an external relay
3. Integrates with the existing proxy security infrastructure

## Background

### What OHTTP Provides

OHTTP creates IP unlinkability between the wallet and target servers (issuers/verifiers):

```
Without OHTTP:
┌────────┐           ┌──────────┐
│ Wallet │ ────────> │  Issuer  │    Issuer sees wallet's IP
└────────┘           └──────────┘

With OHTTP:
┌────────┐    ┌───────┐    ┌─────────┐    ┌──────────┐
│ Wallet │ -> │ Relay │ -> │ Gateway │ -> │  Issuer  │
└────────┘    └───────┘    └─────────┘    └──────────┘
                ↑              ↑
           Sees wallet IP   Sees issuer IP
           Can't decrypt    Can decrypt but
           content          doesn't see wallet IP
```

### Frontend Implementation

The wallet-frontend already has OHTTP support:
- Configuration: `VITE_OHTTP_KEY_CONFIG` (gateway key config URL) and `VITE_OHTTP_RELAY` (relay URL)
- Library: `@hpke/core` + `@hpke/dhkem-x25519` for HPKE
- Algorithms: X25519 (KEM 0x0020), HKDF-SHA256 (KDF 0x0001), AES-128-GCM (AEAD 0x0001)
- Message format: Binary HTTP (RFC 9292)

## Architecture

### Mode 1: Backend as Gateway + Integrated Relay

When no external relay is configured, the backend acts as both relay and gateway. This still provides some privacy benefit:
- Target servers see the backend's IP, not the wallet's IP
- Useful when the wallet frontend is behind NAT or has a dynamic IP

```
┌────────────┐         ┌─────────────────────────────────┐         ┌────────┐
│   Wallet   │  OHTTP  │         Backend                 │  HTTPS  │ Target │
│  Frontend  │ ──────> │  /api/relay -> /ohttp/gateway   │ ──────> │ Server │
└────────────┘         └─────────────────────────────────┘         └────────┘
```

### Mode 2: Backend as Gateway with External Relay

For maximum privacy, an external relay (operated by a third party) sits between the wallet and the backend:

```
┌────────┐         ┌──────────────┐         ┌─────────────────┐         ┌────────┐
│ Wallet │  OHTTP  │   External   │  OHTTP  │     Backend     │  HTTPS  │ Target │
│Frontend│ ──────> │    Relay     │ ──────> │ /ohttp/gateway  │ ──────> │ Server │
└────────┘         └──────────────┘         └─────────────────┘         └────────┘
```

## API Endpoints

### `GET /.well-known/ohttp-keys`

Returns the gateway's OHTTP key configuration in `application/ohttp-keys` format.

**Response Format** (RFC 9458 §3):
```
KeyConfig {
   Key Identifier (8 bits),
   KEM Identifier (16 bits),
   Public Key (Npk bytes),
   Cipher Suites Length (16 bits),
   Cipher Suites (4 * Length bytes) {
     KDF Identifier (16 bits),
     AEAD Identifier (16 bits),
   } ...
}
```

### `POST /ohttp/gateway`

Decapsulates an OHTTP request, validates the target URL via the proxy filter, forwards the request, and encapsulates the response.

**Request**:
- Content-Type: `message/ohttp-req`
- Body: Encapsulated Request (RFC 9458 §4.1)

**Response**:
- Content-Type: `message/ohttp-res`
- Body: Encapsulated Response (RFC 9458 §4.2)

### `POST /api/relay` (Integrated Relay Mode)

When operating without an external relay, this endpoint receives OHTTP requests from the frontend and forwards them to the gateway endpoint.

**Request**:
- Content-Type: `message/ohttp-req`
- Body: Encapsulated Request
- Authorization: Bearer token (standard auth)

**Response**:
- Content-Type: `message/ohttp-res`
- Body: Encapsulated Response

## Implementation

### Package Structure

```
pkg/ohttp/
├── gateway.go       # OHTTP gateway implementation
├── gateway_test.go
├── keys.go          # Key configuration management
├── keys_test.go
├── bhttp.go         # Binary HTTP encoding/decoding
├── bhttp_test.go
└── handler.go       # HTTP handlers
```

### Key Management

```go
// pkg/ohttp/keys.go

package ohttp

import (
    "crypto/rand"
    "encoding/binary"
    
    "github.com/cloudflare/circl/hpke"
    "github.com/cloudflare/circl/kem"
)

const (
    // OHTTP uses X25519 + HKDF-SHA256 + AES-128-GCM (matching frontend)
    KemID  = hpke.KEM_X25519_HKDF_SHA256 // 0x0020
    KdfID  = hpke.KDF_HKDF_SHA256        // 0x0001
    AeadID = hpke.AEAD_AES128GCM         // 0x0001
)

// KeyConfig holds the gateway's OHTTP key configuration.
type KeyConfig struct {
    KeyID      uint8
    PrivateKey kem.PrivateKey
    PublicKey  kem.PublicKey
    Suite      hpke.Suite
}

// NewKeyConfig generates a new OHTTP key configuration.
func NewKeyConfig(keyID uint8) (*KeyConfig, error) {
    suite := hpke.NewSuite(KemID, KdfID, AeadID)
    scheme := KemID.Scheme()
    
    publicKey, privateKey, err := scheme.GenerateKeyPair()
    if err != nil {
        return nil, err
    }
    
    return &KeyConfig{
        KeyID:      keyID,
        PrivateKey: privateKey,
        PublicKey:  publicKey,
        Suite:      suite,
    }, nil
}

// MarshalBinary serializes the key config for /.well-known/ohttp-keys
func (kc *KeyConfig) MarshalBinary() ([]byte, error) {
    scheme := KemID.Scheme()
    pubBytes, err := kc.PublicKey.MarshalBinary()
    if err != nil {
        return nil, err
    }
    
    // Format per RFC 9458 §3
    // Length prefix (2 bytes) + KeyID (1) + KEM (2) + PubKey (32) + SuitesLen (2) + Suite (4)
    configLen := 1 + 2 + len(pubBytes) + 2 + 4
    buf := make([]byte, 2+configLen)
    
    binary.BigEndian.PutUint16(buf[0:2], uint16(configLen))
    offset := 2
    
    buf[offset] = kc.KeyID
    offset++
    
    binary.BigEndian.PutUint16(buf[offset:offset+2], uint16(KemID))
    offset += 2
    
    copy(buf[offset:], pubBytes)
    offset += len(pubBytes)
    
    // One cipher suite: HKDF-SHA256 + AES-128-GCM
    binary.BigEndian.PutUint16(buf[offset:offset+2], 4) // suites length
    offset += 2
    binary.BigEndian.PutUint16(buf[offset:offset+2], uint16(KdfID))
    offset += 2
    binary.BigEndian.PutUint16(buf[offset:offset+2], uint16(AeadID))
    
    return buf, nil
}
```

### Gateway Implementation

```go
// pkg/ohttp/gateway.go

package ohttp

import (
    "bytes"
    "crypto/rand"
    "encoding/binary"
    "fmt"
    "io"
    "net/http"
    
    "github.com/cloudflare/circl/hpke"
)

// Gateway decapsulates OHTTP requests and encapsulates responses.
type Gateway struct {
    keyConfig   *KeyConfig
    proxyFilter ProxyFilterer // Interface to existing proxy filter
    httpClient  *http.Client
}

// ProxyFilterer is the interface to the proxy security filter.
type ProxyFilterer interface {
    IsAllowed(rawURL string) (bool, string)
}

// NewGateway creates an OHTTP gateway.
func NewGateway(keyConfig *KeyConfig, filter ProxyFilterer, client *http.Client) *Gateway {
    return &Gateway{
        keyConfig:   keyConfig,
        proxyFilter: filter,
        httpClient:  client,
    }
}

// DecapsulateRequest decrypts an OHTTP request.
func (g *Gateway) DecapsulateRequest(encapsulated []byte) (*http.Request, hpke.Opener, error) {
    // Parse encapsulated request header (RFC 9458 §4.1)
    if len(encapsulated) < 7 {
        return nil, nil, fmt.Errorf("encapsulated request too short")
    }
    
    keyID := encapsulated[0]
    if keyID != g.keyConfig.KeyID {
        return nil, nil, fmt.Errorf("unknown key ID: %d", keyID)
    }
    
    kemID := binary.BigEndian.Uint16(encapsulated[1:3])
    kdfID := binary.BigEndian.Uint16(encapsulated[3:5])
    aeadID := binary.BigEndian.Uint16(encapsulated[5:7])
    
    // Verify algorithms match
    if kemID != uint16(KemID) || kdfID != uint16(KdfID) || aeadID != uint16(AeadID) {
        return nil, nil, fmt.Errorf("unsupported algorithms")
    }
    
    // X25519 public key is 32 bytes
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
        return nil, nil, fmt.Errorf("failed to create receiver: %w", err)
    }
    
    opener, err := receiver.Setup(enc)
    if err != nil {
        return nil, nil, fmt.Errorf("failed to setup opener: %w", err)
    }
    
    // Decrypt
    plaintext, err := opener.Open(ciphertext, nil)
    if err != nil {
        return nil, nil, fmt.Errorf("decryption failed: %w", err)
    }
    
    // Parse Binary HTTP request
    req, err := DecodeBinaryHTTPRequest(plaintext)
    if err != nil {
        return nil, nil, fmt.Errorf("failed to parse binary HTTP: %w", err)
    }
    
    return req, opener, nil
}

// EncapsulateResponse encrypts an HTTP response.
func (g *Gateway) EncapsulateResponse(resp *http.Response, opener hpke.Opener) ([]byte, error) {
    // Encode response as Binary HTTP
    bhttpResp, err := EncodeBinaryHTTPResponse(resp)
    if err != nil {
        return nil, fmt.Errorf("failed to encode binary HTTP: %w", err)
    }
    
    // Get AEAD parameters
    Nk := uint(AeadID.KeySize())
    Nn := uint(AeadID.NonceSize())
    L := Nk
    if Nn > L {
        L = Nn
    }
    
    // Generate response nonce
    responseNonce := make([]byte, L)
    if _, err := rand.Read(responseNonce); err != nil {
        return nil, fmt.Errorf("failed to generate nonce: %w", err)
    }
    
    // Export secret for response encryption
    secret := opener.Export([]byte("message/bhttp response"), L)
    
    // Derive key and nonce using HKDF
    // Note: We need enc from the request, which should be stored
    // For now, this is a simplified version
    aeadKey := KdfID.Expand(KdfID.Extract(secret, responseNonce), []byte("key"), Nk)
    aeadNonce := KdfID.Expand(KdfID.Extract(secret, responseNonce), []byte("nonce"), Nn)
    
    // Encrypt response
    aead, err := AeadID.New(aeadKey)
    if err != nil {
        return nil, fmt.Errorf("failed to create AEAD: %w", err)
    }
    
    ciphertext := aead.Seal(nil, aeadNonce, bhttpResp, nil)
    
    // Encapsulated response = response_nonce || ciphertext
    result := make([]byte, len(responseNonce)+len(ciphertext))
    copy(result, responseNonce)
    copy(result[len(responseNonce):], ciphertext)
    
    return result, nil
}

// HandleRequest processes a complete OHTTP request.
func (g *Gateway) HandleRequest(encapsulated []byte) ([]byte, error) {
    // Decapsulate
    req, opener, err := g.DecapsulateRequest(encapsulated)
    if err != nil {
        return nil, fmt.Errorf("decapsulation failed: %w", err)
    }
    
    // Validate target URL via proxy filter
    targetURL := req.URL.String()
    if allowed, reason := g.proxyFilter.IsAllowed(targetURL); !allowed {
        return nil, fmt.Errorf("target URL blocked: %s", reason)
    }
    
    // Forward request
    resp, err := g.httpClient.Do(req)
    if err != nil {
        return nil, fmt.Errorf("target request failed: %w", err)
    }
    defer resp.Body.Close()
    
    // Encapsulate response
    return g.EncapsulateResponse(resp, opener)
}
```

### Binary HTTP Implementation

```go
// pkg/ohttp/bhttp.go

package ohttp

import (
    "bytes"
    "encoding/binary"
    "fmt"
    "io"
    "net/http"
    "net/url"
)

// DecodeBinaryHTTPRequest parses a Binary HTTP request (RFC 9292).
func DecodeBinaryHTTPRequest(data []byte) (*http.Request, error) {
    r := bytes.NewReader(data)
    
    // Framing indicator (known-length request = 0)
    framing, err := readVarint(r)
    if err != nil {
        return nil, err
    }
    if framing != 0 {
        return nil, fmt.Errorf("unsupported framing indicator: %d", framing)
    }
    
    // Request control data: method, scheme, authority, path
    method, err := readLengthPrefixedString(r)
    if err != nil {
        return nil, fmt.Errorf("failed to read method: %w", err)
    }
    
    scheme, err := readLengthPrefixedString(r)
    if err != nil {
        return nil, fmt.Errorf("failed to read scheme: %w", err)
    }
    
    authority, err := readLengthPrefixedString(r)
    if err != nil {
        return nil, fmt.Errorf("failed to read authority: %w", err)
    }
    
    path, err := readLengthPrefixedString(r)
    if err != nil {
        return nil, fmt.Errorf("failed to read path: %w", err)
    }
    
    // Build URL
    u := &url.URL{
        Scheme: scheme,
        Host:   authority,
        Path:   path,
    }
    if idx := bytes.IndexByte([]byte(path), '?'); idx >= 0 {
        u.Path = path[:idx]
        u.RawQuery = path[idx+1:]
    }
    
    // Headers (known-length field section)
    headers, err := readFieldSection(r)
    if err != nil {
        return nil, fmt.Errorf("failed to read headers: %w", err)
    }
    
    // Body (known-length content)
    body, err := readContent(r)
    if err != nil {
        return nil, fmt.Errorf("failed to read body: %w", err)
    }
    
    // Build http.Request
    req, err := http.NewRequest(method, u.String(), bytes.NewReader(body))
    if err != nil {
        return nil, err
    }
    
    for name, value := range headers {
        req.Header.Set(name, value)
    }
    
    return req, nil
}

// EncodeBinaryHTTPResponse encodes an HTTP response as Binary HTTP.
func EncodeBinaryHTTPResponse(resp *http.Response) ([]byte, error) {
    var buf bytes.Buffer
    
    // Framing indicator (known-length response = 0)
    buf.Write(encodeVarint(0))
    
    // Response control data: status code
    buf.Write(encodeVarint(uint64(resp.StatusCode)))
    
    // Headers
    if err := writeFieldSection(&buf, resp.Header); err != nil {
        return nil, err
    }
    
    // Body
    body, err := io.ReadAll(resp.Body)
    if err != nil {
        return nil, err
    }
    if err := writeContent(&buf, body); err != nil {
        return nil, err
    }
    
    // Empty trailers
    buf.Write(encodeVarint(0))
    
    return buf.Bytes(), nil
}

// Varint encoding (RFC 9292 / QUIC style)
func encodeVarint(v uint64) []byte {
    if v <= 63 {
        return []byte{byte(v)}
    }
    if v <= 16383 {
        return []byte{byte(0x40 | (v >> 8)), byte(v)}
    }
    if v <= 1073741823 {
        return []byte{
            byte(0x80 | (v >> 24)),
            byte(v >> 16),
            byte(v >> 8),
            byte(v),
        }
    }
    return []byte{
        byte(0xC0 | (v >> 56)),
        byte(v >> 48),
        byte(v >> 40),
        byte(v >> 32),
        byte(v >> 24),
        byte(v >> 16),
        byte(v >> 8),
        byte(v),
    }
}

func readVarint(r io.Reader) (uint64, error) {
    var first [1]byte
    if _, err := r.Read(first[:]); err != nil {
        return 0, err
    }
    
    prefix := first[0] >> 6
    switch prefix {
    case 0:
        return uint64(first[0] & 0x3F), nil
    case 1:
        var second [1]byte
        if _, err := r.Read(second[:]); err != nil {
            return 0, err
        }
        return uint64(first[0]&0x3F)<<8 | uint64(second[0]), nil
    case 2:
        var rest [3]byte
        if _, err := io.ReadFull(r, rest[:]); err != nil {
            return 0, err
        }
        return uint64(first[0]&0x3F)<<24 | uint64(rest[0])<<16 | uint64(rest[1])<<8 | uint64(rest[2]), nil
    case 3:
        var rest [7]byte
        if _, err := io.ReadFull(r, rest[:]); err != nil {
            return 0, err
        }
        return uint64(first[0]&0x3F)<<56 | uint64(rest[0])<<48 | uint64(rest[1])<<40 |
            uint64(rest[2])<<32 | uint64(rest[3])<<24 | uint64(rest[4])<<16 |
            uint64(rest[5])<<8 | uint64(rest[6]), nil
    }
    return 0, fmt.Errorf("invalid varint")
}

func readLengthPrefixedString(r io.Reader) (string, error) {
    length, err := readVarint(r)
    if err != nil {
        return "", err
    }
    data := make([]byte, length)
    if _, err := io.ReadFull(r, data); err != nil {
        return "", err
    }
    return string(data), nil
}

func readFieldSection(r io.Reader) (map[string]string, error) {
    sectionLen, err := readVarint(r)
    if err != nil {
        return nil, err
    }
    
    headers := make(map[string]string)
    section := make([]byte, sectionLen)
    if _, err := io.ReadFull(r, section); err != nil {
        return nil, err
    }
    
    sr := bytes.NewReader(section)
    for sr.Len() > 0 {
        name, err := readLengthPrefixedString(sr)
        if err != nil {
            return nil, err
        }
        value, err := readLengthPrefixedString(sr)
        if err != nil {
            return nil, err
        }
        headers[name] = value
    }
    
    return headers, nil
}

func readContent(r io.Reader) ([]byte, error) {
    length, err := readVarint(r)
    if err != nil {
        return nil, err
    }
    data := make([]byte, length)
    if _, err := io.ReadFull(r, data); err != nil {
        return nil, err
    }
    return data, nil
}

func writeFieldSection(w io.Writer, headers http.Header) error {
    var buf bytes.Buffer
    for name, values := range headers {
        for _, value := range values {
            // Write field line: name_len, name, value_len, value
            buf.Write(encodeVarint(uint64(len(name))))
            buf.WriteString(name)
            buf.Write(encodeVarint(uint64(len(value))))
            buf.WriteString(value)
        }
    }
    w.Write(encodeVarint(uint64(buf.Len())))
    w.Write(buf.Bytes())
    return nil
}

func writeContent(w io.Writer, data []byte) error {
    w.Write(encodeVarint(uint64(len(data))))
    w.Write(data)
    return nil
}
```

### HTTP Handlers

```go
// pkg/ohttp/handler.go

package ohttp

import (
    "io"
    "net/http"
    
    "github.com/gin-gonic/gin"
    "go.uber.org/zap"
)

// Handler provides HTTP handlers for OHTTP endpoints.
type Handler struct {
    gateway *Gateway
    logger  *zap.Logger
}

// NewHandler creates an OHTTP handler.
func NewHandler(gateway *Gateway, logger *zap.Logger) *Handler {
    return &Handler{
        gateway: gateway,
        logger:  logger.Named("ohttp"),
    }
}

// KeysHandler returns the gateway's key configuration.
// GET /.well-known/ohttp-keys
func (h *Handler) KeysHandler(c *gin.Context) {
    keys, err := h.gateway.keyConfig.MarshalBinary()
    if err != nil {
        h.logger.Error("Failed to marshal key config", zap.Error(err))
        c.Status(http.StatusInternalServerError)
        return
    }
    
    c.Data(http.StatusOK, "application/ohttp-keys", keys)
}

// GatewayHandler decapsulates requests and encapsulates responses.
// POST /ohttp/gateway
func (h *Handler) GatewayHandler(c *gin.Context) {
    contentType := c.GetHeader("Content-Type")
    if contentType != "message/ohttp-req" {
        c.Status(http.StatusBadRequest)
        return
    }
    
    encapsulated, err := io.ReadAll(c.Request.Body)
    if err != nil {
        h.logger.Error("Failed to read request body", zap.Error(err))
        c.Status(http.StatusBadRequest)
        return
    }
    
    response, err := h.gateway.HandleRequest(encapsulated)
    if err != nil {
        h.logger.Error("Gateway request failed", zap.Error(err))
        // Return 400 for decapsulation errors, 502 for target errors
        // Don't leak details to prevent oracle attacks
        c.Status(http.StatusBadGateway)
        return
    }
    
    c.Data(http.StatusOK, "message/ohttp-res", response)
}

// RelayHandler acts as an integrated relay (for mode without external relay).
// POST /api/relay
// This endpoint requires authentication and forwards to the gateway.
func (h *Handler) RelayHandler(c *gin.Context) {
    // Auth is handled by middleware before this handler
    
    contentType := c.GetHeader("Content-Type")
    if contentType != "message/ohttp-req" {
        c.Status(http.StatusBadRequest)
        return
    }
    
    encapsulated, err := io.ReadAll(c.Request.Body)
    if err != nil {
        h.logger.Error("Failed to read request body", zap.Error(err))
        c.Status(http.StatusBadRequest)
        return
    }
    
    // Forward to gateway (inline, since we're the same process)
    response, err := h.gateway.HandleRequest(encapsulated)
    if err != nil {
        h.logger.Error("Gateway request failed", zap.Error(err))
        c.Status(http.StatusBadGateway)
        return
    }
    
    c.Data(http.StatusOK, "message/ohttp-res", response)
}
```

## Configuration

```yaml
# config.yaml
ohttp:
  # Enable OHTTP gateway
  enabled: true
  
  # Key ID (1-255, rotated periodically)
  key_id: 1
  
  # Private key file (PEM format, generated if not exists)
  # If not specified, a new key is generated on each startup (not recommended for production)
  private_key_file: /etc/wallet/ohttp-key.pem
  
  # Enable integrated relay mode (backend acts as relay + gateway)
  # When true, /api/relay endpoint is available
  # When false, only /ohttp/gateway is available (requires external relay)
  integrated_relay: true
```

```go
// pkg/config/config.go additions

// OHTTPConfig configures Oblivious HTTP support.
type OHTTPConfig struct {
    // Enabled turns OHTTP on/off
    Enabled bool `yaml:"enabled" envconfig:"OHTTP_ENABLED"`
    
    // KeyID identifies the key (1-255)
    KeyID uint8 `yaml:"key_id" envconfig:"OHTTP_KEY_ID"`
    
    // PrivateKeyFile is the path to the private key PEM file
    // If empty, a new key is generated on each startup
    PrivateKeyFile string `yaml:"private_key_file" envconfig:"OHTTP_PRIVATE_KEY_FILE"`
    
    // IntegratedRelay enables the /api/relay endpoint
    IntegratedRelay bool `yaml:"integrated_relay" envconfig:"OHTTP_INTEGRATED_RELAY"`
}

func DefaultOHTTPConfig() OHTTPConfig {
    return OHTTPConfig{
        Enabled:         false, // Opt-in
        KeyID:           1,
        IntegratedRelay: true,
    }
}
```

## Router Setup

```go
// cmd/server/main.go or pkg/server/router.go

func setupRouter(cfg *config.Config, ...) *gin.Engine {
    r := gin.Default()
    
    // ... existing setup ...
    
    if cfg.OHTTP.Enabled {
        // Load or generate key
        var keyConfig *ohttp.KeyConfig
        if cfg.OHTTP.PrivateKeyFile != "" {
            keyConfig, err = ohttp.LoadKeyConfig(cfg.OHTTP.PrivateKeyFile, cfg.OHTTP.KeyID)
        } else {
            keyConfig, err = ohttp.NewKeyConfig(cfg.OHTTP.KeyID)
            logger.Warn("OHTTP using ephemeral key - not recommended for production")
        }
        
        // Create gateway with proxy filter
        gateway := ohttp.NewGateway(keyConfig, proxyFilter, httpClient)
        ohttpHandler := ohttp.NewHandler(gateway, logger)
        
        // Key configuration endpoint (public)
        r.GET("/.well-known/ohttp-keys", ohttpHandler.KeysHandler)
        
        // Gateway endpoint (no auth - traffic is encrypted)
        r.POST("/ohttp/gateway", ohttpHandler.GatewayHandler)
        
        if cfg.OHTTP.IntegratedRelay {
            // Integrated relay (requires auth to prevent abuse)
            api := r.Group("/api")
            api.Use(authMiddleware)
            api.POST("/relay", ohttpHandler.RelayHandler)
        }
    }
    
    return r
}
```

## Frontend Configuration

For integrated relay mode:
```env
# Frontend .env
VITE_OHTTP_KEY_CONFIG=https://wallet-backend.example.com/.well-known/ohttp-keys
VITE_OHTTP_RELAY=https://wallet-backend.example.com/api/relay
```

For external relay mode:
```env
# Frontend .env
VITE_OHTTP_KEY_CONFIG=https://wallet-backend.example.com/.well-known/ohttp-keys
VITE_OHTTP_RELAY=https://external-relay.example.com/relay
```

The external relay would be configured to forward OHTTP requests to:
```
Target-Gateway: https://wallet-backend.example.com/ohttp/gateway
```

## Security Considerations

### Key Management
- Keys should be persisted and rotated periodically (monthly recommended)
- Key rotation: increment KeyID, publish new key config, keep old key active for 24h
- Private keys should be stored securely (file permissions, secrets manager)

### Proxy Filter Integration
- All decrypted target URLs MUST pass through the existing proxy filter
- This prevents SSRF even through OHTTP
- The RequireHTTPS check is especially important

### Rate Limiting
- The gateway endpoint should have rate limiting
- In integrated relay mode, use existing auth-based rate limiting
- In external relay mode, consider IP-based rate limiting

### Error Handling
- Don't leak decryption errors to prevent oracle attacks
- Return generic 400/502 errors
- Log details server-side for debugging

## Testing

```go
// pkg/ohttp/gateway_test.go

func TestOHTTPRoundTrip(t *testing.T) {
    // Create test server
    target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Type", "application/json")
        w.Write([]byte(`{"status":"ok"}`))
    }))
    defer target.Close()
    
    // Create gateway
    keyConfig, _ := NewKeyConfig(1)
    filter := &mockProxyFilter{allow: true}
    gateway := NewGateway(keyConfig, filter, http.DefaultClient)
    
    // Create encapsulated request (simulate frontend)
    encRequest := encapsulateRequest(keyConfig.PublicKey, "GET", target.URL, nil)
    
    // Process through gateway
    encResponse, err := gateway.HandleRequest(encRequest)
    require.NoError(t, err)
    
    // Decrypt response (simulate frontend)
    response := decapsulateResponse(encResponse, ...)
    assert.Equal(t, 200, response.StatusCode)
    assert.JSONEq(t, `{"status":"ok"}`, string(response.Body))
}
```

## Dependencies

Add to `go.mod`:
```
github.com/cloudflare/circl v1.6.3
```

The `circl` library provides:
- HPKE with X25519 + HKDF-SHA256 + AES-128-GCM
- Well-tested implementation from Cloudflare
- Actively maintained

## Migration Path

1. Add OHTTP package without enabling
2. Deploy backend with OHTTP disabled
3. Enable OHTTP in staging, test with frontend
4. Enable in production with integrated relay
5. (Optional) Set up external relay for full privacy separation

## Future Enhancements

1. **Key Rotation**: Automatic key rotation with old key grace period
2. **Multiple Cipher Suites**: Support additional algorithms
3. **Metrics**: Prometheus metrics for OHTTP requests
4. **External Relay Discovery**: Support for relay discovery protocol
5. **Request Padding**: Add padding to prevent traffic analysis
