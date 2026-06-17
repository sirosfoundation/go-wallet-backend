package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

var (
	ErrWIANotSupported     = errors.New("WIA not supported: keys not configured")
	ErrWIAChallengeExpired = errors.New("WIA challenge expired or invalid")
	ErrWIAPopInvalid       = errors.New("WIA-PoP validation failed")
)

// WIAChallenge is a single-use nonce for WIA generation.
type WIAChallenge struct {
	Challenge string
	ExpiresAt time.Time
}

// WIAService handles Wallet Instance Attestation (CS-04 §7.1.2, §7.1.4).
type WIAService struct {
	cfg        *config.Config
	logger     *zap.Logger
	privateKey *ecdsa.PrivateKey
	certChain  []string

	// In-memory challenge store (single-use nonces).
	// Production: replace with storage.Store for multi-instance.
	mu         sync.Mutex
	challenges map[string]*WIAChallenge
}

// NewWIAService creates a new WIA service.
// It shares the same signing key as the WalletProviderService (same x5c chain).
func NewWIAService(cfg *config.Config, logger *zap.Logger, privateKey *ecdsa.PrivateKey, certChain []string) *WIAService {
	return &WIAService{
		cfg:        cfg,
		logger:     logger.Named("wia-service"),
		privateKey: privateKey,
		certChain:  certChain,
		challenges: make(map[string]*WIAChallenge),
	}
}

// IsSupported returns true if WIA generation is available.
func (s *WIAService) IsSupported() bool {
	return s.privateKey != nil && len(s.certChain) > 0
}

// CreateChallenge generates a new single-use challenge nonce.
func (s *WIAService) CreateChallenge(ctx context.Context) (string, time.Time, error) {
	if !s.IsSupported() {
		return "", time.Time{}, ErrWIANotSupported
	}

	// Generate random nonce
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return "", time.Time{}, fmt.Errorf("generate nonce: %w", err)
	}
	challenge := base64.RawURLEncoding.EncodeToString(nonce)

	ttl := time.Duration(s.cfg.WalletProvider.WIA.ChallengeTTLSeconds) * time.Second
	expiresAt := time.Now().Add(ttl)

	s.mu.Lock()
	// Best-effort pruning of expired, unconsumed challenges
	now := time.Now()
	for k, v := range s.challenges {
		if now.After(v.ExpiresAt) {
			delete(s.challenges, k)
		}
	}
	s.challenges[challenge] = &WIAChallenge{
		Challenge: challenge,
		ExpiresAt: expiresAt,
	}
	s.mu.Unlock()

	s.logger.Debug("WIA challenge created", zap.String("challenge", challenge[:8]+"..."))
	return challenge, expiresAt, nil
}

// consumeChallenge validates and removes a challenge (single-use).
func (s *WIAService) consumeChallenge(challenge string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	c, ok := s.challenges[challenge]
	if !ok {
		return ErrWIAChallengeExpired
	}
	delete(s.challenges, challenge)

	if time.Now().After(c.ExpiresAt) {
		return ErrWIAChallengeExpired
	}
	return nil
}

// WIARequest contains the parameters for WIA generation.
type WIARequest struct {
	// Pop is the WIA-PoP JWT (typ: oauth-client-attestation-pop+jwt)
	Pop string `json:"pop"`
	// Challenge is the nonce from CreateChallenge
	Challenge string `json:"challenge"`
}

// WIAPopClaims are the expected claims in a WIA-PoP JWT.
type WIAPopClaims struct {
	jwt.RegisteredClaims
	Nonce string `json:"nonce"`
}

// GenerateWIA validates the WIA-PoP and generates a WIA JWT.
func (s *WIAService) GenerateWIA(ctx context.Context, req *WIARequest) (string, error) {
	if !s.IsSupported() {
		return "", ErrWIANotSupported
	}

	// Step 1: Consume challenge (single-use)
	if err := s.consumeChallenge(req.Challenge); err != nil {
		return "", err
	}

	// Step 2: Parse and validate WIA-PoP
	cnfJWK, err := s.validatePop(req.Pop, req.Challenge)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrWIAPopInvalid, err)
	}

	// Step 3: Generate WIA JWT
	return s.signWIA(cnfJWK)
}

// validatePop validates the WIA-PoP JWT and extracts the cnf key.
func (s *WIAService) validatePop(popJWT string, expectedNonce string) (map[string]interface{}, error) {
	// Parse without verification first to extract the key
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	token, _, err := parser.ParseUnverified(popJWT, &WIAPopClaims{})
	if err != nil {
		return nil, fmt.Errorf("parse pop: %w", err)
	}

	// Check typ header
	typ, _ := token.Header["typ"].(string)
	if typ != "oauth-client-attestation-pop+jwt" {
		return nil, fmt.Errorf("invalid typ: %q, expected oauth-client-attestation-pop+jwt", typ)
	}

	// Extract JWK from header for verification
	jwkRaw, ok := token.Header["jwk"]
	if !ok {
		return nil, errors.New("pop JWT missing jwk header")
	}
	jwkMap, ok := jwkRaw.(map[string]interface{})
	if !ok {
		return nil, errors.New("pop JWT jwk header not a JSON object")
	}

	// Parse the public key from JWK for signature verification
	pubKey, err := parseECPublicKeyFromJWK(jwkMap)
	if err != nil {
		return nil, fmt.Errorf("parse pop jwk: %w", err)
	}

	// Now verify the signature
	claims := &WIAPopClaims{}
	_, err = jwt.ParseWithClaims(popJWT, claims, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodECDSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return pubKey, nil
	}, jwt.WithValidMethods([]string{"ES256", "ES384", "ES512"}),
		jwt.WithLeeway(config.JWTLeeway))
	if err != nil {
		return nil, fmt.Errorf("pop signature verification: %w", err)
	}

	// Validate nonce matches challenge
	if claims.Nonce != expectedNonce {
		return nil, fmt.Errorf("nonce mismatch")
	}

	// Validate exp is present and not too far in the future (max 10 minutes)
	if claims.ExpiresAt == nil {
		return nil, errors.New("pop missing exp claim")
	}
	maxPopExpiry := time.Now().Add(10 * time.Minute)
	if claims.ExpiresAt.After(maxPopExpiry) {
		return nil, fmt.Errorf("pop exp too far in future (max 10m)")
	}

	// Validate iss is present (wallet instance identifier)
	if claims.Issuer == "" {
		return nil, errors.New("pop missing iss claim")
	}

	return jwkMap, nil
}

// signWIA creates the WIA JWT (typ: oauth-client-attestation+jwt).
func (s *WIAService) signWIA(cnfJWK map[string]interface{}) (string, error) {
	now := time.Now()
	maxExpiry := time.Duration(s.cfg.WalletProvider.WIA.MaxExpirySeconds) * time.Second

	// Build cnf claim with JWK thumbprint and full key
	jkt, err := computeJKT(cnfJWK)
	if err != nil {
		return "", fmt.Errorf("compute jkt: %w", err)
	}

	claims := jwt.MapClaims{
		"cnf": map[string]interface{}{
			"jwk": cnfJWK,
			"jkt": jkt,
		},
		"wallet_name":    s.cfg.WalletProvider.WIA.WalletName,
		"wallet_version": s.cfg.WalletProvider.WIA.WalletVersion,
		"iat":            now.Unix(),
		"exp":            now.Add(maxExpiry).Unix(),
		// attestation_source indicates backend-only attestation (Tier 3 baseline)
		"attestation_source": "backend_attested",
	}

	if s.cfg.WalletProvider.WIA.WalletLink != "" {
		claims["wallet_link"] = s.cfg.WalletProvider.WIA.WalletLink
	}

	// client_status placeholder — populated when Token Status List is implemented
	claims["client_status"] = map[string]interface{}{}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["typ"] = "oauth-client-attestation+jwt"
	token.Header["x5c"] = s.certChain

	// Per EC TS03 §2.2.1: no `iss` claim — identity derived from x5c chain

	tokenString, err := token.SignedString(s.privateKey)
	if err != nil {
		s.logger.Error("Failed to sign WIA JWT", zap.Error(err))
		return "", err
	}

	s.logger.Info("WIA generated", zap.String("jkt", jkt[:8]+"..."))
	return tokenString, nil
}

// computeJKT computes the JWK Thumbprint (RFC 7638) for the given JWK.
func computeJKT(jwk map[string]interface{}) (string, error) {
	// For EC keys, thumbprint input is {"crv":"...","kty":"EC","x":"...","y":"..."}
	kty, _ := jwk["kty"].(string)
	if kty != "EC" {
		return "", fmt.Errorf("unsupported key type for JKT: %s", kty)
	}

	crv, _ := jwk["crv"].(string)
	x, _ := jwk["x"].(string)
	y, _ := jwk["y"].(string)

	if crv == "" || x == "" || y == "" {
		return "", errors.New("incomplete EC JWK (missing crv, x, or y)")
	}

	// RFC 7638: lexicographic order of required members
	thumbprintInput := fmt.Sprintf(`{"crv":"%s","kty":"EC","x":"%s","y":"%s"}`, crv, x, y)
	hash := sha256.Sum256([]byte(thumbprintInput))
	return base64.RawURLEncoding.EncodeToString(hash[:]), nil
}

// parseECPublicKeyFromJWK parses an EC public key from a JWK map.
func parseECPublicKeyFromJWK(jwk map[string]interface{}) (*ecdsa.PublicKey, error) {
	kty, _ := jwk["kty"].(string)
	if kty != "EC" {
		return nil, fmt.Errorf("unsupported key type: %s", kty)
	}

	crv, _ := jwk["crv"].(string)
	xB64, _ := jwk["x"].(string)
	yB64, _ := jwk["y"].(string)

	if crv == "" || xB64 == "" || yB64 == "" {
		return nil, errors.New("incomplete EC JWK")
	}

	xBytes, err := base64.RawURLEncoding.DecodeString(xB64)
	if err != nil {
		return nil, fmt.Errorf("decode x: %w", err)
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(yB64)
	if err != nil {
		return nil, fmt.Errorf("decode y: %w", err)
	}

	curve := ellipticCurveForName(crv)
	if curve == nil {
		return nil, fmt.Errorf("unsupported curve: %s", crv)
	}

	// Build uncompressed point encoding: 0x04 || x || y
	byteLen := (curve.Params().BitSize + 7) / 8
	// Pad x and y to the correct length
	for len(xBytes) < byteLen {
		xBytes = append([]byte{0}, xBytes...)
	}
	for len(yBytes) < byteLen {
		yBytes = append([]byte{0}, yBytes...)
	}
	uncompressed := make([]byte, 1+2*byteLen)
	uncompressed[0] = 0x04
	copy(uncompressed[1:1+byteLen], xBytes)
	copy(uncompressed[1+byteLen:], yBytes)

	pubKey, err := ecdsa.ParseUncompressedPublicKey(curve, uncompressed)
	if err != nil {
		return nil, fmt.Errorf("invalid EC point: %w", err)
	}

	return pubKey, nil
}

// ellipticCurveForName returns the elliptic curve for the given JWK crv name.
func ellipticCurveForName(name string) elliptic.Curve {
	switch name {
	case "P-256":
		return elliptic.P256()
	case "P-384":
		return elliptic.P384()
	case "P-521":
		return elliptic.P521()
	default:
		return nil
	}
}

// CleanupExpiredChallenges removes expired challenges from the in-memory store.
func (s *WIAService) CleanupExpiredChallenges() {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	for k, c := range s.challenges {
		if now.After(c.ExpiresAt) {
			delete(s.challenges, k)
		}
	}
}
