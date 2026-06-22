package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-siros-set/set"
	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
	"github.com/sirosfoundation/go-wallet-backend/pkg/audit"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
	"github.com/sirosfoundation/go-wallet-backend/pkg/signing"
)

var (
	ErrWIANotSupported         = errors.New("WIA not supported: keys not configured")
	ErrWIAChallengeExpired     = errors.New("WIA challenge expired or invalid")
	ErrWIAPopInvalid           = errors.New("WIA-PoP validation failed")
	ErrWIAChallengeCapacityMax = errors.New("challenge capacity exceeded")
)

// WIAChallenge is a single-use nonce for WIA generation.
type WIAChallenge struct {
	Challenge string
	ExpiresAt time.Time
	// Linked list pointers for expiry-ordered eviction.
	prev, next *WIAChallenge
}

// challengeStore is a bounded, expiry-ordered map of challenges.
// Expired entries are evicted in O(1) from the front of the list on insert.
type challengeStore struct {
	mu      sync.Mutex
	items   map[string]*WIAChallenge
	head    *WIAChallenge // oldest expiry
	tail    *WIAChallenge // newest expiry
	maxSize int
}

func newChallengeStore(maxSize int) *challengeStore {
	return &challengeStore{
		items:   make(map[string]*WIAChallenge, maxSize),
		maxSize: maxSize,
	}
}

// put adds a challenge, evicting expired entries first. Returns false if at capacity.
func (cs *challengeStore) put(c *WIAChallenge) bool {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	cs.evictExpired()

	if len(cs.items) >= cs.maxSize {
		return false
	}

	cs.items[c.Challenge] = c

	// Append to tail (newest expiry)
	c.prev = cs.tail
	c.next = nil
	if cs.tail != nil {
		cs.tail.next = c
	}
	cs.tail = c
	if cs.head == nil {
		cs.head = c
	}
	return true
}

// consume removes and returns a challenge if it exists and is not expired.
func (cs *challengeStore) consume(challenge string) (*WIAChallenge, bool) {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	c, ok := cs.items[challenge]
	if !ok {
		return nil, false
	}
	cs.removeLocked(c)
	if time.Now().After(c.ExpiresAt) {
		return nil, false
	}
	return c, true
}

// evictExpired removes expired entries from the front of the list (O(1) per entry).
// Must hold cs.mu.
func (cs *challengeStore) evictExpired() {
	now := time.Now()
	for cs.head != nil && now.After(cs.head.ExpiresAt) {
		cs.removeLocked(cs.head)
	}
}

// removeLocked removes a challenge from both the map and the linked list.
// Must hold cs.mu.
func (cs *challengeStore) removeLocked(c *WIAChallenge) {
	delete(cs.items, c.Challenge)
	if c.prev != nil {
		c.prev.next = c.next
	} else {
		cs.head = c.next
	}
	if c.next != nil {
		c.next.prev = c.prev
	} else {
		cs.tail = c.prev
	}
	c.prev = nil
	c.next = nil
}

// len returns the number of stored challenges.
func (cs *challengeStore) len() int {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	return len(cs.items)
}

// WIAService handles Wallet Instance Attestation (CS-04 §7.1.2, §7.1.4).
type WIAService struct {
	cfg          *config.Config
	logger       *zap.Logger
	jwtSigner    *signing.CryptoSignerES256
	certChain    []string
	nativeAttSvc *NativeAttestationService
	instances    storage.WalletInstanceStore
	audit        *audit.Emitter

	// Challenge store for single-use nonces (memory or MongoDB).
	challenges WIAChallengeStore

	// stopCh signals the cleanup goroutine to exit.
	stopCh    chan struct{}
	stopOnce  sync.Once
	startOnce sync.Once
}

// NewWIAService creates a new WIA service.
// It shares the same signing key as the WalletProviderService (same x5c chain).
func NewWIAService(cfg *config.Config, logger *zap.Logger, jwtSigner *signing.CryptoSignerES256, certChain []string, instances storage.WalletInstanceStore, auditor *audit.Emitter, challengeStore WIAChallengeStore) *WIAService {
	if challengeStore == nil {
		challengeStore = newMemoryWIAChallengeStore(maxChallenges)
	}
	svc := &WIAService{
		cfg:        cfg,
		logger:     logger.Named("wia-service"),
		jwtSigner:  jwtSigner,
		certChain:  certChain,
		instances:  instances,
		audit:      auditor,
		challenges: challengeStore,
	}

	// Wire native attestation if configured
	if cfg.WalletProvider.Attestation.NativeAttestation.Enabled {
		svc.nativeAttSvc = NewNativeAttestationService(cfg, logger)
	}

	return svc
}

// IsSupported returns true if WIA generation is available.
func (s *WIAService) IsSupported() bool {
	return s.jwtSigner != nil && len(s.certChain) > 0
}

// maxChallenges is the maximum number of concurrent pending challenges.
// Prevents memory exhaustion from challenge endpoint abuse.
const maxChallenges = 10000

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
	if ttl <= 0 {
		ttl = 5 * time.Minute // sensible default
	}
	expiresAt := time.Now().Add(ttl)

	ok, err := s.challenges.Put(ctx, challenge, expiresAt)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("store challenge: %w", err)
	}
	if !ok {
		challengeCapacityExceeded.Inc()
		return "", time.Time{}, ErrWIAChallengeCapacityMax
	}

	challengeCreatedTotal.Inc()
	s.logger.Debug("WIA challenge created")
	return challenge, expiresAt, nil
}

// consumeChallenge validates and removes a challenge (single-use).
func (s *WIAService) consumeChallenge(ctx context.Context, challenge string) error {
	ok, err := s.challenges.Consume(ctx, challenge)
	if err != nil {
		return fmt.Errorf("consume challenge: %w", err)
	}
	if !ok {
		challengeExpiredTotal.Inc()
		return ErrWIAChallengeExpired
	}
	challengeConsumedTotal.Inc()
	return nil
}

// WIARequest contains the parameters for WIA generation.
type WIARequest struct {
	// Pop is the WIA-PoP JWT (typ: oauth-client-attestation-pop+jwt)
	Pop string `json:"pop"`
	// Challenge is the nonce from CreateChallenge
	Challenge string `json:"challenge"`
	// NativeAttestation is optional platform attestation evidence
	NativeAttestation *NativeAttestationRequest `json:"native_attestation,omitempty"`
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
	start := time.Now()
	defer func() { wiaGenerationDuration.Observe(time.Since(start).Seconds()) }()

	// Step 1: Consume challenge (single-use, atomic).
	// Must happen before PoP validation to prevent concurrent crypto amplification
	// attacks on the same challenge (TOCTOU). The trade-off is that a malformed PoP
	// burns the nonce, but this is acceptable — the nonce is single-use anyway.
	if err := s.consumeChallenge(ctx, req.Challenge); err != nil {
		return "", err
	}

	// Step 2: Parse and validate WIA-PoP
	cnfJWK, err := s.validatePop(req.Pop, req.Challenge)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrWIAPopInvalid, err)
	}

	// Step 3: Determine attestation source
	attestationSource := "backend_attested" // Tier 3 baseline
	if req.NativeAttestation != nil && s.nativeAttSvc != nil {
		// Bind native attestation challenge to the WIA challenge nonce
		if req.NativeAttestation.Challenge != req.Challenge {
			return "", fmt.Errorf("%w: native attestation challenge does not match WIA challenge", ErrWIAPopInvalid)
		}
		result, err := s.nativeAttSvc.Verify(ctx, req.NativeAttestation)
		if err != nil {
			// When native attestation is submitted but fails, reject the request.
			// If the client doesn't want native attestation, it should omit the field.
			nativeAttestationErrors.Inc()
			return "", fmt.Errorf("%w: native attestation failed: %v", ErrWIAPopInvalid, err)
		}
		if result.Verified {
			attestationSource = result.AttestationSource
			nativeAttestationSuccess.Inc()
		}
	}

	// Step 4: Generate WIA JWT
	return s.signWIA(cnfJWK, attestationSource)
}

// validatePop validates the WIA-PoP JWT and extracts the cnf key.
func (s *WIAService) validatePop(popJWT string, expectedNonce string) (map[string]interface{}, error) {
	// Parse without verification first to extract the self-signed JWK from the header.
	// This is the standard pattern for self-signed PoP JWTs (RFC 9449 / DPoP):
	// the key is in the header, so we must parse to get it, then verify below.
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	token, _, err := parser.ParseUnverified(popJWT, &WIAPopClaims{}) //NOSONAR — verified immediately below with ParseWithClaims+WithValidMethods
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
	}, jwt.WithValidMethods([]string{"ES256"}),
		jwt.WithLeeway(config.JWTLeeway))
	if err != nil {
		return nil, fmt.Errorf("pop signature verification: %w", err)
	}

	// Validate nonce matches challenge (constant-time comparison)
	if subtle.ConstantTimeCompare([]byte(claims.Nonce), []byte(expectedNonce)) != 1 {
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

	// Validate iat is present and not too far in the past (max 10 minutes)
	if claims.IssuedAt == nil {
		return nil, errors.New("pop missing iat claim")
	}
	if claims.IssuedAt.Before(time.Now().Add(-10 * time.Minute)) {
		return nil, fmt.Errorf("pop iat too far in past (max 10m)")
	}

	// Validate iss is present (wallet instance identifier)
	if claims.Issuer == "" {
		return nil, errors.New("pop missing iss claim")
	}

	// Validate aud matches wallet provider URI (if configured)
	if s.cfg.WalletProvider.WIA.WalletProviderURI != "" {
		if len(claims.Audience) == 0 {
			return nil, errors.New("pop missing aud claim")
		}
		found := false
		for _, aud := range claims.Audience {
			if aud == s.cfg.WalletProvider.WIA.WalletProviderURI {
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("pop aud %v does not match wallet provider URI", claims.Audience)
		}
	}

	return jwkMap, nil
}

// signWIA creates the WIA JWT (typ: oauth-client-attestation+jwt).
func (s *WIAService) signWIA(cnfJWK map[string]interface{}, attestationSource string) (string, error) {
	now := time.Now()

	// Use global attestation lifetime, capped by WIA max expiry
	lifetime := time.Duration(s.cfg.WalletProvider.Attestation.LifetimeSeconds) * time.Second
	maxExpiry := time.Duration(s.cfg.WalletProvider.WIA.MaxExpirySeconds) * time.Second
	if maxExpiry <= 0 {
		maxExpiry = 24 * time.Hour // sensible default to prevent zero/negative expiry
	}
	if lifetime > maxExpiry || lifetime == 0 {
		lifetime = maxExpiry
	}

	// Build cnf claim with JWK thumbprint and full key
	jkt, err := computeJKT(cnfJWK)
	if err != nil {
		return "", fmt.Errorf("compute jkt: %w", err)
	}

	claims := jwt.MapClaims{
		"sub": jkt, // wallet instance identifier (JWK Thumbprint)
		"jti": uuid.New().String(),
		"cnf": map[string]interface{}{
			"jwk": cnfJWK,
			"jkt": jkt,
		},
		"iat":                now.Unix(),
		"exp":                now.Add(lifetime).Unix(),
		"attestation_source": attestationSource,
	}

	if s.cfg.WalletProvider.WIA.WalletName != "" {
		claims["wallet_name"] = s.cfg.WalletProvider.WIA.WalletName
	}
	if s.cfg.WalletProvider.WIA.WalletVersion != "" {
		claims["wallet_version"] = s.cfg.WalletProvider.WIA.WalletVersion
	}
	if s.cfg.WalletProvider.WIA.WalletLink != "" {
		claims["wallet_link"] = s.cfg.WalletProvider.WIA.WalletLink
	}

	// Wallet solution certification information (Annex C §C.3.2)
	if len(s.cfg.WalletProvider.WIA.CertificationInfo) > 0 {
		claims["wallet_solution_certification_information"] = s.cfg.WalletProvider.WIA.CertificationInfo
	}

	// Client status (WIA revocation via Token Status List, Annex C §C.3.2)
	switch s.cfg.WalletProvider.Attestation.StatusListMode {
	case "always":
		clientStatus := map[string]interface{}{
			"status": map[string]interface{}{
				"status_list": map[string]interface{}{
					"uri": s.cfg.WalletProvider.Attestation.StatusListURL,
					"idx": statusIndexCounter.Add(1),
				},
			},
		}
		if s.cfg.WalletProvider.Attestation.StatusListExpiry > 0 {
			clientStatus["exp"] = now.Add(time.Duration(s.cfg.WalletProvider.Attestation.StatusListExpiry) * time.Second).Unix()
		}
		claims["client_status"] = clientStatus
	case "never":
		// Omit status list for short-lived attestations
	default:
		// "auto" or unset: omit (same as "never" for now)
	}

	// Configurable iss claim. Default is omitted per TS03 §2.2.1 (identity
	// derived from x5c chain), but some national profiles expect it.
	if s.cfg.WalletProvider.WIA.Issuer != "" {
		claims["iss"] = s.cfg.WalletProvider.WIA.Issuer
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["typ"] = "oauth-client-attestation+jwt"
	token.Header["x5c"] = s.certChain

	tokenString, err := s.jwtSigner.SignToken(token)
	if err != nil {
		s.logger.Error("Failed to sign WIA JWT", zap.Error(err))
		wiaGenerationErrors.Inc()
		return "", err
	}

	wiaGeneratedTotal.WithLabelValues(attestationSource).Inc()
	s.logger.Info("WIA generated", zap.String("jkt", jkt[:8]+"..."))

	// Record wallet instance (upsert: creates on first attestation, updates on subsequent).
	if s.instances != nil {
		now := time.Now().UTC()
		instance := &domain.WalletInstance{
			ID:                jkt,
			TenantID:          domain.DefaultTenantID,
			Status:            domain.InstanceStatusActive,
			WSCDType:          wscdTypeFromAttestation(attestationSource),
			AttestationSource: attestationSource,
			LastAttestedAt:    now,
			CreatedAt:         now,
			UpdatedAt:         now,
		}
		if err := s.instances.Upsert(context.Background(), instance); err != nil {
			s.logger.Warn("failed to record wallet instance", zap.Error(err), zap.String("jkt", jkt[:8]+"..."))
		}
	}

	// Emit audit event
	if s.audit != nil {
		s.audit.EmitWithSubject(set.EventWIAIssued, jkt, map[string]any{
			"attestation_source": attestationSource,
		})
	}

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

	// RFC 7638: JSON with lexicographic order of required members.
	// Using a struct with ordered fields ensures deterministic serialization.
	thumbprintInput := struct {
		Crv string `json:"crv"`
		Kty string `json:"kty"`
		X   string `json:"x"`
		Y   string `json:"y"`
	}{
		Crv: crv,
		Kty: kty,
		X:   x,
		Y:   y,
	}

	data, err := json.Marshal(thumbprintInput)
	if err != nil {
		return "", fmt.Errorf("marshal JKT input: %w", err)
	}

	hash := sha256.Sum256(data)
	return base64.RawURLEncoding.EncodeToString(hash[:]), nil
}

// parseECPublicKeyFromJWK parses an EC public key from a JWK map.
// Only P-256 is accepted (consistent with ES256-only PoP validation).
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

	if crv != "P-256" {
		return nil, fmt.Errorf("unsupported curve %q: only P-256 is accepted for WIA PoP", crv)
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
// Only P-256 is supported (consistent with ES256-only PoP validation).
func ellipticCurveForName(name string) elliptic.Curve {
	switch name {
	case "P-256":
		return elliptic.P256()
	default:
		return nil
	}
}

// CleanupExpiredChallenges removes expired challenges from the store.
// For MongoDB, this is a no-op (TTL indexes handle expiry).
// For in-memory, this evicts expired entries.
func (s *WIAService) CleanupExpiredChallenges() {
	if m, ok := s.challenges.(*memoryWIAChallengeStore); ok {
		m.store.mu.Lock()
		m.store.evictExpired()
		m.store.mu.Unlock()
	}
}

// Start begins the periodic challenge cleanup goroutine.
// Safe to call multiple times; only the first call starts the worker.
func (s *WIAService) Start() {
	s.startOnce.Do(func() {
		s.stopCh = make(chan struct{})
		s.stopOnce = sync.Once{}
		go s.cleanupLoop()
		s.logger.Info("WIA challenge cleanup worker started")
	})
}

// Stop signals the cleanup goroutine to exit.
// Safe to call multiple times; only the first call closes the channel.
func (s *WIAService) Stop() {
	s.stopOnce.Do(func() {
		close(s.stopCh)
	})
}

func (s *WIAService) cleanupLoop() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			s.CleanupExpiredChallenges()
		case <-s.stopCh:
			return
		}
	}
}

// wscdTypeFromAttestation maps attestation source to WSCD type.
func wscdTypeFromAttestation(source string) domain.WSCDType {
	switch source {
	case "ios_app_attest":
		return domain.WSCDTypeNativeIOS
	case "android_play_integrity":
		return domain.WSCDTypeNativeAndroid
	default:
		// Backend-attested instances from web frontend use Web Crypto.
		return domain.WSCDTypeWebCrypto
	}
}
