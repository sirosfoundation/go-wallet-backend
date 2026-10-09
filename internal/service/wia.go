package service

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
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
	"github.com/sirosfoundation/go-wallet-backend/internal/tokengate"
	"github.com/sirosfoundation/go-wallet-backend/pkg/audit"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
	"github.com/sirosfoundation/go-wallet-backend/pkg/jwk"
	"github.com/sirosfoundation/go-wallet-backend/pkg/signing"
)

var (
	ErrWIANotSupported         = errors.New("WIA not supported: keys not configured")
	ErrWIAChallengeExpired     = errors.New("WIA challenge expired or invalid")
	ErrWIAPopInvalid           = errors.New("WIA-PoP validation failed")
	ErrWIAChallengeCapacityMax = errors.New("challenge capacity exceeded")
	ErrWIAInstanceDeactivated  = errors.New("wallet instance is revoked")
	ErrWIAInstanceNotOwned     = errors.New("wallet instance is bound to another tenant or user")
	// ErrWIACredentialNotOwned refuses a credential_id that is not one of the
	// caller's own passkeys (the first link per instance wins).
	ErrWIACredentialNotOwned = errors.New("credential_id is not one of the caller's passkeys")
	// ErrWIAUnknownUser refuses an attestation naming a deleted user (the
	// cut-off went with the record).
	ErrWIAUnknownUser = errors.New("attestation names a user that does not exist")
)

// WIAChallenge is a single-use nonce for WIA generation.
type WIAChallenge struct {
	Challenge string
	TenantID  domain.TenantID
	ExpiresAt time.Time
	// Linked list pointers for expiry-ordered eviction.
	prev, next *WIAChallenge
}

// challengeStore is a bounded, expiry-ordered map of challenges.
// Expired entries are evicted in O(1) from the front of the list on insert.
// Enforces both a global capacity and a per-tenant capacity (issue #224:
// "bounded capacity per tenant to prevent abuse" — a global-only bound lets
// a single tenant exhaust the shared pool and deny challenge creation for
// everyone else).
type challengeStore struct {
	mu               sync.Mutex
	items            map[string]*WIAChallenge
	head             *WIAChallenge // oldest expiry
	tail             *WIAChallenge // newest expiry
	maxSize          int
	maxSizePerTenant int
	perTenant        map[domain.TenantID]int
}

func newChallengeStore(maxSize, maxSizePerTenant int) *challengeStore {
	return &challengeStore{
		items:            make(map[string]*WIAChallenge, maxSize),
		maxSize:          maxSize,
		maxSizePerTenant: maxSizePerTenant,
		perTenant:        make(map[domain.TenantID]int),
	}
}

// put adds a challenge, evicting expired entries first. Returns false if
// either the global or the per-tenant capacity is exceeded.
func (cs *challengeStore) put(c *WIAChallenge) bool {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	cs.evictExpired()

	if len(cs.items) >= cs.maxSize {
		return false
	}
	if cs.maxSizePerTenant > 0 && cs.perTenant[c.TenantID] >= cs.maxSizePerTenant {
		return false
	}

	cs.items[c.Challenge] = c
	cs.perTenant[c.TenantID]++

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

// consume removes and returns an unexpired challenge minted for tenantID.
func (cs *challengeStore) consume(tenantID domain.TenantID, challenge string) (*WIAChallenge, bool) {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	c, ok := cs.items[challenge]
	if !ok || c.TenantID != tenantID {
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

// removeLocked removes a challenge from both the map and the linked list,
// and decrements its tenant's count. Must hold cs.mu.
func (cs *challengeStore) removeLocked(c *WIAChallenge) {
	delete(cs.items, c.Challenge)
	if cs.perTenant[c.TenantID] > 0 {
		cs.perTenant[c.TenantID]--
		if cs.perTenant[c.TenantID] == 0 {
			delete(cs.perTenant, c.TenantID)
		}
	}
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
	// users checks a claimed credential_id; nil refuses every claim.
	users storage.UserStore
	audit *audit.Emitter
	// lifecycle runs the revocation cascade for an instance this service revokes itself.
	lifecycle *WalletLifecycleService

	// Challenge store for single-use nonces (memory or MongoDB).
	challenges WIAChallengeStore

	// stopCh signals the cleanup goroutine to exit.
	stopCh    chan struct{}
	stopOnce  sync.Once
	startOnce sync.Once
}

// SetLifecycle wires the lifecycle service used for self-revocation.
func (s *WIAService) SetLifecycle(l *WalletLifecycleService) { s.lifecycle = l }

// NewWIAService creates a new WIA service.
// It shares the same signing key as the WalletProviderService (same x5c chain).
func NewWIAService(cfg *config.Config, logger *zap.Logger, jwtSigner *signing.CryptoSignerES256, certChain []string, instances storage.WalletInstanceStore, users storage.UserStore, auditor *audit.Emitter, challengeStore WIAChallengeStore) *WIAService {
	if challengeStore == nil {
		challengeStore = newMemoryWIAChallengeStore(maxChallenges, maxChallengesPerTenant)
	}
	svc := &WIAService{
		cfg:        cfg,
		logger:     logger.Named("wia-service"),
		jwtSigner:  jwtSigner,
		certChain:  certChain,
		instances:  instances,
		users:      users,
		audit:      auditor,
		challenges: challengeStore,
	}

	// Wire native attestation if configured
	if cfg.WalletProvider.Attestation.NativeAttestation.Enabled {
		svc.nativeAttSvc = NewNativeAttestationService(cfg, logger)
	}

	return svc
}

// IsSupported returns true if WIA generation is available. Unlike
// WalletProviderService.IsSupported (which gates Key Attestation and always
// requires a certificate), a certificate is only required here in "etsi"
// mode — "ietf" mode issues JWKS-trust WIAs from a signing key alone.
func (s *WIAService) IsSupported() bool {
	if s.jwtSigner == nil {
		return false
	}
	if s.cfg.WalletProvider.WIA.Mode == config.WIAModeIETF {
		return true
	}
	return len(s.certChain) > 0
}

// maxChallenges is the maximum number of concurrent pending challenges,
// across all tenants. Prevents memory exhaustion from challenge endpoint abuse.
const maxChallenges = 10000

// maxChallengesPerTenant additionally bounds how many of those may belong to
// a single tenant at once (issue #224: "bounded capacity per tenant to
// prevent abuse") — without this, a single tenant can still exhaust the
// entire global pool and deny challenge creation for every other tenant.
const maxChallengesPerTenant = maxChallenges / 10

// CreateChallenge generates a new single-use challenge nonce for tenantID.
func (s *WIAService) CreateChallenge(ctx context.Context, tenantID domain.TenantID) (string, time.Time, error) {
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

	ok, err := s.challenges.Put(ctx, tenantID, challenge, expiresAt)
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
func (s *WIAService) consumeChallenge(ctx context.Context, tenantID domain.TenantID, challenge string) error {
	ok, err := s.challenges.Consume(ctx, tenantID, challenge)
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
	// ClientID, when provided, is embedded as the WIA JWT's `sub` claim (see signWIA).
	ClientID string `json:"client_id,omitempty"`
	// NativeAttestation is optional platform attestation evidence
	NativeAttestation *NativeAttestationRequest `json:"native_attestation,omitempty"`
	// CredentialID is the optional base64url credential id of the instance's
	// login passkey (SID-AUTH-06).
	CredentialID string `json:"credential_id,omitempty"`
}

// WIAPopClaims are the expected claims in a WIA-PoP JWT.
type WIAPopClaims struct {
	jwt.RegisteredClaims
	Nonce string `json:"nonce"`
}

// GenerateWIA validates the WIA-PoP and generates a WIA JWT.
// tenantID is the tenant of the authenticated caller (from the request context),
// recorded against the wallet instance so admin views/ownership checks work correctly.
// userID is the authenticated caller's user ID, if known (may be nil) — recorded
// against the instance so GetByUser / ListWalletInstancesByUser can find it.
func (s *WIAService) GenerateWIA(ctx context.Context, tenantID domain.TenantID, userID *domain.UserID, req *WIARequest) (string, error) {
	if !s.IsSupported() {
		return "", ErrWIANotSupported
	}
	start := time.Now()
	defer func() { wiaGenerationDuration.Observe(time.Since(start).Seconds()) }()

	// Step 1: Consume challenge (single-use, atomic).
	// Must happen before PoP validation to prevent concurrent crypto amplification
	// attacks on the same challenge (TOCTOU). The trade-off is that a malformed PoP
	// burns the nonce, but this is acceptable — the nonce is single-use anyway.
	if err := s.consumeChallenge(ctx, tenantID, req.Challenge); err != nil {
		s.emitAuditFailure("challenge_invalid", err)
		return "", err
	}

	// Step 2: Parse and validate WIA-PoP
	cnfJWK, err := s.validatePop(req.Pop, req.Challenge)
	if err != nil {
		s.emitAuditFailure("pop_invalid", err)
		return "", fmt.Errorf("%w: %v", ErrWIAPopInvalid, err)
	}

	jkt, err := jwk.Thumbprint(cnfJWK)
	if err != nil {
		s.emitAuditFailure("jkt_compute_failed", err)
		return "", fmt.Errorf("%w: %v", ErrWIAPopInvalid, err)
	}

	// The named user must still exist: the cut-off goes with a deleted account.
	if err := s.refuseIfUserGone(ctx, userID); err != nil {
		return "", err
	}

	// Step 2.5: Reject issuance for instances an admin has revoked.
	// Without this check, a wallet that still holds its instance key could simply
	// request a fresh challenge/PoP and obtain a brand-new valid WIA, completely
	// bypassing revocation.
	firstAttestation := false
	if s.instances != nil {
		existing, err := s.instances.GetByID(ctx, jkt)
		switch {
		case err == nil:
			// Ownership before lifecycle: do not leak another wallet's state.
			if err := checkInstanceBinding(existing, tenantID, userID); err != nil {
				s.emitAuditFailure("instance_binding_mismatch", err)
				return "", err
			}
			if !existing.Status.IsLive() {
				if !existing.Status.IsKnownNonLive() {
					s.emitAuditFailure("instance_status_unrecognized", fmt.Errorf("instance %s has unrecognized status %q", existing.ID, existing.Status))
					return "", fmt.Errorf("check wallet instance status: instance %s has unrecognized status %q", existing.ID, existing.Status)
				}
				s.emitAuditFailure("instance_deactivated", fmt.Errorf("wallet instance status is %s", existing.Status))
				return "", fmt.Errorf("%w: status is %s", ErrWIAInstanceDeactivated, existing.Status)
			}
			if existing.UserID == nil && userID != nil {
				// First user binding of an anonymous instance counts as a new instance:
				// a deactivated wallet must not adopt it (re-checked after the write).
				firstAttestation = true
				if err := s.refuseIfWalletDeactivated(ctx, tenantID, userID); err != nil {
					return "", err
				}
			}
		case errors.Is(err, storage.ErrNotFound):
			firstAttestation = true
			// A first attestation must not revive a deactivated wallet (SID-AUTH-06).
			if err := s.refuseIfWalletDeactivated(ctx, tenantID, userID); err != nil {
				return "", err
			}
		default:
			return "", fmt.Errorf("check wallet instance status: %w", err)
		}
	}

	// Step 2.6: a claimed passkey link must be the caller's own passkey.
	if err := s.checkCredentialOwnership(ctx, tenantID, userID, req.CredentialID); err != nil {
		s.emitAuditFailure("credential_not_owned", err)
		return "", err
	}

	// Re-judge the token against the cut-off, which may have advanced since the middleware.
	if err := tokengate.RefuseNow(ctx, s.users); err != nil {
		return "", err
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
	return s.signWIA(ctx, cnfJWK, jkt, tenantID, userID, attestationSource, req.ClientID, req.CredentialID, firstAttestation)
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
	pubKey, err := jwk.ParseECPublicKey(jwkMap)
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
// jkt is the JWK Thumbprint of cnfJWK, precomputed by the caller (GenerateWIA)
// so it can also be used for the instance-status guard before signing.
// firstAttestation: the record did not exist at the lifecycle check; re-checked after the write.
func (s *WIAService) signWIA(ctx context.Context, cnfJWK map[string]interface{}, jkt string, tenantID domain.TenantID, userID *domain.UserID, attestationSource string, clientID string, credentialID string, firstAttestation bool) (string, error) {
	now := time.Now()

	lifetime := s.wiaLifetime()

	// sub: draft-ietf-oauth-attestation-based-client-auth-10 requires "the sub
	// claim MUST specify client_id value of the OAuth Client" - NOT the
	// instance identifier (that's what cnf.jkt is for). Falls back to jkt
	// when the caller doesn't supply a client_id (e.g. a WIA requested for
	// something other than OID4VCI/OID4VP client authentication).
	sub := clientID
	if sub == "" {
		sub = jkt
	}
	claims := jwt.MapClaims{
		"sub": sub,
		"jti": uuid.New().String(),
		"cnf": map[string]interface{}{
			"jwk": cnfJWK,
			"jkt": jkt,
		},
		"iat": now.Unix(),
		"exp": now.Add(lifetime).Unix(),
		// attestation_source: a SIROS extension claim — neither EC TS03 nor
		// ETSI TS 119 472-3 define a WIA claim for this. Its values are
		// chosen to mirror the S1/S3 "WIA dimension" tiers from WE BUILD
		// wp4-architecture PR #229 ("cs-04: Add Annex C — Tiered WUA for
		// cross-platform Wallet Solutions", open as of 2026-08, branch
		// cs-04/annex-c-tiered-attestation) — NOT "WP4 CS-05" (Business
		// Wallet, unrelated); Annex C is a proposed addition to CS-04.
		// Annex C's own note is explicit that TS-03/CS-04 don't define this
		// claim: any such signal "may [be conveyed] via the certification
		// information or via an extension claim, but this is outside the
		// scope of TS-03 and CS-04" — this claim is that extension.
		//   "backend_attested"         — Annex C tier S3: backend-only attestation
		//   "ios_app_attest"           — Annex C tier S1: full client attestation (Apple App Attest)
		//   "android_play_integrity"   — Annex C tier S1: full client attestation (Google Play Integrity)
		// Annex C's tier S2 (partial client attestation, e.g. a browser
		// extension/companion) has no corresponding value yet.
		// Third-party wallet providers may omit this claim; issuers must handle
		// both present and absent cases (absent = unknown tier).
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

	// client_status: WIA revocation reference (CS-04 §7.1.2, TS-03 clause
	// 2.3.1). Required on every WIA by CS-04 — a conformant PID/EAA
	// Provider rejects one without it. It points at this wallet provider's
	// own always-VALID status list; see StatusListConfig for why that is
	// not the mechanism actually bounding exposure here.
	if cs := statusClaim(s.cfg, statusIndexWIA, now); cs != nil {
		claims["client_status"] = cs
	}

	// iss: only set in "ietf" mode, where relying parties resolve trust via
	// this wallet provider's JWKS. Even when we also embed x5c in the header
	// (for interoperability with consumers/test suites that expect it), iss
	// remains the identifier for JWKS discovery. config.Validate() enforces
	// Issuer being set whenever Mode is "ietf" and signing keys are
	// configured, so no WalletProviderURI fallback here -
	// WalletProviderService.Issuer() (used by
	// RegisterWalletProviderJWKSRoute's RFC 8414 metadata) computes the same
	// value the same way, so both stay consistent with what Validate()
	// actually requires.
	//
	// In "etsi" mode, no iss is set at all: EC TS03 v1.5.2 removed `iss`
	// from the WIA entirely — Wallet Provider identity is inferred solely
	// from the x5c signing certificate, verified against the Trusted List
	// for Wallet Providers (ETSI TS 119 472-3 AUTH-REQ-PROC-4.4.3-01 /
	// TOKEN-REQ-PROC-4.5.2-01).
	if s.cfg.WalletProvider.WIA.Mode == config.WIAModeIETF && s.cfg.WalletProvider.WIA.Issuer != "" {
		claims["iss"] = s.cfg.WalletProvider.WIA.Issuer
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["typ"] = "oauth-client-attestation+jwt"

	switch s.cfg.WalletProvider.WIA.Mode {
	case config.WIAModeIETF:
		// Relying parties resolve the wallet provider's signing key from its
		// own JWKS (RegisterWalletProviderJWKSRoute, served at the WIA's own
		// iss URL). That resolution is kid-keyed (standard practice for
		// multi-key JWKS, and what existing JWT trust-verification code
		// elsewhere already expects), so the WIA itself must carry a kid
		// header matching the JWKS entry's KeyID ("wallet-provider",
		// hardcoded there since this deployment publishes exactly one signing
		// key) - without it, a relying party has no way to know which of the
		// issuer's published keys to use.
		token.Header["kid"] = "wallet-provider"
		if len(s.certChain) > 0 {
			token.Header["x5c"] = s.certChain
		}
	default: // config.WIAModeETSI
		token.Header["x5c"] = s.certChain
	}

	tokenString, err := s.jwtSigner.SignToken(token)
	if err != nil {
		s.logger.Error("Failed to sign WIA JWT", zap.Error(err))
		wiaGenerationErrors.Inc()
		return "", err
	}

	// Final cut-off check at the mutation boundary, after the slow steps. Fail closed.
	if err := tokengate.RefuseNow(ctx, s.users); err != nil {
		return "", err
	}

	wiaGeneratedTotal.WithLabelValues(attestationSource).Inc()
	s.logger.Info("WIA generated", zap.String("jkt", jkt[:8]+"..."))

	// Record wallet instance (upsert: creates on first attestation, updates on subsequent).
	// Upsert never overwrites the status of an existing instance (that would undo a revocation).
	if s.instances != nil {
		// Serialize with the lifecycle cascade (#330, in-process).
		if s.lifecycle != nil && userID != nil {
			defer s.lifecycle.LockUser(*userID)()
			// Re-check under the lock: account deletion may have completed meanwhile.
			if err := s.refuseIfUserGone(ctx, userID); err != nil {
				return "", err
			}
		}
		now := time.Now().UTC()
		instance := &domain.WalletInstance{
			ID:                jkt,
			TenantID:          tenantID,
			UserID:            userID,
			Status:            domain.InstanceStatusActive,
			CredentialID:      credentialID,
			WSCDType:          wscdTypeFromAttestation(attestationSource),
			AttestationSource: attestationSource,
			LastAttestedAt:    now,
			CreatedAt:         now,
			UpdatedAt:         now,
		}
		if err := s.instances.Upsert(ctx, instance); err != nil {
			if errors.Is(err, storage.ErrAlreadyExists) {
				s.emitAuditFailure("instance_not_owned", err)
				return "", fmt.Errorf("%w: instance belongs to another tenant", ErrWIAInstanceNotOwned)
			}
			// Deleted and re-attested between upsert and bind/link: refuse.
			if errors.Is(err, storage.ErrBindingChanged) {
				s.emitAuditFailure("instance_not_owned", errors.New("wallet instance was replaced during attestation"))
				return "", fmt.Errorf("%w: instance was replaced during attestation", ErrWIAInstanceNotOwned)
			}
			s.emitAuditFailure("instance_record_failed", err)
			return "", fmt.Errorf("record wallet instance: %w", err)
		}
		if err := s.recheckLifecycleAfterWrite(ctx, tenantID, userID, jkt, credentialID, firstAttestation); err != nil {
			return "", err
		}
	}

	// A cut-off landing during the write must still stop the token.
	if err := tokengate.RefuseNow(ctx, s.users); err != nil {
		return "", err
	}

	// Emit audit event
	if s.audit != nil {
		s.audit.EmitWithSubject(set.EventWIAIssued, jkt, map[string]any{
			"attestation_source": attestationSource,
		})
	}

	return tokenString, nil
}

// wiaLifetime is attestation.lifetime_seconds capped by wia.max_expiry_seconds.
func (s *WIAService) wiaLifetime() time.Duration {
	// Short on purpose: there is no revocation chaining, so lifetime bounds exposure.
	lifetime := time.Duration(s.cfg.WalletProvider.Attestation.LifetimeSeconds) * time.Second
	maxExpiry := time.Duration(s.cfg.WalletProvider.WIA.MaxExpirySeconds) * time.Second
	if maxExpiry <= 0 {
		maxExpiry = 24 * time.Hour // sensible default to prevent zero/negative expiry
	}
	if lifetime <= 0 {
		lifetime = maxExpiry
		s.logger.Warn("attestation.lifetime_seconds not set, defaulting to max_expiry_seconds",
			zap.Duration("lifetime", lifetime))
	}
	if lifetime > maxExpiry {
		lifetime = maxExpiry
	}
	return lifetime
}

// checkInstanceBinding refuses a caller from another tenant or user before
// signing. First user binding of an anonymous instance is allowed.
func checkInstanceBinding(existing *domain.WalletInstance, tenantID domain.TenantID, userID *domain.UserID) error {
	if existing.TenantID != tenantID {
		return fmt.Errorf("%w: instance belongs to another tenant", ErrWIAInstanceNotOwned)
	}
	if existing.UserID != nil && userID != nil && *existing.UserID != *userID {
		return fmt.Errorf("%w: instance belongs to another user", ErrWIAInstanceNotOwned)
	}
	return nil
}

// recheckLifecycleAfterWrite closes the window between GenerateWIA's checks
// and the write (Upsert preserves a concurrent revocation, but the WIA is signed).
func (s *WIAService) recheckLifecycleAfterWrite(ctx context.Context, tenantID domain.TenantID, userID *domain.UserID, jkt, credentialID string, firstAttestation bool) error {
	if firstAttestation {
		if err := s.revokeIfWalletDeactivatedMeanwhile(ctx, tenantID, userID, jkt); err != nil {
			return err
		}
	}
	inst, err := s.instances.GetByID(ctx, jkt)
	if err != nil {
		return fmt.Errorf("re-check wallet instance status: %w", err)
	}
	// Ownership before lifecycle, as in GenerateWIA.
	if inst.TenantID != tenantID {
		s.emitAuditFailure("instance_not_owned", errors.New("wallet instance was recorded in another tenant during attestation"))
		return fmt.Errorf("%w: instance belongs to another tenant", ErrWIAInstanceNotOwned)
	}
	if userID != nil && inst.UserID != nil && *inst.UserID != *userID {
		s.emitAuditFailure("instance_not_owned", errors.New("wallet instance was bound to another user during attestation"))
		return fmt.Errorf("%w: instance was bound to another user", ErrWIAInstanceNotOwned)
	}
	if !inst.Status.IsLive() {
		if !inst.Status.IsKnownNonLive() {
			s.emitAuditFailure("instance_status_unrecognized", fmt.Errorf("instance %s has unrecognized status %q", inst.ID, inst.Status))
			return fmt.Errorf("re-check wallet instance status: instance %s has unrecognized status %q", inst.ID, inst.Status)
		}
		s.emitAuditFailure("instance_deactivated", fmt.Errorf("wallet instance became %s during attestation", inst.Status))
		return fmt.Errorf("%w: status is %s", ErrWIAInstanceDeactivated, inst.Status)
	}
	// The link is permanent (first link wins).
	if credentialID != "" && inst.CredentialID != "" && inst.CredentialID != credentialID {
		s.emitAuditFailure("credential_not_owned", errors.New("wallet instance is linked to a different passkey"))
		return fmt.Errorf("%w: this instance is already linked to a different passkey", ErrWIACredentialNotOwned)
	}
	return nil
}

// refuseIfUserGone refuses an attestation naming a missing user.
func (s *WIAService) refuseIfUserGone(ctx context.Context, userID *domain.UserID) error {
	if userID == nil || s.users == nil {
		return nil
	}
	if _, err := s.users.GetByID(ctx, *userID); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			if derr := tokengate.RefuseIfDeleted(ctx, s.users, userID.String()); derr != nil {
				s.emitAuditFailure("account_deleted", derr)
				return derr
			}
			s.emitAuditFailure("unknown_user", errors.New("attestation names a user that does not exist"))
			return ErrWIAUnknownUser
		}
		return fmt.Errorf("check attesting user: %w", err)
	}
	return nil
}

// refuseIfWalletDeactivated returns ErrWIAInstanceDeactivated when the user
// has instances in the tenant and none is live. Anonymous attestations pass.
func (s *WIAService) refuseIfWalletDeactivated(ctx context.Context, tenantID domain.TenantID, userID *domain.UserID) error {
	if userID == nil {
		return nil
	}
	instances, err := s.instances.GetByUser(ctx, tenantID, *userID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil
		}
		return fmt.Errorf("check wallet lifecycle: %w", err)
	}
	if len(instances) == 0 {
		return nil
	}
	var unknown *domain.WalletInstance
	for _, inst := range instances {
		if inst.Status.IsLive() {
			return nil
		}
		if !inst.Status.IsKnownNonLive() {
			unknown = inst
		}
	}
	if unknown != nil {
		s.emitAuditFailure("instance_status_unrecognized", fmt.Errorf("instance %s has unrecognized status %q", unknown.ID, unknown.Status))
		return fmt.Errorf("check wallet lifecycle: instance %s has unrecognized status %q", unknown.ID, unknown.Status)
	}
	s.emitAuditFailure("wallet_deactivated", errors.New("no live wallet instance remains for the user"))
	return fmt.Errorf("%w: wallet deactivated, no live instance remains", ErrWIAInstanceDeactivated)
}

// revokeIfWalletDeactivatedMeanwhile is the post-insert half of the
// first-attestation guard: if all the user's other instances are revoked, the
// new one is revoked too and the attestation refused.
func (s *WIAService) revokeIfWalletDeactivatedMeanwhile(ctx context.Context, tenantID domain.TenantID, userID *domain.UserID, newID string) error {
	if userID == nil {
		return nil
	}
	instances, err := s.instances.GetByUser(ctx, tenantID, *userID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil
		}
		return fmt.Errorf("re-check wallet lifecycle: %w", err)
	}
	others := 0
	var unknown *domain.WalletInstance
	for _, inst := range instances {
		if inst.ID == newID {
			continue
		}
		others++
		if inst.Status.IsLive() {
			return nil
		}
		if !inst.Status.IsKnownNonLive() {
			unknown = inst
		}
	}
	if others == 0 {
		return nil
	}
	if unknown != nil {
		// An unrecognised status must not trigger the destructive revoke.
		s.emitAuditFailure("instance_status_unrecognized", fmt.Errorf("instance %s has unrecognized status %q", unknown.ID, unknown.Status))
		return fmt.Errorf("re-check wallet lifecycle: instance %s has unrecognized status %q", unknown.ID, unknown.Status)
	}
	// A racing first attestation may have inserted newID under another owner;
	// revoking would destroy the winner's instance, so re-read and refuse.
	inserted, err := s.instances.GetByID(ctx, newID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil
		}
		return fmt.Errorf("re-check wallet instance ownership: %w", err)
	}
	if inserted.TenantID != tenantID {
		s.emitAuditFailure("instance_not_owned", errors.New("wallet instance was recorded in another tenant during attestation"))
		return fmt.Errorf("%w: instance belongs to another tenant", ErrWIAInstanceNotOwned)
	}
	if inserted.UserID != nil && *inserted.UserID != *userID {
		s.emitAuditFailure("instance_not_owned", errors.New("wallet instance was bound to another user during attestation"))
		return fmt.Errorf("%w: instance was bound to another user", ErrWIAInstanceNotOwned)
	}
	const reason = "wallet deactivated during attestation"
	alreadyRevoked := false
	// Conditional on owner and generation: the read and write are not atomic.
	if err := s.instances.UpdateStatusIfUnchanged(ctx, newID, tenantID, inserted.Binding(), domain.InstanceStatusRevoked, reason); err != nil {
		if errors.Is(err, storage.ErrBindingChanged) || errors.Is(err, storage.ErrNotFound) {
			s.emitAuditFailure("instance_not_owned", errors.New("wallet instance was replaced during attestation"))
			return fmt.Errorf("%w: instance was replaced during attestation", ErrWIAInstanceNotOwned)
		}
		// A concurrent revoke-all already took the record: intended outcome.
		if !errors.Is(err, domain.ErrInvalidStatusTransition) {
			return fmt.Errorf("revoke instance of deactivated wallet: %w", err)
		}
		alreadyRevoked = true
	}
	if s.audit != nil && !alreadyRevoked {
		s.audit.EmitWithSubject(set.EventWIRevoked, newID, map[string]any{
			"status": string(domain.InstanceStatusRevoked),
			"reason": reason,
			"actor":  "provider",
		})
	}
	s.emitAuditFailure("wallet_deactivated", errors.New("wallet deactivated while the first attestation was in flight"))
	// The cascade that revoked the last other instance may have kept the wallet
	// data because it saw this record as active; re-decide now.
	if s.lifecycle != nil && !alreadyRevoked {
		inserted.Status = domain.InstanceStatusRevoked
		if err := s.lifecycle.CascadeForRevokedLocked(ctx, tenantID, inserted, LifecycleActor{Kind: "provider"}); err != nil {
			s.logger.Error("cascade after revoking a raced first attestation did not complete", zap.Error(err), zap.String("jkt", newID))
			return fmt.Errorf("%w: wallet deactivated during attestation: %w", ErrWIAInstanceDeactivated, err)
		}
	}
	return fmt.Errorf("%w: wallet deactivated during attestation", ErrWIAInstanceDeactivated)
}

// checkCredentialOwnership refuses a credential_id the caller cannot prove is
// theirs (empty is fine). The credential must belong to this tenant; legacy
// credentials count as the default tenant, as in the login path.
func (s *WIAService) checkCredentialOwnership(ctx context.Context, tenantID domain.TenantID, userID *domain.UserID, credentialID string) error {
	if credentialID == "" {
		return nil
	}
	if userID == nil {
		return fmt.Errorf("%w: an anonymous attestation cannot claim a passkey", ErrWIACredentialNotOwned)
	}
	if s.users == nil {
		return fmt.Errorf("%w: passkey ownership cannot be verified here", ErrWIACredentialNotOwned)
	}
	user, err := s.users.GetByID(ctx, *userID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return fmt.Errorf("%w: unknown user", ErrWIACredentialNotOwned)
		}
		return fmt.Errorf("check passkey ownership: %w", err)
	}
	wantTenant := tenantID
	if wantTenant == "" {
		wantTenant = domain.DefaultTenantID
	}
	for _, cred := range user.WebauthnCredentials {
		if cred.ID != credentialID {
			continue
		}
		credTenant := cred.TenantID
		if credTenant == "" {
			credTenant = domain.DefaultTenantID
		}
		if credTenant != wantTenant {
			return fmt.Errorf("%w: the passkey belongs to another tenant", ErrWIACredentialNotOwned)
		}
		return nil
	}
	return fmt.Errorf("%w: the user has no such passkey", ErrWIACredentialNotOwned)
}

// CleanupExpiredChallenges removes expired challenges from the store.
// For MongoDB, this is a no-op (TTL indexes handle expiry).
// For in-memory, this evicts expired entries.
func (s *WIAService) CleanupExpiredChallenges() int {
	if m, ok := s.challenges.(*memoryWIAChallengeStore); ok {
		m.store.mu.Lock()
		before := len(m.store.items)
		m.store.evictExpired()
		evicted := before - len(m.store.items)
		m.store.mu.Unlock()
		return evicted
	}
	return 0
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
			if n := s.CleanupExpiredChallenges(); n > 0 {
				challengeEvictedTotal.Add(float64(n))
			}
		case <-s.stopCh:
			return
		}
	}
}

// emitAuditFailure emits an audit event for a failed WIA generation attempt.
func (s *WIAService) emitAuditFailure(reason string, err error) {
	if s.audit != nil {
		s.audit.EmitWithSubject(set.EventURI("urn:siros:audit:wia:issuance_failed"), reason, map[string]any{
			"error": err.Error(),
		})
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
