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

	"github.com/sirosfoundation/go-wallet-backend/internal/assurance"
	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
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
	ErrWIAInstanceDeactivated  = errors.New("wallet instance is suspended or revoked")
	// ErrWIARefusedByPolicy is returned when the assurance policy is enabled
	// and no assure-wia-issue rule permits the evidence of this request.
	ErrWIARefusedByPolicy = errors.New("WIA refused by assurance policy")
	// ErrWIANativeAttestationUnavailable means the native attestation could not
	// be judged or recorded because storage failed; refused, retryable (503).
	ErrWIANativeAttestationUnavailable = errors.New("native attestation cannot be verified right now")
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
	audit        *audit.Emitter

	// keyAttestations holds per-key evidence verified by the backend. The WIA
	// path reads it for the PoP (instance) key only; nil means no evidence is
	// ever found and the instance records wscd_type unknown.
	keyAttestations storage.KeyAttestationStore

	// appAttestKeys holds attested App Attest keys (see SetAppAttestKeys).
	appAttestKeys storage.AppAttestKeyStore

	// keyVerifiers verifies the optional key_attestation request field, by
	// type. Registered while wiring the service (RegisterInstanceKeyVerifier).
	keyVerifiers map[KeyAttestationType]InstanceKeyEvidenceVerifier

	// Challenge store for single-use nonces (memory or MongoDB).
	challenges WIAChallengeStore

	// assessor is the assurance policy; used only when
	// wallet_provider.attestation.assurance.enabled is true.
	assessor *assurance.Assessor

	// stopCh signals the cleanup goroutine to exit.
	stopCh    chan struct{}
	stopOnce  sync.Once
	startOnce sync.Once
}

// NewWIAService creates a new WIA service.
// It shares the same signing key as the WalletProviderService (same x5c chain).
func NewWIAService(cfg *config.Config, logger *zap.Logger, jwtSigner *signing.CryptoSignerES256, certChain []string, instances storage.WalletInstanceStore, auditor *audit.Emitter, challengeStore WIAChallengeStore) *WIAService {
	if challengeStore == nil {
		challengeStore = newMemoryWIAChallengeStore(maxChallenges, maxChallengesPerTenant)
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

// SetAssessor installs the assurance policy used when
// wallet_provider.attestation.assurance.enabled is true.
func (s *WIAService) SetAssessor(a *assurance.Assessor) { s.assessor = a }

// SetKeyAttestations installs the store of verified per-key evidence that
// the instance key is looked up in (see instanceKeyEvidence).
func (s *WIAService) SetKeyAttestations(k storage.KeyAttestationStore) { s.keyAttestations = k }

// SetAppAttestKeys installs the store of attested Apple App Attest keys: the
// native attestation verifier stores verified keys in it.
func (s *WIAService) SetAppAttestKeys(k storage.AppAttestKeyStore) {
	s.appAttestKeys = k
	if s.nativeAttSvc != nil {
		s.nativeAttSvc.SetAppAttestKeys(k)
	}
}

func (s *WIAService) assuranceEnabled() bool {
	return s.cfg.WalletProvider.Attestation.Assurance.Enabled
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
	// ClientID, when provided, is embedded as the WIA JWT's `sub` claim (see signWIA).
	ClientID string `json:"client_id,omitempty"`
	// NativeAttestation is optional platform attestation evidence
	NativeAttestation *NativeAttestationRequest `json:"native_attestation,omitempty"`
	// KeyAttestation is optional evidence about the instance (PoP) key
	// itself; see instance_key_evidence.go. Absent: the home stays unknown.
	KeyAttestation *KeyAttestation `json:"key_attestation,omitempty"`
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

	// Step 0: an unknown key_attestation type is a client error that must not
	// burn the single-use challenge.
	keyVerifier, err := s.keyVerifierFor(req.KeyAttestation)
	if err != nil {
		return "", err
	}

	// Step 1: Consume challenge (single-use, atomic).
	// Must happen before PoP validation to prevent concurrent crypto amplification
	// attacks on the same challenge (TOCTOU). The trade-off is that a malformed PoP
	// burns the nonce, but this is acceptable — the nonce is single-use anyway.
	if err := s.consumeChallenge(ctx, req.Challenge); err != nil {
		s.emitAuditFailure("challenge_invalid", err)
		return "", err
	}

	// Step 2: Parse and validate WIA-PoP
	cnfJWK, err := s.validatePop(req.Pop, req.Challenge)
	if err != nil {
		s.emitAuditFailure("pop_invalid", err)
		return "", fmt.Errorf("%w: %v", ErrWIAPopInvalid, err)
	}
	popKey, err := jwk.ParseECPublicKey(cnfJWK)
	if err != nil {
		s.emitAuditFailure("pop_invalid", err)
		return "", fmt.Errorf("%w: %v", ErrWIAPopInvalid, err)
	}

	jkt, err := jwk.Thumbprint(cnfJWK)
	if err != nil {
		s.emitAuditFailure("jkt_compute_failed", err)
		return "", fmt.Errorf("%w: %v", ErrWIAPopInvalid, err)
	}

	// Step 2.5: Reject issuance for instances an admin has suspended or revoked.
	// Without this check, a wallet that still holds its instance key could simply
	// request a fresh challenge/PoP and obtain a brand-new valid WIA, completely
	// bypassing revocation.
	if s.instances != nil {
		existing, err := s.instances.GetByID(ctx, jkt)
		switch {
		case err == nil:
			if existing.Status != domain.InstanceStatusActive {
				s.emitAuditFailure("instance_deactivated", fmt.Errorf("wallet instance status is %s", existing.Status))
				return "", fmt.Errorf("%w: status is %s", ErrWIAInstanceDeactivated, existing.Status)
			}
		case errors.Is(err, storage.ErrNotFound):
			// First attestation for this instance key — nothing to check yet.
		default:
			return "", fmt.Errorf("check wallet instance status: %w", err)
		}
	}

	// Step 3: Determine attestation source
	att := wiaAttestation{Source: "backend_attested"} // Tier 3 baseline
	if req.NativeAttestation != nil && s.nativeAttSvc != nil {
		// Bind native attestation challenge to the WIA challenge nonce
		if req.NativeAttestation.Challenge != req.Challenge {
			return "", fmt.Errorf("%w: native attestation challenge does not match WIA challenge", ErrWIAPopInvalid)
		}
		result, err := s.nativeAttSvc.VerifyBound(ctx, NativeAttestationBinding{TenantID: tenantID, UserID: userID, WalletInstanceID: jkt}, req.NativeAttestation)
		if err != nil {
			// When native attestation is submitted but fails, reject the request.
			// If the client doesn't want native attestation, it should omit the field.
			nativeAttestationErrors.Inc()
			if errors.Is(err, ErrNativeAttestationUnavailable) {
				return "", fmt.Errorf("%w: %v", ErrWIANativeAttestationUnavailable, err)
			}
			return "", fmt.Errorf("%w: native attestation failed: %v", ErrWIAPopInvalid, err)
		}
		if result.Verified {
			att.Source = result.AttestationSource
			att.AppID = result.AppID
			nativeAttestationSuccess.Inc()
		}
	}

	// Step 3.4: evidence about the instance key itself (the PoP key), from the
	// store of per-key evidence the backend verified. Never from anything the
	// client reports about its keystore.
	// Step 3.3: evidence the client submitted about that key is verified and
	// stored first, so the lookup below sees it. Invalid evidence refuses the
	// WIA; evidence that names no home changes nothing.
	var submitted *domain.KeyAttestationRecord
	if keyVerifier != nil {
		submitted, err = s.verifyKeyAttestation(ctx, keyVerifier, req.KeyAttestation, tenantID, userIDString(userID), jkt, popKey, req.Challenge)
		if err != nil {
			s.emitAuditFailure("key_attestation_rejected", err)
			return "", err
		}
	}
	att.KeyEvidence = s.instanceKeyEvidence(ctx, tenantID, userIDString(userID), jkt)
	if att.KeyEvidence == nil && s.keyAttestations == nil {
		att.KeyEvidence = submitted // nothing durable to read back from
	}

	// Step 3.5: the assurance policy decides whether a WIA is issued at all,
	// which S profile it carries and which certification information applies.
	// Disabled (default): always issue, exactly as before.
	if s.assuranceEnabled() {
		if err := s.applyAssurance(ctx, jkt, &att); err != nil {
			s.emitAuditFailure("assurance_refused", err)
			return "", err
		}
	}

	// Step 4: Generate WIA JWT
	return s.signWIA(cnfJWK, jkt, tenantID, userID, att, req.ClientID)
}

// wiaAttestation is what one WIA request established and decided.
type wiaAttestation struct {
	// Source is the attestation source the backend verified in THIS request:
	// platform_attested, development_attested or backend_attested. It is
	// what is stored on the wallet instance and what rules see as the
	// platform source.
	Source string
	// AppID is the verified application id, "" when none.
	AppID string

	// Claim is the attestation_source claim value. Empty means Source (the
	// policy-disabled behaviour); with the policy enabled it is the emitted
	// value of the chosen S profile.
	Claim string
	// CertInfo, when non-nil, replaces the configured
	// wallet_solution_certification_information.
	CertInfo map[string]interface{}
	// Decision is the policy outcome, nil with the policy disabled.
	Decision *assurance.WIAOutcome

	// KeyEvidence is the VERIFIED per-key evidence record for the instance
	// key (the thumbprint of the PoP key), nil when the backend holds none.
	// It is what the fido2 evidence slot and the recorded wscd_type derive
	// from; the client-reported plugin is never consulted.
	KeyEvidence *domain.KeyAttestationRecord
}

// instanceKeyEvidence returns the verified key-evidence record stored for the
// instance key with thumbprint jkt, or nil. The lookup is by the PoP key's own
// RFC 7638 thumbprint, so evidence only applies when the key that was attested
// is the key that signs the PoP.
//
// ARKG caveat: for a key derived with ARKG the public key the authenticator
// attested is the base (seed) key, while the PoP key is a derived key with a
// different thumbprint. The thumbprints then differ, nothing matches and the
// result stays "no evidence" (wscd_type unknown). That is intended: the
// evidence says nothing about the derived key unless a later stage binds them.
//
// A store error is treated as no evidence (fail closed to unknown), never as
// permission.
func (s *WIAService) instanceKeyEvidence(ctx context.Context, tenantID domain.TenantID, userID, jkt string) *domain.KeyAttestationRecord {
	if s.keyAttestations == nil {
		return nil
	}
	rec, err := s.keyAttestations.GetByKeyThumbprint(ctx, jkt)
	if err != nil {
		if !errors.Is(err, storage.ErrNotFound) {
			s.logger.Warn("instance key evidence lookup failed; treating as none", zap.Error(err))
		}
		return nil
	}
	if !instanceEvidenceInScope(rec, tenantID, userID) {
		s.logger.Warn("instance key evidence was verified for another tenant or user; ignoring it")
		return nil
	}
	return rec
}

func userIDString(u *domain.UserID) string {
	if u == nil {
		return ""
	}
	return u.String()
}

// instanceKeyEvidenceBuilder turns a verified per-key evidence record of one
// Kind into the verified instance_key evidence slot. New evidence families
// (android_key, app_attest_assertion) register a builder in
// instanceKeyBuilders; nothing else in the WIA path changes.
type instanceKeyEvidenceBuilder interface {
	// Kind is the record kind this builder understands.
	Kind() domain.KeyEvidenceKind
	// Build renders a normalized, verified record of that kind.
	Build(rec *domain.KeyAttestationRecord) *assurance.InstanceKeyVerified
}

// instanceKeyBuilders is keyed by record Kind. A record whose kind has no
// builder yields no slot: unknown evidence is never rendered as verified.
var instanceKeyBuilders = map[domain.KeyEvidenceKind]instanceKeyEvidenceBuilder{
	domain.KeyEvidenceFIDO2:              fido2InstanceKeyBuilder{},
	domain.KeyEvidenceAppAttestAssertion: appAttestAssertionBuilder{},
}

// fido2InstanceKeyBuilder renders a verified FIDO2 attestation: the key was
// attested by an authenticator (binding attested). A FIDO2 record carries no
// security level or boot state, which render none (never invented).
type fido2InstanceKeyBuilder struct{}

func (fido2InstanceKeyBuilder) Kind() domain.KeyEvidenceKind { return domain.KeyEvidenceFIDO2 }

func (fido2InstanceKeyBuilder) Build(rec *domain.KeyAttestationRecord) *assurance.InstanceKeyVerified {
	return &assurance.InstanceKeyVerified{
		Kind:    string(rec.Kind),
		Home:    string(rec.Home),
		Level:   rec.SecurityLevel,
		Boot:    rec.VerifiedBootState,
		Binding: assurance.BindingAttested,
	}
}

// instanceKeyVerifiedFromRecord renders the verified instance_key slot from
// the instance key's evidence record, nil (slot none) when there is no record
// or no builder for its kind. Only this function fills the slot; it is fed
// from storage, never from the request.
func instanceKeyVerifiedFromRecord(rec *domain.KeyAttestationRecord) *assurance.InstanceKeyVerified {
	if rec == nil {
		return nil
	}
	n := *rec
	n.Normalize()
	b, ok := instanceKeyBuilders[n.Kind]
	if !ok {
		return nil
	}
	return b.Build(&n)
}

// fido2VerifiedFromRecord renders a verified FIDO2 record as the evidence
// fido2 slot. Records of other kinds (android_key, app_attest_assertion, ...)
// are not FIDO2 evidence and yield nil. Presence means the attestation chain
// was accepted by the FIDO MDS3 registry.
func fido2VerifiedFromRecord(rec *domain.KeyAttestationRecord) *assurance.Fido2Verified {
	if rec == nil {
		return nil
	}
	n := *rec
	n.Normalize()
	if n.Kind != domain.KeyEvidenceFIDO2 {
		return nil
	}
	out := &assurance.Fido2Verified{AAGUID: n.AAGUID}
	if n.UV {
		out.UV = assurance.UVPresent
	}
	return out
}

// wiaFacts builds the evidence of a WIA decision. The platform slot is the
// native attestation source verified in this request (not stored instance
// state); the FIDO2 slot is the verified FIDO2 record stored for the instance
// key (none when there is none: a WIA request itself carries no FIDO2
// evidence); there are no client claims. This is KEY evidence about the
// instance key: no shipped rule derives a credential key's KA level from it.
func wiaFacts(att wiaAttestation) assurance.Facts {
	return assurance.Facts{
		Platform:    &assurance.PlatformVerified{Source: att.Source, AppID: att.AppID},
		Fido2:       fido2VerifiedFromRecord(att.KeyEvidence),
		InstanceKey: instanceKeyVerifiedFromRecord(att.KeyEvidence),
	}
}

// applyAssurance runs the policy for one WIA request and records the result
// in att. It returns ErrWIARefusedByPolicy when no rule permits issuance.
func (s *WIAService) applyAssurance(ctx context.Context, jkt string, att *wiaAttestation) error {
	if s.assessor == nil {
		return ErrAssuranceUnavailable
	}
	out := s.assessor.AssessWIA(ctx, wiaFacts(*att))
	for _, err := range out.Errors {
		s.logger.Warn("assurance decider error treated as deny", zap.Error(err))
	}
	s.logger.Info("wia assurance decision",
		zap.String("jkt", jkt[:min(8, len(jkt))]+"..."),
		zap.String("policy_hash", out.PolicyVersion),
		zap.Int("schema_version", out.SchemaVersion),
		zap.Strings("rule_ids", out.RuleIDs()),
		zap.Bool("issue", out.Issue),
		zap.Strings("issue_rules", out.IssueRuleIDs),
		zap.String("verified_source", att.Source),
		zap.String("instance_key_kind", instanceKeyAudit(att.KeyEvidence, func(i *assurance.InstanceKeyVerified) string { return i.Kind })),
		zap.String("instance_key_home", instanceKeyAudit(att.KeyEvidence, func(i *assurance.InstanceKeyVerified) string { return i.Home })),
		zap.String("profile", out.Profile.Level),
		zap.String("profile_value", out.Profile.Value),
		zap.Strings("profile_rules", out.Profile.RuleIDs),
		zap.String("certification_entry", out.CertName),
		zap.Strings("certification_rules", out.CertRuleIDs),
	)
	att.Decision = out
	if !out.Issue {
		return ErrWIARefusedByPolicy
	}
	att.Claim = out.Profile.Value
	att.CertInfo = out.CertInfo
	return nil
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

// effectiveWIALifetime is the lifetime signWIA gives a WIA: the configured
// attestation.lifetime_seconds, defaulting to (and capped by)
// wia.max_expiry_seconds, which itself defaults to 24h. unset reports that
// lifetime_seconds was not configured. Platform-evidence freshness for Key
// Attestation uses the same value, so evidence never outlives its WIA.
func effectiveWIALifetime(cfg *config.Config) (lifetime time.Duration, unset bool) {
	lifetime = time.Duration(cfg.WalletProvider.Attestation.LifetimeSeconds) * time.Second
	maxExpiry := time.Duration(cfg.WalletProvider.WIA.MaxExpirySeconds) * time.Second
	if maxExpiry <= 0 {
		maxExpiry = 24 * time.Hour // sensible default to prevent zero/negative expiry
	}
	if lifetime <= 0 {
		lifetime, unset = maxExpiry, true
	}
	if lifetime > maxExpiry {
		lifetime = maxExpiry
	}
	return lifetime, unset
}

// signWIA creates the WIA JWT (typ: oauth-client-attestation+jwt).
// jkt is the JWK Thumbprint of cnfJWK, precomputed by the caller (GenerateWIA)
// so it can also be used for the instance-status guard before signing.
func (s *WIAService) signWIA(cnfJWK map[string]interface{}, jkt string, tenantID domain.TenantID, userID *domain.UserID, att wiaAttestation, clientID string) (string, error) {
	now := time.Now()
	attestationSource := att.Source
	claimSource := att.Claim
	if claimSource == "" {
		claimSource = att.Source
	}

	// WIA lifetime, capped by WIA max expiry. Deliberately short (default
	// 300s / 5 min, see AttestationConfig) — this wallet provider has no
	// client_status/revocation-chaining mechanism (see below); a short
	// lifetime is the actual mechanism bounding exposure from a
	// compromised/revoked wallet instance.
	lifetime, lifetimeUnset := effectiveWIALifetime(s.cfg)
	if lifetimeUnset {
		s.logger.Warn("attestation.lifetime_seconds not set, defaulting to max_expiry_seconds",
			zap.Duration("lifetime", lifetime))
	}

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
		// ETSI TS 119 472-3 define a WIA claim for this. It mirrors the
		// S-tier "WIA dimension" of WE BUILD wp4-architecture PR #229
		// ("cs-04: Add Annex C — Tiered WUA for cross-platform Wallet
		// Solutions", open as of 2026-08, branch
		// cs-04/annex-c-tiered-attestation) — NOT "WP4 CS-05" (Business
		// Wallet, unrelated); Annex C is a proposed addition to CS-04.
		// Annex C's own note is explicit that TS-03/CS-04 don't define this
		// claim: any such signal "may [be conveyed] via the certification
		// information or via an extension claim, but this is outside the
		// scope of TS-03 and CS-04" — this claim is that extension.
		// Values emitted by the backend without the assurance policy (the
		// strings the attestation verifier produces):
		//   "backend_attested"      — Annex C S3: backend-only attestation
		//   "platform_attested"     — Annex C S1: full client attestation,
		//                             a verified Apple App Attest or Google
		//                             Play Integrity check
		//   "development_attested"  — an App Attest chain that only chained
		//                             to a development environment; NOT S1
		// Annex C's S2 (partial client attestation, e.g. a browser
		// extension/companion) has no evidence source and no value yet.
		// With wallet_provider.attestation.assurance enabled the value is
		// the emitted string of the S profile the policy chose
		// (assure-wia); the verified source stays in the audit log and on
		// the wallet instance.
		// Third-party wallet providers may omit this claim; issuers must handle
		// both present and absent cases (absent = unknown tier).
		"attestation_source": claimSource,
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

	// Wallet solution certification information (Annex C §C.3.2). The
	// assurance policy may select a catalogue entry; otherwise the static
	// configuration is used.
	switch {
	case len(att.CertInfo) > 0:
		claims["wallet_solution_certification_information"] = att.CertInfo
	case len(s.cfg.WalletProvider.WIA.CertificationInfo) > 0:
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

	wiaGeneratedTotal.WithLabelValues(claimSource).Inc()
	s.logger.Info("WIA generated", zap.String("jkt", jkt[:8]+"..."))

	// Record wallet instance (upsert: creates on first attestation, updates on subsequent).
	// Status is only ever set here for a brand-new instance (defaults to Active on
	// insert); Upsert must not overwrite the status of an existing instance — that
	// would silently undo an admin suspend/revoke the next time this instance
	// successfully re-attests. See the guard in GenerateWIA above.
	if s.instances != nil {
		now := time.Now().UTC()
		instance := &domain.WalletInstance{
			ID:       jkt,
			TenantID: tenantID,
			UserID:   userID,
			Status:   domain.InstanceStatusActive,
			// The WIA PoP key is the wallet's instance key in its own keystore
			// (software store or any WSCD plugin), not the App Attest / Play
			// Integrity key. Its home is only known from verified per-key
			// evidence for that very key; without it the type is unknown (never
			// derived from the platform attestation or a client-reported plugin).
			WSCDType:          instanceWSCDType(att.KeyEvidence),
			AttestationSource: attestationSource,
			VerifiedAppID:     att.AppID,
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
		payload := map[string]any{"attestation_source": claimSource}
		if att.Decision != nil {
			// With the policy enabled attestation_source is the chosen
			// profile's value, so the verified source goes alongside it.
			payload["verified_attestation_source"] = attestationSource
			payload["assurance_profile"] = att.Decision.Profile.Level
			payload["assurance_policy_hash"] = att.Decision.PolicyVersion
			payload["assurance_rule_ids"] = att.Decision.RuleIDs()
		}
		s.audit.EmitWithSubject(set.EventWIAIssued, jkt, payload)
	}

	return tokenString, nil
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

// wscdTypeFromKeyHome maps the verified home of a key to the WSCD type an
// instance records. It must only be called with the Home of a VERIFIED
// key-evidence record (storage returns only verified records); with nothing
// verified the type is domain.WSCDTypeUnknown, never a guess from the
// client-reported plugin or from the platform attestation.
func wscdTypeFromKeyHome(home domain.KeyHome) domain.WSCDType {
	switch home {
	case domain.KeyHomeStrongBox, domain.KeyHomeTEE:
		return domain.WSCDTypeNativeAndroid
	case domain.KeyHomeSecureEnclaveAsserted:
		return domain.WSCDTypeNativeIOS
	case domain.KeyHomeFIDO2Hardware:
		return domain.WSCDTypeFIDO2Hardware
	case domain.KeyHomeHSM:
		return domain.WSCDTypeRemote
	}
	return domain.WSCDTypeUnknown
}

// instanceWSCDType is the wscd_type to record for an instance key given its
// verified evidence record (nil: nothing verified, so unknown).
func instanceWSCDType(rec *domain.KeyAttestationRecord) domain.WSCDType {
	if rec == nil {
		return domain.WSCDTypeUnknown
	}
	n := *rec
	n.Normalize()
	return wscdTypeFromKeyHome(n.Home)
}

// instanceKeyAudit extracts one field of the instance_key evidence for the
// audit line, "none" when the slot is absent.
func instanceKeyAudit(rec *domain.KeyAttestationRecord, field func(*assurance.InstanceKeyVerified) string) string {
	if ik := instanceKeyVerifiedFromRecord(rec); ik != nil {
		if v := field(ik); v != "" {
			return v
		}
	}
	return assurance.None
}
