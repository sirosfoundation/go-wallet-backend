package service

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/assurance"
	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

// Bounds on a submitted chain. Real chains are 3-5 certificates of 0.5-2 KiB.
const (
	maxAndroidChainCerts   = 8
	maxAndroidCertBytes    = 8 * 1024
	maxAndroidChainBytes   = 32 * 1024
	maxAndroidX5CB64Length = maxAndroidCertBytes*4/3 + 8
)

// androidBootVerified is the verifiedBootState value for a fully verified boot.
const androidBootVerified = 0

// Level strings recorded with the evidence.
const (
	androidLevelNameStrongBox = "strongbox"
	androidLevelNameTEE       = "trusted_environment"
)

// AndroidKeyAttestationVerifier verifies Android Key Attestation chains as
// evidence about the WIA instance key (key_attestation type android_key):
//
//	{"type": "android_key", "x5c": ["<base64 DER leaf>", "<intermediate>", ..., "<root>"]}
//
// The key under attestation is the WIA-PoP key: the chain's LEAF public key
// must equal it, and the leaf's attestationChallenge must equal
// InstanceKeyAttestationChallenge(C) for the WIA challenge C of the request.
// Trust anchors are only those the operator pinned in configuration; the
// verifier ships none and uses no operating-system pool. Revocation uses
// Google's status list and fails closed.
//
// Outcomes (see instance_key_evidence.go):
//   - invalid (WIA refused): malformed payload or ASN.1, broken chain link,
//     expired or not-yet-valid certificate, wrong leaf key, wrong challenge,
//     missing attestation extension, a revoked certificate;
//   - unavailable (WIA refused, nothing recorded): no fresh revocation list;
//   - no home (nothing recorded): not configured (no anchors or no allowed
//     app digests), chain does not end in a pinned anchor, a software
//     security level, a key not generated in the keystore, no SIGN purpose,
//     an application not on the allowlist, and in reject mode a boot state
//     that is not verified, an unlocked bootloader or an old patch level. With
//     enforcement "ignore" (default) the WIA issues with the home unknown;
//     with "reject" the WIA is refused (KeyAttestationNotQualifyingError) with
//     one of the fixed NoHome* reasons;
//   - verified: a record with Home strongbox or tee.
//
// In ignore mode boot state, bootloader lock and patch level are recorded,
// never required: policy decides what to do with them. The record also keeps
// the chain's serial numbers so it can be checked against the revocation list
// again each time it is used (Recheck).
type AndroidKeyAttestationVerifier struct {
	logger     *zap.Logger
	anchors    *x509.CertPool
	numAnchors int
	// anchorFPs are the SHA-256 fingerprints (hex) of the pinned anchors, so a
	// stored record can be checked against the CURRENT pins.
	anchorFPs map[string]struct{}
	digests   map[string]struct{}
	packages  map[string]struct{}
	status    *androidStatusList
	policy    androidEnforcement
}

// androidEnforcement is the configured handling of evidence that does not
// qualify (see config.AndroidKeyAttestationConfig.Enforcement).
type androidEnforcement struct {
	reject        bool
	verifiedBoot  bool
	lockedBoot    bool
	minPatchLevel int
}

// NewAndroidKeyAttestationVerifier builds the verifier from configuration. A
// nil fetcher selects the HTTP fetcher for cfg.StatusListURL using client.
// Unparseable anchors or digests are an error (do not run with a half-read
// trust configuration); an EMPTY configuration is valid and verifies nothing.
func NewAndroidKeyAttestationVerifier(cfg config.AndroidKeyAttestationConfig, logger *zap.Logger, fetcher AttestationStatusFetcher) (*AndroidKeyAttestationVerifier, error) {
	v := &AndroidKeyAttestationVerifier{
		logger:    logger.Named("android-key-attestation"),
		anchors:   x509.NewCertPool(),
		anchorFPs: make(map[string]struct{}),
		digests:   make(map[string]struct{}),
		packages:  make(map[string]struct{}),
		policy: androidEnforcement{
			reject:        cfg.Rejecting(),
			verifiedBoot:  cfg.VerifiedBootRequired(),
			lockedBoot:    cfg.LockedBootloaderRequired(),
			minPatchLevel: cfg.MinPatchLevel,
		},
	}
	var pemData []byte
	if cfg.TrustAnchorsPath != "" {
		b, err := os.ReadFile(cfg.TrustAnchorsPath)
		if err != nil {
			var pe *os.PathError
			if errors.As(err, &pe) {
				err = pe.Err
			}
			return nil, fmt.Errorf("android_key_attestation.trust_anchors_path: %w", err)
		}
		pemData = append(pemData, b...)
		pemData = append(pemData, '\n')
	}
	pemData = append(pemData, cfg.TrustAnchorsPEM...)
	n, err := addPEMAnchors(v.anchors, v.anchorFPs, pemData)
	if err != nil {
		return nil, fmt.Errorf("android_key_attestation trust anchors: %w", err)
	}
	v.numAnchors = n
	for _, d := range cfg.AllowedAppDigests {
		norm, err := normalizeAppDigest(d)
		if err != nil {
			return nil, fmt.Errorf("android_key_attestation.allowed_app_digests: %w", err)
		}
		v.digests[norm] = struct{}{}
	}
	for _, p := range cfg.AllowedPackages {
		if p = strings.TrimSpace(p); p != "" {
			v.packages[p] = struct{}{}
		}
	}
	if fetcher == nil {
		url := cfg.StatusListURL
		if url == "" {
			url = DefaultAndroidAttestationStatusURL
		}
		fetcher = NewHTTPAttestationStatusFetcher(config.HTTPClientConfig{}.NewHTTPClient(10*time.Second), url)
	}
	v.status = newAndroidStatusList(fetcher, time.Duration(cfg.StatusListDefaultTTLSeconds)*time.Second)
	if !v.configured() {
		if v.policy.reject {
			v.logger.Error("android key attestation enforcement is reject but there are no trust anchors or no allowed app digests: every submitted android_key evidence will be refused",
				zap.Int("trust_anchors", v.numAnchors), zap.Int("allowed_app_digests", len(v.digests)))
		} else {
			v.logger.Warn("android key attestation has no trust anchors or no allowed app digests: submitted android_key evidence will be ignored (home unknown)",
				zap.Int("trust_anchors", v.numAnchors), zap.Int("allowed_app_digests", len(v.digests)))
		}
	}
	return v, nil
}

// setStatusClock lets tests control the revocation list's notion of now.
func (v *AndroidKeyAttestationVerifier) setStatusClock(now func() time.Time) { v.status.now = now }

// addPEMAnchors adds every CERTIFICATE block of data to pool. pem.Decode skips
// forward past text it cannot decode, so a malformed block followed by a good
// one would be dropped silently and the operator would run with a partially
// read trust configuration; instead the number of BEGIN lines must equal the
// number of blocks that decoded, and nothing but whitespace may surround them.
func addPEMAnchors(pool *x509.CertPool, fps map[string]struct{}, data []byte) (int, error) {
	begins := bytes.Count(data, []byte("-----BEGIN "))
	if begins > 0 && !bytes.HasPrefix(bytes.TrimSpace(data), []byte("-----BEGIN ")) {
		return 0, errors.New("unexpected data before the first PEM block")
	}
	count := 0
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return 0, fmt.Errorf("unexpected PEM block %q", block.Type)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return 0, fmt.Errorf("parse certificate: %w", err)
		}
		pool.AddCert(cert)
		fp := sha256.Sum256(cert.Raw)
		fps[hex.EncodeToString(fp[:])] = struct{}{}
		count++
	}
	if len(bytes.TrimSpace(data)) != 0 {
		return 0, errors.New("trailing data after the last PEM block")
	}
	if count != begins {
		return 0, fmt.Errorf("%d PEM blocks begin but %d decode", begins, count)
	}
	return count, nil
}

func normalizeAppDigest(d string) (string, error) {
	d = strings.ToLower(strings.NewReplacer(":", "", " ", "").Replace(strings.TrimSpace(d)))
	b, err := hex.DecodeString(d)
	if err != nil || len(b) != sha256.Size {
		return "", errors.New("an app digest must be 32 bytes of hex (SHA-256 of the signing certificate)")
	}
	return d, nil
}

func (v *AndroidKeyAttestationVerifier) configured() bool {
	return v.numAnchors > 0 && len(v.digests) > 0
}

// Type implements InstanceKeyEvidenceVerifier.
func (v *AndroidKeyAttestationVerifier) Type() KeyAttestationType { return KeyAttestationAndroidKey }

func androidInvalid(format string, a ...any) error {
	return fmt.Errorf("%w: android_key: %s", ErrWIAKeyAttestationInvalid, fmt.Sprintf(format, a...))
}

// notQualifying is the outcome for well formed evidence that cannot name a
// home. In ignore mode it is a result with no record (the WIA issues with the
// home unknown); in reject mode it is a KeyAttestationNotQualifyingError. The
// reason is always one of the fixed NoHome* values, never text from the
// evidence.
func (v *AndroidKeyAttestationVerifier) notQualifying(reason string) (*InstanceKeyEvidenceResult, error) {
	if v.policy.reject {
		return nil, &KeyAttestationNotQualifyingError{Reason: reason}
	}
	return &InstanceKeyEvidenceResult{Reason: reason}, nil
}

// parseAndroidChain decodes the x5c members: base64 (standard) DER, bounded
// in count and size.
func parseAndroidChain(x5c []string) ([]*x509.Certificate, error) {
	if len(x5c) < 2 {
		return nil, androidInvalid("x5c needs at least a leaf and a root, got %d", len(x5c))
	}
	if len(x5c) > maxAndroidChainCerts {
		return nil, androidInvalid("x5c has %d certificates, at most %d allowed", len(x5c), maxAndroidChainCerts)
	}
	total := 0
	certs := make([]*x509.Certificate, 0, len(x5c))
	for i, s := range x5c {
		if len(s) > maxAndroidX5CB64Length {
			return nil, androidInvalid("x5c[%d] is too large", i)
		}
		der, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			return nil, androidInvalid("x5c[%d] is not base64: %v", i, err)
		}
		total += len(der)
		if len(der) == 0 || len(der) > maxAndroidCertBytes || total > maxAndroidChainBytes {
			return nil, androidInvalid("x5c[%d] size out of bounds", i)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, androidInvalid("x5c[%d] is not a certificate: %v", i, err)
		}
		certs = append(certs, cert)
	}
	return certs, nil
}

// Verify implements InstanceKeyEvidenceVerifier.
func (v *AndroidKeyAttestationVerifier) Verify(ctx context.Context, in *InstanceKeyEvidenceInput) (*InstanceKeyEvidenceResult, error) {
	if !v.configured() {
		return v.notQualifying(NoHomeNotConfigured)
	}
	var p struct {
		X5C []string `json:"x5c"`
	}
	if err := json.Unmarshal(in.Payload, &p); err != nil {
		return nil, androidInvalid("payload: %v", err)
	}
	certs, err := parseAndroidChain(p.X5C)
	if err != nil {
		return nil, err
	}

	// Every link must be what it says: issuer names chain and each
	// certificate's signature verifies under the next one's key. A broken link
	// is tampering, not merely an unknown root.
	for i := 0; i+1 < len(certs); i++ {
		child, parent := certs[i], certs[i+1]
		if !bytes.Equal(child.RawIssuer, parent.RawSubject) {
			return nil, androidInvalid("certificate %d is not issued by certificate %d", i, i+1)
		}
		if !parent.BasicConstraintsValid || !parent.IsCA {
			return nil, androidInvalid("certificate %d is not a CA but issued certificate %d", i+1, i)
		}
		if err := parent.CheckSignature(child.SignatureAlgorithm, child.RawTBSCertificate, child.Signature); err != nil {
			return nil, androidInvalid("certificate %d signature: %v", i, err)
		}
	}

	// The chain must end in a pinned anchor. x509.Verify enforces validity at
	// the submission time, CA constraints (a leaf key cannot sign further
	// certificates) and path length.
	inter := x509.NewCertPool()
	for _, c := range certs[1:] {
		inter.AddCert(c)
	}
	chains, err := certs[0].Verify(x509.VerifyOptions{
		Roots:         v.anchors,
		Intermediates: inter,
		CurrentTime:   in.Now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil {
		var unknown x509.UnknownAuthorityError
		if errors.As(err, &unknown) {
			return v.notQualifying(NoHomeUntrustedRoot)
		}
		return nil, androidInvalid("chain: %v", err)
	}
	chain := chains[0]

	// The attestation extension is read from the leaf only.
	var extValue []byte
	for _, e := range certs[0].Extensions {
		if e.Id.Equal(oidAndroidKeyDescription) {
			if extValue != nil {
				return nil, androidInvalid("duplicate attestation extension")
			}
			extValue = e.Value
		}
	}
	if extValue == nil {
		return nil, androidInvalid("leaf has no key attestation extension")
	}
	kd, err := parseAndroidKeyDescription(extValue)
	if err != nil {
		return nil, androidInvalid("%v", err)
	}

	// Binding to the PoP key: the attested key IS the WIA key.
	leafKey, ok := certs[0].PublicKey.(*ecdsa.PublicKey)
	if !ok || leafKey.Curve != elliptic.P256() || in.PoPKey == nil || !leafKey.Equal(in.PoPKey) {
		return nil, androidInvalid("attested key is not the WIA-PoP key")
	}
	want := InstanceKeyAttestationChallenge(in.WIAChallenge)
	if subtle.ConstantTimeCompare(kd.Challenge, want) != 1 {
		return nil, androidInvalid("attestation challenge does not match")
	}
	if kd.TEE.Algorithm != nil && *kd.TEE.Algorithm != androidAlgorithmEC {
		return nil, androidInvalid("attested algorithm is not EC")
	}
	if kd.TEE.EcCurve != nil && *kd.TEE.EcCurve != androidCurveP256 {
		return nil, androidInvalid("attested curve is not P-256")
	}

	// Where the key lives: both levels must be hardware, and the weaker wins.
	home, level, ok := androidHome(kd)
	if !ok {
		return v.notQualifying(NoHomeSoftwareSecurityLevel)
	}
	// Facts that hold of the key must come from the hardware-enforced list.
	if kd.TEE.Origin == nil || *kd.TEE.Origin != androidOriginGenerated {
		return v.notQualifying(NoHomeKeyNotGenerated)
	}
	if !kd.TEE.hasPurpose(androidPurposeSign) {
		return v.notQualifying(NoHomeNoSignPurpose)
	}
	appID := kd.Software.AppID
	if appID == nil {
		appID = kd.TEE.AppID
	}
	appDigest, allowed := v.appAllowed(appID)
	if !allowed {
		return v.notQualifying(NoHomeAppNotAllowed)
	}
	appPackages := append([]string(nil), appID.Packages...)
	sort.Strings(appPackages)

	// Reject mode also demands a healthy device. Ignore mode records these
	// facts and decides nothing from them.
	if v.policy.reject {
		if reason := v.bootPolicy(kd); reason != "" {
			return v.notQualifying(reason)
		}
	}

	// Revocation last: the list is only consulted for evidence that would
	// otherwise be accepted. Fail closed.
	serials := make([]*big.Int, 0, len(chain))
	for _, c := range chain {
		serials = append(serials, c.SerialNumber)
	}
	revokedSerial, revoked, err := v.status.check(ctx, serials)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrWIAKeyAttestationUnavailable, err)
	}
	if revoked {
		return nil, androidInvalid("certificate with serial %s is revoked", revokedSerial)
	}

	notAfter := chain[0].NotAfter
	for _, c := range chain {
		if c.NotAfter.Before(notAfter) {
			notAfter = c.NotAfter
		}
	}
	fp := sha256.Sum256(certs[0].Raw)
	anchorFP := sha256.Sum256(chain[len(chain)-1].Raw)
	certSerials := make([]string, 0, len(serials))
	for _, sn := range serials {
		certSerials = append(certSerials, serialKey(sn))
	}
	rec := &domain.KeyAttestationRecord{
		Kind:                   domain.KeyEvidenceAndroidKey,
		CertSerials:            certSerials,
		TrustAnchorFingerprint: hex.EncodeToString(anchorFP[:]),
		Home:                   home,
		SecurityLevel:          level,
		AppDigest:              appDigest,
		AppPackages:            appPackages,
		ChainFingerprint:       hex.EncodeToString(fp[:]),
		ChainNotAfter:          notAfter.UTC(),
		VerifiedAt:             in.Now,
		VerifiedBootState:      "",
	}
	if rot := kd.TEE.RootOfTrust; rot != nil {
		rec.VerifiedBootState = androidBootStateName(rot.VerifiedBootState)
		locked := rot.DeviceLocked
		rec.DeviceLocked = &locked
	}
	if kd.TEE.OsPatchLevel != nil {
		rec.PatchLevel = strconv.Itoa(*kd.TEE.OsPatchLevel)
	}
	return &InstanceKeyEvidenceResult{Record: rec}, nil
}

// bootPolicy applies the reject-mode device requirements to the hardware
// enforced boot facts and returns the NoHome reason of the first one that
// fails, "" when all hold. A missing root of trust (or patch level) fails the
// requirement that needs it: absence is never a pass.
func (v *AndroidKeyAttestationVerifier) bootPolicy(kd *androidKeyDescription) string {
	rot := kd.TEE.RootOfTrust
	if v.policy.verifiedBoot && (rot == nil || rot.VerifiedBootState != androidBootVerified) {
		return NoHomeBootNotVerified
	}
	if v.policy.lockedBoot && (rot == nil || !rot.DeviceLocked) {
		return NoHomeBootloaderUnlocked
	}
	if min := v.policy.minPatchLevel; min > 0 {
		if kd.TEE.OsPatchLevel == nil {
			return NoHomePatchLevelMissing
		}
		if normalizePatchLevel(*kd.TEE.OsPatchLevel) < min {
			return NoHomePatchLevelTooOld
		}
	}
	return ""
}

// normalizePatchLevel reduces a YYYYMMDD patch level to YYYYMM (osPatchLevel
// is YYYYMM; some devices report a day as well).
func normalizePatchLevel(p int) int {
	if p > 999999 {
		return p / 100
	}
	return p
}

// androidHome maps the attestation and keymaster security levels to a key
// home. Both must be TrustedEnvironment or StrongBox; the home is the weaker.
func androidHome(kd *androidKeyDescription) (domain.KeyHome, string, bool) {
	for _, l := range []int{kd.AttestationSecurityLevel, kd.KeymasterSecurityLevel} {
		if l != androidLevelTrustedEnvironment && l != androidLevelStrongBox {
			return "", "", false
		}
	}
	if kd.AttestationSecurityLevel == androidLevelStrongBox && kd.KeymasterSecurityLevel == androidLevelStrongBox {
		return domain.KeyHomeStrongBox, androidLevelNameStrongBox, true
	}
	return domain.KeyHomeTEE, androidLevelNameTEE, true
}

func androidBootStateName(s int) string {
	switch s {
	case 0:
		return "verified"
	case 1:
		return "self_signed"
	case 2:
		return "unverified"
	case 3:
		return "failed"
	}
	return "unknown"
}

// appAllowed applies the allowlists: the application id must be present with
// at least one signing digest, every digest must be allowed and, when
// packages are configured, so must every package. It returns the digests,
// sorted and comma separated, for the record.
func (v *AndroidKeyAttestationVerifier) appAllowed(a *androidAppID) (string, bool) {
	if a == nil || len(a.SignatureDigest) == 0 || len(a.Packages) == 0 {
		return "", false
	}
	digests := make([]string, 0, len(a.SignatureDigest))
	for _, d := range a.SignatureDigest {
		h := hex.EncodeToString(d)
		if _, ok := v.digests[h]; !ok {
			return "", false
		}
		digests = append(digests, h)
	}
	if len(v.packages) > 0 {
		for _, p := range a.Packages {
			if _, ok := v.packages[p]; !ok {
				return "", false
			}
		}
	}
	sort.Strings(digests)
	return strings.Join(digests, ","), true
}

// androidKeyInstanceKeyBuilder renders a verified Android record as the
// instance_key slot: a chain covers the key itself (binding attested).
type androidKeyInstanceKeyBuilder struct{}

func (androidKeyInstanceKeyBuilder) Kind() domain.KeyEvidenceKind {
	return domain.KeyEvidenceAndroidKey
}

func (androidKeyInstanceKeyBuilder) Build(rec *domain.KeyAttestationRecord) *assurance.InstanceKeyVerified {
	return &assurance.InstanceKeyVerified{
		Kind:    string(rec.Kind),
		Home:    string(rec.Home),
		Level:   rec.SecurityLevel,
		Boot:    rec.VerifiedBootState,
		Binding: assurance.BindingAttested,
	}
}

func init() {
	instanceKeyBuilders[domain.KeyEvidenceAndroidKey] = androidKeyInstanceKeyBuilder{}
}

// CheckAndroidKeyAttestationConfig reports a configuration the verifier cannot
// load (an unreadable or malformed anchors file, a malformed app digest).
// cmd/server calls it at startup so a half-read trust configuration stops the
// process instead of silently disabling the verifier.
func CheckAndroidKeyAttestationConfig(cfg config.AndroidKeyAttestationConfig) error {
	v, err := NewAndroidKeyAttestationVerifier(cfg, zap.NewNop(), noStatusFetcher{})
	if err != nil {
		return err
	}
	if v.policy.reject && !v.configured() {
		return fmt.Errorf("android_key_attestation.enforcement=reject needs at least one trust anchor and one allowed app digest (anchors: %d, digests: %d)", v.numAnchors, len(v.digests))
	}
	return nil
}

type noStatusFetcher struct{}

func (noStatusFetcher) Fetch(context.Context) ([]byte, StatusFreshness, error) {
	return nil, StatusFreshness{}, errors.New("not fetching")
}

// newAndroidKeyVerifierForServer builds the verifier for the running server.
// A configuration that cannot be loaded leaves it with no trust (fail closed);
// cmd/server has already refused to start on such a configuration.
func newAndroidKeyVerifierForServer(cfg *config.Config, logger *zap.Logger) *AndroidKeyAttestationVerifier {
	ac := cfg.WalletProvider.Attestation.AndroidKeyAttestation
	url := ac.StatusListURL
	if url == "" {
		url = DefaultAndroidAttestationStatusURL
	}
	fetcher := NewHTTPAttestationStatusFetcher(cfg.HTTPClient.NewHTTPClient(10*time.Second), url)
	v, err := NewAndroidKeyAttestationVerifier(ac, logger, fetcher)
	if err != nil {
		logger.Error("android key attestation configuration unusable; android_key evidence will be ignored", zap.Error(err))
		// Keep the enforcement mode: a reject deployment must keep refusing,
		// not quietly become an ignore deployment.
		v, _ = NewAndroidKeyAttestationVerifier(config.AndroidKeyAttestationConfig{Enforcement: ac.Enforcement}, logger, fetcher)
	}
	return v
}

// Recheck implements InstanceKeyEvidenceRechecker: it decides whether a stored
// android_key record may still be used. In this order:
//
//  1. its chain must not have expired;
//  2. the CURRENT configuration must still accept what the record says: trust
//     and app allowlists (digests, packages) always, and in reject mode the
//     boot-state, bootloader and patch-level requirements (a configuration
//     tightened after submission applies to evidence already stored, so a
//     renewal that submits nothing cannot keep an old approval alive). A record
//     that no longer qualifies is RecheckNotQualifying, not an outage, and is
//     never marked: relaxing the configuration again restores it;
//  3. it must carry the serials of its chain (records stored before they were
//     kept cannot be re-checked and are unknown, never good);
//  4. none of the serials may be on a FRESH revocation list. A list that cannot
//     be had is an error (the caller fails closed).
func (v *AndroidKeyAttestationVerifier) Recheck(ctx context.Context, rec *domain.KeyAttestationRecord, now time.Time) (RecheckResult, error) {
	if !rec.ChainNotAfter.IsZero() && !now.Before(rec.ChainNotAfter) {
		return RecheckResult{Verdict: RecheckExpired, Reason: RecheckReasonExpired}, nil
	}
	if reason := v.storedRecordPolicy(rec); reason != "" {
		return RecheckResult{Verdict: RecheckNotQualifying, Reason: reason}, nil
	}
	if len(rec.CertSerials) == 0 || rec.ChainNotAfter.IsZero() {
		return RecheckResult{Verdict: RecheckUnknown, Reason: RecheckReasonLegacy}, nil
	}
	serial, revoked, err := v.status.checkKeys(ctx, rec.CertSerials)
	if err != nil {
		return RecheckResult{}, err
	}
	if revoked {
		return RecheckResult{Verdict: RecheckRevoked, Reason: RecheckReasonRevoked, Serial: serial}, nil
	}
	return RecheckResult{Verdict: RecheckGood}, nil
}

// storedRecordPolicy applies the current configuration to a stored record and
// returns the NoHome reason of the first requirement it fails, "" when it
// still qualifies. What the record does not carry fails the requirement that
// needs it.
func (v *AndroidKeyAttestationVerifier) storedRecordPolicy(rec *domain.KeyAttestationRecord) string {
	if !v.configured() {
		return NoHomeNotConfigured
	}
	// The root the chain ended in must still be pinned: removing a root from
	// the configuration withdraws what it vouched for. A record that does not
	// say which root it ended in cannot be shown to have a pinned one.
	if _, ok := v.anchorFPs[rec.TrustAnchorFingerprint]; !ok {
		return NoHomeUntrustedRoot
	}
	if rec.AppDigest == "" {
		return NoHomeAppNotAllowed
	}
	for _, d := range strings.Split(rec.AppDigest, ",") {
		if _, ok := v.digests[d]; !ok {
			return NoHomeAppNotAllowed
		}
	}
	if len(v.packages) > 0 {
		if len(rec.AppPackages) == 0 {
			return NoHomeAppNotAllowed
		}
		for _, p := range rec.AppPackages {
			if _, ok := v.packages[p]; !ok {
				return NoHomeAppNotAllowed
			}
		}
	}
	if !v.policy.reject {
		return ""
	}
	if v.policy.verifiedBoot && rec.VerifiedBootState != androidBootStateName(androidBootVerified) {
		return NoHomeBootNotVerified
	}
	if v.policy.lockedBoot && (rec.DeviceLocked == nil || !*rec.DeviceLocked) {
		return NoHomeBootloaderUnlocked
	}
	if min := v.policy.minPatchLevel; min > 0 {
		pl, err := strconv.Atoi(rec.PatchLevel)
		if err != nil {
			return NoHomePatchLevelMissing
		}
		if normalizePatchLevel(pl) < min {
			return NoHomePatchLevelTooOld
		}
	}
	return ""
}
