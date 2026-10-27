package service

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	"github.com/sirosfoundation/go-wallet-backend/internal/assurance"
	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
	"github.com/sirosfoundation/go-wallet-backend/internal/tokengate"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
	"github.com/sirosfoundation/go-wallet-backend/pkg/jwk"
)

// --- source-name fix (legacy, assurance disabled) ---------------------------

func TestKeyAttestationTrustsBatch_PlatformSourceNames(t *testing.T) {
	cases := map[string]bool{
		"platform_attested":      true,
		"development_attested":   false, // chained only to the dev environment
		"backend_attested":       false, // no client-side evidence
		"ios_app_attest":         false, // names nothing ever stored
		"android_play_integrity": false,
		"":                       false,
	}
	for source, want := range cases {
		svc, instances, _ := newTestWalletProviderServiceWithInstances(t)
		if err := instances.Upsert(context.Background(), &domain.WalletInstance{ID: "i", Status: domain.InstanceStatusActive, AttestationSource: source, LastAttestedAt: time.Now()}); err != nil {
			t.Fatal(err)
		}
		jwks := []map[string]interface{}{{"kty": "EC", "crv": "P-256", "x": "abc", "y": "def"}}
		if got := svc.keyAttestationTrustsBatch(context.Background(), "i", jwks); got != want {
			t.Errorf("source %q: trusted = %v, want %v", source, got, want)
		}
	}
}

func TestGenerateKeyAttestation_LegacyPlatformAttestedEndToEnd(t *testing.T) {
	svc, instances, _ := newTestWalletProviderServiceWithInstances(t)
	jwks := []map[string]interface{}{{"kty": "EC", "crv": "P-256", "x": "abc", "y": "def"}}
	sp := &SecurityProperties{KeyStorage: []string{"iso_18045_high"}}
	for source, want := range map[string]string{
		"platform_attested":    "iso_18045_high",
		"development_attested": "iso_18045_basic",
	} {
		if err := instances.Upsert(context.Background(), &domain.WalletInstance{ID: "i-" + source, Status: domain.InstanceStatusActive, AttestationSource: source, LastAttestedAt: time.Now()}); err != nil {
			t.Fatal(err)
		}
		ka, err := svc.GenerateKeyAttestation(context.Background(), jwks, "n", sp, "i-"+source, "")
		if err != nil {
			t.Fatal(err)
		}
		assertKeyStorage(t, parseKAClaims(t, ka), want)
	}
}

// --- assurance disabled behaves exactly as before ---------------------------

// An installed assessor must be inert while the policy is disabled: the
// clamp (floor values and the floor certification URL) is unchanged.
func TestGenerateKeyAttestation_AssuranceDisabledKeepsLegacyClamp(t *testing.T) {
	svc, instances, _ := newTestWalletProviderServiceWithInstances(t)
	svc.cfg.WalletProvider.Attestation.StatusList = config.StatusListConfig{Enabled: true}
	svc.SetAssessor(newTestAssessor(t, nil, "# id: all\n(assure-ks (tier (* set basic enhanced-basic moderate high))(evidence))\n"))
	if err := instances.Upsert(context.Background(), &domain.WalletInstance{ID: "i", Status: domain.InstanceStatusActive, AttestationSource: "backend_attested"}); err != nil {
		t.Fatal(err)
	}
	jwks := []map[string]interface{}{{"kty": "EC", "crv": "P-256", "x": "abc", "y": "def"}}
	ka, err := svc.GenerateKeyAttestation(context.Background(), jwks, "n",
		&SecurityProperties{KeyStorage: []string{"iso_18045_high"}, Certification: map[string]interface{}{"scheme": "EUCC"}}, "i", "")
	if err != nil {
		t.Fatal(err)
	}
	c := parseKAClaims(t, ka)
	assertKeyStorage(t, c, "iso_18045_basic")
	assertUserAuthentication(t, c, "iso_18045_basic")
	if c["certification"] != floorCertificationURL {
		t.Fatalf("certification = %v", c["certification"])
	}
	if idx := statusIdx(t, c); idx != statusIndexKABasic {
		t.Fatalf("status idx = %d", idx)
	}
}

// --- assurance enabled ------------------------------------------------------

func enabledCfg() config.AssuranceConfig {
	return config.AssuranceConfig{
		Enabled:                         true,
		RulesFile:                       "unused.rules",
		KeyStorageScheme:                config.DefaultLevelSchemeID,
		UserAuthenticationScheme:        config.DefaultLevelSchemeID,
		LowerByClaimsKeyStorage:         true,
		LowerByClaimsUserAuthentication: true,
		Certification: config.CertificationCatalogueConfig{Entries: config.CertificationEntryList{
			{Name: "eucc-substantial", Scheme: "EUCC", AssuranceLevel: "substantial"},
		}},
	}
}

func newTestAssessor(t *testing.T, mut func(*config.AssuranceConfig), rules string) *assurance.Assessor {
	t.Helper()
	cfg := enabledCfg()
	if mut != nil {
		mut(&cfg)
	}
	path := filepath.Join(t.TempDir(), "p.rules")
	if err := os.WriteFile(path, []byte(rules), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.RulesFile = path
	a, err := assurance.NewFromConfig(cfg, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func assuranceSvc(t *testing.T, mut func(*config.AssuranceConfig), rules string) (*WalletProviderService, storage.WalletInstanceStore, storage.KeyAttestationStore) {
	t.Helper()
	svc, instances, keys := newTestWalletProviderServiceWithInstances(t)
	cfg := enabledCfg()
	if mut != nil {
		mut(&cfg)
	}
	svc.cfg.WalletProvider.Attestation.Assurance = cfg
	svc.cfg.WalletProvider.Attestation.StatusList = config.StatusListConfig{Enabled: true}
	svc.SetAssessor(newTestAssessor(t, mut, rules))
	return svc, instances, keys
}

func statusIdx(t *testing.T, c jwt.MapClaims) int {
	t.Helper()
	kss, ok := c["key_storage_status"].(map[string]interface{})
	if !ok {
		t.Fatalf("no key_storage_status: %v", c)
	}
	sl := kss["status"].(map[string]interface{})["status_list"].(map[string]interface{})
	return int(sl["idx"].(float64))
}

func markAttested(t *testing.T, keys storage.KeyAttestationStore, j map[string]interface{}, aaguid string) {
	t.Helper()
	tp, err := jwk.Thumbprint(j)
	if err != nil {
		t.Fatal(err)
	}
	if err := keys.MarkKeyAttested(context.Background(), &domain.KeyAttestationRecord{KeyThumbprint: tp, AAGUID: aaguid, VerifiedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
}

func twoKeys() []map[string]interface{} {
	return []map[string]interface{}{
		{"kty": "EC", "crv": "P-256", "x": "k1x", "y": "k1y"},
		{"kty": "EC", "crv": "P-256", "x": "k2x", "y": "k2y"},
	}
}

const fidoRules = `# id: fido-ks
(assure-ks (tier (* set basic enhanced-basic moderate))(evidence (verified (fido2 (mds3 trusted)(aaguid (* set aa1 aa2))))))
# id: fido-cert
(assure-cert (name eucc-substantial)(evidence (verified (fido2 (mds3 trusted)(aaguid aa1)))))
`

func TestAssurance_Fido2RequiresEveryKeyAndOneModel(t *testing.T) {
	jwks := twoKeys()
	cases := []struct {
		name   string
		attest func(t *testing.T, keys storage.KeyAttestationStore)
		want   string
	}{
		{"all keys, same aaguid", func(t *testing.T, k storage.KeyAttestationStore) {
			markAttested(t, k, jwks[0], "aa1")
			markAttested(t, k, jwks[1], "aa1")
		}, "iso_18045_moderate"},
		{"one key missing", func(t *testing.T, k storage.KeyAttestationStore) {
			markAttested(t, k, jwks[0], "aa1")
		}, "iso_18045_basic"},
		{"mixed aaguids", func(t *testing.T, k storage.KeyAttestationStore) {
			markAttested(t, k, jwks[0], "aa1")
			markAttested(t, k, jwks[1], "aa2")
		}, "iso_18045_basic"},
		{"no records", func(t *testing.T, k storage.KeyAttestationStore) {}, "iso_18045_basic"},
	}
	for _, c := range cases {
		svc, _, keys := assuranceSvc(t, nil, fidoRules)
		c.attest(t, keys)
		ka, err := svc.GenerateKeyAttestation(context.Background(), jwks, "n", nil, "", "")
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		assertKeyStorage(t, parseKAClaims(t, ka), c.want)
		if t.Failed() {
			t.Fatalf("case %q failed", c.name)
		}
	}
}

func TestAssurance_EmitsPolicyValuesAndCertification(t *testing.T) {
	jwks := twoKeys()
	svc, _, keys := assuranceSvc(t, nil, fidoRules)
	markAttested(t, keys, jwks[0], "aa1")
	markAttested(t, keys, jwks[1], "aa1")
	// The client claims nothing at all (nil security_properties): the policy
	// still decides from verified evidence.
	ka, err := svc.GenerateKeyAttestation(context.Background(), jwks, "n", nil, "", "")
	if err != nil {
		t.Fatal(err)
	}
	c := parseKAClaims(t, ka)
	assertKeyStorage(t, c, "iso_18045_moderate")
	assertUserAuthentication(t, c, "iso_18045_basic")
	cert, _ := c["certification"].(map[string]interface{})
	if cert["scheme"] != "EUCC" || cert["assurance_level"] != "substantial" || cert["basis"] != nil {
		t.Fatalf("certification = %v", c["certification"])
	}
	if idx := statusIdx(t, c); idx != statusIndexKAModerate {
		t.Fatalf("status idx = %d", idx)
	}

	// A different model gets no certification: the entry is only granted for aa1.
	svc2, _, keys2 := assuranceSvc(t, nil, fidoRules)
	markAttested(t, keys2, jwks[0], "aa2")
	markAttested(t, keys2, jwks[1], "aa2")
	ka, _ = svc2.GenerateKeyAttestation(context.Background(), jwks, "n", nil, "", "")
	if got := parseKAClaims(t, ka)["certification"]; got != "none" {
		t.Fatalf("certification = %v", got)
	}
}

func TestAssurance_PlatformSourceIsTheRealStoredString(t *testing.T) {
	rules := "# id: plat\n(assure-ks (tier (* set basic enhanced-basic moderate))(evidence (verified (fido2)(platform (source platform_attested)))))\n"
	jwks := twoKeys()
	for source, want := range map[string]string{
		"platform_attested":    "iso_18045_moderate",
		"development_attested": "iso_18045_basic", // distinct atom, no rule for it
		"backend_attested":     "iso_18045_basic",
		"ios_app_attest":       "iso_18045_basic",
	} {
		svc, instances, _ := assuranceSvc(t, nil, rules)
		if err := instances.Upsert(context.Background(), &domain.WalletInstance{ID: "i", Status: domain.InstanceStatusActive, AttestationSource: source, LastAttestedAt: time.Now()}); err != nil {
			t.Fatal(err)
		}
		ka, err := svc.GenerateKeyAttestation(context.Background(), jwks, "n", nil, "i", "")
		if err != nil {
			t.Fatal(err)
		}
		if got := parseKAClaims(t, ka)["key_storage"].([]interface{})[0]; got != want {
			t.Errorf("source %q: key_storage = %v, want %v", source, got, want)
		}
	}
}

// What the client says never becomes verified evidence.
func TestAssurance_ClaimsNeverBecomeVerifiedEvidence(t *testing.T) {
	svc, _, _ := assuranceSvc(t, nil, fidoRules)
	sp := &SecurityProperties{
		Plugin:             "aa1",
		KeyStorage:         []string{"iso_18045_high"},
		UserAuthentication: []string{"iso_18045_high"},
		Certification:      map[string]interface{}{"scheme": "EUCC", "assurance_level": "substantial"},
	}
	ka, err := svc.GenerateKeyAttestation(context.Background(), twoKeys(), "n", sp, "", "")
	if err != nil {
		t.Fatal(err)
	}
	c := parseKAClaims(t, ka)
	assertKeyStorage(t, c, "iso_18045_basic")
	if c["certification"] != "none" {
		t.Fatalf("a claimed certification must not be echoed: %v", c["certification"])
	}
}

func TestAssurance_LowerByClaimsAndLegacyVocabulary(t *testing.T) {
	jwks := twoKeys()
	run := func(lower bool, claim []string) string {
		svc, _, keys := assuranceSvc(t, func(c *config.AssuranceConfig) { c.LowerByClaimsKeyStorage = lower }, fidoRules)
		markAttested(t, keys, jwks[0], "aa1")
		markAttested(t, keys, jwks[1], "aa1")
		var sp *SecurityProperties
		if claim != nil {
			sp = &SecurityProperties{KeyStorage: claim}
		}
		ka, err := svc.GenerateKeyAttestation(context.Background(), jwks, "n", sp, "", "")
		if err != nil {
			t.Fatal(err)
		}
		return parseKAClaims(t, ka)["key_storage"].([]interface{})[0].(string)
	}
	if got := run(true, []string{"software"}); got != "iso_18045_basic" {
		t.Errorf("legacy 'software' claim should lower to basic, got %s", got)
	}
	if got := run(true, []string{"iso_18045_enhanced-basic"}); got != "iso_18045_enhanced-basic" {
		t.Errorf("claim below grant should lower, got %s", got)
	}
	if got := run(true, []string{"trusted_execution"}); got != "iso_18045_enhanced-basic" {
		t.Errorf("legacy 'trusted_execution' claim should map to enhanced-basic and lower to it, got %s", got)
	}
	if got := run(true, []string{"remote_hsm"}); got != "iso_18045_moderate" {
		t.Errorf("claim above grant keeps grant, got %s", got)
	}
	if got := run(true, nil); got != "iso_18045_moderate" {
		t.Errorf("no claim, no lowering, got %s", got)
	}
	if got := run(false, []string{"software"}); got != "iso_18045_moderate" {
		t.Errorf("lower_by_claims=false: rules are the authority, got %s", got)
	}
}

func TestAssurance_NonISOSchemeEmitsConfiguredValuesAndMapsStatusIndex(t *testing.T) {
	mut := func(c *config.AssuranceConfig) {
		c.LevelSchemes = config.LevelSchemeList{{ID: "k", Levels: []string{"k3", "k2", "k1"}, Values: []string{"urn:k:3", "urn:k:2", "urn:k:1"}, Floor: "k3"}}
		c.KeyStorageScheme = "k"
	}
	rules := "# id: k2\n(assure-ks (tier (* set k3 k2))(evidence (verified (fido2 (mds3 trusted)))))\n# id: k1\n(assure-ks (tier k1)(evidence (verified (fido2 (mds3 trusted)(aaguid aa1)))))\n"
	jwks := twoKeys()
	for aaguid, want := range map[string]struct {
		val string
		idx int
	}{
		"aa1": {"urn:k:1", statusIndexKAHigh},
		"aa2": {"urn:k:2", statusIndexKAModerate},
	} {
		svc, _, keys := assuranceSvc(t, mut, rules)
		markAttested(t, keys, jwks[0], aaguid)
		markAttested(t, keys, jwks[1], aaguid)
		ka, err := svc.GenerateKeyAttestation(context.Background(), jwks, "n", nil, "", "")
		if err != nil {
			t.Fatal(err)
		}
		c := parseKAClaims(t, ka)
		assertKeyStorage(t, c, want.val)
		if got := statusIdx(t, c); got != want.idx {
			t.Errorf("%s: status idx = %d, want %d", aaguid, got, want.idx)
		}
	}
	// Floor of the custom scheme maps to the basic index.
	svc, _, _ := assuranceSvc(t, mut, rules)
	ka, _ := svc.GenerateKeyAttestation(context.Background(), jwks, "n", nil, "", "")
	c := parseKAClaims(t, ka)
	assertKeyStorage(t, c, "urn:k:3")
	if got := statusIdx(t, c); got != statusIndexKABasic {
		t.Errorf("floor status idx = %d", got)
	}
}

func TestAssurance_EnabledWithoutAssessorFailsClosed(t *testing.T) {
	svc, _, _ := newTestWalletProviderServiceWithInstances(t)
	svc.cfg.WalletProvider.Attestation.Assurance = enabledCfg()
	_, err := svc.GenerateKeyAttestation(context.Background(), twoKeys(), "n", &SecurityProperties{KeyStorage: []string{"iso_18045_high"}}, "", "")
	if !errors.Is(err, ErrAssuranceUnavailable) {
		t.Fatalf("err = %v", err)
	}
}

func TestAssurance_AuditLineHasRuleIDsPolicyHashAndNoNonce(t *testing.T) {
	jwks := twoKeys()
	svc, _, keys := assuranceSvc(t, nil, fidoRules)
	core, logs := observer.New(zap.InfoLevel)
	svc.logger = zap.New(core)
	for _, j := range jwks {
		tp, err := jwk.Thumbprint(j)
		if err != nil {
			t.Fatal(err)
		}
		if err := keys.MarkKeyAttested(context.Background(), &domain.KeyAttestationRecord{KeyThumbprint: tp, WalletInstanceID: "inst-1", AAGUID: "aa1", VerifiedAt: time.Now()}); err != nil {
			t.Fatal(err)
		}
	}
	const nonce = "super-secret-nonce-value"
	if _, err := svc.GenerateKeyAttestation(context.Background(), jwks, nonce, nil, "inst-1", ""); err != nil {
		t.Fatal(err)
	}
	entries := logs.FilterMessage("key attestation assurance decision").All()
	if len(entries) != 1 {
		t.Fatalf("audit lines = %d", len(entries))
	}
	f := entries[0].ContextMap()
	if f["policy_hash"] == "" || f["policy_hash"] == nil || f["schema_version"] != int64(assurance.SchemaVersion) {
		t.Fatalf("fields: %v", f)
	}
	rules := strings.Join(toStrings(f["rule_ids"]), ",")
	if rules != "fido-ks,fido-cert" {
		t.Fatalf("rule_ids = %q", rules)
	}
	if f["key_storage"] != "iso_18045_moderate" {
		t.Fatalf("key_storage = %v", f["key_storage"])
	}
	for k, v := range f {
		if s, ok := v.(string); ok && strings.Contains(s, nonce) {
			t.Fatalf("nonce leaked in field %s", k)
		}
	}
}

func toStrings(v interface{}) []string {
	var out []string
	if xs, ok := v.([]interface{}); ok {
		for _, x := range xs {
			out = append(out, x.(string))
		}
	}
	return out
}

// --- instance ownership ---------------------------------------------------

func TestInstanceOwnership_ForeignInstanceLendsNoEvidence(t *testing.T) {
	owner := domain.UserIDFromString("owner")
	cases := []struct {
		name   string
		caller *KeyAttestationCaller
		inst   *domain.WalletInstance
		want   bool
	}{
		{"owner", &KeyAttestationCaller{TenantID: "t1", UserID: "owner"}, &domain.WalletInstance{ID: "i", TenantID: "t1", UserID: &owner, Status: domain.InstanceStatusActive}, true},
		{"other tenant", &KeyAttestationCaller{TenantID: "t2", UserID: "owner"}, &domain.WalletInstance{ID: "i", TenantID: "t1", UserID: &owner, Status: domain.InstanceStatusActive}, false},
		{"other user", &KeyAttestationCaller{TenantID: "t1", UserID: "mallory"}, &domain.WalletInstance{ID: "i", TenantID: "t1", UserID: &owner, Status: domain.InstanceStatusActive}, false},
		{"instance without user, same tenant", &KeyAttestationCaller{TenantID: "t1", UserID: "owner"}, &domain.WalletInstance{ID: "i", TenantID: "t1", Status: domain.InstanceStatusActive}, true},
		{"instance without user, other tenant", &KeyAttestationCaller{TenantID: "t2"}, &domain.WalletInstance{ID: "i", TenantID: "t1", Status: domain.InstanceStatusActive}, false},
		{"no caller in context: no check", nil, &domain.WalletInstance{ID: "i", TenantID: "t1", UserID: &owner, Status: domain.InstanceStatusActive}, true},
	}
	for _, c := range cases {
		svc, instances, _ := assuranceSvc(t, nil,
			"# id: plat\n(assure-ks (tier (* set basic enhanced-basic moderate))(evidence (verified (fido2)(platform (source platform_attested)))))\n")
		c.inst.AttestationSource, c.inst.LastAttestedAt = "platform_attested", time.Now()
		if err := instances.Upsert(context.Background(), c.inst); err != nil {
			t.Fatal(err)
		}
		ctx := context.Background()
		if c.caller != nil {
			ctx = WithKeyAttestationCaller(ctx, *c.caller)
		}
		jwks := []map[string]interface{}{{"kty": "EC", "crv": "P-256", "x": "abc", "y": "def"}}

		// Legacy path.
		if got := svc.keyAttestationTrustsBatch(ctx, "i", jwks); got != c.want {
			t.Errorf("%s: legacy trust = %v, want %v", c.name, got, c.want)
		}
		// Policy path.
		ka, err := svc.GenerateKeyAttestation(ctx, jwks, "n", nil, "i", "")
		if err != nil {
			t.Fatal(err)
		}
		got := parseKAClaims(t, ka)["key_storage"].([]interface{})[0] == "iso_18045_moderate"
		if got != c.want {
			t.Errorf("%s: policy raised = %v, want %v", c.name, got, c.want)
		}
	}
}

// A configured scheme that replaces iso_18045 keeps its own values: an exact
// match of a configured emitted value is never run through the legacy
// normaliser (which would map the unknown string to basic).
func TestAssurance_ReplacedISOSchemeClaimMatchesExactValueBeforeNormalizing(t *testing.T) {
	mut := func(c *config.AssuranceConfig) {
		c.LevelSchemes = config.LevelSchemeList{{ID: "iso_18045", Levels: []string{"low", "top"}, Values: []string{"lowv", "certified"}, Floor: "low"}}
	}
	svc, _, _ := assuranceSvc(t, mut, "# id: all\n(assure-ks (tier top)(evidence))\n")
	ka, err := svc.GenerateKeyAttestation(context.Background(), twoKeys(), "n", &SecurityProperties{KeyStorage: []string{"certified"}}, "", "")
	if err != nil {
		t.Fatal(err)
	}
	assertKeyStorage(t, parseKAClaims(t, ka), "certified")
}

// Suspended and revoked instances keep their AttestationSource but lend no
// platform evidence, on both the legacy and the policy path.
func TestInstanceStatus_DeactivatedInstanceLendsNoEvidence(t *testing.T) {
	for status, want := range map[domain.InstanceStatus]bool{
		domain.InstanceStatusActive:          true,
		"":                                   true, // records predating the field
		domain.InstanceStatusLegacySuspended: false,
		domain.InstanceStatusRevoked:         false,
		"something-new":                      false,
	} {
		svc, instances, _ := assuranceSvc(t, nil,
			"# id: plat\n(assure-ks (tier (* set basic enhanced-basic moderate))(evidence (verified (fido2)(platform (source platform_attested)))))\n")
		if err := instances.Upsert(context.Background(), &domain.WalletInstance{ID: "i", Status: status, AttestationSource: "platform_attested", LastAttestedAt: time.Now()}); err != nil {
			t.Fatal(err)
		}
		jwks := []map[string]interface{}{{"kty": "EC", "crv": "P-256", "x": "abc", "y": "def"}}
		if got := svc.keyAttestationTrustsBatch(context.Background(), "i", jwks); got != want {
			t.Errorf("status %q: legacy trust = %v, want %v", status, got, want)
		}
		ka, err := svc.GenerateKeyAttestation(context.Background(), jwks, "n", nil, "i", "")
		if !status.IsLive() {
			// The lifecycle gate refuses a KA for an instance that is not live
			// (including a record without a status) before any evidence is read.
			if !errors.Is(err, tokengate.ErrRevoked) {
				t.Errorf("status %q: GenerateKeyAttestation = %v, want a refusal", status, err)
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if got := parseKAClaims(t, ka)["key_storage"].([]interface{})[0] == "iso_18045_moderate"; got != want {
			t.Errorf("status %q: policy raised = %v, want %v", status, got, want)
		}
	}
}

// Platform evidence is only as fresh as the last WIA: past the WIA lifetime
// (default 5 minutes) it lends nothing, on both paths. An instance that never
// recorded an attestation time has no evidence at all.
func TestInstanceFreshness_StalePlatformEvidenceLendsNothing(t *testing.T) {
	cases := []struct {
		name     string
		lifetime int
		maxExp   int
		at       time.Time
		want     bool
	}{
		{"just attested", 300, 0, time.Now(), true},
		{"within lifetime", 300, 0, time.Now().Add(-4 * time.Minute), true},
		{"past lifetime", 300, 0, time.Now().Add(-6 * time.Minute), false},
		{"within long lifetime", 3600, 0, time.Now().Add(-30 * time.Minute), true},
		{"lifetime capped by wia max expiry", 3600, 300, time.Now().Add(-10 * time.Minute), false},
		{"within wia max expiry cap", 3600, 300, time.Now().Add(-4 * time.Minute), true},
		{"lifetime unset follows wia max expiry", 0, 120, time.Now().Add(-3 * time.Minute), false},
		{"never recorded", 300, 0, time.Time{}, false},
	}
	for _, c := range cases {
		svc, instances, _ := assuranceSvc(t, nil,
			"# id: plat\n(assure-ks (tier (* set basic enhanced-basic moderate))(evidence (verified (fido2)(platform (source platform_attested)))))\n")
		svc.cfg.WalletProvider.Attestation.LifetimeSeconds = c.lifetime
		svc.cfg.WalletProvider.WIA.MaxExpirySeconds = c.maxExp
		if err := instances.Upsert(context.Background(), &domain.WalletInstance{ID: "i", Status: domain.InstanceStatusActive, AttestationSource: "platform_attested", LastAttestedAt: c.at}); err != nil {
			t.Fatal(err)
		}
		jwks := []map[string]interface{}{{"kty": "EC", "crv": "P-256", "x": "abc", "y": "def"}}
		if got := svc.keyAttestationTrustsBatch(context.Background(), "i", jwks); got != c.want {
			t.Errorf("%s: legacy trust = %v, want %v", c.name, got, c.want)
		}
		ka, err := svc.GenerateKeyAttestation(context.Background(), jwks, "n", nil, "i", "")
		if err != nil {
			t.Fatal(err)
		}
		if got := parseKAClaims(t, ka)["key_storage"].([]interface{})[0] == "iso_18045_moderate"; got != c.want {
			t.Errorf("%s: policy raised = %v, want %v", c.name, got, c.want)
		}
	}
}
