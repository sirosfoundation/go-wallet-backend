package service

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/sirosfoundation/go-siros-set/set"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	"github.com/sirosfoundation/go-wallet-backend/internal/assurance"
	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage/memory"
	"github.com/sirosfoundation/go-wallet-backend/pkg/audit"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
	"github.com/sirosfoundation/go-wallet-backend/pkg/jwk"
)

// --- uv evidence -------------------------------------------------------------

func markAttestedUV(t *testing.T, keys storage.KeyAttestationStore, j map[string]interface{}, aaguid string, uv bool) {
	t.Helper()
	tp, err := jwk.Thumbprint(j)
	if err != nil {
		t.Fatal(err)
	}
	if err := keys.MarkKeyAttested(context.Background(), &domain.KeyAttestationRecord{KeyThumbprint: tp, AAGUID: aaguid, UV: uv, VerifiedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
}

const uvRules = `# id: ua-uv
(assure-ua (tier (* set basic enhanced-basic moderate))(evidence (verified (fido2 (mds3 trusted)(aaguid aa1)(uv present)))))
`

func uaOf(t *testing.T, svc *WalletProviderService, jwks []map[string]interface{}) string {
	t.Helper()
	ka, err := svc.GenerateKeyAttestation(context.Background(), jwks, "n", nil, "", "")
	if err != nil {
		t.Fatal(err)
	}
	return parseKAClaims(t, ka)["user_authentication"].([]interface{})[0].(string)
}

func TestAssurance_UVPresentOnlyWhenEveryRecordHasIt(t *testing.T) {
	jwks := twoKeys()
	cases := []struct {
		name   string
		uv     [2]bool
		single bool
		want   string
	}{
		{"both uv", [2]bool{true, true}, false, "iso_18045_moderate"},
		{"one without uv", [2]bool{true, false}, false, "iso_18045_basic"},
		{"other without uv", [2]bool{false, true}, false, "iso_18045_basic"},
		{"neither", [2]bool{false, false}, false, "iso_18045_basic"},
		{"single key with uv", [2]bool{true, false}, true, "iso_18045_moderate"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			svc, _, keys := assuranceSvc(t, nil, uvRules)
			markAttestedUV(t, keys, jwks[0], "aa1", c.uv[0])
			markAttestedUV(t, keys, jwks[1], "aa1", c.uv[1])
			batch := jwks
			if c.single {
				batch = jwks[:1]
			}
			if got := uaOf(t, svc, batch); got != c.want {
				t.Errorf("user_authentication = %s, want %s", got, c.want)
			}
		})
	}
}

// A record stored before the uv field existed has uv none.
func TestAssurance_RecordWithoutUVReadsAsNone(t *testing.T) {
	jwks := twoKeys()[:1]
	svc, _, keys := assuranceSvc(t, nil, uvRules)
	markAttested(t, keys, jwks[0], "aa1") // helper stores no UV, like an old record
	if got := uaOf(t, svc, jwks); got != "iso_18045_basic" {
		t.Fatalf("user_authentication = %s", got)
	}
}

// --- WIA decisions -----------------------------------------------------------

const wiaIssueAll = "# id: issue-all\n(assure-wia-issue (evidence))\n"

const wiaFullRules = wiaIssueAll + `# id: s1-platform
(assure-wia (profile s1-full-client)(evidence (verified (fido2)(platform (source platform_attested)))))
# id: cert-s1-rule
(assure-wia-cert (name cert-s1)(evidence (verified (fido2)(platform (source platform_attested)))))
`

func wiaAssuranceSvc(t *testing.T, rules string) (*WIAService, storage.WalletInstanceStore) {
	t.Helper()
	svc, instances := newTestWIAServiceWithInstances(t)
	mut := func(c *config.AssuranceConfig) {
		c.WIACertification = config.WIACertificationCatalogueConfig{Entries: config.WIACertificationEntryList{
			{Name: "cert-s1", Information: map[string]interface{}{"scheme": "S1-cert"}},
		}}
	}
	cfg := enabledCfg()
	mut(&cfg)
	svc.cfg.WalletProvider.Attestation.Assurance = cfg
	svc.SetAssessor(newTestAssessor(t, mut, rules))
	return svc, instances
}

func wiaClaims(t *testing.T, tok string) jwt.MapClaims {
	t.Helper()
	token, _, err := jwt.NewParser(jwt.WithoutClaimsValidation()).ParseUnverified(tok, jwt.MapClaims{})
	if err != nil {
		t.Fatal(err)
	}
	return token.Claims.(jwt.MapClaims)
}

func generateWIAFor(t *testing.T, svc *WIAService) (string, error) {
	t.Helper()
	challenge, _, err := svc.CreateChallenge(context.Background(), domain.DefaultTenantID)
	if err != nil {
		t.Fatal(err)
	}
	pop, _ := createTestPop(t, challenge)
	return svc.GenerateWIA(context.Background(), domain.DefaultTenantID, nil, &WIARequest{Pop: pop, Challenge: challenge})
}

func TestWIAAssurance_DisabledAlwaysIssuesAndKeepsVerifiedSource(t *testing.T) {
	svc, _ := newTestWIAService(t)
	// An installed assessor is inert while the policy is disabled.
	svc.SetAssessor(newTestAssessor(t, nil, ""))
	tok, err := generateWIAFor(t, svc)
	if err != nil {
		t.Fatalf("disabled policy must issue: %v", err)
	}
	if got := wiaClaims(t, tok)["attestation_source"]; got != "backend_attested" {
		t.Fatalf("attestation_source = %v", got)
	}
	// development_attested is emitted verbatim without the policy.
	tok, err = svc.signWIA(map[string]interface{}{"kty": "EC"}, "jkt-12345678", "t", nil, wiaAttestation{Source: "development_attested"}, "c")
	if err != nil {
		t.Fatal(err)
	}
	if got := wiaClaims(t, tok)["attestation_source"]; got != "development_attested" {
		t.Fatalf("attestation_source = %v", got)
	}
}

func TestWIAAssurance_RefusedWithoutIssueRule(t *testing.T) {
	svc, instances := wiaAssuranceSvc(t, "")
	_, err := generateWIAFor(t, svc)
	if !errors.Is(err, ErrWIARefusedByPolicy) {
		t.Fatalf("err = %v, want ErrWIARefusedByPolicy", err)
	}
	// A refused request records no wallet instance.
	list, _ := instances.GetAllByTenant(context.Background(), domain.DefaultTenantID)
	if len(list) != 0 {
		t.Fatalf("a refused WIA recorded %d instances", len(list))
	}
}

func TestWIAAssurance_IssueDecidedByEvidence(t *testing.T) {
	// Only natively attested wallets get a WIA; a plain request has none.
	rules := "# id: native-only\n(assure-wia-issue (evidence (verified (fido2)(platform (source platform_attested)))))\n"
	svc, _ := wiaAssuranceSvc(t, rules)
	if _, err := generateWIAFor(t, svc); !errors.Is(err, ErrWIARefusedByPolicy) {
		t.Fatalf("backend-only request must be refused, err = %v", err)
	}
	att := wiaAttestation{Source: "platform_attested", Platform: NativeAttestationAppleAppAttest}
	if err := svc.applyAssurance(context.Background(), "jkt-native-12345", &att); err != nil {
		t.Fatalf("native request must be issued: %v", err)
	}
}

func TestWIAAssurance_EnabledWithoutAssessorFailsClosed(t *testing.T) {
	svc, _ := newTestWIAService(t)
	svc.cfg.WalletProvider.Attestation.Assurance = enabledCfg()
	if _, err := generateWIAFor(t, svc); !errors.Is(err, ErrAssuranceUnavailable) {
		t.Fatalf("err = %v", err)
	}
}

func TestWIAAssurance_ProfileValueAndCertificationInfoAreEmitted(t *testing.T) {
	svc, instances := wiaAssuranceSvc(t, wiaFullRules)
	svc.cfg.WalletProvider.WIA.CertificationInfo = map[string]interface{}{"scheme": "static"}
	ctx := context.Background()

	att := wiaAttestation{Source: "platform_attested", Platform: NativeAttestationAppleAppAttest, AppID: "app"}
	if err := svc.applyAssurance(ctx, "jkt-native-12345", &att); err != nil {
		t.Fatal(err)
	}
	tok, err := svc.signWIA(map[string]interface{}{"kty": "EC"}, "jkt-native-12345", "t", nil, att, "c")
	if err != nil {
		t.Fatal(err)
	}
	c := wiaClaims(t, tok)
	if c["attestation_source"] != "platform_attested" {
		t.Errorf("attestation_source = %v", c["attestation_source"])
	}
	if ci, _ := c["wallet_solution_certification_information"].(map[string]interface{}); ci["scheme"] != "S1-cert" {
		t.Errorf("certification information = %v", c["wallet_solution_certification_information"])
	}
	// The instance keeps the VERIFIED source and the native WSCD type.
	inst, err := instances.GetByID(ctx, "jkt-native-12345")
	if err != nil {
		t.Fatal(err)
	}
	if inst.AttestationSource != "platform_attested" || inst.WSCDType != domain.WSCDTypeNativeIOS {
		t.Errorf("instance = %+v", inst)
	}

	// A development attestation is not S1: the floor profile is emitted, the
	// static certification information stays, the instance records the truth.
	dev := wiaAttestation{Source: "development_attested", Platform: NativeAttestationAppleAppAttest}
	if err := svc.applyAssurance(ctx, "jkt-dev-123456", &dev); err != nil {
		t.Fatal(err)
	}
	tok, err = svc.signWIA(map[string]interface{}{"kty": "EC"}, "jkt-dev-123456", "t", nil, dev, "c")
	if err != nil {
		t.Fatal(err)
	}
	c = wiaClaims(t, tok)
	if c["attestation_source"] != "backend_attested" {
		t.Errorf("development attestation must not be emitted as S1, got %v", c["attestation_source"])
	}
	if ci, _ := c["wallet_solution_certification_information"].(map[string]interface{}); ci["scheme"] != "static" {
		t.Errorf("static certification information expected, got %v", c["wallet_solution_certification_information"])
	}
	inst, _ = instances.GetByID(ctx, "jkt-dev-123456")
	if inst.AttestationSource != "development_attested" {
		t.Errorf("instance source = %q", inst.AttestationSource)
	}
}

func TestWIAAssurance_AuditLineHasRuleIDsAndPolicyHash(t *testing.T) {
	svc, _ := wiaAssuranceSvc(t, wiaFullRules)
	core, logs := observer.New(zap.InfoLevel)
	svc.logger = zap.New(core)
	att := wiaAttestation{Source: "platform_attested", Platform: NativeAttestationGooglePlayInteg}
	if err := svc.applyAssurance(context.Background(), "jkt-native-12345", &att); err != nil {
		t.Fatal(err)
	}
	entries := logs.FilterMessage("wia assurance decision").All()
	if len(entries) != 1 {
		t.Fatalf("audit lines = %d", len(entries))
	}
	f := entries[0].ContextMap()
	if h, _ := f["policy_hash"].(string); len(h) != 64 {
		t.Fatalf("policy_hash = %v", f["policy_hash"])
	}
	if got := strings.Join(toStrings(f["rule_ids"]), ","); got != "issue-all,s1-platform,cert-s1-rule" {
		t.Fatalf("rule_ids = %q", got)
	}
	if f["issue"] != true || f["profile"] != "s1-full-client" || f["verified_source"] != "platform_attested" {
		t.Fatalf("fields: %v", f)
	}
}

// The platform slot of a WIA decision is the source verified in THIS request,
// not what the instance stored from an earlier one.
func TestWIAAssurance_PlatformSlotIsThisRequestsNotStoredState(t *testing.T) {
	svc, instances := wiaAssuranceSvc(t, wiaFullRules)
	ctx := context.Background()
	// The instance previously attested natively...
	if err := instances.Upsert(ctx, &domain.WalletInstance{ID: "jkt-old-123456", AttestationSource: "platform_attested", Status: domain.InstanceStatusActive}); err != nil {
		t.Fatal(err)
	}
	// ...but this request carries no native evidence.
	att := wiaAttestation{Source: "backend_attested"}
	if err := svc.applyAssurance(ctx, "jkt-old-123456", &att); err != nil {
		t.Fatal(err)
	}
	if att.Claim != "backend_attested" {
		t.Fatalf("stored instance state leaked into the WIA decision: claim %q", att.Claim)
	}
}

func TestWSCDTypeFromAttestation(t *testing.T) {
	cases := []struct {
		source   string
		platform NativeAttestationType
		want     domain.WSCDType
	}{
		{"platform_attested", NativeAttestationAppleAppAttest, domain.WSCDTypeNativeIOS},
		{"platform_attested", NativeAttestationGooglePlayInteg, domain.WSCDTypeNativeAndroid},
		// A development attestation may have bypassed chain verification, so
		// it proves no Secure Enclave: the conservative type.
		{"development_attested", NativeAttestationAppleAppAttest, domain.WSCDTypeWebCrypto},
		{"backend_attested", "", domain.WSCDTypeWebCrypto},
		{"backend_attested", NativeAttestationAppleAppAttest, domain.WSCDTypeWebCrypto},
		{"platform_attested", "", domain.WSCDTypeWebCrypto},
		// The names the old code switched on are not sources anything stores.
		{"ios_app_attest", NativeAttestationAppleAppAttest, domain.WSCDTypeWebCrypto},
		{"android_play_integrity", NativeAttestationGooglePlayInteg, domain.WSCDTypeWebCrypto},
	}
	for _, c := range cases {
		if got := wscdTypeFromAttestation(c.source, c.platform); got != c.want {
			t.Errorf("(%q, %q) = %q, want %q", c.source, c.platform, got, c.want)
		}
	}
}

// The recorded instance of a natively attested WIA is native, not web_crypto
// (the dead-name bug classified every native instance web_crypto).
func TestSignWIA_RecordsNativeWSCDType(t *testing.T) {
	svc, instances := newTestWIAServiceWithInstances(t)
	for jkt, att := range map[string]wiaAttestation{
		"jkt-ios-1234567":     {Source: "platform_attested", Platform: NativeAttestationAppleAppAttest},
		"jkt-android-123456":  {Source: "platform_attested", Platform: NativeAttestationGooglePlayInteg},
		"jkt-web-12345678901": {Source: "backend_attested"},
	} {
		if _, err := svc.signWIA(map[string]interface{}{"kty": "EC"}, jkt, "t", nil, att, "c"); err != nil {
			t.Fatal(err)
		}
	}
	want := map[string]domain.WSCDType{
		"jkt-ios-1234567": domain.WSCDTypeNativeIOS, "jkt-android-123456": domain.WSCDTypeNativeAndroid, "jkt-web-12345678901": domain.WSCDTypeWebCrypto,
	}
	for jkt, w := range want {
		inst, err := instances.GetByID(context.Background(), jkt)
		if err != nil {
			t.Fatal(err)
		}
		if inst.WSCDType != w {
			t.Errorf("%s: WSCDType = %q, want %q", jkt, inst.WSCDType, w)
		}
	}
}

// --- preview -----------------------------------------------------------------

const previewRules = `# id: fido-ks
(assure-ks (tier (* set basic enhanced-basic moderate))(evidence (verified (fido2 (mds3 trusted)(aaguid aa1)))))
# id: ua-uv
(assure-ua (tier (* set basic enhanced-basic moderate))(evidence (verified (fido2 (mds3 trusted)(aaguid aa1)(uv present)))))
# id: issue-all
(assure-wia-issue (evidence))
# id: s1-platform
(assure-wia (profile s1-full-client)(evidence (verified (fido2)(platform (source platform_attested)))))
`

func previewSvc(t *testing.T, rules string, trusted bool) (*WalletProviderService, storage.WalletInstanceStore, storage.KeyAttestationStore) {
	t.Helper()
	svc, instances, keys := assuranceSvc(t, nil, rules)
	fcfg := &config.Config{}
	fcfg.WalletProvider.Attestation.FIDO2Attestation.Enabled = true
	svc.SetFIDO2Verifier(NewFIDO2AttestationService(fcfg, instances, keys, newTestTrustService(t, &stubEvaluator{decision: trusted}), zap.NewNop()))
	return svc, instances, keys
}

func fido2Submission(t *testing.T, aaguid uuid.UUID, flags byte) (*FIDO2AttestationRequest, string) {
	t.Helper()
	hash := make([]byte, 32)
	obj, pub := buildTestAttestationObjectFlags(t, aaguid, hash, flags)
	return &FIDO2AttestationRequest{AttestationObject: obj, ClientDataHash: hash}, expectedThumbprint(t, pub)
}

func TestPreview_FIDO2VerifiedInDryRunAndNothingPersisted(t *testing.T) {
	svc, instances, keys := previewSvc(t, strings.ReplaceAll(previewRules, "aa1", "00000000-0000-0000-0000-0000000000aa"), true)
	aaguid := uuid.MustParse("00000000-0000-0000-0000-0000000000aa")

	withUV, tp := fido2Submission(t, aaguid, 0x40|0x04|0x01)
	got, err := svc.PreviewAssurance(context.Background(), &AssurancePreviewRequest{FIDO2: withUV})
	if err != nil {
		t.Fatal(err)
	}
	if !got.FIDO2Verified || got.KeyStorage[0] != "iso_18045_moderate" || got.UserAuthentication[0] != "iso_18045_moderate" {
		t.Fatalf("%+v", got)
	}
	if got.PolicyVersion == "" || got.SchemaVersion != assurance.SchemaVersion || !got.AssuranceEnabled {
		t.Fatalf("%+v", got)
	}
	if got.WIAProfile != "backend_attested" || !got.WIAIssue {
		t.Fatalf("a WIA request carries no FIDO2 evidence: %+v", got)
	}

	// Without UV the authenticator did not verify the user.
	noUV, _ := fido2Submission(t, aaguid, 0x40|0x01)
	got, err = svc.PreviewAssurance(context.Background(), &AssurancePreviewRequest{FIDO2: noUV})
	if err != nil {
		t.Fatal(err)
	}
	if got.KeyStorage[0] != "iso_18045_moderate" || got.UserAuthentication[0] != "iso_18045_basic" {
		t.Fatalf("%+v", got)
	}

	// Dry run: nothing stored, no instance created.
	if _, err := keys.GetByKeyThumbprint(context.Background(), tp); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("preview persisted a key attestation record: %v", err)
	}
	if list, _ := instances.GetAllByTenant(context.Background(), domain.DefaultTenantID); len(list) != 0 {
		t.Fatalf("preview created %d instances", len(list))
	}
}

func TestPreview_UntrustedOrInvalidAttestationIsAnError(t *testing.T) {
	svc, _, _ := previewSvc(t, previewRules, false)
	sub, _ := fido2Submission(t, uuid.New(), 0x40|0x04)
	if _, err := svc.PreviewAssurance(context.Background(), &AssurancePreviewRequest{FIDO2: sub}); !errors.Is(err, ErrFIDO2AttestationInvalid) {
		t.Fatalf("err = %v", err)
	}
}

// A submission this backend cannot verify counts for nothing.
func TestPreview_UnverifiableFIDO2CountsOnlyAsClaimed(t *testing.T) {
	svc, _, _ := assuranceSvc(t, nil, previewRules) // no verifier installed
	sub, _ := fido2Submission(t, uuid.New(), 0x40|0x04)
	got, err := svc.PreviewAssurance(context.Background(), &AssurancePreviewRequest{
		FIDO2:              sub,
		SecurityProperties: &SecurityProperties{KeyStorage: []string{"iso_18045_high"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.FIDO2Verified || got.KeyStorage[0] != "iso_18045_basic" {
		t.Fatalf("%+v", got)
	}
}

func TestPreview_UsesTheCallersOwnInstanceOnly(t *testing.T) {
	svc, instances, _ := previewSvc(t, previewRules, true)
	owner := domain.UserIDFromString("owner")
	if err := instances.Upsert(context.Background(), &domain.WalletInstance{
		ID: "inst", TenantID: "t1", UserID: &owner, AttestationSource: "platform_attested", Status: domain.InstanceStatusActive,
	}); err != nil {
		t.Fatal(err)
	}
	ownerCtx := WithKeyAttestationCaller(context.Background(), KeyAttestationCaller{TenantID: "t1", UserID: "owner"})
	got, err := svc.PreviewAssurance(ownerCtx, &AssurancePreviewRequest{WalletInstanceID: "inst"})
	if err != nil {
		t.Fatal(err)
	}
	if got.WIAProfile != "platform_attested" {
		t.Fatalf("owner's platform evidence not used: %+v", got)
	}

	for name, caller := range map[string]KeyAttestationCaller{
		"other user":   {TenantID: "t1", UserID: "mallory"},
		"other tenant": {TenantID: "t2", UserID: "owner"},
	} {
		_, err := svc.PreviewAssurance(WithKeyAttestationCaller(context.Background(), caller), &AssurancePreviewRequest{WalletInstanceID: "inst"})
		if !errors.Is(err, storage.ErrNotFound) {
			t.Errorf("%s: err = %v, want ErrNotFound (a foreign instance must be indistinguishable from an unknown one)", name, err)
		}
	}
	if _, err := svc.PreviewAssurance(ownerCtx, &AssurancePreviewRequest{WalletInstanceID: "does-not-exist"}); !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("unknown instance: err = %v", err)
	}
}

func TestPreview_MatchesTheRealKeyAttestationOnTheSameFacts(t *testing.T) {
	jwks := twoKeys()
	svc, _, keys := previewSvc(t, previewRules, true)
	markAttestedUV(t, keys, jwks[0], "aa1", true)
	markAttestedUV(t, keys, jwks[1], "aa1", true)
	sp := &SecurityProperties{KeyStorage: []string{"iso_18045_high"}, UserAuthentication: []string{"iso_18045_high"}}

	pv, err := svc.PreviewAssurance(context.Background(), &AssurancePreviewRequest{JWKS: jwks, SecurityProperties: sp})
	if err != nil {
		t.Fatal(err)
	}
	ka, err := svc.GenerateKeyAttestation(context.Background(), jwks, "n", sp, "", "")
	if err != nil {
		t.Fatal(err)
	}
	c := parseKAClaims(t, ka)
	if c["key_storage"].([]interface{})[0] != pv.KeyStorage[0] || c["user_authentication"].([]interface{})[0] != pv.UserAuthentication[0] {
		t.Fatalf("preview %+v disagrees with the real KA %v", pv, c)
	}
}

func TestPreview_DisabledReturnsTheLegacyResult(t *testing.T) {
	svc, instances, _ := newTestWalletProviderServiceWithInstances(t)
	svc.SetAssessor(newTestAssessor(t, nil, previewRules)) // inert while disabled
	if err := instances.Upsert(context.Background(), &domain.WalletInstance{ID: "n", AttestationSource: "platform_attested", Status: domain.InstanceStatusActive}); err != nil {
		t.Fatal(err)
	}
	jwks := []map[string]interface{}{{"kty": "EC", "crv": "P-256", "x": "abc", "y": "def"}}
	sp := &SecurityProperties{KeyStorage: []string{"iso_18045_high"}}

	got, err := svc.PreviewAssurance(context.Background(), &AssurancePreviewRequest{WalletInstanceID: "n", JWKS: jwks, SecurityProperties: sp})
	if err != nil {
		t.Fatal(err)
	}
	if got.AssuranceEnabled || got.PolicyVersion != "" || got.SchemaVersion != 0 || !got.WIAIssue {
		t.Fatalf("%+v", got)
	}
	ka, err := svc.GenerateKeyAttestation(context.Background(), jwks, "n", sp, "n", "")
	if err != nil {
		t.Fatal(err)
	}
	if want := parseKAClaims(t, ka)["key_storage"].([]interface{})[0]; got.KeyStorage[0] != want || want != "iso_18045_high" {
		t.Fatalf("preview %v vs real %v", got.KeyStorage, want)
	}
	if got.WIAProfile != "platform_attested" {
		t.Fatalf("legacy WIA source = %q", got.WIAProfile)
	}
	// No claims, no trust: the legacy floor.
	got, _ = svc.PreviewAssurance(context.Background(), &AssurancePreviewRequest{})
	if got.KeyStorage[0] != "iso_18045_basic" || got.WIAProfile != "backend_attested" {
		t.Fatalf("%+v", got)
	}
}

func TestPreview_EnabledWithoutAssessorFailsClosed(t *testing.T) {
	svc, _, _ := newTestWalletProviderServiceWithInstances(t)
	svc.cfg.WalletProvider.Attestation.Assurance = enabledCfg()
	if _, err := svc.PreviewAssurance(context.Background(), &AssurancePreviewRequest{}); !errors.Is(err, ErrAssuranceUnavailable) {
		t.Fatalf("err = %v", err)
	}
}

var _ = memory.NewStore

// --- review follow-ups ---------------------------------------------------------

func capturingAuditor(t *testing.T) (*audit.Emitter, *bytes.Buffer) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := set.NewSigner(key, jose.ES256, "k")
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	return audit.New("https://wallet.example", signer, slog.New(slog.NewJSONHandler(&buf, nil))), &buf
}

// auditPayload decodes the payload of the last emitted SET.
func auditPayload(t *testing.T, buf *bytes.Buffer) string {
	t.Helper()
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	var rec struct {
		JWS string `json:"jws"`
	}
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &rec); err != nil {
		t.Fatalf("no audit record: %v (%q)", err, buf.String())
	}
	parts := strings.Split(rec.JWS, ".")
	if len(parts) != 3 {
		t.Fatalf("bad JWS %q", rec.JWS)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	return string(payload)
}

func TestWIAAssurance_IssuedAuditEventCarriesDecisionAndVerifiedSource(t *testing.T) {
	svc, _ := wiaAssuranceSvc(t, wiaFullRules)
	auditor, buf := capturingAuditor(t)
	svc.audit = auditor

	// development_attested is emitted as the floor profile; the event must
	// still say what was verified.
	att := wiaAttestation{Source: "development_attested", Platform: NativeAttestationAppleAppAttest}
	if err := svc.applyAssurance(context.Background(), "jkt-dev-123456", &att); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.signWIA(map[string]interface{}{"kty": "EC"}, "jkt-dev-123456", "t", nil, att, "c"); err != nil {
		t.Fatal(err)
	}
	p := auditPayload(t, buf)
	for _, want := range []string{
		`"attestation_source":"backend_attested"`,
		`"verified_attestation_source":"development_attested"`,
		`"assurance_profile":"s3-backend-only"`,
		`"assurance_rule_ids":["issue-all"]`,
		`"assurance_policy_hash":"`,
	} {
		if !strings.Contains(p, want) {
			t.Errorf("audit payload lacks %s: %s", want, p)
		}
	}
}

func TestWIAAssurance_DisabledAuditEventIsUnchanged(t *testing.T) {
	svc, _ := newTestWIAService(t)
	auditor, buf := capturingAuditor(t)
	svc.audit = auditor
	if _, err := svc.signWIA(map[string]interface{}{"kty": "EC"}, "jkt-12345678", "t", nil, wiaAttestation{Source: "development_attested"}, "c"); err != nil {
		t.Fatal(err)
	}
	p := auditPayload(t, buf)
	if !strings.Contains(p, `"attestation_source":"development_attested"`) || strings.Contains(p, "assurance_") || strings.Contains(p, "verified_attestation_source") {
		t.Fatalf("disabled event changed: %s", p)
	}
}

// Re-attestation updates the recorded WSCD type (the stores used to keep the
// first value, so an instance first seen without native evidence stayed
// web_crypto for good).
func TestSignWIA_ReattestationUpdatesWSCDTypeAndVerifiedAppID(t *testing.T) {
	svc, instances := newTestWIAServiceWithInstances(t)
	const jkt = "jkt-reattest-123456"
	cnf := map[string]interface{}{"kty": "EC"}
	if _, err := svc.signWIA(cnf, jkt, "t", nil, wiaAttestation{Source: "backend_attested"}, "c"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.signWIA(cnf, jkt, "t", nil, wiaAttestation{Source: "platform_attested", Platform: NativeAttestationGooglePlayInteg, AppID: "org.example.app"}, "c"); err != nil {
		t.Fatal(err)
	}
	inst, err := instances.GetByID(context.Background(), jkt)
	if err != nil {
		t.Fatal(err)
	}
	if inst.WSCDType != domain.WSCDTypeNativeAndroid || inst.VerifiedAppID != "org.example.app" || inst.AttestationSource != "platform_attested" {
		t.Fatalf("%+v", inst)
	}
}

// The verified app id (not the client-reported DeviceInfo.AppID) is evidence,
// for the key attestation, the WIA preview and the real WIA alike.
func TestAssurance_VerifiedAppIDIsEvidenceEverywhere(t *testing.T) {
	rules := `# id: app-ks
(assure-ks (tier (* set basic enhanced-basic moderate))(evidence (verified (fido2)(platform (source platform_attested)(app_id org.example.app)))))
# id: issue-all
(assure-wia-issue (evidence))
# id: app-wia
(assure-wia (profile s1-full-client)(evidence (verified (fido2)(platform (source platform_attested)(app_id org.example.app)))))
`
	svc, instances, _ := previewSvc(t, rules, true)
	put := func(id, verified, reported string) {
		t.Helper()
		if err := instances.Upsert(context.Background(), &domain.WalletInstance{
			ID: id, Status: domain.InstanceStatusActive, AttestationSource: "platform_attested", VerifiedAppID: verified,
			DeviceInfo: &domain.DeviceInfo{AppID: reported},
		}); err != nil {
			t.Fatal(err)
		}
	}
	put("good", "org.example.app", "")
	put("liar", "", "org.example.app") // only the client says so

	jwks := twoKeys()
	for id, want := range map[string]string{"good": "iso_18045_moderate", "liar": "iso_18045_basic"} {
		ka, err := svc.GenerateKeyAttestation(context.Background(), jwks, "n", nil, id, "")
		if err != nil {
			t.Fatal(err)
		}
		if got := parseKAClaims(t, ka)["key_storage"].([]interface{})[0]; got != want {
			t.Errorf("KA %s: key_storage = %v, want %s", id, got, want)
		}
		pv, err := svc.PreviewAssurance(context.Background(), &AssurancePreviewRequest{WalletInstanceID: id, JWKS: jwks})
		if err != nil {
			t.Fatal(err)
		}
		wantProfile := map[string]string{"good": "platform_attested", "liar": "backend_attested"}[id]
		if pv.KeyStorage[0] != want || pv.WIAProfile != wantProfile {
			t.Errorf("preview %s: %+v, want ks %s profile %s", id, pv, want, wantProfile)
		}
	}
}
