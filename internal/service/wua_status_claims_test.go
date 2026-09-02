package service

import (
	"context"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

// enableStatusList turns on the WUA status-list claims on a test config
// with the production default maintenance period, so tests exercise the
// same numbers a real deployment gets.
func enableStatusList(cfg *config.Config, uri string) {
	cfg.WalletProvider.Attestation.StatusList = config.StatusListConfig{
		Enabled:                  true,
		URI:                      uri,
		MaintenancePeriodSeconds: config.StatusListDefaultMaintenanceSeconds,
	}
}

// assertStatusListRef checks that claim is a CS-04 §7.1 status reference
// pointing at wantURI/wantIdx, and returns its maintenance exp.
func assertStatusListRef(t *testing.T, claim interface{}, wantURI string, wantIdx int) int64 {
	t.Helper()
	obj, ok := claim.(map[string]interface{})
	if !ok {
		t.Fatalf("status claim = %#v, want an object", claim)
	}
	status, ok := obj["status"].(map[string]interface{})
	if !ok {
		t.Fatalf("status claim missing `status` object: %#v", obj)
	}
	ref, ok := status["status_list"].(map[string]interface{})
	if !ok {
		t.Fatalf("status claim missing `status.status_list`: %#v", status)
	}
	if got := ref["uri"]; got != wantURI {
		t.Errorf("status_list.uri = %v, want %v", got, wantURI)
	}
	// JSON round-trips the index as a float64.
	if got, ok := ref["idx"].(float64); !ok || int(got) != wantIdx {
		t.Errorf("status_list.idx = %v, want %d", ref["idx"], wantIdx)
	}
	exp, ok := obj["exp"].(float64)
	if !ok {
		t.Fatalf("status claim missing numeric `exp`: %#v", obj)
	}
	return int64(exp)
}

// TestGenerateKeyAttestation_KeyStorageStatus is the regression test for
// the WE BUILD ITB failure that PR #261's removal of the claim caused:
// "Key Attestation missing required key_storage_status". CS-04 §7.1.3
// requires it on every KA.
func TestGenerateKeyAttestation_KeyStorageStatus(t *testing.T) {
	svc, _, _ := newTestWalletProviderServiceWithInstances(t)
	enableStatusList(svc.cfg, "")

	jwks := []map[string]interface{}{{"kty": "EC", "crv": "P-256", "x": "abc", "y": "def"}}
	ka, err := svc.GenerateKeyAttestation(context.Background(), jwks, "test-nonce", nil, "untrusted-instance", "")
	if err != nil {
		t.Fatalf("GenerateKeyAttestation: %v", err)
	}
	claims := parseKAClaims(t, ka)

	kss, ok := claims["key_storage_status"]
	if !ok {
		t.Fatal("key_storage_status missing from KA")
	}
	// No explicit URI configured, so it derives from Server.BaseURL. The
	// untrusted floor is iso_18045_basic, hence the basic tier's index.
	exp := assertStatusListRef(t, kss, "https://wp.example.com"+StatusListPath, statusIndexKABasic)

	// The maintenance exp is independent of — and far beyond — the KA's own
	// 15s token exp (CS-04 §7.2's note, TS-03 clause 2.4.1), and leaves more
	// than the 31 days CS-04 §7.2.2 requires at presentation.
	tokenExp, err := claims.GetExpirationTime()
	if err != nil {
		t.Fatal(err)
	}
	if exp <= tokenExp.Unix() {
		t.Errorf("key_storage_status.exp (%d) must be beyond the KA's own exp (%d)", exp, tokenExp.Unix())
	}
	if remaining := time.Until(time.Unix(exp, 0)); remaining < config.StatusListRefMinMaintenanceSeconds*time.Second {
		t.Errorf("key_storage_status.exp leaves %v, want at least 31 days", remaining)
	}
}

// TestGenerateKeyAttestation_KeyStorageStatusDisabled covers the opt-out:
// a deployment that would rather advertise no revocation mechanism than an
// inert one gets no claim at all, not an empty or dangling reference.
func TestGenerateKeyAttestation_KeyStorageStatusDisabled(t *testing.T) {
	svc, _, _ := newTestWalletProviderServiceWithInstances(t)
	// Left at the zero value: disabled.

	jwks := []map[string]interface{}{{"kty": "EC", "crv": "P-256", "x": "abc", "y": "def"}}
	ka, err := svc.GenerateKeyAttestation(context.Background(), jwks, "test-nonce", nil, "instance", "")
	if err != nil {
		t.Fatalf("GenerateKeyAttestation: %v", err)
	}
	if _, ok := parseKAClaims(t, ka)["key_storage_status"]; ok {
		t.Error("key_storage_status emitted while status_list is disabled")
	}
}

// TestGenerateKeyAttestation_KeyStorageStatusNoURI: with the claim enabled
// but no URI derivable (no explicit URI, no BaseURL), emitting a reference
// with an empty/absent uri would be worse than omitting the claim — a
// verifier couldn't tell it was unresolvable until it tried to fetch it.
func TestGenerateKeyAttestation_KeyStorageStatusNoURI(t *testing.T) {
	svc, _, _ := newTestWalletProviderServiceWithInstances(t)
	enableStatusList(svc.cfg, "")
	svc.cfg.Server.BaseURL = ""

	jwks := []map[string]interface{}{{"kty": "EC", "crv": "P-256", "x": "abc", "y": "def"}}
	ka, err := svc.GenerateKeyAttestation(context.Background(), jwks, "test-nonce", nil, "instance", "")
	if err != nil {
		t.Fatalf("GenerateKeyAttestation: %v", err)
	}
	if _, ok := parseKAClaims(t, ka)["key_storage_status"]; ok {
		t.Error("key_storage_status emitted with no resolvable status list URI")
	}
}

// TestGenerateKeyAttestation_KeyStorageStatusExplicitURI covers publishing
// the list somewhere other than this wallet provider's own BaseURL.
func TestGenerateKeyAttestation_KeyStorageStatusExplicitURI(t *testing.T) {
	svc, _, _ := newTestWalletProviderServiceWithInstances(t)
	enableStatusList(svc.cfg, "https://cdn.example.org/wp/ka-status/7")

	jwks := []map[string]interface{}{{"kty": "EC", "crv": "P-256", "x": "abc", "y": "def"}}
	ka, err := svc.GenerateKeyAttestation(context.Background(), jwks, "test-nonce", nil, "instance", "")
	if err != nil {
		t.Fatalf("GenerateKeyAttestation: %v", err)
	}
	assertStatusListRef(t, parseKAClaims(t, ka)["key_storage_status"],
		"https://cdn.example.org/wp/ka-status/7", statusIndexKABasic)
}

// TestKAStatusIndex covers the type-shared index mapping (CS-04 §7.2.3
// Option 1), including that a mixed batch is indexed by its weakest tier.
func TestKAStatusIndex(t *testing.T) {
	tests := []struct {
		name       string
		keyStorage []string
		want       int
	}{
		{"high", []string{"iso_18045_high"}, statusIndexKAHigh},
		{"moderate", []string{"iso_18045_moderate"}, statusIndexKAModerate},
		{"enhanced-basic maps to moderate", []string{"iso_18045_enhanced-basic"}, statusIndexKAModerate},
		{"basic", []string{"iso_18045_basic"}, statusIndexKABasic},
		{"empty falls back to basic", nil, statusIndexKABasic},
		{"unrecognized falls back to basic", []string{"something-else"}, statusIndexKABasic},
		{"mixed uses the weakest tier", []string{"iso_18045_high", "iso_18045_basic"}, statusIndexKABasic},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := kaStatusIndex(tt.keyStorage); got != tt.want {
				t.Errorf("kaStatusIndex(%v) = %d, want %d", tt.keyStorage, got, tt.want)
			}
		})
	}
}

// TestWIAService_ClientStatus covers CS-04 §7.1.2's counterpart requirement
// on the WIA. Emitted here so a conformant PID Provider doesn't reject the
// WIA for the same reason the ITB rejected the KA.
func TestWIAService_ClientStatus(t *testing.T) {
	svc, _ := newTestWIAService(t)
	svc.cfg.Server.BaseURL = "https://wp.example.com/"
	enableStatusList(svc.cfg, "")

	wia, err := svc.signWIA(map[string]interface{}{"kty": "EC"}, "test-jkt", "tenant", nil, "backend_attested", "client-id")
	if err != nil {
		t.Fatalf("signWIA: %v", err)
	}
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	token, _, err := parser.ParseUnverified(wia, jwt.MapClaims{})
	if err != nil {
		t.Fatal(err)
	}
	claims := token.Claims.(jwt.MapClaims)

	cs, ok := claims["client_status"]
	if !ok {
		t.Fatal("client_status missing from WIA")
	}
	// BaseURL's trailing slash must not produce a double slash in the URI.
	assertStatusListRef(t, cs, "https://wp.example.com"+StatusListPath, statusIndexWIA)
}

// TestWIAService_ClientStatusDisabled mirrors the KA opt-out.
func TestWIAService_ClientStatusDisabled(t *testing.T) {
	svc, _ := newTestWIAService(t)
	svc.cfg.Server.BaseURL = "https://wp.example.com"

	wia, err := svc.signWIA(map[string]interface{}{"kty": "EC"}, "test-jkt", "tenant", nil, "backend_attested", "client-id")
	if err != nil {
		t.Fatalf("signWIA: %v", err)
	}
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	token, _, err := parser.ParseUnverified(wia, jwt.MapClaims{})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := token.Claims.(jwt.MapClaims)["client_status"]; ok {
		t.Error("client_status emitted while status_list is disabled")
	}
}

// TestStatusClaimMaintenanceFallback pins the fallback used when a config
// bypassed Validate() (tests, direct struct construction) to the 45-day
// default rather than the 31-day floor. CS-04 §7.2.2's 31 days must remain
// at *presentation*, so falling back to exactly the floor would emit a WUA
// that is out of conformance a second after it is issued.
func TestStatusClaimMaintenanceFallback(t *testing.T) {
	cfg := &config.Config{}
	cfg.Server.BaseURL = "https://wp.example.com"
	cfg.WalletProvider.Attestation.StatusList = config.StatusListConfig{Enabled: true}

	now := time.Now()
	claim := statusClaim(cfg, statusIndexWIA, now)
	if claim == nil {
		t.Fatal("statusClaim returned nil for an enabled, resolvable config")
	}
	want := now.Add(config.StatusListDefaultMaintenanceSeconds * time.Second).Unix()
	if got := claim["exp"]; got != want {
		t.Errorf("exp = %v, want %v (the 45-day default, not the 31-day floor)", got, want)
	}
	if want <= now.Add(config.StatusListRefMinMaintenanceSeconds*time.Second).Unix() {
		t.Error("the fallback leaves no margin above the floor for time between issuance and presentation")
	}
}

// TestStatusListURINilConfig covers the nil-config guard: statusListURI is
// reachable from services constructed directly in tests, where cfg may be
// unset, and must not panic there.
func TestStatusListURINilConfig(t *testing.T) {
	if got := statusListURI(nil); got != "" {
		t.Errorf("statusListURI(nil) = %q, want empty", got)
	}
}

// TestStatusListIndicesFitPublishedList guards the invariant tying the
// referenced indices to the list actually served: a WUA must never point at
// an index beyond the end of the published bitstring, which a verifier
// would treat as an invalid reference.
func TestStatusListIndicesFitPublishedList(t *testing.T) {
	for _, idx := range []int{statusIndexWIA, statusIndexKAHigh, statusIndexKAModerate, statusIndexKABasic} {
		if idx < 0 || idx >= emptyStatusListSize {
			t.Errorf("status index %d is outside the published list of size %d", idx, emptyStatusListSize)
		}
	}
}
