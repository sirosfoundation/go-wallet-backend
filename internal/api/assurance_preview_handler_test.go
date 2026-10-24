package api

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/assurance"
	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/service"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage/memory"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

func previewHandlers(t *testing.T, mut func(*config.Config)) (*Handlers, *memory.Store) {
	t.Helper()
	keyPath, certPath := writeSigningFiles(t)
	cfg := &config.Config{JWT: config.JWTConfig{Secret: "s", Issuer: "i"}}
	cfg.WalletProvider.PrivateKeyPath, cfg.WalletProvider.CertificatePath = keyPath, certPath
	if mut != nil {
		mut(cfg)
	}
	store := memory.NewStore()
	services := service.NewServices(store, cfg, zap.NewNop())
	return NewHandlers(services, cfg, zap.NewNop(), []string{"test"}), store
}

func callPreview(h *Handlers, tenant, user, body string) *httptest.ResponseRecorder {
	router := gin.New()
	router.POST("/p", func(c *gin.Context) {
		c.Set("tenant_id", tenant)
		c.Set("user_id", user)
		h.AssurancePreview(c)
	})
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/p", strings.NewReader(body)))
	return w
}

func TestAssurancePreview_DisabledReturnsLegacyValuesAndStoresNothing(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, store := previewHandlers(t, nil)
	w := callPreview(h, "default", "u", `{"security_properties":{"key_storage":["iso_18045_high"]}}`)
	if w.Code != http.StatusOK {
		t.Fatalf("%d: %s", w.Code, w.Body.String())
	}
	var got map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	// Untrusted claim: the legacy clamp.
	if got["key_storage"].([]interface{})[0] != "iso_18045_basic" || got["assurance_enabled"] != false || got["wia_issue"] != true {
		t.Fatalf("%v", got)
	}
	if got["wia_profile"] != "backend_attested" {
		t.Fatalf("wia_profile = %v", got["wia_profile"])
	}
	if list, _ := store.WalletInstances().GetAllByTenant(context.Background(), domain.DefaultTenantID); len(list) != 0 {
		t.Fatalf("preview stored %d instances", len(list))
	}
}

func TestAssurancePreview_EnabledUsesPolicyAndOwnInstanceOnly(t *testing.T) {
	gin.SetMode(gin.TestMode)
	rules := filepath.Join(t.TempDir(), "p.rules")
	if err := os.WriteFile(rules, []byte("# id: issue-all\n(assure-wia-issue (evidence))\n# id: s1\n(assure-wia (profile s1-full-client)(evidence (verified (fido2)(platform (source platform_attested)))))\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	h, store := previewHandlers(t, func(c *config.Config) {
		c.WalletProvider.Attestation.Assurance = config.AssuranceConfig{
			Enabled: true, RulesFile: rules,
			KeyStorageScheme: config.DefaultLevelSchemeID, UserAuthenticationScheme: config.DefaultLevelSchemeID,
			LowerByClaimsKeyStorage: true, LowerByClaimsUserAuthentication: true,
		}
	})
	owner := domain.UserIDFromString("owner")
	if err := store.WalletInstances().Upsert(context.Background(), &domain.WalletInstance{
		ID: "inst", TenantID: "tenant-a", UserID: &owner, AttestationSource: "platform_attested", Status: domain.InstanceStatusActive,
	}); err != nil {
		t.Fatal(err)
	}

	w := callPreview(h, "tenant-a", "owner", `{"wallet_instance_id":"inst"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("%d: %s", w.Code, w.Body.String())
	}
	var got map[string]interface{}
	_ = json.Unmarshal(w.Body.Bytes(), &got)
	if got["wia_profile"] != "platform_attested" || got["assurance_enabled"] != true || got["policy_version"] == "" {
		t.Fatalf("%v", got)
	}
	// Nothing about the rules leaves the backend.
	for k := range got {
		if strings.Contains(strings.ToLower(k), "rule") {
			t.Errorf("response exposes %q", k)
		}
	}
	if strings.Contains(w.Body.String(), "assure-") {
		t.Errorf("response exposes rule text: %s", w.Body.String())
	}

	for name, who := range map[string][2]string{"other user": {"tenant-a", "mallory"}, "other tenant": {"tenant-b", "owner"}} {
		if w := callPreview(h, who[0], who[1], `{"wallet_instance_id":"inst"}`); w.Code != http.StatusNotFound {
			t.Errorf("%s: %d, want 404: %s", name, w.Code, w.Body.String())
		}
	}
}

func TestAssurancePreview_RejectsMalformedInput(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, _ := previewHandlers(t, nil)
	jwks := make([]string, service.MaxJWKSPerRequest+1)
	for i := range jwks {
		jwks[i] = `{"kty":"EC"}`
	}
	cases := map[string]string{
		"not json":            `{`,
		"too many jwks":       `{"jwks":[` + strings.Join(jwks, ",") + `]}`,
		"null jwk":            `{"jwks":[null]}`,
		"bad attestation b64": `{"fido2_attestation":{"attestation_object":"!!","client_data_hash":"AAAA"}}`,
		"empty attestation":   `{"fido2_attestation":{"attestation_object":"","client_data_hash":"AAAA"}}`,
		"oversize attestation": `{"fido2_attestation":{"attestation_object":"` +
			base64.RawURLEncoding.EncodeToString(make([]byte, maxPreviewAttestationBytes+1)) + `","client_data_hash":"AAAA"}}`,
		"bad hash b64": `{"fido2_attestation":{"attestation_object":"AAAA","client_data_hash":"!!"}}`,
	}
	for name, body := range cases {
		if w := callPreview(h, "default", "u", body); w.Code != http.StatusBadRequest {
			t.Errorf("%s: %d, want 400: %s", name, w.Code, w.Body.String())
		}
	}
}

// With FIDO2 verification disabled a submitted attestation is not verified
// and counts for nothing; with it enabled but garbage it is a 400.
func TestAssurancePreview_UnverifiableAttestationIsIgnoredGarbageIsRefused(t *testing.T) {
	gin.SetMode(gin.TestMode)
	body := `{"fido2_attestation":{"attestation_object":"AAAA","client_data_hash":"` + base64.RawURLEncoding.EncodeToString(make([]byte, 32)) + `"}}`

	h, _ := previewHandlers(t, nil)
	w := callPreview(h, "default", "u", body)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"fido2_verified":false`) {
		t.Fatalf("disabled verifier: %d %s", w.Code, w.Body.String())
	}

	h, _ = previewHandlers(t, func(c *config.Config) { c.WalletProvider.Attestation.FIDO2Attestation.Enabled = true })
	if w := callPreview(h, "default", "u", body); w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "ATTESTATION_INVALID") {
		t.Fatalf("garbage attestation: %d %s", w.Code, w.Body.String())
	}
}

// --- WIA refusal mapping ---------------------------------------------------------

func wiaPop(t *testing.T, nonce string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pad := func(b []byte) []byte { return append(make([]byte, 32-len(b)), b...) }
	now := time.Now()
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"iss": "wallet", "nonce": nonce, "iat": now.Unix(), "exp": now.Add(time.Minute).Unix(),
	})
	tok.Header["typ"] = "oauth-client-attestation-pop+jwt"
	tok.Header["jwk"] = map[string]interface{}{
		"kty": "EC", "crv": "P-256",
		"x": base64.RawURLEncoding.EncodeToString(pad(key.PublicKey.X.Bytes())),
		"y": base64.RawURLEncoding.EncodeToString(pad(key.PublicKey.Y.Bytes())),
	}
	s, err := tok.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestWIAGenerate_PolicyRefusalIs403AndUnavailableIs503(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for name, tc := range map[string]struct {
		install  bool
		wantCode int
		wantErr  string
	}{
		"no issue rule":     {true, http.StatusForbidden, "WIA_REFUSED_BY_POLICY"},
		"policy not loaded": {false, http.StatusServiceUnavailable, "ASSURANCE_UNAVAILABLE"},
	} {
		t.Run(name, func(t *testing.T) {
			rules := filepath.Join(t.TempDir(), "p.rules")
			if err := os.WriteFile(rules, nil, 0o600); err != nil { // empty: nothing permits issue
				t.Fatal(err)
			}
			h, _ := previewHandlers(t, func(c *config.Config) {
				c.WalletProvider.WIA = config.WIAConfig{Enabled: true, WalletName: "W", WalletVersion: "1", MaxExpirySeconds: 86400, ChallengeTTLSeconds: 300}
				c.WalletProvider.Attestation.LifetimeSeconds = 300
				c.WalletProvider.Attestation.Assurance = config.AssuranceConfig{
					Enabled: true, RulesFile: rules,
					KeyStorageScheme: config.DefaultLevelSchemeID, UserAuthenticationScheme: config.DefaultLevelSchemeID,
				}
			})
			if h.services.WIA == nil {
				t.Fatal("WIA service not constructed")
			}
			if tc.install {
				a, err := assurance.NewFromConfig(h.cfg.WalletProvider.Attestation.Assurance, zap.NewNop())
				if err != nil {
					t.Fatal(err)
				}
				h.services.WIA.SetAssessor(a)
			} else {
				h.services.WIA.SetAssessor(nil)
			}

			challenge, _, err := h.services.WIA.CreateChallenge(context.Background(), domain.DefaultTenantID)
			if err != nil {
				t.Fatal(err)
			}
			body, _ := json.Marshal(map[string]string{"pop": wiaPop(t, challenge), "challenge": challenge})
			router := gin.New()
			router.POST("/wia", h.WIAGenerate)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/wia", bytes.NewReader(body)))
			if w.Code != tc.wantCode || !strings.Contains(w.Body.String(), tc.wantErr) {
				t.Fatalf("%d: %s", w.Code, w.Body.String())
			}
		})
	}
}
