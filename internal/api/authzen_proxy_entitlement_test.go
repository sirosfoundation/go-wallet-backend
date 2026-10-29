package api

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	gotrust "github.com/sirosfoundation/go-trust/pkg/authzen"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
	"github.com/sirosfoundation/go-wallet-backend/pkg/issuermetadata"
	"github.com/sirosfoundation/go-wallet-backend/pkg/issuertrust"
	"github.com/sirosfoundation/go-wallet-backend/pkg/trust"
)

type recordingRegistrarPDP struct {
	decision bool
	actions  []string
}

func (p *recordingRegistrarPDP) Evaluate(_ context.Context, req *gotrust.EvaluationRequest) (*gotrust.EvaluationResponse, error) {
	if req.Action != nil {
		p.actions = append(p.actions, req.Action.Name)
	}
	return &gotrust.EvaluationResponse{Decision: p.decision}, nil
}

func forgedRegistrationCert(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "registrar"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"sub":                   "anyone",
		"entitlements":          []string{"https://uri.etsi.org/19475/Entitlement/PID_Provider"},
		"provides_attestations": []map[string]any{{"format": "dc+sd-jwt"}},
	})
	tok.Header["typ"] = "rc-wrp+jwt"
	tok.Header["x5c"] = []string{base64.StdEncoding.EncodeToString(der)}
	s, err := tok.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// /v1/resolve has the same hole as the engine: the registration certificate's
// signer must be authenticated before its claims are used.
func TestEvaluateIssuerEntitlement_AuthenticatesTheRegistrar(t *testing.T) {
	h := &AuthZENProxyHandler{entitlementMode: "fail", logger: zap.NewNop()}
	result := &issuermetadata.ResolveResult{Signed: true, Metadata: map[string]interface{}{
		"credential_configurations_supported": map[string]interface{}{
			"pid": map[string]interface{}{"format": "dc+sd-jwt", "vct": "urn:eudi:pid:1"},
		},
		"issuer_info": []interface{}{map[string]interface{}{
			"format": issuermetadata.FormatRegistrationCert, "data": forgedRegistrationCert(t),
		}},
	}}
	// Any parseable chain gets past "no access certificate"; it is the
	// registration certificate that is under test.
	km := &trust.KeyMaterial{Type: "x5c", X5C: []string{x5cOf(t, forgedRegistrationCert(t))}}

	untrusted := &recordingRegistrarPDP{decision: false}
	d := h.evaluateIssuerEntitlement(context.Background(), untrusted, "https://issuer.example", result, km, true, []string{"pid"})
	if d == nil || d.Allowed {
		t.Fatalf("a registration certificate from an untrusted registrar was believed: %+v", d)
	}
	found := false
	for _, f := range d.Findings {
		found = found || f.Code == issuertrust.CodeRegistrarNotTrusted
	}
	if !found {
		t.Errorf("findings %+v lack registrar_not_trusted", d.Findings)
	}
	if len(untrusted.actions) != 1 || untrusted.actions[0] != trust.RegistrarAction {
		t.Errorf("PDP actions = %v, want [%s]", untrusted.actions, trust.RegistrarAction)
	}

	// Claims of a certificate nobody authenticated are not used either.
	d = h.evaluateIssuerEntitlement(context.Background(), nil, "https://issuer.example", result, km, true, []string{"pid"})
	if d == nil || d.Allowed || d.Evaluated {
		t.Errorf("with no registrar trust path the claims were used: %+v", d)
	}
}

// x5cOf returns the first x5c entry of a JWT header.
func x5cOf(t *testing.T, token string) string {
	t.Helper()
	parsed, _, err := jwt.NewParser().ParseUnverified(token, jwt.MapClaims{})
	if err != nil {
		t.Fatal(err)
	}
	return parsed.Header["x5c"].([]interface{})[0].(string)
}

// The PDP decision for the metadata signer is what anchors the WRPAC chain; a
// chain nobody trusted must not satisfy the check however good the rest is.
func TestEvaluateIssuerEntitlement_RequiresATrustedChain(t *testing.T) {
	h := &AuthZENProxyHandler{entitlementMode: "fail", logger: zap.NewNop()}
	result := &issuermetadata.ResolveResult{Signed: true, Metadata: map[string]interface{}{}}
	km := &trust.KeyMaterial{Type: "x5c", X5C: []string{x5cOf(t, forgedRegistrationCert(t))}}

	d := h.evaluateIssuerEntitlement(context.Background(), nil, "https://issuer.example", result, km, false, nil)

	if d == nil || d.Allowed {
		t.Fatalf("an untrusted chain passed: %+v", d)
	}
	found := false
	for _, f := range d.Findings {
		found = found || f.Code == issuertrust.CodeAccessCertificateNotTrusted
	}
	if !found {
		t.Errorf("findings %+v lack access_certificate_not_trusted", d.Findings)
	}
}

// --- the /v1/resolve outcome contract ---------------------------------------

func resolveEntitlement(t *testing.T, mode string, signed bool) (int, map[string]interface{}) {
	t.Helper()
	pdp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(gotrust.EvaluationResponse{Decision: true})
	}))
	defer pdp.Close()
	resolver := &mockMetadataResolver{result: &issuermetadata.ResolveResult{
		Signed: signed,
		Metadata: map[string]interface{}{
			"credential_issuer": "https://issuer.example",
			"credential_configurations_supported": map[string]interface{}{
				"pid": map[string]interface{}{"format": "dc+sd-jwt", "vct": "urn:eudi:pid:1"},
			},
		},
	}}
	cfg := &config.AuthZENProxyConfig{Enabled: true, PDPURL: pdp.URL, Timeout: 30, AllowResolution: true, IssuerEntitlementMode: mode}
	h := NewAuthZENProxyHandler(cfg, &mockAuthorizer{allowAll: true}, nil, nil, resolver, http.DefaultClient, http.DefaultClient, zap.NewNop())
	router := gin.New()
	router.Use(func(c *gin.Context) { c.Set("tenant_id", "t"); c.Next() })
	router.POST("/v1/resolve", h.Resolve)
	body, _ := json.Marshal(map[string]interface{}{"subject_id": "https://issuer.example", "subject_type": "url", "credential_types": []string{"pid"}})
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/v1/resolve", strings.NewReader(string(body))))
	var out map[string]interface{}
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

// fail: metadata not signed by a certificate chain is refused, exactly as in
// the engine, with the engine's code and the decision, never an ambiguous
// "nothing to report".
func TestResolve_FailModeRefusesWithTheEngineCode(t *testing.T) {
	code, out := resolveEntitlement(t, "fail", false)
	if code != http.StatusForbidden {
		t.Fatalf("status %d, want 403", code)
	}
	if out["code"] != "ISSUER_NOT_ENTITLED" {
		t.Errorf("code = %v, want ISSUER_NOT_ENTITLED", out["code"])
	}
	ent, _ := out["issuer_entitlement"].(map[string]interface{})
	if ent == nil || ent["allowed"] != false || ent["mode"] != "fail" {
		t.Errorf("issuer_entitlement = %v, want allowed=false mode=fail", ent)
	}
}

// warn: the same findings, status 200, allowed=true: the result is always
// present when the check ran, so its absence can only mean mode off.
func TestResolve_WarnModeReportsFindingsWith200(t *testing.T) {
	code, out := resolveEntitlement(t, "warn", false)
	if code != http.StatusOK {
		t.Fatalf("status %d, want 200", code)
	}
	ent, _ := out["issuer_entitlement"].(map[string]interface{})
	if ent == nil || ent["allowed"] != true || ent["mode"] != "warn" {
		t.Fatalf("issuer_entitlement = %v", ent)
	}
	if f, _ := ent["findings"].([]interface{}); len(f) == 0 {
		t.Error("warn must report the findings")
	}
}

func TestResolve_OffModeOmitsTheResult(t *testing.T) {
	code, out := resolveEntitlement(t, "off", false)
	if code != http.StatusOK {
		t.Fatalf("status %d, want 200", code)
	}
	if _, present := out["issuer_entitlement"]; present {
		t.Error("off must not report a result (absent means not checked)")
	}
}
