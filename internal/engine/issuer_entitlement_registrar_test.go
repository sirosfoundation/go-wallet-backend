package engine

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
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
	"github.com/sirosfoundation/go-wallet-backend/pkg/issuermetadata"
	"github.com/sirosfoundation/go-wallet-backend/pkg/issuertrust"
	"github.com/sirosfoundation/go-wallet-backend/pkg/trust"
)

// registrarPDP records the evaluation requests it sees and answers as told.
type registrarPDP struct {
	mu       sync.Mutex
	actions  []string
	decision bool
	failed   bool
}

func (p *registrarPDP) Evaluate(_ context.Context, req *trust.EvaluationRequest) (*trust.EvaluationResponse, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.actions = append(p.actions, req.Action)
	return &trust.EvaluationResponse{Decision: p.decision, Failed: p.failed}, nil
}
func (p *registrarPDP) Name() string { return "registrar-pdp" }
func (p *registrarPDP) SupportedResourceTypes() []trust.ResourceType {
	return []trust.ResourceType{trust.ResourceTypeX5C}
}
func (p *registrarPDP) Healthy() bool { return true }

// signedRegistrationCert is a WRPRC really signed by a fresh registrar key.
// claims are what the (here: forging) provider wrote into it.
func signedRegistrationCert(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(9), Subject: pkix.Name{CommonName: "registrar"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	tok.Header["typ"] = "rc-wrp+jwt"
	tok.Header["x5c"] = []string{base64.StdEncoding.EncodeToString(der)}
	s, err := tok.SignedString(key)
	require.NoError(t, err)
	return s
}

func newRegistrarHandler(t *testing.T, mode string, pdp *registrarPDP) (*OID4VCIHandler, chan map[string]interface{}) {
	t.Helper()
	sent := make(chan map[string]interface{}, 16)
	conn, cleanup := wsTestServer(t, func(srv *websocket.Conn) {
		defer srv.Close()
		for {
			_, raw, err := srv.ReadMessage()
			if err != nil {
				return
			}
			var m map[string]interface{}
			if json.Unmarshal(raw, &m) == nil {
				sent <- m
			}
		}
	})
	t.Cleanup(cleanup)
	cfg := &config.Config{Trust: config.TrustConfig{IssuerEntitlementMode: mode}}
	var svc *TrustService
	if pdp != nil {
		cfg.Trust.PDPURL = "http://pdp.test"
		svc = trust.NewService(cfg, zap.NewNop(),
			func(string, time.Duration) (trust.TrustEvaluator, error) { return pdp, nil })
	}
	session := testSession(conn)
	h := &OID4VCIHandler{}
	h.BaseHandler = BaseHandler{
		Flow:     &Flow{ID: "flow-reg", Session: session, Data: map[string]interface{}{}},
		Logger:   zap.NewNop(),
		Config:   cfg,
		TrustSvc: svc,
	}
	return h, sent
}

func forgedMeta(t *testing.T, claims jwt.MapClaims) *metadataResult {
	return metaOf(t, metaWithIssuerInfo(signedRegistrationCert(t, claims)), selfSignedX5C(t))
}

var forgedClaims = jwt.MapClaims{
	"sub":                   "anyone",
	"entitlements":          []string{"https://uri.etsi.org/19475/Entitlement/PID_Provider"},
	"provides_attestations": []map[string]any{{"format": "dc+sd-jwt", "meta": map[string]any{"vct_values": []string{"urn:eudi:pid:1"}}}},
}

// The hole: the registration certificate was parsed without authenticating its
// signer, so a provider could register itself. Without a trusted Registrar
// the claims must not be believed, and the PDP is asked with the dedicated
// action.
func TestRegistrarTrust_AsksThePDPAboutTheRegistrarKey(t *testing.T) {
	km := &trust.KeyMaterial{Type: "x5c", X5C: []string{"AAAA"}}
	ctx := context.Background()

	t.Run("trusted registrar", func(t *testing.T) {
		pdp := &registrarPDP{decision: true}
		h, _ := newRegistrarHandler(t, "fail", pdp)
		ok, err := h.registrarTrust("https://issuer.example")(ctx, km)
		assert.NoError(t, err)
		assert.True(t, ok)
		assert.Equal(t, []string{trust.RegistrarAction}, pdp.actions)
	})
	t.Run("untrusted registrar", func(t *testing.T) {
		h, _ := newRegistrarHandler(t, "fail", &registrarPDP{decision: false})
		ok, err := h.registrarTrust("https://issuer.example")(ctx, km)
		assert.NoError(t, err)
		assert.False(t, ok)
	})
	t.Run("pdp failure is an error, not a pass", func(t *testing.T) {
		h, _ := newRegistrarHandler(t, "fail", &registrarPDP{decision: true, failed: true})
		ok, err := h.registrarTrust("https://issuer.example")(ctx, km)
		assert.Error(t, err)
		assert.False(t, ok)
	})
	t.Run("no pdp configured: no trust path", func(t *testing.T) {
		h, _ := newRegistrarHandler(t, "fail", nil)
		assert.Nil(t, h.registrarTrust("https://issuer.example"))
	})
}

func TestCheckIssuerEntitlement_FailModeRefusesAnUntrustedRegistrar(t *testing.T) {
	h, _ := newRegistrarHandler(t, "fail", &registrarPDP{decision: false})
	offer := &CredentialOffer{CredentialIssuer: "https://issuer.example", CredentialConfigurationIDs: []string{"pid"}}

	_, err := h.checkIssuerEntitlement(context.Background(), offer.CredentialIssuer, forgedMeta(t, forgedClaims), offer)

	require.ErrorIs(t, err, errIssuerNotEntitled)
	assert.Contains(t, err.Error(), string(issuertrust.CodeRegistrarNotTrusted))
	assert.NotContains(t, err.Error(), "anyone", "claims of the forged certificate are not echoed")
}

// What the client is told: additive to the trust report, bounded, no
// certificate content, and never mistakable for a trust decision.
func TestCheckIssuerEntitlement_ProgressPayloadShape(t *testing.T) {
	h, sent := newRegistrarHandler(t, "warn", &registrarPDP{decision: false})
	offer := &CredentialOffer{CredentialIssuer: "https://issuer.example", CredentialConfigurationIDs: []string{"pid"}}

	_, err := h.checkIssuerEntitlement(context.Background(), offer.CredentialIssuer, forgedMeta(t, forgedClaims), offer)
	require.NoError(t, err)

	var msg map[string]interface{}
	select {
	case msg = <-sent:
	case <-time.After(2 * time.Second):
		t.Fatal("no progress message was sent")
	}
	assert.Equal(t, string(StepTrustEvaluated), msg["step"])
	payload, ok := msg["payload"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, true, payload["issuer_entitlement_evaluated"])
	assert.NotContains(t, payload, "issuer_trust_evaluated", "SDKs key their trust report on this; it must stay absent")
	assert.NotContains(t, payload, "trusted")
	ent, ok := payload["issuer_entitlement"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, true, ent["allowed"])
	assert.Equal(t, "warn", ent["mode"])
	assert.NotContains(t, ent, "entitlements")
	assert.NotContains(t, ent, "subject")
	findings, _ := ent["findings"].([]interface{})
	require.NotEmpty(t, findings)
	var codes []interface{}
	for _, raw := range findings {
		f := raw.(map[string]interface{})
		assert.NotEmpty(t, f["message"])
		codes = append(codes, f["code"])
	}
	assert.Contains(t, codes, string(issuertrust.CodeRegistrarNotTrusted))
	raw, _ := json.Marshal(payload)
	assert.NotContains(t, string(raw), "anyone")
}

// The registration certificate's own content (entitlement URIs, subject) is
// issuer-controlled and display-only: it is in the decision /v1/resolve
// returns, but not in what the engine sends as flow progress.
func TestCheckIssuerEntitlement_ProgressOmitsRegistrationCertificateContent(t *testing.T) {
	h, sent := newRegistrarHandler(t, "warn", &registrarPDP{decision: true})
	offer := &CredentialOffer{CredentialIssuer: "https://issuer.example", CredentialConfigurationIDs: []string{"pid"}}
	meta := forgedMeta(t, forgedClaims)

	full := entitlementFor(context.Background(), issuertrust.ModeWarn, meta, offer.CredentialConfigurationIDs, trustingRegistrar, true)
	require.NotEmpty(t, full.Entitlements, "precondition: the verified certificate's content is in the decision")

	_, err := h.checkIssuerEntitlement(context.Background(), offer.CredentialIssuer, meta, offer)
	require.NoError(t, err)
	msg := <-sent
	raw, _ := json.Marshal(msg["payload"])
	assert.NotContains(t, string(raw), "anyone")
	assert.NotContains(t, string(raw), "PID_Provider")
	assert.NotContains(t, string(raw), `"entitlements"`)
}

// An unknown mode value is warn, not off: the check runs.
func TestCheckIssuerEntitlement_UnknownModeStillChecks(t *testing.T) {
	h, sent := newRegistrarHandler(t, "FAIL ", &registrarPDP{decision: false})
	offer := &CredentialOffer{CredentialIssuer: "https://issuer.example", CredentialConfigurationIDs: []string{"pid"}}
	_, err := h.checkIssuerEntitlement(context.Background(), offer.CredentialIssuer, forgedMeta(t, forgedClaims), offer)
	require.NoError(t, err)
	select {
	case <-sent:
	case <-time.After(2 * time.Second):
		t.Fatal("unknown mode skipped the check")
	}
}

// --- the call site in Execute ------------------------------------------------

type executeFixture struct {
	h    *OID4VCIHandler
	sent chan map[string]interface{}
	msg  *FlowStartMessage
}

// newExecuteFixture wires Execute up as far as the entitlement call site: a
// trusting issuer PDP (so the trust step passes), a resolver returning
// metadata signed by an x5c chain that is not a WRPAC, and a two-configuration
// offer (so the flow would stop at credential selection if it got that far).
func newExecuteFixture(t *testing.T, mode string) *executeFixture {
	t.Helper()
	h, sent := newRegistrarHandler(t, mode, &registrarPDP{decision: true})
	h.Flow = registerTestFlow(h.Flow.Session, "flow-exec")
	raw := map[string]interface{}{
		"credential_issuer":   "https://issuer.example",
		"credential_endpoint": "https://issuer.example/credential",
		"credential_configurations_supported": map[string]interface{}{
			"pid": map[string]interface{}{"format": "dc+sd-jwt", "vct": "urn:eudi:pid:1"},
			"mdl": map[string]interface{}{"format": "dc+sd-jwt", "vct": "urn:eudi:mdl:1"},
		},
	}
	h.metadataResolver = fakeMetadataResolver{result: &issuermetadata.ResolveResult{
		Metadata:          raw,
		Signed:            true,
		Validated:         true,
		SignerKeyMaterial: &issuermetadata.SignerKeyMaterial{Type: "x5c", X5C: []string{selfSignedX5C(t)}},
	}}
	return &executeFixture{h: h, sent: sent, msg: &FlowStartMessage{
		Offer: `{"credential_issuer":"https://issuer.example","credential_configuration_ids":["pid","mdl"]}`,
	}}
}

func drain(sent chan map[string]interface{}) (steps []string, errCodes []string) {
	for {
		select {
		case m := <-sent:
			if step, _ := m["step"].(string); step != "" {
				steps = append(steps, step)
			}
			if m["type"] == "flow_error" {
				if code, _ := m["code"].(string); code != "" {
					errCodes = append(errCodes, code)
				} else if e, ok := m["error"].(map[string]interface{}); ok {
					code, _ := e["code"].(string)
					errCodes = append(errCodes, code)
				}
			}
		case <-time.After(200 * time.Millisecond):
			return
		}
	}
}

func TestExecute_FailModeBlocksBeforeSelection(t *testing.T) {
	f := newExecuteFixture(t, "fail")
	// Bounded, so that without the call site this fails fast at selection
	// instead of waiting out the interaction timeout.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err := f.h.Execute(ctx, f.msg)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "not registered to issue", "refused by the entitlement check, not by the timeout")
	msgs := drainAll(f.sent)
	var steps []string
	var flowErr map[string]interface{}
	for _, m := range msgs {
		if st, _ := m["step"].(string); st != "" {
			steps = append(steps, st)
		}
		if m["type"] == "flow_error" {
			flowErr, _ = m["error"].(map[string]interface{})
		}
	}
	assert.NotContains(t, steps, string(StepAwaitingSelection), "the flow must not reach selection")

	// The wire contract (docs/websocket-protocol-spec.md): a distinct code, the
	// fixed message, and details with the issuer and the bounded decision.
	require.NotNil(t, flowErr, "no flow_error was sent")
	assert.Equal(t, "ISSUER_NOT_ENTITLED", flowErr["code"])
	assert.Equal(t, ErrCodeIssuerNotEntitled.UserFacingMessage(), flowErr["message"])
	details, _ := flowErr["details"].(map[string]interface{})
	require.NotNil(t, details)
	assert.Equal(t, "https://issuer.example", details["issuer"])
	ent, _ := details["issuer_entitlement"].(map[string]interface{})
	require.NotNil(t, ent)
	assert.Equal(t, false, ent["allowed"])
	assert.Equal(t, "fail", ent["mode"])
	assert.NotEmpty(t, ent["findings"])
	assert.NotContains(t, ent, "entitlements")
	assert.NotContains(t, ent, "subject")
}

// A trust-decision refusal keeps its own code: UNTRUSTED_ISSUER is not
// "not registered".
func TestExecute_UntrustedIssuerKeepsItsCode(t *testing.T) {
	f := newExecuteFixture(t, "fail")
	f.h.TrustSvc = trust.NewService(f.h.Config, zap.NewNop(),
		func(string, time.Duration) (trust.TrustEvaluator, error) { return &registrarPDP{decision: false}, nil })

	require.Error(t, f.h.Execute(context.Background(), f.msg))

	var code string
	for _, m := range drainAll(f.sent) {
		if m["type"] == "flow_error" {
			e, _ := m["error"].(map[string]interface{})
			code, _ = e["code"].(string)
		}
	}
	assert.Equal(t, "UNTRUSTED_ISSUER", code)
}

func TestExecute_WarnModeReportsAndReachesSelection(t *testing.T) {
	f := newExecuteFixture(t, "warn")
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	err := f.h.Execute(ctx, f.msg) // stops at selection: nobody answers

	require.Error(t, err)
	assert.NotContains(t, err.Error(), "not registered")
	steps, errCodes := drain(f.sent)
	assert.Contains(t, steps, string(StepAwaitingSelection))
	assert.NotContains(t, errCodes, string(ErrCodeUntrustedIssuer))
}

func TestExecute_OffModeDoesNotCheck(t *testing.T) {
	f := newExecuteFixture(t, "off")
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	_ = f.h.Execute(ctx, f.msg)

	for _, m := range drainAll(f.sent) {
		payload, _ := m["payload"].(map[string]interface{})
		assert.NotContains(t, payload, "issuer_entitlement_evaluated")
	}
}

func drainAll(sent chan map[string]interface{}) []map[string]interface{} {
	var out []map[string]interface{}
	for {
		select {
		case m := <-sent:
			out = append(out, m)
		case <-time.After(200 * time.Millisecond):
			return out
		}
	}
}

// The WRPAC chain must be anchored by the trust path. extractIssuerKeyMaterial
// prefers mdoc_iacas_uri, so the decision made earlier can be about other
// certificates, and then the metadata signer is asked about separately.
func TestChainAnchored(t *testing.T) {
	meta := &metadataResult{SignerX5C: []string{selfSignedX5C(t)}}
	ctx := context.Background()

	t.Run("the evaluated chain is the signer chain", func(t *testing.T) {
		pdp := &registrarPDP{decision: false} // must not be consulted
		h, _ := newRegistrarHandler(t, "fail", pdp)
		h.trustEvaluatedX5C = meta.SignerX5C
		assert.True(t, h.chainAnchored(ctx, "https://issuer.example", meta))
		assert.Empty(t, pdp.actions)
	})
	t.Run("evaluated something else (IACAs): ask about the signer", func(t *testing.T) {
		h, _ := newRegistrarHandler(t, "fail", &registrarPDP{decision: true})
		h.trustEvaluatedX5C = []string{"iaca"}
		assert.True(t, h.chainAnchored(ctx, "https://issuer.example", meta))
	})
	t.Run("the trust path denies the signer", func(t *testing.T) {
		h, _ := newRegistrarHandler(t, "fail", &registrarPDP{decision: false})
		h.trustEvaluatedX5C = []string{"iaca"}
		assert.False(t, h.chainAnchored(ctx, "https://issuer.example", meta))
	})
	t.Run("no PDP", func(t *testing.T) {
		h, _ := newRegistrarHandler(t, "fail", nil)
		h.trustEvaluatedX5C = []string{"iaca"}
		assert.False(t, h.chainAnchored(ctx, "https://issuer.example", meta))
	})
	t.Run("no chain", func(t *testing.T) {
		h, _ := newRegistrarHandler(t, "fail", &registrarPDP{decision: true})
		assert.False(t, h.chainAnchored(ctx, "https://issuer.example", &metadataResult{}))
	})
}

// selectivePDP trusts the registrar and the IACA certificates, and nothing else:
// in particular not a certificate chain the issuer made for itself.
type selectivePDP struct{ trustedKey string }

func (p *selectivePDP) Evaluate(_ context.Context, req *trust.EvaluationRequest) (*trust.EvaluationResponse, error) {
	if req.Action == trust.RegistrarAction {
		return &trust.EvaluationResponse{Decision: true}, nil
	}
	keys, _ := req.Key.([]string)
	return &trust.EvaluationResponse{Decision: len(keys) == 1 && keys[0] == p.trustedKey}, nil
}
func (p *selectivePDP) Name() string { return "selective-pdp" }
func (p *selectivePDP) SupportedResourceTypes() []trust.ResourceType {
	return []trust.ResourceType{trust.ResourceTypeX5C}
}
func (p *selectivePDP) Healthy() bool { return true }

// For an mdoc issuer the issuer trust decision is made on mdoc_iacas_uri
// certificates (extractIssuerKeyMaterial prefers them), not on the chain that
// signed the metadata. A WRPRC is public, so a self-made WRPAC carrying the
// right organisation identifier beside the genuine WRPRC must still be
// refused: the signer chain has to be anchored on its own.
func TestExecute_MdocIssuerWithSelfMadeWRPACIsRefused(t *testing.T) {
	iaca := selfSignedX5C(t)
	iacas := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"iacas": []map[string]string{{"certificate": iaca}}})
	}))
	defer iacas.Close()

	f := newExecuteFixture(t, "fail")
	f.h.httpClient = iacas.Client()
	f.h.TrustSvc = trust.NewService(f.h.Config, zap.NewNop(),
		func(string, time.Duration) (trust.TrustEvaluator, error) { return &selectivePDP{trustedKey: iaca}, nil })
	f.h.metadataResolver = fakeMetadataResolver{result: &issuermetadata.ResolveResult{
		Metadata: map[string]interface{}{
			"credential_issuer":   "https://issuer.example",
			"credential_endpoint": "https://issuer.example/credential",
			"mdoc_iacas_uri":      iacas.URL,
			"credential_configurations_supported": map[string]interface{}{
				"pid": map[string]interface{}{"format": "dc+sd-jwt", "vct": "urn:eudi:pid:1"},
				"mdl": map[string]interface{}{"format": "dc+sd-jwt", "vct": "urn:eudi:mdl:1"},
			},
			// The genuine registration certificate, replayed (it is public).
			"issuer_info": []interface{}{map[string]interface{}{
				"format": issuermetadata.FormatRegistrationCert, "data": signedRegistrationCert(t, forgedClaims),
			}},
		},
		Signed: true, Validated: true,
		SignerKeyMaterial: &issuermetadata.SignerKeyMaterial{Type: "x5c", X5C: []string{selfSignedX5C(t)}},
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err := f.h.Execute(ctx, f.msg)

	require.ErrorIs(t, err, errIssuerNotEntitled, "the issuer trust step passed (IACAs); the entitlement step must refuse")
	var codes []interface{}
	for _, m := range drainAll(f.sent) {
		if m["type"] != "flow_error" {
			continue
		}
		e, _ := m["error"].(map[string]interface{})
		assert.Equal(t, "ISSUER_NOT_ENTITLED", e["code"])
		d, _ := e["details"].(map[string]interface{})
		ent, _ := d["issuer_entitlement"].(map[string]interface{})
		for _, raw := range ent["findings"].([]interface{}) {
			codes = append(codes, raw.(map[string]interface{})["code"])
		}
	}
	assert.Contains(t, codes, string(issuertrust.CodeAccessCertificateNotTrusted))
}
