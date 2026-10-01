package engine

import (
	"bytes"
	"compress/zlib"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
	"github.com/sirosfoundation/go-wallet-backend/pkg/statuslist"
	"github.com/sirosfoundation/go-wallet-backend/pkg/trust"
)

func statusJWK(k *ecdsa.PublicKey) map[string]any {
	return map[string]any{
		"kty": "EC", "crv": "P-256",
		"x": base64.RawURLEncoding.EncodeToString(k.X.FillBytes(make([]byte, 32))),
		"y": base64.RawURLEncoding.EncodeToString(k.Y.FillBytes(make([]byte, 32))),
	}
}

func signJWT(t *testing.T, key *ecdsa.PrivateKey, header map[string]any, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	for k, v := range header {
		tok.Header[k] = v
	}
	s, err := tok.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// statusFixture serves a status list with entry 1 revoked and returns a
// handler wired to it plus a function minting credentials pointing at it.
func statusFixture(t *testing.T, serverBroken bool) (*OID4VPHandler, func(idx int, withStatus bool) string) {
	return statusFixtureTrust(t, serverBroken, func(context.Context, string, *trust.KeyMaterial) (bool, error) { return true, nil })
}

func statusFixtureTrust(t *testing.T, serverBroken bool, signerTrust statuslist.SignerTrust) (*OID4VPHandler, func(idx int, withStatus bool) string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var uri string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if serverBroken {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/statuslist+jwt")
		var buf bytes.Buffer
		zw := zlib.NewWriter(&buf)
		_, _ = zw.Write([]byte{0b10, 0, 0, 0, 0, 0, 0, 0}) // idx 1 = 1
		_ = zw.Close()
		_, _ = w.Write([]byte(signJWT(t, key, map[string]any{"typ": "statuslist+jwt", "jwk": statusJWK(&key.PublicKey)}, jwt.MapClaims{
			"sub": uri, "iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix(),
			"status_list": map[string]any{"bits": 1, "lst": base64.RawURLEncoding.EncodeToString(buf.Bytes())},
		})))
	}))
	t.Cleanup(srv.Close)
	uri = srv.URL + "/statuslists/1"

	h := &OID4VPHandler{
		BaseHandler:   BaseHandler{Logger: zap.NewNop()},
		statusChecker: statuslist.NewChecker(srv.Client(), false, signerTrust),
		statusMode:    config.StatusCheckEnforceRevoked,
	}
	mint := func(idx int, withStatus bool) string {
		claims := jwt.MapClaims{"iss": "https://issuer", "vct": "urn:test"}
		if withStatus {
			claims["status"] = map[string]any{"status_list": map[string]any{"idx": idx, "uri": uri}}
		}
		// Same key signs the credential: exercises the signer binding too.
		return signJWT(t, key, map[string]any{"typ": "dc+sd-jwt", "jwk": statusJWK(&key.PublicKey)}, claims) + "~WyJzIiwiayIsInYiXQ~"
	}
	return h, mint
}

func TestCheckPresentationStatus(t *testing.T) {
	ctx := context.Background()
	h, mint := statusFixture(t, false)

	if err := h.checkPresentationStatus(ctx, mint(0, true)); err != nil {
		t.Fatalf("valid credential refused: %v", err)
	}
	if err := h.checkPresentationStatus(ctx, mint(1, true)); err == nil {
		t.Fatal("revoked credential accepted")
	}
	if err := h.checkPresentationStatus(ctx, mint(1, false)); err != nil {
		t.Fatalf("credential without status claim must pass: %v", err)
	}

	// DCQL shapes: the revoked one anywhere in the object refuses it all.
	obj, _ := json.Marshal(map[string][]string{"a": {mint(0, true)}, "b": {mint(1, true)}})
	if err := h.checkPresentationStatus(ctx, string(obj)); err == nil {
		t.Fatal("revoked credential inside DCQL vp_token accepted")
	}
	ok, _ := json.Marshal(map[string]string{"a": mint(0, true)})
	if err := h.checkPresentationStatus(ctx, string(ok)); err != nil {
		t.Fatalf("valid DCQL vp_token refused: %v", err)
	}
	if err := h.checkPresentationStatus(ctx, mint(0, true)+"\n"+mint(1, true)); err == nil {
		t.Fatal("revoked credential in newline-separated vp_token accepted")
	}

	// mdoc-shaped (not JWT) is not examined.
	if err := h.checkPresentationStatus(ctx, "o2d2ZXJzaW9uYzEuMA"); err != nil {
		t.Fatalf("non-JWT token must be skipped: %v", err)
	}
}

// jwtVP wraps credential JWTs in a JWT VP (jwt_vc_json presentation shape).
func jwtVP(t *testing.T, vcs ...string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var vc any = vcs
	if len(vcs) == 1 {
		vc = vcs[0]
	}
	return signJWT(t, key, map[string]any{"typ": "JWT"}, jwt.MapClaims{
		"iss": "did:example:holder", "vp": map[string]any{"verifiableCredential": vc},
	})
}

func TestCheckPresentationStatus_JWTVP(t *testing.T) {
	ctx := context.Background()
	h, mint := statusFixture(t, false)
	vc := func(idx int) string { return strings.TrimSuffix(strings.SplitN(mint(idx, true), "~", 2)[0], "~") }

	if err := h.checkPresentationStatus(ctx, jwtVP(t, vc(0))); err != nil {
		t.Fatalf("valid embedded VC refused: %v", err)
	}
	if err := h.checkPresentationStatus(ctx, jwtVP(t, vc(1))); err == nil {
		t.Fatal("revoked VC inside a JWT VP accepted")
	}
	// Every credential is covered, not just the first.
	if err := h.checkPresentationStatus(ctx, jwtVP(t, vc(0), vc(0), vc(1))); err == nil {
		t.Fatal("revoked VC among several in a JWT VP accepted")
	}
	if err := h.checkPresentationStatus(ctx, jwtVP(t, vc(0), vc(0))); err != nil {
		t.Fatalf("all-valid JWT VP refused: %v", err)
	}
	// Inside a DCQL vp_token object too.
	obj, _ := json.Marshal(map[string][]string{"a": {jwtVP(t, vc(1))}})
	if err := h.checkPresentationStatus(ctx, string(obj)); err == nil {
		t.Fatal("revoked VC in a JWT VP inside a DCQL vp_token accepted")
	}
	// warn mode logs but never refuses.
	h.statusMode = config.StatusCheckWarn
	if err := h.checkPresentationStatus(ctx, jwtVP(t, vc(1))); err != nil {
		t.Fatalf("warn must not refuse: %v", err)
	}
}

func TestCheckPresentationStatus_JWTVPUnreachable(t *testing.T) {
	ctx := context.Background()
	h, mint := statusFixture(t, true)
	vp := jwtVP(t, strings.SplitN(mint(0, true), "~", 2)[0])
	h.statusMode = config.StatusCheckEnforceRevoked
	if err := h.checkPresentationStatus(ctx, vp); err != nil {
		t.Fatalf("enforce-revoked must proceed when the list is unreachable: %v", err)
	}
	h.statusMode = config.StatusCheckStrict
	if err := h.checkPresentationStatus(ctx, vp); err == nil {
		t.Fatal("strict must refuse an undeterminable embedded VC")
	}
}

func malformedStatusCredential(t *testing.T) string {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	return signJWT(t, key, map[string]any{}, jwt.MapClaims{"status": map[string]any{"status_list": "x"}}) + "~"
}

func TestCheckPresentationStatus_ModeSemantics(t *testing.T) {
	ctx := context.Background()
	up, mintUp := statusFixture(t, false)
	down, mintDown := statusFixture(t, true)

	tests := []struct {
		name       string
		mode       config.StatusCheckMode
		h          *OID4VPHandler
		token      string
		wantRefuse bool
		wantRevoke bool
	}{
		{"enforce: revoked refuses", config.StatusCheckEnforceRevoked, up, mintUp(1, true), true, true},
		{"enforce: valid passes", config.StatusCheckEnforceRevoked, up, mintUp(0, true), false, false},
		{"enforce: unreachable proceeds", config.StatusCheckEnforceRevoked, down, mintDown(0, true), false, false},
		{"enforce: malformed claim proceeds", config.StatusCheckEnforceRevoked, down, malformedStatusCredential(t), false, false},
		{"warn: revoked proceeds", config.StatusCheckWarn, up, mintUp(1, true), false, false},
		{"warn: unreachable proceeds", config.StatusCheckWarn, down, mintDown(0, true), false, false},
		{"strict: revoked refuses", config.StatusCheckStrict, up, mintUp(1, true), true, true},
		{"strict: valid passes", config.StatusCheckStrict, up, mintUp(0, true), false, false},
		{"strict: unreachable refuses", config.StatusCheckStrict, down, mintDown(0, true), true, false},
		{"strict: malformed claim refuses", config.StatusCheckStrict, down, malformedStatusCredential(t), true, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := *tc.h
			h.statusMode = tc.mode
			err := h.checkPresentationStatus(ctx, tc.token)
			if (err != nil) != tc.wantRefuse {
				t.Fatalf("refused=%v, want %v (err %v)", err != nil, tc.wantRefuse, err)
			}
			if err != nil && errors.Is(err, statuslist.ErrRevoked) != tc.wantRevoke {
				t.Fatalf("ErrRevoked=%v, want %v (%v)", errors.Is(err, statuslist.ErrRevoked), tc.wantRevoke, err)
			}
		})
	}
}

func TestPresentOrRefuse_WarnNeverRefuses(t *testing.T) {
	for name, tc := range map[string]struct {
		down bool
		idx  int
	}{"revoked": {false, 1}, "unreachable": {true, 0}} {
		t.Run(name, func(t *testing.T) {
			h, mint, received, posted, authReq := presentFixture(t, config.StatusCheckWarn, tc.down)
			core, logs := observer.New(zap.WarnLevel)
			h.Logger = zap.New(core)
			tok := mint(tc.idx, true)

			require.NoError(t, h.presentOrRefuse(context.Background(), authReq, tok))

			form := <-posted
			assert.Equal(t, tok, form.Get("vp_token"), "warn must still submit the presentation")
			assert.Empty(t, form.Get("error"))
			msg := awaitMessage(t, received, string(TypeFlowComplete))
			assert.NotNil(t, msg)
			select {
			case m := <-received:
				assert.NotEqual(t, string(TypeFlowError), m["type"], "warn must never send CREDENTIAL_REVOKED")
			default:
			}

			require.NotZero(t, logs.Len(), "a warning must be logged")
			for _, e := range logs.All() {
				assert.NotContains(t, e.Message+fmt.Sprint(e.ContextMap()), tok)
			}
			if !tc.down {
				assert.Equal(t, 1, logs.FilterMessage("credential status revoked").Len())
				f := logs.FilterMessage("credential status revoked").All()[0].ContextMap()
				assert.Equal(t, false, f["presentation_refused"])
				assert.Equal(t, "warn", f["status_check"])
			}
		})
	}
}

func TestPresentOrRefuse_RevokedLogIsGreppable(t *testing.T) {
	h, mint, _, _, authReq := presentFixture(t, config.StatusCheckEnforceRevoked, false)
	core, logs := observer.New(zap.WarnLevel)
	h.Logger = zap.New(core)
	require.Error(t, h.presentOrRefuse(context.Background(), authReq, mint(1, true)))
	e := logs.FilterMessage("credential status revoked").All()
	require.Len(t, e, 1)
	assert.Equal(t, true, e[0].ContextMap()["presentation_refused"])
}

func TestListHost(t *testing.T) {
	assert.Equal(t, "status.example:8443", listHost("https://status.example:8443/lists/1"))
	assert.Equal(t, "unknown", listHost(""))
	assert.Equal(t, "unknown", listHost("::bad"))
}

func TestCheckPresentationStatus_Disabled(t *testing.T) {
	h, mint := statusFixture(t, true)
	h.statusChecker = nil
	if err := h.checkPresentationStatus(context.Background(), mint(1, true)); err != nil {
		t.Fatalf("disabled check must not refuse: %v", err)
	}
}

func TestPresentedTokens_Shapes(t *testing.T) {
	assert.Nil(t, presentedTokens("  "))
	assert.ElementsMatch(t, []string{"a", "b", "c"}, presentedTokens(`{"q1":"a","q2":["b","c"]}`))
	assert.ElementsMatch(t, []string{"a", "b"}, presentedTokens(`["a","b"]`))
	assert.Equal(t, []string{"a", "b"}, presentedTokens("a\nb"))
	// Malformed JSON-looking input falls back to being treated as raw tokens.
	assert.Equal(t, []string{`{"q":`}, presentedTokens(`{"q":`))
	assert.Equal(t, []string{`[1,2]`}, presentedTokens(`[1,2]`))
}

func TestDecodeJWTSegment_Errors(t *testing.T) {
	var v map[string]any
	assert.Error(t, decodeJWTSegment("!!", &v))
	assert.Error(t, decodeJWTSegment(base64.RawURLEncoding.EncodeToString([]byte("nope")), &v))
	assert.NoError(t, decodeJWTSegment(base64.RawURLEncoding.EncodeToString([]byte(`{"a":1}`)), &v))
}

// presentFixture wires a selection-test handler (real websocket to the
// "wallet") to a status fixture, plus a verifier endpoint recording what it is
// sent.
func presentFixture(t *testing.T, mode config.StatusCheckMode, listDown bool, trustOpt ...statuslist.SignerTrust) (*OID4VPHandler, func(idx int, withStatus bool) string, chan map[string]any, chan url.Values, *AuthorizationRequest) {
	t.Helper()
	sh, mint := statusFixture(t, listDown)
	if len(trustOpt) > 0 {
		sh, mint = statusFixtureTrust(t, listDown, trustOpt[0])
	}
	h, _, received, cleanup := newSelectionTestHandler(t)
	t.Cleanup(cleanup)
	h.statusChecker = sh.statusChecker
	h.statusMode = mode

	posted := make(chan url.Values, 4)
	verifier := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		posted <- r.PostForm
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"redirect_uri":"https://verifier.example/done"}`))
	}))
	t.Cleanup(verifier.Close)
	return h, mint, received, posted, &AuthorizationRequest{ResponseURI: verifier.URL, State: "st-1"}
}

func TestPresentOrRefuse_RevokedIsRefused(t *testing.T) {
	h, mint, received, posted, authReq := presentFixture(t, config.StatusCheckEnforceRevoked, false)
	err := h.presentOrRefuse(context.Background(), authReq, mint(1, true))
	assert.ErrorIs(t, err, statuslist.ErrRevoked)

	// The verifier hears the generic access_denied, never a vp_token.
	select {
	case form := <-posted:
		assert.Equal(t, "access_denied", form.Get("error"))
		assert.Equal(t, verifierRefusedDescription, form.Get("error_description"))
		assert.Empty(t, form.Get("vp_token"))
		assert.Equal(t, "st-1", form.Get("state"))
	case <-time.After(5 * time.Second):
		t.Fatal("verifier not told")
	}
	select {
	case form := <-posted:
		t.Fatalf("submitResponse must be skipped, verifier also got %v", form)
	default:
	}

	// The wallet is told CREDENTIAL_REVOKED, with the verifier's redirect.
	msg := awaitMessage(t, received, string(TypeFlowError))
	flowErr := msg["error"].(map[string]any)
	assert.Equal(t, string(ErrCodeCredentialRevoked), flowErr["code"])
	assert.Equal(t, ErrCodeCredentialRevoked.UserFacingMessage(), flowErr["message"])
	details, ok := flowErr["details"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "https://verifier.example/done", details["redirect_uri"])
}

func TestPresentOrRefuse_UnreachableListProceeds(t *testing.T) {
	h, mint, received, posted, authReq := presentFixture(t, config.StatusCheckEnforceRevoked, true)
	tok := mint(0, true)
	require.NoError(t, h.presentOrRefuse(context.Background(), authReq, tok))

	select {
	case form := <-posted:
		assert.Equal(t, tok, form.Get("vp_token"), "the presentation must reach the verifier")
		assert.Empty(t, form.Get("error"))
	case <-time.After(5 * time.Second):
		t.Fatal("vp_token never submitted")
	}
	awaitMessage(t, received, string(TypeFlowComplete))
}

func TestPresentOrRefuse_StrictUnreachableRefuses(t *testing.T) {
	h, mint, received, posted, authReq := presentFixture(t, config.StatusCheckStrict, true)
	err := h.presentOrRefuse(context.Background(), authReq, mint(0, true))
	require.Error(t, err)
	assert.NotErrorIs(t, err, statuslist.ErrRevoked)
	form := <-posted
	assert.Equal(t, "access_denied", form.Get("error"))
	msg := awaitMessage(t, received, string(TypeFlowError))
	flowErr := msg["error"].(map[string]any)
	assert.Equal(t, string(ErrCodeCredentialStatusUndetermined), flowErr["code"])
	assert.Equal(t, "A selected credential could not be confirmed as valid", flowErr["message"])
	assert.NotContains(t, flowErr["message"], "revoked")
}

func TestPresentOrRefuse_SubmitFailure(t *testing.T) {
	h, mint, received, _, _ := presentFixture(t, config.StatusCheckEnforceRevoked, false)
	err := h.presentOrRefuse(context.Background(), &AuthorizationRequest{}, mint(0, true))
	require.Error(t, err)
	msg := awaitMessage(t, received, string(TypeFlowError))
	assert.Equal(t, string(ErrCodePresentationError), msg["error"].(map[string]any)["code"])
}

func TestSharedStatusChecker(t *testing.T) {
	cfg := &config.Config{}
	a, b := sharedStatusChecker(cfg, nil), sharedStatusChecker(cfg, nil)
	assert.Same(t, a, b, "one Checker per config so the list cache spans presentations")
	assert.NotSame(t, a, sharedStatusChecker(&config.Config{}, nil))

	// Concurrent use of the shared instance (run with -race).
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = sharedStatusChecker(cfg, nil).Check(context.Background(), &statuslist.Reference{Idx: 1, URI: "http://127.0.0.1:1/x"})
		}()
	}
	wg.Wait()
}

func TestNewOID4VPHandler_StatusMode(t *testing.T) {
	for mode, wantChecker := range map[config.StatusCheckMode]bool{
		"": true, config.StatusCheckWarn: true, config.StatusCheckEnforceRevoked: true,
		config.StatusCheckStrict: true, config.StatusCheckOff: false,
	} {
		cfg := &config.Config{}
		cfg.Presentation.StatusCheck = mode
		fh, err := NewOID4VPHandler(&Flow{}, cfg, zap.NewNop(), nil, nil, nil, nil)
		require.NoError(t, err)
		h := fh.(*OID4VPHandler)
		assert.Equal(t, wantChecker, h.statusChecker != nil, string(mode))
		assert.Equal(t, mode.Effective(), h.statusMode)
	}
}

func untrusted(context.Context, string, *trust.KeyMaterial) (bool, error) { return false, nil }
func trustErr(context.Context, string, *trust.KeyMaterial) (bool, error) {
	return false, errors.New("pdp down")
}

func TestCheckPresentationStatus_TrustGatesVerdict(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name       string
		trust      statuslist.SignerTrust
		mode       config.StatusCheckMode
		wantRefuse bool
		wantRevoke bool
		wantLog    string
	}{
		{"trusted+revoked enforce refuses", nil, config.StatusCheckEnforceRevoked, true, true, "credential status revoked"},
		{"untrusted enforce proceeds", untrusted, config.StatusCheckEnforceRevoked, false, false, "credential status list signer not trusted; list ignored"},
		{"untrusted warn proceeds", untrusted, config.StatusCheckWarn, false, false, "credential status list signer not trusted; list ignored"},
		{"untrusted strict refuses", untrusted, config.StatusCheckStrict, true, false, "credential status list signer not trusted; list ignored"},
		{"trust error enforce proceeds", trustErr, config.StatusCheckEnforceRevoked, false, false, "credential status could not be determined; the verifier is responsible for the status check"},
		{"trust error strict refuses", trustErr, config.StatusCheckStrict, true, false, "credential status could not be determined; the verifier is responsible for the status check"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var h *OID4VPHandler
			var mint func(int, bool) string
			if tc.trust == nil {
				h, mint = statusFixture(t, false)
			} else {
				h, mint = statusFixtureTrust(t, false, tc.trust)
			}
			core, logs := observer.New(zap.WarnLevel)
			h.Logger = zap.New(core)
			h.statusMode = tc.mode
			err := h.checkPresentationStatus(ctx, mint(1, true))
			assert.Equal(t, tc.wantRefuse, err != nil, "%v", err)
			assert.Equal(t, tc.wantRevoke, errors.Is(err, statuslist.ErrRevoked))
			assert.Equal(t, 1, logs.FilterMessage(tc.wantLog).Len(), "logs: %v", logs.All())
		})
	}
}

// fakeTrustEvaluator records the request and answers with a fixed response.
type fakeTrustEvaluator struct {
	resp   *trust.EvaluationResponse
	err    error
	gotReq *trust.EvaluationRequest
	tenant string
	decide func(*trust.EvaluationRequest) bool // overrides resp when set
	onCall func()
}

func (f *fakeTrustEvaluator) Evaluate(ctx context.Context, req *trust.EvaluationRequest) (*trust.EvaluationResponse, error) {
	f.gotReq, f.tenant = req, trust.TenantFromContext(ctx)
	if f.onCall != nil {
		f.onCall()
	}
	if f.decide != nil {
		return &trust.EvaluationResponse{Decision: f.decide(req)}, nil
	}
	return f.resp, f.err
}
func (f *fakeTrustEvaluator) Name() string                                 { return "fake" }
func (f *fakeTrustEvaluator) SupportedResourceTypes() []trust.ResourceType { return nil }
func (f *fakeTrustEvaluator) Healthy() bool                                { return true }

func TestStatusSignerTrust(t *testing.T) {
	assert.Nil(t, statusSignerTrust(nil, true))
	km := &trust.KeyMaterial{Type: "x5c", X5C: []string{"AAAA"}}

	svcWith := func(pdp string, ev *fakeTrustEvaluator) *TrustService {
		cfg := &config.Config{}
		cfg.Trust.PDPURL = pdp
		return trust.NewService(cfg, zap.NewNop(), func(string, time.Duration) (trust.TrustEvaluator, error) { return ev, nil })
	}
	ctx := trust.ContextWithTenant(context.Background(), "tenant-9")

	ev := &fakeTrustEvaluator{resp: &trust.EvaluationResponse{Decision: true}}
	ok, err := statusSignerTrust(svcWith("http://pdp", ev), true)(ctx, "https://status.example", km)
	assert.NoError(t, err)
	assert.True(t, ok)
	// Dedicated action, not the credential-issuer role; x5c resource; tenant in ctx.
	assert.Equal(t, trust.RoleAny, ev.gotReq.Role)
	assert.Equal(t, "status-list-signer", ev.gotReq.GetAction())
	assert.NotEqual(t, "credential-issuer", ev.gotReq.GetAction())
	assert.Equal(t, "https://status.example", ev.gotReq.SubjectID)
	assert.Equal(t, trust.KeyTypeX5C, ev.gotReq.KeyType)
	assert.Equal(t, "tenant-9", ev.tenant)

	// A PDP that trusts only credential-issuer: the negative from
	// status-list-signer is final, so the signer is NOT trusted and the
	// fallback is never asked.
	issuerOnly := &fakeTrustEvaluator{}
	var seen []string
	issuerOnly.decide = func(req *trust.EvaluationRequest) bool {
		name := string(req.Role)
		if name == "" {
			name = req.GetAction()
		}
		seen = append(seen, name)
		return name == "credential-issuer"
	}
	ok, err = statusSignerTrust(svcWith("http://pdp", issuerOnly), true)(ctx, "s", km)
	assert.NoError(t, err)
	assert.False(t, ok, "deny is deny: a negative status-list-signer decision is final")
	assert.Equal(t, []string{"status-list-signer"}, seen)

	// A genuine negative decision: (false, nil), distinct from an error.
	ev = &fakeTrustEvaluator{resp: &trust.EvaluationResponse{Decision: false, Reason: "not in any trust list"}}
	ok, err = statusSignerTrust(svcWith("http://pdp", ev), true)(ctx, "s", km)
	assert.NoError(t, err)
	assert.False(t, ok)

	// Evaluation failure is reported as an error, not as a negative decision.
	ev = &fakeTrustEvaluator{err: errors.New("boom")}
	ok, err = statusSignerTrust(svcWith("http://pdp", ev), true)(ctx, "s", km)
	assert.Error(t, err)
	assert.False(t, ok)

	// The switch reaches the service: first call errors, fallback on asks a
	// second time, off does not.
	for _, fb := range []bool{true, false} {
		ev = &fakeTrustEvaluator{err: errors.New("boom")}
		calls := 0
		ev.onCall = func() { calls++ }
		_, err = statusSignerTrust(svcWith("http://pdp", ev), fb)(ctx, "s", km)
		assert.Error(t, err)
		if fb {
			assert.Equal(t, 2, calls)
		} else {
			assert.Equal(t, 1, calls)
		}
	}

	// No PDP configured: an error (unavailable), not a negative decision.
	ok, err = statusSignerTrust(svcWith("", &fakeTrustEvaluator{}), true)(ctx, "s", km)
	assert.Error(t, err)
	assert.False(t, ok)
}

func TestStatusOutcome_RedactedErrorsAndLogs(t *testing.T) {
	secret := errors.New("Get \"https://issuer.example/lists/secret-idx-4711?x=1\": boom")
	for _, tc := range []struct {
		err   error
		class error
	}{
		{secret, errStatusUndetermined},
		{fmt.Errorf("%w: %v", statuslist.ErrTrustUnavailable, secret), statuslist.ErrTrustUnavailable},
		{fmt.Errorf("%w (%v)", statuslist.ErrSignerUntrusted, secret), statuslist.ErrSignerUntrusted},
		{fmt.Errorf("%w: %v", statuslist.ErrNoSignerKey, secret), statuslist.ErrNoSignerKey},
		{fmt.Errorf("%w: %v", statuslist.ErrRevoked, secret), statuslist.ErrRevoked},
	} {
		core, logs := observer.New(zap.DebugLevel)
		h := &OID4VPHandler{BaseHandler: BaseHandler{Logger: zap.New(core)}, statusMode: config.StatusCheckStrict}
		got := h.statusOutcome(tc.err, "https://issuer.example/lists/1")
		require.Error(t, got)
		assert.ErrorIs(t, got, tc.class)
		assert.NotContains(t, got.Error(), "4711")
		assert.NotContains(t, got.Error(), "boom")
		for _, e := range logs.All() {
			assert.NotContains(t, e.Message+fmt.Sprint(e.ContextMap()), "4711")
			assert.NotContains(t, e.Message+fmt.Sprint(e.ContextMap()), "boom")
			assert.NotContains(t, e.ContextMap(), "error", "raw errors must not be logged")
		}

		// Soft modes log the same redacted fields and do not refuse.
		if !errors.Is(tc.err, statuslist.ErrRevoked) {
			h.statusMode = config.StatusCheckEnforceRevoked
			assert.NoError(t, h.statusOutcome(tc.err, "https://issuer.example/lists/1"))
		}
	}
}

func TestStatusSignerTrust_ReasonTextIsNotASignal(t *testing.T) {
	// A PDP denial whose Reason merely says "Trust evaluation failed" is a denial.
	ev := &fakeTrustEvaluator{resp: &trust.EvaluationResponse{Decision: false, Reason: "Trust evaluation failed: not a real failure"}}
	cfg := &config.Config{}
	cfg.Trust.PDPURL = "http://pdp"
	svc := trust.NewService(cfg, zap.NewNop(), func(string, time.Duration) (trust.TrustEvaluator, error) { return ev, nil })
	ok, err := statusSignerTrust(svc, false)(context.Background(), "s", &trust.KeyMaterial{Type: "x5c", X5C: []string{"AA"}})
	assert.NoError(t, err)
	assert.False(t, ok)
}

// hangingStatusFixture serves status lists that never answer until the
// request is cancelled, and mints credentials that each reference a distinct
// list URI on that server. hits counts requests that reached the server.
func hangingStatusFixture(t *testing.T, mode config.StatusCheckMode) (h *OID4VPHandler, mint func(i int) string, hits *atomic.Int32) {
	t.Helper()
	hits = new(atomic.Int32)
	done := make(chan struct{})
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		select {
		case <-r.Context().Done():
		case <-done:
		}
	}))
	t.Cleanup(func() { close(done); srv.Close() })
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	h = &OID4VPHandler{
		BaseHandler:   BaseHandler{Logger: zap.NewNop()},
		statusChecker: statuslist.NewChecker(srv.Client(), false, func(context.Context, string, *trust.KeyMaterial) (bool, error) { return true, nil }),
		statusMode:    mode,
	}
	mint = func(i int) string {
		claims := jwt.MapClaims{"iss": "https://issuer", "status": map[string]any{"status_list": map[string]any{"idx": 1, "uri": fmt.Sprintf("%s/lists/%d", srv.URL, i)}}}
		return signJWT(t, key, map[string]any{"typ": "dc+sd-jwt", "jwk": statusJWK(&key.PublicKey)}, claims) + "~"
	}
	return h, mint, hits
}

// With an injectable clock: once the budget is spent the remaining credentials
// are skipped without any request. warn and enforce-revoked still proceed;
// strict fails closed.
func TestCheckPresentationStatus_BudgetSkipsRemaining(t *testing.T) {
	for _, tc := range []struct {
		mode    config.StatusCheckMode
		wantErr bool
	}{
		{config.StatusCheckWarn, false},
		{config.StatusCheckEnforceRevoked, false},
		{config.StatusCheckStrict, true},
	} {
		t.Run(string(tc.mode), func(t *testing.T) {
			h, mint, hits := hangingStatusFixture(t, tc.mode)
			h.statusBudget = 10 * time.Second
			// The clock is at t0 when the budget starts and when the first
			// check begins, and 11s later for every later reading.
			var calls int
			t0 := time.Now()
			h.statusNow = func() time.Time {
				calls++
				if calls <= 2 {
					return t0
				}
				return t0.Add(11 * time.Second)
			}
			// Make the first (only) live check fail fast: a cancelled-flow
			// stand-in is not wanted, so bound it with a short real deadline.
			ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
			defer cancel()
			vp := strings.Join([]string{mint(1), mint(2), mint(3)}, "\n")
			err := h.checkPresentationStatus(ctx, vp)
			if got := hits.Load(); got > 1 {
				t.Fatalf("%d lists requested; credentials after the exhausted budget must be skipped", got)
			}
			if tc.wantErr != (err != nil) {
				t.Fatalf("wantErr=%v got %v", tc.wantErr, err)
			}
		})
	}
}

// Real clock, small budget: unreachable lists cannot consume the flow
// deadline, warn still proceeds, strict refuses as undetermined.
func TestCheckPresentationStatus_BudgetBoundsSlowLists(t *testing.T) {
	for _, tc := range []struct {
		mode    config.StatusCheckMode
		wantErr bool
	}{
		{config.StatusCheckWarn, false},
		{config.StatusCheckStrict, true},
	} {
		t.Run(string(tc.mode), func(t *testing.T) {
			h, mint, _ := hangingStatusFixture(t, tc.mode)
			h.statusBudget = 200 * time.Millisecond
			// A long flow context: only the budget may stop the checks.
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			vp := strings.Join([]string{mint(1), mint(2), mint(3), mint(4)}, "\n")
			start := time.Now()
			err := h.checkPresentationStatus(ctx, vp)
			if el := time.Since(start); el > 5*time.Second {
				t.Fatalf("status checks took %v, budget not enforced", el)
			}
			if ctx.Err() != nil {
				t.Fatal("flow context must be untouched")
			}
			if tc.wantErr != (err != nil) {
				t.Fatalf("wantErr=%v got %v", tc.wantErr, err)
			}
			if tc.wantErr && !errors.Is(err, errStatusBudgetExhausted) {
				t.Fatalf("strict must refuse with the budget class, got %v", err)
			}
		})
	}
}

// A credential whose status object carries only another mechanism is not
// covered by the Token Status List check, even in strict mode; an empty or
// null status object is malformed and strict refuses it.
func TestCheckPresentationStatus_OtherMechanismNotCovered(t *testing.T) {
	ctx := context.Background()
	h, _ := statusFixture(t, true)
	h.statusMode = config.StatusCheckStrict
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cred := func(status any) string {
		return signJWT(t, key, map[string]any{}, jwt.MapClaims{"status": status}) + "~"
	}
	if err := h.checkPresentationStatus(ctx, cred(map[string]any{"revocation": map[string]any{"id": "x"}})); err != nil {
		t.Fatalf("strict must not refuse a credential with another status mechanism only: %v", err)
	}
	if err := h.checkPresentationStatus(ctx, jwtVP(t, strings.TrimSuffix(cred(map[string]any{"other": 1}), "~"))); err != nil {
		t.Fatalf("strict must not refuse an embedded VC with another status mechanism only: %v", err)
	}
	for name, st := range map[string]any{"empty": map[string]any{}, "null": nil, "string": "x"} {
		if err := h.checkPresentationStatus(ctx, cred(st)); err == nil {
			t.Fatalf("strict must refuse a %s status claim", name)
		}
	}
}
