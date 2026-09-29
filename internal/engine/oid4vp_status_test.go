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
	"sync"
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
	assert.Equal(t, string(ErrCodeCredentialRevoked), msg["error"].(map[string]any)["code"])
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
}

func (f *fakeTrustEvaluator) Evaluate(ctx context.Context, req *trust.EvaluationRequest) (*trust.EvaluationResponse, error) {
	f.gotReq, f.tenant = req, trust.TenantFromContext(ctx)
	if f.decide != nil {
		return &trust.EvaluationResponse{Decision: f.decide(req)}, nil
	}
	return f.resp, f.err
}
func (f *fakeTrustEvaluator) Name() string                                 { return "fake" }
func (f *fakeTrustEvaluator) SupportedResourceTypes() []trust.ResourceType { return nil }
func (f *fakeTrustEvaluator) Healthy() bool                                { return true }

func TestStatusSignerTrust(t *testing.T) {
	assert.Nil(t, statusSignerTrust(nil))
	km := &trust.KeyMaterial{Type: "x5c", X5C: []string{"AAAA"}}

	svcWith := func(pdp string, ev *fakeTrustEvaluator) *TrustService {
		cfg := &config.Config{}
		cfg.Trust.PDPURL = pdp
		return trust.NewService(cfg, zap.NewNop(), func(string, time.Duration) (trust.TrustEvaluator, error) { return ev, nil })
	}
	ctx := trust.ContextWithTenant(context.Background(), "tenant-9")

	ev := &fakeTrustEvaluator{resp: &trust.EvaluationResponse{Decision: true}}
	ok, err := statusSignerTrust(svcWith("http://pdp", ev))(ctx, "https://status.example", km)
	assert.NoError(t, err)
	assert.True(t, ok)
	// Dedicated action, not the credential-issuer role; x5c resource; tenant in ctx.
	assert.Equal(t, trust.RoleAny, ev.gotReq.Role)
	assert.Equal(t, "status-list-signer", ev.gotReq.GetAction())
	assert.NotEqual(t, "credential-issuer", ev.gotReq.GetAction())
	assert.Equal(t, "https://status.example", ev.gotReq.SubjectID)
	assert.Equal(t, trust.KeyTypeX5C, ev.gotReq.KeyType)
	assert.Equal(t, "tenant-9", ev.tenant)

	// A PDP that only trusts the credential-issuer action must not authorize a
	// list signer: the adapter never sends that role.
	issuerOnly := &fakeTrustEvaluator{}
	issuerOnly.decide = func(req *trust.EvaluationRequest) bool {
		return req.Role == trust.RoleCredentialIssuer || req.GetAction() == "credential-issuer"
	}
	ok, err = statusSignerTrust(svcWith("http://pdp", issuerOnly))(ctx, "s", km)
	assert.NoError(t, err)
	assert.False(t, ok, "a credential-issuer-only positive decision must not authorize a list signer")

	// A genuine negative decision: (false, nil), distinct from an error.
	ev = &fakeTrustEvaluator{resp: &trust.EvaluationResponse{Decision: false, Reason: "not in any trust list"}}
	ok, err = statusSignerTrust(svcWith("http://pdp", ev))(ctx, "s", km)
	assert.NoError(t, err)
	assert.False(t, ok)

	// Evaluation failure is reported as an error, not as a negative decision.
	ev = &fakeTrustEvaluator{err: errors.New("boom")}
	ok, err = statusSignerTrust(svcWith("http://pdp", ev))(ctx, "s", km)
	assert.Error(t, err)
	assert.False(t, ok)

	// No PDP configured: an error (unavailable), not a negative decision.
	ok, err = statusSignerTrust(svcWith("", &fakeTrustEvaluator{}))(ctx, "s", km)
	assert.Error(t, err)
	assert.False(t, ok)
}
