package api

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
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	"github.com/sirosfoundation/go-wallet-backend/internal/service"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage/memory"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
	"github.com/sirosfoundation/go-wallet-backend/pkg/statuslist"
	"github.com/sirosfoundation/go-wallet-backend/pkg/trust"
)

// statusFake answers List from a function.
type statusFake struct {
	mu      sync.Mutex
	fn      func(ctx context.Context, uri string) (*statuslist.VerifiedList, error)
	tenants []string
}

func (f *statusFake) List(ctx context.Context, uri string) (*statuslist.VerifiedList, error) {
	f.mu.Lock()
	f.tenants = append(f.tenants, trust.TenantFromContext(ctx))
	f.mu.Unlock()
	return f.fn(ctx, uri)
}

func fakeVerified() *statuslist.VerifiedList {
	exp := time.Now().Add(time.Hour).UTC()
	return &statuslist.VerifiedList{
		Bits: 1, Lst: []byte{0x78, 0x9c, 0x63, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01}, IssuedAt: time.Now().Add(-time.Minute).UTC(),
		ExpiresAt: &exp, TTL: 10 * time.Minute, FreshUntil: time.Now().Add(5 * time.Minute),
		SignerAction: "status-list-signer", ETag: `"0123456789abcdef0123456789abcdef"`,
	}
}

// setupStatusTestHandlers returns handlers whose Status service is built from
// lister (nil: the status service is absent, as with status_check.enabled=false).
func setupStatusTestHandlers(t *testing.T, lister service.StatusLister, logger *zap.Logger, mutate func(*config.StatusCheckConfig)) (*Handlers, *gin.Engine) {
	t.Helper()
	cfg := &config.Config{
		Server: config.ServerConfig{Host: "localhost", Port: 8080, RPID: "localhost", RPOrigin: "http://localhost:8080", RPName: "Test Wallet"},
		JWT:    config.JWTConfig{Secret: "test-secret-that-is-at-least-32-bytes-long", ExpiryHours: 24, Issuer: "test-wallet"},
	}
	services := service.NewServices(memory.NewStore(), cfg, zap.NewNop())
	services.Status = nil
	if lister != nil {
		sc := config.StatusCheckConfig{Enabled: true}
		if mutate != nil {
			mutate(&sc)
		}
		services.Status = service.NewStatusServiceWithLister(lister, sc, logger)
	}
	handlers := NewHandlers(services, cfg, logger, []string{"test"})
	router := gin.New()
	// Stand-in for the auth middleware.
	router.Use(func(c *gin.Context) {
		c.Set("user_id", "user-1234")
		c.Set("tenant_id", "tenant-x")
	})
	router.POST("/status/v1/lists", handlers.StatusLists)
	return handlers, router
}

func postStatus(router *gin.Engine, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/status/v1/lists", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

func decodeStatus(t *testing.T, w *httptest.ResponseRecorder) StatusListsResponse {
	t.Helper()
	var resp StatusListsResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode %q: %v", w.Body.String(), err)
	}
	return resp
}

func errCode(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
		t.Fatalf("decode %q: %v", w.Body.String(), err)
	}
	s, _ := m["error"].(string)
	return s
}

func TestStatusLists_NilService503(t *testing.T) {
	_, router := setupStatusTestHandlers(t, nil, zap.NewNop(), nil)
	w := postStatus(router, `{"lists":[{"uri":"https://a.example/l"}]}`)
	if w.Code != http.StatusServiceUnavailable || errCode(t, w) != "STATUS_NOT_SUPPORTED" {
		t.Fatalf("status = %d body = %s", w.Code, w.Body.String())
	}
}

func TestStatusLists_Verified(t *testing.T) {
	fake := &statusFake{fn: func(context.Context, string) (*statuslist.VerifiedList, error) { return fakeVerified(), nil }}
	_, router := setupStatusTestHandlers(t, fake, zap.NewNop(), nil)
	w := postStatus(router, `{"lists":[{"uri":"https://a.example/l"}]}`)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", w.Code, w.Body.String())
	}
	resp := decodeStatus(t, w)
	if len(resp.Results) != 1 {
		t.Fatalf("results = %+v", resp.Results)
	}
	r := resp.Results[0]
	if r.State != "verified" || r.URI != "https://a.example/l" || r.Lst != base64.RawURLEncoding.EncodeToString(fakeVerified().Lst) || r.Bits == nil || *r.Bits != 1 {
		t.Fatalf("result = %+v", r)
	}
	if fake.tenants[0] != "tenant-x" {
		t.Fatalf("tenant = %q", fake.tenants[0])
	}
	cc := w.Header().Get("Cache-Control")
	if !strings.HasPrefix(cc, "private, max-age=") || cc == "private, max-age=0" {
		t.Fatalf("Cache-Control = %q", cc)
	}
	// min(ttl 600s, remaining freshness 300s) = 300s, give or take the clock.
	var age int
	_, _ = fmt.Sscanf(cc, "private, max-age=%d", &age)
	if age < 290 || age > 300 {
		t.Fatalf("max-age = %d, want about 300 (the shorter of ttl and remaining freshness)", age)
	}
	if w.Header().Get("ETag") != fakeVerified().ETag {
		t.Fatalf("ETag = %q", w.Header().Get("ETag"))
	}
	if w.Header().Get("Pragma") != "" || w.Header().Get("Expires") != "" {
		t.Fatalf("no-cache headers set on a cacheable response: %v", w.Header())
	}
}

func TestStatusLists_MaxAgeLimitedByTTL(t *testing.T) {
	fake := &statusFake{fn: func(context.Context, string) (*statuslist.VerifiedList, error) {
		v := fakeVerified()
		v.TTL = 30 * time.Second
		return v, nil
	}}
	_, router := setupStatusTestHandlers(t, fake, zap.NewNop(), nil)
	w := postStatus(router, `{"lists":[{"uri":"https://a.example/l"}]}`)
	if got := w.Header().Get("Cache-Control"); got != "private, max-age=30" {
		t.Fatalf("Cache-Control = %q, want max-age=30 (the ttl is shorter than the remaining freshness)", got)
	}
}

func TestStatusLists_PartialFailureIs200AndNotCacheable(t *testing.T) {
	fake := &statusFake{fn: func(_ context.Context, uri string) (*statuslist.VerifiedList, error) {
		if strings.HasSuffix(uri, "/bad") {
			return nil, statuslist.ErrSignerUntrusted
		}
		return fakeVerified(), nil
	}}
	_, router := setupStatusTestHandlers(t, fake, zap.NewNop(), nil)
	w := postStatus(router, `{"lists":[{"uri":"https://a.example/good"},{"uri":"https://a.example/bad"},{"uri":"http://a.example/plain"}]}`)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	res := decodeStatus(t, w).Results
	if len(res) != 3 || res[0].State != "verified" ||
		res[1].State != "undetermined" || res[1].Reason != "signer_untrusted" || res[1].Lst != "" ||
		res[2].State != "undetermined" || res[2].Reason != "uri_not_allowed" {
		t.Fatalf("results = %+v", res)
	}
	if got := w.Header().Get("Cache-Control"); got != "private, no-store" {
		t.Fatalf("Cache-Control = %q: a response carrying an undetermined list must not be reused", got)
	}
	if w.Header().Get("ETag") != "" {
		t.Fatal("ETag set on a multi-list response")
	}
}

func TestStatusLists_NotModified(t *testing.T) {
	fake := &statusFake{fn: func(context.Context, string) (*statuslist.VerifiedList, error) { return fakeVerified(), nil }}
	_, router := setupStatusTestHandlers(t, fake, zap.NewNop(), nil)
	w := postStatus(router, `{"lists":[{"uri":"https://a.example/l","etag":"`+strings.ReplaceAll(fakeVerified().ETag, `"`, `\"`)+`"}]}`)
	r := decodeStatus(t, w).Results[0]
	if w.Code != http.StatusOK || r.State != "not_modified" || r.Lst != "" {
		t.Fatalf("status = %d result = %+v", w.Code, r)
	}
}

func TestStatusLists_BadRequests(t *testing.T) {
	fake := &statusFake{fn: func(context.Context, string) (*statuslist.VerifiedList, error) { return fakeVerified(), nil }}
	_, router := setupStatusTestHandlers(t, fake, zap.NewNop(), func(sc *config.StatusCheckConfig) { sc.MaxListsPerRequest = 2 })
	for name, tc := range map[string]struct{ body, code string }{
		"not json":      {`nope`, "INVALID_REQUEST"},
		"empty body":    {``, "INVALID_REQUEST"},
		"wrong type":    {`{"lists":"x"}`, "INVALID_REQUEST"},
		"no lists":      {`{}`, "INVALID_REQUEST"},
		"empty lists":   {`{"lists":[]}`, "INVALID_REQUEST"},
		"missing uri":   {`{"lists":[{"etag":"x"}]}`, "INVALID_REQUEST"},
		"trailing data": {`{"lists":[{"uri":"https://a/1"}]} {"x":1}`, "INVALID_REQUEST"},
		"too many":      {`{"lists":[{"uri":"https://a/1"},{"uri":"https://a/2"},{"uri":"https://a/3"}]}`, "TOO_MANY_URIS"},
	} {
		t.Run(name, func(t *testing.T) {
			w := postStatus(router, tc.body)
			if w.Code != http.StatusBadRequest || errCode(t, w) != tc.code {
				t.Fatalf("status = %d body = %s, want 400 %s", w.Code, w.Body.String(), tc.code)
			}
		})
	}
	// At the cap is fine.
	if w := postStatus(router, `{"lists":[{"uri":"https://a/1"},{"uri":"https://a/2"}]}`); w.Code != http.StatusOK {
		t.Fatalf("at the cap: %d %s", w.Code, w.Body.String())
	}
}

func TestStatusLists_BodyTooLarge413(t *testing.T) {
	fake := &statusFake{fn: func(context.Context, string) (*statuslist.VerifiedList, error) { return fakeVerified(), nil }}
	_, router := setupStatusTestHandlers(t, fake, zap.NewNop(), nil)
	w := postStatus(router, `{"lists":[{"uri":"https://a.example/`+strings.Repeat("a", maxStatusRequestBytes)+`"}]}`)
	if w.Code != http.StatusRequestEntityTooLarge || errCode(t, w) != "REQUEST_TOO_LARGE" {
		t.Fatalf("status = %d body = %.200s", w.Code, w.Body.String())
	}
}

// statusToken builds a signed Token Status List (jwk header) for uri.
func statusToken(t *testing.T, key *ecdsa.PrivateKey, uri string) (token string, lst []byte) {
	t.Helper()
	var buf bytes.Buffer
	zw := zlib.NewWriter(&buf)
	_, _ = zw.Write(make([]byte, 16))
	_ = zw.Close()
	lst = buf.Bytes()
	claims := jwt.MapClaims{
		"sub": uri, "iat": time.Now().Add(-time.Minute).Unix(), "exp": time.Now().Add(time.Hour).Unix(),
		"status_list": map[string]any{"bits": 1, "lst": base64.RawURLEncoding.EncodeToString(lst)},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	tok.Header["typ"] = "statuslist+jwt"
	tok.Header["jwk"] = map[string]any{
		"kty": "EC", "crv": "P-256",
		"x": base64.RawURLEncoding.EncodeToString(key.X.FillBytes(make([]byte, 32))),
		"y": base64.RawURLEncoding.EncodeToString(key.Y.FillBytes(make([]byte, 32))),
	}
	s, err := tok.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return s, lst
}

type pdpStub struct{ decision bool }

func (p *pdpStub) Evaluate(context.Context, *trust.EvaluationRequest) (*trust.EvaluationResponse, error) {
	return &trust.EvaluationResponse{Decision: p.decision}, nil
}
func (p *pdpStub) Name() string                                 { return "pdp-stub" }
func (p *pdpStub) SupportedResourceTypes() []trust.ResourceType { return nil }
func (p *pdpStub) Healthy() bool                                { return true }

// TestStatusLists_EndToEnd_NoURIInAnyLog drives a request through the real
// Checker, the real trust service and the real handler, with every logger
// (handler, service, trust) captured at debug level, and requires that no log
// entry contains any part of a requested URI. It also checks the verified list
// matches the signed token byte for byte and that an untrusted signer yields
// undetermined.
func TestStatusLists_EndToEnd_NoURIInAnyLog(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	var tokenURI string
	var token string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/statuslist+jwt")
		if strings.HasSuffix(r.URL.Path, "/gone") {
			http.Error(w, "no", http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte(token))
	}))
	defer srv.Close()
	tokenURI = srv.URL + "/very-secret-issuer-path/list-7"
	tok, wantLst := statusToken(t, key, tokenURI)
	token = tok

	core, logs := observer.New(zap.DebugLevel)
	logger := zap.New(core)
	pdp := &pdpStub{decision: true}
	trustSvc := trust.NewService(&config.Config{Trust: config.TrustConfig{Timeout: 10, PDPURL: "https://pdp.example"}}, logger,
		func(string, time.Duration) (trust.TrustEvaluator, error) { return pdp, nil })
	signer := func(ctx context.Context, subject string, km *trust.KeyMaterial) (bool, string, error) {
		info, err := trustSvc.EvaluateStatusListSigner(ctx, subject, "", km, true)
		if err != nil {
			return false, "", err
		}
		if info.EvaluationFailed {
			return false, "", errors.New("trust evaluation failed")
		}
		return info.Trusted, info.Action, nil
	}
	checker := statuslist.NewChecker(srv.Client(), false, nil).WithSignerTrustAction(signer)
	_, router := setupStatusTestHandlers(t, checker, logger, nil)

	goneURI := srv.URL + "/very-secret-issuer-path/gone"
	w := postStatus(router, fmt.Sprintf(`{"lists":[{"uri":%q},{"uri":%q}]}`, tokenURI, goneURI))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", w.Code, w.Body.String())
	}
	res := decodeStatus(t, w).Results
	if res[0].State != "verified" || res[0].Lst != base64.RawURLEncoding.EncodeToString(wantLst) || res[0].SignerTrust != trust.StatusListSignerAction {
		t.Fatalf("verified result = %+v", res[0])
	}
	if res[1].State != "undetermined" || res[1].Reason != "fetch_failed" {
		t.Fatalf("unreachable result = %+v", res[1])
	}

	// An untrusted signer, same pipeline.
	pdp.decision = false
	trustSvcDeny := tokenURI + "?v=2"
	tok2, _ := statusToken(t, key, trustSvcDeny)
	token = tok2
	w = postStatus(router, fmt.Sprintf(`{"lists":[{"uri":%q}]}`, trustSvcDeny))
	r2 := decodeStatus(t, w).Results[0]
	if r2.State != "undetermined" || r2.Reason != "signer_untrusted" || r2.Lst != "" {
		t.Fatalf("untrusted result = %+v", r2)
	}

	if logs.Len() == 0 {
		t.Fatal("no log entries captured: the privacy assertion would be vacuous")
	}
	needles := []string{tokenURI, goneURI, srv.URL, strings.TrimPrefix(srv.URL, "https://"), "very-secret-issuer-path", "list-7", "/gone"}
	for _, e := range logs.All() {
		dump := e.Message + " " + fmt.Sprint(e.ContextMap())
		for _, n := range needles {
			if strings.Contains(dump, n) {
				t.Fatalf("log entry leaks %q: %s", n, dump)
			}
		}
		// A user id must never sit next to list data either.
		if strings.Contains(dump, "user-1234") && strings.Contains(dump, "status") {
			t.Fatalf("log entry ties the user to status list activity: %s", dump)
		}
	}
}
