package service

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
	"github.com/sirosfoundation/go-wallet-backend/pkg/statuslist"
	"github.com/sirosfoundation/go-wallet-backend/pkg/trust"
)

// fakeLister answers List from a function and records what it was asked.
type fakeLister struct {
	mu      sync.Mutex
	fn      func(ctx context.Context, uri string) (*statuslist.VerifiedList, error)
	uris    []string
	tenants []string
}

func (f *fakeLister) List(ctx context.Context, uri string) (*statuslist.VerifiedList, error) {
	f.mu.Lock()
	f.uris = append(f.uris, uri)
	f.tenants = append(f.tenants, trust.TenantFromContext(ctx))
	f.mu.Unlock()
	return f.fn(ctx, uri)
}

func goodList() *statuslist.VerifiedList {
	exp := time.Now().Add(time.Hour).UTC()
	return &statuslist.VerifiedList{
		Bits: 2, Lst: []byte{0x78, 0x9c, 0x01, 0x02, 0xff}, IssuedAt: time.Now().Add(-time.Minute).UTC(),
		ExpiresAt: &exp, TTL: 15 * time.Minute, FreshUntil: time.Now().Add(10 * time.Minute),
		SignerAction: "status-list-signer", ETag: `"abc123abc123abc123"`,
	}
}

func newTestStatusService(l StatusLister, mutate func(*config.StatusCheckConfig)) (*StatusService, *observer.ObservedLogs) {
	sc := config.StatusCheckConfig{Enabled: true}
	if mutate != nil {
		mutate(&sc)
	}
	core, logs := observer.New(zap.DebugLevel)
	return NewStatusServiceWithLister(l, sc, zap.New(core)), logs
}

const testListURI = "https://status.example.org/lists/1"

func TestStatusService_VerifiedList(t *testing.T) {
	l := &fakeLister{fn: func(context.Context, string) (*statuslist.VerifiedList, error) { return goodList(), nil }}
	svc, _ := newTestStatusService(l, nil)

	res, err := svc.Lists(context.Background(), "tenant-a", []StatusListRequest{{URI: testListURI}})
	if err != nil || len(res) != 1 {
		t.Fatalf("Lists = %+v, %v", res, err)
	}
	r, want := res[0], goodList()
	if r.State != StatusStateVerified || r.Reason != "" || r.URI != testListURI {
		t.Fatalf("result = %+v", r)
	}
	if r.Bits == nil || *r.Bits != 2 || r.Lst != base64.RawURLEncoding.EncodeToString(want.Lst) {
		t.Fatalf("bits/lst = %v / %q", r.Bits, r.Lst)
	}
	if r.IssuedAt == nil || r.ExpiresAt == nil || r.TTL == nil || *r.TTL != 900 || r.FreshUntil == nil {
		t.Fatalf("times = %+v", r)
	}
	if r.ETag != want.ETag || r.SignerTrust != "status-list-signer" {
		t.Fatalf("etag/signer = %q / %q", r.ETag, r.SignerTrust)
	}
	if l.tenants[0] != "tenant-a" {
		t.Fatalf("tenant in ctx = %q, want tenant-a (the signer trust decision is tenant scoped)", l.tenants[0])
	}
}

func TestStatusService_NotModified(t *testing.T) {
	l := &fakeLister{fn: func(context.Context, string) (*statuslist.VerifiedList, error) { return goodList(), nil }}
	svc, _ := newTestStatusService(l, nil)

	res, _ := svc.Lists(context.Background(), "t", []StatusListRequest{{URI: testListURI, ETag: goodList().ETag}})
	r := res[0]
	if r.State != StatusStateNotModified || r.Lst != "" || r.Bits != nil || r.ETag != goodList().ETag || r.FreshUntil == nil {
		t.Fatalf("matching etag: %+v", r)
	}
	res, _ = svc.Lists(context.Background(), "t", []StatusListRequest{{URI: testListURI, ETag: `"stale"`}})
	if res[0].State != StatusStateVerified || res[0].Lst == "" {
		t.Fatalf("stale etag must get the full list: %+v", res[0])
	}
}

// TestStatusService_NeverVerifiedOnFailure runs every failure the service can
// meet (one per reason code, plus the service's own guards) and requires an
// undetermined result with that reason and no list data.
func TestStatusService_NeverVerifiedOnFailure(t *testing.T) {
	bad := func(mut func(*statuslist.VerifiedList)) func(context.Context, string) (*statuslist.VerifiedList, error) {
		return func(context.Context, string) (*statuslist.VerifiedList, error) {
			v := goodList()
			mut(v)
			return v, nil
		}
	}
	failWith := func(err error) func(context.Context, string) (*statuslist.VerifiedList, error) {
		return func(context.Context, string) (*statuslist.VerifiedList, error) { return nil, err }
	}
	cases := []struct {
		reason statuslist.Reason
		uri    string
		fn     func(context.Context, string) (*statuslist.VerifiedList, error)
		mutate func(*config.StatusCheckConfig)
	}{
		{reason: statuslist.ReasonSignerUntrusted, fn: failWith(fmt.Errorf("%w (https://status.example.org)", statuslist.ErrSignerUntrusted))},
		{reason: statuslist.ReasonTrustUnavailable, fn: failWith(fmt.Errorf("%w: pdp down", statuslist.ErrTrustUnavailable))},
		{reason: statuslist.ReasonNoSignerKey, fn: failWith(statuslist.ErrNoSignerKey)},
		{reason: statuslist.ReasonBudgetExhausted, fn: failWith(context.DeadlineExceeded)},
		{reason: statuslist.ReasonMalformed, fn: failWith(errors.New("anything unclassified"))},
		{reason: statuslist.ReasonMalformed, fn: func(context.Context, string) (*statuslist.VerifiedList, error) { return nil, nil }},
		{reason: statuslist.ReasonMalformed, fn: bad(func(v *statuslist.VerifiedList) { v.Bits = 3 })},
		{reason: statuslist.ReasonMalformed, fn: bad(func(v *statuslist.VerifiedList) { v.Lst = nil })},
		{reason: statuslist.ReasonMalformed, fn: bad(func(v *statuslist.VerifiedList) { v.ETag = "" })},
		{reason: statuslist.ReasonMalformed, fn: func(context.Context, string) (*statuslist.VerifiedList, error) { panic("boom") }},
		{reason: statuslist.ReasonTooLarge, fn: bad(func(v *statuslist.VerifiedList) { v.Lst = make([]byte, 33) }),
			mutate: func(sc *config.StatusCheckConfig) { sc.MaxListBytes = 32 }},
		{reason: statuslist.ReasonURINotAllowed, uri: "http://status.example.org/l", fn: bad(func(*statuslist.VerifiedList) {})},
		{reason: statuslist.ReasonURINotAllowed, uri: "https://user:pw@status.example.org/l", fn: bad(func(*statuslist.VerifiedList) {})},
		{reason: statuslist.ReasonURINotAllowed, uri: "https://status.example.org/l#frag", fn: bad(func(*statuslist.VerifiedList) {})},
		{reason: statuslist.ReasonURINotAllowed, uri: "https:///nohost", fn: bad(func(*statuslist.VerifiedList) {})},
		{reason: statuslist.ReasonURINotAllowed, uri: "ftp://status.example.org/l", fn: bad(func(*statuslist.VerifiedList) {})},
		{reason: statuslist.ReasonURINotAllowed, uri: "https://status.example.org/" + strings.Repeat("a", maxStatusURILength), fn: bad(func(*statuslist.VerifiedList) {})},
	}
	// Reasons raised inside statuslist.Checker are covered by
	// TestIntegration_StatusService_RealChecker below and statuslist's own tests.
	for i, tc := range cases {
		t.Run(fmt.Sprintf("%d_%s", i, tc.reason), func(t *testing.T) {
			svc, _ := newTestStatusService(&fakeLister{fn: tc.fn}, tc.mutate)
			uri := tc.uri
			if uri == "" {
				uri = testListURI
			}
			res, err := svc.Lists(context.Background(), "t", []StatusListRequest{{URI: uri}})
			if err != nil || len(res) != 1 {
				t.Fatalf("Lists = %+v, %v", res, err)
			}
			r := res[0]
			if r.State != StatusStateUndetermined || r.Reason != string(tc.reason) {
				t.Fatalf("state/reason = %q/%q, want undetermined/%s", r.State, r.Reason, tc.reason)
			}
			if r.Lst != "" || r.Bits != nil || r.IssuedAt != nil || r.ETag != "" || r.FreshUntil != nil || r.SignerTrust != "" {
				t.Fatalf("undetermined result carries list data: %+v", r)
			}
		})
	}
}

func TestStatusService_RequestValidation(t *testing.T) {
	l := &fakeLister{fn: func(context.Context, string) (*statuslist.VerifiedList, error) { return goodList(), nil }}
	svc, _ := newTestStatusService(l, func(sc *config.StatusCheckConfig) { sc.MaxListsPerRequest = 3 })
	ctx := context.Background()

	if _, err := svc.Lists(ctx, "t", nil); !errors.Is(err, ErrStatusInvalidRequest) {
		t.Fatalf("empty: %v", err)
	}
	if _, err := svc.Lists(ctx, "t", []StatusListRequest{{URI: ""}}); !errors.Is(err, ErrStatusInvalidRequest) {
		t.Fatalf("no uri: %v", err)
	}
	if _, err := svc.Lists(ctx, "t", []StatusListRequest{{URI: testListURI, ETag: strings.Repeat("x", maxStatusETagLength+1)}}); !errors.Is(err, ErrStatusInvalidRequest) {
		t.Fatalf("long etag: %v", err)
	}
	four := []StatusListRequest{{URI: "https://a/1"}, {URI: "https://a/2"}, {URI: "https://a/3"}, {URI: "https://a/4"}}
	if _, err := svc.Lists(ctx, "t", four); !errors.Is(err, ErrStatusTooManyLists) {
		t.Fatalf("over the cap: %v", err)
	}
	if len(l.uris) != 0 {
		t.Fatalf("a rejected request fetched %v", l.uris)
	}
	// At the cap is fine.
	if res, err := svc.Lists(ctx, "t", four[:3]); err != nil || len(res) != 3 {
		t.Fatalf("at the cap: %v, %v", res, err)
	}
}

func TestStatusService_DefaultCap(t *testing.T) {
	svc, _ := newTestStatusService(&fakeLister{}, nil)
	if svc.MaxLists() != config.DefaultStatusMaxListsPerRequest || svc.MaxLists() != 20 {
		t.Fatalf("default cap = %d, want 20", svc.MaxLists())
	}
}

func TestStatusService_DedupesAndKeepsOrder(t *testing.T) {
	l := &fakeLister{fn: func(context.Context, string) (*statuslist.VerifiedList, error) { return goodList(), nil }}
	svc, _ := newTestStatusService(l, nil)
	res, err := svc.Lists(context.Background(), "t", []StatusListRequest{
		{URI: "https://a/2", ETag: goodList().ETag}, {URI: "https://a/1"}, {URI: "https://a/2"}, {URI: "https://a/1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 2 || res[0].URI != "https://a/2" || res[1].URI != "https://a/1" {
		t.Fatalf("results = %+v, want one per distinct uri in first-occurrence order", res)
	}
	if res[0].State != StatusStateNotModified {
		t.Fatalf("the first occurrence's etag must count: %+v", res[0])
	}
	if len(l.uris) != 2 {
		t.Fatalf("fetched %v, want each distinct uri once", l.uris)
	}
}

func TestStatusService_PerRequestDeadline(t *testing.T) {
	l := &fakeLister{fn: func(ctx context.Context, uri string) (*statuslist.VerifiedList, error) {
		if strings.HasSuffix(uri, "/fast") {
			return goodList(), nil
		}
		<-ctx.Done() // a hung list host
		return nil, fmt.Errorf("status list load: %w", ctx.Err())
	}}
	svc, _ := newTestStatusService(l, nil)
	svc.timeout = 150 * time.Millisecond

	start := time.Now()
	res, err := svc.Lists(context.Background(), "t", []StatusListRequest{{URI: "https://a/slow1"}, {URI: "https://a/fast"}, {URI: "https://a/slow2"}})
	if err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("request took %v, the deadline is 150ms", d)
	}
	if res[0].Reason != string(statuslist.ReasonBudgetExhausted) || res[2].Reason != string(statuslist.ReasonBudgetExhausted) {
		t.Fatalf("hung lists: %+v / %+v", res[0], res[2])
	}
	if res[1].State != StatusStateVerified {
		t.Fatalf("a finished list is not lost to a slow one: %+v", res[1])
	}
}

// A fast list whose token expires while a slow list is still running must not
// be returned as verified or not_modified.
func TestStatusService_TokenExpiresWhileBatchWaits(t *testing.T) {
	l := &fakeLister{fn: func(_ context.Context, uri string) (*statuslist.VerifiedList, error) {
		vl := goodList()
		if strings.HasSuffix(uri, "/fast") {
			exp := time.Now().Add(50 * time.Millisecond)
			vl.ExpiresAt = &exp
			return vl, nil
		}
		time.Sleep(150 * time.Millisecond)
		return vl, nil
	}}
	svc, _ := newTestStatusService(l, nil)

	res, err := svc.Lists(context.Background(), "t", []StatusListRequest{
		{URI: "https://a/fast"}, {URI: "https://a/slow"}, {URI: "https://b/fast", ETag: goodList().ETag},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, i := range []int{0, 2} {
		r := res[i]
		if r.State != StatusStateUndetermined || r.Reason != string(statuslist.ReasonExpired) || r.Lst != "" || r.Bits != nil || r.ETag != "" || r.FreshUntil != nil {
			t.Fatalf("result %d = %+v, want undetermined/expired without list data", i, r)
		}
	}
	if res[1].State != StatusStateVerified {
		t.Fatalf("slow list with a long-lived token: %+v", res[1])
	}
}

func TestStatusService_DefaultDeadlineBelowWriteTimeout(t *testing.T) {
	svc, _ := newTestStatusService(&fakeLister{}, nil)
	if svc.timeout >= 15*time.Second || svc.timeout <= 0 {
		t.Fatalf("default deadline %v must be positive and well under the 15s write timeout", svc.timeout)
	}
}

// TestStatusService_LogsNoURI: only counts, outcomes and a duration are logged,
// never a URI (including from errors, which carry them).
func TestStatusService_LogsNoURI(t *testing.T) {
	l := &fakeLister{fn: func(_ context.Context, uri string) (*statuslist.VerifiedList, error) {
		if strings.HasSuffix(uri, "/bad") {
			return nil, fmt.Errorf("fetch status list: Get %q: connection refused", uri)
		}
		return goodList(), nil
	}}
	svc, logs := newTestStatusService(l, nil)
	uris := []string{"https://secret-issuer.example/lists/good", "https://secret-issuer.example/lists/bad"}
	if _, err := svc.Lists(context.Background(), "t", []StatusListRequest{{URI: uris[0]}, {URI: uris[1]}}); err != nil {
		t.Fatal(err)
	}
	if logs.Len() == 0 {
		t.Fatal("expected a summary log entry")
	}
	for _, e := range logs.All() {
		dump := e.Message + fmt.Sprint(e.ContextMap())
		if strings.Contains(dump, "secret-issuer") || strings.Contains(dump, "/lists/") {
			t.Fatalf("log entry leaks a list uri: %s", dump)
		}
	}
	e := logs.All()[0].ContextMap()
	if e["lists"] != int64(2) || e["verified"] != int64(1) || e["undetermined"] != int64(1) {
		t.Fatalf("summary = %v", e)
	}
}

func TestNewStatusService_DisabledIsNil(t *testing.T) {
	cfg := &config.Config{StatusCheck: config.StatusCheckConfig{Enabled: false}}
	if NewStatusService(cfg, nil, zap.NewNop()) != nil {
		t.Fatal("status_check.enabled=false must yield no service")
	}
	cfg.StatusCheck.Enabled = true
	if NewStatusService(cfg, nil, zap.NewNop()) == nil {
		t.Fatal("expected a service when enabled")
	}
}

// recordingEvaluator is a trust PDP stand-in.
type recordingEvaluator struct {
	decision bool
	err      error
	reqs     []*trust.EvaluationRequest
}

func (r *recordingEvaluator) Evaluate(_ context.Context, req *trust.EvaluationRequest) (*trust.EvaluationResponse, error) {
	r.reqs = append(r.reqs, req)
	if r.err != nil {
		return nil, r.err
	}
	return &trust.EvaluationResponse{Decision: r.decision}, nil
}
func (r *recordingEvaluator) Name() string                                 { return "recording" }
func (r *recordingEvaluator) SupportedResourceTypes() []trust.ResourceType { return nil }
func (r *recordingEvaluator) Healthy() bool                                { return true }

func newTrustSvc(t *testing.T, pdp string, ev trust.TrustEvaluator, logger *zap.Logger) *trust.Service {
	t.Helper()
	cfg := &config.Config{Trust: config.TrustConfig{Timeout: 10, PDPURL: pdp}}
	return trust.NewService(cfg, logger, func(string, time.Duration) (trust.TrustEvaluator, error) { return ev, nil })
}

func TestStatusSignerTrust(t *testing.T) {
	km := &trust.KeyMaterial{Type: "x5c", X5C: []string{"MIIB"}}
	ctx := trust.ContextWithTenant(context.Background(), "t")

	t.Run("positive reports the accepting action", func(t *testing.T) {
		fn := statusSignerTrust(newTrustSvc(t, "https://pdp", &recordingEvaluator{decision: true}, zap.NewNop()), true)
		ok, action, err := fn(ctx, "https://s.example", km)
		if !ok || err != nil || action != trust.StatusListSignerAction {
			t.Fatalf("= %v, %q, %v", ok, action, err)
		}
	})
	t.Run("negative is a plain negative", func(t *testing.T) {
		fn := statusSignerTrust(newTrustSvc(t, "https://pdp", &recordingEvaluator{decision: false}, zap.NewNop()), true)
		ok, _, err := fn(ctx, "https://s.example", km)
		if ok || err != nil {
			t.Fatalf("= %v, %v; want untrusted without error", ok, err)
		}
	})
	t.Run("no PDP is an error, not a negative", func(t *testing.T) {
		fn := statusSignerTrust(newTrustSvc(t, "", &recordingEvaluator{decision: true}, zap.NewNop()), true)
		if ok, _, err := fn(ctx, "https://s.example", km); ok || err == nil {
			t.Fatalf("= %v, %v; want an error", ok, err)
		}
	})
	t.Run("evaluation failure is an error, not a negative", func(t *testing.T) {
		fn := statusSignerTrust(newTrustSvc(t, "https://pdp", &recordingEvaluator{err: errors.New("down")}, zap.NewNop()), false)
		if ok, _, err := fn(ctx, "https://s.example", km); ok || err == nil {
			t.Fatalf("= %v, %v; want an error", ok, err)
		}
	})
	t.Run("nil trust service never trusts", func(t *testing.T) {
		if ok, _, err := statusSignerTrust(nil, true)(ctx, "https://s.example", km); ok || err == nil {
			t.Fatalf("= %v, %v", ok, err)
		}
	})
}

// reachProbe is a loopback server that records whether it was connected to
// (conns) and whether a request got as far as the handler (hits), so a test can
// tell which layer of the outbound policy stopped a fetch.
type reachProbe struct {
	srv   *httptest.Server
	conns atomic.Int32
	hits  atomic.Int32
}

func newReachProbe(t *testing.T, tls bool) *reachProbe {
	t.Helper()
	p := &reachProbe{}
	p.srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		p.hits.Add(1)
		w.WriteHeader(http.StatusNotFound)
	}))
	p.srv.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			p.conns.Add(1)
		}
	}
	if tls {
		p.srv.StartTLS()
	} else {
		p.srv.Start()
	}
	t.Cleanup(p.srv.Close)
	return p
}

// The status fetcher follows the operator's http_client policy like every
// other untrusted-URL fetch: strict by default, and each toggle relaxes
// exactly its own restriction and nothing else. The list is then still
// signature-verified and trust-evaluated (nil trust service here, so every
// list ends undetermined; what differs is how far the fetch got).
func TestNewStatusService_HonoursHTTPClientPolicy(t *testing.T) {
	tests := []struct {
		name string
		http config.HTTPClientConfig
		// Expected progress against a loopback http server and a loopback
		// self-signed TLS server.
		plainConn, tlsConn bool // a connection was made at all
		tlsHit             bool // a TLS request reached the handler (certificate accepted)
		allowsHTTPURI      bool
	}{
		{name: "default is strict"},
		{name: "allow_http alone keeps the address guard", http: config.HTTPClientConfig{AllowHTTP: true}, allowsHTTPURI: true},
		{name: "insecure_skip_verify alone keeps the address guard", http: config.HTTPClientConfig{InsecureSkipVerify: true}, allowsHTTPURI: true},
		{name: "allow_private_ips reaches private hosts but still verifies certificates", http: config.HTTPClientConfig{AllowPrivateIPs: true},
			plainConn: true, tlsConn: true, allowsHTTPURI: true},
		{name: "private plus insecure_skip_verify accepts the certificate", http: config.HTTPClientConfig{AllowPrivateIPs: true, InsecureSkipVerify: true},
			plainConn: true, tlsConn: true, tlsHit: true, allowsHTTPURI: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plain, tlsSrv := newReachProbe(t, false), newReachProbe(t, true)
			cfg := &config.Config{StatusCheck: config.StatusCheckConfig{Enabled: true}, HTTPClient: tt.http}
			svc := NewStatusService(cfg, nil, zap.NewNop())
			if svc.allowHTTP != tt.allowsHTTPURI {
				t.Fatalf("allowHTTP = %v, want %v", svc.allowHTTP, tt.allowsHTTPURI)
			}
			res, err := svc.Lists(context.Background(), "t", []StatusListRequest{
				{URI: plain.srv.URL + "/l/1"}, {URI: tlsSrv.srv.URL + "/l/2"},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, r := range res {
				if r.State != StatusStateUndetermined {
					t.Fatalf("result = %+v: a list from an unverifiable fetch must never be verified", r)
				}
			}
			if got := plain.conns.Load() > 0; got != tt.plainConn {
				t.Errorf("plain http server connected = %v, want %v", got, tt.plainConn)
			}
			if got := tlsSrv.conns.Load() > 0; got != tt.tlsConn {
				t.Errorf("TLS server connected = %v, want %v", got, tt.tlsConn)
			}
			if got := tlsSrv.hits.Load() > 0; got != tt.tlsHit {
				t.Errorf("TLS request reached handler = %v, want %v", got, tt.tlsHit)
			}
		})
	}
}

func TestStatusURIAllowed(t *testing.T) {
	for _, tt := range []struct {
		uri       string
		strict    bool
		allowHTTP bool
	}{
		{"https://status.example/l", true, true},
		{"http://status.example/l", false, true},
		{"ftp://status.example/l", false, false},
		{"https://user@status.example/l", false, false},
		{"https://status.example/l#f", false, false},
		{"https:///l", false, false},
		{"//status.example/l", false, false},
	} {
		if got := statusURIAllowed(tt.uri, false); got != tt.strict {
			t.Errorf("%q strict = %v, want %v", tt.uri, got, tt.strict)
		}
		if got := statusURIAllowed(tt.uri, true); got != tt.allowHTTP {
			t.Errorf("%q allowHTTP = %v, want %v", tt.uri, got, tt.allowHTTP)
		}
	}
}
