package engine

import (
	"net/http"
	"net/http/httptest"
	"sort"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sirosfoundation/go-wmp/pkg/wmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

// resolveEnv is a WMP session that negotiated resolve, against a type metadata
// registry whose answer the test chooses.
func resolveEnv(t *testing.T, registry http.HandlerFunc, mutate func(*config.Config)) func(uri string) reply {
	t.Helper()
	reg := httptest.NewServer(registry)
	t.Cleanup(reg.Close)
	cfg := &config.Config{}
	cfg.Trust.RegistryURL = reg.URL
	cfg.HTTPClient.AllowPrivateIPs = true // the registry is on loopback
	if mutate != nil {
		mutate(cfg)
	}
	e := newWMPEnvCfg(t, cfg)
	e.m.RegisterFlowHandler(ProtocolVCTM, NewVCTMHandler)
	tok := e.token("alice", "t1", "ir", "j1")
	sid := e.create(tok, "resolve")
	return func(uri string) reply {
		return e.post(tok, sid, req(wmp.MethodResolve, map[string]any{"wmp": meta(sid), "type": "vctm", "uri": uri}))
	}
}

func keysOf(m map[string]any) []string {
	var ks []string
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

// A found document is projected to the six members of the resolution (go-wmp's
// ProjectVCTM): vct, name, description, display, claims and schema, verbatim;
// every other member of the document is dropped, and a document without a vct
// gets the uri.
func TestWMPResolve_VCTMIsProjected(t *testing.T) {
	doc := `{"vct":"urn:example:id","name":"Example","description":"d","display":[{"lang":"en","name":"E"}],
	  "claims":[{"path":["given_name"]}],"schema":{"type":"object"},"extends":"urn:base","svg_templates":[{"uri":"x"}],"secret":"S"}`
	resolve := resolveEnv(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(doc)) }, nil)

	r := resolve("urn:example:id")
	require.Equal(t, 0, r.code(), "%v", r.Body)
	md := r.result()["metadata"].(map[string]any)
	assert.Equal(t, []string{"claims", "description", "display", "name", "schema", "vct"}, keysOf(md), "exactly the six")
	assert.Equal(t, []any{map[string]any{"lang": "en", "name": "E"}}, md["display"])
	assert.NotContains(t, r.result(), "trust_info")

	noVCT := resolveEnv(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{"name":"N"}`)) }, nil)
	md = noVCT("urn:example:other").result()["metadata"].(map[string]any)
	assert.Equal(t, "urn:example:other", md["vct"], "the uri when the document has none")
	assert.Equal(t, []string{"name", "vct"}, keysOf(md))
}

func requireFetchError(t *testing.T, r reply) {
	t.Helper()
	assert.Equal(t, wmp.ErrInternalError, r.code(), "%v", r.Body)
	assert.Equal(t, map[string]any{"reason": "metadata_fetch_error"}, r.errData(), "nothing of the failure")
	assert.NotContains(t, r.Body, "result", "an error, not a null metadata")
}

// A lookup that cannot produce a document is the -32603 error, never null: the
// registry failing, a document that is not an object, one that cannot be
// carried, and a registry miss for a URL that then cannot be fetched.
func TestWMPResolve_FailureIsMetadataFetchError(t *testing.T) {
	for name, tc := range map[string]struct {
		registry http.HandlerFunc
		uri      string
	}{
		"registry error": {func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "boom secret-1", 500) }, "urn:x"},
		"not json":       {func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("<html>")) }, "urn:x"},
		"array":          {func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`[1]`)) }, "urn:x"},
		"null":           {func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`null`)) }, "urn:x"},
		"name not a string": {func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"vct":"urn:x","name":5}`))
		}, "urn:x"},
		"registry miss, URL not fetchable": {func(w http.ResponseWriter, _ *http.Request) { http.NotFound(w, nil) }, "http://127.0.0.1:1/vct"},
	} {
		t.Run(name, func(t *testing.T) {
			r := resolveEnv(t, tc.registry, nil)(tc.uri)
			requireFetchError(t, r)
			assert.NotContains(t, r.Body["error"], "secret-1")
		})
	}
}

// null metadata is for a lookup that knows the type is unknown: the registry has
// no entry and the identifier is not a URL to try.
func TestWMPResolve_UnknownIsNull(t *testing.T) {
	r := resolveEnv(t, func(w http.ResponseWriter, _ *http.Request) { http.NotFound(w, nil) }, nil)("urn:example:unknown")
	require.Equal(t, 0, r.code(), "%v", r.Body)
	md, present := r.result()["metadata"]
	assert.True(t, present, "metadata is required")
	assert.Nil(t, md)
	assert.Equal(t, "vctm", r.result()["type"])
	assert.Equal(t, "urn:example:unknown", r.result()["uri"])
}

// The registry having no entry, or being unreachable, falls through to the URL.
func TestWMPResolve_FallsThroughToTheURL(t *testing.T) {
	var hits atomic.Int32
	vct := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte(`{"name":"From the URL","svg_templates":[1]}`))
	}))
	defer vct.Close()
	allow := func(c *config.Config) { c.HTTPClient.AllowHTTP = true }

	r := resolveEnv(t, func(w http.ResponseWriter, _ *http.Request) { http.NotFound(w, nil) }, allow)(vct.URL + "/type")
	require.Equal(t, 0, r.code(), "%v", r.Body)
	md := r.result()["metadata"].(map[string]any)
	assert.Equal(t, vct.URL+"/type", md["vct"])
	assert.Equal(t, "From the URL", md["name"])
	assert.NotContains(t, md, "svg_templates")

	// A registry error is a failed lookup: it does not fall through to the URL.
	before := hits.Load()
	r = resolveEnv(t, func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "x", 500) }, allow)(vct.URL + "/type")
	requireFetchError(t, r)
	assert.Equal(t, before, hits.Load())
}

// An empty uri is invalid params.
func TestWMPResolve_EmptyURIIsInvalidParams(t *testing.T) {
	r := resolveEnv(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{}`)) }, nil)("")
	assert.Equal(t, wmp.ErrInvalidParams, r.code(), "%v", r.Body)
}

// The egress policy is the HTTP client's: a loopback or private address is not
// fetched, and neither is a URL that is not HTTPS, unless the deployment is
// configured for local development. The same server is fetched when it is.
func TestWMPResolve_EgressPolicy(t *testing.T) {
	var hits atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte(`{"name":"internal"}`))
	}))
	defer target.Close()
	miss := func(w http.ResponseWriter, _ *http.Request) { http.NotFound(w, nil) }

	strict := func(c *config.Config) { c.HTTPClient = config.HTTPClientConfig{} } // no development switches
	r := resolveEnv(t, miss, strict)(target.URL + "/type")
	requireFetchError(t, r)
	assert.EqualValues(t, 0, hits.Load(), "a loopback address is not fetched")

	// Plain HTTP alone does not open the address policy.
	r = resolveEnv(t, miss, func(c *config.Config) { c.HTTPClient = config.HTTPClientConfig{AllowHTTP: true} })(target.URL + "/type")
	requireFetchError(t, r)
	assert.EqualValues(t, 0, hits.Load())

	// A public-looking plain HTTP URL is refused before any connection is made.
	start := time.Now()
	r = resolveEnv(t, miss, strict)("http://203.0.113.7/type")
	requireFetchError(t, r)
	assert.Less(t, time.Since(start), 3*time.Second, "refused, not dialled")

	r = resolveEnv(t, miss, func(c *config.Config) { c.HTTPClient = config.HTTPClientConfig{AllowPrivateIPs: true, AllowHTTP: true} })(target.URL + "/type")
	require.Equal(t, 0, r.code(), "%v", r.Body)
	assert.EqualValues(t, 1, hits.Load(), "development configuration reaches it")
}
