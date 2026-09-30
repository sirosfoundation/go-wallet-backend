package r2ps

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestIsValidPathSegment(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"", false},
		{".", false},
		{"..", false},
		{"foo", true},
		{"foo.bar", true},
		{"foo/bar", false},
		{"foo\\bar", false},
		{"..%2fadmin", false}, // percent-escaped slash: rejected too, since
		// net/url unescapes URL.Path and cannot distinguish this from a
		// literal "/" once decoded downstream.
		{"..%5cadmin", false}, // same for percent-escaped backslash
		{"100%", false},       // any literal "%" is rejected, not just traversal patterns
	}
	for _, tc := range cases {
		if got := isValidPathSegment(tc.in); got != tc.want {
			t.Errorf("isValidPathSegment(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestListStatuses_InvalidCategory(t *testing.T) {
	c := mustNewClient(t, "http://example.invalid")
	_, err := c.ListStatuses(context.Background(), "../secret")
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput, got %v", err)
	}
}

func TestListStatuses_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/admin/store/statuses/cat1" {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"category":"cat1","count":1,"entries":[{"idx":1,"status":0,"label":"ok"}]}`))
	}))
	defer srv.Close()

	c := mustNewClient(t, srv.URL)
	entries, err := c.ListStatuses(context.Background(), "cat1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 1 || entries[0].Idx != 1 {
		t.Errorf("unexpected entries: %+v", entries)
	}
}

func TestListStatuses_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := mustNewClient(t, srv.URL)
	_, err := c.ListStatuses(context.Background(), "cat1")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestListStatuses_DecodeError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("not json"))
	}))
	defer srv.Close()

	c := mustNewClient(t, srv.URL)
	_, err := c.ListStatuses(context.Background(), "cat1")
	if err == nil {
		t.Fatal("expected decode error")
	}
}

func TestGetClientStatuses(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/admin/store/clients/client-1/cat1" {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"client_id":"client-1","category":"cat1","indices":[{"idx":1,"status":0,"label":"valid"},{"idx":2,"status":1,"label":"revoked"},{"idx":3,"status":2,"label":"suspended"}]}`))
	}))
	defer srv.Close()

	c := mustNewClient(t, srv.URL)
	indices, err := c.GetClientStatuses(context.Background(), "client-1", "cat1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(indices) != 3 || indices[1].Idx != 2 || indices[1].Status != 1 || indices[1].Label != "revoked" {
		t.Errorf("unexpected indices: %+v", indices)
	}
}

func TestGetClientStatuses_InvalidClientID(t *testing.T) {
	c := mustNewClient(t, "http://example.invalid")
	_, err := c.GetClientStatuses(context.Background(), "../etc", "cat1")
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput, got %v", err)
	}
}

func TestGetClientStatuses_InvalidCategory(t *testing.T) {
	c := mustNewClient(t, "http://example.invalid")
	_, err := c.GetClientStatuses(context.Background(), "client-1", "../etc")
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput, got %v", err)
	}
}

func TestGetClientStatuses_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := mustNewClient(t, srv.URL)
	_, err := c.GetClientStatuses(context.Background(), "client-1", "cat1")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestGetClientStatuses_DecodeError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("not json"))
	}))
	defer srv.Close()

	c := mustNewClient(t, srv.URL)
	_, err := c.GetClientStatuses(context.Background(), "client-1", "cat1")
	if err == nil {
		t.Fatal("expected decode error")
	}
}

func TestGetStatus_InvalidCategory(t *testing.T) {
	c := mustNewClient(t, "http://example.invalid")
	_, err := c.GetStatus(context.Background(), "..", 1)
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput, got %v", err)
	}
}

func TestGetStatus_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/admin/store/status/cat1/5" {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"category":"cat1","idx":5,"status":1}`))
	}))
	defer srv.Close()

	c := mustNewClient(t, srv.URL)
	entry, err := c.GetStatus(context.Background(), "cat1", 5)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if entry == nil || entry.Index != 5 || entry.Status != 1 {
		t.Errorf("unexpected entry: %+v", entry)
	}
}

func TestGetStatus_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	c := mustNewClient(t, srv.URL)
	entry, err := c.GetStatus(context.Background(), "cat1", 5)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if entry != nil {
		t.Errorf("expected nil entry, got %+v", entry)
	}
}

func TestGetStatus_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := mustNewClient(t, srv.URL)
	_, err := c.GetStatus(context.Background(), "cat1", 5)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestGetStatus_DecodeError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("not json"))
	}))
	defer srv.Close()

	c := mustNewClient(t, srv.URL)
	_, err := c.GetStatus(context.Background(), "cat1", 5)
	if err == nil {
		t.Fatal("expected decode error")
	}
}

func TestSetStatus_InvalidCategory(t *testing.T) {
	c := mustNewClient(t, "http://example.invalid")
	err := c.SetStatus(context.Background(), "../etc", 1, 0)
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput, got %v", err)
	}
}

func TestSetStatus_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			t.Errorf("expected PUT, got %s", r.Method)
		}
		if r.URL.Path != "/admin/store/status/cat1/5" {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	c := mustNewClient(t, srv.URL)
	if err := c.SetStatus(context.Background(), "cat1", 5, 1); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSetStatus_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := mustNewClient(t, srv.URL)
	err := c.SetStatus(context.Background(), "cat1", 5, 1)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestListKeys(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/admin/store/keys" {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		if r.URL.Query().Get("client_id") != "client-1" {
			t.Errorf("expected client_id query param, got %q", r.URL.RawQuery)
		}
		_, _ = w.Write([]byte(`{"keys":[{"kid":"k1","curve":"P-256","pub_key":"abc","creation_time":1,"client_id":"client-1"}]}`))
	}))
	defer srv.Close()

	c := mustNewClient(t, srv.URL)
	keys, err := c.ListKeys(context.Background(), "client-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(keys) != 1 || keys[0].KID != "k1" {
		t.Errorf("unexpected keys: %+v", keys)
	}
}

func TestListKeys_NoFilter(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.RawQuery != "" {
			t.Errorf("expected no query, got %q", r.URL.RawQuery)
		}
		_, _ = w.Write([]byte(`{"keys":[]}`))
	}))
	defer srv.Close()

	c := mustNewClient(t, srv.URL)
	keys, err := c.ListKeys(context.Background(), "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(keys) != 0 {
		t.Errorf("expected no keys, got %+v", keys)
	}
}

func TestListKeys_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := mustNewClient(t, srv.URL)
	_, err := c.ListKeys(context.Background(), "")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestListKeys_DecodeError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("not json"))
	}))
	defer srv.Close()

	c := mustNewClient(t, srv.URL)
	_, err := c.ListKeys(context.Background(), "")
	if err == nil {
		t.Fatal("expected decode error")
	}
}

func TestGetKey_InvalidKID(t *testing.T) {
	c := mustNewClient(t, "http://example.invalid")
	_, err := c.GetKey(context.Background(), "../etc")
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput, got %v", err)
	}
}

func TestGetKey_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/admin/store/keys/k1" {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"kid":"k1","curve":"P-256","pub_key":"abc","creation_time":1,"client_id":"client-1"}`))
	}))
	defer srv.Close()

	c := mustNewClient(t, srv.URL)
	key, err := c.GetKey(context.Background(), "k1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if key == nil || key.KID != "k1" {
		t.Errorf("unexpected key: %+v", key)
	}
}

func TestGetKey_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	c := mustNewClient(t, srv.URL)
	key, err := c.GetKey(context.Background(), "k1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if key != nil {
		t.Errorf("expected nil key, got %+v", key)
	}
}

func TestGetKey_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := mustNewClient(t, srv.URL)
	_, err := c.GetKey(context.Background(), "k1")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestGetKey_DecodeError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("not json"))
	}))
	defer srv.Close()

	c := mustNewClient(t, srv.URL)
	_, err := c.GetKey(context.Background(), "k1")
	if err == nil {
		t.Fatal("expected decode error")
	}
}

func TestWithTimeout(t *testing.T) {
	c := mustNewClient(t, "http://example.invalid", WithTimeout(5*time.Second))
	if c.httpClient.Timeout != 5*time.Second {
		t.Errorf("expected timeout 5s, got %v", c.httpClient.Timeout)
	}
}

func TestDoGet_RequestFailure(t *testing.T) {
	c := mustNewClient(t, "http://127.0.0.1:0")
	_, err := c.doGet(context.Background(), c.buildURL("x"))
	if err == nil {
		t.Fatal("expected error")
	}
}

func mustNewClient(t *testing.T, baseURL string, opts ...ClientOption) *Client {
	t.Helper()
	c, err := NewClient(baseURL, append([]ClientOption{WithAllowPlaintext(true)}, opts...)...)
	if err != nil {
		t.Fatalf("NewClient(%q): %v", baseURL, err)
	}
	return c
}

func TestNewClient_BaseURLValidation(t *testing.T) {
	bad := []string{
		"", "r2ps:8444", "ftp://host", "http://", "https://", "https://user:pw@host",
		"https://host?x=1", "https://host#frag", "https://host?", "http://%zz",
	}
	for _, b := range bad {
		if _, err := NewClient(b, WithAllowPlaintext(true)); err == nil {
			t.Errorf("NewClient(%q): expected error", b)
		}
	}
	if _, err := NewClient("http://host:8444"); err == nil {
		t.Error("plaintext http must be rejected by default")
	}
	if _, err := NewClient("http://host:8444", WithAllowPlaintext(true)); err != nil {
		t.Errorf("plaintext http with allow: %v", err)
	}
	if _, err := NewClient("https://host:8444/base/"); err != nil {
		t.Errorf("https: %v", err)
	}
}

func TestWithHTTPClient(t *testing.T) {
	hc := &http.Client{Timeout: 3 * time.Second}
	c, err := NewClient("https://host", WithHTTPClient(hc))
	if err != nil || c.httpClient != hc {
		t.Fatalf("custom client not used: %v", err)
	}
	c, _ = NewClient("https://host", WithHTTPClient(nil))
	if c.httpClient == nil {
		t.Fatal("nil option must keep default client")
	}
}

func TestNegativeIdxAndBadStatus_Rejected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("upstream must not be called: %s", r.URL)
	}))
	defer srv.Close()
	c := mustNewClient(t, srv.URL)
	ctx := context.Background()
	if _, err := c.GetStatus(ctx, "cat", -1); !errors.Is(err, ErrInvalidInput) {
		t.Errorf("GetStatus(-1): %v", err)
	}
	if err := c.SetStatus(ctx, "cat", -1, 1); !errors.Is(err, ErrInvalidInput) {
		t.Errorf("SetStatus idx -1: %v", err)
	}
	if err := c.SetStatus(ctx, "cat", 1, 3); !errors.Is(err, ErrInvalidInput) {
		t.Errorf("SetStatus status 3: %v", err)
	}
	if err := c.SetStatus(ctx, "cat", 1, -1); !errors.Is(err, ErrInvalidInput) {
		t.Errorf("SetStatus status -1: %v", err)
	}
}

func TestIsValidPathSegment_Dangerous(t *testing.T) {
	for _, s := range []string{"", ".", "..", "a/b", `a\b`, "%2F", "%2f", "%5C", "..%2fadmin", "a?b", "a#b", "a\x00b", "a\nb", "a\x7fb", "a b", "a\tb"} {
		if isValidPathSegment(s) {
			t.Errorf("%q must be rejected", s)
		}
	}
	for _, s := range []string{"cat1", "wscd-key_1", "a.b", "abc123"} {
		if !isValidPathSegment(s) {
			t.Errorf("%q must be accepted", s)
		}
	}
}

func TestRequestsStayOnBaseHostAndPrefix(t *testing.T) {
	var got []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = append(got, r.URL.RequestURI())
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	c := mustNewClient(t, srv.URL+"/")
	ctx := context.Background()
	_, _ = c.ListKeys(ctx, "a&b=c d")
	_, _ = c.GetStatus(ctx, "cat", 7)
	if len(got) != 2 || got[0] != "/admin/store/keys?client_id=a%26b%3Dc+d" || got[1] != "/admin/store/status/cat/7" {
		t.Errorf("unexpected request URIs: %v", got)
	}
}

func TestBearerToken_SentOnEveryRequest(t *testing.T) {
	const tok = "s3cret-token"
	var methods []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+tok {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		methods = append(methods, r.Method)
		_, _ = w.Write([]byte(`{"keys":[],"entries":[],"indices":[]}`))
	}))
	defer srv.Close()

	c := mustNewClient(t, srv.URL, WithBearerToken("  "+tok+"\n"))
	ctx := context.Background()
	if _, err := c.ListKeys(ctx, ""); err != nil {
		t.Fatalf("ListKeys: %v", err)
	}
	if err := c.SetStatus(ctx, "cat", 1, 1); err != nil {
		t.Fatalf("SetStatus: %v", err)
	}
	if len(methods) != 2 {
		t.Fatalf("expected 2 authorized requests, got %v", methods)
	}

	// Without a token the fake server answers 401, and the token never
	// appears in the error text.
	anon := mustNewClient(t, srv.URL)
	err := anon.SetStatus(ctx, "cat", 1, 1)
	var se *StatusError
	if !errors.As(err, &se) || se.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 StatusError, got %v", err)
	}
	wrong := mustNewClient(t, srv.URL, WithBearerToken("other-secret"))
	if _, err := wrong.ListKeys(ctx, ""); err == nil || strings.Contains(err.Error(), "other-secret") {
		t.Fatalf("expected error without token text, got %v", err)
	}
}

func TestStatusError_NotFoundPreserved(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	c := mustNewClient(t, srv.URL)
	err := c.SetStatus(context.Background(), "cat", 1, 1)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
	var se *StatusError
	if !errors.As(err, &se) || se.StatusCode != 404 {
		t.Fatalf("expected StatusError 404, got %v", err)
	}
	if errors.Is(&StatusError{Op: "x", StatusCode: 500}, ErrNotFound) {
		t.Fatal("500 must not match ErrNotFound")
	}
	// GET single-item endpoints keep returning (nil, nil) on 404.
	if e, err := c.GetStatus(context.Background(), "cat", 1); e != nil || err != nil {
		t.Fatalf("GetStatus 404: %v %v", e, err)
	}
}
