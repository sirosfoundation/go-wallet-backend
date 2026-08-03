package r2ps

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
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
		{"..%2fadmin", true}, // percent-escaped, not a literal slash
	}
	for _, tc := range cases {
		if got := isValidPathSegment(tc.in); got != tc.want {
			t.Errorf("isValidPathSegment(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestListStatuses_InvalidCategory(t *testing.T) {
	c := NewClient("http://example.invalid")
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

	c := NewClient(srv.URL)
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

	c := NewClient(srv.URL)
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

	c := NewClient(srv.URL)
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
		_, _ = w.Write([]byte(`{"indices":[1,2,3]}`))
	}))
	defer srv.Close()

	c := NewClient(srv.URL)
	indices, err := c.GetClientStatuses(context.Background(), "client-1", "cat1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(indices) != 3 {
		t.Errorf("unexpected indices: %+v", indices)
	}
}

func TestGetClientStatuses_InvalidClientID(t *testing.T) {
	c := NewClient("http://example.invalid")
	_, err := c.GetClientStatuses(context.Background(), "../etc", "cat1")
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput, got %v", err)
	}
}

func TestGetClientStatuses_InvalidCategory(t *testing.T) {
	c := NewClient("http://example.invalid")
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

	c := NewClient(srv.URL)
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

	c := NewClient(srv.URL)
	_, err := c.GetClientStatuses(context.Background(), "client-1", "cat1")
	if err == nil {
		t.Fatal("expected decode error")
	}
}

func TestGetStatus_InvalidCategory(t *testing.T) {
	c := NewClient("http://example.invalid")
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

	c := NewClient(srv.URL)
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

	c := NewClient(srv.URL)
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

	c := NewClient(srv.URL)
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

	c := NewClient(srv.URL)
	_, err := c.GetStatus(context.Background(), "cat1", 5)
	if err == nil {
		t.Fatal("expected decode error")
	}
}

func TestSetStatus_InvalidCategory(t *testing.T) {
	c := NewClient("http://example.invalid")
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

	c := NewClient(srv.URL)
	if err := c.SetStatus(context.Background(), "cat1", 5, 1); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSetStatus_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := NewClient(srv.URL)
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

	c := NewClient(srv.URL)
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

	c := NewClient(srv.URL)
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

	c := NewClient(srv.URL)
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

	c := NewClient(srv.URL)
	_, err := c.ListKeys(context.Background(), "")
	if err == nil {
		t.Fatal("expected decode error")
	}
}

func TestGetKey_InvalidKID(t *testing.T) {
	c := NewClient("http://example.invalid")
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

	c := NewClient(srv.URL)
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

	c := NewClient(srv.URL)
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

	c := NewClient(srv.URL)
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

	c := NewClient(srv.URL)
	_, err := c.GetKey(context.Background(), "k1")
	if err == nil {
		t.Fatal("expected decode error")
	}
}

func TestWithTimeout(t *testing.T) {
	c := NewClient("http://example.invalid", WithTimeout(5))
	if c.httpClient.Timeout != 5 {
		t.Errorf("expected timeout 5, got %v", c.httpClient.Timeout)
	}
}

func TestDoGet_RequestFailure(t *testing.T) {
	c := NewClient("http://127.0.0.1:0")
	_, err := c.doGet(context.Background(), c.baseURL+"/x")
	if err == nil {
		t.Fatal("expected error")
	}
}
