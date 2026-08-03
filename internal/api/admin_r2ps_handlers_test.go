package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/storage/memory"
	"github.com/sirosfoundation/go-wallet-backend/pkg/r2ps"
)

func setupR2PSTestHandlers(t *testing.T, r2psHandler http.HandlerFunc) (*AdminHandlers, *gin.Engine, func()) {
	t.Helper()
	srv := httptest.NewServer(r2psHandler)

	logger := zap.NewNop()
	store := memory.NewStore()
	client := r2ps.NewClient(srv.URL)
	handlers := NewAdminHandlers(store, logger, client)

	router := gin.New()
	router.GET("/admin/r2ps/keys", handlers.R2PSListKeys)
	router.GET("/admin/r2ps/keys/:kid", handlers.R2PSGetKey)
	router.GET("/admin/r2ps/statuses/:category", handlers.R2PSListStatuses)
	router.GET("/admin/r2ps/status/:category/:idx", handlers.R2PSGetStatus)
	router.PUT("/admin/r2ps/status/:category/:idx", handlers.R2PSSetStatus)

	return handlers, router, srv.Close
}

func TestR2PSListKeys_Success(t *testing.T) {
	_, router, cleanup := setupR2PSTestHandlers(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"keys":[{"kid":"k1"}]}`))
	})
	defer cleanup()

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/admin/r2ps/keys", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestR2PSListKeys_UpstreamError(t *testing.T) {
	_, router, cleanup := setupR2PSTestHandlers(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	defer cleanup()

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/admin/r2ps/keys", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadGateway {
		t.Fatalf("expected 502, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if resp["error"] != errR2PSQueryFailed {
		t.Errorf("unexpected error message: %q", resp["error"])
	}
}

func TestR2PSGetKey_Success(t *testing.T) {
	_, router, cleanup := setupR2PSTestHandlers(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"kid":"k1"}`))
	})
	defer cleanup()

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/admin/r2ps/keys/k1", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestR2PSGetKey_NotFound(t *testing.T) {
	_, router, cleanup := setupR2PSTestHandlers(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	defer cleanup()

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/admin/r2ps/keys/k1", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", w.Code, w.Body.String())
	}
}

func TestR2PSGetKey_InvalidKID_Returns400(t *testing.T) {
	_, router, cleanup := setupR2PSTestHandlers(t, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("upstream should not be called for an invalid kid")
	})
	defer cleanup()

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/admin/r2ps/keys/..", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestR2PSListStatuses_Success(t *testing.T) {
	_, router, cleanup := setupR2PSTestHandlers(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"category":"cat1","count":0,"entries":[]}`))
	})
	defer cleanup()

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/admin/r2ps/statuses/cat1", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestR2PSListStatuses_UpstreamError(t *testing.T) {
	_, router, cleanup := setupR2PSTestHandlers(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	defer cleanup()

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/admin/r2ps/statuses/cat1", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadGateway {
		t.Fatalf("expected 502, got %d: %s", w.Code, w.Body.String())
	}
}

func TestR2PSGetStatus_Success(t *testing.T) {
	_, router, cleanup := setupR2PSTestHandlers(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"category":"cat1","idx":3,"status":0}`))
	})
	defer cleanup()

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/admin/r2ps/status/cat1/3", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestR2PSGetStatus_InvalidIndex(t *testing.T) {
	_, router, cleanup := setupR2PSTestHandlers(t, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("upstream should not be called for an invalid index")
	})
	defer cleanup()

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/admin/r2ps/status/cat1/notanumber", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestR2PSGetStatus_NotFound(t *testing.T) {
	_, router, cleanup := setupR2PSTestHandlers(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	defer cleanup()

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/admin/r2ps/status/cat1/3", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", w.Code, w.Body.String())
	}
}

func TestR2PSGetStatus_InvalidCategory_Returns400(t *testing.T) {
	_, router, cleanup := setupR2PSTestHandlers(t, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("upstream should not be called for an invalid category")
	})
	defer cleanup()

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/admin/r2ps/status/../3", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest && w.Code != http.StatusNotFound {
		t.Fatalf("expected 400 (or gin 404 for path escape), got %d: %s", w.Code, w.Body.String())
	}
}

func TestR2PSSetStatus_Success(t *testing.T) {
	_, router, cleanup := setupR2PSTestHandlers(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	defer cleanup()

	body := bytes.NewBufferString(`{"status":1,"reason":"testing"}`)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/admin/r2ps/status/cat1/3", body)
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestR2PSSetStatus_InvalidBody(t *testing.T) {
	_, router, cleanup := setupR2PSTestHandlers(t, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("upstream should not be called for an invalid body")
	})
	defer cleanup()

	body := bytes.NewBufferString(`{"status":99}`)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/admin/r2ps/status/cat1/3", body)
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestR2PSSetStatus_MissingStatus(t *testing.T) {
	_, router, cleanup := setupR2PSTestHandlers(t, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("upstream should not be called when status is missing")
	})
	defer cleanup()

	body := bytes.NewBufferString(`{"reason":"testing"}`)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/admin/r2ps/status/cat1/3", body)
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestR2PSSetStatus_InvalidIndex(t *testing.T) {
	_, router, cleanup := setupR2PSTestHandlers(t, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("upstream should not be called for an invalid index")
	})
	defer cleanup()

	body := bytes.NewBufferString(`{"status":1}`)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/admin/r2ps/status/cat1/notanumber", body)
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestR2PSSetStatus_UpstreamError(t *testing.T) {
	_, router, cleanup := setupR2PSTestHandlers(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	defer cleanup()

	body := bytes.NewBufferString(`{"status":1}`)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/admin/r2ps/status/cat1/3", body)
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadGateway {
		t.Fatalf("expected 502, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if resp["error"] != "failed to update R2PS status" {
		t.Errorf("unexpected error message: %q", resp["error"])
	}
}
