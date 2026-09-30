package api

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"log/slog"

	"bytes"
	"encoding/json"
	"github.com/go-jose/go-jose/v4"
	"github.com/sirosfoundation/go-wallet-backend/pkg/audit"
	"net/http"
	"net/http/httptest"
	"strings"
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
	client, err := r2ps.NewClient(srv.URL, r2ps.WithAllowPlaintext(true))
	if err != nil {
		t.Fatal(err)
	}
	handlers := NewAdminHandlers(store, logger, nil)
	handlers.SetR2PSClient(client)

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
		_, _ = w.Write([]byte(`{"category":"cat1","idx":3,"status":1,"label":"revoked","used":true}`))
	})
	defer cleanup()

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/admin/r2ps/status/cat1/3", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var got map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got["label"] != "revoked" || got["used"] != true {
		t.Errorf("label/used not passed through: %v", got)
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

func TestR2PSGetStatus_NegativeIndex_Returns400(t *testing.T) {
	_, router, cleanup := setupR2PSTestHandlers(t, func(w http.ResponseWriter, r *http.Request) {
		t.Error("upstream should not be called for a negative index")
	})
	defer cleanup()

	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/admin/r2ps/status/cat1/-1", nil))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestR2PSSetStatus_NegativeIndex_Returns400(t *testing.T) {
	_, router, cleanup := setupR2PSTestHandlers(t, func(w http.ResponseWriter, r *http.Request) {
		t.Error("upstream should not be called for a negative index")
	})
	defer cleanup()

	req := httptest.NewRequest(http.MethodPut, "/admin/r2ps/status/cat1/-1", bytes.NewBufferString(`{"status":1}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestR2PSSetStatus_MalformedJSON_ReportsInvalidBody(t *testing.T) {
	_, router, cleanup := setupR2PSTestHandlers(t, func(w http.ResponseWriter, r *http.Request) {
		t.Error("upstream should not be called for malformed JSON")
	})
	defer cleanup()

	req := httptest.NewRequest(http.MethodPut, "/admin/r2ps/status/cat1/3", bytes.NewBufferString(`{not json`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "invalid JSON request body") {
		t.Errorf("unexpected body: %s", w.Body.String())
	}
}

func TestR2PSSetStatus_Upstream404_Returns404(t *testing.T) {
	_, router, cleanup := setupR2PSTestHandlers(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	defer cleanup()

	req := httptest.NewRequest(http.MethodPut, "/admin/r2ps/status/cat1/3", bytes.NewBufferString(`{"status":1}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", w.Code, w.Body.String())
	}
}

func TestR2PSListStatuses_Upstream404_Returns404(t *testing.T) {
	_, router, cleanup := setupR2PSTestHandlers(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	defer cleanup()

	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/admin/r2ps/statuses/cat1", nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestR2PSSetStatus_EmitsAuditEvent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	var logBuf bytes.Buffer
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, nil)
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	auditor := audit.New("test-issuer", signer, logger)

	client, err := r2ps.NewClient(srv.URL, r2ps.WithAllowPlaintext(true))
	if err != nil {
		t.Fatal(err)
	}
	h := NewAdminHandlers(memory.NewStore(), zap.NewNop(), auditor)
	h.SetR2PSClient(client)
	router := gin.New()
	router.PUT("/admin/r2ps/status/:category/:idx", h.R2PSSetStatus)

	req := httptest.NewRequest(http.MethodPut, "/admin/r2ps/status/cat1/3", bytes.NewBufferString(`{"status":1,"reason":"key compromise"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(logBuf.String(), "urn:siros:audit:r2ps:status_changed") {
		t.Errorf("audit event not emitted; log: %s", logBuf.String())
	}
}
