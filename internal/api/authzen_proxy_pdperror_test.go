package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestPDPErrorMapping verifies that a PDP client error (4xx) is surfaced to the
// caller as a client error with the PDP's body, while genuine upstream
// failures remain 502/504. Covers /v1/evaluate, /v1/resolve (key subject
// proxied to the PDP) and /v1/resolve (url subject, trust evaluation step).
func TestPDPErrorMapping(t *testing.T) {
	longBody := `{"error":"` + strings.Repeat("x", 5000) + `"}`

	cases := []struct {
		name       string
		pdpStatus  int
		pdpBody    string
		sleep      time.Duration
		wantStatus int
		wantError  string // expected top-level "error"; "" = skip
		wantDetail bool
	}{
		{"400 json passthrough", 400, `{"error":"resource.id must match subject.id"}`, 0, 400, "resource.id must match subject.id", true},
		{"422 passthrough", 422, `{"error":"bad action","field":"action.name"}`, 0, 422, "bad action", true},
		{"400 non-json body", 400, `plain text problem`, 0, 400, "trust evaluation request rejected by PDP", true},
		{"400 oversized body bounded", 400, longBody, 0, 400, "trust evaluation request rejected by PDP", true},
		{"500 stays 502", 500, `{"error":"boom internal detail"}`, 0, 502, "unavailable", false},
		{"401 from PDP is proxy config, 502", 401, `{"error":"no creds"}`, 0, 502, "unavailable", false},
		{"429 from PDP stays 502", 429, ``, 0, 502, "unavailable", false},
		{"timeout is 504", 200, `{"decision":true}`, 3 * time.Second, 504, "timed out", false},
	}

	endpoints := []struct {
		name string
		path string
		body string
	}{
		{"evaluate", "/v1/evaluate", `{"subject":{"type":"key","id":"abc"},"resource":{"type":"jwk","id":"abc"}}`},
		{"resolve-key", "/v1/resolve", `{"subject_id":"did:web:example.com"}`},
		{"resolve-url", "/v1/resolve", `{"subject_id":"https://issuer.example.com","subject_type":"url"}`},
	}

	for _, ep := range endpoints {
		for _, tc := range cases {
			t.Run(ep.name+"/"+tc.name, func(t *testing.T) {
				pdp := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if tc.sleep > 0 {
						select {
						case <-time.After(tc.sleep):
						case <-r.Context().Done():
						}
						return
					}
					w.WriteHeader(tc.pdpStatus)
					_, _ = w.Write([]byte(tc.pdpBody))
				})
				h, router, srv := setupAuthZENProxyHandler(t, &mockAuthorizer{allowAll: true}, pdp)
				defer srv.Close()
				h.cfg.Timeout = 1

				w := httptest.NewRecorder()
				req := httptest.NewRequest(http.MethodPost, ep.path, strings.NewReader(ep.body))
				req.Header.Set("Content-Type", "application/json")
				router.ServeHTTP(w, req)

				if w.Code != tc.wantStatus {
					t.Fatalf("status = %d, want %d: %s", w.Code, tc.wantStatus, w.Body.String())
				}
				var got map[string]interface{}
				if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
					t.Fatalf("body not JSON: %v: %s", err, w.Body.String())
				}
				if tc.wantError != "" {
					e, _ := got["error"].(string)
					if !strings.Contains(e, tc.wantError) {
						t.Errorf("error = %q, want contains %q", e, tc.wantError)
					}
				}
				_, hasDetail := got["details"]
				if hasDetail != tc.wantDetail {
					t.Errorf("details present = %v, want %v (%s)", hasDetail, tc.wantDetail, w.Body.String())
				}
				if tc.wantStatus >= 500 && strings.Contains(w.Body.String(), "boom internal detail") {
					t.Errorf("upstream 5xx body leaked: %s", w.Body.String())
				}
				if w.Body.Len() > 4*maxPDPErrorBodyBytes {
					t.Errorf("response not bounded: %d bytes", w.Body.Len())
				}
				if tc.wantStatus == 422 && got["field"] == nil {
					if d, ok := got["details"].(map[string]interface{}); !ok || d["field"] != "action.name" {
						t.Errorf("structured PDP body not preserved: %s", w.Body.String())
					}
				}
			})
		}
	}
}
