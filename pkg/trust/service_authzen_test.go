package trust_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
	"github.com/sirosfoundation/go-wallet-backend/pkg/trust"
	"github.com/sirosfoundation/go-wallet-backend/pkg/trust/authzen"
)

// These tests drive EvaluateStatusListSigner through the real AuthZEN adapter
// against an httptest PDP, so they cover the in-band failure reporting that a
// fake evaluator returning Go errors cannot.
func authzenService(t *testing.T, url string) *trust.Service {
	t.Helper()
	cfg := &config.Config{Trust: config.TrustConfig{Timeout: 5, PDPURL: url}}
	return trust.NewService(cfg, zap.NewNop(), func(endpoint string, _ time.Duration) (trust.TrustEvaluator, error) {
		return authzen.NewEvaluator(&authzen.Config{BaseURL: endpoint, Timeout: 2 * time.Second})
	})
}

// pdp answers by action name: the map value is the HTTP status, 0 = allow,
// -1 = deny.
func pdp(t *testing.T, byAction map[string]int, calls *[]string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Action struct {
				Name string `json:"name"`
			} `json:"action"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		*calls = append(*calls, req.Action.Name)
		switch st := byAction[req.Action.Name]; st {
		case 0, -1:
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"decision": st == 0})
		default:
			http.Error(w, "boom", st)
		}
	}))
}

var km = &trust.KeyMaterial{Type: "x5c", X5C: []string{"AA"}}

func TestAuthZENAdapter_StatusListSigner(t *testing.T) {
	sl, ci := trust.StatusListSignerAction, trust.StatusListSignerFallbackAction
	cases := []struct {
		name        string
		pdp         map[string]int
		fallback    bool
		wantTrusted bool
		wantAction  string
		wantFailed  bool
		wantCalls   []string
	}{
		{"500 then issuer allows: fallback", map[string]int{sl: 500, ci: 0}, true, true, ci, false, []string{sl, ci}},
		{"500 with fallback disabled: failure stands", map[string]int{sl: 500, ci: 0}, false, false, "", true, []string{sl}},
		{"500 on both: failure", map[string]int{sl: 500, ci: 500}, true, false, "", true, []string{sl, ci}},
		{"500 then issuer denies: final deny", map[string]int{sl: 500, ci: -1}, true, false, "", false, []string{sl, ci}},
		{"genuine deny is final, no fallback", map[string]int{sl: -1, ci: 0}, true, false, "", false, []string{sl}},
		{"allow", map[string]int{sl: 0}, true, true, sl, false, []string{sl}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var calls []string
			srv := pdp(t, tc.pdp, &calls)
			defer srv.Close()
			info, err := authzenService(t, srv.URL).EvaluateStatusListSigner(context.Background(), "https://s", "", km, tc.fallback)
			if err != nil {
				t.Fatal(err)
			}
			if info.Trusted != tc.wantTrusted || info.Action != tc.wantAction || info.EvaluationFailed != tc.wantFailed {
				t.Fatalf("got trusted=%v action=%q failed=%v (%s)", info.Trusted, info.Action, info.EvaluationFailed, info.Reason)
			}
			if len(calls) != len(tc.wantCalls) {
				t.Fatalf("calls = %v, want %v", calls, tc.wantCalls)
			}
			for i := range calls {
				if calls[i] != tc.wantCalls[i] {
					t.Fatalf("calls = %v, want %v", calls, tc.wantCalls)
				}
			}
		})
	}
}

func TestAuthZENAdapter_StatusListSigner_Unreachable(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL
	srv.Close() // nothing listens any more
	info, err := authzenService(t, url).EvaluateStatusListSigner(context.Background(), "https://s", "", km, true)
	if err != nil || info.Trusted || !info.EvaluationFailed {
		t.Fatalf("unreachable PDP must be an evaluation failure: %+v, %v", info, err)
	}
}
