package api

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
)

// pdpVerifierIDsReply is the raw PDP reply used by the verifier_ids
// passthrough tests. It is deliberately a JSON literal and not built from
// go-trust types: the point of these tests is to prove the proxy does not
// lose members of the PDP's context when it relays the reply to the wallet.
const pdpVerifierIDsReply = `{
  "decision": true,
  "context": {
    "id": "d1",
    "verifier_ids": [
      {"verifier_id_type": "semantic", "verifier_id": "VATSE-5560000001", "basis": "access_certificate"},
      {"verifier_id_type": "x509_san_dns", "verifier_id": "verifier.example.com", "basis": "x509_san_dns"}
    ]
  }
}`

// wantVerifierIDs is the verifier_ids member expected in the wallet-facing body.
var wantVerifierIDs = []interface{}{
	map[string]interface{}{"verifier_id_type": "semantic", "verifier_id": "VATSE-5560000001", "basis": "access_certificate"},
	map[string]interface{}{"verifier_id_type": "x509_san_dns", "verifier_id": "verifier.example.com", "basis": "x509_san_dns"},
}

// pdpCapture records the raw request body the PDP received.
type pdpCapture struct {
	mu   sync.Mutex
	body []byte
}

func (p *pdpCapture) handler(t *testing.T) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read PDP request: %v", err)
		}
		p.mu.Lock()
		p.body = b
		p.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(pdpVerifierIDsReply))
	})
}

func (p *pdpCapture) received(t *testing.T) map[string]interface{} {
	t.Helper()
	p.mu.Lock()
	defer p.mu.Unlock()
	var m map[string]interface{}
	if err := json.Unmarshal(p.body, &m); err != nil {
		t.Fatalf("PDP received unparsable body %q: %v", p.body, err)
	}
	return m
}

func assertVerifierIDsRelayed(t *testing.T, body []byte) {
	t.Helper()
	var got struct {
		Decision bool                   `json:"decision"`
		Context  map[string]interface{} `json:"context"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("wallet-facing body is not JSON: %v: %s", err, body)
	}
	if !got.Decision {
		t.Errorf("decision = false, want true: %s", body)
	}
	if got.Context["id"] != "d1" {
		t.Errorf("context.id = %v, want d1: %s", got.Context["id"], body)
	}
	if !reflect.DeepEqual(got.Context["verifier_ids"], wantVerifierIDs) {
		t.Errorf("context.verifier_ids was not relayed unchanged\n got: %#v\nwant: %#v\nbody: %s",
			got.Context["verifier_ids"], wantVerifierIDs, body)
	}
}

// TestEvaluate_RelaysContextVerifierIDs guards the wallet-facing /v1/evaluate
// proxy against dropping the PDP's context.verifier_ids member (go-trust
// authzen verifier_ids) and checks that the request-side context
// verifier_id_type hint reaches the PDP unchanged.
func TestEvaluate_RelaysContextVerifierIDs(t *testing.T) {
	pdp := &pdpCapture{}
	_, router, pdpServer := setupAuthZENProxyHandler(t, &mockAuthorizer{allowAll: true}, pdp.handler(t))
	defer pdpServer.Close()

	reqBody := `{"subject":{"type":"key","id":"https://verifier.example.com"},` +
		`"resource":{"type":"jwk","id":"https://verifier.example.com"},` +
		`"context":{"verifier_id_type":"x509_san_dns"}}`

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/evaluate", strings.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", w.Code, w.Body.String())
	}

	assertVerifierIDsRelayed(t, w.Body.Bytes())

	sent := pdp.received(t)
	ctxMember, _ := sent["context"].(map[string]interface{})
	if ctxMember["verifier_id_type"] != "x509_san_dns" {
		t.Errorf("PDP request context.verifier_id_type = %v, want x509_san_dns; PDP body: %v", ctxMember["verifier_id_type"], sent)
	}
}

// TestResolve_KeySubject_RelaysContextVerifierIDs covers /v1/resolve for a
// key subject, which proxies the PDP reply through the same typed path.
// /v1/resolve has no request-side context, so only the response is checked.
func TestResolve_KeySubject_RelaysContextVerifierIDs(t *testing.T) {
	pdp := &pdpCapture{}
	_, router, pdpServer := setupAuthZENProxyHandler(t, &mockAuthorizer{allowAll: true}, pdp.handler(t))
	defer pdpServer.Close()

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/resolve", strings.NewReader(`{"subject_id":"did:web:example.com","subject_type":"key"}`))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", w.Code, w.Body.String())
	}
	assertVerifierIDsRelayed(t, w.Body.Bytes())
}
