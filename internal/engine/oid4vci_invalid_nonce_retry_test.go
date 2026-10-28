package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// nonceIssuer is a credential endpoint (plus optional Nonce Endpoint) whose
// credential answers are scripted per request.
type nonceIssuer struct {
	srv *httptest.Server

	mu          sync.Mutex
	credReplies []string // body per credential request; "" = success; status 400 otherwise
	credCalls   int
	nonceCalls  int
}

func newNonceIssuer(t *testing.T, credReplies ...string) *nonceIssuer {
	t.Helper()
	ni := &nonceIssuer{credReplies: credReplies}
	mux := http.NewServeMux()
	mux.HandleFunc("/nonce", func(w http.ResponseWriter, r *http.Request) {
		ni.mu.Lock()
		ni.nonceCalls++
		n := ni.nonceCalls
		ni.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"c_nonce":"endpoint-nonce-%d"}`, n)
	})
	mux.HandleFunc("/credential", func(w http.ResponseWriter, r *http.Request) {
		ni.mu.Lock()
		i := ni.credCalls
		ni.credCalls++
		ni.mu.Unlock()
		reply := ""
		if i < len(ni.credReplies) {
			reply = ni.credReplies[i]
		}
		w.Header().Set("Content-Type", "application/json")
		if reply == "" {
			_, _ = w.Write([]byte(`{"credential":"c"}`))
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(reply))
	})
	ni.srv = httptest.NewServer(mux)
	t.Cleanup(ni.srv.Close)
	return ni
}

func (ni *nonceIssuer) metadata(withNonceEndpoint bool) *IssuerMetadata {
	m := &IssuerMetadata{CredentialIssuer: ni.srv.URL, CredentialEndpoint: ni.srv.URL + "/credential"}
	if withNonceEndpoint {
		m.NonceEndpoint = ni.srv.URL + "/nonce"
	}
	return m
}

// proofNonces returns the nonce of every generate_proof request the engine sent.
func proofNonces(t *testing.T, fc *fakeClient) []string {
	t.Helper()
	var out []string
	for _, m := range fc.outboundMessages() {
		var params struct {
			Action SignAction `json:"action"`
			Params struct {
				Nonce string `json:"nonce"`
			} `json:"params"`
		}
		raw, err := json.Marshal(m)
		require.NoError(t, err)
		require.NoError(t, json.Unmarshal(raw, &params))
		if params.Action == SignActionGenerateProof {
			out = append(out, params.Params.Nonce)
		}
	}
	return out
}

func runNonceRetry(t *testing.T, withEndpoint bool, replies ...string) (*nonceIssuer, *fakeClient, string, error) {
	t.Helper()
	ni := newNonceIssuer(t, replies...)
	fc := &fakeClient{t: t}
	h, logs, cleanup := newBlindHandler(t, fc, ni.srv.Client())
	defer cleanup()
	cfg := &CredentialConfig{Format: "vc+sd-jwt", ProofTypesSupported: map[string]interface{}{"jwt": map[string]interface{}{}}}
	tok := tokenBearer()
	tok.CNonce = "token-nonce"
	err := h.issueCredential(context.Background(), ni.metadata(withEndpoint), tok, "cfg", cfg, nil, "")
	return ni, fc, logDump(logs), err
}

// OpenID4VCI 1.0 section 8.3.1.2: invalid_nonce carries no c_nonce; the
// wallet gets a fresh one from the Nonce Endpoint and signs new proofs.
func TestIssueCredential_InvalidNonceWithoutCNonce_UsesNonceEndpoint(t *testing.T) {
	ni, fc, logs, err := runNonceRetry(t, true, `{"error":"invalid_nonce"}`, "")
	require.NoError(t, err)
	assert.Equal(t, 2, ni.credCalls)
	assert.Equal(t, 2, ni.nonceCalls, "initial nonce + one fresh nonce")
	assert.Equal(t, []string{"endpoint-nonce-1", "endpoint-nonce-2"}, proofNonces(t, fc), "new nonce => new proofs")
	assert.NotContains(t, logs, "endpoint-nonce")
}

func TestIssueCredential_InvalidNonceTwice_IsTerminal(t *testing.T) {
	ni, fc, _, err := runNonceRetry(t, true, `{"error":"invalid_nonce"}`, `{"error":"invalid_nonce"}`, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid_nonce")
	assert.Equal(t, 2, ni.credCalls, "exactly one retry, no loop")
	assert.Len(t, proofNonces(t, fc), 2)
}

func TestIssueCredential_OtherErrorIsNotRetried(t *testing.T) {
	for _, body := range []string{`{"error":"invalid_proof"}`, `{"error":"invalid_credential_request"}`, `not json`} {
		ni, _, _, err := runNonceRetry(t, true, body, "")
		require.Error(t, err, body)
		assert.Equal(t, 1, ni.credCalls, body)
		assert.Equal(t, 1, ni.nonceCalls, "only the initial nonce fetch: %s", body)
	}
}

// Older/draft issuers answer with a c_nonce in the body and no Nonce Endpoint.
func TestIssueCredential_LegacyCNonceBodyStillRetried(t *testing.T) {
	ni, fc, logs, err := runNonceRetry(t, false, `{"error":"invalid_nonce","c_nonce":"legacy-n2"}`, "")
	require.NoError(t, err)
	assert.Equal(t, 2, ni.credCalls)
	assert.Equal(t, []string{"token-nonce", "legacy-n2"}, proofNonces(t, fc))
	assert.NotContains(t, logs, "legacy-n2", "nonce values are never logged")
}

func TestIssueCredential_CNonceBodyWithoutInvalidNonceCodeStillRetried(t *testing.T) {
	ni, _, _, err := runNonceRetry(t, false, `{"error":"invalid_proof","c_nonce":"legacy-n2"}`, "")
	require.NoError(t, err)
	assert.Equal(t, 2, ni.credCalls)
}

func TestIssueCredential_InvalidNonceNoEndpointNoCNonce_IsTerminal(t *testing.T) {
	ni, fc, _, err := runNonceRetry(t, false, `{"error":"invalid_nonce"}`, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid_nonce")
	assert.Equal(t, 1, ni.credCalls)
	assert.Len(t, proofNonces(t, fc), 1)
}
