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

// Issuer free text (error_description) can repeat the nonce: it is never logged.
func TestIssueCredential_ErrorDescriptionNonceNotLogged(t *testing.T) {
	_, _, logs, err := runNonceRetry(t, false,
		`{"error":"invalid_nonce","error_description":"nonce secret-n2 has expired","c_nonce":"secret-n2"}`,
		`{"error":"invalid_nonce","error_description":"nonce secret-n3 expired","c_nonce":"secret-n3"}`)
	require.Error(t, err)
	assert.NotContains(t, logs, "secret-n")
	assert.Contains(t, logs, "invalid_nonce")
}

func TestSafeErrorCode(t *testing.T) {
	assert.Equal(t, "invalid_nonce", safeErrorCode("invalid_nonce"))
	assert.Equal(t, "", safeErrorCode(""))
	assert.Equal(t, "unrecognized", safeErrorCode("nonce abc expired"))
	assert.Equal(t, "unrecognized", safeErrorCode(string(make([]byte, 65))))
}

// A body that repeats a member, or spells one in another letter case, is read
// as encoding/json reads it (the last wins, names match without case): the
// retry decision follows that single reading and no reading is refused.
func TestIssueCredential_RepeatedOrFoldedMemberIsReadNormally(t *testing.T) {
	for name, tc := range map[string]struct {
		body         string
		withEndpoint bool
		retried      bool
	}{
		"invalid_nonce first, invalid_proof last": {`{"error":"invalid_nonce","error":"invalid_proof"}`, true, false},
		"invalid_proof first, invalid_nonce last": {`{"error":"invalid_proof","error":"invalid_nonce"}`, true, true},
		"repeated c_nonce, last used":             {`{"error":"invalid_nonce","c_nonce":"rep-n1","c_nonce":"rep-n2"}`, false, true},
		"folded C_Nonce":                          {`{"error":"invalid_proof","C_Nonce":"rep-n1"}`, false, true},
		"folded ERROR":                            {`{"ERROR":"invalid_nonce"}`, true, true},
	} {
		t.Run(name, func(t *testing.T) {
			ni, fc, logs, err := runNonceRetry(t, tc.withEndpoint, tc.body, "")
			assert.NotContains(t, logs, "rep-n")
			if !tc.retried {
				require.Error(t, err)
				assert.Equal(t, 1, ni.credCalls)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, 2, ni.credCalls)
			assert.Len(t, proofNonces(t, fc), 2, "new nonce => new proofs")
		})
	}
}

func countFlowErrors(fc *fakeClient) int {
	n := 0
	for _, m := range fc.outboundMessages() {
		if string(m["type"]) == `"flow_error"` {
			n++
		}
	}
	return n
}

// invalid_nonce-looking text next to a conflict code is still the conflict:
// terminal, reported once, never retried, and nothing of the text leaks.
func TestIssueCredential_ConflictWithInvalidNonceText_NotRetried(t *testing.T) {
	const body = `{"error":"auxiliary_data_conflict","error_description":"invalid_nonce SECRET-N","c_nonce":"conflict-n2"}`
	ni, fc, logs, err := runNonceRetry(t, true, body, "")
	require.Error(t, err)
	assert.Equal(t, 1, ni.credCalls)
	assert.Equal(t, 1, ni.nonceCalls, "no fresh nonce is fetched for a conflict")
	assert.Len(t, proofNonces(t, fc), 1)
	assert.NotContains(t, logs, "SECRET-N")
	assert.NotContains(t, logs, "conflict-n2")
	fc.settle()
	assert.Equal(t, 1, countFlowErrors(fc))
}

// The retry re-runs generate_proof, which is where the auxiliary data entries
// and the response-encryption offer travel: both must be sent again, the same.
func TestIssueCredential_InvalidNonceRetry_ResendsAuxiliaryDataAndEncryptionOffer(t *testing.T) {
	ni := newNonceIssuer(t, `{"error":"invalid_nonce"}`, `{"error":"auxiliary_data_conflict"}`)
	fc := &fakeClient{t: t}
	h, _, cleanup := newBlindHandler(t, fc, ni.srv.Client())
	defer cleanup()
	md := ni.metadata(true)
	md.CredentialResponseEncryption = gcmCfg(false)
	err := h.issueCredential(context.Background(), md, tokenBearer(), "cfg", auxCfg(auxAdvFull), nil, "")
	require.Error(t, err)
	assert.Equal(t, 2, ni.credCalls, "one retry; the conflict that answers it is final")

	var reqs []map[string]json.RawMessage
	for _, m := range fc.outboundMessages() {
		raw, jerr := json.Marshal(m)
		require.NoError(t, jerr)
		var env struct {
			Action SignAction                 `json:"action"`
			Params map[string]json.RawMessage `json:"params"`
		}
		require.NoError(t, json.Unmarshal(raw, &env))
		if env.Action == SignActionGenerateProof {
			reqs = append(reqs, env.Params)
		}
	}
	require.Len(t, reqs, 2)
	for i, p := range reqs {
		assert.JSONEq(t, `[`+auxToIssuerPSC+`]`, string(p["auxiliary_data_to_issuer"]), "request %d", i)
		assert.JSONEq(t, `[`+auxToWalletSSC+`]`, string(p["auxiliary_data_to_wallet"]), "request %d", i)
		assert.NotEmpty(t, p["credential_response_encryption"], "request %d", i)
	}
	assert.NotEqual(t, string(reqs[0]["nonce"]), string(reqs[1]["nonce"]))
}

// A c_nonce of the wrong type must not hide the error code: a conflict stays
// terminal, and an invalid_nonce still retries (with the Nonce Endpoint's nonce).
func TestIssueCredential_NonStringCNonce(t *testing.T) {
	ni, fc, logs, err := runNonceRetry(t, true, `{"error":"auxiliary_data_conflict","c_nonce":123,"error_description":"SECRET-N"}`, "")
	require.Error(t, err)
	assert.Equal(t, 1, ni.credCalls, "a conflict is never retried")
	assert.NotContains(t, logs, "SECRET-N")
	fc.settle()
	assert.Equal(t, 1, countFlowErrors(fc))

	ni, _, _, err = runNonceRetry(t, true, `{"error":"invalid_nonce","c_nonce":123}`, "")
	require.NoError(t, err)
	assert.Equal(t, 2, ni.credCalls)
}
