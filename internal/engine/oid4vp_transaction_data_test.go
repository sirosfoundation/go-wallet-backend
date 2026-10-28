package engine

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"hash"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
	"github.com/sirosfoundation/go-wallet-backend/pkg/trust"
)

// payDCQL is a DCQL query with the credential "pay" that the test entries are bound to.
var payDCQL = json.RawMessage(`{"credentials":[{"id":"pay","format":"dc+sd-jwt","meta":{"vct_values":["x"]}}]}`)

// tdClient is a client that declared FeatureTransactionDataV1.
var tdClient = &FlowStartMessage{Features: []string{FeatureTransactionDataV1}}

type tdVector struct {
	Name         string            `json:"name"`
	Note         string            `json:"note"`
	JSON         string            `json:"json"`
	Raw          string            `json:"raw"`
	Noncanonical bool              `json:"noncanonical"`
	Hashes       map[string]string `json:"hashes"`
}

// loadTDVectors reads the shared golden vectors. The hashes in the file were
// computed with Python's hashlib over the ASCII bytes of `raw`, so agreement
// with Go's crypto here is agreement between two independent implementations,
// not a function checking itself.
func loadTDVectors(t *testing.T) []tdVector {
	t.Helper()
	b, err := os.ReadFile("testdata/ts12/transaction_data_vectors.json")
	require.NoError(t, err)
	var f struct {
		Vectors []tdVector `json:"vectors"`
	}
	require.NoError(t, json.Unmarshal(b, &f))
	require.NotEmpty(t, f.Vectors)
	return f.Vectors
}

func tdHash(t *testing.T, alg string) hash.Hash {
	t.Helper()
	switch alg {
	case "sha-256":
		return sha256.New()
	case "sha-384":
		return sha512.New384()
	case "sha-512":
		return sha512.New()
	}
	t.Fatalf("unknown alg %q", alg)
	return nil
}

func hashOf(t *testing.T, alg, in string) string {
	h := tdHash(t, alg)
	h.Write([]byte(in))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

func rawArray(t *testing.T, entries ...string) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(entries)
	require.NoError(t, err)
	return b
}

// --- Golden vectors ---

// The vector file itself must be internally consistent: raw decodes to json,
// and every hash is what Go computes over raw as received.
func TestTransactionDataVectors_Consistent(t *testing.T) {
	for _, v := range loadTDVectors(t) {
		t.Run(v.Name, func(t *testing.T) {
			dec, err := base64.RawURLEncoding.DecodeString(v.Raw)
			require.NoError(t, err)
			assert.Equal(t, v.JSON, string(dec))
			for alg, want := range v.Hashes {
				assert.Equal(t, want, hashOf(t, alg, v.Raw), alg)
			}
		})
	}
}

// decodeTransactionData must hand back each entry exactly as the verifier sent
// it. This is what a presentation has to hash, and it is the property a
// decode-then-re-encode design cannot have.
func TestDecodeTransactionData_PreservesRawStringExactly(t *testing.T) {
	for _, v := range loadTDVectors(t) {
		t.Run(v.Name, func(t *testing.T) {
			entries, err := decodeTransactionData(rawArray(t, v.Raw))
			require.NoError(t, err)
			require.Len(t, entries, 1)
			assert.Equal(t, v.Raw, entries[0].Raw)
			assert.Equal(t, "urn:eudi:sca:payment:1", entries[0].Data.Type)
		})
	}
}

// Documents why the raw string is carried and not re-derived: re-serializing
// the decoded object (the only thing a client gets today) does not reproduce
// the hash for any non-canonical entry. sorted_compact is the control: the one
// shape a re-serializer happens to reproduce, which shows the comparison can
// pass and is not vacuously failing.
func TestTransactionDataReserializationDoesNotReproduceHash(t *testing.T) {
	for _, v := range loadTDVectors(t) {
		t.Run(v.Name, func(t *testing.T) {
			var generic map[string]any
			require.NoError(t, json.Unmarshal([]byte(v.JSON), &generic))
			reencoded, err := json.Marshal(generic)
			require.NoError(t, err)
			got := hashOf(t, "sha-256", base64.RawURLEncoding.EncodeToString(reencoded))
			if v.Noncanonical {
				assert.NotEqual(t, v.Hashes["sha-256"], got,
					"re-serialization reproduced the hash; the vector no longer demonstrates the problem")
			} else {
				assert.Equal(t, v.Hashes["sha-256"], got, "control vector should survive re-serialization")
			}
		})
	}
}

// --- hash algorithm member (B7) ---

func TestHashAlgList_Unmarshal(t *testing.T) {
	cases := map[string]struct {
		in   string
		want HashAlgList
		err  bool
	}{
		"array (OID4VP 1.0 request form)": {`["sha-256","sha-384"]`, HashAlgList{"sha-256", "sha-384"}, false},
		"bare string tolerated":           {`"sha-384"`, HashAlgList{"sha-384"}, false},
		// OID4VP: a non-empty array of algorithm identifiers. An empty list
		// leaves the wallet nothing valid to choose, so it is invalid, not "absent".
		"empty array rejected":         {`[]`, nil, true},
		"null rejected":                {`null`, nil, true},
		"empty string rejected":        {`""`, nil, true},
		"empty name in array rejected": {`["sha-256",""]`, nil, true},
		"number rejected":              {`5`, nil, true},
		"array of numbers rejected":    {`[1,2]`, nil, true},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			var got HashAlgList
			err := json.Unmarshal([]byte(c.in), &got)
			if c.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, c.want, got)
		})
	}
}

// A verifier following the specification sends the array. Before the fix this
// failed to unmarshal and the whole request was rejected as invalid JSON.
func TestDecodeTransactionData_AcceptsHashAlgArrayAndString(t *testing.T) {
	byName := map[string]tdVector{}
	for _, v := range loadTDVectors(t) {
		byName[v.Name] = v
	}
	arr, err := decodeTransactionData(rawArray(t, byName["hash_alg_array"].Raw))
	require.NoError(t, err)
	assert.Equal(t, HashAlgList{"sha-256", "sha-384"}, arr[0].Data.TransactionDataHashesAlg)

	str, err := decodeTransactionData(rawArray(t, byName["hash_alg_string"].Raw))
	require.NoError(t, err)
	assert.Equal(t, HashAlgList{"sha-384"}, str[0].Data.TransactionDataHashesAlg)
}

func TestDecodeTransactionData_MalformedAlgIsAStructuralError(t *testing.T) {
	enc := base64.RawURLEncoding.EncodeToString([]byte(`{"type":"x","transaction_data_hashes_alg":7}`))
	_, err := decodeTransactionData(rawArray(t, enc))
	require.Error(t, err)
	var tdErr *transactionDataError
	require.True(t, errors.As(err, &tdErr))
	assert.Equal(t, ErrCodeInvalidMessage, tdErr.code)
	assert.Contains(t, err.Error(), "invalid JSON")
}

// --- Support gate ---

func owfRaw(t *testing.T) json.RawMessage {
	t.Helper()
	enc := base64.RawURLEncoding.EncodeToString([]byte(`{"type":"owf_payment_initiation","credential_ids":["pay"]}`))
	return rawArray(t, enc)
}

func TestValidateTransactionData_RefusesClientThatDidNotDeclareSupport(t *testing.T) {
	for name, msg := range map[string]*FlowStartMessage{
		"nil message":         nil,
		"no features":         {},
		"unrelated feature":   {Features: []string{"something_else"}},
		"lookalike (version)": {Features: []string{"transaction_data.v2"}},
	} {
		t.Run(name, func(t *testing.T) {
			authReq := &AuthorizationRequest{TransactionDataRaw: owfRaw(t), DCQLQuery: payDCQL}
			err := validateTransactionData(authReq, msg)
			require.Error(t, err)
			var tdErr *transactionDataError
			require.True(t, errors.As(err, &tdErr))
			assert.Equal(t, ErrCodeUnsupportedTransactionData, tdErr.code)
			assert.Empty(t, authReq.TransactionData, "nothing may be forwarded to a client that cannot honour it")
		})
	}
}

func TestValidateTransactionData_AcceptsDeclaringClient(t *testing.T) {
	authReq := &AuthorizationRequest{TransactionDataRaw: owfRaw(t), DCQLQuery: payDCQL}
	require.NoError(t, validateTransactionData(authReq, tdClient))
	require.Len(t, authReq.TransactionData, 1)
}

// Behaviour for requests WITHOUT transaction_data must be untouched for every
// client, declaring or not: this is the backward-compatibility guarantee.
func TestValidateTransactionData_NoTransactionDataIsUnaffectedByDeclaration(t *testing.T) {
	for name, msg := range map[string]*FlowStartMessage{"nil": nil, "none": {}, "declared": tdClient} {
		t.Run(name, func(t *testing.T) {
			assert.NoError(t, validateTransactionData(&AuthorizationRequest{}, msg))
		})
	}
}

func TestValidateTransactionData_StructuralErrorsKeepGenericCode(t *testing.T) {
	err := validateTransactionData(&AuthorizationRequest{TransactionDataRaw: json.RawMessage(`null`)}, tdClient)
	var tdErr *transactionDataError
	require.True(t, errors.As(err, &tdErr))
	assert.Equal(t, ErrCodeInvalidMessage, tdErr.code)
}

// --- Step 1: structural validation, raw and payload carried to the client ---

func entry(t *testing.T, jsonText string) string {
	t.Helper()
	return base64.RawURLEncoding.EncodeToString([]byte(jsonText))
}

func TestValidateTransactionData_AcceptsTS12TypesForDeclaringClient(t *testing.T) {
	for _, v := range loadTDVectors(t) {
		t.Run(v.Name, func(t *testing.T) {
			authReq := &AuthorizationRequest{TransactionDataRaw: rawArray(t, v.Raw), DCQLQuery: payDCQL}
			require.NoError(t, validateTransactionData(authReq, tdClient))
			require.Len(t, authReq.TransactionData, 1)
			got := authReq.TransactionData[0]
			assert.Equal(t, "urn:eudi:sca:payment:1", got.Type)
			assert.Equal(t, []string{"pay"}, got.CredentialIDs)
			assert.Equal(t, v.Raw, got.Raw, "the string the verifier sent, byte for byte")
			assert.NotEmpty(t, got.Payload)
		})
	}
}

// A verifier controls the JSON it encodes, so it can put a `raw` member in it.
// Raw must still be the string that was received, not whatever the JSON says.
func TestDecodeTransactionData_RawMemberInVerifierJSONIsIgnored(t *testing.T) {
	enc := entry(t, `{"type":"x","credential_ids":["c"],"raw":"AAAA-attacker-chosen"}`)
	entries, err := decodeTransactionData(rawArray(t, enc))
	require.NoError(t, err)
	assert.Equal(t, enc, entries[0].Raw)
	assert.Equal(t, enc, entries[0].Data.Raw)
}

// A `raw` member of another type is ignored too, not a reason to reject an
// otherwise valid entry.
func TestDecodeTransactionData_NonStringRawMemberIsIgnored(t *testing.T) {
	for _, member := range []string{`{}`, `7`, `null`, `["x"]`} {
		enc := entry(t, `{"type":"x","credential_ids":["c"],"raw":`+member+`}`)
		entries, err := decodeTransactionData(rawArray(t, enc))
		require.NoError(t, err, member)
		assert.Equal(t, enc, entries[0].Data.Raw)
	}
}

func TestValidateTransactionData_StructuralChecks(t *testing.T) {
	dcql := json.RawMessage(`{"credentials":[{"id":"pay"},{"id":"age"}]}`)
	cases := map[string]struct {
		entry string
		dcql  json.RawMessage
		want  string
	}{
		"missing type":           {`{"credential_ids":["pay"]}`, dcql, "missing type"},
		"no credential_ids":      {`{"type":"x"}`, dcql, "credential_ids must be a non-empty array"},
		"empty credential_ids":   {`{"type":"x","credential_ids":[]}`, dcql, "credential_ids must be a non-empty array"},
		"id not in dcql":         {`{"type":"x","credential_ids":["nope"]}`, dcql, `"nope"`},
		"one of several unknown": {`{"type":"x","credential_ids":["pay","nope"]}`, dcql, `"nope"`},
		"no dcql: refused, nothing for credential_ids to name": {`{"type":"x","credential_ids":["anything"]}`, nil, "no dcql_query"},
		"unreadable dcql: refused":                             {`{"type":"x","credential_ids":["anything"]}`, json.RawMessage(`{"credentials":[]}`), "no dcql_query"},
		"id in dcql":                                           {`{"type":"x","credential_ids":["age"]}`, dcql, ""},
		"dcql credential without id: refused":                  {`{"type":"x","credential_ids":[""]}`, json.RawMessage(`{"credentials":[{}]}`), "no dcql_query"},
		"dcql credential with null id: refused":                {`{"type":"x","credential_ids":[""]}`, json.RawMessage(`{"credentials":[{"id":null}]}`), "no dcql_query"},
		"dcql credential with empty id: refused":               {`{"type":"x","credential_ids":[""]}`, json.RawMessage(`{"credentials":[{"id":""}]}`), "no dcql_query"},
		"empty id beside a valid one: empty not nameable":      {`{"type":"x","credential_ids":[""]}`, json.RawMessage(`{"credentials":[{"id":"pay"},{"id":""}]}`), `references ""`},
		"valid id beside an empty one: still accepted":         {`{"type":"x","credential_ids":["pay"]}`, json.RawMessage(`{"credentials":[{"id":""},{"id":"pay"}]}`), ""},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			authReq := &AuthorizationRequest{TransactionDataRaw: rawArray(t, entry(t, c.entry)), DCQLQuery: c.dcql}
			err := validateTransactionData(authReq, tdClient)
			if c.want == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), c.want)
			var tdErr *transactionDataError
			require.True(t, errors.As(err, &tdErr))
			assert.Equal(t, ErrCodeInvalidMessage, tdErr.code, "a malformed entry is the verifier's fault, not a missing client feature")
		})
	}
}

// A client that did not declare the feature is refused before any structural
// check, so the answer for it is always "update the wallet".
func TestValidateTransactionData_GateComesBeforeStructuralChecks(t *testing.T) {
	authReq := &AuthorizationRequest{TransactionDataRaw: rawArray(t, entry(t, `{"credential_ids":[]}`))}
	err := validateTransactionData(authReq, nil)
	var tdErr *transactionDataError
	require.True(t, errors.As(err, &tdErr))
	assert.Equal(t, ErrCodeUnsupportedTransactionData, tdErr.code)
}

// What a client receives. The sign_request must carry raw and payload for each
// entry and the response_mode, and a presentation without transaction data
// must be byte-for-byte what it was before.
func TestSignRequestParams_WireCarriesRawPayloadAndResponseMode(t *testing.T) {
	v := loadTDVectors(t)[2] // pretty_printed
	authReq := &AuthorizationRequest{TransactionDataRaw: rawArray(t, v.Raw), DCQLQuery: payDCQL}
	require.NoError(t, validateTransactionData(authReq, tdClient))

	b, err := json.Marshal(SignRequestParams{
		Audience: "a", Nonce: "n", TransactionData: authReq.TransactionData, ResponseMode: "direct_post",
	})
	require.NoError(t, err)
	var wire struct {
		ResponseMode    string `json:"response_mode"`
		TransactionData []struct {
			Raw           string          `json:"raw"`
			Type          string          `json:"type"`
			Payload       json.RawMessage `json:"payload"`
			CredentialIDs []string        `json:"credential_ids"`
		} `json:"transaction_data"`
	}
	require.NoError(t, json.Unmarshal(b, &wire))
	assert.Equal(t, "direct_post", wire.ResponseMode)
	require.Len(t, wire.TransactionData, 1)
	assert.Equal(t, v.Raw, wire.TransactionData[0].Raw)
	assert.Equal(t, "urn:eudi:sca:payment:1", wire.TransactionData[0].Type)
	assert.JSONEq(t, `{"transaction_id":"tx-0001","payee":{"name":"Shop AB","id":"SE1234567890"},"amount":"49.99","currency":"EUR","execution_date":"2026-10-06"}`, string(wire.TransactionData[0].Payload))

	// The raw string the client receives is still the hash input: it matches
	// the independent vector, even though the object was decoded in between.
	assert.Equal(t, v.Hashes["sha-256"], hashOf(t, "sha-256", wire.TransactionData[0].Raw))
}

func TestSignRequestParams_UnchangedWithoutTransactionData(t *testing.T) {
	b, err := json.Marshal(SignRequestParams{Audience: "a", Nonce: "n"})
	require.NoError(t, err)
	assert.JSONEq(t, `{"audience":"a","nonce":"n"}`, string(b))
}

func TestFlowStartMessage_Supports(t *testing.T) {
	var nilMsg *FlowStartMessage
	assert.False(t, nilMsg.Supports(FeatureTransactionDataV1))
	assert.False(t, (&FlowStartMessage{}).Supports(FeatureTransactionDataV1))
	assert.True(t, tdClient.Supports(FeatureTransactionDataV1))
	// An unknown declared feature is ignored rather than rejected, so a newer
	// client can talk to this engine.
	assert.True(t, (&FlowStartMessage{Features: []string{"future_thing", FeatureTransactionDataV1}}).Supports(FeatureTransactionDataV1))
}

// The wire name is part of the contract with every client.
func TestFlowStartMessage_FeaturesWireName(t *testing.T) {
	var m FlowStartMessage
	require.NoError(t, json.Unmarshal([]byte(`{"type":"flow_start","protocol":"oid4vp","features":["transaction_data.v1"]}`), &m))
	assert.True(t, m.Supports(FeatureTransactionDataV1))

	// Existing clients send no `features`: still decodes, supports nothing.
	var old FlowStartMessage
	require.NoError(t, json.Unmarshal([]byte(`{"type":"flow_start","protocol":"oid4vp"}`), &old))
	assert.False(t, old.Supports(FeatureTransactionDataV1))
}

// --- Verifier is told ---

// The gate is only useful if both ends hear about it: the verifier gets
// invalid_transaction_data so its session ends now, and the client gets the
// distinct error code so it can tell the user to update.
func TestFailTransactionData_NotifiesVerifierAndClient(t *testing.T) {
	var form url.Values
	verifier := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		form = r.PostForm
		_, _ = w.Write([]byte(`{"redirect_uri":"https://verifier.example.com/back"}`))
	}))
	defer verifier.Close()

	got := make(chan FlowErrorMessage, 1)
	conn, cleanup := wsTestServer(t, func(srv *websocket.Conn) {
		defer srv.Close()
		_, data, err := srv.ReadMessage()
		if err != nil {
			return
		}
		var m FlowErrorMessage
		if json.Unmarshal(data, &m) == nil {
			got <- m
		}
	})
	defer cleanup()

	h := &OID4VPHandler{}
	h.BaseHandler = BaseHandler{Logger: zap.NewNop(), Flow: &Flow{ID: "flow-1", Session: testSession(conn)}}
	h.httpClient = verifier.Client()

	authReq := &AuthorizationRequest{ResponseMode: ResponseModeDirectPost, ResponseURI: verifier.URL, State: "st-1"}
	tdErr := newTransactionDataError(ErrCodeUnsupportedTransactionData, "x").(*transactionDataError)
	h.failTransactionData(context.Background(), authReq, tdErr)

	assert.Equal(t, "invalid_transaction_data", form.Get("error"))
	assert.Equal(t, transactionDataVerifierDescription, form.Get("error_description"))
	assert.Equal(t, "st-1", form.Get("state"))

	select {
	case m := <-got:
		assert.Equal(t, TypeFlowError, m.Type)
		assert.Equal(t, "flow-1", m.FlowID)
		assert.Equal(t, StepParsingRequest, m.Step)
		assert.Equal(t, ErrCodeUnsupportedTransactionData, m.Error.Code)
		assert.Equal(t, "https://verifier.example.com/back", m.Error.Details["redirect_uri"])
	case <-time.After(2 * time.Second):
		t.Fatal("client never received the flow_error")
	}
}

func TestUnsupportedTransactionData_UserFacingMessage(t *testing.T) {
	msg := ErrCodeUnsupportedTransactionData.UserFacingMessage()
	assert.NotEqual(t, ErrorCode("").UserFacingMessage(), msg, "must have its own message, not the generic fallback")
	assert.Contains(t, msg, "update")
}

// --- Inline-URL requests must not drop transaction_data ---

func inlineURL(t *testing.T, params map[string]string) *url.URL {
	t.Helper()
	q := url.Values{}
	for k, v := range params {
		q.Set(k, v)
	}
	return &url.URL{RawQuery: q.Encode()}
}

func TestParseRequestFromURL_KeepsTransactionData(t *testing.T) {
	h := &OID4VPHandler{}
	arr := string(rawArray(t, loadTDVectors(t)[1].Raw))
	authReq, err := h.parseRequestFromURL(inlineURL(t, map[string]string{
		"client_id": "x", "nonce": "n", "transaction_data": arr,
	}))
	require.NoError(t, err)
	assert.JSONEq(t, arr, string(authReq.TransactionDataRaw))

	entries, err := decodeTransactionData(authReq.TransactionDataRaw)
	require.NoError(t, err)
	assert.Equal(t, loadTDVectors(t)[1].Raw, entries[0].Raw, "the raw string must survive the by-value query form too")
}

func TestParseRequestFromURL_NoTransactionDataStaysEmpty(t *testing.T) {
	authReq, err := (&OID4VPHandler{}).parseRequestFromURL(inlineURL(t, map[string]string{"client_id": "x", "nonce": "n"}))
	require.NoError(t, err)
	assert.Empty(t, authReq.TransactionDataRaw)
}

func TestParseRequestFromURL_InvalidTransactionDataJSON(t *testing.T) {
	_, err := (&OID4VPHandler{}).parseRequestFromURL(inlineURL(t, map[string]string{"transaction_data": "{not json"}))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid transaction_data")
}

func TestParseRequestFromURL_EmptyTransactionDataParameterIsRejected(t *testing.T) {
	_, err := (&OID4VPHandler{}).parseRequestFromURL(inlineURL(t, map[string]string{"client_id": "x", "transaction_data": ""}))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid transaction_data")
}

func TestValidateTransactionData_EmptyArrayIsRejected(t *testing.T) {
	err := validateTransactionData(&AuthorizationRequest{TransactionDataRaw: json.RawMessage(`[]`)}, tdClient)
	var tdErr *transactionDataError
	require.True(t, errors.As(err, &tdErr))
	assert.Equal(t, ErrCodeInvalidMessage, tdErr.code)
}

// --- Execute: the verifier is contacted only after its trust is established ---

// executeRecorder runs Execute for a request and records what the verifier's
// response_uri received and which flow errors the client saw.
type executeRecorder struct {
	verifierHits chan url.Values
	clientErrors chan FlowErrorMessage
	signRequests chan SignRequestMessage
	verifierURL  string
	handler      *OID4VPHandler
}

func newExecuteRecorder(t *testing.T, cfg *config.Config, trustSvc *TrustService) *executeRecorder {
	t.Helper()
	r := &executeRecorder{verifierHits: make(chan url.Values, 4), clientErrors: make(chan FlowErrorMessage, 8), signRequests: make(chan SignRequestMessage, 4)}

	verifier := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		_ = req.ParseForm()
		r.verifierHits <- req.PostForm
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(verifier.Close)
	r.verifierURL = verifier.URL

	conn, cleanup := wsTestServer(t, func(srv *websocket.Conn) {
		defer srv.Close()
		for {
			_, data, err := srv.ReadMessage()
			if err != nil {
				return
			}
			var m FlowErrorMessage
			if json.Unmarshal(data, &m) == nil && m.Type == TypeFlowError {
				r.clientErrors <- m
			}
			var sr SignRequestMessage
			if json.Unmarshal(data, &sr) == nil && sr.Type == TypeSignRequest {
				r.signRequests <- sr
			}
		}
	})
	t.Cleanup(cleanup)

	r.handler = &OID4VPHandler{}
	r.handler.BaseHandler = BaseHandler{
		Logger: zap.NewNop(), Config: cfg, TrustSvc: trustSvc,
		Flow: &Flow{ID: "flow-1", Session: testSession(conn), Data: map[string]interface{}{}},
	}
	r.handler.httpClient = verifier.Client()
	return r
}

// run calls Execute; a panic means Execute carried on past where the test
// expects it to stop, which is reported as a plain failure.
func (r *executeRecorder) run(t *testing.T, msg *FlowStartMessage) (err error) {
	t.Helper()
	defer func() {
		if rec := recover(); rec != nil {
			t.Fatalf("Execute continued past where this test expects it to stop: %v", rec)
		}
	}()
	return r.handler.Execute(context.Background(), msg)
}

func (r *executeRecorder) clientError(t *testing.T) FlowErrorMessage {
	t.Helper()
	select {
	case m := <-r.clientErrors:
		return m
	case <-time.After(2 * time.Second):
		t.Fatal("client never received a flow_error")
		return FlowErrorMessage{}
	}
}

func (r *executeRecorder) verifierWasContacted() bool {
	select {
	case <-r.verifierHits:
		return true
	case <-time.After(300 * time.Millisecond):
		return false
	}
}

// Security: refusing transaction_data means telling the verifier, which means
// POSTing to the response_uri the REQUEST supplied. Until the verifier's trust
// is established that is an attacker-chosen URL, so an unauthenticated request
// must not be able to aim the backend at it just by carrying transaction_data.
// An unsigned decentralized_identifier request passes request validation and is
// then refused by trust evaluation: the verifier must never be contacted, and
// the client must hear "untrusted verifier", not the transaction_data error.
func TestExecute_TransactionDataFromUntrustedVerifier_VerifierIsNotContacted(t *testing.T) {
	r := newExecuteRecorder(t, testConfig(), nil)

	q := url.Values{}
	q.Set("client_id", ClientIDSchemeDecentralizedIdentifier+":did:web:verifier.example")
	q.Set("client_id_scheme", ClientIDSchemeDecentralizedIdentifier)
	q.Set("response_type", "vp_token")
	q.Set("response_mode", ResponseModeDirectPost)
	q.Set("response_uri", r.verifierURL)
	q.Set("nonce", "n-1")
	q.Set("state", "st-1")
	q.Set("dcql_query", `{"credentials":[{"id":"pay","format":"dc+sd-jwt","meta":{"vct_values":["x"]}}]}`)
	q.Set("transaction_data", string(owfRaw(t)))

	// A client from before the feature: no Features in its flow_start.
	err := r.run(t, &FlowStartMessage{Protocol: ProtocolOID4VP, RequestURI: "openid4vp://?" + q.Encode()})
	require.Error(t, err)

	assert.False(t, r.verifierWasContacted(), "the verifier must not be contacted before its trust is established")
	assert.Equal(t, ErrCodeUntrustedVerifier, r.clientError(t).Error.Code)
}

// The other half: once the verifier IS trusted, a transaction_data request from
// a client that did not declare support is refused, the verifier is told, and
// the client gets the distinct error and the verifier's redirect.
func TestExecute_TransactionDataFromTrustedVerifier_RefusedAndVerifierTold(t *testing.T) {
	const (
		did      = "did:web:verifier.example"
		clientID = ClientIDSchemeDecentralizedIdentifier + ":" + did
		kid      = did + "#jwk-1"
	)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	stub := &stubDIDResolver{
		didDoc: map[string]interface{}{
			"id": did,
			"verificationMethod": []interface{}{map[string]interface{}{
				"id": kid, "type": "JsonWebKey2020", "controller": did, "publicKeyJwk": ecPublicJWK(&key.PublicKey, kid),
			}},
		},
		decisionOk: true, decision: true,
	}
	cfg := testConfig()
	cfg.Trust.PDPURL = "http://pdp.test"
	trustSvc := trust.NewService(cfg, zap.NewNop(), func(_ string, _ time.Duration) (trust.TrustEvaluator, error) { return stub, nil })
	r := newExecuteRecorder(t, cfg, trustSvc)

	payload, err := json.Marshal(map[string]any{
		"client_id": clientID, "response_type": "vp_token", "response_mode": ResponseModeDirectPost,
		"response_uri": r.verifierURL, "nonce": "n-1", "state": "st-1",
		"dcql_query":       json.RawMessage(`{"credentials":[{"id":"pay","format":"dc+sd-jwt","meta":{"vct_values":["x"]}}]}`),
		"transaction_data": []string{string(owfRawEntry(t))},
	})
	require.NoError(t, err)
	jwt := signedKidJWT(t, key, kid, payload)

	q := url.Values{}
	q.Set("client_id", clientID)
	q.Set("request", jwt)
	err = r.run(t, &FlowStartMessage{Protocol: ProtocolOID4VP, RequestURI: "openid4vp://?" + q.Encode()})

	var tdErr *transactionDataError
	require.True(t, errors.As(err, &tdErr), "Execute returned %v", err)
	assert.Equal(t, ErrCodeUnsupportedTransactionData, tdErr.code)

	select {
	case form := <-r.verifierHits:
		assert.Equal(t, "invalid_transaction_data", form.Get("error"))
		assert.Equal(t, "st-1", form.Get("state"))
	case <-time.After(2 * time.Second):
		t.Fatal("a trusted verifier was not told")
	}
	assert.Equal(t, ErrCodeUnsupportedTransactionData, r.clientError(t).Error.Code)
}

// owfRawEntry is the single base64url entry owfRaw wraps in an array.
func owfRawEntry(t *testing.T) []byte {
	t.Helper()
	var arr []string
	require.NoError(t, json.Unmarshal(owfRaw(t), &arr))
	return []byte(arr[0])
}

// signedKidJWT signs payload with an ES256 key identified by kid, the way
// buildKidSignedJWT does but with a caller-supplied payload.
func signedKidJWT(t *testing.T, key *ecdsa.PrivateKey, kid string, payload []byte) string {
	t.Helper()
	enc := base64.RawURLEncoding.EncodeToString
	signingInput := enc([]byte(`{"alg":"ES256","kid":"`+kid+`"}`)) + "." + enc(payload)
	sum := sha256.Sum256([]byte(signingInput))
	rr, ss, err := ecdsa.Sign(rand.Reader, key, sum[:])
	require.NoError(t, err)
	n := (key.Curve.Params().BitSize + 7) / 8
	sig := make([]byte, 2*n)
	rr.FillBytes(sig[:n])
	ss.FillBytes(sig[n:])
	return signingInput + "." + enc(sig)
}

// direct_post.jwt needs an error response that is itself a JWT, which this does
// not build. Posting plain form fields would only be rejected by such a
// verifier, so it is not contacted.
func TestFailTransactionData_DirectPostJWTVerifierIsNotSentAForm(t *testing.T) {
	r := newExecuteRecorder(t, testConfig(), nil)
	authReq := &AuthorizationRequest{ResponseMode: ResponseModeDirectPostJWT, ResponseURI: r.verifierURL, State: "st-1"}
	tdErr := newTransactionDataError(ErrCodeUnsupportedTransactionData, "x").(*transactionDataError)

	r.handler.failTransactionData(context.Background(), authReq, tdErr)

	assert.False(t, r.verifierWasContacted(), "no form POST to a direct_post.jwt verifier")
	assert.Equal(t, ErrCodeUnsupportedTransactionData, r.clientError(t).Error.Code, "the client is still told")
}

// requestVPSignature is where the sign_request is assembled, so this is the
// check that the client really receives raw, payload and response_mode, and
// that a presentation with no transaction data sends neither.
func signRequestFor(t *testing.T, authReq *AuthorizationRequest) SignRequestMessage {
	t.Helper()
	got := make(chan SignRequestMessage, 1)
	conn, cleanup := wsTestServer(t, func(srv *websocket.Conn) {
		defer srv.Close()
		_, data, err := srv.ReadMessage()
		if err != nil {
			return
		}
		var m SignRequestMessage
		if json.Unmarshal(data, &m) == nil {
			got <- m
		}
	})
	defer cleanup()

	session := testSession(conn)
	h := &OID4VPHandler{}
	h.BaseHandler = BaseHandler{Logger: zap.NewNop(), Flow: &Flow{ID: "flow-1", Session: session}}

	done := make(chan error, 1)
	go func() {
		_, err := h.requestVPSignature(context.Background(), authReq,
			[]ConsentSelection{{CredentialID: "cred-1", CredentialQueryID: "pay"}}, "verifier.example.com")
		done <- err
	}()

	select {
	case m := <-got:
		resp := &SignResponseMessage{Message: Message{MessageID: m.MessageID}, VPToken: "vp"}
		if re := m.Params.ResponseEncryption; re != nil {
			// direct_post.jwt: the client answers with the finished JWE.
			hdr, _ := json.Marshal(map[string]string{"alg": re.Alg, "enc": re.Enc})
			seg := base64.RawURLEncoding.EncodeToString
			// An encrypted key exists only for key-wrapping algorithms.
			ek := ""
			if re.Alg != "ECDH-ES" {
				ek = seg([]byte("k"))
			}
			resp = &SignResponseMessage{Message: Message{MessageID: m.MessageID},
				ResponseJWE: seg(hdr) + "." + ek + "." + seg([]byte("i")) + "." + seg([]byte("c")) + "." + seg([]byte("t"))}
		}
		session.signCh <- resp
		require.NoError(t, <-done)
		return m
	case <-time.After(2 * time.Second):
		t.Fatal("no sign_request was sent")
		return SignRequestMessage{}
	}
}

func TestRequestVPSignature_CarriesTransactionDataAndResponseMode(t *testing.T) {
	v := loadTDVectors(t)[1]
	authReq := &AuthorizationRequest{
		Nonce: "n", ClientID: "verifier.example.com", ResponseMode: ResponseModeDirectPost,
		TransactionDataRaw: rawArray(t, v.Raw), DCQLQuery: payDCQL,
	}
	require.NoError(t, validateTransactionData(authReq, tdClient))

	m := signRequestFor(t, authReq)
	assert.Equal(t, SignActionSignPresentation, m.Action)
	assert.Equal(t, ResponseModeDirectPost, m.Params.ResponseMode)
	require.Len(t, m.Params.TransactionData, 1)
	assert.Equal(t, v.Raw, m.Params.TransactionData[0].Raw, "the client gets the string it must hash")
	assert.Equal(t, v.Hashes["sha-256"], hashOf(t, "sha-256", m.Params.TransactionData[0].Raw))
}

func TestRequestVPSignature_OmitsBothForAPresentationWithoutTransactionData(t *testing.T) {
	authReq := &AuthorizationRequest{Nonce: "n", ClientID: "verifier.example.com", ResponseMode: ResponseModeDirectPost}
	m := signRequestFor(t, authReq)
	assert.Empty(t, m.Params.ResponseMode, "response_mode is only sent with transaction data")
	assert.Empty(t, m.Params.TransactionData)
}

// --- response_mode: the sign request carries the mode the engine really uses ---

func TestEffectiveResponseMode(t *testing.T) {
	cases := map[string]string{
		"":                        ResponseModeDirectPost, // a request naming none is answered as direct_post
		ResponseModeDirectPost:    ResponseModeDirectPost,
		ResponseModeDirectPostJWT: ResponseModeDirectPostJWT,
		ResponseModeQuery:         ResponseModeQuery,
		ResponseModeFragment:      ResponseModeFragment,
	}
	for in, want := range cases {
		assert.Equal(t, want, effectiveResponseMode(&AuthorizationRequest{ResponseMode: in}), "response_mode %q", in)
	}
}

// A valid request may omit response_mode. The engine answers it as direct_post,
// so the wallet must be told direct_post: an empty value in the sign request
// would make the key binding JWT carry no response_mode, or be refused.
func TestRequestVPSignature_SendsTheEffectiveResponseMode(t *testing.T) {
	v := loadTDVectors(t)[1]
	for name, tc := range map[string]struct{ requested, sent string }{
		"absent defaults to direct_post": {"", ResponseModeDirectPost},
		"direct_post.jwt kept":           {ResponseModeDirectPostJWT, ResponseModeDirectPostJWT},
		"fragment kept":                  {ResponseModeFragment, ResponseModeFragment},
	} {
		t.Run(name, func(t *testing.T) {
			authReq := &AuthorizationRequest{
				Nonce: "n", ClientID: "verifier.example.com", ResponseMode: tc.requested,
				TransactionDataRaw: rawArray(t, v.Raw), DCQLQuery: payDCQL,
			}
			if tc.requested == ResponseModeDirectPostJWT {
				// The client builds the encrypted response itself, so the
				// engine needs the verifier's encryption key to ask for it.
				authReq.ClientMetadata = &ClientMetadata{JWKS: json.RawMessage(`{"keys":[{"kty":"EC","crv":"P-256","use":"enc","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}]}`)}
			}
			require.NoError(t, validateTransactionData(authReq, tdClient))
			assert.Equal(t, tc.sent, signRequestFor(t, authReq).Params.ResponseMode)
		})
	}
}

// --- transaction_data needs a DCQL query to bind to ---

// credential_ids name credentials of the DCQL query. With no query there is
// nothing for them to name; the request must be refused, not waved through
// with the binding skipped.
func TestValidateAuthorizationRequest_TransactionDataWithoutDCQLIsRefused(t *testing.T) {
	for name, dcql := range map[string]json.RawMessage{
		"no dcql_query":               nil,
		"a query with no credentials": json.RawMessage(`{"credentials":[]}`),
		"an unreadable query":         json.RawMessage(`[1,2,3]`),
	} {
		t.Run(name, func(t *testing.T) {
			authReq := &AuthorizationRequest{
				Nonce: "abc", ResponseMode: ResponseModeDirectPost, ResponseURI: "https://verifier.example.com/response",
				ClientID: "https://verifier.example.com", ClientIDScheme: ClientIDSchemeRedirectURI,
				TransactionDataRaw: owfRaw(t), DCQLQuery: dcql,
			}
			err := (&OID4VPHandler{}).validateAuthorizationRequest(authReq, tdClient)
			var tdErr *transactionDataError
			require.True(t, errors.As(err, &tdErr), "got %v", err)
			assert.Equal(t, ErrCodeInvalidMessage, tdErr.code, "the verifier's fault, not a missing client feature")
			assert.Contains(t, err.Error(), "no dcql_query")
			assert.Empty(t, authReq.TransactionData, "nothing may be forwarded")
		})
	}
}

// failSignHarness runs failSign against a verifier endpoint and a client socket,
// returning what the verifier's response_uri received (nil when never contacted)
// and the flow errors the client saw.
func failSignHarness(t *testing.T, td []TransactionData, err error) (url.Values, []FlowErrorMessage) {
	t.Helper()
	var form url.Values
	verifier := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		form = r.PostForm
		w.WriteHeader(http.StatusOK)
	}))
	defer verifier.Close()

	errs := make(chan FlowErrorMessage, 4)
	conn, cleanup := wsTestServer(t, func(srv *websocket.Conn) {
		defer srv.Close()
		for {
			_, data, err := srv.ReadMessage()
			if err != nil {
				return
			}
			var m FlowErrorMessage
			if json.Unmarshal(data, &m) == nil && m.Type == TypeFlowError {
				errs <- m
			}
		}
	})
	defer cleanup()

	h := &OID4VPHandler{}
	h.BaseHandler = BaseHandler{Logger: zap.NewNop(), Flow: &Flow{ID: "flow-1", Session: testSession(conn)}}
	h.httpClient = verifier.Client()
	authReq := &AuthorizationRequest{
		ClientID: "https://verifier.example.com", ResponseMode: ResponseModeDirectPost,
		ResponseURI: verifier.URL, State: "st-1", TransactionData: td,
	}
	h.failSign(context.Background(), authReq, err)

	var got []FlowErrorMessage
	select {
	case m := <-errs:
		got = append(got, m)
	case <-time.After(2 * time.Second):
		t.Fatal("client never received a flow_error")
	}
	return form, got
}

// A client that refuses the transaction type after the request validated: the
// verifier is told, and the client gets the distinct code.
func TestFailSign_ClientRefusalOfTransactionDataTellsVerifier(t *testing.T) {
	form, errs := failSignHarness(t, []TransactionData{{Type: "owf_payment_initiation"}},
		&SignError{Code: ErrCodeUnsupportedTransactionData})
	assert.Equal(t, "invalid_transaction_data", form.Get("error"))
	assert.Equal(t, "st-1", form.Get("state"))
	assert.Equal(t, ErrCodeUnsupportedTransactionData, errs[0].Error.Code)
}

// The classification counts only for a request that carried transaction_data, and
// any other sign failure stays a SIGN_ERROR that does not contact the verifier.
func TestFailSign_OtherFailuresStaySignError(t *testing.T) {
	form, errs := failSignHarness(t, nil, &SignError{Code: ErrCodeUnsupportedTransactionData})
	assert.Nil(t, form)
	assert.Equal(t, ErrCodeSignError, errs[0].Error.Code)

	form, errs = failSignHarness(t, []TransactionData{{Type: "x"}}, errors.New("boom"))
	assert.Nil(t, form)
	assert.Equal(t, ErrCodeSignError, errs[0].Error.Code)
}

// A client's sign_response carrying error + error_code reaches RequestSign's
// caller as a SignError. Only the allowlisted code survives, and neither the
// client's text nor an arbitrary code is ever part of the error string (which is
// logged).
func TestSession_RequestSign_ClientErrorBecomesSignError(t *testing.T) {
	srvConnCh := make(chan *websocket.Conn, 1)
	clientConn, cleanup := wsTestServer(t, func(srvConn *websocket.Conn) { srvConnCh <- srvConn })
	defer cleanup()
	session := testSession(<-srvConnCh)

	for _, tc := range []struct {
		name     string
		code     ErrorCode
		wantCode ErrorCode
		wantStr  string
	}{
		{"allowlisted", ErrCodeUnsupportedTransactionData, ErrCodeUnsupportedTransactionData, "client failed the sign request (UNSUPPORTED_TRANSACTION_DATA)"},
		{"unlisted", "evil\ninjected log line", "", "client failed the sign request"},
		{"absent", "", "", "client failed the sign request"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			go func() {
				var req SignRequestMessage
				if clientConn.ReadJSON(&req) != nil {
					return
				}
				session.signCh <- &SignResponseMessage{
					Message:   Message{Type: TypeSignResponse, MessageID: req.MessageID},
					Error:     "secret client text",
					ErrorCode: tc.code,
				}
			}()
			_, err := session.RequestSign(context.Background(), "f", SignActionSignPresentation, SignRequestParams{})
			var se *SignError
			require.ErrorAs(t, err, &se)
			assert.Equal(t, tc.wantCode, se.Code)
			assert.Equal(t, tc.wantStr, err.Error())
			assert.NotContains(t, err.Error(), "secret client text")
		})
	}
}

// error_code is read from the client's JSON sign_response.
func TestSignResponseMessage_ErrorCodeDecodes(t *testing.T) {
	var m SignResponseMessage
	require.NoError(t, json.Unmarshal([]byte(`{"type":"sign_response","error":"x","error_code":"UNSUPPORTED_TRANSACTION_DATA"}`), &m))
	assert.Equal(t, ErrCodeUnsupportedTransactionData, m.ErrorCode)
}

func TestSignResult_UnknownClientErrorCodeNeverInErrorString(t *testing.T) {
	_, err := signResult(&SignResponseMessage{Error: "x", ErrorCode: "evil\ninjected log line"})
	var se *SignError
	require.ErrorAs(t, err, &se)
	assert.Empty(t, se.Code)
	assert.NotContains(t, err.Error(), "injected")

	_, err = signResult(&SignResponseMessage{Error: "x", ErrorCode: ErrCodeUnsupportedTransactionData})
	require.ErrorAs(t, err, &se)
	assert.Equal(t, ErrCodeUnsupportedTransactionData, se.Code)
}

// End to end: a trusted verifier's transaction_data request reaches a client that
// declared support; the client then refuses the transaction type in its
// sign_response (error + error_code). Execute must tell the verifier
// invalid_transaction_data and give the client the distinct code, not leave the
// verifier waiting behind a bare SIGN_ERROR.
func TestExecute_ClientRefusesTransactionDataAtSign_VerifierIsTold(t *testing.T) {
	const (
		did      = "did:web:verifier.example"
		clientID = ClientIDSchemeDecentralizedIdentifier + ":" + did
		kid      = did + "#jwk-1"
	)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	stub := &stubDIDResolver{
		didDoc: map[string]interface{}{
			"id": did,
			"verificationMethod": []interface{}{map[string]interface{}{
				"id": kid, "type": "JsonWebKey2020", "controller": did, "publicKeyJwk": ecPublicJWK(&key.PublicKey, kid),
			}},
		},
		decisionOk: true, decision: true,
	}
	cfg := testConfig()
	cfg.Trust.PDPURL = "http://pdp.test"
	trustSvc := trust.NewService(cfg, zap.NewNop(), func(_ string, _ time.Duration) (trust.TrustEvaluator, error) { return stub, nil })
	r := newExecuteRecorder(t, cfg, trustSvc)

	payload, err := json.Marshal(map[string]any{
		"client_id": clientID, "response_type": "vp_token", "response_mode": ResponseModeDirectPost,
		"response_uri": r.verifierURL, "nonce": "n-1", "state": "st-1",
		"dcql_query":       json.RawMessage(`{"credentials":[{"id":"pay","format":"dc+sd-jwt","meta":{"vct_values":["x"]}}]}`),
		"transaction_data": []string{string(owfRawEntry(t))},
	})
	require.NoError(t, err)
	q := url.Values{}
	q.Set("client_id", clientID)
	q.Set("request", signedKidJWT(t, key, kid, payload))

	session := r.handler.Flow.Session
	feedAction(t, session, "flow-1", ActionConsent, ConsentPayload{
		SelectedCredentials: []ConsentSelection{{CredentialQueryID: "pay", CredentialID: "cred-1"}},
	})
	go func() {
		req := <-r.signRequests
		session.signCh <- &SignResponseMessage{
			Message:   Message{Type: TypeSignResponse, FlowID: req.FlowID, MessageID: req.MessageID},
			Error:     "unsupported transaction type",
			ErrorCode: ErrCodeUnsupportedTransactionData,
		}
	}()

	err = r.run(t, &FlowStartMessage{Protocol: ProtocolOID4VP, RequestURI: "openid4vp://?" + q.Encode(), Features: []string{FeatureTransactionDataV1}})
	var signErr *SignError
	require.ErrorAs(t, err, &signErr)
	assert.Equal(t, ErrCodeUnsupportedTransactionData, signErr.Code)

	select {
	case form := <-r.verifierHits:
		assert.Equal(t, "invalid_transaction_data", form.Get("error"))
		assert.Equal(t, "st-1", form.Get("state"))
	case <-time.After(2 * time.Second):
		t.Fatal("the verifier was not told the client refused the transaction data")
	}
	assert.Equal(t, ErrCodeUnsupportedTransactionData, r.clientError(t).Error.Code)
}

// A reply delivered straight to the waiting request (the per-request channel,
// as another request's waiter does) carries the client's refusal the same way.
func TestSession_RequestSign_ReplyViaOwnChannelBecomesSignError(t *testing.T) {
	srvConnCh := make(chan *websocket.Conn, 1)
	clientConn, cleanup := wsTestServer(t, func(srvConn *websocket.Conn) { srvConnCh <- srvConn })
	defer cleanup()
	session := testSession(<-srvConnCh)

	go func() {
		var req SignRequestMessage
		if clientConn.ReadJSON(&req) != nil {
			return
		}
		session.signWaitersMu.Lock()
		mine := session.signWaiters[req.MessageID]
		session.signWaitersMu.Unlock()
		mine <- &SignResponseMessage{Message: Message{MessageID: req.MessageID}, Error: "x", ErrorCode: ErrCodeUnsupportedTransactionData}
	}()
	_, err := session.RequestSign(context.Background(), "f", SignActionSignPresentation, SignRequestParams{})
	var se *SignError
	require.ErrorAs(t, err, &se)
	assert.Equal(t, ErrCodeUnsupportedTransactionData, se.Code)
}
