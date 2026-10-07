package engine

import (
	"context"
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
)

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
		"empty array":                     {`[]`, HashAlgList{}, false},
		"number rejected":                 {`5`, nil, true},
		"array of numbers rejected":       {`[1,2]`, nil, true},
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
			assert.NoError(t, validateTransactionData(&AuthorizationRequest{TransactionDataRaw: json.RawMessage(`[]`)}, msg))
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

// payDCQL is a DCQL query naming the credential ids the transaction_data
// fixtures reference.
var payDCQL = json.RawMessage(`{"credentials":[{"id":"pay"},{"id":"age"}]}`)

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

func TestValidateTransactionData_StructuralChecks(t *testing.T) {
	dcql := json.RawMessage(`{"credentials":[{"id":"pay"},{"id":"age"}]}`)
	cases := map[string]struct {
		entry string
		dcql  json.RawMessage
		want  string
	}{
		"missing type":             {`{"credential_ids":["pay"]}`, dcql, "missing type"},
		"no credential_ids":        {`{"type":"x"}`, dcql, "credential_ids must be a non-empty array"},
		"empty credential_ids":     {`{"type":"x","credential_ids":[]}`, dcql, "credential_ids must be a non-empty array"},
		"id not in dcql":           {`{"type":"x","credential_ids":["nope"]}`, dcql, `"nope"`},
		"one of several unknown":   {`{"type":"x","credential_ids":["pay","nope"]}`, dcql, `"nope"`},
		"no dcql: fail closed":     {`{"type":"x","credential_ids":["anything"]}`, nil, "requires a dcql_query"},
		"dcql without credentials": {`{"type":"x","credential_ids":["anything"]}`, json.RawMessage(`{"credentials":[]}`), "requires a dcql_query"},
		"unreadable dcql":          {`{"type":"x","credential_ids":["anything"]}`, json.RawMessage(`"nope"`), "requires a dcql_query"},
		"id in dcql":               {`{"type":"x","credential_ids":["age"]}`, dcql, ""},
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

// End to end through Execute: a verifier that sends transaction_data in an
// inline URL to a client that never declared support must be refused, the
// verifier told, and the client given the distinct error. This is the wiring
// the unit tests above cannot show: parse -> validate -> typed error ->
// failTransactionData, instead of the generic invalid-request path.
func TestExecute_InlineTransactionData_RefusedForClientThatDidNotDeclare(t *testing.T) {
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

	q := url.Values{}
	q.Set("client_id", "https://verifier.example.com")
	q.Set("client_id_scheme", ClientIDSchemeRedirectURI)
	q.Set("response_type", "vp_token")
	q.Set("response_mode", ResponseModeDirectPost)
	q.Set("response_uri", verifier.URL)
	q.Set("nonce", "n-1")
	q.Set("state", "st-1")
	q.Set("dcql_query", `{"credentials":[{"id":"pay","format":"dc+sd-jwt","meta":{"vct_values":["x"]}}]}`)
	q.Set("transaction_data", string(owfRaw(t)))

	// A client from before the feature: no Features in its flow_start.
	// Execute continuing past validation is exactly the failure this guards
	// against; with this minimal handler that surfaces as a panic further on,
	// which is reported as a plain test failure instead of aborting the package.
	var err error
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("Execute continued past request validation (transaction_data was not refused): %v", r)
			}
		}()
		err = h.Execute(context.Background(), &FlowStartMessage{
			Protocol:   ProtocolOID4VP,
			RequestURI: "openid4vp://?" + q.Encode(),
		})
	}()

	var tdErr *transactionDataError
	require.True(t, errors.As(err, &tdErr), "Execute returned %v", err)
	assert.Equal(t, ErrCodeUnsupportedTransactionData, tdErr.code)

	assert.Equal(t, "invalid_transaction_data", form.Get("error"), "verifier must be told")
	assert.Equal(t, "st-1", form.Get("state"))

	select {
	case m := <-errs:
		assert.Equal(t, ErrCodeUnsupportedTransactionData, m.Error.Code, "client must get the distinct code, not the generic one")
	case <-time.After(2 * time.Second):
		t.Fatal("client never received a flow_error")
	}
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
		session.signCh <- &SignResponseMessage{Message: Message{MessageID: m.MessageID}, VPToken: "vp"}
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

// OID4VP defaults an omitted response_mode to direct_post. The key binding JWT
// of a transaction-data presentation must carry that effective mode, not the
// empty string the request left out.
func TestRequestVPSignature_OmittedResponseModeIsSignedAsDirectPost(t *testing.T) {
	v := loadTDVectors(t)[1]
	authReq := &AuthorizationRequest{
		Nonce: "n", ClientID: "verifier.example.com", // no ResponseMode
		TransactionDataRaw: rawArray(t, v.Raw), DCQLQuery: payDCQL,
	}
	require.NoError(t, validateTransactionData(authReq, tdClient))

	m := signRequestFor(t, authReq)
	assert.Equal(t, ResponseModeDirectPost, m.Params.ResponseMode)
}

func TestEffectiveResponseMode(t *testing.T) {
	assert.Equal(t, ResponseModeDirectPost, effectiveResponseMode(&AuthorizationRequest{}))
	assert.Equal(t, ResponseModeDirectPostJWT, effectiveResponseMode(&AuthorizationRequest{ResponseMode: ResponseModeDirectPostJWT}))
	assert.Equal(t, ResponseModeFragment, effectiveResponseMode(&AuthorizationRequest{ResponseMode: ResponseModeFragment}))
}
