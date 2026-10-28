package engine

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

// Values that must never be visible to the engine once the issuer encrypts
// its response to the client's key.
const (
	secretCred1 = "SECRET-CREDENTIAL-ONE-eyJhbGciOiJFUzI1NiJ9"
	secretCred2 = "SECRET-CREDENTIAL-TWO-eyJhbGciOiJFUzI1NiJ9"
	secretNotif = "SECRET-NOTIFICATION-ID-77"
	secretTx    = "tx-opaque-1"
)

var blindSecrets = []string{secretCred1, secretCred2, secretNotif, secretSeedA, secretSeedB}

// fakeClient plays the wallet client over the websocket the handler talks to:
// it generates the response-encryption key, decrypts relayed JWEs and answers
// with control fields only, exactly as the contract says.
type fakeClient struct {
	t *testing.T

	mu          sync.Mutex
	session     *Session
	keys        []*ecdsa.PrivateKey // one per generate_proof that asked for a key
	outbound    []string            // every raw message the engine sent
	signActions []SignAction
	decrypted   []string // plaintexts the CLIENT decrypted (never visible to the engine)
	relayed     []string // JWEs relayed to the client

	decline      bool                                        // answer generate_proof without a key
	jwkOverride  func(jwk map[string]any) json.RawMessage    // tamper with the returned key
	errorOnProof bool                                        // generate_proof answers error
	decryptErr   bool                                        // decrypt answers error (with the plaintext in the text)
	reply        func(pt []byte) (SignResponseMessage, bool) // override the decrypt answer
	// proofMaker overrides the proof JWT the client returns for proof i; by
	// default a request carrying auxiliary_data_to_issuer is answered with a
	// proof holding a valid commitment for every advertised entry.
	proofMaker func(i int, req *SignRequestMessage) string
}

func (c *fakeClient) setSession(s *Session) {
	c.mu.Lock()
	c.session = s
	c.mu.Unlock()
}

func (c *fakeClient) lastKey() *ecdsa.PrivateKey {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.keys) == 0 {
		return nil
	}
	return c.keys[len(c.keys)-1]
}

func (c *fakeClient) newKey() *ecdsa.PrivateKey {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(c.t, err)
	c.mu.Lock()
	c.keys = append(c.keys, k)
	c.mu.Unlock()
	return k
}

func (c *fakeClient) handle(data []byte) {
	c.mu.Lock()
	c.outbound = append(c.outbound, string(data))
	sess := c.session
	c.mu.Unlock()
	var head struct {
		Type MessageType `json:"type"`
	}
	if json.Unmarshal(data, &head) != nil || head.Type != TypeSignRequest {
		return
	}
	var req SignRequestMessage
	require.NoError(c.t, json.Unmarshal(data, &req))
	c.mu.Lock()
	c.signActions = append(c.signActions, req.Action)
	c.mu.Unlock()

	resp := SignResponseMessage{Message: Message{Type: TypeSignResponse, FlowID: req.FlowID, MessageID: req.MessageID}}
	switch req.Action {
	case SignActionGenerateProof:
		c.answerProof(&req, &resp)
	case SignActionDecryptCredentialResponse:
		c.answerDecrypt(&req, &resp)
	}
	sess.dispatchSignResponse(&resp)
}

func (c *fakeClient) answerProof(req *SignRequestMessage, resp *SignResponseMessage) {
	if c.errorOnProof {
		resp.Error = "boom"
		return
	}
	if req.Params.CredentialResponseEncryption != nil && !c.decline {
		k := c.newKey()
		jwk := map[string]any{}
		raw, err := json.Marshal(jose.JSONWebKey{Key: &k.PublicKey, Use: "enc", Algorithm: req.Params.CredentialResponseEncryption.Alg})
		require.NoError(c.t, err)
		require.NoError(c.t, json.Unmarshal(raw, &jwk))
		if c.jwkOverride != nil {
			resp.CredentialResponseEncryptionJWK = c.jwkOverride(jwk)
		} else {
			resp.CredentialResponseEncryptionJWK = raw
		}
	}
	if len(req.Params.ProofTypesSupported) > 0 {
		n := req.Params.Count
		if n == 0 {
			n = 1
		}
		for i := 0; i < n; i++ {
			jwt := fmt.Sprintf("proof-%d", i)
			switch {
			case c.proofMaker != nil:
				jwt = c.proofMaker(i, req)
			case len(req.Params.AuxiliaryDataToIssuer) > 0:
				jwt = auxProofJWT(c.t, validAuxClaim(c.t, req.Params.AuxiliaryDataToIssuer, 0))
			}
			resp.Proofs = append(resp.Proofs, ProofObject{ProofType: "jwt", JWT: jwt})
		}
	}
}

func (c *fakeClient) answerDecrypt(req *SignRequestMessage, resp *SignResponseMessage) {
	c.mu.Lock()
	c.relayed = append(c.relayed, req.Params.JWE)
	c.mu.Unlock()
	key := c.lastKey()
	jwe, err := jose.ParseEncrypted(req.Params.JWE,
		[]jose.KeyAlgorithm{jose.ECDH_ES, jose.ECDH_ES_A128KW, jose.ECDH_ES_A256KW},
		[]jose.ContentEncryption{jose.A128GCM, jose.A256GCM, jose.A128CBC_HS256})
	if err != nil || key == nil {
		resp.Error = "cannot parse"
		return
	}
	pt, err := jwe.Decrypt(key)
	if err != nil {
		resp.Error = "cannot decrypt"
		return
	}
	c.mu.Lock()
	c.decrypted = append(c.decrypted, string(pt))
	c.mu.Unlock()
	if c.decryptErr {
		resp.Error = "client failed on " + string(pt) // text the engine must never surface
		return
	}
	if c.reply != nil {
		if r, ok := c.reply(pt); ok {
			resp.TransactionID, resp.Interval, resp.CredentialCount, resp.Error = r.TransactionID, r.Interval, r.CredentialCount, r.Error
			return
		}
	}
	var body struct {
		Credential    json.RawMessage   `json:"credential"`
		Credentials   []json.RawMessage `json:"credentials"`
		TransactionID string            `json:"transaction_id"`
		Interval      int               `json:"interval"`
	}
	require.NoError(c.t, json.Unmarshal(pt, &body))
	if body.TransactionID != "" {
		resp.TransactionID, resp.Interval = body.TransactionID, body.Interval
		return
	}
	n := len(body.Credentials)
	if len(body.Credential) > 0 {
		n++
	}
	resp.CredentialCount = n
}

// clientRE is a negotiated response encryption already carrying a client key.
func clientRE(t *testing.T) *responseEncryption {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	re := &responseEncryption{Alg: "ECDH-ES+A256KW", Enc: "A256GCM"}
	jwk, err := clientResponseEncryptionJWK(mustJWK(t, k), re.Alg)
	require.NoError(t, err)
	return re.withJWK(jwk)
}

// settle waits until the engine has stopped sending, so outbound is complete.
func (c *fakeClient) settle() {
	last := -1
	for i := 0; i < 100; i++ {
		c.mu.Lock()
		n := len(c.outbound)
		c.mu.Unlock()
		if n == last {
			return
		}
		last = n
		time.Sleep(30 * time.Millisecond)
	}
}

// engineSaw returns everything the engine sent to the client, as one string.
func (c *fakeClient) engineSaw() string {
	c.settle()
	c.mu.Lock()
	defer c.mu.Unlock()
	return strings.Join(c.outbound, "\n")
}

func (c *fakeClient) outboundMessages() []map[string]json.RawMessage {
	c.settle()
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []map[string]json.RawMessage
	for _, m := range c.outbound {
		var mm map[string]json.RawMessage
		if json.Unmarshal([]byte(m), &mm) == nil {
			out = append(out, mm)
		}
	}
	return out
}

func (c *fakeClient) actions() []SignAction {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]SignAction(nil), c.signActions...)
}

// newBlindHandler returns a handler whose session is served by fc. The
// returned log observer records everything the handler logs at any level.
func newBlindHandler(t *testing.T, fc *fakeClient, httpClient *http.Client) (*OID4VCIHandler, *observer.ObservedLogs, func()) {
	t.Helper()
	conn, cleanup := wsTestServer(t, func(srv *websocket.Conn) {
		defer srv.Close()
		for {
			_, data, err := srv.ReadMessage()
			if err != nil {
				return
			}
			fc.handle(data)
		}
	})
	sess := testSession(conn)
	sess.notifications = newNotificationContextStore()
	fc.setSession(sess)
	core, logs := observer.New(zap.DebugLevel)
	flow := &Flow{ID: "f-blind", Session: sess, Data: map[string]interface{}{}}
	h := &OID4VCIHandler{httpClient: httpClient, clientAuthMode: clientAuthLegacy, legacyAttestationRequested: true}
	h.BaseHandler = BaseHandler{Flow: flow, Logger: zap.New(core)}
	return h, logs, cleanup
}

// jweTo encrypts plaintext for the JWK the engine put in a request.
func jweTo(t *testing.T, enc map[string]any, plaintext string) string {
	t.Helper()
	jb, err := json.Marshal(enc["jwk"])
	require.NoError(t, err)
	var wk jose.JSONWebKey
	require.NoError(t, json.Unmarshal(jb, &wk))
	e, err := jose.NewEncrypter(jose.ContentEncryption(enc["enc"].(string)),
		jose.Recipient{Algorithm: jose.KeyAlgorithm(wk.Algorithm), Key: &wk}, nil)
	require.NoError(t, err)
	out, err := e.Encrypt([]byte(plaintext))
	require.NoError(t, err)
	s, err := out.CompactSerialize()
	require.NoError(t, err)
	return s
}

// issuerStub is a credential/deferred endpoint that encrypts its answers to
// the key it is given in the request (as OID4VCI requires).
type issuerStub struct {
	srv *httptest.Server

	mu       sync.Mutex
	requests []map[string]any
	// credentialBody / deferredBodies are the plaintext Credential Response
	// and the successive Deferred Credential Responses (nil = 202 pending).
	credentialBody string
	deferredBodies []string
	plainDeferred  bool // answer deferred in clear although a key was given
	deferredHits   int
	// encPendingBody, when set, makes a pending poll an ENCRYPTED 202 with this
	// plaintext; malformedPending makes it a 202 jwt that is not a compact JWE.
	encPendingBody   string
	malformedPending bool
	times            []time.Time
}

func newIssuerStub(t *testing.T, credentialBody string, deferredBodies ...string) *issuerStub {
	st := &issuerStub{credentialBody: credentialBody, deferredBodies: deferredBodies}
	st.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var req map[string]any
		_ = json.Unmarshal(raw, &req)
		st.mu.Lock()
		st.requests = append(st.requests, req)
		st.times = append(st.times, time.Now())
		deferred := strings.HasSuffix(r.URL.Path, "/deferred_credential")
		body := st.credentialBody
		pending := false
		if deferred {
			i := st.deferredHits
			st.deferredHits++
			if i < len(st.deferredBodies) {
				body = st.deferredBodies[i]
			}
			pending = body == ""
		}
		plain := deferred && st.plainDeferred
		st.mu.Unlock()
		if pending {
			enc, hasKey := req["credential_response_encryption"].(map[string]any)
			switch {
			case st.malformedPending:
				w.Header().Set("Content-Type", "application/jwt")
				w.WriteHeader(http.StatusAccepted)
				_, _ = w.Write([]byte("not-a-jwe"))
			case st.encPendingBody != "" && hasKey:
				w.Header().Set("Content-Type", "application/jwt")
				w.WriteHeader(http.StatusAccepted)
				_, _ = w.Write([]byte(jweTo(t, enc, st.encPendingBody)))
			default:
				w.WriteHeader(http.StatusAccepted)
				_, _ = w.Write([]byte(`{"interval":1}`))
			}
			return
		}
		enc, ok := req["credential_response_encryption"].(map[string]any)
		if !ok || plain {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(body))
			return
		}
		w.Header().Set("Content-Type", "application/jwt")
		_, _ = w.Write([]byte(jweTo(t, enc, body)))
	}))
	t.Cleanup(st.srv.Close)
	return st
}

func (st *issuerStub) metadata(encCfg *CredentialResponseEncryptionConfig) *IssuerMetadata {
	return &IssuerMetadata{
		CredentialIssuer:             st.srv.URL,
		CredentialEndpoint:           st.srv.URL + "/credential",
		CredentialResponseEncryption: encCfg,
		NotificationEndpoint:         st.srv.URL + "/notification",
	}
}

func gcmCfg(required bool) *CredentialResponseEncryptionConfig {
	return &CredentialResponseEncryptionConfig{
		AlgValuesSupported: []string{"ECDH-ES"},
		EncValuesSupported: []string{"A128GCM"},
		EncryptionRequired: required,
	}
}

const seedResponse = `{"credentials":[{"credential":"` + secretCred1 + `"},{"credential":"` + secretCred2 + `"}],` +
	`"notification_id":"` + secretNotif + `","credential_metadata":{"auxiliary_data":[{"type":"hash_commitment","alg":"sha-256",` +
	`"path":["org.iso.18013.5.1","ssc"],"opening":"` + secretSeedA + `"}]}}`

func seedConfig() *CredentialConfig {
	c := seedCfg()
	c.Format = "vc+sd-jwt"
	c.ProofTypesSupported = map[string]interface{}{"jwt": map[string]interface{}{}}
	return c
}

func tokenBearer() *TokenResponse { return &TokenResponse{AccessToken: "at", TokenType: "Bearer"} }

// assertNoSecrets fails when any of the secrets is in s.
func assertNoSecrets(t *testing.T, what, s string) {
	t.Helper()
	for _, secret := range blindSecrets {
		assert.NotContains(t, s, secret, "%s must not contain %q", what, secret)
	}
}

func logDump(logs *observer.ObservedLogs) string {
	var b strings.Builder
	for _, e := range logs.All() {
		b.WriteString(e.Message)
		for _, f := range e.Context {
			b.WriteString(" " + f.Key + "=" + f.String)
			if f.Interface != nil {
				j, _ := json.Marshal(f.Interface)
				b.Write(j)
				if f.Type == zapcore.ErrorType {
					b.WriteString(f.Interface.(error).Error())
				}
			}
		}
		b.WriteString("\n")
	}
	return b.String()
}

func fastDeferredPolling(t *testing.T) {
	t.Helper()
	oldD, oldU := deferredPollDefaultInterval, deferredPollIntervalUnit
	deferredPollDefaultInterval, deferredPollIntervalUnit = 10*time.Millisecond, 10*time.Millisecond
	t.Cleanup(func() { deferredPollDefaultInterval, deferredPollIntervalUnit = oldD, oldU })
}

// completion returns the flow_complete the engine sent.
func completion(t *testing.T, fc *fakeClient) map[string]json.RawMessage {
	t.Helper()
	var found map[string]json.RawMessage
	for _, m := range fc.outboundMessages() {
		if string(m["type"]) == `"flow_complete"` {
			require.Nil(t, found, "exactly one flow_complete")
			found = m
		}
	}
	require.NotNil(t, found, "flow_complete was sent")
	return found
}

// --- the whole issuance, immediate ---

func TestBlind_ImmediateIssuance_EngineNeverHoldsContents(t *testing.T) {
	st := newIssuerStub(t, seedResponse)
	fc := &fakeClient{t: t}
	h, logs, cleanup := newBlindHandler(t, fc, st.srv.Client())
	defer cleanup()

	md := st.metadata(gcmCfg(false))
	cfg := seedConfig()
	require.NoError(t, h.issueCredential(context.Background(), md, tokenBearer(), "cfg", cfg, nil, ""))

	// The client saw the secrets in clear (it holds the key): the test is not
	// vacuous, the response really did carry them.
	require.Len(t, fc.decrypted, 1)
	assert.Contains(t, fc.decrypted[0], secretCred1)
	assert.Contains(t, fc.decrypted[0], secretSeedA)

	// The engine asked the client for the key, relayed the JWE, and nothing else.
	assert.Equal(t, []SignAction{SignActionGenerateProof, SignActionDecryptCredentialResponse}, fc.actions())
	require.Len(t, fc.relayed, 1)

	// Everything the engine sent: no secret anywhere except as opaque ciphertext.
	assertNoSecrets(t, "outbound messages", fc.engineSaw())
	assert.Contains(t, fc.engineSaw(), fc.relayed[0], "the JWE is relayed verbatim")
	assertNoSecrets(t, "logs", logDump(logs))

	// The credential request carried the client's public key and the pair.
	require.Len(t, st.requests, 1)
	enc := st.requests[0]["credential_response_encryption"].(map[string]any)
	assert.NotContains(t, enc, "alg")
	assert.Equal(t, "A128GCM", enc["enc"])
	jwk := enc["jwk"].(map[string]any)
	assert.Equal(t, "ECDH-ES", jwk["alg"])
	assert.NotContains(t, jwk, "d", "only the public key is sent")
	assert.Equal(t, "enc", jwk["use"])

	// flow_complete: entries per credential, no credential value, no metadata.
	done := completion(t, fc)
	assert.JSONEq(t, `true`, string(done["credential_response_encrypted"]))
	assert.NotContains(t, done, "credential_metadata")
	assert.NotContains(t, done, "credential_metadata_encrypted_response")
	var creds []map[string]any
	require.NoError(t, json.Unmarshal(done["credentials"], &creds))
	require.Len(t, creds, 2, "one entry per decrypted credential")
	for _, c := range creds {
		assert.Equal(t, "vc+sd-jwt", c["format"])
		assert.NotContains(t, c, "credential")
		assert.NotContains(t, c, "notification_id")
	}

	// The notification context holds no id: the client's id matches.
	assert.True(t, h.Flow.Session.notifications.hasValid("f-blind", secretNotif))
	assert.True(t, h.Flow.Session.notifications.hasValid("f-blind", "anything-the-client-sends"))
	nc := h.Flow.Session.notifications.take("f-blind")
	require.NotNil(t, nc)
	assert.Empty(t, nc.notificationID)
	assertNoSecrets(t, "notification context", fmt.Sprintf("%+v", *nc))

	// The handler holds no private key: the only keys are the client's.
	assert.Nil(t, h.dpopKey)
}

// A response of a different shape (no seed) goes the same way, and a single
// credential field counts as one.
func TestBlind_SingleCredentialCount(t *testing.T) {
	st := newIssuerStub(t, `{"credential":"`+secretCred1+`"}`)
	fc := &fakeClient{t: t}
	h, _, cleanup := newBlindHandler(t, fc, st.srv.Client())
	defer cleanup()
	require.NoError(t, h.issueCredential(context.Background(), st.metadata(gcmCfg(false)), tokenBearer(), "cfg", seedConfig(), nil, ""))
	var creds []map[string]any
	require.NoError(t, json.Unmarshal(completion(t, fc)["credentials"], &creds))
	assert.Len(t, creds, 1)
	assertNoSecrets(t, "outbound", fc.engineSaw())
}

// --- deferred issuance goes through the same path ---

func TestBlind_DeferredIssuance_SameClientPath(t *testing.T) {
	fastDeferredPolling(t)
	st := newIssuerStub(t, `{"transaction_id":"`+secretTx+`","interval":1}`,
		"", // first poll: pending
		seedResponse)
	st.encPendingBody = `{"transaction_id":"` + secretTx + `","interval":1}`
	fc := &fakeClient{t: t}
	h, logs, cleanup := newBlindHandler(t, fc, st.srv.Client())
	defer cleanup()
	require.NoError(t, h.issueCredential(context.Background(), st.metadata(gcmCfg(false)), tokenBearer(), "cfg", seedConfig(), nil, ""))

	assert.Equal(t, []SignAction{SignActionGenerateProof, SignActionDecryptCredentialResponse, SignActionDecryptCredentialResponse, SignActionDecryptCredentialResponse}, fc.actions())
	// First relay: deferred=false, then the encrypted pending 202 and the final answer: deferred=true.
	var deferredFlags []string
	for _, m := range fc.outboundMessages() {
		if string(m["type"]) != `"sign_request"` || !strings.Contains(string(m["action"]), "decrypt") {
			continue
		}
		var p map[string]json.RawMessage
		require.NoError(t, json.Unmarshal(m["params"], &p))
		deferredFlags = append(deferredFlags, string(p["deferred"]))
	}
	assert.Equal(t, []string{"false", "true", "true"}, deferredFlags, "deferred is sent explicitly, false included")

	// The deferred request repeated credential_response_encryption with the
	// same key (OID4VCI 1.0 §9.1): otherwise the issuer answers in clear.
	st.mu.Lock()
	defer st.mu.Unlock()
	require.GreaterOrEqual(t, len(st.requests), 3)
	first := st.requests[0]["credential_response_encryption"].(map[string]any)
	for _, req := range st.requests[1:] {
		assert.Equal(t, secretTx, req["transaction_id"])
		assert.Equal(t, first, req["credential_response_encryption"])
	}

	assertNoSecrets(t, "outbound", fc.engineSaw())
	assertNoSecrets(t, "logs", logDump(logs))
	done := completion(t, fc)
	assert.JSONEq(t, `true`, string(done["credential_response_encrypted"]))
	var creds []map[string]any
	require.NoError(t, json.Unmarshal(done["credentials"], &creds))
	assert.Len(t, creds, 2)
}

// An encrypted 202 pending answer is relayed to the client, and the
// transaction_id and interval the client reports replace the engine's own.
func TestBlind_DeferredEncryptedPending202_ClientUpdatesTxAndInterval(t *testing.T) {
	oldD, oldU := deferredPollDefaultInterval, deferredPollIntervalUnit
	deferredPollDefaultInterval, deferredPollIntervalUnit = time.Millisecond, 60*time.Millisecond
	t.Cleanup(func() { deferredPollDefaultInterval, deferredPollIntervalUnit = oldD, oldU })

	st := newIssuerStub(t, `{"transaction_id":"tx1"}`,
		"", // first poll: encrypted pending 202
		seedResponse)
	st.encPendingBody = `{"transaction_id":"tx2","interval":3}`
	fc := &fakeClient{t: t}
	h, logs, cleanup := newBlindHandler(t, fc, st.srv.Client())
	defer cleanup()
	require.NoError(t, h.issueCredential(context.Background(), st.metadata(gcmCfg(false)), tokenBearer(), "cfg", seedConfig(), nil, ""))

	st.mu.Lock()
	defer st.mu.Unlock()
	require.Len(t, st.requests, 3, "credential request, pending poll, final poll")
	assert.Equal(t, "tx1", st.requests[1]["transaction_id"])
	assert.Equal(t, "tx2", st.requests[2]["transaction_id"], "the client-reported transaction_id is used")
	assert.GreaterOrEqual(t, st.times[2].Sub(st.times[1]), 3*deferredPollIntervalUnit-20*time.Millisecond,
		"the client-reported interval (3 units) is waited, not the default")
	// The pending JWE was relayed, so the client decrypted it.
	require.Len(t, fc.decrypted, 3)
	assert.Contains(t, fc.decrypted[1], "tx2")
	assertNoSecrets(t, "outbound", fc.engineSaw())
	assertNoSecrets(t, "logs", logDump(logs))
}

// An encrypted 202 that is not a compact JWE fails closed.
func TestBlind_DeferredEncrypted202MalformedJWE_Fails(t *testing.T) {
	fastDeferredPolling(t)
	st := newIssuerStub(t, `{"transaction_id":"tx1"}`, "")
	st.malformedPending = true
	fc := &fakeClient{t: t}
	h, _, cleanup := newBlindHandler(t, fc, st.srv.Client())
	defer cleanup()
	err := h.issueCredential(context.Background(), st.metadata(gcmCfg(false)), tokenBearer(), "cfg", seedConfig(), nil, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "malformed encrypted")
	st.mu.Lock()
	assert.Len(t, st.requests, 2, "no further polling after a malformed answer")
	st.mu.Unlock()
}

// A plain 202 to a seed-advertising request is refused like a plain 200.
func TestBlind_DeferredPlain202ToSeedRefused(t *testing.T) {
	fastDeferredPolling(t)
	st := newIssuerStub(t, `{"transaction_id":"tx1"}`, "")
	fc := &fakeClient{t: t}
	h, _, cleanup := newBlindHandler(t, fc, st.srv.Client())
	defer cleanup()
	err := h.issueCredential(context.Background(), st.metadata(gcmCfg(false)), tokenBearer(), "cfg", seedConfig(), nil, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "without encrypting")
}

// The engine used to read a deferred answer as plain JSON whatever it was.
// A seed-advertising issuer answering a deferred request in clear is refused
// without parsing.
func TestBlind_DeferredPlainAnswerToSeedRefusedUnread(t *testing.T) {
	fastDeferredPolling(t)
	st := newIssuerStub(t, `{"transaction_id":"tx1"}`, seedResponse)
	st.plainDeferred = true
	fc := &fakeClient{t: t}
	h, logs, cleanup := newBlindHandler(t, fc, st.srv.Client())
	defer cleanup()
	err := h.issueCredential(context.Background(), st.metadata(gcmCfg(false)), tokenBearer(), "cfg", seedConfig(), nil, "")
	require.Error(t, err)
	assertNoSecrets(t, "error", err.Error())
	assertNoSecrets(t, "outbound", fc.engineSaw())
	assertNoSecrets(t, "logs", logDump(logs))
	for _, m := range fc.outboundMessages() {
		assert.NotEqual(t, `"flow_complete"`, string(m["type"]))
	}
}

// --- fail closed ---

func TestBlind_ClientDeclinesRequiredEncryptionFailsClosed(t *testing.T) {
	st := newIssuerStub(t, seedResponse)
	fc := &fakeClient{t: t, decline: true}
	h, _, cleanup := newBlindHandler(t, fc, st.srv.Client())
	defer cleanup()
	// seed advertised => required
	err := h.issueCredential(context.Background(), st.metadata(gcmCfg(false)), tokenBearer(), "cfg", seedConfig(), nil, "")
	require.Error(t, err)
	assert.Empty(t, st.requests, "no credential request is made")
	assertNoSecrets(t, "outbound", fc.engineSaw())

	// issuer-required encryption also fails closed
	fc2 := &fakeClient{t: t, decline: true}
	h2, _, cleanup2 := newBlindHandler(t, fc2, st.srv.Client())
	defer cleanup2()
	plainCfg := &CredentialConfig{Format: "vc+sd-jwt", ProofTypesSupported: map[string]interface{}{"jwt": map[string]interface{}{}}}
	require.Error(t, h2.issueCredential(context.Background(), st.metadata(gcmCfg(true)), tokenBearer(), "cfg", plainCfg, nil, ""))
	assert.Empty(t, st.requests)
}

func TestBlind_ClientDeclinesOptionalEncryptionProceedsInClear(t *testing.T) {
	st := newIssuerStub(t, `{"credential":"plain-cred"}`)
	// the stub encrypts only when asked; here it is not asked
	fc := &fakeClient{t: t, decline: true}
	h, _, cleanup := newBlindHandler(t, fc, st.srv.Client())
	defer cleanup()
	plainCfg := &CredentialConfig{Format: "vc+sd-jwt", ProofTypesSupported: map[string]interface{}{"jwt": map[string]interface{}{}}}
	require.NoError(t, h.issueCredential(context.Background(), st.metadata(gcmCfg(false)), tokenBearer(), "cfg", plainCfg, nil, ""))
	require.Len(t, st.requests, 1)
	assert.NotContains(t, st.requests[0], "credential_response_encryption")
	done := completion(t, fc)
	assert.NotContains(t, done, "credential_response_encrypted")
	assert.Contains(t, string(done["credentials"]), "plain-cred", "an issuer that does not encrypt stays engine-visible")
}

func TestBlind_InvalidClientJWKFailsClosed(t *testing.T) {
	good, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	priv, _ := json.Marshal(jose.JSONWebKey{Key: good, Use: "enc"})
	cases := map[string]func(jwk map[string]any) json.RawMessage{
		"not json":    func(map[string]any) json.RawMessage { return json.RawMessage(`"nope"`) },
		"missing x":   func(j map[string]any) json.RawMessage { delete(j, "x"); b, _ := json.Marshal(j); return b },
		"missing kty": func(j map[string]any) json.RawMessage { delete(j, "kty"); b, _ := json.Marshal(j); return b },
		"private key": func(map[string]any) json.RawMessage { return priv },
		"wrong curve": func(map[string]any) json.RawMessage {
			b, _ := json.Marshal(jose.JSONWebKey{Key: &p384.PublicKey})
			return b
		},
		"use sig":            func(j map[string]any) json.RawMessage { j["use"] = "sig"; b, _ := json.Marshal(j); return b },
		"alg mismatch":       func(j map[string]any) json.RawMessage { j["alg"] = "ECDH-ES+A256KW"; b, _ := json.Marshal(j); return b },
		"RSA key":            func(map[string]any) json.RawMessage { return json.RawMessage(`{"kty":"RSA","n":"AQAB","e":"AQAB"}`) },
		"point not on curve": func(j map[string]any) json.RawMessage { j["y"] = j["x"]; b, _ := json.Marshal(j); return b },
	}
	for name, mut := range cases {
		for _, required := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/required=%v", name, required), func(t *testing.T) {
				st := newIssuerStub(t, seedResponse)
				fc := &fakeClient{t: t, jwkOverride: mut}
				h, _, cleanup := newBlindHandler(t, fc, st.srv.Client())
				defer cleanup()
				plainCfg := &CredentialConfig{Format: "vc+sd-jwt", ProofTypesSupported: map[string]interface{}{"jwt": map[string]interface{}{}}}
				require.Error(t, h.issueCredential(context.Background(), st.metadata(gcmCfg(required)), tokenBearer(), "cfg", plainCfg, nil, ""))
				assert.Empty(t, st.requests, "no credential request with an unusable key")
				assert.NotContains(t, completionTypes(fc), "flow_complete")
			})
		}
	}
}

func completionTypes(fc *fakeClient) []string {
	var out []string
	for _, m := range fc.outboundMessages() {
		out = append(out, strings.Trim(string(m["type"]), `"`))
	}
	return out
}

func TestBlind_JWKNormalisedAndNegotiatedAlgPinned(t *testing.T) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	// alg and use absent, plus an extra member: the engine forwards only the
	// key with use=enc and the negotiated alg.
	pubJSON, err := json.Marshal(jose.JSONWebKey{Key: &k.PublicKey})
	require.NoError(t, err)
	var m map[string]any
	require.NoError(t, json.Unmarshal(pubJSON, &m))
	m["extra"] = "member"
	m["kid"] = "client-kid"
	in, _ := json.Marshal(m)
	out, err := clientResponseEncryptionJWK(in, "ECDH-ES+A128KW")
	require.NoError(t, err)
	var got map[string]any
	require.NoError(t, json.Unmarshal(out, &got))
	assert.Equal(t, "enc", got["use"])
	assert.Equal(t, "ECDH-ES+A128KW", got["alg"])
	assert.Equal(t, "client-kid", got["kid"], "kid passes through when present, it is not required")
	assert.NotContains(t, got, "extra")
}

func TestBlind_ProofRequestCarriesNegotiatedEncryption(t *testing.T) {
	st := newIssuerStub(t, `{"credential":"c"}`)
	fc := &fakeClient{t: t}
	h, _, cleanup := newBlindHandler(t, fc, st.srv.Client())
	defer cleanup()
	cfg := &CredentialConfig{Format: "vc+sd-jwt", ProofTypesSupported: map[string]interface{}{"jwt": map[string]interface{}{}}}
	require.NoError(t, h.issueCredential(context.Background(), st.metadata(&CredentialResponseEncryptionConfig{
		AlgValuesSupported: []string{"ECDH-ES+A256KW"}, EncValuesSupported: []string{"A128GCM"}, EncryptionRequired: true}), tokenBearer(), "cfg", cfg, nil, ""))
	var found bool
	for _, m := range fc.outboundMessages() {
		if string(m["action"]) != `"generate_proof"` {
			continue
		}
		found = true
		var p struct {
			CRE map[string]any `json:"credential_response_encryption"`
		}
		require.NoError(t, json.Unmarshal(m["params"], &p))
		assert.Equal(t, map[string]any{"alg": "ECDH-ES+A256KW", "enc": "A128GCM", "required": true}, p.CRE)
	}
	assert.True(t, found)
}

func TestBlind_NoEncryptionOfferedWhenIssuerOffersNone(t *testing.T) {
	st := newIssuerStub(t, `{"credential":"c"}`)
	fc := &fakeClient{t: t}
	h, _, cleanup := newBlindHandler(t, fc, st.srv.Client())
	defer cleanup()
	cfg := &CredentialConfig{Format: "vc+sd-jwt", ProofTypesSupported: map[string]interface{}{"jwt": map[string]interface{}{}}}
	require.NoError(t, h.issueCredential(context.Background(), st.metadata(nil), tokenBearer(), "cfg", cfg, nil, ""))
	for _, m := range fc.outboundMessages() {
		assert.NotContains(t, string(m["params"]), "credential_response_encryption")
	}
	assert.Equal(t, []SignAction{SignActionGenerateProof}, fc.actions())
}

// A configuration without key binding still gets its key, in a key-only
// generate_proof (no proof_types_supported, no proofs expected back).
func TestBlind_NoProofConfigStillGetsKey(t *testing.T) {
	st := newIssuerStub(t, seedResponse)
	fc := &fakeClient{t: t}
	h, _, cleanup := newBlindHandler(t, fc, st.srv.Client())
	defer cleanup()
	cfg := seedCfg()
	cfg.Format = "vc+sd-jwt"
	require.NoError(t, h.issueCredential(context.Background(), st.metadata(gcmCfg(false)), tokenBearer(), "cfg", cfg, nil, ""))
	assert.Equal(t, []SignAction{SignActionGenerateProof, SignActionDecryptCredentialResponse}, fc.actions())
	require.Len(t, st.requests, 1)
	assert.Contains(t, st.requests[0], "credential_response_encryption")
	assert.NotContains(t, st.requests[0], "proofs")
}

// A fresh key per generate_proof (the c_nonce retry loop must not reuse one).
func TestBlind_FreshKeyPerProofRequest(t *testing.T) {
	calls := 0
	var seen []map[string]any
	var st *issuerStub
	st = newIssuerStub(t, `{"credential":"c"}`)
	inner := st.srv.Config.Handler
	st.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			raw, _ := io.ReadAll(r.Body)
			var req map[string]any
			_ = json.Unmarshal(raw, &req)
			seen = append(seen, req["credential_response_encryption"].(map[string]any))
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_nonce","c_nonce":"n2"}`))
			return
		}
		inner.ServeHTTP(w, r)
	})
	fc := &fakeClient{t: t}
	h, _, cleanup := newBlindHandler(t, fc, st.srv.Client())
	defer cleanup()
	cfg := &CredentialConfig{Format: "vc+sd-jwt", ProofTypesSupported: map[string]interface{}{"jwt": map[string]interface{}{}}}
	require.NoError(t, h.issueCredential(context.Background(), st.metadata(gcmCfg(false)), tokenBearer(), "cfg", cfg, nil, ""))
	require.Len(t, fc.keys, 2, "one key per generate_proof")
	require.Len(t, st.requests, 1)
	second := st.requests[0]["credential_response_encryption"].(map[string]any)
	assert.NotEqual(t, seen[0]["jwk"], second["jwk"])
	require.Len(t, fc.decrypted, 1, "the response is decrypted with the second key")
}

// --- the JWE relay itself ---

// A failure that is not the client's report (here the flow's context ending) is
// passed through unchanged, not rewritten as a client decryption failure. The
// client never answers, so the context ending is the only way out of RequestSign
// and the outcome does not depend on a reply racing the cancellation.
func TestRelayEncryptedResponse_NonClientFailureIsNotRewritten(t *testing.T) {
	conn, cleanup := wsTestServer(t, func(srv *websocket.Conn) {
		defer srv.Close()
		for {
			if _, _, err := srv.ReadMessage(); err != nil {
				return
			}
		}
	})
	defer cleanup()
	h := &OID4VCIHandler{}
	h.BaseHandler = BaseHandler{Logger: zap.NewNop(), Flow: &Flow{ID: "f-blind", Session: testSession(conn), Data: map[string]interface{}{}}}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := h.relayEncryptedResponse(ctx, "a.b.c.d.e", false, &responseEncryption{})
	require.ErrorIs(t, err, context.Canceled)
	var se *SignError
	assert.False(t, errors.As(err, &se))
}

func TestRelayEncryptedResponse_RefusesMalformedJWE(t *testing.T) {
	for name, jwe := range map[string]string{
		"empty":            "",
		"json body":        `{"credential":"` + secretCred1 + `"}`,
		"too few parts":    "a.b.c.d",
		"too many parts":   "a.b.c.d.e.f",
		"empty header":     ".b.c.d.e",
		"empty iv":         "a.b..d.e",
		"empty ciphertext": "a.b.c..e",
		"empty tag":        "a.b.c.d.",
		"not base64url":    "a.b.c.d.e=",
		"space":            "a.b.c.d. e",
		"plain jwt":        "eyJhbGciOiJub25lIn0.eyJhIjoxfQ.",
	} {
		t.Run(name, func(t *testing.T) {
			fc := &fakeClient{t: t}
			h, logs, cleanup := newBlindHandler(t, fc, http.DefaultClient)
			defer cleanup()
			_, err := h.relayEncryptedResponse(context.Background(), jwe, false, &responseEncryption{})
			require.Error(t, err)
			assertNoSecrets(t, "error", err.Error())
			assertNoSecrets(t, "logs", logDump(logs))
			assert.Empty(t, fc.actions(), "nothing is relayed to the client")
		})
	}
	// Compact shape with an empty encrypted key (ECDH-ES direct) is fine.
	assert.True(t, isCompactJWE("a..c.d.e"))
}

func TestRelayEncryptedResponse_ClientAnswers(t *testing.T) {
	cases := map[string]struct {
		resp    SignResponseMessage
		wantErr bool
	}{
		"transaction":                   {resp: SignResponseMessage{TransactionID: "t", Interval: 3}},
		"count":                         {resp: SignResponseMessage{CredentialCount: 2}},
		"error":                         {resp: SignResponseMessage{Error: "x"}, wantErr: true},
		"neither":                       {resp: SignResponseMessage{}, wantErr: true},
		"both":                          {resp: SignResponseMessage{TransactionID: "t", CredentialCount: 1}, wantErr: true},
		"negative count":                {resp: SignResponseMessage{CredentialCount: -1}, wantErr: true},
		"count over the cap":            {resp: SignResponseMessage{CredentialCount: maxEncryptedCredentialCount + 1}, wantErr: true},
		"count at the cap":              {resp: SignResponseMessage{CredentialCount: maxEncryptedCredentialCount}},
		"negative interval is ignored":  {resp: SignResponseMessage{TransactionID: "t", Interval: -5}},
		"transaction with credential_c": {resp: SignResponseMessage{TransactionID: "t", CredentialCount: 0, Interval: 0}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			fc := &fakeClient{t: t, reply: func([]byte) (SignResponseMessage, bool) { return tc.resp, true }}
			h, _, cleanup := newBlindHandler(t, fc, http.DefaultClient)
			defer cleanup()
			k := fc.newKey()
			var jm any
			require.NoError(t, json.Unmarshal(mustJWK(t, k), &jm))
			jm.(map[string]any)["alg"] = "ECDH-ES"
			enc := map[string]any{"enc": "A128GCM", "jwk": jm}
			out, err := h.relayEncryptedResponse(context.Background(), jweTo(t, enc, `{"credential":"c"}`), false, &responseEncryption{})
			if tc.wantErr {
				require.Error(t, err)
				assert.NotContains(t, err.Error(), "x\"", "client error text is not surfaced")
				return
			}
			require.NoError(t, err)
			assert.True(t, out.Encrypted)
		})
	}
}

// The client's error text is client-controlled and here deliberately echoes
// the decrypted plaintext: it must not reach an error or a log.
func TestRelayEncryptedResponse_ClientErrorTextNeverSurfaced(t *testing.T) {
	st := newIssuerStub(t, seedResponse)
	fc := &fakeClient{t: t, decryptErr: true}
	h, logs, cleanup := newBlindHandler(t, fc, st.srv.Client())
	defer cleanup()
	err := h.issueCredential(context.Background(), st.metadata(gcmCfg(false)), tokenBearer(), "cfg", seedConfig(), nil, "")
	require.Error(t, err)
	require.NotEmpty(t, fc.decrypted, "the client did see the plaintext, so the echo is real")
	assertNoSecrets(t, "error", err.Error())
	assertNoSecrets(t, "logs", logDump(logs))
	assertNoSecrets(t, "outbound", fc.engineSaw())
	assert.NotContains(t, completionTypes(fc), "flow_complete")
}

// The issuer ignores our key and answers in clear although a seed was
// advertised: refused unread (existing behaviour, preserved).
func TestBlind_SeedPlainAnswerRefusedUnread(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(seedResponse))
	}))
	defer srv.Close()
	fc := &fakeClient{t: t}
	h, logs, cleanup := newBlindHandler(t, fc, srv.Client())
	defer cleanup()
	md := &IssuerMetadata{CredentialIssuer: srv.URL, CredentialEndpoint: srv.URL, CredentialResponseEncryption: gcmCfg(false)}
	err := h.issueCredential(context.Background(), md, tokenBearer(), "cfg", seedConfig(), nil, "")
	require.Error(t, err)
	assertNoSecrets(t, "error", err.Error())
	assertNoSecrets(t, "logs", logDump(logs))
	assertNoSecrets(t, "outbound", fc.engineSaw())
}

// A JWE content type with a body that is not a compact JWE is refused.
func TestBlind_NonCompactBodyUnderJWTContentTypeRefused(t *testing.T) {
	for name, body := range map[string]string{"empty": "", "json": seedResponse} {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/jwt")
				_, _ = w.Write([]byte(body))
			}))
			defer srv.Close()
			fc := &fakeClient{t: t}
			h, logs, cleanup := newBlindHandler(t, fc, srv.Client())
			defer cleanup()
			md := &IssuerMetadata{CredentialIssuer: srv.URL, CredentialEndpoint: srv.URL, CredentialResponseEncryption: gcmCfg(false)}
			cfg := &CredentialConfig{Format: "vc+sd-jwt", ProofTypesSupported: map[string]interface{}{"jwt": map[string]interface{}{}}}
			require.Error(t, h.issueCredential(context.Background(), md, tokenBearer(), "cfg", cfg, nil, ""))
			assert.NotContains(t, fc.actions(), SignActionDecryptCredentialResponse)
			assertNoSecrets(t, "logs", logDump(logs))
			assertNoSecrets(t, "outbound", fc.engineSaw())
		})
	}
}

func TestBlind_ProofErrorAndMissingKey(t *testing.T) {
	st := newIssuerStub(t, seedResponse)
	fc := &fakeClient{t: t, errorOnProof: true}
	h, _, cleanup := newBlindHandler(t, fc, st.srv.Client())
	defer cleanup()
	require.Error(t, h.issueCredential(context.Background(), st.metadata(gcmCfg(false)), tokenBearer(), "cfg", seedConfig(), nil, ""))
	assert.Empty(t, st.requests)
}

// --- negotiation from issuer metadata ---

func TestNegotiateResponseEncryption(t *testing.T) {
	h := &OID4VCIHandler{}
	h.BaseHandler = BaseHandler{Logger: zap.NewNop()}
	// Flow nil: h.Error would panic, so only success and the non-sending
	// (non-seed) failure paths are covered here; the seed refusals are
	// exercised through the handler in TestBlind_SeedRefusals.
	plain := &CredentialConfig{Format: "x"}
	type tc struct {
		cfg      *CredentialResponseEncryptionConfig
		wantNil  bool
		alg, enc string
		required bool
		wantErr  string
	}
	for name, c := range map[string]tc{
		"none offered": {cfg: nil, wantNil: true},
		"prefers plain ECDH-ES and A256GCM": {cfg: &CredentialResponseEncryptionConfig{
			AlgValuesSupported: []string{"ECDH-ES+A128KW", "ECDH-ES"}, EncValuesSupported: []string{"A128GCM", "A256GCM"}}, alg: "ECDH-ES", enc: "A256GCM"},
		"gdc style KW only": {cfg: &CredentialResponseEncryptionConfig{
			AlgValuesSupported: []string{"ECDH-ES+A256KW"}, EncValuesSupported: []string{"A256GCM"}}, alg: "ECDH-ES+A256KW", enc: "A256GCM"},
		"A128KW with CBC": {cfg: &CredentialResponseEncryptionConfig{
			AlgValuesSupported: []string{"ECDH-ES+A128KW"}, EncValuesSupported: []string{"A128CBC-HS256"}}, alg: "ECDH-ES+A128KW", enc: "A128CBC-HS256"},
		"issuer requires => required": {cfg: &CredentialResponseEncryptionConfig{
			AlgValuesSupported: []string{"ECDH-ES"}, EncValuesSupported: []string{"A128GCM"}, EncryptionRequired: true}, alg: "ECDH-ES", enc: "A128GCM", required: true},
		"unsupported alg, optional": {cfg: &CredentialResponseEncryptionConfig{
			AlgValuesSupported: []string{"RSA-OAEP-256"}, EncValuesSupported: []string{"A128GCM"}}, wantNil: true},
		"unsupported enc, optional": {cfg: &CredentialResponseEncryptionConfig{
			AlgValuesSupported: []string{"ECDH-ES"}, EncValuesSupported: []string{"A192GCM"}}, wantNil: true},
		"unsupported but required": {cfg: &CredentialResponseEncryptionConfig{
			AlgValuesSupported: []string{"RSA-OAEP-256"}, EncValuesSupported: []string{"A128CBC-HS256"}, EncryptionRequired: true},
			wantErr: "no mutually supported alg/enc pair"},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := h.negotiateResponseEncryption(&IssuerMetadata{CredentialResponseEncryption: c.cfg}, plain)
			if c.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), c.wantErr)
				return
			}
			require.NoError(t, err)
			if c.wantNil {
				assert.Nil(t, got)
				return
			}
			require.NotNil(t, got)
			assert.Equal(t, c.alg, got.Alg)
			assert.Equal(t, c.enc, got.Enc)
			assert.Equal(t, c.required, got.Required)
			assert.False(t, got.Seed)
			assert.Empty(t, got.JWK, "no key before the client answers")
		})
	}
}

func TestBlind_SeedRefusals(t *testing.T) {
	cases := map[string]*CredentialResponseEncryptionConfig{
		"issuer offers no encryption": nil,
		"no mutually supported pair":  {AlgValuesSupported: []string{"RSA-OAEP"}, EncValuesSupported: []string{"A128GCM"}},
		"enc not offered by issuer":   {AlgValuesSupported: []string{"ECDH-ES"}, EncValuesSupported: []string{"A192GCM"}},
	}
	for name, encCfg := range cases {
		t.Run(name, func(t *testing.T) {
			st := newIssuerStub(t, seedResponse)
			fc := &fakeClient{t: t}
			h, logs, cleanup := newBlindHandler(t, fc, st.srv.Client())
			defer cleanup()
			err := h.issueCredential(context.Background(), st.metadata(encCfg), tokenBearer(), "cfg", seedConfig(), nil, "")
			require.Error(t, err)
			assert.Empty(t, st.requests, "refused before any request")
			assert.Empty(t, fc.actions(), "refused before the client is asked for a key")
			assertNoSecrets(t, "logs", logDump(logs))
		})
	}
	t.Run("malformed advertisement", func(t *testing.T) {
		st := newIssuerStub(t, seedResponse)
		fc := &fakeClient{t: t}
		h, _, cleanup := newBlindHandler(t, fc, st.srv.Client())
		defer cleanup()
		cfg := seedCfg()
		cfg.AuxiliaryDataSupported = json.RawMessage(`{"to_wallet":[{"type":"hash_commitment","alg":"sha-256","path":["a"],"opening":"` + secretSeedA + `"}]}`)
		err := h.issueCredential(context.Background(), st.metadata(gcmCfg(false)), tokenBearer(), "cfg", cfg, nil, "")
		require.Error(t, err)
		assert.NotContains(t, err.Error(), secretSeedA)
		assert.Empty(t, st.requests)
	})
}

// An advertised seed makes the request required; the plain response of an
// issuer that merely supports encryption stays engine-visible by policy.
func TestBlind_SeedAdvertisementMakesEncryptionRequired(t *testing.T) {
	h, _, cleanup := newBlindHandler(t, &fakeClient{t: t}, http.DefaultClient)
	defer cleanup()
	got, err := h.negotiateResponseEncryption(&IssuerMetadata{CredentialResponseEncryption: gcmCfg(false)}, seedCfg())
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.True(t, got.Required)
	assert.True(t, got.Seed)
}

// --- flow_complete and messages ---

func TestFlowComplete_PlainResponseUnchanged(t *testing.T) {
	h, ch, cleanup := captureHandler(t)
	defer cleanup()
	resp := &CredentialResponse{Credentials: []interface{}{"c0", "c1"}, NotificationID: "n-1"}
	require.NoError(t, h.finishIssuance(context.Background(), resp, &CredentialConfig{Format: "mso_mdoc"}, nil, nil, &TokenResponse{}))
	m := nextMsg(t, ch)
	assert.NotContains(t, m, "credential_response_encrypted")
	assert.NotContains(t, m, "credential_metadata")
	var creds []CredentialResult
	require.NoError(t, json.Unmarshal(m["credentials"], &creds))
	require.Len(t, creds, 2)
	assert.Equal(t, "c0", creds[0].Credential)
	assert.Equal(t, "n-1", creds[0].NotificationID)
}

// Plain response without a seed: only display and claims are relayed; every
// extension member is dropped.
func TestPlainResponse_OnlyDisplayMetadataRelayed(t *testing.T) {
	core, logs := observer.New(zap.DebugLevel)
	h, ch, cleanup := captureHandler(t)
	defer cleanup()
	h.Logger = zap.New(core)
	var resp CredentialResponse
	body := `{"credentials":["c0"],"credential_metadata":{"display":[{"name":"MARKER-DISPLAY"}],` +
		`"claims":[{"path":["a"]}],"org.example.x":"OTHER-MEMBER"}}`
	require.NoError(t, json.Unmarshal([]byte(body), &resp))
	require.NoError(t, h.finishIssuance(context.Background(), &resp, &CredentialConfig{Format: "x"}, nil, nil, &TokenResponse{}))
	m := nextMsg(t, ch)
	assert.JSONEq(t, `{"display":[{"name":"MARKER-DISPLAY"}],"claims":[{"path":["a"]}]}`, string(m["credential_metadata"]))
	wire, err := json.Marshal(m)
	require.NoError(t, err)
	assertNoSecrets(t, "flow_complete", string(wire))
	assert.NotContains(t, string(wire), "OTHER-MEMBER")
	assertNoSecrets(t, "logs", logDump(logs))
	assert.NotContains(t, m, "credential_response_encrypted")
}

func TestPlainResponse_NoDisplayMembersMeansNoField(t *testing.T) {
	for _, md := range []string{`{"org.example.x":"OTHER-MEMBER"}`, `"str"`, `[1]`, `null`} {
		h, ch, cleanup := captureHandler(t)
		var resp CredentialResponse
		require.NoError(t, json.Unmarshal([]byte(`{"credentials":["c0"],"credential_metadata":`+md+`}`), &resp))
		require.NoError(t, h.finishIssuance(context.Background(), &resp, &CredentialConfig{Format: "x"}, nil, nil, &TokenResponse{}))
		m := nextMsg(t, ch)
		assert.NotContains(t, m, "credential_metadata")
		wire, _ := json.Marshal(m)
		assertNoSecrets(t, "flow_complete", string(wire))
		cleanup()
	}
}

// Encrypted: never any credential_metadata, even if a (buggy) path set it.
func TestEncryptedResponse_NeverCredentialMetadata(t *testing.T) {
	h, ch, cleanup := captureHandler(t)
	defer cleanup()
	resp := &CredentialResponse{Encrypted: true, CredentialCount: 1,
		CredentialMetadata: json.RawMessage(`{"display":[{"name":"X"}]}`)}
	require.NoError(t, h.finishIssuance(context.Background(), resp, &CredentialConfig{Format: "x"}, nil, nil, &TokenResponse{}))
	assert.NotContains(t, nextMsg(t, ch), "credential_metadata")
}

func TestSignRequestWire_DecryptAndGenerateProofShapes(t *testing.T) {
	f := false
	b, err := json.Marshal(SignRequestMessage{Action: SignActionDecryptCredentialResponse, Params: SignRequestParams{JWE: "a.b.c.d.e", Deferred: &f}})
	require.NoError(t, err)
	assert.JSONEq(t, `{"type":"","timestamp":0,"action":"decrypt_credential_response","params":{"jwe":"a.b.c.d.e","deferred":false}}`, normaliseEnvelope(b))
	b, err = json.Marshal(SignRequestParams{Count: 1, CredentialResponseEncryption: &CredentialResponseEncryptionParams{Alg: "ECDH-ES", Enc: "A256GCM", Required: false}})
	require.NoError(t, err)
	assert.JSONEq(t, `{"count":1,"credential_response_encryption":{"alg":"ECDH-ES","enc":"A256GCM","required":false}}`, string(b))
	// Absent on every other sign request.
	b, err = json.Marshal(SignRequestParams{Audience: "a"})
	require.NoError(t, err)
	assert.NotContains(t, string(b), "jwe")
	assert.NotContains(t, string(b), "deferred")
	assert.NotContains(t, string(b), "credential_response_encryption")
}

// normaliseEnvelope reduces a message to type/timestamp placeholders so a
// test can pin action and params only.
func normaliseEnvelope(b []byte) string {
	var m map[string]json.RawMessage
	_ = json.Unmarshal(b, &m)
	out := map[string]json.RawMessage{"type": json.RawMessage(`""`), "timestamp": json.RawMessage(`0`), "action": m["action"], "params": m["params"]}
	j, _ := json.Marshal(out)
	return string(j)
}

// The client may reject what it decrypted and then reports credential_failure:
// the notification context exists even though the client answered with error.
func TestBlind_NotificationContextSurvivesClientRejection(t *testing.T) {
	st := newIssuerStub(t, seedResponse)
	fc := &fakeClient{t: t, decryptErr: true}
	h, _, cleanup := newBlindHandler(t, fc, st.srv.Client())
	defer cleanup()
	require.Error(t, h.issueCredential(context.Background(), st.metadata(gcmCfg(false)), tokenBearer(), "cfg", seedConfig(), nil, ""))
	assert.True(t, h.Flow.Session.notifications.hasValid("f-blind", secretNotif))
}

// terminalErrors returns the flow_error messages the engine sent.
func terminalErrors(t *testing.T, fc *fakeClient) []FlowErrorMessage {
	t.Helper()
	var out []FlowErrorMessage
	for _, m := range fc.outboundMessages() {
		if string(m["type"]) != `"flow_error"` {
			continue
		}
		raw, err := json.Marshal(m)
		require.NoError(t, err)
		var em FlowErrorMessage
		require.NoError(t, json.Unmarshal(raw, &em))
		out = append(out, em)
	}
	return out
}

// Every way the immediate-response relay can fail must end the flow with one
// generic CREDENTIAL_ERROR: the session runner only logs a returned error, so
// without it the client would get neither completion nor a terminal message.
func TestBlind_ImmediateRelayFailureSendsTerminalError(t *testing.T) {
	cases := map[string]*fakeClient{
		"client decrypt error": {decryptErr: true},
		"neither field":        {reply: func([]byte) (SignResponseMessage, bool) { return SignResponseMessage{}, true }},
		"both fields": {reply: func([]byte) (SignResponseMessage, bool) {
			return SignResponseMessage{TransactionID: "t", CredentialCount: 1}, true
		}},
		"count over the cap": {reply: func([]byte) (SignResponseMessage, bool) {
			return SignResponseMessage{CredentialCount: maxEncryptedCredentialCount + 1}, true
		}},
	}
	for name, fc := range cases {
		t.Run(name, func(t *testing.T) {
			fc.t = t
			st := newIssuerStub(t, seedResponse)
			h, logs, cleanup := newBlindHandler(t, fc, st.srv.Client())
			defer cleanup()
			err := h.issueCredential(context.Background(), st.metadata(gcmCfg(false)), tokenBearer(), "cfg", seedConfig(), nil, "")
			require.Error(t, err)
			fc.settle()
			errs := terminalErrors(t, fc)
			require.Len(t, errs, 1, "exactly one terminal flow_error")
			assert.Equal(t, ErrCodeCredentialError, errs[0].Error.Code)
			assert.Equal(t, ErrCodeCredentialError.UserFacingMessage(), errs[0].Error.Message)
			assert.NotContains(t, completionTypes(fc), "flow_complete")
			assertNoSecrets(t, "outbound", fc.engineSaw())
			assertNoSecrets(t, "logs", logDump(logs))
			assert.NotContains(t, fc.engineSaw(), "client failed on")
		})
	}
}

func TestBlind_ImmediateMalformedJWESendsTerminalError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/jwt")
		_, _ = w.Write([]byte("not-a-jwe"))
	}))
	defer srv.Close()
	fc := &fakeClient{t: t}
	h, _, cleanup := newBlindHandler(t, fc, srv.Client())
	defer cleanup()
	md := &IssuerMetadata{CredentialIssuer: srv.URL, CredentialEndpoint: srv.URL, CredentialResponseEncryption: gcmCfg(false)}
	cfg := &CredentialConfig{Format: "vc+sd-jwt", ProofTypesSupported: map[string]interface{}{"jwt": map[string]interface{}{}}}
	require.Error(t, h.issueCredential(context.Background(), md, tokenBearer(), "cfg", cfg, nil, ""))
	fc.settle()
	errs := terminalErrors(t, fc)
	require.Len(t, errs, 1)
	assert.Equal(t, ErrCodeCredentialError, errs[0].Error.Code)
	assert.NotContains(t, fc.actions(), SignActionDecryptCredentialResponse)
}

// A plain initial response carrying a transaction_id followed by an encrypted
// deferred response the client rejects: the client still owes the issuer a
// credential_failure, so the notification context must exist.
func TestBlind_DeferredRelayRejection_NotificationContextExists(t *testing.T) {
	fastDeferredPolling(t)
	st := newIssuerStub(t, "", seedResponse)
	inner := st.srv.Config.Handler
	st.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/deferred_credential") {
			inner.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"transaction_id":"tx-plain","interval":1}`))
	})
	md := st.metadata(gcmCfg(false))
	fc := &fakeClient{t: t, decryptErr: true}
	h, logs, cleanup := newBlindHandler(t, fc, st.srv.Client())
	defer cleanup()
	cfg := &CredentialConfig{Format: "vc+sd-jwt", ProofTypesSupported: map[string]interface{}{"jwt": map[string]interface{}{}}}
	require.Error(t, h.issueCredential(context.Background(), md, tokenBearer(), "cfg", cfg, nil, ""))
	require.Contains(t, fc.actions(), SignActionDecryptCredentialResponse, "the deferred JWE was relayed")
	assert.True(t, h.Flow.Session.notifications.hasValid("f-blind", "id-the-client-read"))
	assertNoSecrets(t, "logs", logDump(logs))
	assertNoSecrets(t, "outbound", fc.engineSaw())
}

// An advertised batch_size above what an encrypted response can carry is
// capped when response encryption is offered, so the proof count never exceeds
// what the relay accepts.
func TestBlind_BatchSizeCappedWhenResponseEncrypted(t *testing.T) {
	st := newIssuerStub(t, `{"credentials":[{"credential":"c"}]}`)
	fc := &fakeClient{t: t}
	h, _, cleanup := newBlindHandler(t, fc, st.srv.Client())
	defer cleanup()
	md := st.metadata(gcmCfg(false))
	md.BatchCredentialIssuance = &BatchCredentialIssuance{BatchSize: maxEncryptedCredentialCount + 1}
	cfg := &CredentialConfig{Format: "vc+sd-jwt", ProofTypesSupported: map[string]interface{}{"jwt": map[string]interface{}{}}}
	require.NoError(t, h.issueCredential(context.Background(), md, tokenBearer(), "cfg", cfg, nil, ""))
	require.Len(t, st.requests, 1)
	proofs, _ := st.requests[0]["proofs"].(map[string]any)
	jwts, _ := proofs["jwt"].([]any)
	assert.Len(t, jwts, maxEncryptedCredentialCount)
	_ = completion(t, fc)
}
