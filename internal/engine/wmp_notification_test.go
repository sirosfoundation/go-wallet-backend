package engine

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sirosfoundation/go-tokenauth/claims"
	"github.com/sirosfoundation/go-wmp/pkg/wmp"
	"github.com/sirosfoundation/go-wmp/pkg/wmp/openid4x"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

// ---------------------------------------------------------------------------
// Harness: the adapter driven in-process over wmp.ChannelTransport, the way an
// embedder drives it (no HTTP between wallet and engine), with an issuer's
// notification endpoint behind httptest.
// ---------------------------------------------------------------------------

// notifIssuer is an issuer's notification endpoint that records the requests it
// gets.
type notifIssuer struct {
	srv *httptest.Server

	mu       sync.Mutex
	requests []notifRequest
	status   int // the answer; 204 when zero
}

type notifRequest struct {
	URI           string
	Authorization string
	DPoP          string
	Body          map[string]any
}

func newNotifIssuer(t *testing.T) *notifIssuer {
	t.Helper()
	ni := &notifIssuer{}
	ni.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var body map[string]any
		_ = json.Unmarshal(b, &body)
		ni.mu.Lock()
		ni.requests = append(ni.requests, notifRequest{URI: r.URL.RequestURI(), Authorization: r.Header.Get("Authorization"), DPoP: r.Header.Get("DPoP"), Body: body})
		status := ni.status
		ni.mu.Unlock()
		if status == 0 {
			status = http.StatusNoContent
		}
		w.WriteHeader(status)
	}))
	t.Cleanup(ni.srv.Close)
	return ni
}

func (ni *notifIssuer) endpoint() string { return ni.srv.URL + "/notify?tenant=a" }

func (ni *notifIssuer) count() int {
	ni.mu.Lock()
	defer ni.mu.Unlock()
	return len(ni.requests)
}

func (ni *notifIssuer) last() notifRequest {
	ni.mu.Lock()
	defer ni.mu.Unlock()
	return ni.requests[len(ni.requests)-1]
}

// chanWallet is a wallet on a ChannelTransport: it pushes what a wallet sends
// and reads what the engine sends.
type chanWallet struct {
	t    *testing.T
	a    *WMPAdapter
	ct   *wmp.ChannelTransport
	ctx  context.Context
	sid  string
	seq  int
	back []map[string]any
}

type chanEnv struct {
	t   *testing.T
	m   *Manager
	a   *WMPAdapter
	iss *notifIssuer
	key *ecdsa.PrivateKey // the wallet's DPoP key: the issuance token is bound to it
}

// newChanEnv builds an engine whose OID4VCI flow is scripted to finish an issuance
// of one credential with finishIssuance (the real completion and the real
// registration of the notification context), against the issuer's notification
// endpoint. tokenType and the client-held mode are what the issuance negotiated;
// encrypted makes the response one the engine cannot read.
func newChanEnv(t *testing.T, tokenType string, encrypted bool) *chanEnv {
	t.Helper()
	cfg := &config.Config{}
	cfg.HTTPClient.AllowPrivateIPs = true // the issuer is on loopback
	m := NewManager(cfg, zap.NewNop())
	a := NewWMPAdapter(m, zap.NewNop(), func(*http.Request) string { return "" })
	t.Cleanup(func() { a.Close(); m.Close() })
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	e := &chanEnv{t: t, m: m, a: a, iss: newNotifIssuer(t), key: key}
	registerScripted(m, ProtocolOID4VCI, func(ctx context.Context, f *Flow, _ *FlowStartMessage) error {
		h := &OID4VCIHandler{clientAuthMode: clientAuthClientHeld, dpopKeyID: "kid-1"}
		h.BaseHandler = BaseHandler{Flow: f, Logger: zap.NewNop()}
		resp := &CredentialResponse{Credential: "cred-1", NotificationID: "nid-1"}
		if encrypted {
			resp = &CredentialResponse{Encrypted: true, CredentialCount: 1}
		}
		return h.finishIssuance(ctx, resp, &CredentialConfig{Format: "dc+sd-jwt", VCT: "https://v.example/pid"}, nil,
			&IssuerMetadata{CredentialIssuer: "https://issuer.example", NotificationEndpoint: e.iss.endpoint()},
			&TokenResponse{AccessToken: "access-1", TokenType: tokenType})
	})
	return e
}

// wallet creates a session for user offering capabilities and returns its wallet.
func (e *chanEnv) wallet(user string, tac claims.TAC, offered ...string) *chanWallet {
	e.t.Helper()
	principal := NewWMPPrincipal(user, "t1", "jti-"+user, tac)
	ctx, cancel := context.WithCancel(wmp.ContextWithPrincipal(context.Background(), principal))
	e.t.Cleanup(cancel)

	h, opts := e.a.NewSessionHandler(ctx, principal, "")
	createPeer := wmp.NewPeer(wmp.NewChannelTransport(8, 8), h, opts...)
	caps := map[string]any{}
	for _, c := range offered {
		caps[c] = map[string]any{}
	}
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": "c1", "method": wmp.MethodSessionCreate, "params": map[string]any{
		"wmp": map[string]any{"version": wmp.Version}, "security": map[string]any{"mode": "tls"}, "capabilities_offered": caps}})
	out, err := createPeer.HandleRequestSync(ctx, body)
	require.NoError(e.t, err)
	var created wmp.Response
	require.NoError(e.t, json.Unmarshal(out, &created))
	require.Nil(e.t, created.Error, "%s", out)
	var res wmp.SessionCreateResult
	require.NoError(e.t, json.Unmarshal(created.Result, &res))

	h2, opts2 := e.a.NewSessionHandler(ctx, principal, res.WMP.SessionID)
	ct := wmp.NewChannelTransport(16, 16)
	peer := wmp.NewPeer(ct, h2, opts2...)
	go func() { _ = peer.Serve(ctx) }()
	return &chanWallet{t: e.t, a: e.a, ct: ct, ctx: ctx, sid: res.WMP.SessionID}
}

func (w *chanWallet) push(msg map[string]any) {
	w.t.Helper()
	msg["jsonrpc"] = "2.0"
	b, err := json.Marshal(msg)
	require.NoError(w.t, err)
	require.NoError(w.t, w.ct.Push(b))
}

// recv returns the next message the engine sent, from the backlog first.
func (w *chanWallet) recv(match func(map[string]any) bool) map[string]any {
	w.t.Helper()
	for i, m := range w.back {
		if match(m) {
			w.back = append(w.back[:i], w.back[i+1:]...)
			return m
		}
	}
	deadline := time.After(10 * time.Second)
	for {
		select {
		case data := <-w.ct.Out():
			var m map[string]any
			require.NoError(w.t, json.Unmarshal(data, &m))
			if match(m) {
				return m
			}
			w.back = append(w.back, m)
		case <-deadline:
			w.t.Fatalf("timed out; unmatched messages: %v", w.back)
		}
	}
}

func (w *chanWallet) method(name string) map[string]any {
	w.t.Helper()
	return w.recv(func(m map[string]any) bool { return m["method"] == name })
}

// call sends a request and returns its response (result or error).
func (w *chanWallet) call(method string, params map[string]any) map[string]any {
	w.t.Helper()
	w.seq++
	id := "w" + string(rune('a'+w.seq))
	w.push(map[string]any{"id": id, "method": method, "params": params})
	return w.recv(func(m map[string]any) bool { return m["id"] == id && m["method"] == nil })
}

func (w *chanWallet) start(flowType, flowID string, params map[string]any, extra ...map[string]any) map[string]any {
	p := map[string]any{"wmp": meta(w.sid), "flow_type": flowType, "flow_id": flowID, "params": params}
	for _, x := range extra {
		for k, v := range x {
			p[k] = v
		}
	}
	return w.call(wmp.MethodFlowStart, p)
}

func (w *chanWallet) issue(flowID string) map[string]any {
	w.t.Helper()
	r := w.start("oid4vci", flowID, map[string]any{"credential_offer": "openid-credential-offer://x"})
	require.Nil(w.t, r["error"], "%v", r)
	return w.method(wmp.MethodFlowComplete)
}

func (w *chanWallet) notify(flowID, issuanceFlowID, notificationID, event string, extra ...map[string]any) map[string]any {
	return w.start(openid4x.FlowTypeCredentialNotification, flowID,
		map[string]any{"issuance_flow_id": issuanceFlowID, "notification_id": notificationID, "event": event}, extra...)
}

func rpcParams(m map[string]any) map[string]any {
	p, _ := m["params"].(map[string]any)
	return p
}

func rpcError(m map[string]any) (code int, data map[string]any) {
	e, _ := m["error"].(map[string]any)
	c, _ := e["code"].(float64)
	d, _ := e["data"].(map[string]any)
	return int(c), d
}

// answerSign is the wallet's side of a sign_client_auth sub-flow: it accepts the
// start and completes it with a DPoP proof over exactly the requested values,
// signed with the key the token is bound to. It returns the start's params.
func (w *chanWallet) answerSign(key *ecdsa.PrivateKey, accessToken string) map[string]any {
	w.t.Helper()
	start := w.method(wmp.MethodFlowStart)
	p := rpcParams(start)
	require.Equal(w.t, "sign", p["flow_type"])
	sp, _ := p["params"].(map[string]any)
	proof, err := createDPoPProof(key, sp["htm"].(string), sp["htu"].(string), accessToken, "")
	require.NoError(w.t, err)
	w.push(map[string]any{"id": start["id"], "result": map[string]any{"wmp": meta(w.sid), "flow_id": p["flow_id"], "flow_type": "sign"}})
	w.push(notification(wmp.MethodFlowComplete, map[string]any{"wmp": meta(w.sid), "flow_id": p["flow_id"], "result": map[string]any{"dpop_proof": proof}}))
	return sp
}

// notificationOutcome is the terminal message of a notification flow.
func (w *chanWallet) outcome(flowID string) (method string, params map[string]any) {
	w.t.Helper()
	m := w.recv(func(m map[string]any) bool {
		return (m["method"] == wmp.MethodFlowComplete || m["method"] == wmp.MethodFlowError) && rpcParams(m)["flow_id"] == flowID
	})
	return m["method"].(string), rpcParams(m)
}

func (w *chanWallet) reason(flowID string) (reason string, retryable bool) {
	w.t.Helper()
	method, p := w.outcome(flowID)
	require.Equal(w.t, wmp.MethodFlowError, method, "%v", p)
	assert.EqualValues(w.t, wmp.ErrFlowError, p["code"])
	d, _ := p["data"].(map[string]any)
	assert.Len(w.t, d, 2, "reason and retryable, nothing else: %v", d)
	reason, _ = d["reason"].(string)
	retryable, _ = d["retryable"].(bool)
	return reason, retryable
}

const fullTAC claims.TAC = "ir"

// ---------------------------------------------------------------------------
// The end-to-end flow
// ---------------------------------------------------------------------------

// An issuance completes, the wallet starts the notification flow, the engine
// asks for a DPoP proof with a sign_client_auth sub-flow of the notification
// flow, the wallet signs it for the htu without query, and the engine forwards
// the event to the issuer, with the request going to the full endpoint. The id
// is then spent.
func TestWMPNotification_EndToEnd(t *testing.T) {
	e := newChanEnv(t, "DPoP", false)
	w := e.wallet("alice", fullTAC, "oid4vci", "credential_notification")

	done := w.issue("f1")
	res := rpcParams(done)["result"].(map[string]any)
	creds := res["credentials"].([]any)
	require.Len(t, creds, 1)
	assert.Equal(t, "nid-1", creds[0].(map[string]any)["notification_id"], "plain responses carry the issuer's id")
	assert.Equal(t, e.iss.endpoint(), res["notification_endpoint"], "the wallet records it with the issuance")
	for _, k := range []string{"type", "flow_id", "message_id", "timestamp"} {
		assert.NotContains(t, res, k)
	}

	r := w.notify("n1", "f1", "nid-1", "credential_accepted")
	require.Nil(t, r["error"], "%v", r)
	assert.Equal(t, "n1", r["result"].(map[string]any)["flow_id"])

	sp := w.answerSign(e.key, "access-1")
	assert.Equal(t, "sign_client_auth", sp["action"])
	assert.Equal(t, "n1", sp["parent_flow_id"], "a sub-flow of the notification flow")
	assert.Equal(t, "POST", sp["htm"])
	assert.Equal(t, e.iss.srv.URL+"/notify", sp["htu"], "the htu has no query")
	assert.Equal(t, accessTokenHash("access-1"), sp["ath"])
	assert.Equal(t, "https://issuer.example", sp["audience"])
	assert.NotContains(t, sp, "key_id", "the dpop_key_id is a secret of the issuance")

	method, p := w.outcome("n1")
	require.Equal(t, wmp.MethodFlowComplete, method, "%v", p)
	assert.Equal(t, map[string]any{"status": "forwarded", "notification_id": "nid-1"}, p["result"])

	require.Equal(t, 1, e.iss.count())
	got := e.iss.last()
	assert.Equal(t, "/notify?tenant=a", got.URI, "the request goes to the full endpoint")
	assert.Equal(t, "DPoP access-1", got.Authorization)
	assert.Equal(t, map[string]any{"notification_id": "nid-1", "event": "credential_accepted"}, got.Body)
	// The proof is the wallet's, over exactly the request that was made.
	seg := strings.Split(got.DPoP, ".")
	require.Len(t, seg, 3, "a DPoP proof JWT")
	payload, err := base64.RawURLEncoding.DecodeString(seg[1])
	require.NoError(t, err)
	var pc map[string]any
	require.NoError(t, json.Unmarshal(payload, &pc))
	assert.Equal(t, "POST", pc["htm"])
	assert.Equal(t, e.iss.srv.URL+"/notify", pc["htu"])
	assert.Equal(t, accessTokenHash("access-1"), pc["ath"])

	// Single use.
	w.notify("n2", "f1", "nid-1", "credential_accepted")
	reason, retryable := w.reason("n2")
	assert.Equal(t, "context_unavailable", reason)
	assert.False(t, retryable)
	assert.Equal(t, 1, e.iss.count(), "the issuer is told once")
}

// A token that is not DPoP-bound needs no proof: no sub-flow, the event is
// forwarded, and an event_description travels.
func TestWMPNotification_BearerNeedsNoSigning(t *testing.T) {
	e := newChanEnv(t, "Bearer", false)
	w := e.wallet("alice", fullTAC, "oid4vci", "credential_notification")
	w.issue("f1")
	r := w.start(openid4x.FlowTypeCredentialNotification, "n1",
		map[string]any{"issuance_flow_id": "f1", "notification_id": "nid-1", "event": "credential_failure", "event_description": "could not store"})
	require.Nil(t, r["error"], "%v", r)
	method, p := w.outcome("n1")
	require.Equal(t, wmp.MethodFlowComplete, method, "%v", p)
	got := e.iss.last()
	assert.Equal(t, "Bearer access-1", got.Authorization)
	assert.Empty(t, got.DPoP)
	assert.Equal(t, map[string]any{"notification_id": "nid-1", "event": "credential_failure", "event_description": "could not store"}, got.Body)
	for _, m := range w.back {
		assert.NotEqual(t, wmp.MethodFlowStart, m["method"], "no sign sub-flow")
	}
}

// An encrypted response is relayed unread: the completion carries no
// notification_id of the issuer's, the engine accepts the id the wallet read from
// the decrypted response (once each), and the endpoint is still recorded.
func TestWMPNotification_EncryptedResponseTakesTheWalletsIDs(t *testing.T) {
	e := newChanEnv(t, "Bearer", true)
	w := e.wallet("alice", fullTAC, "oid4vci", "credential_notification")
	done := w.issue("f1")
	res := rpcParams(done)["result"].(map[string]any)
	assert.Equal(t, e.iss.endpoint(), res["notification_endpoint"])
	for _, c := range res["credentials"].([]any) {
		assert.NotContains(t, c, "notification_id")
	}

	for i, id := range []string{"wallet-id-1", "wallet-id-2"} {
		fid := "n" + string(rune('1'+i))
		w.notify(fid, "f1", id, "credential_accepted")
		method, p := w.outcome(fid)
		require.Equal(t, wmp.MethodFlowComplete, method, "%v", p)
		assert.Equal(t, id, e.iss.last().Body["notification_id"])
	}
	w.notify("n3", "f1", "wallet-id-1", "credential_accepted")
	reason, _ := w.reason("n3")
	assert.Equal(t, "context_unavailable", reason, "each id once")
	assert.Equal(t, 2, e.iss.count())
}

// ---------------------------------------------------------------------------
// Failure reasons (OpenID4x 3.4.2): only the reason and retryable reach the wallet.
// ---------------------------------------------------------------------------

func TestWMPNotification_ContextUnavailable(t *testing.T) {
	e := newChanEnv(t, "Bearer", false)
	w := e.wallet("alice", fullTAC, "oid4vci", "credential_notification")
	w.issue("f1")

	for name, fn := range map[string]func() (string, string, string){
		"no such issuance":       func() (string, string, string) { return "nope", "nid-1", "credential_accepted" },
		"an id it does not know": func() (string, string, string) { return "f1", "someone-elses-id", "credential_accepted" },
	} {
		t.Run(name, func(t *testing.T) {
			iss, nid, ev := fn()
			fid := "n-" + strings.ReplaceAll(name, " ", "-")
			w.notify(fid, iss, nid, ev)
			reason, retryable := w.reason(fid)
			assert.Equal(t, "context_unavailable", reason)
			assert.False(t, retryable)
		})
	}
	assert.Equal(t, 0, e.iss.count())

	// A wrong id did not spend the context: the right one still works.
	w.notify("n-ok", "f1", "nid-1", "credential_accepted")
	method, _ := w.outcome("n-ok")
	assert.Equal(t, wmp.MethodFlowComplete, method)
}

// The context belongs to the session it ran in: another user's session cannot
// name it (a user has one live session: a second supersedes the first), and the
// context is not spent by trying.
func TestWMPNotification_ContextIsBoundToItsSession(t *testing.T) {
	e := newChanEnv(t, "Bearer", false)
	w1 := e.wallet("alice", fullTAC, "oid4vci", "credential_notification")
	w2 := e.wallet("bob", fullTAC, "oid4vci", "credential_notification")
	w1.issue("f1")

	w2.notify("n1", "f1", "nid-1", "credential_accepted")
	reason, _ := w2.reason("n1")
	assert.Equal(t, "context_unavailable", reason)
	assert.Equal(t, 0, e.iss.count())

	w1.notify("n1", "f1", "nid-1", "credential_accepted")
	method, _ := w1.outcome("n1")
	assert.Equal(t, wmp.MethodFlowComplete, method)
}

// The store binds the context to the principal that ran the issuance, and a call
// that does not come from it, or in another session, is unavailable.
func TestWMPNotification_ForwarderBindsPrincipalAndSession(t *testing.T) {
	e := newChanEnv(t, "Bearer", false)
	w := e.wallet("alice", fullTAC, "oid4vci", "credential_notification")
	w.issue("f1")
	fwd := &wmpNotificationForwarder{a: e.a, sessionID: w.sid}
	req := openid4x.NotificationRequest{SessionID: w.sid, FlowID: "n1", IssuanceFlowID: "f1", NotificationID: "nid-1", Event: "credential_accepted"}
	noSign := func(context.Context, openid4x.ClientAuthRequest) (string, error) { return "", nil }

	bob := wmp.ContextWithPrincipal(context.Background(), NewWMPPrincipal("bob", "t1", "jti-bob", fullTAC))
	require.ErrorIs(t, fwd.ForwardNotification(bob, req, noSign), openid4x.ErrNotificationContextUnavailable, "another principal")
	require.ErrorIs(t, fwd.ForwardNotification(context.Background(), req, noSign), openid4x.ErrNotificationContextUnavailable, "no principal")
	other := req
	other.SessionID = "another-session"
	alice := wmp.ContextWithPrincipal(context.Background(), NewWMPPrincipal("alice", "t1", "jti-alice", fullTAC))
	require.ErrorIs(t, fwd.ForwardNotification(alice, other, noSign), openid4x.ErrNotificationContextUnavailable, "another session")
	// Same user, other tenant: another principal.
	tenant2 := wmp.ContextWithPrincipal(context.Background(), NewWMPPrincipal("alice", "t2", "jti-alice", fullTAC))
	require.ErrorIs(t, fwd.ForwardNotification(tenant2, req, noSign), openid4x.ErrNotificationContextUnavailable, "another tenant")
	assert.Equal(t, 0, e.iss.count())

	require.NoError(t, fwd.ForwardNotification(alice, req, noSign))
	assert.Equal(t, 1, e.iss.count())
}

// At the forwarding limit the flow ends busy, retryable, and the context (and the
// id) is kept: a start with a new flow_id forwards.
func TestWMPNotification_Busy(t *testing.T) {
	e := newChanEnv(t, "Bearer", false)
	w := e.wallet("alice", fullTAC, "oid4vci", "credential_notification")
	w.issue("f1")

	for i := 0; i < cap(e.m.notificationSem); i++ {
		e.m.notificationSem <- struct{}{}
	}
	w.notify("n1", "f1", "nid-1", "credential_accepted")
	reason, retryable := w.reason("n1")
	assert.Equal(t, "busy", reason)
	assert.True(t, retryable)
	assert.Equal(t, 0, e.iss.count())

	for len(e.m.notificationSem) > 0 {
		<-e.m.notificationSem
	}
	w.notify("n2", "f1", "nid-1", "credential_accepted")
	method, p := w.outcome("n2")
	require.Equal(t, wmp.MethodFlowComplete, method, "the context was kept: %v", p)
	assert.Equal(t, 1, e.iss.count())
}

// A wallet that fails the sign sub-flow, or answers it without a proof, ends the
// flow with signing_failed; nothing it said reaches the wallet's error or the
// issuer.
func TestWMPNotification_SigningFailed(t *testing.T) {
	answers := map[string]func(w *chanWallet, start map[string]any){
		"wallet errors": func(w *chanWallet, start map[string]any) {
			w.push(map[string]any{"id": start["id"], "result": map[string]any{"wmp": meta(w.sid), "flow_id": rpcParams(start)["flow_id"], "flow_type": "sign"}})
			w.push(notification(wmp.MethodFlowError, map[string]any{"wmp": meta(w.sid), "flow_id": rpcParams(start)["flow_id"],
				"code": wmp.ErrFlowError, "message": "wallet text: secret-123", "data": map[string]any{"reason": "rejected"}}))
		},
		"no proof": func(w *chanWallet, start map[string]any) {
			w.push(map[string]any{"id": start["id"], "result": map[string]any{"wmp": meta(w.sid), "flow_id": rpcParams(start)["flow_id"], "flow_type": "sign"}})
			w.push(notification(wmp.MethodFlowComplete, map[string]any{"wmp": meta(w.sid), "flow_id": rpcParams(start)["flow_id"], "result": map[string]any{}}))
		},
		"wallet refuses the start": func(w *chanWallet, start map[string]any) {
			w.push(map[string]any{"id": start["id"], "error": map[string]any{"code": wmp.ErrFlowError, "message": "secret-123"}})
		},
	}
	for name, answer := range answers {
		t.Run(name, func(t *testing.T) {
			e := newChanEnv(t, "DPoP", false)
			w := e.wallet("alice", fullTAC, "oid4vci", "credential_notification")
			w.issue("f1")
			w.notify("n1", "f1", "nid-1", "credential_accepted")
			answer(w, w.method(wmp.MethodFlowStart))
			reason, retryable := w.reason("n1")
			assert.Equal(t, "signing_failed", reason)
			assert.False(t, retryable)
			assert.Equal(t, 0, e.iss.count())
			for _, m := range w.back {
				b, _ := json.Marshal(m)
				assert.NotContains(t, string(b), "secret-123")
			}
		})
	}
}

// The issuer's refusal is forward_failed, with nothing of its answer.
func TestWMPNotification_ForwardFailed(t *testing.T) {
	e := newChanEnv(t, "Bearer", false)
	e.iss.status = http.StatusInternalServerError
	w := e.wallet("alice", fullTAC, "oid4vci", "credential_notification")
	w.issue("f1")
	w.notify("n1", "f1", "nid-1", "credential_accepted")
	reason, retryable := w.reason("n1")
	assert.Equal(t, "forward_failed", reason)
	assert.False(t, retryable)
	assert.Equal(t, 1, e.iss.count())
}

// A flow whose own timeout expires while it waits for the wallet's proof ends with
// the terminal reason timeout (Core 6.2).
func TestWMPNotification_Timeout(t *testing.T) {
	e := newChanEnv(t, "DPoP", false)
	w := e.wallet("alice", fullTAC, "oid4vci", "credential_notification")
	w.issue("f1")
	start := time.Now()
	w.notify("n1", "f1", "nid-1", "credential_accepted", map[string]any{"timeout": 1})
	w.method(wmp.MethodFlowStart) // the sign request, left unanswered
	reason, retryable := w.reason("n1")
	assert.Equal(t, "timeout", reason)
	assert.False(t, retryable)
	assert.Less(t, time.Since(start), 8*time.Second, "the flow's own bound, not go-wmp's sign timeout")
	assert.Equal(t, 0, e.iss.count())
}

// ---------------------------------------------------------------------------
// Capability, authorization, validation
// ---------------------------------------------------------------------------

// The capability is advertised with the events and the context lifetime, and
// negotiated only when offered.
func TestWMPNotification_CapabilityAdvertised(t *testing.T) {
	e := newChanEnv(t, "Bearer", false)
	caps := e.a.serverCapabilities()
	raw, ok := caps[openid4x.CapabilityCredentialNotification]
	require.True(t, ok)
	var c openid4x.CredentialNotificationCap
	require.NoError(t, json.Unmarshal(raw, &c))
	assert.Equal(t, []string{"credential_accepted", "credential_failure"}, c.Events)
	assert.Equal(t, int(notificationContextTTL/time.Second), c.ContextTTLSeconds)

	w := e.wallet("alice", fullTAC, "oid4vci")
	r := w.call(wmp.MethodCapabilityList, map[string]any{"wmp": meta(w.sid)})
	assert.NotContains(t, r["result"].(map[string]any)["capabilities"], "credential_notification", "not offered: not negotiated")
	w = e.wallet("alice", fullTAC, "oid4vci", "credential_notification")
	r = w.call(wmp.MethodCapabilityList, map[string]any{"wmp": meta(w.sid)})
	assert.Contains(t, r["result"].(map[string]any)["capabilities"], "credential_notification")
}

// A session that did not negotiate the capability gets -31005 as the response to
// the start, and nothing is retained for it: the completion carries no endpoint
// and the engine holds no context.
func TestWMPNotification_NotNegotiated(t *testing.T) {
	e := newChanEnv(t, "Bearer", false)
	w := e.wallet("alice", fullTAC, "oid4vci")
	done := w.issue("f1")
	assert.NotContains(t, rpcParams(done)["result"], "notification_endpoint")
	assert.Nil(t, e.a.session(w.sid).session.notifications.take("f1"), "nothing retained for a wallet that will not use it")

	r := w.notify("n1", "f1", "nid-1", "credential_accepted")
	code, data := rpcError(r)
	assert.Equal(t, wmp.ErrCapabilityNotSupported, code)
	assert.Equal(t, map[string]any{"unsupported": "credential_notification", "capability": "credential_notification"}, data)
}

// Invalid params are -32602 {"member": name} as the response, before the flow
// exists; nothing of the value is echoed.
func TestWMPNotification_InvalidStart(t *testing.T) {
	e := newChanEnv(t, "Bearer", false)
	w := e.wallet("alice", fullTAC, "oid4vci", "credential_notification")
	w.issue("f1")
	good := map[string]any{"issuance_flow_id": "f1", "notification_id": "nid-1", "event": "credential_accepted"}
	with := func(k string, v any) map[string]any {
		m := map[string]any{}
		for a, b := range good {
			m[a] = b
		}
		if v == nil {
			delete(m, k)
		} else {
			m[k] = v
		}
		return m
	}
	for name, tc := range map[string]struct {
		params map[string]any
		member string
	}{
		"no issuance_flow_id": {with("issuance_flow_id", nil), "issuance_flow_id"},
		"no notification_id":  {with("notification_id", nil), "notification_id"},
		"event not offered":   {with("event", "credential_deleted"), "event"},
		"long id":             {with("notification_id", strings.Repeat("x", 257)), "notification_id"},
		"description":         {with("event_description", "bad\nline"), "event_description"},
	} {
		t.Run(name, func(t *testing.T) {
			r := w.start(openid4x.FlowTypeCredentialNotification, "n-"+strings.ReplaceAll(name, " ", "-"), tc.params)
			code, data := rpcError(r)
			assert.Equal(t, wmp.ErrInvalidParams, code)
			assert.Equal(t, map[string]any{"member": tc.member}, data)
		})
	}
	assert.Equal(t, 0, e.iss.count())
}

// The flow type is authorized exactly as oid4vci: a token without the issuance
// permission is -31002 and cannot start it.
func TestWMPNotification_NeedsTheIssuancePermission(t *testing.T) {
	e := newChanEnv(t, "Bearer", false)
	w := e.wallet("alice", fullTAC, "oid4vci", "credential_notification")
	w.issue("f1")
	weak := wmp.ContextWithPrincipal(context.Background(), NewWMPPrincipal("alice", "t1", "jti-alice", "r"))
	h, opts := e.a.NewSessionHandler(weak, NewWMPPrincipal("alice", "t1", "jti-alice", "r"), w.sid)
	ct := wmp.NewChannelTransport(8, 8)
	peer := wmp.NewPeer(ct, h, opts...)
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": "s1", "method": wmp.MethodFlowStart, "params": map[string]any{
		"wmp": meta(w.sid), "flow_type": openid4x.FlowTypeCredentialNotification, "flow_id": "n1",
		"params": map[string]any{"issuance_flow_id": "f1", "notification_id": "nid-1", "event": "credential_accepted"}}})
	out, err := peer.HandleRequestSync(weak, body)
	require.NoError(t, err)
	var resp wmp.Response
	require.NoError(t, json.Unmarshal(out, &resp))
	require.NotNil(t, resp.Error, "%s", out)
	assert.Equal(t, wmp.ErrNotAuthorized, resp.Error.Code)
	assert.Equal(t, 0, e.iss.count())
}

// ---------------------------------------------------------------------------
// The store and the completion
// ---------------------------------------------------------------------------

func TestNotificationContextStore_Claim(t *testing.T) {
	put := func(s *notificationContextStore, nid, principal string) {
		s.put("f1", &notificationContext{endpoint: "https://i/n", notificationID: nid, principal: principal})
	}
	t.Run("a known id is single use and spends the context", func(t *testing.T) {
		s := newNotificationContextStore()
		put(s, "n1", "p")
		require.NotNil(t, s.claim("f1", "p", "n1"))
		assert.Nil(t, s.claim("f1", "p", "n1"))
		assert.Nil(t, s.take("f1"), "the issuance's only id is used")
	})
	t.Run("another principal, an unknown id, none", func(t *testing.T) {
		s := newNotificationContextStore()
		put(s, "n1", "p")
		assert.Nil(t, s.claim("f1", "q", "n1"))
		assert.Nil(t, s.claim("f1", "p", "other"))
		assert.Nil(t, s.claim("f1", "p", ""))
		assert.Nil(t, s.claim("f1", "", "n1"))
		assert.NotNil(t, s.claim("f1", "p", "n1"), "the failed attempts spent nothing")
	})
	t.Run("a WebSocket context has no principal and is not claimable", func(t *testing.T) {
		s := newNotificationContextStore()
		put(s, "n1", "")
		assert.Nil(t, s.claim("f1", "", "n1"))
		assert.Empty(t, s.wmpEndpointFor("f1"))
	})
	t.Run("a context that knows no id accepts each once, up to the bound", func(t *testing.T) {
		s := newNotificationContextStore()
		put(s, "", "p")
		for i := 0; i < maxBlindNotificationIDs; i++ {
			require.NotNil(t, s.claim("f1", "p", "id-"+string(rune(0x4e00+i))), "id %d", i)
		}
		assert.Nil(t, s.claim("f1", "p", "id-"+string(rune(0x4e00))), "an id is used once")
		assert.Nil(t, s.claim("f1", "p", "one-too-many"))
	})
	t.Run("expired", func(t *testing.T) {
		s := newNotificationContextStore()
		put(s, "n1", "p")
		s.ctx["f1"].expiresAt = time.Now().Add(-time.Second)
		assert.Nil(t, s.claim("f1", "p", "n1"))
		assert.Empty(t, s.wmpEndpointFor("f1"))
	})
}

func TestWMPNotification_CompletionBounds(t *testing.T) {
	long := strings.Repeat("x", 257)
	m := &FlowCompleteMessage{Credentials: []CredentialResult{
		{Format: "dc+sd-jwt", Credential: "c1", NotificationID: strings.Repeat("x", 256)},
		{Format: "dc+sd-jwt", Credential: "c2", NotificationID: long},
	}}
	raw, err := completionResult(m, "https://i/"+strings.Repeat("e", 2048))
	require.NoError(t, err)
	var res struct {
		Credentials          []map[string]any `json:"credentials"`
		NotificationEndpoint string           `json:"notification_endpoint"`
	}
	require.NoError(t, json.Unmarshal(raw, &res))
	assert.Len(t, res.Credentials[0]["notification_id"], 256, "within the bound")
	assert.NotContains(t, res.Credentials[1], "notification_id", "an id the wallet could not start a flow with")
	assert.Equal(t, "c2", res.Credentials[1]["credential"], "the rest of the entry is intact")
	assert.Empty(t, res.NotificationEndpoint, "over 2048 characters")

	raw, err = completionResult(m, "https://i/n")
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(raw, &res))
	assert.Equal(t, "https://i/n", res.NotificationEndpoint)
}

// The DPoP htu of a notification is the endpoint without query and fragment for
// every signer, engine-held included (RFC 9449 section 4.2).
func TestSendNotification_DPoPHTUHasNoQuery(t *testing.T) {
	var gotHTU atomic.Value
	issuer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/n?x=1", r.URL.RequestURI())
		w.WriteHeader(http.StatusNoContent)
	}))
	defer issuer.Close()
	nc := &notificationContext{endpoint: issuer.URL + "/n?x=1#frag", accessToken: "t", tokenType: "DPoP",
		dpopSigner: dpopSignerFunc(func(_ context.Context, htm, htu, _, _ string) (string, error) {
			gotHTU.Store(htu)
			return "proof", nil
		})}
	require.NoError(t, sendNotification(context.Background(), issuer.Client(), nc, "n1", "credential_accepted", "", zap.NewNop()))
	assert.Equal(t, issuer.URL+"/n", gotHTU.Load())
}

type dpopSignerFunc func(ctx context.Context, htm, htu, accessToken, nonce string) (string, error)

func (f dpopSignerFunc) Proof(ctx context.Context, htm, htu, accessToken, nonce string) (string, error) {
	return f(ctx, htm, htu, accessToken, nonce)
}

// ---------------------------------------------------------------------------
// Review round 1
// ---------------------------------------------------------------------------

// The flow and the legacy wmp.credential.notification method use one consumption
// record per notification_id: an id forwarded by either cannot be forwarded by
// the other (a conflicting event with the same issuance token), and ids that were
// not used stay usable by either.
func TestWMPNotification_FlowAndLegacyMethodShareTheConsumptionRecord(t *testing.T) {
	e := newChanEnv(t, "Bearer", true) // encrypted: the wallet names the ids
	w := e.wallet("alice", fullTAC, "oid4vci", "credential_notification")
	w.issue("f1")
	legacy := func(id, event string) string {
		ws := e.a.session(w.sid)
		e.m.dispatchCredentialNotification(ws.session, &CredentialNotificationMessage{
			Message: Message{Type: TypeCredentialNotification, FlowID: "f1"}, NotificationID: id, Event: event})
		ev := w.method(wmp.MethodMessageDeliver)
		body, _ := rpcParams(ev)["body"].(map[string]any)
		return body["status"].(string)
	}

	w.notify("n1", "f1", "id-a", "credential_accepted")
	method, _ := w.outcome("n1")
	require.Equal(t, wmp.MethodFlowComplete, method)
	assert.Equal(t, "rejected", legacy("id-a", "credential_failure"), "spent by the flow")
	assert.Equal(t, 1, e.iss.count())

	assert.Equal(t, "forwarded", legacy("id-b", "credential_accepted"))
	w.notify("n2", "f1", "id-b", "credential_failure")
	reason, _ := w.reason("n2")
	assert.Equal(t, "context_unavailable", reason, "spent by the legacy method")
	assert.Equal(t, 2, e.iss.count())

	w.notify("n3", "f1", "id-c", "credential_accepted")
	method, _ = w.outcome("n3")
	assert.Equal(t, wmp.MethodFlowComplete, method, "an unused id is still usable")
	assert.Equal(t, 3, e.iss.count())
}

// A message about a running notification flow, or its sign sub-flow, needs the
// issuance permission like any message about an oid4vci flow: a token with only
// "r" cannot end the flow, and the wallet can still finish it.
func TestWMPNotification_ReducedPermissionCannotEndTheFlow(t *testing.T) {
	e := newChanEnv(t, "DPoP", false)
	w := e.wallet("alice", fullTAC, "oid4vci", "credential_notification")
	w.issue("f1")
	w.notify("n1", "f1", "nid-1", "credential_accepted")
	signStart := w.method(wmp.MethodFlowStart) // the flow waits for the proof

	weakP := NewWMPPrincipal("alice", "t1", "jti-alice", "r")
	weak := wmp.ContextWithPrincipal(w.ctx, weakP)
	h, opts := e.a.NewSessionHandler(weak, weakP, w.sid)
	peer := wmp.NewPeer(wmp.NewChannelTransport(8, 8), h, opts...)
	send := func(method string, id any, params map[string]any) *wmp.Response {
		m := map[string]any{"jsonrpc": "2.0", "method": method, "params": params}
		if id != nil {
			m["id"] = id
		}
		body, _ := json.Marshal(m)
		out, err := peer.HandleRequestSync(weak, body)
		require.NoError(t, err)
		if len(out) == 0 {
			return nil
		}
		var resp wmp.Response
		require.NoError(t, json.Unmarshal(out, &resp))
		return &resp
	}
	sub := rpcParams(signStart)["flow_id"].(string)
	for name, tc := range map[string]struct {
		method string
		params map[string]any
	}{
		"cancel the notification":   {wmp.MethodFlowCancel, map[string]any{"wmp": meta(w.sid), "flow_id": "n1"}},
		"complete the notification": {wmp.MethodFlowComplete, map[string]any{"wmp": meta(w.sid), "flow_id": "n1", "result": map[string]any{"status": "forwarded", "notification_id": "nid-1"}}},
		"error the notification":    {wmp.MethodFlowError, map[string]any{"wmp": meta(w.sid), "flow_id": "n1", "code": wmp.ErrFlowError, "message": "x"}},
		"complete the sub-flow":     {wmp.MethodFlowComplete, map[string]any{"wmp": meta(w.sid), "flow_id": sub, "result": map[string]any{"dpop_proof": "forged"}}},
		"error the sub-flow":        {wmp.MethodFlowError, map[string]any{"wmp": meta(w.sid), "flow_id": sub, "code": wmp.ErrFlowError, "message": "x"}},
	} {
		t.Run(name, func(t *testing.T) {
			var id any
			if tc.method == wmp.MethodFlowCancel {
				id = "weak-1"
			}
			if resp := send(tc.method, id, tc.params); resp != nil {
				require.NotNil(t, resp.Error, "%v", resp)
				assert.Equal(t, wmp.ErrNotAuthorized, resp.Error.Code)
			}
		})
	}
	assert.Equal(t, 0, e.iss.count())

	// The flow is still running: the wallet finishes it.
	p := rpcParams(signStart)
	sp := p["params"].(map[string]any)
	proof, err := createDPoPProof(e.key, sp["htm"].(string), sp["htu"].(string), "access-1", "")
	require.NoError(t, err)
	w.push(map[string]any{"id": signStart["id"], "result": map[string]any{"wmp": meta(w.sid), "flow_id": sub, "flow_type": "sign"}})
	w.push(notification(wmp.MethodFlowComplete, map[string]any{"wmp": meta(w.sid), "flow_id": sub, "result": map[string]any{"dpop_proof": proof}}))
	method, out := w.outcome("n1")
	require.Equal(t, wmp.MethodFlowComplete, method, "%v", out)
	assert.Equal(t, 1, e.iss.count())
}

// A notification flow takes a slot of the session's concurrent-flow limit like
// every flow: flows that wait for an unanswered proof cannot exceed it, the next
// one ends busy (retryable), and a slot given back is usable again.
func TestWMPNotification_TakesASessionFlowSlot(t *testing.T) {
	e := newChanEnv(t, "DPoP", true)
	w := e.wallet("alice", fullTAC, "oid4vci", "credential_notification")
	w.issue("f1")
	for i := 0; i < MaxPendingFlowsPerSession; i++ {
		r := w.notify("n"+string(rune('1'+i)), "f1", "id-"+string(rune('a'+i)), "credential_accepted")
		require.Nil(t, r["error"], "%v", r)
		w.method(wmp.MethodFlowStart) // each waits for its proof
	}
	w.notify("n-over", "f1", "id-z", "credential_accepted")
	reason, retryable := w.reason("n-over")
	assert.Equal(t, "busy", reason)
	assert.True(t, retryable)
	assert.Equal(t, 0, e.iss.count())

	// An engine flow is refused by the same limit.
	w.start("oid4vci", "f2", map[string]any{"credential_offer": "openid-credential-offer://x"})
	errMsg := w.recv(func(m map[string]any) bool {
		return m["method"] == wmp.MethodFlowError && rpcParams(m)["flow_id"] == "f2"
	})
	assert.EqualValues(t, wmp.ErrRateLimited, rpcParams(errMsg)["code"])

	// A cancelled notification gives its slot back.
	w.call(wmp.MethodFlowCancel, map[string]any{"wmp": meta(w.sid), "flow_id": "n1"})
	require.Eventually(t, func() bool {
		ws := e.a.session(w.sid)
		ws.session.flowsMu.RLock()
		defer ws.session.flowsMu.RUnlock()
		return len(ws.session.flows) < MaxPendingFlowsPerSession
	}, 3*time.Second, 20*time.Millisecond)
}

// No action is accepted for a notification flow: it has none (OpenID4x 3.4).
func TestWMPNotification_HasNoActions(t *testing.T) {
	e := newChanEnv(t, "DPoP", false)
	w := e.wallet("alice", fullTAC, "oid4vci", "credential_notification")
	w.issue("f1")
	w.notify("n1", "f1", "nid-1", "credential_accepted")
	w.method(wmp.MethodFlowStart)
	r := w.call(wmp.MethodFlowAction, map[string]any{"wmp": meta(w.sid), "flow_id": "n1", "action": "cancel", "params": map[string]any{}})
	code, _ := rpcError(r)
	assert.Equal(t, wmp.ErrInvalidParams, code)
}

// hasValid, the legacy pre-check, reads the same record: an id the flow spent is
// not valid, an unused one is.
func TestNotificationContextStore_HasValidReadsTheConsumptionRecord(t *testing.T) {
	s := newNotificationContextStore()
	s.put("f1", &notificationContext{endpoint: "https://i/n", principal: "p"}) // knows no id
	require.NotNil(t, s.claim("f1", "p", "id-a"))
	assert.False(t, s.hasValid("f1", "id-a"))
	assert.True(t, s.hasValid("f1", "id-b"))
	assert.Nil(t, s.takeForNotification("f1", "id-a"))
	assert.NotNil(t, s.takeForNotification("f1", "id-b"))
}
