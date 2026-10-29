package engine

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	gojose "github.com/go-jose/go-jose/v4"
	gojosejwt "github.com/go-jose/go-jose/v4/jwt"
	"github.com/sirosfoundation/go-tokenauth/claims"
	"github.com/sirosfoundation/go-wmp/pkg/wmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

// ---------------------------------------------------------------------------
// Harness: the real adapter behind httptest, driven the way a wallet drives it
// (JSON-RPC POSTs, an SSE stream), with stub engine flows.
// ---------------------------------------------------------------------------

// scriptedFlow is an engine flow whose behaviour the test supplies.
type scriptedFlow struct {
	flow *Flow
	run  func(ctx context.Context, f *Flow, msg *FlowStartMessage) error

	mu     sync.Mutex
	cancel context.CancelFunc
}

func (s *scriptedFlow) Execute(ctx context.Context, msg *FlowStartMessage) error {
	ctx, cancel := context.WithCancel(ctx)
	s.mu.Lock()
	s.cancel = cancel
	s.mu.Unlock()
	defer cancel()
	return s.run(ctx, s.flow, msg)
}

func (s *scriptedFlow) Cancel() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cancel != nil {
		s.cancel()
	}
}

func registerScripted(m *Manager, p Protocol, run func(ctx context.Context, f *Flow, msg *FlowStartMessage) error) {
	m.RegisterFlowHandler(p, func(flow *Flow, _ *config.Config, _ *zap.Logger, _ *TrustService, _ *RegistryClient, _ storage.VerifierStore, _ *TrustCache) (FlowHandler, error) {
		return &scriptedFlow{flow: flow, run: run}, nil
	})
}

type wmpEnv struct {
	t   *testing.T
	m   *Manager
	a   *WMPAdapter
	srv *httptest.Server
	key *ecdsa.PrivateKey
	iss string
}

func newWMPEnv(t *testing.T) *wmpEnv { return newWMPEnvCfg(t, &config.Config{}) }

func newWMPEnvCfg(t *testing.T, cfg *config.Config) *wmpEnv {
	t.Helper()
	m := NewManager(cfg, zap.NewNop())
	_, key, iss := ensureEngineValidator(t, m)
	a := NewWMPAdapter(m, zap.NewNop(), func(r *http.Request) string {
		_, tok, _ := strings.Cut(r.Header.Get("Authorization"), " ")
		return strings.TrimSpace(tok)
	})
	env := &wmpEnv{t: t, m: m, a: a, key: key, iss: iss}
	env.srv = httptest.NewServer(a)
	t.Cleanup(func() {
		env.srv.Close()
		a.Close()
		m.Close()
	})
	return env
}

// token signs a session token for user with the given TAC and jti.
func (e *wmpEnv) token(user, tenant string, tac claims.TAC, jti string) string {
	e.t.Helper()
	signer, err := gojose.NewSigner(
		gojose.SigningKey{Algorithm: gojose.ES256, Key: e.key},
		(&gojose.SignerOptions{}).WithType("JWT").WithHeader("kid", "test-key"),
	)
	require.NoError(e.t, err)
	now := time.Now()
	raw, err := gojosejwt.Signed(signer).Claims(claims.AccessTokenClaims{
		Claims: gojosejwt.Claims{
			Issuer: e.iss, Subject: user, ID: jti,
			Audience:  gojosejwt.Audience{"wallet-backend"},
			IssuedAt:  gojosejwt.NewNumericDate(now),
			NotBefore: gojosejwt.NewNumericDate(now.Add(-time.Second)),
			Expiry:    gojosejwt.NewNumericDate(now.Add(5 * time.Minute)),
		},
		TenantID: tenant,
		TAC:      tac,
		ACR:      "urn:siros:acr:passkey",
	}).Serialize()
	require.NoError(e.t, err)
	return raw
}

type reply struct {
	Status int
	Body   map[string]any
}

func (r reply) code() int {
	if e, _ := r.Body["error"].(map[string]any); e != nil {
		c, _ := e["code"].(float64)
		return int(c)
	}
	return 0
}

func (r reply) errData() map[string]any {
	e, _ := r.Body["error"].(map[string]any)
	d, _ := e["data"].(map[string]any)
	return d
}

func (r reply) result() map[string]any {
	res, _ := r.Body["result"].(map[string]any)
	return res
}

// post sends one JSON-RPC message with the bearer token. sid, when set, names
// the session in the header.
func (e *wmpEnv) post(token, sid string, msg map[string]any) reply {
	e.t.Helper()
	msg["jsonrpc"] = "2.0"
	b, err := json.Marshal(msg)
	require.NoError(e.t, err)
	req, _ := http.NewRequest(http.MethodPost, e.srv.URL+WMPRPCPath, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if sid != "" {
		req.Header.Set("Wmp-Session-Id", sid)
	}
	resp, err := http.DefaultClient.Do(req)
	require.NoError(e.t, err)
	defer resp.Body.Close() //nolint:errcheck
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(resp.Body)
	out := reply{Status: resp.StatusCode}
	_ = json.Unmarshal(buf.Bytes(), &out.Body)
	return out
}

var idSeq atomic.Int64

func req(method string, params map[string]any) map[string]any {
	return map[string]any{"id": fmt.Sprintf("r%d", idSeq.Add(1)), "method": method, "params": params}
}

func notification(method string, params map[string]any) map[string]any {
	return map[string]any{"method": method, "params": params}
}

func meta(sid string) map[string]any {
	return map[string]any{"version": wmp.Version, "session_id": sid}
}

// create opens a session offering the named capabilities.
func (e *wmpEnv) create(token string, offered ...string) (sid string) {
	e.t.Helper()
	caps := map[string]any{}
	for _, c := range offered {
		switch c {
		case wmp.CapabilityTransactionData:
			caps[c] = map[string]any{"versions": []int{1}}
		default:
			caps[c] = map[string]any{}
		}
	}
	r := e.post(token, "", req(wmp.MethodSessionCreate, map[string]any{
		"wmp":                  map[string]any{"version": wmp.Version},
		"security":             map[string]any{"mode": "tls"},
		"capabilities_offered": caps,
	}))
	require.Equal(e.t, 0, r.code(), "create: %v", r.Body)
	sid, _ = r.result()["wmp"].(map[string]any)["session_id"].(string)
	require.NotEmpty(e.t, sid)
	return sid
}

// stream is an open event stream.
type stream struct {
	events chan sseEvent
	cancel context.CancelFunc
}

type sseEvent struct {
	ID   string
	Data map[string]any
	Raw  string
}

func (e *wmpEnv) openStream(token, sid, lastEventID string) (*stream, int) {
	e.t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	e.t.Cleanup(cancel)
	rq, _ := http.NewRequestWithContext(ctx, http.MethodGet, e.srv.URL+WMPClientEventsPath, nil)
	rq.Header.Set("Authorization", "Bearer "+token)
	rq.Header.Set("Wmp-Session-Id", sid)
	if lastEventID != "" {
		rq.Header.Set("Last-Event-ID", lastEventID)
	}
	resp, err := http.DefaultClient.Do(rq)
	require.NoError(e.t, err)
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		cancel()
		return nil, resp.StatusCode
	}
	s := &stream{events: make(chan sseEvent, 64), cancel: cancel}
	go func() {
		defer resp.Body.Close() //nolint:errcheck
		defer close(s.events)
		sc := bufio.NewScanner(resp.Body)
		sc.Buffer(make([]byte, 1<<20), 1<<20)
		var ev sseEvent
		for sc.Scan() {
			line := sc.Text()
			switch {
			case strings.HasPrefix(line, "id: "):
				ev.ID = strings.TrimPrefix(line, "id: ")
			case strings.HasPrefix(line, "data: "):
				ev.Raw = strings.TrimPrefix(line, "data: ")
				_ = json.Unmarshal([]byte(ev.Raw), &ev.Data)
			case line == "":
				if ev.Raw != "" {
					s.events <- ev
				}
				ev = sseEvent{}
			}
		}
	}()
	return s, resp.StatusCode
}

// next returns the next event, or fails after a timeout.
func (s *stream) next(t *testing.T) sseEvent {
	t.Helper()
	select {
	case ev, ok := <-s.events:
		require.True(t, ok, "stream ended")
		return ev
	case <-time.After(5 * time.Second):
		t.Fatal("no event within 5s")
		return sseEvent{}
	}
}

// nextMethod skips events until one of the given method arrives.
func (s *stream) nextMethod(t *testing.T, method string) sseEvent {
	t.Helper()
	for {
		ev := s.next(t)
		if ev.Data["method"] == method {
			return ev
		}
	}
}

func params(ev sseEvent) map[string]any {
	p, _ := ev.Data["params"].(map[string]any)
	return p
}

// waitFlows waits until the engine session holds n flows.
func waitFlows(t *testing.T, e *wmpEnv, sid string, n int) {
	t.Helper()
	require.Eventually(t, func() bool {
		ws := e.a.session(sid)
		ws.session.flowsMu.RLock()
		defer ws.session.flowsMu.RUnlock()
		return len(ws.session.flows) == n
	}, 2*time.Second, 5*time.Millisecond)
}

func startOID4VP(sid, flowID string) map[string]any {
	return req(wmp.MethodFlowStart, map[string]any{
		"wmp": meta(sid), "flow_type": "oid4vp", "flow_id": flowID,
		"params": map[string]any{"request_uri": "openid4vp://x"},
	})
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// A flow's progress and completion reach the wallet as wmp.flow.progress and
// wmp.flow.complete on the flow, with the engine's result.
func TestWMPBridge_FlowProgressAndComplete(t *testing.T) {
	e := newWMPEnv(t)
	registerScripted(e.m, ProtocolOID4VP, func(_ context.Context, f *Flow, _ *FlowStartMessage) error {
		_ = f.Session.SendProgress(f.ID, StepParsingRequest, map[string]string{"message": "hi"})
		return f.Session.SendFlowComplete(f.ID, nil, "https://verifier.example/done")
	})
	tok := e.token("alice", "t1", "ir", "j1")
	sid := e.create(tok, "oid4vp")
	st, status := e.openStream(tok, sid, "")
	require.Equal(t, http.StatusOK, status)

	r := e.post(tok, sid, startOID4VP(sid, "f1"))
	require.Equal(t, 0, r.code(), "%v", r.Body)
	assert.Equal(t, "f1", r.result()["flow_id"])

	prog := st.nextMethod(t, wmp.MethodFlowProgress)
	assert.Equal(t, "f1", params(prog)["flow_id"])
	assert.Equal(t, string(StepParsingRequest), params(prog)["step"])
	done := st.nextMethod(t, wmp.MethodFlowComplete)
	assert.Equal(t, "f1", params(done)["flow_id"])
	res, _ := params(done)["result"].(map[string]any)
	assert.Equal(t, "https://verifier.example/done", res["redirect_uri"])
	// Every message carries the session and version (Core 2.2.3).
	assert.Equal(t, sid, params(done)["wmp"].(map[string]any)["session_id"])
}

// Core 10.3: a flow type whose capability was not negotiated is -31005 with
// data {"unsupported": type}; so is one this engine does not serve over WMP
// (vctm is a resolve type, not a flow type).
func TestWMPBridge_FlowStartRefusesUnnegotiatedFlowType(t *testing.T) {
	e := newWMPEnv(t)
	registerScripted(e.m, ProtocolOID4VP, func(context.Context, *Flow, *FlowStartMessage) error { return nil })
	registerScripted(e.m, ProtocolOID4VCI, func(context.Context, *Flow, *FlowStartMessage) error { return nil })
	e.m.RegisterFlowHandler(ProtocolVCTM, NewVCTMHandler)
	tok := e.token("alice", "t1", "ir", "j1")
	sid := e.create(tok, "oid4vci") // oid4vp not offered

	for _, ft := range []string{"oid4vp", "vctm", "nonsense"} {
		r := e.post(tok, sid, req(wmp.MethodFlowStart, map[string]any{"wmp": meta(sid), "flow_type": ft, "flow_id": "f-" + ft}))
		assert.Equal(t, wmp.ErrCapabilityNotSupported, r.code(), ft)
		assert.Equal(t, ft, r.errData()["unsupported"], ft)
	}
}

// The TAC is judged per request from the token that authenticated it: the
// session's creation-time TAC and the current request's must both grant the
// permission. A reduced token cannot drive a session created with more.
func TestWMPBridge_TACIsEvaluatedPerRequest(t *testing.T) {
	e := newWMPEnv(t)
	started := make(chan string, 4)
	registerScripted(e.m, ProtocolOID4VP, func(_ context.Context, f *Flow, _ *FlowStartMessage) error {
		started <- f.ID
		return f.Session.SendFlowComplete(f.ID, nil, "")
	})
	full := e.token("alice", "t1", "ir", "j1")
	noRead := e.token("alice", "t1", "i", "j2") // same user, refreshed with fewer permissions
	sid := e.create(full, "oid4vp")

	r := e.post(noRead, sid, startOID4VP(sid, "denied"))
	assert.Equal(t, wmp.ErrNotAuthorized, r.code(), "request TAC lacks r")
	assert.NotEmpty(t, r.errData()["reason"])
	select {
	case id := <-started:
		t.Fatalf("flow %s started with a token lacking r", id)
	case <-time.After(100 * time.Millisecond):
	}

	r = e.post(full, sid, startOID4VP(sid, "ok"))
	assert.Equal(t, 0, r.code(), "%v", r.Body)
	assert.Equal(t, "ok", <-started)

	// A session created with a token that lacks the permission cannot start the
	// flow even if the next request's token has it.
	weak := e.token("bob", "t1", "i", "j3")
	strong := e.token("bob", "t1", "ir", "j4")
	sid2 := e.create(weak, "oid4vp")
	r = e.post(strong, sid2, startOID4VP(sid2, "denied2"))
	assert.Equal(t, wmp.ErrNotAuthorized, r.code(), "session TAC lacks r")
}

// Requests without a valid token are 401, and a session is not reachable by
// another user (not found, indistinguishable from unknown).
func TestWMPBridge_Authentication(t *testing.T) {
	e := newWMPEnv(t)
	registerScripted(e.m, ProtocolOID4VP, func(context.Context, *Flow, *FlowStartMessage) error { return nil })
	alice := e.token("alice", "t1", "ir", "j1")
	sid := e.create(alice, "oid4vp")

	r := e.post("", "", req(wmp.MethodSessionCreate, map[string]any{"wmp": map[string]any{"version": wmp.Version}}))
	assert.Equal(t, http.StatusUnauthorized, r.Status)
	r = e.post("not-a-token", sid, startOID4VP(sid, "f"))
	assert.Equal(t, http.StatusUnauthorized, r.Status)

	bob := e.token("bob", "t1", "ir", "j2")
	r = e.post(bob, sid, startOID4VP(sid, "f"))
	assert.Equal(t, wmp.ErrSessionNotFound, r.code())
	// The same user name in another tenant is another principal.
	other := e.token("alice", "t2", "ir", "j3")
	r = e.post(other, sid, startOID4VP(sid, "f"))
	assert.Equal(t, wmp.ErrSessionNotFound, r.code())
}

// A revoked user's next request is refused at once: the token is validated on
// every request, not only at session creation.
func TestWMPBridge_RevocationEndsAccess(t *testing.T) {
	e := newWMPEnv(t)
	registerScripted(e.m, ProtocolOID4VP, func(context.Context, *Flow, *FlowStartMessage) error { return nil })
	tok := e.token("carol", "t1", "ir", "j1")
	sid := e.create(tok, "oid4vp")
	require.NotNil(t, e.a.session(sid))

	e.m.RevokeUser("carol")
	r := e.post(tok, sid, startOID4VP(sid, "f"))
	assert.Equal(t, http.StatusUnauthorized, r.Status)
	// RevokeUser closed her sessions: the engine session and the WMP session end.
	require.Eventually(t, func() bool { return e.a.session(sid) == nil }, 2*time.Second, 10*time.Millisecond)
	_, ok := e.a.svc.Store().Get(sid)
	assert.False(t, ok, "the stored WMP session ends with the engine session")
}

// A sign request of the engine is a sign sub-flow at the wallet; the wallet's
// result becomes the engine's sign_response.
func TestWMPBridge_SignSubFlowRoundTrip(t *testing.T) {
	e := newWMPEnv(t)
	got := make(chan *SignResponseMessage, 1)
	registerScripted(e.m, ProtocolOID4VP, func(ctx context.Context, f *Flow, _ *FlowStartMessage) error {
		resp, err := f.Session.RequestSign(ctx, f.ID, SignActionSignPresentation, SignRequestParams{Audience: "https://v.example", Nonce: "n-1"})
		if err != nil {
			return err
		}
		got <- resp
		return f.Session.SendFlowComplete(f.ID, nil, "")
	})
	tok := e.token("alice", "t1", "ir", "j1")
	sid := e.create(tok, "oid4vp")
	st, _ := e.openStream(tok, sid, "")
	require.Equal(t, 0, e.post(tok, sid, startOID4VP(sid, "f1")).code())

	start := st.nextMethod(t, wmp.MethodFlowStart)
	assert.Equal(t, "sign", params(start)["flow_type"])
	sub := params(start)["flow_id"].(string)
	subParams, _ := params(start)["params"].(map[string]any)
	assert.Equal(t, "f1", subParams["parent_flow_id"])
	assert.Equal(t, "n-1", subParams["nonce"])
	assert.Equal(t, "https://v.example", subParams["audience"])

	// The wallet accepts the start, then completes the sub-flow.
	r := e.post(tok, sid, map[string]any{"id": start.Data["id"], "result": map[string]any{
		"wmp": meta(sid), "flow_id": sub, "flow_type": "sign"}})
	assert.Equal(t, 0, r.code(), "%v", r.Body)
	e.post(tok, sid, notification(wmp.MethodFlowComplete, map[string]any{
		"wmp": meta(sid), "flow_id": sub, "result": map[string]any{"vp_token": "vp-abc"}}))

	select {
	case resp := <-got:
		assert.Equal(t, "vp-abc", resp.VPToken)
	case <-time.After(5 * time.Second):
		t.Fatal("the engine's RequestSign did not return")
	}
	st.nextMethod(t, wmp.MethodFlowComplete)
}

// What the wallet reports about a failed sub-flow never reaches the engine:
// only the allowlisted code survives. -31005 {"unsupported":"transaction_data"}
// is the transaction_data refusal; any other -31005 is not.
func TestWMPBridge_SignSubFlowFailures(t *testing.T) {
	cases := []struct {
		name     string
		code     int
		data     map[string]any
		wantCode ErrorCode
	}{
		{"rejected", wmp.ErrFlowError, map[string]any{"reason": "rejected"}, ""},
		{"transaction_data unsupported", wmp.ErrCapabilityNotSupported, map[string]any{"unsupported": "transaction_data"}, ErrCodeUnsupportedTransactionData},
		{"another unsupported is not transaction_data", wmp.ErrCapabilityNotSupported, map[string]any{"unsupported": "sign"}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newWMPEnv(t)
			got := make(chan error, 1)
			registerScripted(e.m, ProtocolOID4VP, func(ctx context.Context, f *Flow, _ *FlowStartMessage) error {
				_, err := f.Session.RequestSign(ctx, f.ID, SignActionSignPresentation, SignRequestParams{Nonce: "n"})
				got <- err
				return err
			})
			tok := e.token("alice", "t1", "ir", "j1")
			sid := e.create(tok, "oid4vp")
			st, _ := e.openStream(tok, sid, "")
			require.Equal(t, 0, e.post(tok, sid, startOID4VP(sid, "f1")).code())
			start := st.nextMethod(t, wmp.MethodFlowStart)
			sub := params(start)["flow_id"].(string)
			e.post(tok, sid, map[string]any{"id": start.Data["id"], "result": map[string]any{"wmp": meta(sid), "flow_id": sub, "flow_type": "sign"}})
			e.post(tok, sid, notification(wmp.MethodFlowError, map[string]any{
				"wmp": meta(sid), "flow_id": sub, "code": tc.code, "message": "wallet text: secret-123", "data": tc.data}))

			select {
			case err := <-got:
				var se *SignError
				require.ErrorAs(t, err, &se)
				assert.Equal(t, tc.wantCode, se.Code)
				assert.NotContains(t, err.Error(), "secret-123", "wallet text must not reach the engine")
			case <-time.After(5 * time.Second):
				t.Fatal("RequestSign did not return")
			}
		})
	}
}

// A transaction_data refusal ends the flow with -31005
// {"unsupported":"transaction_data"} and keeps the verifier's redirect_uri as an
// additive member (OpenID4x 2.3).
func TestWMPBridge_TransactionDataRefusalData(t *testing.T) {
	e := newWMPEnv(t)
	registerScripted(e.m, ProtocolOID4VP, func(_ context.Context, f *Flow, _ *FlowStartMessage) error {
		return f.Session.SendFlowError(f.ID, StepSubmittingResponse, ErrCodeUnsupportedTransactionData, "no",
			map[string]interface{}{"redirect_uri": "https://v.example/cb"})
	})
	tok := e.token("alice", "t1", "ir", "j1")
	sid := e.create(tok, "oid4vp")
	st, _ := e.openStream(tok, sid, "")
	require.Equal(t, 0, e.post(tok, sid, startOID4VP(sid, "f1")).code())

	ev := st.nextMethod(t, wmp.MethodFlowError)
	assert.EqualValues(t, wmp.ErrCapabilityNotSupported, params(ev)["code"])
	data, _ := params(ev)["data"].(map[string]any)
	assert.Equal(t, "transaction_data", data["unsupported"])
	assert.Equal(t, "https://v.example/cb", data["redirect_uri"])
}

// transaction_data reaches only a wallet that offered the capability.
func TestWMPBridge_TransactionDataFeatureFollowsNegotiation(t *testing.T) {
	e := newWMPEnv(t)
	features := make(chan []string, 2)
	registerScripted(e.m, ProtocolOID4VP, func(_ context.Context, f *Flow, msg *FlowStartMessage) error {
		features <- msg.Features
		return f.Session.SendFlowComplete(f.ID, nil, "")
	})
	tok := e.token("alice", "t1", "ir", "j1")
	sid := e.create(tok, "oid4vp", wmp.CapabilityTransactionData)
	require.Equal(t, 0, e.post(tok, sid, startOID4VP(sid, "f1")).code())
	assert.Equal(t, []string{FeatureTransactionDataV1}, <-features)

	tok2 := e.token("bob", "t1", "ir", "j2")
	sid2 := e.create(tok2, "oid4vp")
	require.Equal(t, 0, e.post(tok2, sid2, startOID4VP(sid2, "f2")).code())
	assert.Empty(t, <-features)
}

// select_credentials is a closed shape: a wallet that sends anything more is
// answered -32602 without data and the flow is declined. A valid one reaches
// the engine as the consent with the verifier's query ids and the handle, and
// the sign request that follows carries only those back.
func TestWMPBridge_SelectCredentials(t *testing.T) {
	const handle = "abcdefghijklmnopqrstuv"
	newEnv := func() (*wmpEnv, chan *FlowActionMessage) {
		e := newWMPEnv(t)
		actions := make(chan *FlowActionMessage, 2)
		registerScripted(e.m, ProtocolOID4VP, func(ctx context.Context, f *Flow, _ *FlowStartMessage) error {
			act, err := f.Session.WaitForAction(ctx, f.ID, ActionConsent, ActionDecline)
			if err != nil {
				return err
			}
			actions <- act
			if act.Action == ActionDecline {
				return f.Session.SendFlowError(f.ID, StepCredentialSelection, ErrCodePresentationError, "declined")
			}
			var consent ConsentPayload
			if err := json.Unmarshal(act.Payload, &consent); err != nil {
				return err
			}
			refs := make([]CredentialRef, len(consent.SelectedCredentials))
			for i, s := range consent.SelectedCredentials {
				refs[i] = CredentialRef(s)
			}
			_, err = f.Session.RequestSign(ctx, f.ID, SignActionSignPresentation, SignRequestParams{
				CredentialsToInclude: refs, SelectionHandle: consent.SelectionHandle})
			return err
		})
		return e, actions
	}
	selectAction := func(sid string, p map[string]any) map[string]any {
		return req(wmp.MethodFlowAction, map[string]any{"wmp": meta(sid), "flow_id": "f1", "action": "select_credentials", "params": p})
	}

	t.Run("closed shape violations are refused", func(t *testing.T) {
		for name, p := range map[string]map[string]any{
			"unknown member in a selection": {"consent": true, "selections": []any{map[string]any{"query_id": "q1", "selection_handle": handle, "credential_id": "c1"}}},
			"unknown top-level member":      {"consent": true, "selections": []any{map[string]any{"query_id": "q1", "selection_handle": handle}}, "disclosed_claims": []string{"a"}},
			"consent without selections":    {"consent": true},
		} {
			t.Run(name, func(t *testing.T) {
				e, actions := newEnv()
				tok := e.token("alice", "t1", "ir", "j1")
				sid := e.create(tok, "oid4vp")
				require.Equal(t, 0, e.post(tok, sid, startOID4VP(sid, "f1")).code())
				waitFlows(t, e, sid, 1)

				r := e.post(tok, sid, selectAction(sid, p))
				assert.Equal(t, wmp.ErrInvalidParams, r.code())
				assert.Nil(t, r.errData(), "nothing of the params is echoed")
				select {
				case act := <-actions:
					assert.Equal(t, ActionDecline, act.Action, "the flow is declined")
				case <-time.After(5 * time.Second):
					t.Fatal("the flow was not declined")
				}
			})
		}
	})

	t.Run("a valid consent carries query ids and the handle only", func(t *testing.T) {
		e, actions := newEnv()
		tok := e.token("alice", "t1", "ir", "j1")
		sid := e.create(tok, "oid4vp")
		st, _ := e.openStream(tok, sid, "")
		require.Equal(t, 0, e.post(tok, sid, startOID4VP(sid, "f1")).code())
		waitFlows(t, e, sid, 1)

		r := e.post(tok, sid, selectAction(sid, map[string]any{"consent": true,
			"selections": []any{map[string]any{"query_id": "q1", "selection_handle": handle}}}))
		assert.Equal(t, 0, r.code(), "%v", r.Body)
		act := <-actions
		assert.Equal(t, ActionConsent, act.Action)

		start := st.nextMethod(t, wmp.MethodFlowStart)
		sp, _ := params(start)["params"].(map[string]any)
		assert.Equal(t, handle, sp["selection_handle"])
		assert.Equal(t, []any{map[string]any{"credential_query_id": "q1"}}, sp["credentials_to_include"])
		assert.NotContains(t, start.Raw, "credential_id")
		assert.NotContains(t, start.Raw, "disclosed_claims")
	})

	t.Run("consent false declines", func(t *testing.T) {
		e, actions := newEnv()
		tok := e.token("alice", "t1", "ir", "j1")
		sid := e.create(tok, "oid4vp")
		require.Equal(t, 0, e.post(tok, sid, startOID4VP(sid, "f1")).code())
		waitFlows(t, e, sid, 1)
		r := e.post(tok, sid, selectAction(sid, map[string]any{"consent": false}))
		assert.Equal(t, 0, r.code(), "%v", r.Body)
		assert.Equal(t, ActionDecline, (<-actions).Action)
	})
}

// A wmp.flow.cancel ends the engine flow; a flow that ends without a result, or
// outlives the timeout the client named, is reported to the client as -31006
// (it would otherwise wait for ever).
func TestWMPBridge_FlowEnds(t *testing.T) {
	t.Run("cancel", func(t *testing.T) {
		e := newWMPEnv(t)
		cancelled := make(chan struct{})
		registerScripted(e.m, ProtocolOID4VP, func(ctx context.Context, _ *Flow, _ *FlowStartMessage) error {
			<-ctx.Done()
			close(cancelled)
			return ctx.Err()
		})
		tok := e.token("alice", "t1", "ir", "j1")
		sid := e.create(tok, "oid4vp")
		require.Equal(t, 0, e.post(tok, sid, startOID4VP(sid, "f1")).code())
		waitFlows(t, e, sid, 1)
		r := e.post(tok, sid, req(wmp.MethodFlowCancel, map[string]any{"wmp": meta(sid), "flow_id": "f1"}))
		assert.Equal(t, 0, r.code(), "%v", r.Body)
		assert.Equal(t, "cancelled", r.result()["status"])
		select {
		case <-cancelled:
		case <-time.After(5 * time.Second):
			t.Fatal("the engine flow was not cancelled")
		}
		waitFlows(t, e, sid, 0)
	})

	t.Run("ends without a result", func(t *testing.T) {
		e := newWMPEnv(t)
		registerScripted(e.m, ProtocolOID4VP, func(context.Context, *Flow, *FlowStartMessage) error { return nil })
		tok := e.token("alice", "t1", "ir", "j1")
		sid := e.create(tok, "oid4vp")
		st, _ := e.openStream(tok, sid, "")
		require.Equal(t, 0, e.post(tok, sid, startOID4VP(sid, "f1")).code())
		ev := st.nextMethod(t, wmp.MethodFlowError)
		assert.EqualValues(t, wmp.ErrFlowError, params(ev)["code"])
	})

	t.Run("client timeout", func(t *testing.T) {
		e := newWMPEnv(t)
		registerScripted(e.m, ProtocolOID4VP, func(ctx context.Context, _ *Flow, _ *FlowStartMessage) error {
			<-ctx.Done()
			return ctx.Err()
		})
		tok := e.token("alice", "t1", "ir", "j1")
		sid := e.create(tok, "oid4vp")
		st, _ := e.openStream(tok, sid, "")
		msg := startOID4VP(sid, "f1")
		msg["params"].(map[string]any)["timeout"] = 1
		require.Equal(t, 0, e.post(tok, sid, msg).code())
		start := time.Now()
		ev := st.nextMethod(t, wmp.MethodFlowError)
		assert.EqualValues(t, wmp.ErrFlowError, params(ev)["code"])
		assert.Less(t, time.Since(start), 4*time.Second, "the client's 1s timeout applies, not the 5 minute default")
	})
}

// wmp.message.deliver as a request is -31008 (there is no participant to
// deliver to); ack and status are dropped. None reaches an engine handler.
func TestWMPBridge_InboundMessagesAreNotRouted(t *testing.T) {
	e := newWMPEnv(t)
	registerScripted(e.m, ProtocolOID4VP, func(context.Context, *Flow, *FlowStartMessage) error { return nil })
	tok := e.token("alice", "t1", "ir", "j1")
	sid := e.create(tok, "oid4vp")

	r := e.post(tok, sid, req(wmp.MethodMessageDeliver, map[string]any{"wmp": meta(sid), "message_id": "m1", "content_type": "text/plain", "body": "x"}))
	assert.Equal(t, wmp.ErrParticipantNotFound, r.code())
	e.post(tok, sid, notification(wmp.MethodMessageAck, map[string]any{"wmp": meta(sid), "message_id": "m1"}))
	e.post(tok, sid, notification(wmp.MethodMessageStatus, map[string]any{"wmp": meta(sid), "message_id": "m1", "status": "delivered"}))
	assert.EqualValues(t, 1, e.a.inboundRefused.Load())
	assert.EqualValues(t, 3, e.a.inboundMessages.Load())
}

// vctm is resolved with wmp.resolve, not a flow; an unknown type is -31005.
func TestWMPBridge_ResolveVCTM(t *testing.T) {
	var hits atomic.Int32
	reg := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Query().Get("vct") != "urn:example:id" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"vct":"urn:example:id","name":"Example ID"}`))
	}))
	defer reg.Close()

	cfg := &config.Config{}
	cfg.Trust.RegistryURL = reg.URL
	cfg.HTTPClient.AllowPrivateIPs = true
	e := newWMPEnvCfg(t, cfg)
	e.m.RegisterFlowHandler(ProtocolVCTM, NewVCTMHandler)
	tok := e.token("alice", "t1", "ir", "j1")
	sid := e.create(tok, "resolve")

	r := e.post(tok, sid, req(wmp.MethodResolve, map[string]any{"wmp": meta(sid), "type": "vctm", "uri": "urn:example:id"}))
	require.Equal(t, 0, r.code(), "%v", r.Body)
	md, _ := r.result()["metadata"].(map[string]any)
	assert.Equal(t, "Example ID", md["name"])

	r = e.post(tok, sid, req(wmp.MethodResolve, map[string]any{"wmp": meta(sid), "type": "trust", "uri": "x"}))
	assert.Equal(t, wmp.ErrCapabilityNotSupported, r.code())
	assert.Equal(t, "trust", r.errData()["unsupported"])

	// A session that did not negotiate resolve cannot use it (Core 5.8).
	sid2 := e.create(tok)
	r = e.post(tok, sid2, req(wmp.MethodResolve, map[string]any{"wmp": meta(sid2), "type": "vctm", "uri": "urn:example:id"}))
	assert.Equal(t, wmp.ErrCapabilityNotSupported, r.code())
}

// The capabilities are advertised from the registered flow handlers with the
// OpenID4x descriptors; vctm is a resolve type, never a flow.
func TestWMPBridge_Capabilities(t *testing.T) {
	e := newWMPEnv(t)
	registerScripted(e.m, ProtocolOID4VCI, func(context.Context, *Flow, *FlowStartMessage) error { return nil })
	registerScripted(e.m, ProtocolOID4VP, func(context.Context, *Flow, *FlowStartMessage) error { return nil })
	e.m.RegisterFlowHandler(ProtocolVCTM, NewVCTMHandler)
	tok := e.token("alice", "t1", "ir", "j1")

	// Offering nothing negotiates nothing: there is no implicit "everything".
	r := e.post(tok, "", req(wmp.MethodSessionCreate, map[string]any{"wmp": map[string]any{"version": wmp.Version}}))
	require.Equal(t, 0, r.code())
	assert.Empty(t, r.result()["capabilities"])

	sid := e.create(tok, "oid4vci", "oid4vp", "resolve", "transaction_data", "flows", "unknown_cap")
	rc := e.post(tok, sid, req(wmp.MethodCapabilityList, map[string]any{"wmp": meta(sid)}))
	require.Equal(t, 0, rc.code(), "%v", rc.Body)
	caps, _ := rc.result()["capabilities"].(map[string]any)
	for _, name := range []string{"oid4vci", "oid4vp", "resolve", "transaction_data", "flows"} {
		assert.Contains(t, caps, name)
	}
	assert.NotContains(t, caps, "unknown_cap")
	vci, _ := caps["oid4vci"].(map[string]any)
	assert.Contains(t, vci["supported_grants"], "pre-authorized_code")
	vp, _ := caps["oid4vp"].(map[string]any)
	assert.Contains(t, vp["supported_response_modes"], "direct_post.jwt")
	res, _ := caps["resolve"].(map[string]any)
	assert.Equal(t, []any{"vctm"}, res["supported_types"])

	// transaction_data needs a version the client offered, not merely the name.
	r = e.post(tok, "", req(wmp.MethodSessionCreate, map[string]any{
		"wmp":                  map[string]any{"version": wmp.Version},
		"capabilities_offered": map[string]any{"oid4vp": map[string]any{}, "transaction_data": map[string]any{"versions": []int{2}}}}))
	require.Equal(t, 0, r.code())
	assert.NotContains(t, r.result()["capabilities"], "transaction_data")
}

// Discovery lists the endpoints and the same capabilities.
func TestWMPBridge_Discovery(t *testing.T) {
	e := newWMPEnv(t)
	registerScripted(e.m, ProtocolOID4VP, func(context.Context, *Flow, *FlowStartMessage) error { return nil })

	w := httptest.NewRecorder()
	e.a.HandleWMPConfiguration(w, httptest.NewRequest(http.MethodGet, "/.well-known/wmp-configuration", nil))
	assert.Equal(t, http.StatusServiceUnavailable, w.Code, "no external URL: fails closed")

	require.NoError(t, e.a.SetExternalURL("wss://wallet.example.com/"))
	w = httptest.NewRecorder()
	e.a.HandleWMPConfiguration(w, httptest.NewRequest(http.MethodGet, "/.well-known/wmp-configuration", nil))
	require.Equal(t, http.StatusOK, w.Code)
	var cfg wmp.WellKnownConfig
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &cfg))
	assert.Equal(t, "https://wallet.example.com"+WMPRPCPath, cfg.Endpoints["rpc"])
	assert.Equal(t, "https://wallet.example.com"+WMPClientEventsPath, cfg.Endpoints["events"])
	assert.Contains(t, cfg.Capabilities, "oid4vp")
	assert.Contains(t, cfg.Capabilities, "transaction_data")

	assert.Error(t, e.a.SetExternalURL("http://wallet.example.com"), "plain http only for loopback")
	assert.NoError(t, e.a.SetExternalURL("http://localhost:8080"))
}

// Closing the session, expiry and the engine ending it all end the engine
// session and release its budget.
func TestWMPBridge_SessionLifecycle(t *testing.T) {
	registerNop := func(e *wmpEnv) {
		registerScripted(e.m, ProtocolOID4VP, func(context.Context, *Flow, *FlowStartMessage) error { return nil })
	}
	t.Run("wmp.session.close", func(t *testing.T) {
		e := newWMPEnv(t)
		registerNop(e)
		tok := e.token("alice", "t1", "ir", "j1")
		sid := e.create(tok, "oid4vp")
		ws := e.a.session(sid)
		require.NotNil(t, ws)
		e.post(tok, sid, notification(wmp.MethodSessionClose, map[string]any{"wmp": meta(sid)}))
		require.Eventually(t, func() bool { return e.a.session(sid) == nil }, 2*time.Second, 10*time.Millisecond)
		select {
		case <-ws.session.closeCh:
		default:
			t.Fatal("the engine session was not ended")
		}
		_, err := e.m.GetSession(sid)
		assert.Error(t, err, "unregistered from the manager")
	})

	t.Run("another user cannot close it", func(t *testing.T) {
		e := newWMPEnv(t)
		registerNop(e)
		tok := e.token("alice", "t1", "ir", "j1")
		sid := e.create(tok, "oid4vp")
		bob := e.token("bob", "t1", "ir", "j2")
		e.post(bob, sid, notification(wmp.MethodSessionClose, map[string]any{"wmp": meta(sid)}))
		time.Sleep(50 * time.Millisecond)
		assert.NotNil(t, e.a.session(sid))
	})

	t.Run("expiry", func(t *testing.T) {
		e := newWMPEnv(t)
		registerNop(e)
		tok := e.token("alice", "t1", "ir", "j1")
		sid := e.create(tok, "oid4vp")
		rec, ok := e.a.svc.Store().Get(sid)
		require.True(t, ok)
		expired := *rec
		expired.ExpiresAt = time.Now().Add(-time.Second)
		require.NoError(t, e.a.svc.Store().Update(&expired))
		_, err := e.a.svc.Sweep(context.Background())
		require.NoError(t, err)
		assert.Nil(t, e.a.session(sid), "the expire hook ended the engine session")
	})

	t.Run("a newer session of the same user supersedes", func(t *testing.T) {
		e := newWMPEnv(t)
		registerNop(e)
		old := e.create(e.token("alice", "t1", "ir", "j1"), "oid4vp")
		fresh := e.create(e.token("alice", "t1", "ir", "j2"), "oid4vp")
		require.Eventually(t, func() bool { return e.a.session(old) == nil }, 2*time.Second, 10*time.Millisecond)
		_, ok := e.a.svc.Store().Get(old)
		assert.False(t, ok, "the superseded WMP session is gone too")
		assert.NotNil(t, e.a.session(fresh))
	})

	t.Run("per-token session limit", func(t *testing.T) {
		e := newWMPEnv(t)
		registerNop(e)
		// Anonymous tokens are not superseded by user, so only the limit bounds them.
		tok := e.token("", "t1", "ir", "anon-1")
		for i := 0; i < maxWMPSessionsPerToken; i++ {
			e.create(tok, "oid4vp")
		}
		r := e.post(tok, "", req(wmp.MethodSessionCreate, map[string]any{"wmp": map[string]any{"version": wmp.Version}}))
		assert.Equal(t, wmp.ErrRateLimited, r.code())
	})
}

// Replay redacts the secrets of a completion (refresh_token, dpop_jwk) while the
// live copy keeps them, and a reconnect with an unknown Last-Event-ID is 410.
func TestWMPBridge_ReplayRedactionAndGap(t *testing.T) {
	e := newWMPEnv(t)
	registerScripted(e.m, ProtocolOID4VCI, func(_ context.Context, f *Flow, _ *FlowStartMessage) error {
		_ = f.Session.SendProgress(f.ID, StepParsingRequest, nil)
		return f.Session.SendFlowCompleteWithRefreshToken(f.ID, nil, "", "rt-secret", `{"kty":"EC"}`, "")
	})
	tok := e.token("alice", "t1", "ir", "j1")
	sid := e.create(tok, "oid4vci")
	live, _ := e.openStream(tok, sid, "")
	require.Equal(t, 0, e.post(tok, sid, req(wmp.MethodFlowStart, map[string]any{
		"wmp": meta(sid), "flow_type": "oid4vci", "flow_id": "f1", "params": map[string]any{"offer": "openid-credential-offer://x"}})).code())
	first := live.nextMethod(t, wmp.MethodFlowProgress)
	done := live.nextMethod(t, wmp.MethodFlowComplete)
	assert.Contains(t, done.Raw, "rt-secret", "the live copy keeps the secret")

	replayed, status := e.openStream(tok, sid, first.ID)
	require.Equal(t, http.StatusOK, status)
	again := replayed.nextMethod(t, wmp.MethodFlowComplete)
	assert.NotContains(t, again.Raw, "rt-secret", "the replayed copy never holds it")
	res, _ := params(again)["result"].(map[string]any)
	assert.Contains(t, res["redacted_members"], "refresh_token")

	_, status = e.openStream(tok, sid, "no-such-event")
	assert.Equal(t, http.StatusGone, status)
}

// E0: the bridge needs no *http.Request. A caller that has its Principal drives
// the same engine over a wmp.Peer and in-memory channels.
func TestWMPBridge_InProcessWithoutHTTP(t *testing.T) {
	m := NewManager(&config.Config{}, zap.NewNop())
	a := NewWMPAdapter(m, zap.NewNop(), func(*http.Request) string { return "" })
	t.Cleanup(func() { a.Close(); m.Close() })
	registerScripted(m, ProtocolOID4VP, func(_ context.Context, f *Flow, _ *FlowStartMessage) error {
		return f.Session.SendFlowComplete(f.ID, nil, "https://v.example/done")
	})

	principal := NewWMPPrincipal("dora", "t1", "jti-1", "ir")
	ctx := wmp.ContextWithPrincipal(context.Background(), principal)

	// The session is created on a throw-away peer, as the server does.
	h, opts := a.NewSessionHandler(ctx, principal, "")
	createPeer := wmp.NewPeer(wmp.NewChannelTransport(8, 8), h, opts...)
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": "c1", "method": wmp.MethodSessionCreate, "params": map[string]any{
		"wmp": map[string]any{"version": wmp.Version}, "security": map[string]any{"mode": "tls"},
		"capabilities_offered": map[string]any{"oid4vp": map[string]any{}}}})
	out, err := createPeer.HandleRequestSync(ctx, body)
	require.NoError(t, err)
	var created wmp.Response
	require.NoError(t, json.Unmarshal(out, &created))
	require.Nil(t, created.Error, "%s", out)
	var res wmp.SessionCreateResult
	require.NoError(t, json.Unmarshal(created.Result, &res))
	sid := res.WMP.SessionID
	require.NotNil(t, a.session(sid), "the engine session exists")
	assert.Equal(t, "dora", a.session(sid).session.UserID)

	// The long-lived peer runs the flow; its output is the peer's transport.
	h2, opts2 := a.NewSessionHandler(ctx, principal, sid)
	ct := wmp.NewChannelTransport(8, 8)
	peer := wmp.NewPeer(ct, h2, opts2...)
	startBody, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": "s1", "method": wmp.MethodFlowStart, "params": map[string]any{
		"wmp": meta(sid), "flow_type": "oid4vp", "flow_id": "f1", "params": map[string]any{"request_uri": "openid4vp://x"}}})
	out, err = peer.HandleRequestSync(ctx, startBody)
	require.NoError(t, err)
	var started wmp.Response
	require.NoError(t, json.Unmarshal(out, &started))
	require.Nil(t, started.Error, "%s", out)

	select {
	case data := <-ct.Out():
		var msg map[string]any
		require.NoError(t, json.Unmarshal(data, &msg))
		assert.Equal(t, wmp.MethodFlowComplete, msg["method"])
	case <-time.After(5 * time.Second):
		t.Fatal("no completion on the peer's transport")
	}

	// Without a Principal in the context nothing is served.
	out, err = peer.HandleRequestSync(context.Background(), startBody)
	require.NoError(t, err)
	var denied wmp.Response
	require.NoError(t, json.Unmarshal(out, &denied))
	require.NotNil(t, denied.Error)
	assert.Equal(t, wmp.ErrNotAuthorized, denied.Error.Code)
}

// A credential notification needs the issuance permission, and its answer (the
// engine's notification_ack, which has no WMP method of its own) travels as a
// wmp.message.deliver on the stream.
func TestWMPBridge_CredentialNotification(t *testing.T) {
	e := newWMPEnv(t)
	registerScripted(e.m, ProtocolOID4VCI, func(context.Context, *Flow, *FlowStartMessage) error { return nil })
	notify := func(sid string) map[string]any {
		return req(wmp.MethodCredentialNotification, map[string]any{
			"wmp": meta(sid), "flow_id": "f-done", "notification_id": "n-1", "event": "credential_accepted"})
	}

	full := e.token("alice", "t1", "ir", "j1")
	sid := e.create(full, "oid4vci")
	st, _ := e.openStream(full, sid, "")
	r := e.post(full, sid, notify(sid))
	assert.Equal(t, 0, r.code(), "%v", r.Body)
	ev := st.nextMethod(t, wmp.MethodMessageDeliver)
	assert.Equal(t, string(TypeNotificationAck), params(ev)["message_type"])
	body, _ := params(ev)["body"].(map[string]any)
	assert.Equal(t, "n-1", body["notification_id"])
	assert.Equal(t, "rejected", body["status"], "no notification context for the flow")

	readOnly := e.token("alice", "t1", "r", "j2")
	r = e.post(readOnly, sid, notify(sid))
	assert.Equal(t, wmp.ErrNotAuthorized, r.code(), "the request's TAC lacks i")
}

// A match sub-flow relays only whether the wallet can satisfy the query.
func TestWMPBridge_MatchSubFlow(t *testing.T) {
	for _, tc := range []struct {
		name      string
		result    map[string]any
		wantError bool
		wantCode  string
	}{
		{"satisfiable", map[string]any{"satisfiable": true}, false, ""},
		{"not satisfiable", map[string]any{"satisfiable": false, "code": "no_match"}, false, "no_match"},
		{"non-conforming result", map[string]any{"satisfiable": true, "credentials": []any{}}, true, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newWMPEnv(t)
			got := make(chan *MatchResponseMessage, 1)
			registerScripted(e.m, ProtocolOID4VP, func(ctx context.Context, f *Flow, _ *FlowStartMessage) error {
				resp, err := f.Session.RequestMatch(ctx, f.ID, json.RawMessage(`{"credentials":[{"id":"q1"}]}`))
				if err != nil {
					got <- &MatchResponseMessage{Error: err.Error()}
					return err
				}
				got <- resp
				return nil
			})
			tok := e.token("alice", "t1", "ir", "j1")
			sid := e.create(tok, "oid4vp")
			st, _ := e.openStream(tok, sid, "")
			require.Equal(t, 0, e.post(tok, sid, startOID4VP(sid, "f1")).code())
			start := st.nextMethod(t, wmp.MethodFlowStart)
			assert.Equal(t, "match", params(start)["flow_type"])
			sub := params(start)["flow_id"].(string)
			e.post(tok, sid, map[string]any{"id": start.Data["id"], "result": map[string]any{"wmp": meta(sid), "flow_id": sub, "flow_type": "match"}})
			e.post(tok, sid, notification(wmp.MethodFlowComplete, map[string]any{"wmp": meta(sid), "flow_id": sub, "result": tc.result}))
			resp := <-got
			assert.Equal(t, tc.wantError, resp.Error != "", resp.Error)
			assert.Equal(t, tc.wantCode, resp.NoMatchReason)
			assert.NotContains(t, resp.Error, "credentials", "the offending result is not echoed")
		})
	}
}

// ServeAuthenticated serves a Principal without a bearer token, and reapOrphans
// ends an engine session whose stored WMP session is gone.
func TestWMPBridge_ServeAuthenticatedAndOrphans(t *testing.T) {
	e := newWMPEnv(t)
	registerScripted(e.m, ProtocolOID4VP, func(context.Context, *Flow, *FlowStartMessage) error { return nil })
	principal := NewWMPPrincipal("erin", "t1", "j1", "ir")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { e.a.ServeAuthenticated(w, r, principal) }))
	defer srv.Close()

	body := `{"jsonrpc":"2.0","id":"c1","method":"wmp.session.create","params":{"wmp":{"version":"0.1"},"capabilities_offered":{"oid4vp":{}}}}`
	resp, err := http.Post(srv.URL, "application/json", strings.NewReader(body))
	require.NoError(t, err)
	defer resp.Body.Close() //nolint:errcheck
	var out struct {
		Result struct {
			WMP struct {
				SessionID string `json:"session_id"`
			} `json:"wmp"`
		} `json:"result"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	sid := out.Result.WMP.SessionID
	require.NotEmpty(t, sid)
	require.NotNil(t, e.a.session(sid))

	require.NoError(t, e.a.svc.Store().Delete(sid)) // gone from the store by some other path
	e.a.reapOrphans()
	assert.Nil(t, e.a.session(sid))
}

// Every parameter of the engine's sign request has a counterpart in the WMP sign
// sub-flow, or is listed here as deliberately not relayed. A field added to the
// engine's SignRequestParams fails this test until it is mapped.
func TestWMPBridge_SignRequestParamsAreAllRelayed(t *testing.T) {
	var params SignRequestParams
	fillNonZero(reflect.ValueOf(&params).Elem())
	sub, err := signSubFlowParams(&SignRequestMessage{Action: SignActionSignPresentation, Params: params})
	require.NoError(t, err)

	asKeys := func(v any) map[string]bool {
		b, err := json.Marshal(v)
		require.NoError(t, err)
		var m map[string]json.RawMessage
		require.NoError(t, json.Unmarshal(b, &m))
		keys := map[string]bool{}
		for k := range m {
			keys[k] = true
		}
		return keys
	}
	engine, wire := asKeys(params), asKeys(sub)
	notRelayed := map[string]string{
		"holder_commitments": "the legacy proof-claim advert: go-wmp has no such member (Credential Auxiliary Data replaces it)",
	}
	for k := range engine {
		if _, ok := notRelayed[k]; ok {
			assert.False(t, wire[k], "%s is documented as not relayed", k)
			continue
		}
		assert.True(t, wire[k], "SignRequestParams.%s has no counterpart in the WMP sign sub-flow", k)
	}
	assert.True(t, wire["action"])
}

// fillNonZero sets every field reachable from v to a non-zero value.
func fillNonZero(v reflect.Value) {
	switch v.Kind() {
	case reflect.String:
		v.SetString("x")
	case reflect.Bool:
		v.SetBool(true)
	case reflect.Int, reflect.Int64:
		v.SetInt(1)
	case reflect.Ptr:
		v.Set(reflect.New(v.Type().Elem()))
		fillNonZero(v.Elem())
	case reflect.Slice:
		if v.Type().Elem().Kind() == reflect.Uint8 { // json.RawMessage
			v.SetBytes([]byte(`{"k":"v"}`))
			return
		}
		v.Set(reflect.MakeSlice(v.Type(), 1, 1))
		fillNonZero(v.Index(0))
	case reflect.Map:
		v.Set(reflect.MakeMap(v.Type()))
		k, e := reflect.New(v.Type().Key()).Elem(), reflect.New(v.Type().Elem()).Elem()
		fillNonZero(k)
		fillNonZero(e)
		v.SetMapIndex(k, e)
	case reflect.Interface:
		v.Set(reflect.ValueOf("x"))
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			if v.Field(i).CanSet() {
				fillNonZero(v.Field(i))
			}
		}
	}
}

// Engine error codes map to WMP's integer codes (OpenID4x 2.3 for the
// transaction_data refusal).
func TestWMPBridge_MapErrorCode(t *testing.T) {
	for code, want := range map[ErrorCode]int{
		ErrCodeAuthFailed:                 wmp.ErrNotAuthorized,
		ErrCodeForbidden:                  wmp.ErrNotAuthorized,
		ErrCodeInvalidMessage:             wmp.ErrInvalidRequest,
		ErrCodeUnsupportedTransactionData: wmp.ErrCapabilityNotSupported,
		ErrCodeTooManyRequests:            wmp.ErrRateLimited,
		ErrCodeInternalError:              wmp.ErrInternalError,
		ErrCodeSignError:                  wmp.ErrFlowError,
		ErrCodePresentationError:          wmp.ErrFlowError,
	} {
		assert.Equal(t, want, mapErrorCode(code), string(code))
	}
}

// The engine's own errors about flows the session does not run (an action for an
// unknown flow) are still delivered, on the Peer directly.
func TestWMPBridge_ErrorForUnknownFlow(t *testing.T) {
	e := newWMPEnv(t)
	registerScripted(e.m, ProtocolOID4VP, func(context.Context, *Flow, *FlowStartMessage) error { return nil })
	tok := e.token("alice", "t1", "ir", "j1")
	sid := e.create(tok, "oid4vp")
	st, _ := e.openStream(tok, sid, "")
	ws := e.a.session(sid)
	require.NoError(t, ws.session.SendFlowError("ghost", "", ErrCodeUnknownFlow, "Flow not found or already completed"))
	ev := st.nextMethod(t, wmp.MethodFlowError)
	assert.Equal(t, "ghost", params(ev)["flow_id"])
	assert.EqualValues(t, wmp.ErrFlowError, params(ev)["code"])
}
