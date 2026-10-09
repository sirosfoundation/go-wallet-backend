package engine

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
	"github.com/sirosfoundation/go-wmp/pkg/wmp"
	"github.com/sirosfoundation/go-wmp/pkg/wmp/httpsse"
)

// postRPC drives HandleWMPRPC with a bearer token and NO Wmp-Session-Id header.
func postRPC(a *WMPAdapter, token string, body []byte) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, WMPRPCPath, strings.NewReader(string(body)))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	a.HandleWMPRPC(w, req)
	return w
}

func wmpResponseTo(id json.RawMessage) []byte {
	b, _ := json.Marshal(map[string]interface{}{"jsonrpc": "2.0", "id": id, "result": map[string]interface{}{}})
	return b
}

func (a *WMPAdapter) outboundCount() int {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return len(a.outbound)
}

func registerSignTest(m *Manager, signReceived chan *SignResponseMessage) {
	m.RegisterFlowHandler("sign_test", func(flow *Flow, _ *config.Config, _ *zap.Logger, _ *TrustService, _ *RegistryClient, _ storage.VerifierStore, _ *TrustCache) (FlowHandler, error) {
		return &signFlowHandler{flow: flow, signReceived: signReceived}, nil
	})
}

// pendingChildStart starts a parent sign flow on a session and returns the
// JSON-RPC id and child flow id of the server-initiated sign wmp.flow.start.
func pendingChildStart(t *testing.T, a *WMPAdapter, sid string) (json.RawMessage, string) {
	t.Helper()
	events, err := a.Events(sid)
	require.NoError(t, err)
	resp, err := a.HandleRPC(context.Background(), sid, "", "", wmpRequest("2", wmp.MethodFlowStart, wmp.FlowStartParams{
		WMP: wmp.Metadata{Version: wmp.Version, SessionID: sid}, FlowType: "sign_test", FlowID: "parent",
	}))
	require.NoError(t, err)
	var sr wmp.Response
	require.NoError(t, json.Unmarshal(resp, &sr))
	require.Nil(t, sr.Error)
	deadline := time.After(3 * time.Second)
	for {
		select {
		case ev := <-events:
			var n struct {
				ID     json.RawMessage     `json:"id"`
				Method string              `json:"method"`
				Params wmp.FlowStartParams `json:"params"`
			}
			if json.Unmarshal(ev, &n) == nil && n.Method == wmp.MethodFlowStart && n.Params.FlowType == wmp.FlowTypeSign {
				require.NotEmpty(t, n.ID)
				return n.ID, n.Params.FlowID
			}
		case <-deadline:
			t.Fatal("no sign sub-flow start delivered")
		}
	}
}

// The stock go-wmp client sends only construction-time headers and a response has no
// params.wmp.session_id, so the ack of a server-initiated sign flow.start carries no session identity.
func TestWMP_OutboundResponse_RealClientAcksChildFlowStartWithoutSessionHeader(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)
	signReceived := make(chan *SignResponseMessage, 1)
	registerSignTest(m, signReceived)

	mux := http.NewServeMux()
	mux.HandleFunc(WMPRPCPath, a.HandleWMPRPC)
	mux.HandleFunc(WMPClientEventsPath, a.HandleWMPEvents)
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()

	hdr := http.Header{"Authorization": {"Bearer " + testToken("user-1", "tenant-a")}}
	client := srv.Client()
	tr := client.Transport.(*http.Transport).Clone()
	tr.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, srv.Listener.Addr().String())
	}
	client.Transport = tr
	ct, err := httpsse.NewClientTransport(srv.URL+WMPRPCPath, httpsse.WithHTTPClient(client), httpsse.WithHeaders(hdr))
	require.NoError(t, err)
	defer ct.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	next := func() (wmp.Message, []byte) {
		t.Helper()
		raw, err := ct.ReadMessage(ctx)
		require.NoError(t, err)
		msg, err := wmp.DecodeMessage(raw)
		require.NoError(t, err)
		return *msg, raw
	}

	require.NoError(t, ct.WriteMessage(ctx, wmpRequest("1", wmp.MethodSessionCreate, wmp.SessionCreateParams{
		WMP:      wmp.Metadata{Version: wmp.Version},
		Security: wmp.SecurityMode{Mode: "tls"},
		Auth:     &wmp.AuthObject{Type: "bearer", Token: testToken("user-1", "tenant-a")},
	})))
	created, _ := next()
	var cr wmp.SessionCreateResult
	require.NoError(t, json.Unmarshal(created.Result, &cr))
	sid := cr.WMP.SessionID
	require.NoError(t, ct.ConnectSSE(ctx, sid))

	require.NoError(t, ct.WriteMessage(ctx, wmpRequest("2", wmp.MethodFlowStart, wmp.FlowStartParams{
		WMP: wmp.Metadata{Version: wmp.Version, SessionID: sid}, FlowType: "sign_test", FlowID: "parent",
	})))

	var child string
	var childReqID json.RawMessage
	for child == "" {
		msg, _ := next()
		if msg.Method != wmp.MethodFlowStart {
			continue
		}
		var p wmp.FlowStartParams
		require.NoError(t, json.Unmarshal(msg.Params, &p))
		if p.FlowType == wmp.FlowTypeSign {
			child, childReqID = p.FlowID, msg.ID
		}
	}
	require.NotEmpty(t, childReqID)
	assert.Equal(t, 1, a.outboundCount(), "the server-initiated request is tracked")

	// The acknowledgement: no header, no params at all.
	require.NoError(t, ct.WriteMessage(ctx, wmpResponseTo(childReqID)))
	assert.Equal(t, 0, a.outboundCount(), "an answered ID is consumed")

	// The ack reached the session's peer: the parent's RequestSign proceeds
	// to wait, so the child's completion is delivered to it.
	require.NoError(t, ct.WriteMessage(ctx, wmpNotification(wmp.MethodFlowComplete, wmp.FlowCompleteParams{
		WMP: wmp.Metadata{Version: wmp.Version, SessionID: sid}, FlowID: child, Result: json.RawMessage(`{"proof_jwt":"p"}`),
	})))
	select {
	case got := <-signReceived:
		assert.Equal(t, "p", got.ProofJWT)
	case <-time.After(5 * time.Second):
		t.Fatal("parent flow did not receive the sign result")
	}

	// One-shot: replaying the acknowledgement is rejected.
	w := postRPC(a, testToken("user-1", "tenant-a"), wmpResponseTo(childReqID))
	assert.Contains(t, w.Body.String(), "unknown or unauthorized response ID")
}

func TestWMP_OutboundResponse_UnknownIDRejected(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)
	createWMPSessionWithToken(t, a, "user-1", "tenant-a")

	w := postRPC(a, testToken("user-1", "tenant-a"), wmpResponseTo(json.RawMessage(`"req-nope"`)))
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "unknown or unauthorized response ID")
	assert.Contains(t, w.Body.String(), `"error"`)
}

func TestWMP_OutboundResponse_OtherUsersTokenRejectedAndDoesNotConsume(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)
	signReceived := make(chan *SignResponseMessage, 1)
	registerSignTest(m, signReceived)

	sid, _ := createWMPSessionWithToken(t, a, "user-1", "tenant-a")
	id, _ := pendingChildStart(t, a, sid)
	require.Equal(t, 1, a.outboundCount())

	for _, tok := range []string{testToken("user-2", "tenant-a"), testToken("user-1", "tenant-b")} {
		w := postRPC(a, tok, wmpResponseTo(id))
		assert.Contains(t, w.Body.String(), "unknown or unauthorized response ID")
		assert.Equal(t, 1, a.outboundCount(), "a foreign token must not consume the owner's ID")
	}

	w := postRPC(a, testToken("user-1", "tenant-a"), wmpResponseTo(id))
	assert.Equal(t, http.StatusAccepted, w.Code)
	assert.Equal(t, 0, a.outboundCount())
}

func TestWMP_OutboundResponse_IDsCleanedUp(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)
	registerSignTest(m, make(chan *SignResponseMessage, 1))

	// Session close drops its pending IDs.
	sid, _ := createWMPSessionWithToken(t, a, "user-1", "tenant-a")
	id, _ := pendingChildStart(t, a, sid)
	require.Equal(t, 1, a.outboundCount())
	a.CloseSession(sid)
	assert.Equal(t, 0, a.outboundCount())
	w := postRPC(a, testToken("user-1", "tenant-a"), wmpResponseTo(id))
	assert.Contains(t, w.Body.String(), "unknown or unauthorized response ID")

	// Entries past their TTL are swept and no longer routable.
	sid2, _ := createWMPSessionWithToken(t, a, "user-1", "tenant-a")
	id2, _ := pendingChildStart(t, a, sid2)
	a.mu.Lock()
	o := a.outbound[string(id2)]
	o.expiresAt = time.Now().Add(-time.Second)
	a.outbound[string(id2)] = o
	a.mu.Unlock()
	w = postRPC(a, testToken("user-1", "tenant-a"), wmpResponseTo(id2))
	assert.Contains(t, w.Body.String(), "unknown or unauthorized response ID", "expired ID is not routable")
	assert.Equal(t, 0, a.outboundCount())

	a.trackOutbound(sid2, []byte(`{"jsonrpc":"2.0","id":"x","method":"m"}`))
	a.mu.Lock()
	o = a.outbound[`"x"`]
	o.expiresAt = time.Now().Add(-time.Second)
	a.outbound[`"x"`] = o
	a.mu.Unlock()
	a.cleanupExpired()
	assert.Equal(t, 0, a.outboundCount(), "cleanup sweeps expired IDs")

	// Notifications and responses are never tracked.
	a.trackOutbound(sid2, []byte(`{"jsonrpc":"2.0","method":"m"}`))
	a.trackOutbound(sid2, []byte(`{"jsonrpc":"2.0","id":"y","result":{}}`))
	assert.Equal(t, 0, a.outboundCount())
}
