package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

const (
	cmSeedHex  = "00112233445566778899aabbccddeeff"
	cmSeedMD   = `{"org.siros.secret_seed":{"ns1":"` + cmSeedHex + `"},"display":[{"name":"Card"}]}`
	cmDisplay  = `{"display":[{"name":"DeferredCard"}]}`
	cmSecretIn = cmSeedHex
	cmRefresh  = "rt-SECRET-refresh-token"
	cmDPoPJWK  = `{\"kty\":\"EC\",\"d\":\"DPOP-PRIVATE-D\"}`
	cmDPoPKID  = "dpop-key-id-SECRET"
)

// cmSendFull sends a completion carrying every secret member.
func cmSendFull(t *testing.T, sess *Session, md json.RawMessage) {
	t.Helper()
	require.NoError(t, sess.sendFlowComplete("f1", cmCreds(), "", cmRefresh, `{"kty":"EC","d":"DPOP-PRIVATE-D"}`, cmDPoPKID, false, md))
}

// cmSeedRelay is credential_metadata carrying a seed. The engine never relays
// one (oid4vci drops everything but display members), so this is the worst case
// the replay redaction must still withhold.
func cmSeedRelay() json.RawMessage { return json.RawMessage(cmSeedMD) }

// assertNoSecrets checks s holds none of the secret values.
func cmAssertNoSecrets(t *testing.T, s string) {
	t.Helper()
	for _, v := range []string{cmSeedHex, cmRefresh, "DPOP-PRIVATE-D", cmDPoPKID, "org.siros.secret_seed"} {
		assert.NotContains(t, s, v)
	}
}

func redactedMembers(t *testing.T, res map[string]json.RawMessage) []string {
	t.Helper()
	var m []string
	require.NoError(t, json.Unmarshal(res[wmpRedactedMembersKey], &m))
	return m
}

var cmAllWithheld = []string{"credential_metadata", "dpop_jwk", "dpop_key_id", "refresh_token"}

func cmCreds() []CredentialResult {
	return []CredentialResult{{Format: "mso_mdoc", Credential: "cred-bytes"}}
}

// cmSession returns a WMP adapter, its session and event buffer.
func cmSession(t *testing.T, a *WMPAdapter) (string, *Session, *wmpEventBuffer) {
	t.Helper()
	sid, _, _ := createSessionFull(t, a, "u", "t", nil)
	a.mu.RLock()
	sess := a.peers[sid].session
	buf := a.eventBufs[sid]
	a.mu.RUnlock()
	return sid, sess, buf
}

// cmConnect opens an SSE stream (optionally with a cursor) and returns the
// recorder and a stop func that waits for the handler to finish.
func cmConnect(t *testing.T, a *WMPAdapter, sid, lastEventID string) (*syncRecorder, func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest(http.MethodGet, WMPEventsPath+"?session_id="+sid, nil).WithContext(ctx)
	req.Header.Set("Authorization", "Bearer "+testToken("u", "t"))
	if lastEventID != "" {
		req.Header.Set("Last-Event-ID", lastEventID)
	}
	w := &syncRecorder{ResponseRecorder: httptest.NewRecorder()}
	done := make(chan struct{})
	go func() { a.HandleWMPEvents(w, req); close(done) }()
	return w, func() { cancel(); <-done }
}

func cmWaitFor(t *testing.T, w *syncRecorder, s string) {
	t.Helper()
	require.Eventually(t, func() bool { return strings.Contains(w.String(), s) }, 2*time.Second, 5*time.Millisecond, "SSE body: %s", w.String())
}

// ringBytes returns every byte retained for replay.
func ringBytes(buf *wmpEventBuffer) string {
	evs, _ := buf.after(0)
	var sb strings.Builder
	for _, e := range evs {
		sb.Write(e.Data)
	}
	return sb.String()
}

// sseResult extracts the flow-complete result object from an SSE body.
func sseCompleteResults(t *testing.T, body string) []map[string]json.RawMessage {
	t.Helper()
	var out []map[string]json.RawMessage
	for _, line := range strings.Split(body, "\n") {
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		var env struct {
			Method string `json:"method"`
			Params struct {
				Result map[string]json.RawMessage `json:"result"`
			} `json:"params"`
		}
		require.NoError(t, json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &env))
		if env.Method == "wmp.flow.complete" {
			out = append(out, env.Params.Result)
		}
	}
	return out
}

func TestWMP_FlowComplete_LiveCarriesCredentialMetadata(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)
	sid, sess, _ := cmSession(t, a)

	w, stop := cmConnect(t, a, sid, "")
	defer stop()
	time.Sleep(50 * time.Millisecond)
	cmSendFull(t, sess, cmSeedRelay())
	cmWaitFor(t, w, "wmp.flow.complete")

	res := sseCompleteResults(t, w.String())
	require.Len(t, res, 1)
	assert.JSONEq(t, cmSeedMD, string(res[0]["credential_metadata"]))
	assert.Equal(t, `"`+cmRefresh+`"`, string(res[0]["refresh_token"]), "live copy is the full completion")
	assert.Contains(t, string(res[0]["dpop_jwk"]), "DPOP-PRIVATE-D")
	assert.Equal(t, `"`+cmDPoPKID+`"`, string(res[0]["dpop_key_id"]))
	_, marked := res[0][wmpRedactedMembersKey]
	assert.False(t, marked, "the live event is not marked redacted")
}

func TestWMP_FlowComplete_RingNeverHoldsSecrets(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)
	sid, sess, buf := cmSession(t, a)

	w, stop := cmConnect(t, a, sid, "")
	time.Sleep(50 * time.Millisecond)
	cmSendFull(t, sess, cmSeedRelay())
	cmWaitFor(t, w, cmSecretIn) // delivered live
	stop()

	stored := ringBytes(buf)
	require.Contains(t, stored, "wmp.flow.complete")
	cmAssertNoSecrets(t, stored)
	for _, k := range cmAllWithheld {
		assert.NotContains(t, stored, `"`+k+`":`, "member %s must not be a key of the retained copy", k)
	}
	assert.Contains(t, stored, `"redacted_members":["credential_metadata","dpop_jwk","dpop_key_id","refresh_token"]`)
	assert.Contains(t, stored, "cred-bytes", "credentials stay replayable")

	// Replay to a reconnecting client (no cursor and old cursor): marker, no secrets.
	for _, cursor := range []string{"", "0"} {
		w2, stop2 := cmConnect(t, a, sid, cursor)
		cmWaitFor(t, w2, "wmp.flow.complete")
		stop2()
		cmAssertNoSecrets(t, w2.String())
		res := sseCompleteResults(t, w2.String())
		require.Len(t, res, 1)
		assert.Equal(t, cmAllWithheld, redactedMembers(t, res[0]))
		assert.Contains(t, string(res[0]["credentials"]), "cred-bytes")
		for _, k := range cmAllWithheld {
			_, has := res[0][k]
			assert.False(t, has, k)
		}
	}

	// A cursor past the completion replays nothing of it.
	w3, stop3 := cmConnect(t, a, sid, "1")
	time.Sleep(100 * time.Millisecond)
	stop3()
	assert.NotContains(t, w3.String(), "wmp.flow.complete")

	// The convenience subscription reads the buffer too.
	ev, err := a.Events(sid)
	require.NoError(t, err)
	for {
		select {
		case d := <-ev:
			cmAssertNoSecrets(t, string(d))
			if strings.Contains(string(d), "wmp.flow.complete") {
				return
			}
		case <-time.After(2 * time.Second):
			t.Fatal("no flow.complete on Events()")
		}
	}
}

// Only the secret members present are listed: a refresh-token-only completion.
func TestWMP_FlowComplete_RefreshTokenOnlyReplayedWithMarker(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)
	sid, sess, buf := cmSession(t, a)
	require.NoError(t, sess.sendFlowComplete("f1", cmCreds(), "", cmRefresh, "", cmDPoPKID, false, nil))
	require.Eventually(t, func() bool { return buf.pendingCount() == 1 }, time.Second, 5*time.Millisecond)
	w, stop := cmConnect(t, a, sid, "")
	cmWaitFor(t, w, "wmp.flow.complete")
	stop()
	cmAssertNoSecrets(t, w.String())
	res := sseCompleteResults(t, w.String())
	require.Len(t, res, 1)
	assert.Equal(t, []string{"dpop_key_id", "refresh_token"}, redactedMembers(t, res[0]))
}

// A completion emitted while no SSE client is connected is replayed redacted:
// the seed is dropped, never held for a later connection.
func TestWMP_FlowComplete_NoStreamAtEmissionIsNeverHeld(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)
	sid, sess, buf := cmSession(t, a)

	cmSendFull(t, sess, cmSeedRelay())
	require.Eventually(t, func() bool { return buf.pendingCount() == 1 }, time.Second, 5*time.Millisecond)

	w, stop := cmConnect(t, a, sid, "")
	cmWaitFor(t, w, "wmp.flow.complete")
	stop()
	cmAssertNoSecrets(t, w.String())
	cmAssertNoSecrets(t, ringBytes(buf))
	res := sseCompleteResults(t, w.String())
	require.Len(t, res, 1)
	assert.Equal(t, cmAllWithheld, redactedMembers(t, res[0]))
}

// The deferred completion shape: display-only metadata, no encrypted flag.
func TestWMP_FlowComplete_DeferredPath(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)
	sid, sess, buf := cmSession(t, a)

	w, stop := cmConnect(t, a, sid, "")
	time.Sleep(50 * time.Millisecond)
	require.NoError(t, sess.sendFlowComplete("f1", cmCreds(), "", "", "", "", false, json.RawMessage(cmDisplay)))
	cmWaitFor(t, w, "wmp.flow.complete")
	stop()

	res := sseCompleteResults(t, w.String())
	require.Len(t, res, 1)
	assert.JSONEq(t, cmDisplay, string(res[0]["credential_metadata"]))
	_, flag := res[0]["credential_response_encrypted"]
	assert.False(t, flag, "plain response: encrypted flag absent")

	// The whole object is withheld from the ring, display data included.
	stored := ringBytes(buf)
	assert.NotContains(t, stored, "DeferredCard")
	assert.Contains(t, stored, `"redacted_members":["credential_metadata"]`)
}

// A completion without credential_metadata is stored and replayed untouched.
func TestWMP_FlowComplete_WithoutMetadataUnchanged(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)
	_, sess, buf := cmSession(t, a)
	require.NoError(t, sess.SendFlowComplete("f1", cmCreds(), ""))
	require.Eventually(t, func() bool { return buf.pendingCount() == 1 }, time.Second, 5*time.Millisecond)
	stored := ringBytes(buf)
	assert.NotContains(t, stored, wmpRedactedMembersKey)
	assert.Contains(t, stored, "cred-bytes")
}

// WebSocket and WMP carry the same credential_metadata and flag for the same completion.
func TestFlowComplete_CredentialMetadata_WebSocketAndWMPParity(t *testing.T) {
	relay := cmSeedRelay()

	// WebSocket.
	frames := make(chan []byte, 1)
	conn, cleanup := wsTestServer(t, func(srv *websocket.Conn) {
		defer srv.Close()
		_, data, err := srv.ReadMessage()
		if err == nil {
			frames <- data
		}
	})
	defer cleanup()
	ws := testSession(conn)
	cmSendFull(t, ws, relay)
	var wsMsg map[string]json.RawMessage
	select {
	case d := <-frames:
		require.NoError(t, json.Unmarshal(d, &wsMsg))
	case <-time.After(2 * time.Second):
		t.Fatal("no websocket frame")
	}

	// WMP.
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)
	sid, sess, _ := cmSession(t, a)
	w, stop := cmConnect(t, a, sid, "")
	defer stop()
	time.Sleep(50 * time.Millisecond)
	cmSendFull(t, sess, relay)
	cmWaitFor(t, w, "wmp.flow.complete")
	res := sseCompleteResults(t, w.String())
	require.Len(t, res, 1)
	for _, k := range []string{"refresh_token", "dpop_jwk", "dpop_key_id", "credentials"} {
		assert.JSONEq(t, string(wsMsg[k]), string(res[0][k]), k)
	}

	assert.JSONEq(t, string(wsMsg["credential_metadata"]), string(res[0]["credential_metadata"]))
	assert.Contains(t, string(wsMsg["credential_metadata"]), cmSeedHex)
}

// logCapture collects slog records (go-wmp logs through slog.Default).
type logCapture struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *logCapture) Enabled(context.Context, slog.Level) bool { return true }
func (l *logCapture) Handle(_ context.Context, r slog.Record) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprintf(&l.buf, "%s", r.Message)
	r.Attrs(func(a slog.Attr) bool { fmt.Fprintf(&l.buf, " %s=%v", a.Key, a.Value); return true })
	l.buf.WriteByte('\n')
	return nil
}
func (l *logCapture) WithAttrs([]slog.Attr) slog.Handler { return l }
func (l *logCapture) WithGroup(string) slog.Handler      { return l }
func (l *logCapture) String() string                     { l.mu.Lock(); defer l.mu.Unlock(); return l.buf.String() }

func TestWMP_FlowComplete_SeedNeverLogged(t *testing.T) {
	core, logs := observer.New(zap.DebugLevel)
	sl := &logCapture{}
	prev := slog.Default()
	slog.SetDefault(slog.New(sl))
	defer slog.SetDefault(prev)

	m := testManager()
	a := NewWMPAdapter(m, zap.New(core), testBearerToken)
	defer cleanupWMP(a, m)
	sid, sess, buf := cmSession(t, a)

	w, stop := cmConnect(t, a, sid, "")
	time.Sleep(50 * time.Millisecond)
	cmSendFull(t, sess, cmSeedRelay())
	cmWaitFor(t, w, cmSecretIn)
	stop()
	w2, stop2 := cmConnect(t, a, sid, "")
	cmWaitFor(t, w2, "wmp.flow.complete")
	stop2()
	require.NotZero(t, buf.pendingCount())

	for _, e := range logs.All() {
		cmAssertNoSecrets(t, fmt.Sprintf("%s %v", e.Message, e.ContextMap()))
	}
	cmAssertNoSecrets(t, sl.String())
}

// Nothing the session store (Redis) holds can contain the seed: it keeps only
// SessionData, and a seed completion does not change that.
func TestWMP_FlowComplete_RedisHoldsNoSeed(t *testing.T) {
	store, mr := newTestRedisStore(t)
	m := testManager()
	m.SetSessionStore(store)
	a := NewWMPAdapter(m, zap.NewNop(), testBearerToken)
	defer cleanupWMP(a, m)
	sid, sess, buf := cmSession(t, a)

	cmSendFull(t, sess, cmSeedRelay())
	require.Eventually(t, func() bool { return buf.pendingCount() == 1 }, time.Second, 5*time.Millisecond)
	_ = sid

	keys := mr.Keys()
	require.NotEmpty(t, keys, "the session is persisted, so the scan is not vacuous")
	for _, k := range keys {
		cmAssertNoSecrets(t, k)
		if v, err := mr.Get(k); err == nil {
			cmAssertNoSecrets(t, v)
			assert.NotContains(t, v, "credential_metadata")
		}
		if fs, err := mr.HKeys(k); err == nil {
			for _, f := range fs {
				cmAssertNoSecrets(t, mr.HGet(k, f))
			}
		}
		if mem, err := mr.SMembers(k); err == nil {
			cmAssertNoSecrets(t, strings.Join(mem, ","))
		}
	}
}

func TestSplitFlowCompleteSecrets(t *testing.T) {
	complete := `{"jsonrpc":"2.0","method":"wmp.flow.complete","params":{"wmp":{"version":"1"},"flow_id":"f","result":{"credentials":[{"credential":"c"}],"credential_metadata":` + cmSeedMD + `,"refresh_token":"rt","dpop_jwk":"{}","dpop_key_id":"k","unknown_member":1.50}}}`
	replay, live, ok := splitFlowCompleteSecrets([]byte(complete))
	require.True(t, ok)
	assert.Equal(t, complete, string(live))
	assert.NotContains(t, string(replay), cmSeedHex)
	assert.Contains(t, string(replay), `"unknown_member":1.50`, "other members are preserved verbatim")
	assert.Contains(t, string(replay), `"redacted_members":["credential_metadata","dpop_jwk","dpop_key_id","refresh_token"]`)
	assert.NotContains(t, string(replay), `"rt"`)

	// A completion with none of them is untouched.
	plain := `{"jsonrpc":"2.0","method":"wmp.flow.complete","params":{"result":{"credentials":[]}}}`
	r1, l1, ok := splitFlowCompleteSecrets([]byte(plain))
	require.True(t, ok)
	assert.Equal(t, plain, string(r1))
	assert.Nil(t, l1)

	// Not a flow.complete, even though it mentions credential_metadata.
	progress := `{"jsonrpc":"2.0","method":"wmp.flow.progress","params":{"payload":{"credential_metadata":1,"refresh_token":"x"}}}`
	r2, l2, ok := splitFlowCompleteSecrets([]byte(progress))
	require.True(t, ok)
	assert.Equal(t, progress, string(r2))
	assert.Nil(t, l2)

	// Fail closed.
	_, _, ok = splitFlowCompleteSecrets([]byte(`{"method":"wmp.flow.complete","params":"credential_metadata"`))
	assert.False(t, ok)
	_, _, ok = splitFlowCompleteSecrets([]byte(`{"method":"wmp.flow.complete","params":{"result":[1]},"refresh_token":"x"}`))
	assert.False(t, ok)
}
