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
)

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
	require.NoError(t, sess.sendFlowComplete("f1", cmCreds(), "", "", "", "", &CredentialMetadataRelay{Metadata: json.RawMessage(cmSeedMD), Encrypted: true}))
	cmWaitFor(t, w, "wmp.flow.complete")

	res := sseCompleteResults(t, w.String())
	require.Len(t, res, 1)
	assert.JSONEq(t, cmSeedMD, string(res[0]["credential_metadata"]))
	assert.Equal(t, "true", string(res[0]["credential_metadata_encrypted_response"]))
	_, marked := res[0][wmpCredentialMetadataRedactedKey]
	assert.False(t, marked, "the live event is not marked redacted")
}

func TestWMP_FlowComplete_RingNeverHoldsSeed(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)
	sid, sess, buf := cmSession(t, a)

	w, stop := cmConnect(t, a, sid, "")
	time.Sleep(50 * time.Millisecond)
	require.NoError(t, sess.sendFlowComplete("f1", cmCreds(), "", "refresh-x", "", "", &CredentialMetadataRelay{Metadata: json.RawMessage(cmSeedMD), Encrypted: true}))
	cmWaitFor(t, w, cmSecretIn) // delivered live
	stop()

	stored := ringBytes(buf)
	require.Contains(t, stored, "wmp.flow.complete")
	assert.NotContains(t, stored, cmSecretIn)
	assert.NotContains(t, stored, "org.siros.secret_seed")
	assert.NotContains(t, stored, "credential_metadata\"")
	assert.NotContains(t, stored, "credential_metadata_encrypted_response")
	assert.Contains(t, stored, `"credential_metadata_redacted":true`)
	assert.Contains(t, stored, "cred-bytes", "the rest of the completion stays replayable")

	// Replay to a reconnecting client (no cursor and old cursor): marker, no seed.
	for _, cursor := range []string{"", "0"} {
		w2, stop2 := cmConnect(t, a, sid, cursor)
		cmWaitFor(t, w2, "wmp.flow.complete")
		stop2()
		assert.NotContains(t, w2.String(), cmSecretIn)
		res := sseCompleteResults(t, w2.String())
		require.Len(t, res, 1)
		assert.Equal(t, "true", string(res[0][wmpCredentialMetadataRedactedKey]))
		_, has := res[0]["credential_metadata"]
		assert.False(t, has)
	}

	// The convenience subscription reads the buffer too.
	ev, err := a.Events(sid)
	require.NoError(t, err)
	for {
		select {
		case d := <-ev:
			assert.NotContains(t, string(d), cmSecretIn)
			if strings.Contains(string(d), "wmp.flow.complete") {
				return
			}
		case <-time.After(2 * time.Second):
			t.Fatal("no flow.complete on Events()")
		}
	}
}

// A completion emitted while no SSE client is connected is replayed redacted:
// the seed is dropped, never held for a later connection.
func TestWMP_FlowComplete_NoStreamAtEmissionIsNeverHeld(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)
	sid, sess, buf := cmSession(t, a)

	require.NoError(t, sess.sendFlowComplete("f1", cmCreds(), "", "", "", "", &CredentialMetadataRelay{Metadata: json.RawMessage(cmSeedMD), Encrypted: true}))
	require.Eventually(t, func() bool { return buf.pendingCount() == 1 }, time.Second, 5*time.Millisecond)

	w, stop := cmConnect(t, a, sid, "")
	cmWaitFor(t, w, "wmp.flow.complete")
	stop()
	assert.NotContains(t, w.String(), cmSecretIn)
	assert.NotContains(t, ringBytes(buf), cmSecretIn)
	res := sseCompleteResults(t, w.String())
	require.Len(t, res, 1)
	assert.Equal(t, "true", string(res[0][wmpCredentialMetadataRedactedKey]))
}

// The deferred completion shape: display-only metadata, no encrypted flag.
func TestWMP_FlowComplete_DeferredPath(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)
	sid, sess, buf := cmSession(t, a)

	w, stop := cmConnect(t, a, sid, "")
	time.Sleep(50 * time.Millisecond)
	require.NoError(t, sess.sendFlowComplete("f1", cmCreds(), "", "", "", "", &CredentialMetadataRelay{Metadata: json.RawMessage(cmDisplay), Encrypted: false}))
	cmWaitFor(t, w, "wmp.flow.complete")
	stop()

	res := sseCompleteResults(t, w.String())
	require.Len(t, res, 1)
	assert.JSONEq(t, cmDisplay, string(res[0]["credential_metadata"]))
	_, flag := res[0]["credential_metadata_encrypted_response"]
	assert.False(t, flag, "plain (deferred) response: flag absent")

	// The whole object is withheld from the ring, display data included.
	stored := ringBytes(buf)
	assert.NotContains(t, stored, "DeferredCard")
	assert.Contains(t, stored, `"credential_metadata_redacted":true`)
}

// A completion without credential_metadata is stored and replayed untouched.
func TestWMP_FlowComplete_WithoutMetadataUnchanged(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)
	_, sess, buf := cmSession(t, a)
	require.NoError(t, sess.SendFlowComplete("f1", cmCreds(), ""))
	require.Eventually(t, func() bool { return buf.pendingCount() == 1 }, time.Second, 5*time.Millisecond)
	stored := ringBytes(buf)
	assert.NotContains(t, stored, wmpCredentialMetadataRedactedKey)
	assert.Contains(t, stored, "cred-bytes")
}

// WebSocket and WMP carry the same credential_metadata and flag for the same completion.
func TestFlowComplete_CredentialMetadata_WebSocketAndWMPParity(t *testing.T) {
	relay := &CredentialMetadataRelay{Metadata: json.RawMessage(cmSeedMD), Encrypted: true}

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
	require.NoError(t, ws.sendFlowComplete("f1", cmCreds(), "", "", "", "", relay))
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
	require.NoError(t, sess.sendFlowComplete("f1", cmCreds(), "", "", "", "", relay))
	cmWaitFor(t, w, "wmp.flow.complete")
	res := sseCompleteResults(t, w.String())
	require.Len(t, res, 1)

	assert.JSONEq(t, string(wsMsg["credential_metadata"]), string(res[0]["credential_metadata"]))
	assert.Equal(t, string(wsMsg["credential_metadata_encrypted_response"]), string(res[0]["credential_metadata_encrypted_response"]))
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
	require.NoError(t, sess.sendFlowComplete("f1", cmCreds(), "", "", "", "", &CredentialMetadataRelay{Metadata: json.RawMessage(cmSeedMD), Encrypted: true}))
	cmWaitFor(t, w, cmSecretIn)
	stop()
	w2, stop2 := cmConnect(t, a, sid, "")
	cmWaitFor(t, w2, "wmp.flow.complete")
	stop2()
	require.NotZero(t, buf.pendingCount())

	for _, e := range logs.All() {
		assert.NotContains(t, fmt.Sprintf("%s %v", e.Message, e.ContextMap()), cmSecretIn)
	}
	assert.NotContains(t, sl.String(), cmSecretIn)
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

	require.NoError(t, sess.sendFlowComplete("f1", cmCreds(), "", "", "", "", &CredentialMetadataRelay{Metadata: json.RawMessage(cmSeedMD), Encrypted: true}))
	require.Eventually(t, func() bool { return buf.pendingCount() == 1 }, time.Second, 5*time.Millisecond)
	_ = sid

	keys := mr.Keys()
	require.NotEmpty(t, keys, "the session is persisted, so the scan is not vacuous")
	for _, k := range keys {
		assert.NotContains(t, k, cmSecretIn)
		if v, err := mr.Get(k); err == nil {
			assert.NotContains(t, v, cmSecretIn)
			assert.NotContains(t, v, "credential_metadata")
		}
		if fs, err := mr.HKeys(k); err == nil {
			for _, f := range fs {
				assert.NotContains(t, mr.HGet(k, f), cmSecretIn)
			}
		}
		if mem, err := mr.SMembers(k); err == nil {
			assert.NotContains(t, strings.Join(mem, ","), cmSecretIn)
		}
	}
}

func TestSplitFlowCompleteSecrets(t *testing.T) {
	complete := `{"jsonrpc":"2.0","method":"wmp.flow.complete","params":{"wmp":{"version":"1"},"flow_id":"f","result":{"credentials":[{"credential":"c"}],"credential_metadata":` + cmSeedMD + `,"credential_metadata_encrypted_response":true,"unknown_member":1.50}}}`
	replay, live, ok := splitFlowCompleteSecrets([]byte(complete))
	require.True(t, ok)
	assert.Equal(t, complete, string(live))
	assert.NotContains(t, string(replay), cmSeedHex)
	assert.Contains(t, string(replay), `"unknown_member":1.50`, "other members are preserved verbatim")
	assert.Contains(t, string(replay), `"credential_metadata_redacted":true`)

	// Not a flow.complete, even though it mentions credential_metadata.
	progress := `{"jsonrpc":"2.0","method":"wmp.flow.progress","params":{"payload":{"credential_metadata":1}}}`
	r2, l2, ok := splitFlowCompleteSecrets([]byte(progress))
	require.True(t, ok)
	assert.Equal(t, progress, string(r2))
	assert.Nil(t, l2)

	// Fail closed.
	_, _, ok = splitFlowCompleteSecrets([]byte(`{"method":"wmp.flow.complete","params":"credential_metadata`))
	assert.False(t, ok)
	_, _, ok = splitFlowCompleteSecrets([]byte(`{"method":"wmp.flow.complete","params":{"result":[1]},"x":"credential_metadata"}`))
	assert.False(t, ok)
}
