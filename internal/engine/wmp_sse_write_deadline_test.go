package engine

import (
	"bufio"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// deadlineWriter is a ResponseWriter whose Write blocks like a socket with a
// non-reading peer: it only returns once the write deadline set via
// http.ResponseController has passed.
type deadlineWriter struct {
	hdr       http.Header
	mu        sync.Mutex
	deadlines []time.Time
	writes    int
}

func (d *deadlineWriter) Header() http.Header { return d.hdr }
func (d *deadlineWriter) WriteHeader(int)     {}
func (d *deadlineWriter) Flush()              {}
func (d *deadlineWriter) SetWriteDeadline(t time.Time) error {
	d.mu.Lock()
	d.deadlines = append(d.deadlines, t)
	d.mu.Unlock()
	return nil
}
func (d *deadlineWriter) Write(p []byte) (int, error) {
	d.mu.Lock()
	var dl time.Time
	if n := len(d.deadlines); n > 0 {
		dl = d.deadlines[n-1]
	}
	d.writes++
	d.mu.Unlock()
	if dl.IsZero() {
		select {} // no deadline: a stuck peer blocks forever
	}
	time.Sleep(time.Until(dl))
	return 0, http.ErrHandlerTimeout
}

// A client that stops reading must not pin the SSE handler: every write is
// bounded by a fresh deadline, so the handler returns.
func TestWMP_SSE_SlowClientWriteIsBounded(t *testing.T) {
	old := wmpSSEWriteTimeout
	wmpSSEWriteTimeout = 100 * time.Millisecond
	defer func() { wmpSSEWriteTimeout = old }()

	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)
	sid := createWMPSession(t, a)
	a.getOrCreateEventBuffer(sid).append([]byte(`{"x":1}`))

	req := httptest.NewRequest(http.MethodGet, WMPEventsPath+"?session_id="+sid, nil)
	req.Header.Set("Authorization", "Bearer "+testToken("user-1", "tenant-a"))
	req.Header.Set("Last-Event-ID", "0")
	w := &deadlineWriter{hdr: http.Header{}}

	done := make(chan struct{})
	go func() { a.HandleWMPEvents(w, req); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("SSE handler stayed blocked on a write to a non-reading client")
	}

	w.mu.Lock()
	defer w.mu.Unlock()
	require.NotEmpty(t, w.deadlines)
	for _, d := range w.deadlines {
		assert.False(t, d.IsZero(), "the deadline must never be cleared")
	}
}

// The stream as a whole outlives the server's WriteTimeout, because the
// deadline is re-armed around each write.
func TestWMP_SSE_StreamOutlivesServerWriteTimeout(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)
	sid := createWMPSession(t, a)
	buf := a.getOrCreateEventBuffer(sid)

	ts := httptest.NewUnstartedServer(http.HandlerFunc(a.HandleWMPEvents))
	ts.Config.WriteTimeout = 150 * time.Millisecond
	ts.Start()
	defer ts.Close()

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"?session_id="+sid, nil)
	req.Header.Set("Authorization", "Bearer "+testToken("user-1", "tenant-a"))
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	time.Sleep(400 * time.Millisecond) // past the server WriteTimeout
	buf.append([]byte(`{"late":true}`))

	got := make(chan string, 1)
	go func() {
		sc := bufio.NewScanner(resp.Body)
		for sc.Scan() {
			if strings.HasPrefix(sc.Text(), "data: ") {
				got <- sc.Text()
				return
			}
		}
		got <- ""
	}()
	select {
	case line := <-got:
		assert.Contains(t, line, "late")
	case <-time.After(3 * time.Second):
		t.Fatal("no event after the server WriteTimeout")
	}
}
