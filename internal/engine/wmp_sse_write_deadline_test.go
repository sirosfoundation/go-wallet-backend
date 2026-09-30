package engine

import (
	"bufio"
	"context"
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
	assert.Positive(t, w.writes, "the write that was bounded must have been attempted")
	assert.False(t, w.deadlines[len(w.deadlines)-1].IsZero(), "the blocked write ran under an armed deadline")
}

// A healthy stream that is idle for longer than the write timeout must still
// deliver a later event: the deadline is cleared after each successful flush
// rather than left to expire.
func TestWMP_SSE_IdleStreamSurvivesWriteTimeout(t *testing.T) {
	old := wmpSSEWriteTimeout
	wmpSSEWriteTimeout = 100 * time.Millisecond
	defer func() { wmpSSEWriteTimeout = old }()

	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)
	sid := createWMPSession(t, a)
	buf := a.getOrCreateEventBuffer(sid)

	ts := httptest.NewServer(http.HandlerFunc(a.HandleWMPEvents))
	defer ts.Close()

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"?session_id="+sid, nil)
	req.Header.Set("Authorization", "Bearer "+testToken("user-1", "tenant-a"))
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	lines := make(chan string, 16)
	go func() {
		sc := bufio.NewScanner(resp.Body)
		for sc.Scan() {
			if strings.HasPrefix(sc.Text(), "data: ") {
				lines <- sc.Text()
			}
		}
		close(lines)
	}()

	buf.append([]byte(`{"first":true}`))
	select {
	case l := <-lines:
		assert.Contains(t, l, "first")
	case <-time.After(3 * time.Second):
		t.Fatal("no first event")
	}

	time.Sleep(4 * wmpSSEWriteTimeout) // idle well past the write timeout
	buf.append([]byte(`{"late":true}`))
	select {
	case l, ok := <-lines:
		require.True(t, ok, "idle stream was closed by an expired write deadline")
		assert.Contains(t, l, "late")
	case <-time.After(3 * time.Second):
		t.Fatal("no event after the idle period")
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

// flushFailWriter accepts writes but fails every flush after the first (the
// initial header flush), like a connection that drops with data still buffered.
type flushFailWriter struct {
	hdr     http.Header
	flushes int
}

func (f *flushFailWriter) Header() http.Header         { return f.hdr }
func (f *flushFailWriter) WriteHeader(int)             {}
func (f *flushFailWriter) Write(p []byte) (int, error) { return len(p), nil }
func (f *flushFailWriter) Flush()                      {}
func (f *flushFailWriter) FlushError() error {
	f.flushes++
	if f.flushes > 1 {
		return http.ErrHandlerTimeout
	}
	return nil
}

// An event whose flush failed must not count as delivered, or a reconnect
// without Last-Event-ID would skip it for good.
func TestWMP_SSE_FlushFailureDoesNotAdvanceDelivered(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)
	sid := createWMPSession(t, a)
	buf := a.getOrCreateEventBuffer(sid)
	buf.append([]byte(`{"x":1}`))

	req := httptest.NewRequest(http.MethodGet, WMPEventsPath+"?session_id="+sid, nil)
	req.Header.Set("Authorization", "Bearer "+testToken("user-1", "tenant-a"))
	w := &flushFailWriter{hdr: http.Header{}}

	done := make(chan struct{})
	go func() { a.HandleWMPEvents(w, req); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("SSE handler did not stop after a failed flush")
	}
	assert.Zero(t, buf.delivered(), "a failed flush must not advance deliveredID")
}

// recordingWriter accepts every write and flush and records the deadlines set.
type recordingWriter struct {
	hdr       http.Header
	mu        sync.Mutex
	deadlines []time.Time
	written   int
}

func (r *recordingWriter) Header() http.Header { return r.hdr }
func (r *recordingWriter) WriteHeader(int)     {}
func (r *recordingWriter) Flush()              {}
func (r *recordingWriter) SetWriteDeadline(t time.Time) error {
	r.mu.Lock()
	r.deadlines = append(r.deadlines, t)
	r.mu.Unlock()
	return nil
}
func (r *recordingWriter) Write(p []byte) (int, error) {
	r.mu.Lock()
	r.written += len(p)
	r.mu.Unlock()
	return len(p), nil
}
func (r *recordingWriter) state() (last time.Time, n, written int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if n = len(r.deadlines); n > 0 {
		last = r.deadlines[n-1]
	}
	return last, n, r.written
}

// While the stream is idle after a successful flush no write deadline may be
// left armed (SetWriteDeadline is persistent), both after the initial flush
// and after an event flush.
func TestWMP_SSE_DeadlineClearedAfterSuccessfulFlush(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)
	sid := createWMPSession(t, a)
	buf := a.getOrCreateEventBuffer(sid)

	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest(http.MethodGet, WMPEventsPath+"?session_id="+sid, nil).WithContext(ctx)
	req.Header.Set("Authorization", "Bearer "+testToken("user-1", "tenant-a"))
	w := &recordingWriter{hdr: http.Header{}}
	done := make(chan struct{})
	go func() { a.HandleWMPEvents(w, req); close(done) }()
	defer func() { cancel(); <-done }()

	require.Eventually(t, func() bool { _, n, _ := w.state(); return n >= 2 }, 2*time.Second, 5*time.Millisecond)
	last, _, _ := w.state()
	assert.True(t, last.IsZero(), "deadline must be cleared after the initial flush")

	buf.append([]byte(`{"x":1}`))
	require.Eventually(t, func() bool { _, _, n := w.state(); return n > 0 }, 2*time.Second, 5*time.Millisecond)
	require.Eventually(t, func() bool { last, _, _ := w.state(); return last.IsZero() }, 2*time.Second, 5*time.Millisecond,
		"deadline must be cleared after the event flush")
}
