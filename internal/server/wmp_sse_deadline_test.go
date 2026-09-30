package server

import (
	"bufio"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

// streamAfterTimeout serves a route that writes a second SSE frame after the
// server's WriteTimeout has elapsed, and reports whether the client saw it.
func streamAfterTimeout(t *testing.T, middleware ...gin.HandlerFunc) bool {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	h := append(middleware, func(c *gin.Context) {
		c.Header("Content-Type", "text/event-stream")
		_, _ = c.Writer.WriteString("data: one\n\n")
		c.Writer.Flush()
		time.Sleep(400 * time.Millisecond) // > WriteTimeout below
		_, _ = c.Writer.WriteString("data: two\n\n")
		c.Writer.Flush()
	})
	r.GET("/events", h...)

	srv := httptest.NewUnstartedServer(r)
	srv.Config.WriteTimeout = 150 * time.Millisecond
	srv.Start()
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/events")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		if sc.Text() == "data: two" {
			return true
		}
	}
	return false
}

func TestSSERoute_ClearWriteDeadline_StreamOutlivesWriteTimeout(t *testing.T) {
	if streamAfterTimeout(t) {
		t.Fatal("control failed: stream should be cut by WriteTimeout without the middleware")
	}
	if !streamAfterTimeout(t, clearWriteDeadline()) {
		t.Fatal("stream was cut off by the server WriteTimeout despite clearWriteDeadline")
	}
}
