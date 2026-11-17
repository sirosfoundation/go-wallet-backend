package as

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func newModeContext(header string) *gin.Context {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
	if header != "" {
		c.Request.Header.Set(TokenModeHeader, header)
	}
	return c
}

func TestIsSessionMode(t *testing.T) {
	if !IsSessionMode(newModeContext(TokenModeSessionValue)) {
		t.Error("X-Token-Mode: session must select session mode")
	}
	if IsSessionMode(newModeContext("")) {
		t.Error("no X-Token-Mode header is not session mode")
	}
	if IsSessionMode(newModeContext("legacy")) {
		t.Error("an unknown X-Token-Mode value is not session mode")
	}
}

// A request without X-Token-Mode: session gets 410, not a cookie-only session.
func TestSessionModeGate(t *testing.T) {
	gin.SetMode(gin.TestMode)
	run := func(header string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		_, r := gin.CreateTestContext(w)
		r.POST("/x", sessionModeGate(), func(c *gin.Context) { c.Status(http.StatusOK) })
		req := httptest.NewRequest(http.MethodPost, "/x", nil)
		if header != "" {
			req.Header.Set(TokenModeHeader, header)
		}
		r.ServeHTTP(w, req)
		return w
	}
	if w := run(TokenModeSessionValue); w.Code != http.StatusOK {
		t.Errorf("session mode must pass, got %d", w.Code)
	}
	w := run("")
	if w.Code != http.StatusGone || !strings.Contains(w.Body.String(), "legacy_tokens_disabled") {
		t.Errorf("a request without X-Token-Mode: session must get 410 legacy_tokens_disabled, got %d %s", w.Code, w.Body.String())
	}
}
