package as

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestDetectClientMode_Session(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
	c.Request.Header.Set(TokenModeHeader, TokenModeSessionValue)

	mode := DetectClientMode(c)
	if mode != ClientModeSession {
		t.Errorf("expected ClientModeSession, got %s", mode)
	}
}

func TestDetectClientMode_Legacy(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/", nil)

	mode := DetectClientMode(c)
	if mode != ClientModeLegacy {
		t.Errorf("expected ClientModeLegacy, got %s", mode)
	}
}
