package integration

import (
	"net/http"
	"testing"
)

func TestStatus(t *testing.T) {
	h := NewTestHarness(t)

	resp := h.GET("/status")
	resp.Status(http.StatusOK)

	var body map[string]interface{}
	resp.JSON(&body)

	if body["status"] != "ok" {
		t.Errorf("Expected status 'ok', got %q", body["status"])
	}
	if body["service"] != "wallet-backend" {
		t.Errorf("Expected service 'wallet-backend', got %q", body["service"])
	}
}

func TestDeprecatedPasswordAuth(t *testing.T) {
	h := NewTestHarness(t)

	t.Run("register returns 410 Gone", func(t *testing.T) {
		resp := h.POST("/user/register", map[string]string{
			"username": "test",
			"password": "test",
		})
		resp.Status(http.StatusGone)
		resp.BodyContains("Password-based registration is deprecated")
	})

	t.Run("login returns 410 Gone", func(t *testing.T) {
		resp := h.POST("/user/login", map[string]string{
			"username": "test",
			"password": "test",
		})
		resp.Status(http.StatusGone)
		resp.BodyContains("Password-based login is deprecated")
	})
}
