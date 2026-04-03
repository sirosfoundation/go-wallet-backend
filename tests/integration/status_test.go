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
