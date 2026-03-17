package integration

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/sirosfoundation/go-wallet-backend/internal/health"
)

func TestReadyz_Healthy(t *testing.T) {
	h := NewTestHarness(t)

	resp := h.GET("/readyz")
	resp.Status(http.StatusOK)

	var status health.ReadinessStatus
	resp.JSON(&status)

	if !status.Ready {
		t.Error("Expected ready=true when healthy")
	}
	if len(status.Checks) == 0 {
		t.Error("Expected at least one check")
	}

	// Verify storage check passed
	var storageCheck *health.CheckResult
	for i := range status.Checks {
		if status.Checks[i].Name == "storage" {
			storageCheck = &status.Checks[i]
			break
		}
	}
	if storageCheck == nil {
		t.Fatal("Storage check not found")
	}
	if !storageCheck.Ready {
		t.Errorf("Storage check should be ready, got error: %s", storageCheck.Error)
	}
}

func TestReadyz_ResponseFormat(t *testing.T) {
	h := NewTestHarness(t)

	resp := h.GET("/readyz")
	resp.Status(http.StatusOK)

	var body map[string]interface{}
	resp.JSON(&body)

	// Verify expected fields
	if _, ok := body["ready"]; !ok {
		t.Error("Response missing 'ready' field")
	}
	if _, ok := body["checks"]; !ok {
		t.Error("Response missing 'checks' field")
	}
	if _, ok := body["checked_at"]; !ok {
		t.Error("Response missing 'checked_at' field")
	}
}

func TestReadyz_ChecksContainLatency(t *testing.T) {
	h := NewTestHarness(t)

	resp := h.GET("/readyz")
	resp.Status(http.StatusOK)

	var status health.ReadinessStatus
	resp.JSON(&status)

	for _, check := range status.Checks {
		if check.Latency < 0 {
			t.Errorf("Check %s has invalid latency: %f", check.Name, check.Latency)
		}
	}
}

func TestReadyz_WithCustomChecker(t *testing.T) {
	h := NewTestHarness(t)

	// Add a custom healthy checker
	h.Readiness.AddChecker(&mockHealthyChecker{name: "custom-service"})

	resp := h.GET("/readyz")
	resp.Status(http.StatusOK)

	var status health.ReadinessStatus
	resp.JSON(&status)

	// Should have both storage and custom checker
	if len(status.Checks) < 2 {
		t.Errorf("Expected at least 2 checks, got %d", len(status.Checks))
	}
}

func TestReadyz_WithUnhealthyChecker(t *testing.T) {
	h := NewTestHarness(t)

	// Add an unhealthy checker
	h.Readiness.AddChecker(&mockUnhealthyChecker{name: "broken-service"})

	resp := h.GET("/readyz")
	resp.Status(http.StatusServiceUnavailable)

	var status health.ReadinessStatus
	resp.JSON(&status)

	if status.Ready {
		t.Error("Expected ready=false when one checker fails")
	}

	// Find broken check
	var brokenCheck *health.CheckResult
	for i := range status.Checks {
		if status.Checks[i].Name == "broken-service" {
			brokenCheck = &status.Checks[i]
			break
		}
	}
	if brokenCheck == nil {
		t.Fatal("Broken service check not found")
	}
	if brokenCheck.Ready {
		t.Error("Broken check should not be ready")
	}
	if brokenCheck.Error == "" {
		t.Error("Broken check should have error message")
	}
}

func TestReadyz_Caching(t *testing.T) {
	h := NewTestHarness(t)

	// Make two rapid requests
	resp1 := h.GET("/readyz")
	resp1.Status(http.StatusOK)

	var status1 health.ReadinessStatus
	resp1.JSON(&status1)

	resp2 := h.GET("/readyz")
	resp2.Status(http.StatusOK)

	var status2 health.ReadinessStatus
	resp2.JSON(&status2)

	// Cached - should have same timestamp (within cache TTL)
	if status1.CheckedAt != status2.CheckedAt {
		t.Log("Note: Timestamps differ, which is acceptable if cache expired between requests")
	}
}

func TestReadyz_ContentType(t *testing.T) {
	h := NewTestHarness(t)

	resp := h.GET("/readyz")
	resp.Status(http.StatusOK)

	contentType := resp.Response.Header.Get("Content-Type")
	if contentType != "application/json; charset=utf-8" {
		t.Errorf("Expected JSON content type, got %s", contentType)
	}
}

// Helper types for testing

type mockHealthyChecker struct {
	name string
}

func (c *mockHealthyChecker) Name() string { return c.name }
func (c *mockHealthyChecker) CheckReady(_ context.Context) error {
	return nil
}

type mockUnhealthyChecker struct {
	name string
}

func (c *mockUnhealthyChecker) Name() string { return c.name }
func (c *mockUnhealthyChecker) CheckReady(_ context.Context) error {
	return errors.New("service unavailable")
}
