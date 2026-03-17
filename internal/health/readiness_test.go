package health

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"
)

// mockChecker is a mock ReadinessChecker for testing
type mockChecker struct {
	name      string
	ready     bool
	err       error
	checkTime time.Duration
}

func (m *mockChecker) Name() string { return m.name }

func (m *mockChecker) CheckReady(ctx context.Context) error {
	if m.checkTime > 0 {
		select {
		case <-time.After(m.checkTime):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if !m.ready {
		return m.err
	}
	return nil
}

func TestReadinessManager_NoCheckers(t *testing.T) {
	mgr := NewReadinessManager()

	status := mgr.CheckReady(context.Background())

	if !status.Ready {
		t.Error("Expected ready=true when no checkers registered")
	}
	if len(status.Checks) != 0 {
		t.Errorf("Expected 0 checks, got %d", len(status.Checks))
	}
}

func TestReadinessManager_AllReady(t *testing.T) {
	mgr := NewReadinessManager()
	mgr.AddChecker(&mockChecker{name: "db", ready: true})
	mgr.AddChecker(&mockChecker{name: "cache", ready: true})

	status := mgr.CheckReady(context.Background())

	if !status.Ready {
		t.Error("Expected ready=true when all checkers pass")
	}
	if len(status.Checks) != 2 {
		t.Errorf("Expected 2 checks, got %d", len(status.Checks))
	}
	for _, check := range status.Checks {
		if !check.Ready {
			t.Errorf("Check %s should be ready", check.Name)
		}
	}
}

func TestReadinessManager_OneNotReady(t *testing.T) {
	mgr := NewReadinessManager()
	mgr.AddChecker(&mockChecker{name: "db", ready: true})
	mgr.AddChecker(&mockChecker{name: "cache", ready: false, err: errors.New("connection refused")})

	status := mgr.CheckReady(context.Background())

	if status.Ready {
		t.Error("Expected ready=false when one checker fails")
	}

	// Find the failed check
	var cacheCheck *CheckResult
	for i := range status.Checks {
		if status.Checks[i].Name == "cache" {
			cacheCheck = &status.Checks[i]
			break
		}
	}
	if cacheCheck == nil {
		t.Fatal("Cache check not found")
	}
	if cacheCheck.Ready {
		t.Error("Cache check should not be ready")
	}
	if cacheCheck.Error != "connection refused" {
		t.Errorf("Expected error 'connection refused', got '%s'", cacheCheck.Error)
	}
}

func TestReadinessManager_CheckTimeout(t *testing.T) {
	mgr := NewReadinessManager(WithCheckTimeout(100 * time.Millisecond))
	mgr.AddChecker(&mockChecker{name: "slow", ready: true, checkTime: 5 * time.Second})

	start := time.Now()
	status := mgr.CheckReady(context.Background())
	elapsed := time.Since(start)

	// Should timeout quickly, not wait for 5 seconds
	if elapsed > 500*time.Millisecond {
		t.Errorf("Check should have timed out, took %v", elapsed)
	}
	if status.Ready {
		t.Error("Expected ready=false due to timeout")
	}
}

func TestReadinessManager_Caching(t *testing.T) {
	checkCount := 0
	checker := &mockChecker{name: "db", ready: true}

	mgr := NewReadinessManager(WithCacheTTL(500 * time.Millisecond))
	// Wrap to count calls
	wrappedChecker := &countingChecker{
		ReadinessChecker: checker,
		count:            &checkCount,
	}
	mgr.AddChecker(wrappedChecker)

	// First call - should run check
	mgr.CheckReady(context.Background())
	if checkCount != 1 {
		t.Errorf("Expected 1 check, got %d", checkCount)
	}

	// Immediate second call - should use cache
	mgr.CheckReady(context.Background())
	if checkCount != 1 {
		t.Errorf("Expected 1 check (cached), got %d", checkCount)
	}

	// Wait for cache to expire
	time.Sleep(600 * time.Millisecond)

	// Third call - should run check again
	mgr.CheckReady(context.Background())
	if checkCount != 2 {
		t.Errorf("Expected 2 checks after cache expiry, got %d", checkCount)
	}
}

type countingChecker struct {
	ReadinessChecker
	count *int
}

func (c *countingChecker) CheckReady(ctx context.Context) error {
	*c.count++
	return c.ReadinessChecker.CheckReady(ctx)
}

func TestReadinessManager_ParallelChecks(t *testing.T) {
	mgr := NewReadinessManager()

	// Add 3 checkers that each take 100ms
	for i := 0; i < 3; i++ {
		mgr.AddChecker(&mockChecker{
			name:      "check",
			ready:     true,
			checkTime: 100 * time.Millisecond,
		})
	}

	start := time.Now()
	status := mgr.CheckReady(context.Background())
	elapsed := time.Since(start)

	if !status.Ready {
		t.Error("Expected ready=true")
	}

	// If run in parallel, should complete in ~100ms, not 300ms
	if elapsed > 200*time.Millisecond {
		t.Errorf("Checks should run in parallel, took %v", elapsed)
	}
}

func TestReadinessManager_SelfHealing(t *testing.T) {
	// Simulate a checker that starts unhealthy and becomes healthy
	checker := &mockChecker{name: "db", ready: false, err: errors.New("connection refused")}

	mgr := NewReadinessManager(WithCacheTTL(50 * time.Millisecond))
	mgr.AddChecker(checker)

	// Initial check - not ready
	status := mgr.CheckReady(context.Background())
	if status.Ready {
		t.Error("Expected ready=false initially")
	}

	// "Fix" the dependency
	checker.ready = true
	checker.err = nil

	// Wait for cache to expire
	time.Sleep(100 * time.Millisecond)

	// Check again - should now be ready (self-healed)
	status = mgr.CheckReady(context.Background())
	if !status.Ready {
		t.Error("Expected ready=true after dependency recovers")
	}
}

func TestDatabaseChecker(t *testing.T) {
	t.Run("healthy", func(t *testing.T) {
		pinger := &mockPinger{healthy: true}
		checker := NewDatabaseChecker("postgres", pinger)

		err := checker.CheckReady(context.Background())
		if err != nil {
			t.Errorf("Expected no error, got %v", err)
		}
	})

	t.Run("unhealthy", func(t *testing.T) {
		pinger := &mockPinger{healthy: false, err: errors.New("connection refused")}
		checker := NewDatabaseChecker("postgres", pinger)

		err := checker.CheckReady(context.Background())
		if err == nil {
			t.Error("Expected error for unhealthy database")
		}
	})

	t.Run("nil pinger", func(t *testing.T) {
		checker := NewDatabaseChecker("postgres", nil)

		err := checker.CheckReady(context.Background())
		if err == nil {
			t.Error("Expected error for nil pinger")
		}
	})
}

type mockPinger struct {
	healthy bool
	err     error
}

func (m *mockPinger) Ping(ctx context.Context) error {
	if !m.healthy {
		return m.err
	}
	return nil
}

func TestReadinessManager_BackgroundProbe(t *testing.T) {
	checkCount := 0
	checker := &countingChecker{
		ReadinessChecker: &mockChecker{name: "db", ready: true},
		count:            &checkCount,
	}

	mgr := NewReadinessManager(WithCacheTTL(10 * time.Second)) // Long TTL
	mgr.AddChecker(checker)

	// Start background probe with short interval
	mgr.StartBackgroundProbe(50 * time.Millisecond)
	defer mgr.Stop()

	// Initial check runs immediately
	time.Sleep(10 * time.Millisecond)
	if checkCount < 1 {
		t.Error("Expected at least 1 background check")
	}

	// Wait for a few probe cycles
	time.Sleep(150 * time.Millisecond)

	// Should have run multiple checks
	if checkCount < 2 {
		t.Errorf("Expected multiple background checks, got %d", checkCount)
	}
}

// Additional edge case tests

func TestReadinessManager_ContextCancellation(t *testing.T) {
	mgr := NewReadinessManager(WithCheckTimeout(5 * time.Second))
	mgr.AddChecker(&mockChecker{name: "slow", ready: true, checkTime: 10 * time.Second})

	// Create a context that gets cancelled quickly
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	start := time.Now()
	status := mgr.CheckReady(ctx)
	elapsed := time.Since(start)

	// Should respect context cancellation, not the 5s check timeout
	if elapsed > 200*time.Millisecond {
		t.Errorf("Should have respected context cancellation, took %v", elapsed)
	}
	if status.Ready {
		t.Error("Expected ready=false due to context cancellation")
	}
}

func TestReadinessManager_ConcurrentChecks(t *testing.T) {
	checker := &mockChecker{name: "db", ready: true, checkTime: 10 * time.Millisecond}
	mgr := NewReadinessManager(WithCacheTTL(100 * time.Millisecond))
	mgr.AddChecker(checker)

	// Run many concurrent checks
	const numGoroutines = 100
	done := make(chan struct{}, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			status := mgr.CheckReady(context.Background())
			if !status.Ready {
				t.Error("Expected ready=true")
			}
		}()
	}

	// Wait for all to complete
	for i := 0; i < numGoroutines; i++ {
		<-done
	}
}

func TestReadinessManager_StopMultipleTimes(t *testing.T) {
	mgr := NewReadinessManager()
	mgr.StartBackgroundProbe(50 * time.Millisecond)

	// Stopping multiple times should be safe
	mgr.Stop()
	mgr.Stop()
	mgr.Stop()
}

func TestReadinessManager_AddCheckerConcurrent(t *testing.T) {
	mgr := NewReadinessManager()

	// Add checkers concurrently while running checks
	done := make(chan struct{}, 50)
	for i := 0; i < 25; i++ {
		go func(idx int) {
			defer func() { done <- struct{}{} }()
			mgr.AddChecker(&mockChecker{name: fmt.Sprintf("checker-%d", idx), ready: true})
		}(i)
		go func() {
			defer func() { done <- struct{}{} }()
			mgr.CheckReady(context.Background())
		}()
	}

	for i := 0; i < 50; i++ {
		<-done
	}
}

func TestReadinessManager_EmptyCheckerName(t *testing.T) {
	mgr := NewReadinessManager()
	mgr.AddChecker(&mockChecker{name: "", ready: true})

	status := mgr.CheckReady(context.Background())
	if !status.Ready {
		t.Error("Expected ready=true")
	}
	if len(status.Checks) != 1 {
		t.Errorf("Expected 1 check, got %d", len(status.Checks))
	}
}

func TestReadinessManager_CheckLatency(t *testing.T) {
	mgr := NewReadinessManager()
	mgr.AddChecker(&mockChecker{name: "fast", ready: true, checkTime: 50 * time.Millisecond})

	status := mgr.CheckReady(context.Background())

	if len(status.Checks) != 1 {
		t.Fatal("Expected 1 check")
	}
	// Latency should be recorded and ~50ms
	if status.Checks[0].Latency < 40 || status.Checks[0].Latency > 100 {
		t.Errorf("Expected latency ~50ms, got %f ms", status.Checks[0].Latency)
	}
}

func TestReadinessManager_CheckedAtTimestamp(t *testing.T) {
	mgr := NewReadinessManager()
	mgr.AddChecker(&mockChecker{name: "db", ready: true})

	before := time.Now()
	status := mgr.CheckReady(context.Background())
	after := time.Now()

	if status.CheckedAt.Before(before) || status.CheckedAt.After(after) {
		t.Errorf("CheckedAt %v should be between %v and %v", status.CheckedAt, before, after)
	}
}

func TestReadinessManager_MultipleFailures(t *testing.T) {
	mgr := NewReadinessManager()
	mgr.AddChecker(&mockChecker{name: "db", ready: false, err: errors.New("db down")})
	mgr.AddChecker(&mockChecker{name: "cache", ready: false, err: errors.New("cache down")})
	mgr.AddChecker(&mockChecker{name: "healthy", ready: true})

	status := mgr.CheckReady(context.Background())

	if status.Ready {
		t.Error("Expected ready=false with multiple failures")
	}

	// Count failures
	failures := 0
	for _, check := range status.Checks {
		if !check.Ready {
			failures++
		}
	}
	if failures != 2 {
		t.Errorf("Expected 2 failures, got %d", failures)
	}
}

func TestReadinessStatus_JSON(t *testing.T) {
	status := &ReadinessStatus{
		Ready: true,
		Checks: []CheckResult{
			{Name: "db", Ready: true, Latency: 1.5, CheckedAt: time.Now()},
			{Name: "cache", Ready: false, Error: "timeout", Latency: 100.0, CheckedAt: time.Now()},
		},
		CheckedAt: time.Now(),
	}

	data, err := json.Marshal(status)
	if err != nil {
		t.Fatalf("Failed to marshal status: %v", err)
	}

	var decoded ReadinessStatus
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal status: %v", err)
	}

	if decoded.Ready != status.Ready {
		t.Error("Ready mismatch")
	}
	if len(decoded.Checks) != 2 {
		t.Error("Checks count mismatch")
	}
}

func TestDatabaseChecker_Timeout(t *testing.T) {
	slowPinger := &slowMockPinger{delay: 5 * time.Second}
	checker := NewDatabaseChecker("db", slowPinger)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	err := checker.CheckReady(ctx)
	if err == nil {
		t.Error("Expected timeout error")
	}
}

type slowMockPinger struct {
	delay time.Duration
}

func (p *slowMockPinger) Ping(ctx context.Context) error {
	select {
	case <-time.After(p.delay):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
