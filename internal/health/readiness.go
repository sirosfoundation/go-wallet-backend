// Package health provides health and readiness checking for the wallet backend.
// The readiness system supports Kubernetes-style probes with mode-specific checks.
package health

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// ReadinessChecker defines the interface for mode-specific readiness checks.
// Each provider (backend, registry, engine) implements this to verify its dependencies.
type ReadinessChecker interface {
	// CheckReady verifies the component is ready to serve requests.
	// Returns nil if ready, an error describing the issue if not.
	// Implementations should return quickly (< 2s) and handle their own timeouts.
	CheckReady(ctx context.Context) error

	// Name returns a human-readable name for logging and status reporting.
	Name() string
}

// CheckResult holds the result of a readiness check
type CheckResult struct {
	Name      string    `json:"name"`
	Ready     bool      `json:"ready"`
	Error     string    `json:"error,omitempty"`
	Latency   float64   `json:"latency_ms"`
	CheckedAt time.Time `json:"checked_at"`
}

// ReadinessStatus represents the overall readiness status
type ReadinessStatus struct {
	Ready     bool          `json:"ready"`
	Checks    []CheckResult `json:"checks"`
	CheckedAt time.Time     `json:"checked_at"`
}

// ReadinessManager aggregates multiple readiness checkers and caches results.
// It provides fast response times through caching while ensuring timely detection
// of dependency failures and recovery (self-healing).
type ReadinessManager struct {
	checkers []ReadinessChecker
	mu       sync.RWMutex

	// Cached status for quick response
	cachedStatus *ReadinessStatus
	cacheTTL     time.Duration

	// Check timeout
	checkTimeout time.Duration

	// Background probe
	stopCh   chan struct{}
	stopOnce sync.Once
}

// ReadinessOption configures the ReadinessManager
type ReadinessOption func(*ReadinessManager)

// WithCacheTTL sets the cache TTL for readiness results.
// Default is 2 seconds - balances quick detection with burst protection.
func WithCacheTTL(ttl time.Duration) ReadinessOption {
	return func(m *ReadinessManager) {
		m.cacheTTL = ttl
	}
}

// WithCheckTimeout sets the maximum time for each readiness check.
// Default is 2 seconds.
func WithCheckTimeout(timeout time.Duration) ReadinessOption {
	return func(m *ReadinessManager) {
		m.checkTimeout = timeout
	}
}

// NewReadinessManager creates a new readiness manager with the given checkers.
func NewReadinessManager(opts ...ReadinessOption) *ReadinessManager {
	m := &ReadinessManager{
		checkers:     make([]ReadinessChecker, 0),
		cacheTTL:     2 * time.Second,
		checkTimeout: 2 * time.Second,
		stopCh:       make(chan struct{}),
	}

	for _, opt := range opts {
		opt(m)
	}

	return m
}

// AddChecker registers a readiness checker.
// Call this before starting the background probe.
func (m *ReadinessManager) AddChecker(checker ReadinessChecker) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.checkers = append(m.checkers, checker)
}

// CheckReady performs readiness checks and returns the aggregated status.
// Uses cached results if available and fresh (within TTL).
// This method is optimized for quick response in Kubernetes probes.
func (m *ReadinessManager) CheckReady(ctx context.Context) *ReadinessStatus {
	// Check cache first for quick response
	m.mu.RLock()
	if m.cachedStatus != nil && time.Since(m.cachedStatus.CheckedAt) < m.cacheTTL {
		status := m.cachedStatus
		m.mu.RUnlock()
		return status
	}
	m.mu.RUnlock()

	// Cache miss or expired - run checks
	return m.runChecks(ctx)
}

// runChecks executes all readiness checks in parallel with timeout.
func (m *ReadinessManager) runChecks(ctx context.Context) *ReadinessStatus {
	m.mu.RLock()
	checkers := make([]ReadinessChecker, len(m.checkers))
	copy(checkers, m.checkers)
	m.mu.RUnlock()

	if len(checkers) == 0 {
		// No checkers registered - consider ready
		status := &ReadinessStatus{
			Ready:     true,
			Checks:    []CheckResult{},
			CheckedAt: time.Now(),
		}
		m.updateCache(status)
		return status
	}

	// Create timeout context for all checks
	checkCtx, cancel := context.WithTimeout(ctx, m.checkTimeout)
	defer cancel()

	// Run checks in parallel
	results := make([]CheckResult, len(checkers))
	var wg sync.WaitGroup

	for i, checker := range checkers {
		wg.Add(1)
		go func(idx int, c ReadinessChecker) {
			defer wg.Done()

			start := time.Now()
			err := c.CheckReady(checkCtx)
			latency := time.Since(start).Seconds() * 1000

			result := CheckResult{
				Name:      c.Name(),
				Ready:     err == nil,
				Latency:   latency,
				CheckedAt: time.Now(),
			}
			if err != nil {
				result.Error = err.Error()
			}
			results[idx] = result
		}(i, checker)
	}

	wg.Wait()

	// Aggregate results - ready only if ALL checks pass
	allReady := true
	for _, r := range results {
		if !r.Ready {
			allReady = false
			break
		}
	}

	status := &ReadinessStatus{
		Ready:     allReady,
		Checks:    results,
		CheckedAt: time.Now(),
	}

	m.updateCache(status)
	return status
}

// updateCache stores the status in the cache
func (m *ReadinessManager) updateCache(status *ReadinessStatus) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cachedStatus = status
}

// StartBackgroundProbe starts a background goroutine that periodically checks
// readiness and updates the cache. This ensures fresh cached values for
// burst traffic and enables proactive detection of dependency recovery.
func (m *ReadinessManager) StartBackgroundProbe(interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		// Run initial check
		m.runChecks(context.Background())

		for {
			select {
			case <-ticker.C:
				m.runChecks(context.Background())
			case <-m.stopCh:
				return
			}
		}
	}()
}

// Stop stops the background probe
func (m *ReadinessManager) Stop() {
	m.stopOnce.Do(func() {
		close(m.stopCh)
	})
}

// DatabaseChecker checks database connectivity
type DatabaseChecker struct {
	name   string
	pinger Pinger
}

// Pinger interface for database ping operations
type Pinger interface {
	Ping(ctx context.Context) error
}

// NewDatabaseChecker creates a checker for database connectivity
func NewDatabaseChecker(name string, pinger Pinger) *DatabaseChecker {
	return &DatabaseChecker{
		name:   name,
		pinger: pinger,
	}
}

func (c *DatabaseChecker) Name() string { return c.name }

func (c *DatabaseChecker) CheckReady(ctx context.Context) error {
	if c.pinger == nil {
		return fmt.Errorf("database not configured")
	}
	return c.pinger.Ping(ctx)
}
