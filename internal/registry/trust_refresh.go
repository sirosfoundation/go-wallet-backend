package registry

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
	"github.com/sirosfoundation/go-wallet-backend/pkg/trust/authzen"
	"go.uber.org/zap"
)

// TrustRefreshWorker periodically refreshes stale trust evaluations in the background.
// It calls go-trust endpoints (AuthZEN) to re-evaluate trust for issuers with
// expired trust evaluations.
type TrustRefreshWorker struct {
	issuerStore            storage.IssuerStore
	tenantStore            storage.TenantStore
	defaultTrustEndpoint   string
	defaultRefreshInterval time.Duration
	logger                 *zap.Logger

	mu      sync.Mutex
	running bool
	stopCh  chan struct{}
	wg      sync.WaitGroup
}

// TrustRefreshConfig configures the TrustRefreshWorker
type TrustRefreshConfig struct {
	// DefaultTrustEndpoint is the go-trust endpoint to use when tenant has none configured
	DefaultTrustEndpoint string
	// DefaultRefreshInterval is the interval for checking stale trust
	DefaultRefreshInterval time.Duration
}

// NewTrustRefreshWorker creates a new TrustRefreshWorker
func NewTrustRefreshWorker(
	issuerStore storage.IssuerStore,
	tenantStore storage.TenantStore,
	config *TrustRefreshConfig,
	logger *zap.Logger,
) *TrustRefreshWorker {
	interval := 1 * time.Hour // Default 1 hour
	endpoint := ""
	if config != nil {
		if config.DefaultRefreshInterval > 0 {
			interval = config.DefaultRefreshInterval
		}
		endpoint = config.DefaultTrustEndpoint
	}
	return &TrustRefreshWorker{
		issuerStore:            issuerStore,
		tenantStore:            tenantStore,
		defaultTrustEndpoint:   endpoint,
		defaultRefreshInterval: interval,
		logger:                 logger.Named("trust-refresh"),
	}
}

// Start begins the background refresh worker
func (w *TrustRefreshWorker) Start() {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.running {
		return
	}

	w.running = true
	w.stopCh = make(chan struct{})
	w.wg.Add(1)

	go w.run()
	w.logger.Info("trust refresh worker started",
		zap.Duration("default_interval", w.defaultRefreshInterval))
}

// Stop stops the background refresh worker
func (w *TrustRefreshWorker) Stop() {
	w.mu.Lock()
	if !w.running {
		w.mu.Unlock()
		return
	}
	w.running = false
	close(w.stopCh)
	w.mu.Unlock()

	w.wg.Wait()
	w.logger.Info("trust refresh worker stopped")
}

// run is the main worker loop
func (w *TrustRefreshWorker) run() {
	defer w.wg.Done()

	ticker := time.NewTicker(w.defaultRefreshInterval)
	defer ticker.Stop()

	// Run immediately on start
	w.refreshAllTenants()

	for {
		select {
		case <-w.stopCh:
			return
		case <-ticker.C:
			w.refreshAllTenants()
		}
	}
}

// refreshAllTenants refreshes stale trust for all tenants
func (w *TrustRefreshWorker) refreshAllTenants() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Get all tenants
	tenants, err := w.tenantStore.GetAll(ctx)
	if err != nil {
		w.logger.Error("failed to get tenants for refresh", zap.Error(err))
		return
	}

	for _, tenant := range tenants {
		if !tenant.Enabled {
			continue
		}
		w.refreshTenant(ctx, tenant)
	}
}

// refreshTenant refreshes stale trust for a specific tenant
func (w *TrustRefreshWorker) refreshTenant(ctx context.Context, tenant *domain.Tenant) {
	// Get trust TTL for this tenant
	ttl := 86400 * time.Second // Default 24 hours
	if tenant.TrustConfig.TrustTTL > 0 {
		ttl = time.Duration(tenant.TrustConfig.TrustTTL) * time.Second
	}

	// Get all issuers for the tenant
	issuers, err := w.issuerStore.GetAll(ctx, tenant.ID)
	if err != nil {
		w.logger.Error("failed to get issuers for tenant",
			zap.String("tenant", string(tenant.ID)),
			zap.Error(err))
		return
	}

	refreshed := 0
	for _, issuer := range issuers {
		// Check if trust is stale
		if issuer.TrustEvaluatedAt != nil && time.Since(*issuer.TrustEvaluatedAt) < ttl {
			continue // Still valid
		}

		// Refresh trust
		if err := w.refreshIssuer(ctx, tenant, issuer); err != nil {
			w.logger.Warn("failed to refresh issuer trust",
				zap.String("tenant", string(tenant.ID)),
				zap.String("issuer", issuer.CredentialIssuerIdentifier),
				zap.Error(err))
			continue
		}
		refreshed++
	}

	if refreshed > 0 {
		w.logger.Info("refreshed issuer trust",
			zap.String("tenant", string(tenant.ID)),
			zap.Int("count", refreshed))
	}
}

// refreshIssuer re-evaluates trust for a specific issuer
func (w *TrustRefreshWorker) refreshIssuer(ctx context.Context, tenant *domain.Tenant, issuer *domain.CredentialIssuer) error {
	// Determine which trust endpoint to use
	trustEndpoint := w.defaultTrustEndpoint
	if tenant.TrustConfig.TrustEndpoint != "" {
		trustEndpoint = tenant.TrustConfig.TrustEndpoint
	}

	now := time.Now()

	// No trust endpoint configured - keep existing status, just update timestamp
	if trustEndpoint == "" {
		issuer.TrustEvaluatedAt = &now
		return w.issuerStore.Update(ctx, issuer)
	}

	// Create AuthZEN evaluator for this endpoint
	evaluator, err := authzen.NewEvaluator(&authzen.Config{
		BaseURL: trustEndpoint,
		Timeout: 15 * time.Second,
	})
	if err != nil {
		return fmt.Errorf("failed to create AuthZEN evaluator: %w", err)
	}

	// Evaluate trust (without certificates for refresh - just entity identifier)
	trustResp, err := evaluator.EvaluateX5C(ctx, issuer.CredentialIssuerIdentifier, nil, "issue")
	if err != nil {
		return fmt.Errorf("trust evaluation failed: %w", err)
	}

	// Update issuer
	if trustResp.Decision {
		issuer.TrustStatus = domain.TrustStatusTrusted
	} else {
		issuer.TrustStatus = domain.TrustStatusUntrusted
	}
	issuer.TrustFramework = detectTrustFramework(trustResp.TrustMetadata)
	issuer.TrustEvaluatedAt = &now

	return w.issuerStore.Update(ctx, issuer)
}

// detectTrustFramework attempts to identify the trust framework from metadata
func detectTrustFramework(metadata interface{}) string {
	if metadata == nil {
		return ""
	}

	if m, ok := metadata.(map[string]interface{}); ok {
		if tf, ok := m["trust_framework"].(string); ok {
			return tf
		}
	}

	return ""
}
