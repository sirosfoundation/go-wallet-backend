package registry

import (
	"context"
	"sync"
	"time"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/service"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
	"go.uber.org/zap"
)

// TrustRefreshWorker periodically refreshes stale trust evaluations in the background.
// It uses the same logic as IssuerMetadataHandler but operates on all issuers with
// expired trust evaluations.
type TrustRefreshWorker struct {
	trustService         *service.TrustService
	issuerStore          storage.IssuerStore
	tenantStore          storage.TenantStore
	defaultRefreshInterval time.Duration
	logger               *zap.Logger

	mu      sync.Mutex
	running bool
	stopCh  chan struct{}
	wg      sync.WaitGroup
}

// TrustRefreshConfig configures the TrustRefreshWorker
type TrustRefreshConfig struct {
	// DefaultRefreshInterval is the default interval for checking stale trust (if tenant has none configured)
	DefaultRefreshInterval time.Duration
}

// NewTrustRefreshWorker creates a new TrustRefreshWorker
func NewTrustRefreshWorker(
	trustService *service.TrustService,
	issuerStore storage.IssuerStore,
	tenantStore storage.TenantStore,
	config *TrustRefreshConfig,
	logger *zap.Logger,
) *TrustRefreshWorker {
	interval := 1 * time.Hour // Default 1 hour
	if config != nil && config.DefaultRefreshInterval > 0 {
		interval = config.DefaultRefreshInterval
	}
	return &TrustRefreshWorker{
		trustService:           trustService,
		issuerStore:            issuerStore,
		tenantStore:            tenantStore,
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
	if w.trustService == nil {
		// No trust service configured, just update timestamp
		now := time.Now()
		issuer.TrustEvaluatedAt = &now
		return w.issuerStore.Update(ctx, issuer)
	}

	// Evaluate trust (without fetching metadata again for refresh)
	// For background refresh, we just re-evaluate with existing information
	trustResp, err := w.trustService.EvaluateIssuer(ctx, issuer.CredentialIssuerIdentifier, "", nil)
	if err != nil {
		return err
	}

	// Update issuer
	now := time.Now()
	if trustResp.Trusted {
		issuer.TrustStatus = domain.TrustStatusTrusted
	} else {
		issuer.TrustStatus = domain.TrustStatusUntrusted
	}
	issuer.TrustFramework = trustResp.TrustFramework
	issuer.TrustEvaluatedAt = &now

	return w.issuerStore.Update(ctx, issuer)
}
