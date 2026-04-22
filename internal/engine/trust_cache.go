package engine

import (
	"sync"
	"time"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
)

// TrustCacheEntry holds a cached trust evaluation result with expiry.
type TrustCacheEntry struct {
	Verifier  *TrustCacheRecord
	ExpiresAt time.Time
}

// TrustCacheRecord stores the trust evaluation fields that are cached in memory.
type TrustCacheRecord struct {
	Name           string
	URL            string
	ClientIDScheme string
	TrustStatus    domain.TrustStatus
	TrustFramework string
	Trusted        bool
}

// TrustCache is a tenant-aware, in-memory TTL cache for verifier trust evaluations.
// It replaces the previous approach of writing to VerifierStore (which polluted the admin registry).
type TrustCache struct {
	mu      sync.RWMutex
	entries map[string]*TrustCacheEntry // key: tenantID + "|" + verifierURL
	ttl     time.Duration
}

// NewTrustCache creates a new in-memory trust cache with the given TTL.
func NewTrustCache(ttl time.Duration) *TrustCache {
	return &TrustCache{
		entries: make(map[string]*TrustCacheEntry),
		ttl:     ttl,
	}
}

func trustCacheKey(tenantID domain.TenantID, verifierURL string) string {
	return string(tenantID) + "|" + verifierURL
}

// Get retrieves a cached trust record for the given tenant and verifier URL.
// Returns nil if not found or expired.
func (c *TrustCache) Get(tenantID domain.TenantID, verifierURL string) *TrustCacheRecord {
	key := trustCacheKey(tenantID, verifierURL)

	c.mu.RLock()
	entry, ok := c.entries[key]
	c.mu.RUnlock()

	if !ok {
		return nil
	}
	if time.Now().After(entry.ExpiresAt) {
		// Expired — remove lazily
		c.mu.Lock()
		delete(c.entries, key)
		c.mu.Unlock()
		return nil
	}
	return entry.Verifier
}

// Set stores a trust evaluation result in the cache.
func (c *TrustCache) Set(tenantID domain.TenantID, verifierURL string, record *TrustCacheRecord) {
	key := trustCacheKey(tenantID, verifierURL)

	c.mu.Lock()
	c.entries[key] = &TrustCacheEntry{
		Verifier:  record,
		ExpiresAt: time.Now().Add(c.ttl),
	}
	c.mu.Unlock()
}

// Len returns the number of entries (including potentially expired ones).
func (c *TrustCache) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}
