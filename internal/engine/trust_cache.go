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

// TrustCache is a tenant-aware, in-memory TTL cache for verifier trust
// evaluations. It replaces the previous approach of writing to VerifierStore
// (which polluted the admin registry).
//
// TrustCache itself is agnostic to what the string key represents - callers
// decide that. OID4VPHandler (see oid4vp.go's evaluateVerifierTrust) keys it
// by the authenticated identity that scheme-bound signature verification
// produces (e.g. a verified DID, or a client_id whose request JWT verified
// against its x5c/attestation cnf key) rather than a bare client-supplied
// URL, specifically so one verifier's entry can never answer for a
// different claimed identity that happens to share a URL. It also only ever
// writes a PDP-backed verdict here, never a client-asserted one - see
// cacheVerifierTrust's doc comment.
type TrustCache struct {
	mu      sync.RWMutex
	entries map[string]*TrustCacheEntry // key: tenantID + "|" + cacheKey
	ttl     time.Duration
	now     func() time.Time // injectable clock for testing
}

// NewTrustCache creates a new in-memory trust cache with the given TTL.
//
// A non-positive ttl disables the cache: Get always misses and Set never
// stores, so every evaluation reaches the PDP. That is one meaning for the
// value rather than an entry that expires the instant it is written, which
// would still be a cache hit for any caller racing it.
func NewTrustCache(ttl time.Duration) *TrustCache {
	return &TrustCache{
		entries: make(map[string]*TrustCacheEntry),
		ttl:     ttl,
		now:     time.Now,
	}
}

func trustCacheKey(tenantID domain.TenantID, cacheKey string) string {
	return string(tenantID) + "|" + cacheKey
}

// Get retrieves a cached trust record for the given tenant and cache key.
// Returns nil if not found or expired.
func (c *TrustCache) Get(tenantID domain.TenantID, cacheKey string) *TrustCacheRecord {
	if c == nil || c.ttl <= 0 {
		return nil
	}
	key := trustCacheKey(tenantID, cacheKey)

	c.mu.RLock()
	entry, ok := c.entries[key]
	c.mu.RUnlock()

	if !ok {
		return nil
	}
	if c.now().After(entry.ExpiresAt) {
		// Expired — remove lazily
		c.mu.Lock()
		delete(c.entries, key)
		c.mu.Unlock()
		return nil
	}
	return entry.Verifier
}

// Set stores a trust evaluation result in the cache.
// Also sweeps expired entries to prevent unbounded growth.
//
// Callers must only store PDP-backed verdicts here, never a client-asserted
// one - TrustCache itself has no way to enforce that; see
// OID4VPHandler.cacheVerifierTrust for where that rule is enforced.
func (c *TrustCache) Set(tenantID domain.TenantID, cacheKey string, record *TrustCacheRecord) {
	if c == nil || c.ttl <= 0 {
		return
	}
	key := trustCacheKey(tenantID, cacheKey)
	now := c.now()

	c.mu.Lock()
	c.entries[key] = &TrustCacheEntry{
		Verifier:  record,
		ExpiresAt: now.Add(c.ttl),
	}
	// Sweep expired entries opportunistically on each Set to prevent unbounded growth
	for k, e := range c.entries {
		if now.After(e.ExpiresAt) {
			delete(c.entries, k)
		}
	}
	c.mu.Unlock()
}

// Len returns the number of entries (including potentially expired ones).
func (c *TrustCache) Len() int {
	if c == nil {
		return 0
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}
