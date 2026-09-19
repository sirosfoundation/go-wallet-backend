package engine

import (
	"testing"
	"time"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
)

func TestTrustCache_SetAndGet(t *testing.T) {
	cache := NewTrustCache(1 * time.Hour)
	tenant := domain.TenantID("test-tenant")

	record := &TrustCacheRecord{
		Name:           "Test Verifier",
		URL:            "https://verifier.example.com/response",
		ClientIDScheme: "redirect_uri",
		TrustStatus:    domain.TrustStatusTrusted,
		TrustFramework: "eidas",
		Trusted:        true,
	}

	cache.Set(tenant, "https://verifier.example.com/response", record)

	got := cache.Get(tenant, "https://verifier.example.com/response")
	if got == nil {
		t.Fatal("expected cached record, got nil")
	}
	if got.Name != "Test Verifier" {
		t.Errorf("Name = %q, want %q", got.Name, "Test Verifier")
	}
	if got.TrustStatus != domain.TrustStatusTrusted {
		t.Errorf("TrustStatus = %q, want %q", got.TrustStatus, domain.TrustStatusTrusted)
	}
	if !got.Trusted {
		t.Error("Trusted = false, want true")
	}
}

func TestTrustCache_GetMiss(t *testing.T) {
	cache := NewTrustCache(1 * time.Hour)
	tenant := domain.TenantID("test-tenant")

	got := cache.Get(tenant, "https://unknown.example.com")
	if got != nil {
		t.Errorf("expected nil for unknown key, got %+v", got)
	}
}

func TestTrustCache_TenantIsolation(t *testing.T) {
	cache := NewTrustCache(1 * time.Hour)
	url := "https://verifier.example.com"

	cache.Set("tenant-a", url, &TrustCacheRecord{
		Name:    "Verifier A",
		Trusted: true,
	})
	cache.Set("tenant-b", url, &TrustCacheRecord{
		Name:    "Verifier B",
		Trusted: false,
	})

	a := cache.Get("tenant-a", url)
	b := cache.Get("tenant-b", url)

	if a == nil || a.Name != "Verifier A" || !a.Trusted {
		t.Errorf("tenant-a record wrong: %+v", a)
	}
	if b == nil || b.Name != "Verifier B" || b.Trusted {
		t.Errorf("tenant-b record wrong: %+v", b)
	}
}

func TestTrustCache_Expiry(t *testing.T) {
	cache := NewTrustCache(1 * time.Hour)
	tenant := domain.TenantID("test")

	// Use injectable clock to avoid flaky time.Sleep-based tests
	fakeNow := time.Now()
	cache.now = func() time.Time { return fakeNow }

	cache.Set(tenant, "https://verifier.example.com", &TrustCacheRecord{
		Name:    "Expiring",
		Trusted: true,
	})

	// Should be present immediately
	if got := cache.Get(tenant, "https://verifier.example.com"); got == nil {
		t.Fatal("expected record immediately after set")
	}

	// Advance clock past TTL
	fakeNow = fakeNow.Add(2 * time.Hour)

	got := cache.Get(tenant, "https://verifier.example.com")
	if got != nil {
		t.Errorf("expected nil after expiry, got %+v", got)
	}

	// Verify entry was cleaned up
	if cache.Len() != 0 {
		t.Errorf("expected 0 entries after expired get, got %d", cache.Len())
	}
}

func TestTrustCache_Overwrite(t *testing.T) {
	cache := NewTrustCache(1 * time.Hour)
	tenant := domain.TenantID("test")
	url := "https://verifier.example.com"

	cache.Set(tenant, url, &TrustCacheRecord{
		Name:        "Old",
		TrustStatus: domain.TrustStatusUntrusted,
		Trusted:     false,
	})
	cache.Set(tenant, url, &TrustCacheRecord{
		Name:        "New",
		TrustStatus: domain.TrustStatusTrusted,
		Trusted:     true,
	})

	got := cache.Get(tenant, url)
	if got == nil {
		t.Fatal("expected record after overwrite")
	}
	if got.Name != "New" {
		t.Errorf("Name = %q, want %q", got.Name, "New")
	}
	if !got.Trusted {
		t.Error("Trusted = false, want true after overwrite")
	}
}

func TestTrustCache_Len(t *testing.T) {
	cache := NewTrustCache(1 * time.Hour)

	if cache.Len() != 0 {
		t.Errorf("Len() = %d, want 0 for empty cache", cache.Len())
	}

	cache.Set("t1", "url1", &TrustCacheRecord{Name: "a"})
	cache.Set("t1", "url2", &TrustCacheRecord{Name: "b"})
	cache.Set("t2", "url1", &TrustCacheRecord{Name: "c"})

	if cache.Len() != 3 {
		t.Errorf("Len() = %d, want 3", cache.Len())
	}
}

func TestTrustCache_SweepOnSet(t *testing.T) {
	cache := NewTrustCache(1 * time.Hour)

	fakeNow := time.Now()
	cache.now = func() time.Time { return fakeNow }

	// Add some entries
	cache.Set("t1", "url1", &TrustCacheRecord{Name: "a"})
	cache.Set("t1", "url2", &TrustCacheRecord{Name: "b"})
	cache.Set("t2", "url1", &TrustCacheRecord{Name: "c"})

	if cache.Len() != 3 {
		t.Fatalf("Len() = %d, want 3 before sweep", cache.Len())
	}

	// Advance clock past TTL so all existing entries are expired
	fakeNow = fakeNow.Add(2 * time.Hour)

	// Set a new entry — this should sweep the 3 expired entries
	cache.Set("t3", "url3", &TrustCacheRecord{Name: "d"})

	// Only the new entry should remain
	if cache.Len() != 1 {
		t.Errorf("Len() = %d, want 1 after sweep-on-set", cache.Len())
	}
	if got := cache.Get("t3", "url3"); got == nil || got.Name != "d" {
		t.Errorf("new entry missing after sweep, got %+v", got)
	}
}

// TestTrustCache_DisabledNeverCaches pins what config.TrustConfig.CacheDisabled
// buys: with a non-positive TTL nothing is stored and nothing is returned, so
// every evaluation reaches the PDP.
//
// This is the switch that makes trust configuration testable. With the cache
// on, a denial is reused for the whole TTL without consulting the PDP at all,
// so fixing a whitelist or a key and redeploying changes nothing until it
// expires - and no log says the answer was stale.
func TestTrustCache_DisabledNeverCaches(t *testing.T) {
	for _, ttl := range []time.Duration{0, -time.Second} {
		c := NewTrustCache(ttl)
		c.Set(domain.DefaultTenantID, "https://verifier.example", &TrustCacheRecord{
			URL:     "https://verifier.example",
			Trusted: true,
		})
		// Checked before any Get, and this ordering is the whole test: an
		// entry written with a zero TTL is already expired, so a later Get
		// would evict it and report a miss even if Set had stored it. Only
		// Len here tells "never stored" from "stored and instantly stale".
		if c.Len() != 0 {
			t.Fatalf("ttl %v: expected nothing stored, got %d entries", ttl, c.Len())
		}
		if got := c.Get(domain.DefaultTenantID, "https://verifier.example"); got != nil {
			t.Fatalf("ttl %v: expected a miss, got %+v", ttl, got)
		}
	}
}

// A denial is cached exactly like an approval, so disabling the cache has to
// suppress both - that is the case the switch exists for.
func TestTrustCache_DisabledDoesNotCacheDenials(t *testing.T) {
	c := NewTrustCache(0)
	c.Set(domain.DefaultTenantID, "https://verifier.example", &TrustCacheRecord{
		URL:     "https://verifier.example",
		Trusted: false,
	})
	if c.Len() != 0 {
		t.Fatalf("expected the denial not to be stored, got %d entries", c.Len())
	}
	if got := c.Get(domain.DefaultTenantID, "https://verifier.example"); got != nil {
		t.Fatalf("expected a miss for a cached denial, got %+v", got)
	}
}

// A nil cache is what a handler holds when the manager never set one; every
// exported method must behave like a disabled one rather than panic. Get and
// Set guard the receiver explicitly; Len does not touch any field before
// acquiring c.mu, so a bare nil check is required there too - c.mu.RLock()
// on a nil *TrustCache panics on the implicit dereference of c, and nothing
// else in this file was exercising Len on a nil receiver to catch that.
func TestTrustCache_NilIsSafe(t *testing.T) {
	var c *TrustCache
	c.Set(domain.DefaultTenantID, "https://verifier.example", &TrustCacheRecord{Trusted: true})
	if got := c.Get(domain.DefaultTenantID, "https://verifier.example"); got != nil {
		t.Fatalf("expected nil from a nil cache, got %+v", got)
	}
	if got := c.Len(); got != 0 {
		t.Fatalf("expected 0 from a nil cache, got %d", got)
	}
}
