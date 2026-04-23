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
