package as

import (
	"testing"
	"time"
)

func TestLegacyTokenIssuer_IssueAndValidate(t *testing.T) {
	secret := []byte("test-secret-32-bytes-long-value!")
	issuer := NewLegacyTokenIssuer(secret, "test-issuer", 24*time.Hour)

	token, err := issuer.Issue("user-123", "did:example:abc", "tenant-1", "rp-1")
	if err != nil {
		t.Fatalf("Issue failed: %v", err)
	}
	if token == "" {
		t.Fatal("expected non-empty token")
	}

	claims, err := issuer.Validate(token, "rp-1")
	if err != nil {
		t.Fatalf("Validate failed: %v", err)
	}

	if claims.UserID != "user-123" {
		t.Errorf("expected user_id user-123, got %s", claims.UserID)
	}
	if claims.DID != "did:example:abc" {
		t.Errorf("expected did did:example:abc, got %s", claims.DID)
	}
	if claims.TenantID != "tenant-1" {
		t.Errorf("expected tenant_id tenant-1, got %s", claims.TenantID)
	}
	if claims.Issuer != "test-issuer" {
		t.Errorf("expected issuer test-issuer, got %s", claims.Issuer)
	}
}

func TestLegacyTokenIssuer_ValidateExpired(t *testing.T) {
	secret := []byte("test-secret-32-bytes-long-value!")
	// Issue with -10s TTL — token is well past the 5s leeway.
	issuer := NewLegacyTokenIssuer(secret, "test-issuer", -10*time.Second)

	token, err := issuer.Issue("user-1", "", "tenant-1", "rp-1")
	if err != nil {
		t.Fatalf("Issue failed: %v", err)
	}

	_, err = issuer.Validate(token, "rp-1")
	if err == nil {
		t.Fatal("expected validation to fail for expired token")
	}
}

func TestLegacyTokenIssuer_ValidateWrongSecret(t *testing.T) {
	secret1 := []byte("secret-one-32-bytes-long-value!")
	secret2 := []byte("secret-two-32-bytes-long-value!")
	issuer1 := NewLegacyTokenIssuer(secret1, "test-issuer", 24*time.Hour)
	issuer2 := NewLegacyTokenIssuer(secret2, "test-issuer", 24*time.Hour)

	token, err := issuer1.Issue("user-1", "", "tenant-1", "rp-1")
	if err != nil {
		t.Fatalf("Issue failed: %v", err)
	}

	_, err = issuer2.Validate(token, "rp-1")
	if err == nil {
		t.Fatal("expected validation to fail with wrong secret")
	}
}

func TestLegacyTokenIssuer_IssueRefresh(t *testing.T) {
	secret := []byte("test-secret-32-bytes-long-value!")
	issuer := NewLegacyTokenIssuer(secret, "test-issuer", 24*time.Hour)

	token, err := issuer.IssueRefresh("user-1", "did:example:xyz", "tenant-1", "rp-1", 7*24*time.Hour)
	if err != nil {
		t.Fatalf("IssueRefresh failed: %v", err)
	}
	if token == "" {
		t.Fatal("expected non-empty refresh token")
	}
}

func TestLegacyTokenIssuer_ValidateWrongIssuer(t *testing.T) {
	secret := []byte("test-secret-32-bytes-long-value!")
	issuer1 := NewLegacyTokenIssuer(secret, "issuer-a", 24*time.Hour)
	issuer2 := NewLegacyTokenIssuer(secret, "issuer-b", 24*time.Hour)

	token, err := issuer1.Issue("user-1", "", "tenant-1", "rp-1")
	if err != nil {
		t.Fatalf("Issue failed: %v", err)
	}

	// Validate with issuer2 checks for "issuer-b" but token has "issuer-a".
	_, err = issuer2.Validate(token, "rp-1")
	if err == nil {
		t.Fatal("expected validation to fail for wrong issuer")
	}
}

func TestLegacyTokenIssuer_ValidateWrongAudience(t *testing.T) {
	secret := []byte("test-secret-32-bytes-long-value!")
	issuer := NewLegacyTokenIssuer(secret, "test-issuer", 24*time.Hour)

	token, err := issuer.Issue("user-1", "", "tenant-1", "rp-1")
	if err != nil {
		t.Fatalf("Issue failed: %v", err)
	}

	// Token was issued for "rp-1", validate against "rp-2".
	_, err = issuer.Validate(token, "rp-2")
	if err == nil {
		t.Fatal("expected validation to fail for wrong audience")
	}
}

func TestLegacyTokenIssuer_ValidateNoAudience(t *testing.T) {
	secret := []byte("test-secret-32-bytes-long-value!")
	issuer := NewLegacyTokenIssuer(secret, "test-issuer", 24*time.Hour)

	token, err := issuer.Issue("user-1", "", "tenant-1", "rp-1")
	if err != nil {
		t.Fatalf("Issue failed: %v", err)
	}

	// When no audience is passed, issuer check still applies but aud is not checked.
	claims, err := issuer.Validate(token)
	if err != nil {
		t.Fatalf("Validate without audience should succeed: %v", err)
	}
	if claims.UserID != "user-1" {
		t.Errorf("expected user-1, got %s", claims.UserID)
	}
}
