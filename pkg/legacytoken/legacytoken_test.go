package legacytoken

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func signTestToken(t *testing.T, secret string, claims jwt.MapClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString([]byte(secret))
	if err != nil {
		t.Fatalf("SignedString: %v", err)
	}
	return signed
}

func TestSID_ReturnsTheSIDClaim(t *testing.T) {
	secret := "test-secret"
	token := signTestToken(t, secret, jwt.MapClaims{
		"user_id": "user-1",
		"sid":     "sid-family-1",
		"exp":     time.Now().Add(time.Hour).Unix(),
	})

	got := SID(secret, token)
	if got != "sid-family-1" {
		t.Errorf("SID() = %q, want %q", got, "sid-family-1")
	}
}

func TestSID_NoSIDClaim_ReturnsEmpty(t *testing.T) {
	secret := "test-secret"
	token := signTestToken(t, secret, jwt.MapClaims{
		"user_id": "user-1",
		"exp":     time.Now().Add(time.Hour).Unix(),
	})

	got := SID(secret, token)
	if got != "" {
		t.Errorf("SID() = %q, want empty string for a token with no sid claim", got)
	}
}

func TestSID_WrongSecret_ReturnsEmpty(t *testing.T) {
	token := signTestToken(t, "correct-secret", jwt.MapClaims{
		"sid": "sid-family-1",
		"exp": time.Now().Add(time.Hour).Unix(),
	})

	got := SID("wrong-secret", token)
	if got != "" {
		t.Errorf("SID() = %q, want empty string when the signature doesn't verify", got)
	}
}

func TestSID_MalformedToken_ReturnsEmpty(t *testing.T) {
	got := SID("test-secret", "not-a-jwt")
	if got != "" {
		t.Errorf("SID() = %q, want empty string for a malformed token", got)
	}
}

func TestSID_NonHMACSigningMethod_Rejected(t *testing.T) {
	// A token whose alg isn't HMAC (e.g. "none") must not be accepted even
	// if it happens to carry a sid claim - this mirrors the same signing
	// method check every other legacy-token parse in this codebase does.
	token := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims{
		"sid": "sid-family-1",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	signed, err := token.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("SignedString: %v", err)
	}

	got := SID("test-secret", signed)
	if got != "" {
		t.Errorf("SID() = %q, want empty string for a non-HMAC-signed token", got)
	}
}
