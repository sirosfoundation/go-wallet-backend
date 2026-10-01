package legacytoken

import (
	"errors"
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

// TestParseSID_AcceptsTokenInsideClockSkewWindow is the regression test for
// the fail-open review finding: go-tokenauth accepts a token up to its
// leeway past exp, so the re-parse must not re-validate time claims.
func TestParseSID_AcceptsTokenInsideClockSkewWindow(t *testing.T) {
	secret := "test-secret"
	token := signTestToken(t, secret, jwt.MapClaims{
		"sid": "sid-skew",
		"exp": time.Now().Add(-2 * time.Second).Unix(), // expired, within 5s leeway
		"nbf": time.Now().Add(2 * time.Second).Unix(),  // not yet valid, within leeway
		"iat": time.Now().Add(2 * time.Second).Unix(),
	})

	sid, err := ParseSID(secret, token)
	if err != nil || sid != "sid-skew" {
		t.Errorf("ParseSID() = (%q, %v), want (sid-skew, nil)", sid, err)
	}
	if got := SID(secret, token); got != "sid-skew" {
		t.Errorf("SID() = %q, want sid-skew", got)
	}
}

func TestParseSID_NoSID_NilError(t *testing.T) {
	token := signTestToken(t, "s", jwt.MapClaims{"exp": time.Now().Add(time.Hour).Unix()})
	sid, err := ParseSID("s", token)
	if err != nil || sid != "" {
		t.Errorf("ParseSID() = (%q, %v), want (\"\", nil)", sid, err)
	}
}

func TestParseSID_UnverifiableTokens_ReturnErrUnparseable(t *testing.T) {
	good := signTestToken(t, "right", jwt.MapClaims{"sid": "x"})
	none, _ := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims{"sid": "x"}).SignedString(jwt.UnsafeAllowNoneSignatureType)
	for name, tok := range map[string]string{
		"wrong secret": good,
		"malformed":    "not-a-jwt",
		"alg none":     none,
		"empty":        "",
	} {
		secret := "wrong"
		if name != "wrong secret" {
			secret = "right"
		}
		if sid, err := ParseSID(secret, tok); !errors.Is(err, ErrUnparseable) || sid != "" {
			t.Errorf("%s: ParseSID() = (%q, %v), want (\"\", ErrUnparseable)", name, sid, err)
		}
	}
}
