package legacytoken

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strconv"
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

func hsToken(t *testing.T, method jwt.SigningMethod, secret string, c jwt.MapClaims) string {
	t.Helper()
	s, err := jwt.NewWithClaims(method, c).SignedString([]byte(secret))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestValidateAnyAudience(t *testing.T) {
	const secret = "0123456789abcdef0123456789abcdef"
	issuers := []string{"wallet-backend"}
	good := func(mod func(jwt.MapClaims)) string {
		c := jwt.MapClaims{"iss": "wallet-backend", "user_id": "u1", "did": "did:x", "tenant_id": "acme",
			"jti": "j1", "exp": time.Now().Add(time.Hour).Unix()}
		if mod != nil {
			mod(c)
		}
		return hsToken(t, jwt.SigningMethodHS256, secret, c)
	}

	// Positive controls: a valid token is accepted whatever its audience.
	for name, aud := range map[string]any{
		"no aud": nil, "rp id": "wallet.example.org", "unrelated": "https://other", "list": []string{"a", "b"}, "empty": "",
	} {
		aud := aud
		res, err := ValidateAnyAudience(secret, issuers, good(func(c jwt.MapClaims) {
			if aud != nil {
				c["aud"] = aud
			}
		}))
		if err != nil {
			t.Fatalf("%s: valid token rejected: %v", name, err)
		}
		if res.UserID != "u1" || res.DID != "did:x" || res.TenantID != "acme" || res.JTI != "j1" || res.Mode != "legacy" {
			t.Errorf("%s: unexpected result %+v", name, res)
		}
	}

	// Positive control for iat: a past iat is accepted.
	if _, err := ValidateAnyAudience(secret, issuers, good(func(c jwt.MapClaims) { c["iat"] = time.Now().Add(-time.Minute).Unix() })); err != nil {
		t.Fatalf("token with past iat rejected: %v", err)
	}

	// Negative cases (non-vacuous: each differs from the control in one thing).
	expired := good(func(c jwt.MapClaims) { c["exp"] = time.Now().Add(-time.Hour).Unix() })
	noExp := good(func(c jwt.MapClaims) { delete(c, "exp") })
	badIss := good(func(c jwt.MapClaims) { c["iss"] = "someone-else" })
	noIss := good(func(c jwt.MapClaims) { delete(c, "iss") })
	notYet := good(func(c jwt.MapClaims) { c["nbf"] = time.Now().Add(time.Hour).Unix() })
	futureIat := good(func(c jwt.MapClaims) { c["iat"] = time.Now().Add(time.Hour).Unix() })
	wrongSecret := hsToken(t, jwt.SigningMethodHS256, "another-secret-another-secret-00000", jwt.MapClaims{
		"iss": "wallet-backend", "exp": time.Now().Add(time.Hour).Unix()})
	none, err := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims{"iss": "wallet-backend", "exp": time.Now().Add(time.Hour).Unix()}).
		SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatal(err)
	}
	for name, tok := range map[string]string{"expired": expired, "no exp": noExp, "bad issuer": badIss, "no issuer": noIss,
		"nbf in future": notYet, "iat in future": futureIat, "wrong secret": wrongSecret, "alg none": none, "garbage": "x.y.z"} {
		if _, err := ValidateAnyAudience(secret, issuers, tok); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := ValidateAnyAudience("", issuers, good(nil)); err == nil {
		t.Error("empty secret accepted")
	}
	if _, err := ValidateAnyAudience(secret, nil, good(nil)); err == nil {
		t.Error("no issuers accepted")
	}
	if _, err := ValidateAnyAudience(secret, []string{""}, good(func(c jwt.MapClaims) { delete(c, "iss") })); err == nil {
		t.Error("empty configured issuer matched a missing iss")
	}
}

func TestIsHMAC(t *testing.T) {
	hs := hsToken(t, jwt.SigningMethodHS384, "s", jwt.MapClaims{"a": 1})
	if !IsHMAC(hs) {
		t.Error("HS384 not recognised")
	}
	for _, m := range []jwt.SigningMethod{jwt.SigningMethodHS256, jwt.SigningMethodHS512} {
		if !IsHMAC(hsToken(t, m, "s", jwt.MapClaims{"a": 1})) {
			t.Errorf("%s not recognised", m.Alg())
		}
	}
	ek, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	es, err := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{"a": 1}).SignedString(ek)
	if err != nil {
		t.Fatal(err)
	}
	none, _ := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims{}).SignedString(jwt.UnsafeAllowNoneSignatureType)
	for _, tok := range []string{es, none, "", "junk", "a.b.c"} {
		if IsHMAC(tok) {
			t.Errorf("%q treated as HMAC", tok)
		}
	}
}

// Algorithm-confusion: a token whose header claims RS256 (or none) but which
// is MAC'd with the shared HMAC secret must be refused by both the router and
// the validator.
func TestAlgConfusionRefused(t *testing.T) {
	const secret = "0123456789abcdef0123456789abcdef"
	enc := base64.RawURLEncoding.EncodeToString
	signing := enc([]byte(`{"alg":"RS256","typ":"JWT"}`)) + "." +
		enc([]byte(`{"iss":"wallet-backend","exp":`+strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10)+`}`))
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(signing))
	rs := signing + "." + enc(mac.Sum(nil))

	if IsHMAC(rs) {
		t.Error("RS256-header token routed as HMAC")
	}
	if _, err := ValidateAnyAudience(secret, []string{"wallet-backend"}, rs); err == nil {
		t.Error("RS256-with-HMAC-secret token accepted by ValidateAnyAudience")
	}
	if _, err := ParseSID(secret, rs); err == nil {
		t.Error("RS256-with-HMAC-secret token accepted by ParseSID")
	}
}
