package issuertrust

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/sirosfoundation/go-wallet-backend/pkg/trust"
)

// signedWRPRC returns a WRPRC really signed by a fresh registrar key, with the
// registrar certificate in x5c, plus the unmodified payload claims.
func signedWRPRC(t *testing.T, mutate func(h jwt.MapClaims, header map[string]any)) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(7),
		Subject:      pkix.Name{CommonName: "registrar"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	claims := jwt.MapClaims{"sub": testIdentifier, "entitlements": []string{"x"}}
	tok := jwt.New(jwt.SigningMethodES256)
	tok.Header["typ"] = "rc-wrp+jwt"
	tok.Header["x5c"] = []string{base64.StdEncoding.EncodeToString(der)}
	if mutate != nil {
		mutate(claims, tok.Header)
	}
	tok.Claims = claims
	s, err := tok.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func registrar(answer bool, err error, called *bool) RegistrarTrust {
	return func(context.Context, *trust.KeyMaterial) (bool, error) {
		if called != nil {
			*called = true
		}
		return answer, err
	}
}

func TestAuthenticateRegistrationCert(t *testing.T) {
	ctx := context.Background()
	valid := signedWRPRC(t, nil)

	if got := AuthenticateRegistrationCert(ctx, valid, registrar(true, nil, nil)); got != AuthVerified {
		t.Errorf("valid signature by a trusted registrar = %v, want AuthVerified", got)
	}
	if got := AuthenticateRegistrationCert(ctx, valid, registrar(false, nil, nil)); got != AuthUntrustedRegistrar {
		t.Errorf("registrar denied = %v, want AuthUntrustedRegistrar", got)
	}
	if got := AuthenticateRegistrationCert(ctx, valid, registrar(true, errors.New("pdp down"), nil)); got != AuthUnchecked {
		t.Errorf("registrar evaluation error = %v, want AuthUnchecked (never a pass)", got)
	}
	if got := AuthenticateRegistrationCert(ctx, valid, nil); got != AuthUnchecked {
		t.Errorf("no trust path = %v, want AuthUnchecked", got)
	}
}

// A payload swapped under an authentic header must not pass: this is the
// attack the unauthenticated parse allowed. The registrar must not even be
// asked about a document whose signature does not hold.
func TestAuthenticateRegistrationCertRejectsATamperedPayload(t *testing.T) {
	valid := signedWRPRC(t, nil)
	parts := strings.Split(valid, ".")
	forged := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"x","provides_attestations":[{"format":"dc+sd-jwt"}]}`))
	tampered := parts[0] + "." + forged + "." + parts[2]

	called := false
	if got := AuthenticateRegistrationCert(context.Background(), tampered, registrar(true, nil, &called)); got != AuthUnchecked {
		t.Errorf("tampered payload = %v, want AuthUnchecked", got)
	}
	if called {
		t.Error("the registrar was consulted about a document with a bad signature")
	}
}

func TestAuthenticateRegistrationCertRejectsWrongTypeAndMissingChain(t *testing.T) {
	ctx := context.Background()
	wrongTyp := signedWRPRC(t, func(_ jwt.MapClaims, h map[string]any) { h["typ"] = "JWT" })
	if got := AuthenticateRegistrationCert(ctx, wrongTyp, registrar(true, nil, nil)); got != AuthUnchecked {
		t.Errorf("wrong typ = %v, want AuthUnchecked", got)
	}
	noChain := signedWRPRC(t, func(_ jwt.MapClaims, h map[string]any) { delete(h, "x5c") })
	if got := AuthenticateRegistrationCert(ctx, noChain, registrar(true, nil, nil)); got != AuthUnchecked {
		t.Errorf("no x5c = %v, want AuthUnchecked", got)
	}
	if got := AuthenticateRegistrationCert(ctx, "not.a.jwt", registrar(true, nil, nil)); got != AuthUnchecked {
		t.Errorf("garbage = %v, want AuthUnchecked", got)
	}
}

// The wiring that matters: claims of a document nobody authenticated are not
// read, so a provider cannot register itself for what it likes.
func TestEvaluateIgnoresClaimsOfAnUnauthenticatedRegistrationCert(t *testing.T) {
	for _, tc := range []struct {
		name string
		auth AuthResult
		want Code
	}{
		{"unchecked", AuthUnchecked, CodeRegistrationUnverified},
		{"untrusted registrar", AuthUntrustedRegistrar, CodeRegistrarNotTrusted},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := input(t, defaultWRPRC(), pidOffer) // would be a perfect pass if believed
			in.RegistrationAuth = tc.auth
			d := Evaluate(in, ModeFail)
			if d.Allowed {
				t.Fatal("claims of an unauthenticated registration certificate were believed in fail mode")
			}
			if !hasCode(d, tc.want) {
				t.Errorf("findings %v lack %s", codes(d), tc.want)
			}
			if d.Evaluated || len(d.Entitlements) != 0 || d.Subject != "" {
				t.Errorf("claims leaked into the decision: %+v", d)
			}
		})
	}
}

// Input.RegistrationAuth defaults to unchecked, so a caller that never wires
// the check fails closed rather than open.
func TestEvaluateZeroValueAuthFailsClosed(t *testing.T) {
	in := input(t, defaultWRPRC(), pidOffer)
	in.RegistrationAuth = 0
	if d := Evaluate(in, ModeFail); d.Allowed {
		t.Fatal("zero-value RegistrationAuth passed")
	}
}

func TestDecisionIsBoundedAndCarriesNoIssuerText(t *testing.T) {
	longType := "urn:" + strings.Repeat("x", 500) + "\n\x00evil"
	var offers []Offer
	for i := 0; i < 100; i++ {
		offers = append(offers, Offer{Format: "dc+sd-jwt", Type: longType})
	}
	d := Evaluate(input(t, defaultWRPRC(), offers...), ModeFail)

	if d.Allowed {
		t.Error("truncating findings must not allow issuance")
	}
	if len(d.Findings) != MaxFindings || !d.FindingsTruncated {
		t.Errorf("findings = %d truncated = %v, want %d and true", len(d.Findings), d.FindingsTruncated, MaxFindings)
	}
	for _, f := range d.Findings {
		if len(f.CredentialType) > MaxCredentialTypeLen || strings.ContainsAny(f.CredentialType, "\n\x00") {
			t.Errorf("credential_type not bounded/sanitised: %q", f.CredentialType)
		}
		if strings.Contains(f.Message, "xxx") || strings.Contains(f.Message, "urn:") {
			t.Errorf("message echoes issuer text: %q", f.Message)
		}
	}
}

func TestSummaryDropsRegistrationCertificateContent(t *testing.T) {
	d := Evaluate(input(t, defaultWRPRC(), pidOffer), ModeWarn)
	if len(d.Entitlements) == 0 || d.Subject == "" {
		t.Fatal("precondition: decision should carry display data")
	}
	s := d.Summary()
	if len(s.Entitlements) != 0 || s.Subject != "" {
		t.Errorf("summary still carries certificate content: %+v", s)
	}
	if len(d.Entitlements) == 0 {
		t.Error("Summary mutated the original decision")
	}
}
