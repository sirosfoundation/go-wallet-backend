package issuertrust

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/url"
	"testing"
	"time"
)

// oidOrganizationIdentifier is EN 319 412-3's attribute for a legal person's
// identifier. The WRPAC profile reads it to bind against the WRPRC.
var oidOrganizationIdentifier = asn1.ObjectIdentifier{2, 5, 4, 97}

// policyNCPLegalPerson is one of the four TS 119 411-8 WRPAC policy OIDs.
const policyNCPLegalPerson = "0.4.0.194118.1.2"

const testIdentifier = "LEIXG-529900T8BM49AURSDO55"

// wrpac builds a certificate that satisfies the WRPAC profile: a policy OID,
// nonRepudiation, a subjectAltName contact, and the identifier where
// EN 319 412-3 puts it.
func wrpac(t *testing.T, identifier string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	oid, err := x509.ParseOID(policyNCPLegalPerson)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse("https://issuer.test/support")
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Test Provider",
			Organization: []string{"Test Provider AB"},
			Country:      []string{"SE"},
			ExtraNames: []pkix.AttributeTypeAndValue{
				{Type: oidOrganizationIdentifier, Value: identifier},
			},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageContentCommitment | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		Policies:              []x509.OID{oid},
		URIs:                  []*url.URL{u},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// plainCert is a certificate with none of the WRPAC profile's requirements —
// what a document-signing certificate would look like if one were substituted.
func plainCert(t *testing.T) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "Document Signer"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// wrprcOpts shapes the registration certificate a test wants.
type wrprcOpts struct {
	subject      string
	entitlements []string
	provides     []map[string]any
	iat          int64
	exp          int64
}

func defaultWRPRC() wrprcOpts {
	now := time.Now().UTC().Unix()
	return wrprcOpts{
		subject:      testIdentifier,
		entitlements: []string{"https://uri.etsi.org/19475/Entitlement/PID_Provider"},
		provides: []map[string]any{
			{"format": "dc+sd-jwt", "meta": map[string]any{"vct_values": []string{"urn:eudi:pid:1"}}},
		},
		iat: now,
		exp: now + 3600,
	}
}

// wrprc builds a compact rc-wrp+jwt. The signature is not verified by this
// package — the resolver checks the metadata JWS, and go-trust parses claims —
// so the test only needs a well-formed token, and using a real one would
// misrepresent where the signature check happens.
func wrprc(t *testing.T, o wrprcOpts) string {
	t.Helper()
	header := map[string]any{"typ": "rc-wrp+jwt", "alg": "ES256"}
	payload := map[string]any{
		"name":         "Test Provider",
		"sub":          o.subject,
		"entitlements": o.entitlements,
		"iat":          o.iat,
		"exp":          o.exp,
	}
	if o.provides != nil {
		payload["provides_attestations"] = o.provides
	}
	enc := base64.RawURLEncoding
	h, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	p, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	sig := sha256.Sum256(append(h, p...))
	return enc.EncodeToString(h) + "." + enc.EncodeToString(p) + "." + enc.EncodeToString(sig[:])
}

// findings reduces a decision to its codes, so assertions read as intent.
func codes(d *Decision) []Code {
	out := make([]Code, 0, len(d.Findings))
	for _, f := range d.Findings {
		out = append(out, f.Code)
	}
	return out
}

func hasCode(d *Decision, c Code) bool {
	for _, got := range codes(d) {
		if got == c {
			return true
		}
	}
	return false
}
