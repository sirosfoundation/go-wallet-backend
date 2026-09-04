package issuertrust_test

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"strings"
	"testing"

	"github.com/sirosfoundation/go-wallet-backend/pkg/issuertrust"
)

// TestWrpacToolOutputSatisfiesIssuerTrust feeds real siros-wrpac-tool output
// into this package's evaluation. The two halves were written against the same
// standards but never against each other, and agreeing with a standard
// separately is not the same as interoperating.
//
// Skipped unless ISSUED_DIR points at a siros-wrpac-tool `apply` output
// directory, because the alternative - committing a real WRPAC and WRPRC as
// fixtures - would bake in certificates that expire and fail CI on a date
// nobody chose. Run it after regenerating a deployment:
//
//	ISSUED_DIR=.../fixtures/wrpac-clients/vc-issuer.issued go test ./pkg/issuertrust/ -run Wrpac -v
func TestWrpacToolOutputSatisfiesIssuerTrust(t *testing.T) {
	dir := os.Getenv("ISSUED_DIR")
	if dir == "" {
		t.Skip("set ISSUED_DIR to a siros-wrpac-tool apply output directory")
	}
	pemBytes, err := os.ReadFile(dir + "/wrpac.pem")
	if err != nil {
		t.Fatal(err)
	}
	jwt, err := os.ReadFile(dir + "/wrprc.jwt")
	if err != nil {
		t.Fatal(err)
	}
	// A file written by a shell redirect or an editor carries a trailing
	// newline; a compact JWS with one is not a compact JWS.
	registrationCert := strings.TrimSpace(string(jwt))

	var chain []*x509.Certificate
	rest := pemBytes
	for {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		if blk.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		chain = append(chain, c)
	}
	if len(chain) == 0 {
		t.Fatal("no certificates in wrpac.pem")
	}
	t.Logf("chain of %d, leaf subject %s", len(chain), chain[0].Subject)

	d := issuertrust.Evaluate(issuertrust.Input{
		Chain:            chain,
		RegistrationCert: registrationCert,
		Offers: []issuertrust.Offer{
			{Format: "dc+sd-jwt", Type: "urn:eudi:pid:1"},
			{Format: "mso_mdoc", Type: "eu.europa.ec.eudi.pid.1"},
		},
	}, issuertrust.ModeFail)

	t.Logf("allowed=%v evaluated=%v subject=%q entitlements=%v", d.Allowed, d.Evaluated, d.Subject, d.Entitlements)
	for _, f := range d.Findings {
		t.Logf("  finding %s: %s", f.Code, f.Message)
	}
	if !d.Evaluated {
		t.Error("decision was not evaluated - the registration certificate was not usable")
	}
	if !d.Allowed {
		t.Error("real wrpac-tool output was refused by the backend's own check")
	}

	// And the negative: something it did not register for must be refused.
	d2 := issuertrust.Evaluate(issuertrust.Input{
		Chain:            chain,
		RegistrationCert: registrationCert,
		Offers:           []issuertrust.Offer{{Format: "dc+sd-jwt", Type: "urn:example:unregistered"}},
	}, issuertrust.ModeFail)
	if d2.Allowed {
		t.Error("an unregistered attestation type was allowed")
	} else {
		t.Logf("unregistered type correctly refused: %v", d2.Findings)
	}
}
