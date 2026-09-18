package issuertrust

import (
	"crypto/x509"
	"testing"
	"time"
)

func input(t *testing.T, o wrprcOpts, offers ...Offer) Input {
	t.Helper()
	return Input{
		Chain:            []*x509.Certificate{wrpac(t, testIdentifier)},
		RegistrationCert: wrprc(t, o),
		Offers:           offers,
	}
}

var pidOffer = Offer{Format: "dc+sd-jwt", Type: "urn:eudi:pid:1"}

func TestAllowsARegisteredProvider(t *testing.T) {
	d := Evaluate(input(t, defaultWRPRC(), pidOffer), ModeFail)
	if !d.Allowed {
		t.Fatalf("a registered provider was refused: %v", codes(d))
	}
	if !d.Evaluated {
		t.Error("Evaluated should be true when a registration certificate was read")
	}
	if d.Subject != testIdentifier {
		t.Errorf("Subject = %q, want the registered identifier", d.Subject)
	}
	if len(d.Findings) != 0 {
		t.Errorf("unexpected findings: %v", codes(d))
	}
}

// The offered type must appear in provides_attestations. This is the check the
// whole track exists for: a provider registered for PIDs must not quietly issue
// diplomas.
func TestRefusesAnUnregisteredAttestationType(t *testing.T) {
	d := Evaluate(input(t, defaultWRPRC(), Offer{Format: "dc+sd-jwt", Type: "urn:eudi:diploma:1"}), ModeFail)
	if d.Allowed {
		t.Fatal("an unregistered attestation type was allowed")
	}
	if !hasCode(d, CodeTypeNotRegistered) {
		t.Errorf("codes = %v, want %s", codes(d), CodeTypeNotRegistered)
	}
}

func TestRefusesAWrongFormatForARegisteredType(t *testing.T) {
	d := Evaluate(input(t, defaultWRPRC(), Offer{Format: "mso_mdoc", Type: "urn:eudi:pid:1"}), ModeFail)
	if d.Allowed {
		t.Fatal("a format the provider did not register was allowed")
	}
}

func TestRefusesAPartyWithNoProviderEntitlement(t *testing.T) {
	o := defaultWRPRC()
	o.entitlements = []string{"https://uri.etsi.org/19475/Entitlement/Service_Provider"}
	o.provides = nil

	d := Evaluate(input(t, o, pidOffer), ModeFail)
	if d.Allowed {
		t.Fatal("a plain service provider was allowed to issue")
	}
	if !hasCode(d, CodeNotProvider) {
		t.Errorf("codes = %v, want %s", codes(d), CodeNotProvider)
	}
}

// A genuine registration certificate belonging to somebody else must not pass.
func TestRefusesARegistrationCertificateForAnotherParty(t *testing.T) {
	o := defaultWRPRC()
	o.subject = "LEIXG-SOMEONEELSE0000000000"

	d := Evaluate(input(t, o, pidOffer), ModeFail)
	if d.Allowed {
		t.Fatal("a registration certificate for another party was accepted")
	}
	if !hasCode(d, CodeBindingMismatch) {
		t.Errorf("codes = %v, want %s", codes(d), CodeBindingMismatch)
	}
}

func TestRefusesAnExpiredRegistrationCertificate(t *testing.T) {
	o := defaultWRPRC()
	past := time.Now().UTC().Add(-48 * time.Hour).Unix()
	o.iat, o.exp = past, past+3600

	d := Evaluate(input(t, o, pidOffer), ModeFail)
	if d.Allowed {
		t.Fatal("an expired registration certificate was accepted")
	}
	if !hasCode(d, CodeRegistrationExpired) {
		t.Errorf("codes = %v, want %s", codes(d), CodeRegistrationExpired)
	}
}

// Signing metadata with something that is not an access certificate must be
// caught, or a document-signing certificate could stand in for a WRPAC.
func TestRefusesAChainThatIsNotAWRPAC(t *testing.T) {
	in := input(t, defaultWRPRC(), pidOffer)
	in.Chain = []*x509.Certificate{plainCert(t)}

	d := Evaluate(in, ModeFail)
	if d.Allowed {
		t.Fatal("a non-WRPAC signing certificate was accepted")
	}
	if !hasCode(d, CodeNotWRPAC) {
		t.Errorf("codes = %v, want %s", codes(d), CodeNotWRPAC)
	}
}

func TestRefusesUnsignedMetadata(t *testing.T) {
	d := Evaluate(Input{Offers: []Offer{pidOffer}}, ModeFail)
	if d.Allowed {
		t.Fatal("metadata with no certificate chain was accepted")
	}
	if !hasCode(d, CodeNoAccessCertificate) {
		t.Errorf("codes = %v, want %s", codes(d), CodeNoAccessCertificate)
	}
}

// "No registration certificate" must be distinguishable from "checked and
// fine". Evaluated stays false so nothing downstream can mistake one for the
// other.
func TestMissingRegistrationCertificateIsNotAPass(t *testing.T) {
	in := input(t, defaultWRPRC(), pidOffer)
	in.RegistrationCert = ""

	d := Evaluate(in, ModeWarn)
	if d.Evaluated {
		t.Error("Evaluated must be false when there was no registration certificate")
	}
	if !hasCode(d, CodeNoRegistrationCert) {
		t.Errorf("codes = %v, want %s", codes(d), CodeNoRegistrationCert)
	}
	if !d.Allowed {
		t.Error("warn mode should still allow issuance")
	}
}

func TestMalformedRegistrationCertificateIsReported(t *testing.T) {
	in := input(t, defaultWRPRC(), pidOffer)
	in.RegistrationCert = "not-a-jwt"

	d := Evaluate(in, ModeFail)
	if d.Allowed {
		t.Fatal("a malformed registration certificate was accepted")
	}
	if !hasCode(d, CodeRegistrationMalformed) {
		t.Errorf("codes = %v, want %s", codes(d), CodeRegistrationMalformed)
	}
}

// Warn mode must report exactly what fail mode would refuse, so turning the
// knob changes the consequence and not the diagnosis.
func TestWarnModeReportsTheSameFindingsItAllows(t *testing.T) {
	bad := input(t, defaultWRPRC(), Offer{Format: "dc+sd-jwt", Type: "urn:eudi:diploma:1"})

	warn := Evaluate(bad, ModeWarn)
	fail := Evaluate(bad, ModeFail)

	if !warn.Allowed {
		t.Error("warn mode must allow")
	}
	if fail.Allowed {
		t.Error("fail mode must refuse")
	}
	if len(warn.Findings) != len(fail.Findings) {
		t.Errorf("warn reported %d findings, fail reported %d — they must agree",
			len(warn.Findings), len(fail.Findings))
	}
}

func TestOffModeSkipsEvaluationEntirely(t *testing.T) {
	d := Evaluate(input(t, defaultWRPRC(), Offer{Format: "dc+sd-jwt", Type: "urn:eudi:diploma:1"}), ModeOff)
	if !d.Allowed || d.Evaluated || len(d.Findings) != 0 {
		t.Errorf("off mode should do nothing: allowed=%v evaluated=%v findings=%v",
			d.Allowed, d.Evaluated, codes(d))
	}
}

// A configuration typo must not silently disable the check.
func TestParseModeDefaultsToWarnNotOff(t *testing.T) {
	for _, in := range []string{"", "nonsense", "Warn", "FAIL"} {
		if got := ParseMode(in); got == ModeOff {
			t.Errorf("ParseMode(%q) = off — a typo must never disable the check", in)
		}
	}
	if ParseMode("off") != ModeOff {
		t.Error(`ParseMode("off") should be off`)
	}
	if ParseMode("fail") != ModeFail {
		t.Error(`ParseMode("fail") should be fail`)
	}
}

func TestMultipleOffersReportOnePerUnregisteredType(t *testing.T) {
	d := Evaluate(input(t, defaultWRPRC(),
		pidOffer,
		Offer{Format: "dc+sd-jwt", Type: "urn:eudi:diploma:1"},
		Offer{Format: "dc+sd-jwt", Type: "urn:eudi:mdl:1"},
	), ModeFail)

	var n int
	for _, f := range d.Findings {
		if f.Code == CodeTypeNotRegistered {
			n++
			if f.CredentialType == "" {
				t.Error("a type finding must name the type it is about")
			}
		}
	}
	if n != 2 {
		t.Errorf("got %d type findings, want 2 (the registered one must not be flagged)", n)
	}
}

// GEN-5.2.4-08 caps validity at twelve months from issuance. That is a
// conformance defect in the document, not the same thing as being expired, and
// the two must report differently or one of them stops being asked.
func TestOverlongValidityIsDistinctFromExpiry(t *testing.T) {
	o := defaultWRPRC()
	o.exp = o.iat + int64((400 * 24 * time.Hour).Seconds())

	d := Evaluate(input(t, o, pidOffer), ModeFail)
	if !hasCode(d, CodeRegistrationOverlong) {
		t.Errorf("codes = %v, want %s", codes(d), CodeRegistrationOverlong)
	}
	if hasCode(d, CodeRegistrationExpired) {
		t.Error("a currently-valid certificate must not also be reported as expired")
	}
}

func TestNotYetValidIsReportedAsExpired(t *testing.T) {
	o := defaultWRPRC()
	future := time.Now().UTC().Add(48 * time.Hour).Unix()
	o.iat, o.exp = future, future+3600

	d := Evaluate(input(t, o, pidOffer), ModeFail)
	if !hasCode(d, CodeRegistrationExpired) {
		t.Errorf("codes = %v, want %s for a not-yet-valid certificate", codes(d), CodeRegistrationExpired)
	}
}
