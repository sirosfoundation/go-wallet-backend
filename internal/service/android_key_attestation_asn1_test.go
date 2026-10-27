package service

import (
	"math/rand"
	"strings"
	"testing"
)

func validKDForParser() []byte {
	return encodeKeyDescription(goodParams(InstanceKeyAttestationChallenge("c")))
}

func TestParseAndroidKeyDescription_Fields(t *testing.T) {
	kd, err := parseAndroidKeyDescription(validKDForParser())
	if err != nil {
		t.Fatal(err)
	}
	if kd.AttestationVersion != 4 || kd.AttestationSecurityLevel != androidLevelTrustedEnvironment || kd.KeymasterSecurityLevel != androidLevelTrustedEnvironment {
		t.Fatalf("kd = %+v", kd)
	}
	tee := kd.TEE
	if *tee.Origin != androidOriginGenerated || !tee.hasPurpose(androidPurposeSign) || *tee.Algorithm != androidAlgorithmEC || *tee.EcCurve != androidCurveP256 || *tee.OsPatchLevel != 20241005 {
		t.Fatalf("tee = %+v", tee)
	}
	if tee.RootOfTrust == nil || !tee.RootOfTrust.DeviceLocked || tee.RootOfTrust.VerifiedBootState != 0 {
		t.Fatalf("rot = %+v", tee.RootOfTrust)
	}
	app := kd.Software.AppID
	if app == nil || len(app.Packages) != 1 || app.Packages[0] != testAppPackage || len(app.SignatureDigest) != 1 {
		t.Fatalf("app = %+v", app)
	}
}

// Hostile input never panics and never reports success for a structurally
// broken description: every single-byte mutation and every truncation of a
// valid one, plus random garbage, is parsed.
func TestParseAndroidKeyDescription_NoPanicOnHostileInput(t *testing.T) {
	valid := validKDForParser()
	for i := range valid {
		for _, delta := range []byte{0x01, 0x80, 0xff} {
			m := append([]byte(nil), valid...)
			m[i] ^= delta
			_, _ = parseAndroidKeyDescription(m)
		}
	}
	for i := 0; i < len(valid); i++ {
		if _, err := parseAndroidKeyDescription(valid[:i]); err == nil {
			t.Fatalf("truncation at %d parsed", i)
		}
	}
	rng := rand.New(rand.NewSource(1))
	for i := 0; i < 20000; i++ {
		b := make([]byte, rng.Intn(300))
		rng.Read(b)
		_, _ = parseAndroidKeyDescription(b)
	}
	// Deeply nested and huge-length encodings.
	_, _ = parseAndroidKeyDescription([]byte{0x30, 0x84, 0xff, 0xff, 0xff, 0xff})
	deep := []byte{0x05, 0x00}
	for i := 0; i < 5000; i++ {
		deep = seq(deep)
	}
	_, _ = parseAndroidKeyDescription(deep)
	// More members than the element bound.
	many := make([]byte, 0, 4*maxASN1Elements)
	for i := 0; i < maxASN1Elements+10; i++ {
		many = append(many, integer(i%100)...)
	}
	if _, err := parseAndroidKeyDescription(seq(many)); err == nil {
		t.Fatal("over-long sequence parsed")
	}
}

func FuzzParseAndroidKeyDescription(f *testing.F) {
	f.Add(validKDForParser())
	f.Add([]byte{})
	f.Add([]byte{0x30, 0x00})
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = parseAndroidKeyDescription(data)
	})
}

func TestParseAppID_Bounds(t *testing.T) {
	var pk [][]byte
	for i := 0; i < maxAppIDEntries+1; i++ {
		pk = append(pk, []byte("p"))
	}
	var pkgs []string
	for range pk {
		pkgs = append(pkgs, "p")
	}
	if _, err := parseAppID(appIDDER(pkgs, [][]byte{{1}})); err == nil {
		t.Fatal("too many packages accepted")
	}
	if _, err := parseAppID(appIDDER([]string{"p"}, [][]byte{{1}})); err != nil {
		t.Fatal(err)
	}
}

func TestParseAndroidKeyDescription_Bounds(t *testing.T) {
	// A structurally valid description over the size bound is refused for its size.
	kd := goodParams(nil)
	kd.ExtraSoftware = [][]byte{explicit(9999, octets(make([]byte, maxKeyDescriptionBytes)))}
	if _, err := parseAndroidKeyDescription(encodeKeyDescription(kd)); err == nil || !strings.Contains(err.Error(), "out of bounds") {
		t.Fatalf("oversized description: %v", err)
	}
	// The member bound holds on its own, whatever the members are.
	var members []byte
	for i := 0; i < maxASN1Elements+1; i++ {
		members = append(members, integer(1)...)
	}
	if _, err := asn1Elements(members); err == nil {
		t.Fatal("over-long element list accepted")
	}
	if els, err := asn1Elements(members[:len(members)-3]); err != nil || len(els) != maxASN1Elements {
		t.Fatalf("els=%d err=%v", len(els), err)
	}
}
