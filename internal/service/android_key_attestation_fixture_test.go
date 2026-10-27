package service

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"os"
	"testing"
	"time"
)

// This file builds SYNTHETIC Android attestation chains for tests: a test root,
// an intermediate and a leaf whose KeyDescription extension is encoded by hand
// from the schema at
// https://source.android.com/docs/security/features/keystore/attestation#schema
// No real Google chain is involved; real ones go in testdata/android (see
// TestAndroidKeyAttestation_RealPixelChains).

func intp(v int) *int { return &v }

// kdParams describes a KeyDescription. Zero values are a valid StrongBox/TEE
// attestation of a generated signing key; tests mutate single fields.
type kdParams struct {
	Version  int
	AttLevel int
	KmLevel  int
	// Challenge is attestationChallenge.
	Challenge []byte

	// TEE (hardware enforced) list.
	Origin        *int // nil: omit
	Purposes      []int
	Algorithm     *int
	Curve         *int
	NoRootOfTrust bool
	BootState     int
	Locked        bool
	Patch         *int

	// Where the app id lives: software list (default) or the TEE list.
	AppIDInTEE bool
	NoAppID    bool
	Packages   []string
	Digests    [][]byte

	// ExtraSoftware / ExtraTEE are raw extra authorization-list members.
	ExtraSoftware [][]byte
	ExtraTEE      [][]byte

	// DuplicateOrigin emits the origin member twice.
	DuplicateOrigin bool
}

func rv(class, tag int, compound bool, content []byte) []byte {
	b, err := asn1.Marshal(asn1.RawValue{Class: class, Tag: tag, IsCompound: compound, Bytes: content})
	if err != nil {
		panic(err)
	}
	return b
}

func mustMarshal(v any, params ...string) []byte {
	var b []byte
	var err error
	if len(params) > 0 {
		b, err = asn1.MarshalWithParams(v, params[0])
	} else {
		b, err = asn1.Marshal(v)
	}
	if err != nil {
		panic(err)
	}
	return b
}

func cat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func seq(parts ...[]byte) []byte {
	return rv(asn1.ClassUniversal, asn1.TagSequence, true, cat(parts...))
}

func derSet(parts ...[]byte) []byte { return rv(asn1.ClassUniversal, asn1.TagSet, true, cat(parts...)) }
func octets(b []byte) []byte        { return mustMarshal(b) }
func integer(i int) []byte          { return mustMarshal(i) }
func enum(i int) []byte             { return mustMarshal(asn1.Enumerated(i)) }

// explicit encodes [tag] EXPLICIT inner.
func explicit(tag int, inner []byte) []byte {
	return rv(asn1.ClassContextSpecific, tag, true, inner)
}

func appIDDER(packages []string, digests [][]byte) []byte {
	var pk []byte
	for _, p := range packages {
		pk = append(pk, seq(octets([]byte(p)), integer(1))...)
	}
	var dg []byte
	for _, d := range digests {
		dg = append(dg, octets(d)...)
	}
	return seq(derSet(pk), derSet(dg))
}

func encodeKeyDescription(p kdParams) []byte {
	if p.Version == 0 {
		p.Version = 4
	}
	if p.AttLevel == 0 && p.KmLevel == 0 {
		p.AttLevel, p.KmLevel = androidLevelTrustedEnvironment, androidLevelTrustedEnvironment
	}
	var tee [][]byte
	if p.Purposes != nil {
		var ps []byte
		for _, v := range p.Purposes {
			ps = append(ps, integer(v)...)
		}
		tee = append(tee, explicit(akTagPurpose, derSet(ps)))
	}
	if p.Algorithm != nil {
		tee = append(tee, explicit(akTagAlgorithm, integer(*p.Algorithm)))
	}
	if p.Curve != nil {
		tee = append(tee, explicit(akTagEcCurve, integer(*p.Curve)))
	}
	if p.Origin != nil {
		tee = append(tee, explicit(akTagOrigin, integer(*p.Origin)))
		if p.DuplicateOrigin {
			tee = append(tee, explicit(akTagOrigin, integer(*p.Origin)))
		}
	}
	if !p.NoRootOfTrust {
		tee = append(tee, explicit(akTagRootOfTrust, seq(
			octets(make([]byte, 32)), mustMarshal(p.Locked), enum(p.BootState), octets(make([]byte, 32)))))
	}
	if p.Patch != nil {
		tee = append(tee, explicit(akTagOsPatchLevel, integer(*p.Patch)))
	}
	app := explicit(akTagAppID, octets(appIDDER(p.Packages, p.Digests)))
	sw := p.ExtraSoftware
	if !p.NoAppID {
		if p.AppIDInTEE {
			tee = append(tee, app)
		} else {
			sw = append(sw, app)
		}
	}
	tee = append(tee, p.ExtraTEE...)
	return seq(
		integer(p.Version), enum(p.AttLevel), integer(p.Version), enum(p.KmLevel),
		octets(p.Challenge), octets(nil),
		seq(sw...), seq(tee...),
	)
}

// goodParams is a hardware-backed, generated, signing P-256 key of the test app.
func goodParams(challenge []byte) kdParams {
	return kdParams{
		AttLevel: androidLevelTrustedEnvironment, KmLevel: androidLevelTrustedEnvironment,
		Challenge: challenge,
		Origin:    intp(androidOriginGenerated),
		Purposes:  []int{androidPurposeSign},
		Algorithm: intp(androidAlgorithmEC),
		Curve:     intp(androidCurveP256),
		BootState: 0, Locked: true, Patch: intp(20241005),
		Packages: []string{testAppPackage},
		Digests:  [][]byte{testAppDigest[:]},
	}
}

const testAppPackage = "org.siros.wallet"

var testAppDigest = sha256.Sum256([]byte("siros wallet signing certificate"))

func testAppDigestHex() string { return hex.EncodeToString(testAppDigest[:]) }

// chainFixture is a test PKI: root -> intermediate -> (leaf per call).
type chainFixture struct {
	t        *testing.T
	rootKey  *ecdsa.PrivateKey
	root     *x509.Certificate
	rootDER  []byte
	intKey   *ecdsa.PrivateKey
	inter    *x509.Certificate
	interDER []byte
	serial   int64
}

func newChainFixture(t *testing.T) *chainFixture {
	t.Helper()
	f := &chainFixture{t: t, serial: 1000}
	f.rootKey = genKey(t)
	f.root, f.rootDER = f.sign(&x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test Attestation Root"},
		NotBefore: time.Now().Add(-48 * time.Hour), NotAfter: time.Now().Add(48 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}, &f.rootKey.PublicKey, nil, f.rootKey)
	f.intKey = genKey(t)
	f.inter, f.interDER = f.sign(&x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Test Attestation Intermediate"},
		NotBefore: time.Now().Add(-24 * time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}, &f.intKey.PublicKey, f.root, f.rootKey)
	return f
}

func genKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// sign creates a certificate for pub signed by (parent, signer); parent nil
// means self-signed.
func (f *chainFixture) sign(tmpl *x509.Certificate, pub *ecdsa.PublicKey, parent *x509.Certificate, signer *ecdsa.PrivateKey) (*x509.Certificate, []byte) {
	if parent == nil {
		parent = tmpl
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signer)
	if err != nil {
		f.t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		f.t.Fatal(err)
	}
	return c, der
}

// leafOpts shapes the leaf certificate.
type leafOpts struct {
	NotBefore, NotAfter time.Time
	Serial              int64
	// Extension, when set, replaces the attestation extension value.
	Extension []byte
	// NoExtension omits the extension.
	NoExtension bool
	// DuplicateExtension adds the extension twice (via ExtraExtensions only
	// one is honoured by CreateCertificate, so the DER is patched after).
	Parent    *x509.Certificate
	ParentKey *ecdsa.PrivateKey
}

// leaf issues the leaf for pub with the KeyDescription kd and returns the
// DER chain [leaf, intermediate, root].
func (f *chainFixture) leaf(pub *ecdsa.PublicKey, kd []byte, o leafOpts) [][]byte {
	f.t.Helper()
	if o.NotBefore.IsZero() {
		o.NotBefore = time.Now().Add(-time.Hour)
	}
	if o.NotAfter.IsZero() {
		o.NotAfter = time.Now().Add(12 * time.Hour)
	}
	if o.Serial == 0 {
		f.serial++
		o.Serial = f.serial
	}
	parent, parentKey := f.inter, f.intKey
	if o.Parent != nil {
		parent, parentKey = o.Parent, o.ParentKey
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(o.Serial), Subject: pkix.Name{CommonName: "Android Keystore Key"},
		NotBefore: o.NotBefore, NotAfter: o.NotAfter,
		KeyUsage: x509.KeyUsageDigitalSignature,
	}
	if !o.NoExtension {
		val := kd
		if o.Extension != nil {
			val = o.Extension
		}
		tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, pkix.Extension{Id: oidAndroidKeyDescription, Value: val})
	}
	_, der := f.sign(tmpl, pub, parent, parentKey)
	return [][]byte{der, f.interDER, f.rootDER}
}

func b64chain(chain [][]byte) []string {
	out := make([]string, len(chain))
	for i, d := range chain {
		out[i] = base64.StdEncoding.EncodeToString(d)
	}
	return out
}

func (f *chainFixture) rootPEM() string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.rootDER}))
}

func writeFile(path, content string) error { return os.WriteFile(path, []byte(content), 0o600) }

// duplicateExtension returns the DER of cert with its attestation extension
// repeated, re-signing is not needed: the certificate only has to parse (or
// not) and the signature check runs on the original TBS, so the verifier sees
// either a parse failure or a link failure. Both are "invalid".
func duplicateExtension(t *testing.T, certDER, kd []byte) []byte {
	t.Helper()
	ext, err := asn1.Marshal(struct {
		ID    asn1.ObjectIdentifier
		Value []byte
	}{oidAndroidKeyDescription, kd})
	if err != nil {
		t.Fatal(err)
	}
	i := bytes.Index(certDER, ext)
	if i < 0 {
		t.Fatal("extension not found in certificate")
	}
	// Insert a second copy right after the first and fix up the enclosing
	// lengths by re-encoding the SEQUENCEs on the path: simplest is to rebuild
	// the Extensions list via asn1.RawValue walking.
	var cert asn1.RawValue
	if _, err := asn1.Unmarshal(certDER, &cert); err != nil {
		t.Fatal(err)
	}
	parts, _ := asn1Elements(cert.Bytes) // tbs, sigalg, sig
	tbs, _ := asn1Elements(parts[0].Bytes)
	var rebuilt []byte
	for _, f := range tbs {
		if f.Class == asn1.ClassContextSpecific && f.Tag == 3 { // [3] extensions
			inner, _ := asn1Single(f.Bytes)
			exts, _ := asn1Elements(inner.Bytes)
			var all []byte
			for _, e := range exts {
				all = append(all, e.FullBytes...)
				if bytes.Contains(e.FullBytes, ext) {
					all = append(all, e.FullBytes...)
				}
			}
			rebuilt = append(rebuilt, rv(asn1.ClassContextSpecific, 3, true, seq(all))...)
			continue
		}
		rebuilt = append(rebuilt, f.FullBytes...)
	}
	return seq(seq(rebuilt), parts[1].FullBytes, parts[2].FullBytes)
}
