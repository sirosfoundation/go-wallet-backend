package service

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"math/big"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/golang-jwt/jwt/v5"
)

// testAppleCA stands in for the Apple App Attestation Root CA: a root and one
// intermediate, injected into the verifier as its root pool.
type testAppleCA struct {
	pool    *x509.CertPool
	interK  *ecdsa.PrivateKey
	interC  *x509.Certificate
	interDR []byte
}

func newTestAppleCA(t *testing.T) *testAppleCA {
	t.Helper()
	rootK, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootT := &x509.Certificate{
		SerialNumber: big.NewInt(100), Subject: pkix.Name{CommonName: "Test App Attestation Root"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootT, rootT, &rootK.PublicKey, rootK)
	if err != nil {
		t.Fatal(err)
	}
	rootC, _ := x509.ParseCertificate(rootDER)
	interK, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	interT := &x509.Certificate{
		SerialNumber: big.NewInt(101), Subject: pkix.Name{CommonName: "Test App Attestation CA 1"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(12 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	interDER, err := x509.CreateCertificate(rand.Reader, interT, rootC, &interK.PublicKey, rootK)
	if err != nil {
		t.Fatal(err)
	}
	interC, _ := x509.ParseCertificate(interDER)
	pool := x509.NewCertPool()
	pool.AddCert(rootC)
	return &testAppleCA{pool: pool, interK: interK, interC: interC, interDR: interDER}
}

// testAppAttestDevice is a synthetic App Attest key.
type testAppAttestDevice struct {
	key   *ecdsa.PrivateKey
	keyID []byte // SHA-256 of the X9.62 uncompressed public key
}

func newTestAppAttestDevice(t *testing.T) *testAppAttestDevice {
	t.Helper()
	return newTestAppAttestDeviceOnCurve(t, elliptic.P256())
}

func newTestAppAttestDeviceOnCurve(t *testing.T, c elliptic.Curve) *testAppAttestDevice {
	t.Helper()
	k, err := ecdsa.GenerateKey(c, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := k.PublicKey.ECDH()
	id := sha256.Sum256(pub.Bytes())
	return &testAppAttestDevice{key: k, keyID: id[:]}
}

func (d *testAppAttestDevice) keyIDB64() string { return base64.StdEncoding.EncodeToString(d.keyID) }

var (
	testAAGUIDProd = [16]byte{'a', 'p', 'p', 'a', 't', 't', 'e', 's', 't'}
	testAAGUIDDev  = [16]byte{'a', 'p', 'p', 'a', 't', 't', 'e', 's', 't', 'd', 'e', 'v', 'e', 'l', 'o', 'p'}
)

// attOpts selects how a synthetic attestation deviates from a valid one.
type attOpts struct {
	appID         string   // rpIdHash is SHA-256 of this
	aaguid        [16]byte // zero value means production
	counter       uint32
	credID        []byte // nil = the device key id
	flags         byte   // 0 = 0x40
	nonceFor      string // challenge the nonce is computed for ("" = the challenge)
	unknownRoot   bool   // chain from a CA the verifier does not trust
	shortCredID   bool   // truncate the credential id to 31 bytes
	truncateAuth  int    // when > 0, authData is cut to this length
	skipNonceExt  bool
	wrongNonceExt []byte
	credLen       uint16 // when non-zero, the credentialIdLength field is this regardless of the real length
	receiptPad    int    // extra receipt bytes, to build an otherwise valid but oversize object
}

// attestation builds a base64 App Attest attestation object for challenge.
func (d *testAppAttestDevice) attestation(t *testing.T, ca *testAppleCA, challenge string, o attOpts) string {
	t.Helper()
	if o.aaguid == ([16]byte{}) {
		o.aaguid = testAAGUIDProd
	}
	credID := o.credID
	if credID == nil {
		credID = d.keyID
	}
	if o.shortCredID {
		credID = credID[:31]
	}
	flags := o.flags
	if flags == 0 {
		flags = 0x40
	}
	rp := sha256.Sum256([]byte(o.appID))
	authData := append([]byte{}, rp[:]...)
	authData = append(authData, flags)
	authData = binary.BigEndian.AppendUint32(authData, o.counter)
	authData = append(authData, o.aaguid[:]...)
	credLen := uint16(len(credID))
	if o.credLen != 0 {
		credLen = o.credLen
	}
	authData = binary.BigEndian.AppendUint16(authData, credLen)
	authData = append(authData, credID...)
	pub, _ := d.key.PublicKey.ECDH()
	xy := pub.Bytes()
	cose, err := cbor.Marshal(map[int]any{1: 2, 3: -7, -1: 1, -2: xy[1 : 1+(len(xy)-1)/2], -3: xy[1+(len(xy)-1)/2:]})
	if err != nil {
		t.Fatal(err)
	}
	authData = append(authData, cose...)
	if o.truncateAuth > 0 {
		authData = authData[:o.truncateAuth]
	}

	nf := o.nonceFor
	if nf == "" {
		nf = challenge
	}
	cdh := sha256.Sum256([]byte(nf))
	nonce := sha256.Sum256(append(append([]byte{}, authData...), cdh[:]...))
	nonceBytes := nonce[:]
	if o.wrongNonceExt != nil {
		nonceBytes = o.wrongNonceExt
	}

	issuerK, issuerC := ca.interK, ca.interC
	interDER := ca.interDR
	if o.unknownRoot {
		other := newTestAppleCA(t)
		issuerK, issuerC, interDER = other.interK, other.interC, other.interDR
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "credCert"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
	}
	if !o.skipNonceExt {
		tmpl.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 8, 2}, Value: buildAppAttestNonceExtension(nonceBytes)}}
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, tmpl, issuerC, &d.key.PublicKey, issuerK)
	if err != nil {
		t.Fatal(err)
	}
	obj := appleAppAttestAttestation{
		Fmt:      "apple-appattest",
		AttStmt:  appleAppAttestAttestStatement{X5C: [][]byte{leafDER, interDER}, Receipt: append([]byte("receipt"), make([]byte, o.receiptPad)...)},
		AuthData: authData,
	}
	b, err := cbor.Marshal(obj)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(b)
}

// assertionOpts selects how a synthetic assertion deviates from a valid one.
type assertionOpts struct {
	appID    string
	counter  uint32
	signOver []byte // client data hash the signature is computed over; nil = the real one
	badSig   bool
	flags    byte
}

// assertion builds a base64 App Attest assertion (CBOR {signature,
// authenticatorData}) over clientDataHash.
func (d *testAppAttestDevice) assertion(t *testing.T, clientDataHash []byte, o assertionOpts) string {
	t.Helper()
	rp := sha256.Sum256([]byte(o.appID))
	authData := append([]byte{}, rp[:]...)
	authData = append(authData, o.flags)
	authData = binary.BigEndian.AppendUint32(authData, o.counter)
	signed := clientDataHash
	if o.signOver != nil {
		signed = o.signOver
	}
	nonce := sha256.Sum256(append(append([]byte{}, authData...), signed...))
	// ECDSA-with-SHA-256 over the nonce: the signed digest is SHA-256(nonce).
	digest := sha256.Sum256(nonce[:])
	sig, err := ecdsa.SignASN1(rand.Reader, d.key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	if o.badSig {
		sig[len(sig)-1] ^= 0xff
	}
	b, err := cbor.Marshal(map[string]any{"signature": sig, "authenticatorData": authData})
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(b)
}

func sha256Of(s string) []byte {
	h := sha256.Sum256([]byte(s))
	return h[:]
}

// cborMarshalAssertion encodes an assertion object with an arbitrary
// signature and authenticatorData.
func cborMarshalAssertion(sig, authData []byte) (string, error) {
	b, err := cbor.Marshal(map[string]any{"signature": sig, "authenticatorData": authData})
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

// resignPop builds a WIA-PoP JWT for an existing instance key and nonce (a
// renewal with the same key).
func resignPop(t *testing.T, key *ecdsa.PrivateKey, nonce string) string {
	t.Helper()
	claims := &WIAPopClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "urn:wallet:instance:test-123",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
		Nonce: nonce,
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	tok.Header["typ"] = "oauth-client-attestation-pop+jwt"
	tok.Header["jwk"] = map[string]interface{}{
		"kty": "EC", "crv": "P-256",
		"x": base64.RawURLEncoding.EncodeToString(key.PublicKey.X.FillBytes(make([]byte, 32))),
		"y": base64.RawURLEncoding.EncodeToString(key.PublicKey.Y.FillBytes(make([]byte, 32))),
	}
	s, err := tok.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}
