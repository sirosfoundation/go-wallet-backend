package signing

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/asn1"
	"errors"
	"io"
	"math/big"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

func TestParseASN1Signature_Success(t *testing.T) {
	want := struct {
		R *big.Int
		S *big.Int
	}{R: big.NewInt(12345), S: big.NewInt(67890)}
	der, err := asn1.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}

	r, s, err := parseASN1Signature(der)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.Cmp(want.R) != 0 || s.Cmp(want.S) != 0 {
		t.Errorf("got r=%v s=%v, want r=%v s=%v", r, s, want.R, want.S)
	}
}

func TestParseASN1Signature_MalformedInput(t *testing.T) {
	_, _, err := parseASN1Signature([]byte("not asn.1 data"))
	if err == nil {
		t.Fatal("expected error for malformed input")
	}
}

func TestParseASN1Signature_TrailingData(t *testing.T) {
	seq := struct {
		R *big.Int
		S *big.Int
	}{R: big.NewInt(1), S: big.NewInt(2)}
	der, err := asn1.Marshal(seq)
	if err != nil {
		t.Fatal(err)
	}
	der = append(der, 0xFF, 0xFF) // trailing garbage

	_, _, err = parseASN1Signature(der)
	if err == nil {
		t.Fatal("expected error for trailing data")
	}
}

func TestCryptoSignerES256_SignToken(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	signer, err := NewCryptoSignerES256(key)
	if err != nil {
		t.Fatal(err)
	}

	claims := jwt.MapClaims{
		"sub":  "test-subject",
		"name": "Test",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["typ"] = "test+jwt"

	tokenString, err := signer.SignToken(token)
	if err != nil {
		t.Fatalf("SignToken: %v", err)
	}

	if tokenString == "" {
		t.Fatal("empty token string")
	}

	// Verify the token with the public key
	parsed, err := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
		return &key.PublicKey, nil
	}, jwt.WithValidMethods([]string{"ES256"}))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if !parsed.Valid {
		t.Fatal("token not valid")
	}

	parsedClaims := parsed.Claims.(jwt.MapClaims)
	if parsedClaims["sub"] != "test-subject" {
		t.Errorf("sub = %v, want test-subject", parsedClaims["sub"])
	}
}

func TestCryptoSignerES256_RejectsNonP256(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	_, err := NewCryptoSignerES256(key)
	if err == nil {
		t.Fatal("should reject P-384 key")
	}
}

// nonECDSASigner is a minimal crypto.Signer whose Public() is not
// *ecdsa.PublicKey, to exercise NewCryptoSignerES256's type-assertion
// rejection branch.
type nonECDSASigner struct{}

func (nonECDSASigner) Public() crypto.PublicKey { return "not-an-ecdsa-key" }
func (nonECDSASigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, nil
}

func TestCryptoSignerES256_RejectsNonECDSASigner(t *testing.T) {
	_, err := NewCryptoSignerES256(nonECDSASigner{})
	if err == nil {
		t.Fatal("should reject a signer whose public key is not *ecdsa.PublicKey")
	}
}

// erroringSigner wraps a real ECDSA key but always fails to sign, to
// exercise Sign's crypto.Signer.Sign error branch (e.g. an HSM/PKCS#11
// backend becoming unavailable).
type erroringSigner struct {
	pub *ecdsa.PublicKey
}

func (s erroringSigner) Public() crypto.PublicKey { return s.pub }
func (erroringSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, errors.New("simulated signer failure")
}

func TestCryptoSignerES256_Sign_SignerError(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	signer, err := NewCryptoSignerES256(erroringSigner{pub: &key.PublicKey})
	if err != nil {
		t.Fatal(err)
	}

	_, err = signer.Sign("test-string", nil)
	if err == nil {
		t.Fatal("expected error when the underlying crypto.Signer fails")
	}
}

func TestCryptoSignerES256_RejectsNonNilKey(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	signer, err := NewCryptoSignerES256(key)
	if err != nil {
		t.Fatal(err)
	}

	_, err = signer.Sign("test-string", "unexpected-key")
	if err == nil {
		t.Fatal("Sign should reject non-nil key")
	}
}

func TestCryptoSignerES256_Verify(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	signer, err := NewCryptoSignerES256(key)
	if err != nil {
		t.Fatal(err)
	}

	// Sign a token, then verify it using the Verify method
	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{"sub": "test"})
	tokenString, err := signer.SignToken(token)
	if err != nil {
		t.Fatalf("SignToken: %v", err)
	}

	// Parse to get the parts
	parsed, parts, err := jwt.NewParser().ParseUnverified(tokenString, jwt.MapClaims{})
	_ = parsed
	if err != nil {
		t.Fatalf("ParseUnverified: %v", err)
	}

	signingString := parts[0] + "." + parts[1]
	sigBytes, err := jwt.NewParser().DecodeSegment(parts[2])
	if err != nil {
		t.Fatalf("DecodeSegment: %v", err)
	}

	err = signer.Verify(signingString, sigBytes, &key.PublicKey)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestCryptoSignerES256_Alg(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	signer, err := NewCryptoSignerES256(key)
	if err != nil {
		t.Fatal(err)
	}

	if alg := signer.Alg(); alg != "ES256" {
		t.Errorf("Alg() = %q, want ES256", alg)
	}
}
