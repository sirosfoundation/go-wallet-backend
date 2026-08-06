package audit

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"log/slog"
	"os"
	"testing"

	"github.com/sirosfoundation/go-siros-set/set"
)

func writeTestKey(t *testing.T, key *ecdsa.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.CreateTemp(t.TempDir(), "audit-key-*.pem")
	if err != nil {
		t.Fatal(err)
	}
	if err := pem.Encode(f, &pem.Block{Type: "EC PRIVATE KEY", Bytes: der}); err != nil {
		t.Fatal(err)
	}
	f.Close()
	return f.Name()
}

func TestNewFromFile_P256(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	path := writeTestKey(t, key)

	e, err := NewFromFile("https://test.example.com", path, "test-kid")
	if err != nil {
		t.Fatalf("NewFromFile: %v", err)
	}
	if e == nil {
		t.Fatal("emitter should not be nil")
	}
}

// TestNewFromFile_P384 and TestNewFromFile_P521 are regression tests for a
// review finding: selecting jose.ES256 for any ECDSA key (regardless of
// curve) produces invalid JWS for P-384/P-521 keys, since ES256 specifically
// requires a P-256 key. The fix selects the JOSE alg from the actual curve
// size instead of hardcoding ES256.
func TestNewFromFile_P384(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	path := writeTestKey(t, key)

	e, err := NewFromFile("https://test.example.com", path, "test-kid")
	if err != nil {
		t.Fatalf("NewFromFile: %v", err)
	}
	if e == nil {
		t.Fatal("emitter should not be nil")
	}
}

func TestNewFromFile_P521(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	path := writeTestKey(t, key)

	e, err := NewFromFile("https://test.example.com", path, "test-kid")
	if err != nil {
		t.Fatalf("NewFromFile: %v", err)
	}
	if e == nil {
		t.Fatal("emitter should not be nil")
	}
}

func TestNewFromFile_UnsupportedCurveSize(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	path := writeTestKey(t, key)

	_, err := NewFromFile("https://test.example.com", path, "test-kid")
	if err == nil {
		t.Fatal("expected error for unsupported EC curve size")
	}
}

func TestNewFromFile_MissingFile(t *testing.T) {
	_, err := NewFromFile("https://test.example.com", "/nonexistent/key.pem", "kid")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestNewFromFile_InvalidPEM(t *testing.T) {
	f, _ := os.CreateTemp(t.TempDir(), "bad-*.pem")
	f.Write([]byte("not a pem file"))
	f.Close()

	_, err := NewFromFile("https://test.example.com", f.Name(), "kid")
	if err == nil {
		t.Fatal("expected error for invalid PEM")
	}
}

func TestNewFromFile_InvalidKeyData(t *testing.T) {
	f, _ := os.CreateTemp(t.TempDir(), "bad-key-*.pem")
	pem.Encode(f, &pem.Block{Type: "EC PRIVATE KEY", Bytes: []byte("invalid")})
	f.Close()

	_, err := NewFromFile("https://test.example.com", f.Name(), "kid")
	if err == nil {
		t.Fatal("expected error for invalid key data")
	}
}

func TestNewFromFile_PKCS8EC(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.CreateTemp(t.TempDir(), "audit-pkcs8-*.pem")
	if err != nil {
		t.Fatal(err)
	}
	if err := pem.Encode(f, &pem.Block{Type: "PRIVATE KEY", Bytes: der}); err != nil {
		t.Fatal(err)
	}
	f.Close()

	e, err := NewFromFile("https://test.example.com", f.Name(), "test-kid")
	if err != nil {
		t.Fatalf("NewFromFile: %v", err)
	}
	if e == nil {
		t.Fatal("emitter should not be nil")
	}
}

// TestNewFromFile_PKCS8UnsupportedKeyType is a regression test for the other
// half of the same review finding: a non-ECDSA key (e.g. RSA) previously
// silently fell into the "default: alg = jose.EdDSA" branch, which is wrong
// unless the key actually is Ed25519. Non-ECDSA keys must now error
// explicitly instead of being signed with a mismatched algorithm.
func TestNewFromFile_PKCS8UnsupportedKeyType(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.CreateTemp(t.TempDir(), "audit-rsa-*.pem")
	if err != nil {
		t.Fatal(err)
	}
	if err := pem.Encode(f, &pem.Block{Type: "PRIVATE KEY", Bytes: der}); err != nil {
		t.Fatal(err)
	}
	f.Close()

	_, err = NewFromFile("https://test.example.com", f.Name(), "test-kid")
	if err == nil {
		t.Fatal("expected error for unsupported (non-ECDSA) key type")
	}
}

func TestEmit_NilEmitter(t *testing.T) {
	var e *Emitter
	// Should not panic
	e.Emit(set.EventWIAIssued, nil)
	e.EmitWithSubject(set.EventWIAIssued, "sub", nil)
}

func TestNew_NilSigner(t *testing.T) {
	e := New("issuer", nil, nil)
	if e != nil {
		t.Error("New with nil signer should return nil")
	}
}

func TestEmit_Success(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	path := writeTestKey(t, key)

	e, err := NewFromFile("https://test.example.com", path, "test-kid")
	if err != nil {
		t.Fatalf("NewFromFile: %v", err)
	}

	// Should not panic — just verify it runs without error.
	e.Emit(set.EventWIAIssued, map[string]any{"test": true})
	e.EmitWithSubject(set.EventWIAIssued, "test-subject", map[string]any{"test": true})
}

func TestNew_WithLogger(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	joseSigner, err := set.NewSigner(key, "ES256", "test-kid")
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	e := New("https://test.example.com", joseSigner, logger)
	if e == nil {
		t.Fatal("expected non-nil emitter")
	}
}

func TestNewFromFile_PKCS8EC(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.CreateTemp(t.TempDir(), "audit-pkcs8-*.pem")
	if err != nil {
		t.Fatal(err)
	}
	if err := pem.Encode(f, &pem.Block{Type: "PRIVATE KEY", Bytes: der}); err != nil {
		t.Fatal(err)
	}
	f.Close()

	e, err := NewFromFile("https://test.example.com", f.Name(), "test-kid")
	if err != nil {
		t.Fatalf("NewFromFile: %v", err)
	}
	if e == nil {
		t.Fatal("emitter should not be nil")
	}
}

func TestNewFromFile_PKCS8UnsupportedKeyType(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.CreateTemp(t.TempDir(), "audit-rsa-*.pem")
	if err != nil {
		t.Fatal(err)
	}
	if err := pem.Encode(f, &pem.Block{Type: "PRIVATE KEY", Bytes: der}); err != nil {
		t.Fatal(err)
	}
	f.Close()

	_, err = NewFromFile("https://test.example.com", f.Name(), "test-kid")
	if err == nil {
		t.Fatal("expected error for unsupported (non-ECDSA) key type")
	}
}

func TestNewFromFile_P521(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	path := writeTestKey(t, key)

	e, err := NewFromFile("https://test.example.com", path, "test-kid")
	if err != nil {
		t.Fatalf("NewFromFile: %v", err)
	}
	if e == nil {
		t.Fatal("emitter should not be nil")
	}
}

func TestNewFromFile_UnsupportedCurveSize(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	path := writeTestKey(t, key)

	_, err := NewFromFile("https://test.example.com", path, "test-kid")
	if err == nil {
		t.Fatal("expected error for unsupported EC curve size")
	}
}

func TestEmit_MarshalError(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	path := writeTestKey(t, key)

	e, err := NewFromFile("https://test.example.com", path, "test-kid")
	if err != nil {
		t.Fatalf("NewFromFile: %v", err)
	}

	// A func value can't be JSON-marshaled, forcing the record-signing
	// error path. Should be logged, not panic or propagate.
	e.Emit(set.EventWIAIssued, map[string]any{"bad": func() {}})
	e.EmitWithSubject(set.EventWIAIssued, "test-subject", map[string]any{"bad": func() {}})
}
