package audit

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
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

	// Should not panic — just verify it runs without error
	e.Emit(set.EventWIAIssued, map[string]any{"test": true})
	e.EmitWithSubject(set.EventWIAIssued, "test-subject", map[string]any{"test": true})
}
