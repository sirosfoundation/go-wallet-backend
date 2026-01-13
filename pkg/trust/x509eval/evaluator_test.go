package x509eval

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"testing"
	"time"

	"github.com/sirosfoundation/go-wallet-backend/pkg/trust"
)

// generateTestCerts creates a test CA and leaf certificate
func generateTestCerts(t *testing.T) (caPEM []byte, leafDER []byte) {
	t.Helper()

	// Generate CA key
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate CA key: %v", err)
	}

	// Create CA certificate
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test CA"},
			CommonName:   "Test CA",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("failed to create CA certificate: %v", err)
	}

	// Convert CA to PEM
	caPEM = []byte("-----BEGIN CERTIFICATE-----\n" +
		base64.StdEncoding.EncodeToString(caDER) +
		"\n-----END CERTIFICATE-----\n")

	// Generate leaf key
	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate leaf key: %v", err)
	}

	// Create leaf certificate
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
			CommonName:   "test.example.com",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("failed to parse CA certificate: %v", err)
	}

	leafDER, err = x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("failed to create leaf certificate: %v", err)
	}

	return caPEM, leafDER
}

func TestNewEvaluator(t *testing.T) {
	t.Run("nil config returns error", func(t *testing.T) {
		_, err := NewEvaluator(nil)
		if err == nil {
			t.Error("expected error for nil config")
		}
	})

	t.Run("valid config creates evaluator", func(t *testing.T) {
		caPEM, _ := generateTestCerts(t)
		cfg := &Config{
			RootCertificates: [][]byte{caPEM},
		}

		eval, err := NewEvaluator(cfg)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if eval == nil {
			t.Error("expected evaluator to be created")
		}
	})

	t.Run("invalid PEM returns error", func(t *testing.T) {
		cfg := &Config{
			RootCertificates: [][]byte{[]byte("not a cert")},
		}

		_, err := NewEvaluator(cfg)
		if err == nil {
			t.Error("expected error for invalid PEM")
		}
	})
}

func TestEvaluator_Name(t *testing.T) {
	caPEM, _ := generateTestCerts(t)
	eval, _ := NewEvaluator(&Config{RootCertificates: [][]byte{caPEM}})

	if eval.Name() != "x509" {
		t.Errorf("expected name 'x509', got '%s'", eval.Name())
	}
}

func TestEvaluator_SupportedResourceTypes(t *testing.T) {
	caPEM, _ := generateTestCerts(t)
	eval, _ := NewEvaluator(&Config{RootCertificates: [][]byte{caPEM}})

	types := eval.SupportedResourceTypes()
	if len(types) != 1 || types[0] != trust.ResourceTypeX5C {
		t.Errorf("expected [x5c], got %v", types)
	}
}

func TestEvaluator_Healthy(t *testing.T) {
	caPEM, _ := generateTestCerts(t)
	eval, _ := NewEvaluator(&Config{RootCertificates: [][]byte{caPEM}})

	if !eval.Healthy() {
		t.Error("expected evaluator to be healthy")
	}
}

func TestEvaluator_Evaluate(t *testing.T) {
	caPEM, leafDER := generateTestCerts(t)

	eval, err := NewEvaluator(&Config{RootCertificates: [][]byte{caPEM}})
	if err != nil {
		t.Fatalf("failed to create evaluator: %v", err)
	}

	t.Run("valid certificate chain", func(t *testing.T) {
		leafB64 := base64.StdEncoding.EncodeToString(leafDER)

		resp, err := eval.Evaluate(context.Background(), &trust.EvaluationRequest{
			Subject: trust.Subject{
				Type: trust.SubjectTypeKey,
				ID:   "test.example.com",
			},
			Resource: trust.Resource{
				Type: trust.ResourceTypeX5C,
				ID:   "test.example.com",
				Key:  []string{leafB64},
			},
		})

		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !resp.Decision {
			t.Errorf("expected Decision=true, got false: %s", resp.Reason)
		}
	})

	t.Run("unsupported resource type", func(t *testing.T) {
		resp, err := eval.Evaluate(context.Background(), &trust.EvaluationRequest{
			Subject: trust.Subject{Type: trust.SubjectTypeKey, ID: "test"},
			Resource: trust.Resource{
				Type: trust.ResourceTypeJWK,
				ID:   "test",
			},
		})

		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.Decision {
			t.Error("expected Decision=false for unsupported type")
		}
	})

	t.Run("no certificates provided", func(t *testing.T) {
		resp, err := eval.Evaluate(context.Background(), &trust.EvaluationRequest{
			Subject: trust.Subject{Type: trust.SubjectTypeKey, ID: "test"},
			Resource: trust.Resource{
				Type: trust.ResourceTypeX5C,
				ID:   "test",
				Key:  nil,
			},
		})

		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.Decision {
			t.Error("expected Decision=false for no certificates")
		}
	})

	t.Run("invalid certificate", func(t *testing.T) {
		resp, err := eval.Evaluate(context.Background(), &trust.EvaluationRequest{
			Subject: trust.Subject{Type: trust.SubjectTypeKey, ID: "test"},
			Resource: trust.Resource{
				Type: trust.ResourceTypeX5C,
				ID:   "test",
				Key:  []string{"not-valid-base64-cert"},
			},
		})

		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.Decision {
			t.Error("expected Decision=false for invalid certificate")
		}
	})

	t.Run("untrusted certificate", func(t *testing.T) {
		// Create a self-signed cert not in the trust pool
		untrustedKey, _ := rsa.GenerateKey(rand.Reader, 2048)
		untrustedTemplate := &x509.Certificate{
			SerialNumber: big.NewInt(99),
			Subject:      pkix.Name{CommonName: "untrusted"},
			NotBefore:    time.Now().Add(-1 * time.Hour),
			NotAfter:     time.Now().Add(24 * time.Hour),
		}
		untrustedDER, _ := x509.CreateCertificate(rand.Reader, untrustedTemplate, untrustedTemplate, &untrustedKey.PublicKey, untrustedKey)
		untrustedB64 := base64.StdEncoding.EncodeToString(untrustedDER)

		resp, err := eval.Evaluate(context.Background(), &trust.EvaluationRequest{
			Subject: trust.Subject{Type: trust.SubjectTypeKey, ID: "untrusted"},
			Resource: trust.Resource{
				Type: trust.ResourceTypeX5C,
				ID:   "untrusted",
				Key:  []string{untrustedB64},
			},
		})

		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.Decision {
			t.Error("expected Decision=false for untrusted certificate")
		}
	})
}

func TestEvaluator_AddRootCert(t *testing.T) {
	caPEM, _ := generateTestCerts(t)

	eval, _ := NewEvaluator(&Config{RootCertificates: [][]byte{caPEM}})

	// Add another root cert
	caPEM2, _ := generateTestCerts(t)
	err := eval.AddRootCert(caPEM2)
	if err != nil {
		t.Errorf("unexpected error adding root cert: %v", err)
	}

	// Invalid cert should fail
	err = eval.AddRootCert([]byte("not a cert"))
	if err == nil {
		t.Error("expected error for invalid PEM")
	}
}

func TestEvaluator_AddIntermediateCert(t *testing.T) {
	caPEM, _ := generateTestCerts(t)

	eval, err := NewEvaluator(&Config{RootCertificates: [][]byte{caPEM}})
	if err != nil {
		t.Fatalf("unexpected error creating evaluator: %v", err)
	}

	// Add an intermediate cert (using CA cert as example)
	err = eval.AddIntermediateCert(caPEM)
	if err != nil {
		t.Errorf("unexpected error adding intermediate cert: %v", err)
	}

	// Invalid cert should fail
	err = eval.AddIntermediateCert([]byte("not a cert"))
	if err == nil {
		t.Error("expected error for invalid PEM")
	}
}

func TestNewEvaluatorFromPaths(t *testing.T) {
	// Test with non-existent path
	_, err := NewEvaluatorFromPaths([]string{"/nonexistent/path.pem"}, nil)
	if err == nil {
		t.Error("expected error for non-existent path")
	}
}
