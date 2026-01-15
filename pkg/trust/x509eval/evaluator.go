// Package x509eval provides an X.509 certificate trust evaluator.
//
// This evaluator validates certificate chains against a configured root CA pool.
// It supports basic PKI trust evaluation for simple deployment scenarios.
package x509eval

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"os"
	"sync"

	"github.com/sirosfoundation/go-wallet-backend/pkg/trust"
)

// Evaluator validates X.509 certificate chains against a root CA pool.
type Evaluator struct {
	rootPool *x509.CertPool
	intPool  *x509.CertPool
	mu       sync.RWMutex
	healthy  bool
}

// Config holds configuration for the X509 evaluator.
type Config struct {
	// RootCertificates are the trusted root CA certificates in PEM format.
	RootCertificates [][]byte
	// IntermediateCertificates are optional intermediate CA certificates.
	IntermediateCertificates [][]byte
}

// NewEvaluator creates a new X.509 certificate evaluator.
func NewEvaluator(cfg *Config) (*Evaluator, error) {
	rootPool := x509.NewCertPool()
	intPool := x509.NewCertPool()

	if cfg == nil {
		return nil, fmt.Errorf("config is required")
	}

	// Add root certificates
	for i, certPEM := range cfg.RootCertificates {
		if !rootPool.AppendCertsFromPEM(certPEM) {
			return nil, fmt.Errorf("failed to parse root certificate %d", i)
		}
	}

	// Add intermediate certificates
	for i, certPEM := range cfg.IntermediateCertificates {
		if !intPool.AppendCertsFromPEM(certPEM) {
			return nil, fmt.Errorf("failed to parse intermediate certificate %d", i)
		}
	}

	return &Evaluator{
		rootPool: rootPool,
		intPool:  intPool,
		healthy:  true,
	}, nil
}

// NewEvaluatorFromPaths creates an evaluator from certificate file paths.
func NewEvaluatorFromPaths(rootPaths, intermediatePaths []string) (*Evaluator, error) {
	cfg := &Config{}

	for _, path := range rootPaths {
		cert, err := loadCertFile(path)
		if err != nil {
			return nil, fmt.Errorf("loading root cert %s: %w", path, err)
		}
		cfg.RootCertificates = append(cfg.RootCertificates, cert)
	}

	for _, path := range intermediatePaths {
		cert, err := loadCertFile(path)
		if err != nil {
			return nil, fmt.Errorf("loading intermediate cert %s: %w", path, err)
		}
		cfg.IntermediateCertificates = append(cfg.IntermediateCertificates, cert)
	}

	return NewEvaluator(cfg)
}

// loadCertFile reads a PEM certificate file.
func loadCertFile(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading cert file: %w", err)
	}
	return data, nil
}

// Name returns the evaluator name.
func (e *Evaluator) Name() string {
	return "x509"
}

// SupportedResourceTypes returns the types this evaluator handles.
func (e *Evaluator) SupportedResourceTypes() []trust.ResourceType {
	return []trust.ResourceType{trust.ResourceTypeX5C}
}

// Healthy returns whether the evaluator is operational.
func (e *Evaluator) Healthy() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.healthy
}

// Evaluate validates a certificate chain against the root pool.
func (e *Evaluator) Evaluate(ctx context.Context, req *trust.EvaluationRequest) (*trust.EvaluationResponse, error) {
	keyType := req.GetKeyType()
	if keyType != trust.ResourceTypeX5C {
		return &trust.EvaluationResponse{
			Decision: false,
			Reason:   fmt.Sprintf("unsupported resource type: %s", keyType),
		}, nil
	}

	// Parse certificates from request
	certs, err := e.parseCertificates(req)
	if err != nil {
		return &trust.EvaluationResponse{
			Decision: false,
			Reason:   fmt.Sprintf("failed to parse certificates: %v", err),
		}, nil
	}

	if len(certs) == 0 {
		return &trust.EvaluationResponse{
			Decision: false,
			Reason:   "no certificates provided",
		}, nil
	}

	// Verify the certificate chain
	opts := x509.VerifyOptions{
		Roots:         e.rootPool,
		Intermediates: e.intPool,
	}

	// If action specifies a DNS name or other constraint, add it
	action := req.GetAction()
	if action != "" {
		// For TLS server validation, the action name might be a hostname
		opts.DNSName = action
	}

	leaf := certs[0]
	chains, err := leaf.Verify(opts)
	if err != nil {
		return &trust.EvaluationResponse{
			Decision: false,
			Reason:   fmt.Sprintf("certificate verification failed: %v", err),
		}, nil
	}

	// Use the first valid chain
	var validChain []*x509.Certificate
	if len(chains) > 0 {
		validChain = chains[0]
	}

	return &trust.EvaluationResponse{
		Decision: true,
		Reason:   "certificate chain verified successfully",
		Chain:    validChain,
	}, nil
}

// parseCertificates extracts certificates from the request.
func (e *Evaluator) parseCertificates(req *trust.EvaluationRequest) ([]*x509.Certificate, error) {
	// Use pre-parsed certificates from legacy Resource field if available
	if len(req.Resource.Certificates) > 0 {
		return req.Resource.Certificates, nil
	}

	// Parse from Key field (new or legacy)
	key := req.GetKey()
	switch k := key.(type) {
	case []string:
		return e.parseCertStrings(k)
	case []interface{}:
		strs := make([]string, len(k))
		for i, v := range k {
			s, ok := v.(string)
			if !ok {
				return nil, fmt.Errorf("certificate %d is not a string", i)
			}
			strs[i] = s
		}
		return e.parseCertStrings(strs)
	case nil:
		return nil, fmt.Errorf("no key material provided")
	default:
		return nil, fmt.Errorf("unsupported key type: %T", key)
	}
}

// parseCertStrings parses base64-encoded DER certificates.
func (e *Evaluator) parseCertStrings(certStrs []string) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate

	for i, certStr := range certStrs {
		// Decode base64
		der, err := base64.StdEncoding.DecodeString(certStr)
		if err != nil {
			// Try URL-safe base64
			der, err = base64.RawURLEncoding.DecodeString(certStr)
			if err != nil {
				return nil, fmt.Errorf("certificate %d: invalid base64: %w", i, err)
			}
		}

		// Parse certificate
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("certificate %d: invalid DER: %w", i, err)
		}

		certs = append(certs, cert)
	}

	return certs, nil
}

// AddRootCert adds a root certificate to the pool.
func (e *Evaluator) AddRootCert(certPEM []byte) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if !e.rootPool.AppendCertsFromPEM(certPEM) {
		return fmt.Errorf("failed to parse certificate")
	}
	return nil
}

// AddIntermediateCert adds an intermediate certificate to the pool.
func (e *Evaluator) AddIntermediateCert(certPEM []byte) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if !e.intPool.AppendCertsFromPEM(certPEM) {
		return fmt.Errorf("failed to parse certificate")
	}
	return nil
}
