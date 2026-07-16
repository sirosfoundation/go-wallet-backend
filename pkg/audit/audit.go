package audit

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"
	"os"

	"github.com/go-jose/go-jose/v4"

	"github.com/sirosfoundation/go-siros-set/emit"
	"github.com/sirosfoundation/go-siros-set/set"
)

// Emitter wraps the SET emit.Emitter for audit trail generation.
type Emitter struct {
	e *emit.Emitter
}

// New creates a new audit Emitter. If signer is nil, returns nil (audit disabled).
func New(issuer string, signer jose.Signer, logger *slog.Logger) *Emitter {
	if signer == nil {
		return nil
	}
	var opts []emit.Option
	if logger != nil {
		opts = append(opts, emit.WithLogger(logger))
	}
	return &Emitter{e: emit.New(issuer, signer, opts...)}
}

// NewFromFile creates an Emitter from a PEM-encoded EC private key file.
func NewFromFile(issuer, keyPath, keyID string) (*Emitter, error) {
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("audit: read key: %w", err)
	}
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, fmt.Errorf("audit: decode PEM key")
	}

	var signer crypto.Signer
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		key2, err2 := x509.ParseECPrivateKey(block.Bytes)
		if err2 != nil {
			return nil, fmt.Errorf("audit: parse key (PKCS#8: %w, EC: %v)", err, err2)
		}
		signer = key2
	} else {
		s, ok := key.(crypto.Signer)
		if !ok {
			return nil, fmt.Errorf("audit: key does not implement crypto.Signer")
		}
		signer = s
	}

	var alg jose.SignatureAlgorithm
	switch k := signer.Public().(type) {
	case *ecdsa.PublicKey:
		switch k.Curve.Params().BitSize {
		case 256:
			alg = jose.ES256
		case 384:
			alg = jose.ES384
		case 521:
			alg = jose.ES512
		default:
			return nil, fmt.Errorf("audit: unsupported EC curve size %d", k.Curve.Params().BitSize)
		}
	default:
		return nil, fmt.Errorf("audit: unsupported key type %T (only ECDSA keys are supported)", signer.Public())
	}

	joseSigner, err := set.NewSigner(signer, alg, keyID)
	if err != nil {
		return nil, fmt.Errorf("audit: create JOSE signer: %w", err)
	}

	return New(issuer, joseSigner, nil), nil
}

// Emit emits an audit event. Errors are logged but do not fail the operation.
func (a *Emitter) Emit(event set.EventURI, data map[string]any) {
	if a == nil {
		return
	}
	if err := a.e.Emit(event, data); err != nil {
		slog.Error("audit emit failed", "event", string(event), "error", err)
	}
}

// EmitWithSubject emits an audit event with a subject identifier.
func (a *Emitter) EmitWithSubject(event set.EventURI, subject string, data map[string]any) {
	if a == nil {
		return
	}
	if err := a.e.EmitWithSubject(event, subject, data); err != nil {
		slog.Error("audit emit failed", "event", string(event), "subject", subject, "error", err)
	}
}
