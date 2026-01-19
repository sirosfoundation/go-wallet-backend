package service

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"time"

	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
	"github.com/sirosfoundation/go-wallet-backend/pkg/trust"
	"github.com/sirosfoundation/go-wallet-backend/pkg/trust/authzen"
	"github.com/sirosfoundation/go-wallet-backend/pkg/trust/x509eval"
)

// TrustService provides trust evaluation for issuers and verifiers.
// It wraps the trust.TrustEvaluator interface to provide a higher-level API.
type TrustService struct {
	evaluator trust.TrustEvaluator
	logger    *zap.Logger
}

// TrustResponse contains the result of a trust evaluation.
type TrustResponse struct {
	Trusted        bool
	Reason         string
	TrustFramework string
}

// NewTrustService creates a new TrustService.
// If no trust configuration is provided, returns nil (no trust evaluation).
func NewTrustService(cfg *config.Config, logger *zap.Logger) *TrustService {
	if cfg.Trust.AuthZEN.BaseURL == "" && len(cfg.Trust.X509.RootCertPaths) == 0 {
		logger.Info("No trust configuration provided, trust evaluation disabled")
		return nil
	}

	// Create composite evaluator
	manager := trust.NewEvaluatorManager()

	// Add AuthZEN evaluator if configured
	if cfg.Trust.AuthZEN.BaseURL != "" {
		authzenCfg := &authzen.Config{
			BaseURL: cfg.Trust.AuthZEN.BaseURL,
		}
		if cfg.Trust.AuthZEN.Timeout > 0 {
			authzenCfg.Timeout = time.Duration(cfg.Trust.AuthZEN.Timeout) * time.Second
		}

		authzenEval, err := authzen.NewEvaluator(authzenCfg)
		if err != nil {
			logger.Error("Failed to create AuthZEN evaluator", zap.Error(err))
		} else {
			manager.AddEvaluator(authzenEval)
			logger.Info("AuthZEN trust evaluator configured", zap.String("url", cfg.Trust.AuthZEN.BaseURL))
		}
	}

	// Add X.509 evaluator if configured
	if len(cfg.Trust.X509.RootCertPaths) > 0 {
		x509Eval, err := x509eval.NewEvaluatorFromPaths(
			cfg.Trust.X509.RootCertPaths,
			cfg.Trust.X509.IntermediateCertPaths,
		)
		if err != nil {
			logger.Error("Failed to create X.509 evaluator", zap.Error(err))
		} else {
			manager.AddEvaluator(x509Eval)
			logger.Info("X.509 trust evaluator configured",
				zap.Int("root_certs", len(cfg.Trust.X509.RootCertPaths)))
		}
	}

	if len(manager.SupportedResourceTypes()) == 0 {
		logger.Warn("No trust evaluators configured successfully")
		return nil
	}

	return &TrustService{
		evaluator: manager,
		logger:    logger.Named("trust"),
	}
}

// EvaluateIssuer evaluates trust for a credential issuer.
func (s *TrustService) EvaluateIssuer(ctx context.Context, issuerURL, credentialType string, pemCertificates []string) (*TrustResponse, error) {
	// Parse PEM certificates if provided
	var certs []*x509.Certificate
	for _, pemCert := range pemCertificates {
		block, _ := pem.Decode([]byte(pemCert))
		if block != nil {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				s.logger.Warn("Failed to parse certificate", zap.Error(err))
				continue
			}
			certs = append(certs, cert)
		}
	}

	req := &trust.EvaluationRequest{
		Subject: trust.Subject{
			Type: trust.SubjectTypeCertificate,
			ID:   issuerURL,
		},
		Resource: trust.Resource{
			Type:         trust.ResourceTypeX5C,
			ID:           issuerURL,
			Certificates: certs,
		},
		LegacyAction: &trust.Action{
			Name: string(trust.RoleIssuer),
		},
	}

	// Also set new-style fields
	req.SubjectID = issuerURL
	req.KeyType = trust.KeyTypeX5C
	req.Role = trust.RoleIssuer
	req.CredentialType = credentialType
	req.Key = certs

	result, err := s.evaluator.Evaluate(ctx, req)
	if err != nil {
		return nil, err
	}

	return &TrustResponse{
		Trusted:        result.Decision,
		Reason:         result.Reason,
		TrustFramework: s.detectTrustFramework(result),
	}, nil
}

// EvaluateVerifier evaluates trust for a credential verifier.
func (s *TrustService) EvaluateVerifier(ctx context.Context, verifierURL, credentialType string) (*TrustResponse, error) {
	req := &trust.EvaluationRequest{
		Subject: trust.Subject{
			Type: trust.SubjectTypeKey,
			ID:   verifierURL,
		},
		LegacyAction: &trust.Action{
			Name: string(trust.RoleVerifier),
		},
	}

	// Also set new-style fields
	req.SubjectID = verifierURL
	req.Role = trust.RoleVerifier
	req.CredentialType = credentialType

	result, err := s.evaluator.Evaluate(ctx, req)
	if err != nil {
		return nil, err
	}

	return &TrustResponse{
		Trusted:        result.Decision,
		Reason:         result.Reason,
		TrustFramework: s.detectTrustFramework(result),
	}, nil
}

// detectTrustFramework attempts to identify the trust framework from metadata
func (s *TrustService) detectTrustFramework(resp *trust.EvaluationResponse) string {
	if resp.TrustMetadata == nil {
		return ""
	}

	// Check if metadata contains trust framework hints
	if m, ok := resp.TrustMetadata.(map[string]interface{}); ok {
		if tf, ok := m["trust_framework"].(string); ok {
			return tf
		}
	}

	return ""
}
