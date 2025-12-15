// Package trust provides a plugin-based trust evaluation system for the wallet backend.
//
// Per ADR 010, trust evaluation is plugin-based with two built-in plugins:
// 1. X509 evaluator - validates certificates against a root CA pool
// 2. AuthZEN evaluator - delegates to a go-trust PDP service
//
// The TrustEvaluator interface allows for custom trust evaluation implementations.
package trust

import (
	"context"
	"crypto/x509"
)

// SubjectType represents the type of subject being evaluated.
type SubjectType string

const (
	// SubjectTypeKey represents a public key subject (used in AuthZEN).
	SubjectTypeKey SubjectType = "key"
	// SubjectTypeCertificate represents an X.509 certificate subject.
	SubjectTypeCertificate SubjectType = "certificate"
)

// ResourceType represents the type of resource/credential being validated.
type ResourceType string

const (
	// ResourceTypeX5C represents an X.509 certificate chain.
	ResourceTypeX5C ResourceType = "x5c"
	// ResourceTypeJWK represents a JSON Web Key.
	ResourceTypeJWK ResourceType = "jwk"
)

// EvaluationRequest represents a trust evaluation request.
// It is designed to be compatible with AuthZEN but also supports simpler X.509 evaluation.
type EvaluationRequest struct {
	// Subject identifies what is being validated.
	Subject Subject
	// Resource contains the cryptographic material (certificate chain, JWK, etc.).
	Resource Resource
	// Action optionally specifies the role or action being validated.
	Action *Action
	// Context provides additional information for evaluation.
	Context map[string]interface{}
}

// Subject represents the entity whose trust is being evaluated.
type Subject struct {
	// Type is the subject type (e.g., "key", "certificate").
	Type SubjectType
	// ID is the identifier for the subject (e.g., DID, issuer name).
	ID string
}

// Resource contains the cryptographic material to validate.
type Resource struct {
	// Type is the resource type (e.g., "x5c", "jwk").
	Type ResourceType
	// ID is the identifier for the resource, typically matching Subject.ID.
	ID string
	// Key contains the actual key material.
	// For x5c: slice of base64-encoded certificate strings
	// For jwk: the JWK as map[string]interface{}
	Key interface{}
	// Certificates is a convenience field for pre-parsed X.509 certificates.
	Certificates []*x509.Certificate
}

// Action specifies the role or operation being validated.
type Action struct {
	// Name is the action/role name (e.g., "http://ec.europa.eu/NS/wallet-provider").
	Name string
}

// EvaluationResponse contains the result of a trust evaluation.
type EvaluationResponse struct {
	// Decision is true if the subject is trusted for the requested action.
	Decision bool
	// Reason provides human-readable explanation for the decision.
	Reason string
	// TrustMetadata contains additional trust information (e.g., DID document).
	TrustMetadata interface{}
	// Chain contains the validated certificate chain, if applicable.
	Chain []*x509.Certificate
}

// TrustEvaluator is the interface for trust evaluation plugins.
// Implementations must be safe for concurrent use.
type TrustEvaluator interface {
	// Evaluate performs trust evaluation for the given request.
	// Returns EvaluationResponse with Decision=true if trusted, false otherwise.
	// Should not return an error for "not trusted" cases; use Decision=false.
	Evaluate(ctx context.Context, req *EvaluationRequest) (*EvaluationResponse, error)

	// Name returns a human-readable name for this evaluator.
	Name() string

	// SupportedResourceTypes returns the resource types this evaluator can handle.
	SupportedResourceTypes() []ResourceType

	// Healthy returns true if the evaluator is operational.
	Healthy() bool
}

// EvaluatorManager coordinates multiple trust evaluators.
// It routes requests to the appropriate evaluator based on resource type.
type EvaluatorManager struct {
	evaluators []TrustEvaluator
}

// NewEvaluatorManager creates a new EvaluatorManager with the given evaluators.
func NewEvaluatorManager(evaluators ...TrustEvaluator) *EvaluatorManager {
	return &EvaluatorManager{
		evaluators: evaluators,
	}
}

// AddEvaluator adds an evaluator to the manager.
func (m *EvaluatorManager) AddEvaluator(e TrustEvaluator) {
	m.evaluators = append(m.evaluators, e)
}

// Name returns the name of the evaluator manager.
func (m *EvaluatorManager) Name() string {
	return "composite"
}

// SupportedResourceTypes returns all resource types supported by any registered evaluator.
func (m *EvaluatorManager) SupportedResourceTypes() []ResourceType {
	seen := make(map[ResourceType]bool)
	var result []ResourceType
	for _, e := range m.evaluators {
		for _, rt := range e.SupportedResourceTypes() {
			if !seen[rt] {
				seen[rt] = true
				result = append(result, rt)
			}
		}
	}
	return result
}

// Evaluate routes the request to an appropriate evaluator.
// It tries evaluators in order until one returns a decision.
func (m *EvaluatorManager) Evaluate(ctx context.Context, req *EvaluationRequest) (*EvaluationResponse, error) {
	for _, e := range m.evaluators {
		for _, rt := range e.SupportedResourceTypes() {
			if rt == req.Resource.Type {
				return e.Evaluate(ctx, req)
			}
		}
	}

	return &EvaluationResponse{
		Decision: false,
		Reason:   "no evaluator available for resource type: " + string(req.Resource.Type),
	}, nil
}

// Healthy returns true if at least one evaluator is healthy.
func (m *EvaluatorManager) Healthy() bool {
	for _, e := range m.evaluators {
		if e.Healthy() {
			return true
		}
	}
	return len(m.evaluators) == 0 // Empty manager is "healthy"
}

// AllHealthy returns true if all evaluators are healthy.
func (m *EvaluatorManager) AllHealthy() bool {
	for _, e := range m.evaluators {
		if !e.Healthy() {
			return false
		}
	}
	return true
}
