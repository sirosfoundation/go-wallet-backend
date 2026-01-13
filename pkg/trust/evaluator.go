// Package trust provides a plugin-based trust evaluation system for the wallet backend.
//
// Per ADR 010, trust evaluation is plugin-based with two built-in plugins:
// 1. X509 evaluator - validates certificates against a root CA pool
// 2. AuthZEN evaluator - delegates to a go-trust PDP service
//
// This package uses types from github.com/sirosfoundation/go-trust/pkg/trustapi
// for compatibility with other ecosystem components (vc, etc.).
package trust

import (
	"context"
	"crypto/x509"

	"github.com/sirosfoundation/go-trust/pkg/trustapi"
)

// Type aliases from trustapi for compatibility.
type (
	// KeyType indicates the format of the public key being validated.
	KeyType = trustapi.KeyType

	// Role represents the expected role of the key holder.
	Role = trustapi.Role

	// TrustOptions contains additional options for trust evaluation.
	TrustOptions = trustapi.TrustOptions

	// X5CCertChain is a helper type for x5c certificate chains.
	X5CCertChain = trustapi.X5CCertChain
)

// Constants re-exported from trustapi.
const (
	KeyTypeJWK = trustapi.KeyTypeJWK
	KeyTypeX5C = trustapi.KeyTypeX5C

	RoleIssuer             = trustapi.RoleIssuer
	RoleVerifier           = trustapi.RoleVerifier
	RoleWalletProvider     = trustapi.RoleWalletProvider
	RolePIDProvider        = trustapi.RolePIDProvider
	RoleCredentialIssuer   = trustapi.RoleCredentialIssuer
	RoleCredentialVerifier = trustapi.RoleCredentialVerifier
	RoleAny                = trustapi.RoleAny
)

// Legacy type aliases for backward compatibility.
// These map the old Resource/Subject model to the new flat model.
type (
	// SubjectType represents the type of subject being evaluated.
	// Deprecated: Use KeyType instead.
	SubjectType = string

	// ResourceType represents the type of resource/credential being validated.
	// Deprecated: Use KeyType instead.
	ResourceType = KeyType
)

// Legacy constants for backward compatibility.
const (
	// SubjectTypeKey represents a public key subject (used in AuthZEN).
	SubjectTypeKey SubjectType = "key"
	// SubjectTypeCertificate represents an X.509 certificate subject.
	SubjectTypeCertificate SubjectType = "certificate"

	// ResourceTypeX5C represents an X.509 certificate chain.
	ResourceTypeX5C ResourceType = KeyTypeX5C
	// ResourceTypeJWK represents a JSON Web Key.
	ResourceTypeJWK ResourceType = KeyTypeJWK
)

// EvaluationRequest represents a trust evaluation request.
// This wraps trustapi.EvaluationRequest and adds wallet-specific fields.
type EvaluationRequest struct {
	trustapi.EvaluationRequest

	// Subject identifies what is being validated (legacy field).
	// Prefer using SubjectID directly.
	Subject Subject

	// Resource contains the cryptographic material (legacy field).
	// Prefer using Key and KeyType directly.
	Resource Resource

	// LegacyAction specifies the action (legacy field).
	// Deprecated: Use EvaluationRequest.Action or Role directly.
	LegacyAction *Action

	// Context provides additional information for evaluation (legacy field).
	// Prefer using Options.
	Context map[string]interface{}
}

// Subject represents the entity whose trust is being evaluated.
// Deprecated: Use EvaluationRequest.SubjectID directly.
type Subject struct {
	// Type is the subject type (e.g., "key", "certificate").
	Type SubjectType
	// ID is the identifier for the subject (e.g., DID, issuer name).
	ID string
}

// Resource contains the cryptographic material to validate.
// Deprecated: Use EvaluationRequest.Key and KeyType directly.
type Resource struct {
	// Type is the resource type (e.g., "x5c", "jwk").
	Type ResourceType
	// ID is the identifier for the resource, typically matching Subject.ID.
	ID string
	// Key contains the actual key material.
	Key interface{}
	// Certificates is a convenience field for pre-parsed X.509 certificates.
	Certificates []*x509.Certificate
}

// Action specifies the role or operation being validated.
// Deprecated: Use EvaluationRequest.Role or Action field directly.
type Action struct {
	// Name is the action/role name.
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

// ToTrustDecision converts EvaluationResponse to trustapi.TrustDecision.
func (r *EvaluationResponse) ToTrustDecision() *trustapi.TrustDecision {
	return &trustapi.TrustDecision{
		Trusted:  r.Decision,
		Reason:   r.Reason,
		Metadata: r.TrustMetadata,
	}
}

// FromTrustDecision creates an EvaluationResponse from trustapi.TrustDecision.
func FromTrustDecision(d *trustapi.TrustDecision) *EvaluationResponse {
	return &EvaluationResponse{
		Decision:      d.Trusted,
		Reason:        d.Reason,
		TrustMetadata: d.Metadata,
	}
}

// GetSubjectID returns the subject ID, preferring the new field over legacy.
func (r *EvaluationRequest) GetSubjectID() string {
	if r.SubjectID != "" {
		return r.SubjectID
	}
	return r.Subject.ID
}

// GetKeyType returns the key type, preferring the new field over legacy.
func (r *EvaluationRequest) GetKeyType() KeyType {
	if r.KeyType != "" {
		return r.KeyType
	}
	return r.Resource.Type
}

// GetKey returns the key material, preferring the new field over legacy.
func (r *EvaluationRequest) GetKey() interface{} {
	if r.Key != nil {
		return r.Key
	}
	if len(r.Resource.Certificates) > 0 {
		return r.Resource.Certificates
	}
	return r.Resource.Key
}

// GetAction returns the action name, preferring the new field over legacy.
func (r *EvaluationRequest) GetAction() string {
	if r.Action != "" {
		return r.Action
	}
	if r.LegacyAction != nil {
		return r.LegacyAction.Name
	}
	return ""
}

// TrustEvaluator is the interface for trust evaluation plugins.
// Implementations must be safe for concurrent use.
//
// This interface is compatible with trustapi.TrustEvaluator but uses
// wallet-specific request/response types for backward compatibility.
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

// TrustapiEvaluator wraps a trustapi.TrustEvaluator for use with wallet-backend types.
type TrustapiEvaluator struct {
	inner trustapi.TrustEvaluator
}

// NewTrustapiEvaluator wraps a trustapi.TrustEvaluator.
func NewTrustapiEvaluator(e trustapi.TrustEvaluator) *TrustapiEvaluator {
	return &TrustapiEvaluator{inner: e}
}

// Evaluate implements TrustEvaluator.
func (e *TrustapiEvaluator) Evaluate(ctx context.Context, req *EvaluationRequest) (*EvaluationResponse, error) {
	// Convert to trustapi request
	apiReq := &trustapi.EvaluationRequest{
		SubjectID:      req.GetSubjectID(),
		KeyType:        req.GetKeyType(),
		Key:            req.GetKey(),
		Role:           req.Role,
		Action:         req.Action,
		CredentialType: req.CredentialType,
		DocType:        req.DocType,
		Options:        req.Options,
	}

	decision, err := e.inner.Evaluate(ctx, apiReq)
	if err != nil {
		return nil, err
	}

	return FromTrustDecision(decision), nil
}

// Name implements TrustEvaluator.
func (e *TrustapiEvaluator) Name() string {
	return e.inner.Name()
}

// SupportedResourceTypes implements TrustEvaluator.
func (e *TrustapiEvaluator) SupportedResourceTypes() []ResourceType {
	var result []ResourceType
	if e.inner.SupportsKeyType(KeyTypeX5C) {
		result = append(result, ResourceTypeX5C)
	}
	if e.inner.SupportsKeyType(KeyTypeJWK) {
		result = append(result, ResourceTypeJWK)
	}
	return result
}

// Healthy implements TrustEvaluator.
func (e *TrustapiEvaluator) Healthy() bool {
	return e.inner.Healthy()
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
	keyType := req.GetKeyType()
	for _, e := range m.evaluators {
		for _, rt := range e.SupportedResourceTypes() {
			if rt == keyType {
				return e.Evaluate(ctx, req)
			}
		}
	}

	return &EvaluationResponse{
		Decision: false,
		Reason:   "no evaluator available for resource type: " + string(keyType),
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
