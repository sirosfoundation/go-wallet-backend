// Package authz provides authorization for AuthZEN proxy queries.
//
// This package implements query-level authorization to ensure that only
// permitted queries are forwarded to the backend PDP (Policy Decision Point).
// This is a "firewall" layer that prevents clients from making arbitrary
// trust evaluation requests.
package authz

import (
	"context"
	"errors"

	gotrust "github.com/sirosfoundation/go-trust/pkg/authzen"
)

// Common authorization errors.
var (
	// ErrUnauthorized indicates the query is not authorized by policy.
	ErrUnauthorized = errors.New("query not authorized")

	// ErrInvalidQuery indicates the query is malformed or missing required fields.
	ErrInvalidQuery = errors.New("invalid query")

	// ErrUnsupportedAction indicates the action is not in the allowed set.
	ErrUnsupportedAction = errors.New("unsupported action")

	// ErrUnsupportedResourceType indicates the resource type is not allowed.
	ErrUnsupportedResourceType = errors.New("unsupported resource type")
)

// AuthorizationRequest contains all context needed for authorization.
type AuthorizationRequest struct {
	// TenantID is the tenant making the request (from JWT).
	TenantID string

	// UserID is the user making the request (from JWT).
	UserID string

	// Request is the AuthZEN evaluation request being authorized.
	Request *gotrust.EvaluationRequest
}

// Authorizer determines whether an AuthZEN query is permitted.
type Authorizer interface {
	// Authorize checks if the given request is authorized.
	// Returns nil if authorized, or an error explaining why not.
	Authorize(ctx context.Context, req *AuthorizationRequest) error
}

// NoOpAuthorizer always allows requests (for development/testing).
type NoOpAuthorizer struct{}

// Authorize always returns nil (allows all requests).
func (NoOpAuthorizer) Authorize(ctx context.Context, req *AuthorizationRequest) error {
	return nil
}
