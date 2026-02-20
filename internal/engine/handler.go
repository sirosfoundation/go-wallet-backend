package engine

import (
	"context"

	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

// FlowHandler handles a specific credential protocol flow
type FlowHandler interface {
	// Execute runs the flow to completion
	Execute(ctx context.Context, msg *FlowStartMessage) error

	// Cancel cancels the flow
	Cancel()
}

// FlowHandlerFactory creates a flow handler for a flow
type FlowHandlerFactory func(flow *Flow, cfg *config.Config, logger *zap.Logger) (FlowHandler, error)

// BaseHandler provides common functionality for flow handlers
type BaseHandler struct {
	Flow   *Flow
	Config *config.Config
	Logger *zap.Logger
	cancel context.CancelFunc
}

// Cancel cancels the flow
func (h *BaseHandler) Cancel() {
	if h.cancel != nil {
		h.cancel()
	}
}

// Progress sends a progress update to the client
func (h *BaseHandler) Progress(step FlowStep, payload interface{}) error {
	h.Flow.mu.Lock()
	h.Flow.State = step
	h.Flow.mu.Unlock()

	return h.Flow.Session.SendProgress(h.Flow.ID, step, payload)
}

// ProgressMessage sends a progress update with just a message
func (h *BaseHandler) ProgressMessage(step FlowStep, message string) error {
	return h.Progress(step, map[string]string{"message": message})
}

// Error sends a flow error to the client
func (h *BaseHandler) Error(step FlowStep, code ErrorCode, message string) error {
	return h.Flow.Session.SendFlowError(h.Flow.ID, step, code, message)
}

// Complete sends a flow completion message
func (h *BaseHandler) Complete(credentials []CredentialResult, redirectURI string) error {
	return h.Flow.Session.SendFlowComplete(h.Flow.ID, credentials, redirectURI)
}

// RequestSign requests a client-side signature
func (h *BaseHandler) RequestSign(ctx context.Context, action SignAction, params SignRequestParams) (*SignResponseMessage, error) {
	return h.Flow.Session.RequestSign(ctx, h.Flow.ID, action, params)
}

// WaitForAction waits for a client action
func (h *BaseHandler) WaitForAction(ctx context.Context, expectedActions ...string) (*FlowActionMessage, error) {
	return h.Flow.Session.WaitForAction(ctx, h.Flow.ID, expectedActions...)
}

// SetData stores flow-specific data
func (h *BaseHandler) SetData(key string, value interface{}) {
	h.Flow.mu.Lock()
	defer h.Flow.mu.Unlock()
	h.Flow.Data[key] = value
}

// GetData retrieves flow-specific data
func (h *BaseHandler) GetData(key string) (interface{}, bool) {
	h.Flow.mu.RLock()
	defer h.Flow.mu.RUnlock()
	val, ok := h.Flow.Data[key]
	return val, ok
}
