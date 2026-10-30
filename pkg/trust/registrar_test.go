package trust

import (
	"context"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

type actionRecorder struct {
	decision bool
	actions  []string
}

func (a *actionRecorder) Evaluate(_ context.Context, req *EvaluationRequest) (*EvaluationResponse, error) {
	a.actions = append(a.actions, req.Action)
	return &EvaluationResponse{Decision: a.decision}, nil
}
func (a *actionRecorder) Name() string                           { return "recorder" }
func (a *actionRecorder) SupportedResourceTypes() []ResourceType { return nil }
func (a *actionRecorder) Healthy() bool                          { return true }

func TestEvaluateRegistrar(t *testing.T) {
	km := &KeyMaterial{Type: "x5c", X5C: []string{"AAAA"}}

	rec := &actionRecorder{decision: true}
	cfg := &config.Config{}
	cfg.Trust.PDPURL = "http://pdp.test"
	svc := NewService(cfg, zap.NewNop(), func(string, time.Duration) (TrustEvaluator, error) { return rec, nil })

	info, err := svc.EvaluateRegistrar(context.Background(), "https://issuer.example", "", km)
	if err != nil || !info.Trusted {
		t.Fatalf("trusted registrar: %+v, %v", info, err)
	}
	if len(rec.actions) != 1 || rec.actions[0] != RegistrarAction {
		t.Errorf("action = %v, want [%s]: a dedicated policy must be targetable", rec.actions, RegistrarAction)
	}

	// No PDP fails closed.
	none := NewService(&config.Config{}, zap.NewNop(), func(string, time.Duration) (TrustEvaluator, error) { return rec, nil })
	info, err = none.EvaluateRegistrar(context.Background(), "https://issuer.example", "", km)
	if err != nil || info.Trusted || info.Framework != FrameworkNone {
		t.Errorf("no PDP must be untrusted: %+v, %v", info, err)
	}
}
