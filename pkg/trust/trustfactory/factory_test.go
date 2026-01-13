package trustfactory

import (
	"context"
	"testing"

	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

func TestNewFromConfig(t *testing.T) {
	ctx := context.Background()

	t.Run("nil config returns nil", func(t *testing.T) {
		eval, err := NewFromConfig(ctx, nil)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if eval != nil {
			t.Error("expected nil evaluator")
		}
	})

	t.Run("empty type returns nil", func(t *testing.T) {
		eval, err := NewFromConfig(ctx, &config.TrustConfig{Type: ""})
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if eval != nil {
			t.Error("expected nil evaluator")
		}
	})

	t.Run("type 'none' returns nil", func(t *testing.T) {
		eval, err := NewFromConfig(ctx, &config.TrustConfig{Type: "none"})
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if eval != nil {
			t.Error("expected nil evaluator")
		}
	})

	t.Run("unknown type returns error", func(t *testing.T) {
		_, err := NewFromConfig(ctx, &config.TrustConfig{Type: "invalid"})
		if err == nil {
			t.Error("expected error for unknown type")
		}
	})

	t.Run("authzen without base_url returns error", func(t *testing.T) {
		_, err := NewFromConfig(ctx, &config.TrustConfig{Type: "authzen"})
		if err == nil {
			t.Error("expected error for missing base_url")
		}
	})

	t.Run("authzen with base_url creates evaluator", func(t *testing.T) {
		cfg := &config.TrustConfig{
			Type: "authzen",
			AuthZEN: config.AuthZENConfig{
				BaseURL: "https://pdp.example.com",
			},
		}
		eval, err := NewFromConfig(ctx, cfg)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if eval == nil {
			t.Error("expected evaluator to be created")
		}
		if eval.Name() != "authzen" {
			t.Errorf("expected name 'authzen', got '%s'", eval.Name())
		}
	})

	t.Run("composite with authzen creates evaluator", func(t *testing.T) {
		cfg := &config.TrustConfig{
			Type: "composite",
			AuthZEN: config.AuthZENConfig{
				BaseURL: "https://pdp.example.com",
			},
		}
		eval, err := NewFromConfig(ctx, cfg)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if eval == nil {
			t.Error("expected evaluator to be created")
		}
		if eval.Name() != "composite" {
			t.Errorf("expected name 'composite', got '%s'", eval.Name())
		}
	})
}
