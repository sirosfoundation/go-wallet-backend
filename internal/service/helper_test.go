package service

import (
	"context"
	"testing"

	"go.uber.org/zap"
)

func TestNewHelperService(t *testing.T) {
	logger := zap.NewNop()

	svc := NewHelperService(logger)

	if svc == nil {
		t.Fatal("expected helper service to not be nil")
	}
}

func TestHelperService_GetCertificateChain_InvalidURL(t *testing.T) {
	logger := zap.NewNop()
	svc := NewHelperService(logger)
	ctx := context.Background()

	_, err := svc.GetCertificateChain(ctx, "://invalid-url")
	if err == nil {
		t.Error("expected error for invalid URL")
	}
}

func TestHelperService_GetCertificateChain_HTTPScheme(t *testing.T) {
	logger := zap.NewNop()
	svc := NewHelperService(logger)
	ctx := context.Background()

	_, err := svc.GetCertificateChain(ctx, "http://example.com")
	if err == nil {
		t.Error("expected error for HTTP scheme (not HTTPS)")
	}
}

func TestHelperService_GetCertificateChain_InvalidHost(t *testing.T) {
	logger := zap.NewNop()
	svc := NewHelperService(logger)
	ctx := context.Background()

	// Use a hostname that won't resolve
	_, err := svc.GetCertificateChain(ctx, "https://invalid-host-that-does-not-exist.example.invalid:443")
	if err == nil {
		t.Error("expected error for invalid host")
	}
}
