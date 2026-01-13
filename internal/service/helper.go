package service

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"net/url"
	"time"

	"go.uber.org/zap"
)

// HelperService provides utility functions for the wallet
type HelperService struct {
	logger *zap.Logger
}

// CertificateResponse contains the certificate chain
type CertificateResponse struct {
	X5C []string `json:"x5c"`
}

// NewHelperService creates a new HelperService
func NewHelperService(logger *zap.Logger) *HelperService {
	return &HelperService{
		logger: logger.Named("helper-service"),
	}
}

// GetCertificateChain fetches the SSL certificate chain from a URL
func (s *HelperService) GetCertificateChain(ctx context.Context, targetURL string) (*CertificateResponse, error) {
	// Parse the URL
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}

	if parsedURL.Scheme != "https" {
		return nil, fmt.Errorf("URL must use HTTPS scheme")
	}

	// Determine the host and port
	host := parsedURL.Hostname()
	port := parsedURL.Port()
	if port == "" {
		port = "443"
	}
	address := net.JoinHostPort(host, port)

	s.logger.Debug("Fetching certificate chain",
		zap.String("url", targetURL),
		zap.String("address", address),
	)

	// Create a TLS connection to get the certificate
	dialer := &net.Dialer{
		Timeout: 10 * time.Second,
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", address, &tls.Config{
		ServerName: host,
		// We want to get the certificate even if it's invalid
		InsecureSkipVerify: false,
	})
	if err != nil {
		// Try again with InsecureSkipVerify to get self-signed certs
		conn, err = tls.DialWithDialer(dialer, "tcp", address, &tls.Config{
			ServerName:         host,
			InsecureSkipVerify: true,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to connect: %w", err)
		}
	}
	defer func() { _ = conn.Close() }()

	// Get the peer certificates
	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, fmt.Errorf("no certificates found")
	}

	// Build the x5c chain (base64 encoded DER certificates)
	x5c := make([]string, 0, len(state.PeerCertificates))
	for _, cert := range state.PeerCertificates {
		x5c = append(x5c, base64.StdEncoding.EncodeToString(cert.Raw))
	}

	s.logger.Debug("Certificate chain retrieved",
		zap.Int("chain_length", len(x5c)),
		zap.String("subject", state.PeerCertificates[0].Subject.String()),
	)

	return &CertificateResponse{
		X5C: x5c,
	}, nil
}
