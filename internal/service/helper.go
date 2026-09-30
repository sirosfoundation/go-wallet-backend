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

	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

// HelperService provides utility functions for the wallet
type HelperService struct {
	logger *zap.Logger

	// dial opens the raw TCP connection GetCertificateChain performs its own
	// TLS handshake over. It is config.HTTPClientConfig.GuardedDialContext(),
	// not a plain net.Dialer: this is a caller-supplied URL reachable from an
	// authenticated endpoint, so it must carry the same address policy
	// (private/loopback/link-local/cloud-metadata blocked unless
	// AllowPrivateIPs) that every other outbound fetch in this backend goes
	// through via config.HTTPClientConfig.NewHTTPClient - see that method's
	// docs for why. Without it, this handler is a blind in-cluster SSRF/port
	// scanner: any URL, including internal service addresses, gets dialed
	// and its TLS certificate (subject, SANs, issuing CA) handed back.
	dial func(ctx context.Context, network, addr string) (net.Conn, error)
}

// CertificateResponse contains the certificate chain
type CertificateResponse struct {
	X5C []string `json:"x5c"`
}

// NewHelperService creates a new HelperService.
func NewHelperService(logger *zap.Logger, httpClientCfg config.HTTPClientConfig) *HelperService {
	return &HelperService{
		logger: logger.Named("helper-service"),
		dial:   httpClientCfg.GuardedDialContext(),
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

	// Connect and read the certificate, verified.
	state, err := s.tlsHandshake(ctx, address, host, false)
	if err != nil {
		// Try again without verification, to get self-signed certs.
		state, err = s.tlsHandshake(ctx, address, host, true)
		if err != nil {
			return nil, fmt.Errorf("failed to connect: %w", err)
		}
	}

	// Get the peer certificates
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

// tlsHandshake dials address through s.dial - the address-policy-checked
// dialer, never a raw net.Dialer - and performs a TLS handshake over the
// resulting connection. Unlike tls.DialWithDialer, which resolves and dials
// the hostname itself, this never lets anything but s.dial open a network
// connection, so the address policy sees the same connection that is
// actually made (no second, unchecked resolution to race against).
func (s *HelperService) tlsHandshake(ctx context.Context, address, host string, insecureSkipVerify bool) (tls.ConnectionState, error) {
	// Bounds lookup + dial + handshake together; s.dial's own net.Dialer
	// timeout only covers the dial itself once a checked address is in hand.
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	rawConn, err := s.dial(ctx, "tcp", address)
	if err != nil {
		return tls.ConnectionState{}, err
	}

	tlsConn := tls.Client(rawConn, &tls.Config{
		ServerName: host,
		// We want to get the certificate even if it's invalid - the caller
		// retries with this set once an already-address-checked connection's
		// verified handshake fails.
		InsecureSkipVerify: insecureSkipVerify, //nolint:gosec // deliberate: see above
	})
	defer func() { _ = tlsConn.Close() }()

	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return tls.ConnectionState{}, err
	}
	return tlsConn.ConnectionState(), nil
}
