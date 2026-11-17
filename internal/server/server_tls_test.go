package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

func writeSelfSigned(t *testing.T, dir, name string) (certPath, keyPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPath = filepath.Join(dir, name+".crt")
	keyPath = filepath.Join(dir, name+".key")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func TestManagerStartFailsOnBadTLSCertificate(t *testing.T) {
	dir := t.TempDir()
	goodCert, goodKey := writeSelfSigned(t, dir, "good")
	_, otherKey := writeSelfSigned(t, dir, "other")
	malformed := filepath.Join(dir, "bad.crt")
	if err := os.WriteFile(malformed, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}

	cases := map[string]config.TLSConfig{
		"missing":   {Enabled: true, CertFile: filepath.Join(dir, "nope.crt"), KeyFile: filepath.Join(dir, "nope.key")},
		"malformed": {Enabled: true, CertFile: malformed, KeyFile: goodKey},
		"mismatch":  {Enabled: true, CertFile: goodCert, KeyFile: otherKey},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := startTestManager(t, &ServerConfig{HTTPAddress: "127.0.0.1", HTTPPort: 0, TLS: tc})
			if err == nil {
				t.Fatal("Start() succeeded with an invalid TLS certificate, want error")
			}
		})
	}
}

func TestManagerStartTLSFailureReleasesBoundListeners(t *testing.T) {
	dir := t.TempDir()
	httpPort := freePort(t)

	// HTTP is plain and binds first; the admin server's TLS then fails.
	_, err := startTestManager(t, &ServerConfig{
		HTTPAddress: "127.0.0.1", HTTPPort: httpPort,
		AdminPort: freePort(t), AdminToken: "test-token",
		AdminTLS: &config.TLSConfig{Enabled: true, CertFile: filepath.Join(dir, "x.crt"), KeyFile: filepath.Join(dir, "x.key")},
	})
	if err == nil {
		t.Fatal("Start() succeeded with a missing admin certificate, want error")
	}

	ln, lerr := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", httpPort))
	if lerr != nil {
		t.Fatalf("HTTP listener was not released after failed Start: %v", lerr)
	}
	_ = ln.Close()
}

func TestManagerStartServesValidTLS(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writeSelfSigned(t, dir, "ok")
	port := freePort(t)

	_, err := startTestManager(t, &ServerConfig{
		HTTPAddress: "127.0.0.1", HTTPPort: port,
		TLS: config.TLSConfig{Enabled: true, CertFile: certPath, KeyFile: keyPath, MinVersion: "tls13"},
	})
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	// The files are no longer needed once Start returned.
	_ = os.Remove(certPath)
	_ = os.Remove(keyPath)

	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, //nolint:gosec // self-signed test cert
	}
	var resp *http.Response
	for i := 0; i < 50; i++ {
		resp, err = client.Get(fmt.Sprintf("https://127.0.0.1:%d/status", port))
		if err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("TLS request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.TLS == nil || resp.TLS.Version != tls.VersionTLS13 {
		t.Errorf("negotiated TLS state = %+v, want TLS 1.3", resp.TLS)
	}
}
