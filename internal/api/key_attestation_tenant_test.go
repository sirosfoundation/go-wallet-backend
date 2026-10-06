package api

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/service"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage/memory"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

// The tenant the KA instance check judges comes from the handler, via a
// context value that the service silently does not judge when absent. This
// goes through the real handler so that dropping the handler's call fails.
func TestHandlers_GenerateKeyAttestation_InstanceTenantScoping(t *testing.T) {
	gin.SetMode(gin.TestMode)
	dir := t.TempDir()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalECPrivateKey(key)
	certDER, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{SerialNumber: big.NewInt(1)}, &x509.Certificate{SerialNumber: big.NewInt(1)}, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyPath, certPath := filepath.Join(dir, "key.pem"), filepath.Join(dir, "cert.pem")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{}
	cfg.JWT = config.JWTConfig{Secret: "test-secret-that-is-at-least-32-bytes-long", ExpiryHours: 24, Issuer: "test-wallet"}
	cfg.WalletProvider.PrivateKeyPath = keyPath
	cfg.WalletProvider.CertificatePath = certPath
	cfg.WalletProvider.Attestation = config.AttestationConfig{KAExpirySeconds: 15}

	store := memory.NewStore()
	services := service.NewServices(store, cfg, zap.NewNop())
	if !services.WalletProvider.IsSupported() {
		t.Fatal("key attestation must be supported with the configured key and certificate")
	}
	if err := store.WalletInstances().Upsert(context.Background(), &domain.WalletInstance{
		ID: "inst-b", TenantID: "tenant-b", Status: domain.InstanceStatusActive,
	}); err != nil {
		t.Fatal(err)
	}
	handlers := NewHandlers(services, cfg, zap.NewNop(), []string{"test"})

	post := func(tenant string) *httptest.ResponseRecorder {
		router := gin.New()
		router.POST("/ka", func(c *gin.Context) {
			c.Set("tenant_id", tenant) // as AuthMiddleware sets it from the JWT
			handlers.GenerateKeyAttestation(c)
		})
		body := `{"jwks":[{"kty":"EC","crv":"P-256","x":"a","y":"b"}],"openid4vci":{"nonce":"n"},"wallet_instance_id":"inst-b"}`
		req := httptest.NewRequest(http.MethodPost, "/ka", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w
	}

	if w := post("tenant-a"); w.Code != http.StatusForbidden {
		t.Fatalf("an instance of another tenant must be refused with 403, got %d %s", w.Code, w.Body.String())
	}
	if w := post("tenant-b"); w.Code != http.StatusOK {
		t.Fatalf("the owning tenant must be accepted, got %d %s", w.Code, w.Body.String())
	}
}
