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
	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/service"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage/memory"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

func writeSigningFiles(t *testing.T) (keyPath, certPath string) {
	t.Helper()
	dir := t.TempDir()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1)}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyPath, certPath = filepath.Join(dir, "k.pem"), filepath.Join(dir, "c.pem")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return keyPath, certPath
}

// A wallet_instance_id owned by another tenant or user must not lend its
// platform attestation to the caller, in the real handler, with the policy
// disabled (the legacy path).
func TestHandlers_KeyAttestation_ForeignInstanceDoesNotRaiseClaims(t *testing.T) {
	gin.SetMode(gin.TestMode)
	keyPath, certPath := writeSigningFiles(t)
	cfg := &config.Config{JWT: config.JWTConfig{Secret: "s", Issuer: "i"}}
	cfg.WalletProvider.PrivateKeyPath, cfg.WalletProvider.CertificatePath = keyPath, certPath
	store := memory.NewStore()
	owner := domain.UserIDFromString("owner")
	if err := store.WalletInstances().Upsert(context.Background(), &domain.WalletInstance{
		ID: "inst", TenantID: "tenant-a", UserID: &owner, AttestationSource: "platform_attested",
	}); err != nil {
		t.Fatal(err)
	}
	services := service.NewServices(store, cfg, zap.NewNop())
	h := NewHandlers(services, cfg, zap.NewNop(), []string{"test"})

	call := func(tenant, user string) string {
		router := gin.New()
		router.POST("/ka", func(c *gin.Context) {
			c.Set("tenant_id", tenant)
			c.Set("user_id", user)
			h.GenerateKeyAttestation(c)
		})
		body := `{"jwks":[{"kty":"EC","crv":"P-256","x":"abc","y":"def"}],"openid4vci":{"nonce":"n"},"wallet_instance_id":"inst","security_properties":{"key_storage":["iso_18045_high"]}}`
		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/ka", strings.NewReader(body)))
		if w.Code != http.StatusOK {
			t.Fatalf("status %d: %s", w.Code, w.Body.String())
		}
		raw := w.Body.String()
		i := strings.Index(raw, `"key_attestation":"`)
		tok := raw[i+len(`"key_attestation":"`):]
		tok = tok[:strings.Index(tok, `"`)]
		claims := jwt.MapClaims{}
		if _, _, err := jwt.NewParser(jwt.WithoutClaimsValidation()).ParseUnverified(tok, claims); err != nil {
			t.Fatal(err)
		}
		return claims["key_storage"].([]interface{})[0].(string)
	}

	if got := call("tenant-a", "owner"); got != "iso_18045_high" {
		t.Errorf("owner: key_storage = %s, want iso_18045_high", got)
	}
	if got := call("tenant-b", "owner"); got != "iso_18045_basic" {
		t.Errorf("other tenant: key_storage = %s, want iso_18045_basic", got)
	}
	if got := call("tenant-a", "someone-else"); got != "iso_18045_basic" {
		t.Errorf("other user: key_storage = %s, want iso_18045_basic", got)
	}
}
