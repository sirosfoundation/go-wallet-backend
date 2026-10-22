package as

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/service"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

// A passkey session created under the default AS config must be able to add and remove passkeys and
// delete the account (i, d), but never delegate or administer (k, a).
func TestPasskeySession_DefaultMaxTACCoversOrdinaryWalletOperations(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfg := &config.ASConfig{SessionTTL: time.Hour, InsecureCookies: true}
	cfg.SetDefaults()
	store := NewMemorySessionStore()
	mock := &mockWebAuthn{finishLoginResp: &service.FinishLoginResponse{UUID: "u1", TenantID: "t1"}}
	h := NewPasskeyHandlers(mock, store, cfg, zap.NewNop())
	router := gin.New()
	router.POST("/auth/passkey/login/finish", h.LoginFinish)

	body, _ := json.Marshal(service.FinishLoginRequest{ChallengeID: "c1"})
	req := httptest.NewRequest(http.MethodPost, "/auth/passkey/login/finish", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Token-Mode", "session")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("login finish: %d %s", w.Code, w.Body.String())
	}
	var sess *Session
	for _, c := range w.Result().Cookies() {
		if c.Name == sessionCookieInsecure {
			sess, _ = store.Get(context.Background(), c.Value)
		}
	}
	if sess == nil {
		t.Fatal("no session created")
	}
	if !TAC("rwlid").IsSubsetOf(sess.MaxTAC) {
		t.Errorf("session max_tac %q must cover rwlid", sess.MaxTAC)
	}
	if sess.MaxTAC.Has(TACDelegate) || sess.MaxTAC.Has(TACAdmin) {
		t.Errorf("session max_tac %q must not include k or a", sess.MaxTAC)
	}
}
