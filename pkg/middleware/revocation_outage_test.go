package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/sirosfoundation/go-tokenauth/claims"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/service"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage/memory"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

// unreachableMongoStore is a storage.Store that reports a MongoDB database
// nobody is listening on, so service.NewServices selects the MongoDB
// revocation store and cannot set it up.
type unreachableMongoStore struct {
	storage.Store
	db *mongo.Database
}

func (s unreachableMongoStore) Database() *mongo.Database { return s.db }

// With MongoDB selected and unreachable, the real service wiring must refuse
// authenticated requests rather than accept them unchecked.
func TestMongoOutage_RealWiringRefuses(t *testing.T) {
	client, err := mongo.Connect(context.Background(), options.Client().
		ApplyURI("mongodb://127.0.0.1:1").SetServerSelectionTimeout(200*time.Millisecond))
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Disconnect(context.Background()) })

	cfg := &config.Config{}
	cfg.Server.RPID = "localhost"
	cfg.Server.RPOrigin = "http://localhost"
	cfg.Security.TokenBlacklist = config.TokenBlacklistConfig{Enabled: true} // default backend: MongoDB here

	store := unreachableMongoStore{Store: memory.NewStore(), db: client.Database("unreachable")}
	svc := service.NewServices(store, cfg, zap.NewNop())

	v, key, issuer := setupTokenAuthTest(t)
	tenants := &stubTenantStore{tenants: map[domain.TenantID]*domain.Tenant{
		"test-tenant": {ID: "test-tenant", Enabled: true},
	}}
	token := signToken(t, key, issuer, claims.AccessTokenClaims{
		Claims:   jwt.Claims{Subject: "user-1", Audience: jwt.Audience{testTokenAudience}},
		TenantID: "test-tenant",
		TAC:      "rwl",
	})
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(TokenAuthMiddleware(v, tenants, svc.TokenBlacklist, zap.NewNop()))
	router.GET("/test", func(c *gin.Context) { c.Status(http.StatusOK) })

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	require.Equal(t, http.StatusServiceUnavailable, w.Code, w.Body.String())
}
