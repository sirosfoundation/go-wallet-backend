package api

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/service"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage/memory"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

// removalFailStore fails holder-data listing once the user record is removed.
type removalFailStore struct {
	storage.Store
	removed atomic.Bool
}

type removalFailUsers struct {
	storage.UserStore
	s *removalFailStore
}

func (s *removalFailStore) Users() storage.UserStore { return &removalFailUsers{s.Store.Users(), s} }

func (u *removalFailUsers) Delete(ctx context.Context, id domain.UserID) error {
	err := u.UserStore.Delete(ctx, id)
	if err == nil {
		u.s.removed.Store(true)
	}
	return err
}

type removalFailCreds struct {
	storage.CredentialStore
	s *removalFailStore
}

func (s *removalFailStore) Credentials() storage.CredentialStore {
	return &removalFailCreds{s.Store.Credentials(), s}
}

func (c *removalFailCreds) GetAllByHolder(ctx context.Context, tid domain.TenantID, did string) ([]*domain.VerifiableCredential, error) {
	if c.s.removed.Load() {
		return nil, errors.New("db down")
	}
	return c.CredentialStore.GetAllByHolder(ctx, tid, did)
}

// When the sweep after the account's removal fails the account is gone, so the
// answer must say so and must not tell the caller to repeat the request.
func TestDeleteUser_PostRemovalCleanupFailureIsNotAskedToRepeat(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfg := &config.Config{
		Server: config.ServerConfig{RPID: "localhost", RPOrigin: "http://localhost:8080"},
		JWT:    config.JWTConfig{Secret: "test-secret", ExpiryHours: 24, Issuer: "test-wallet"},
	}
	inner := memory.NewStore()
	const userID = "user-cleanup-pending"
	require.NoError(t, inner.Users().Create(context.Background(), &domain.User{
		UUID: domain.UserIDFromString(userID), DID: domain.HolderDID(userID),
	}))
	logger := zap.NewNop()
	services := service.NewServices(&removalFailStore{Store: inner}, cfg, logger)
	handlers := NewHandlers(services, cfg, logger, []string{"test"})
	router := gin.New()
	router.DELETE("/user", legacyAuthContext(userID), handlers.DeleteUser)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodDelete, "/user", nil))

	assert.Equal(t, http.StatusAccepted, w.Code, w.Body.String())
	assert.Contains(t, w.Body.String(), errCodeDeletionCleanupPending)
	assert.NotContains(t, w.Body.String(), errCodeDeletionIncomplete)
	assert.NotContains(t, w.Body.String(), "repeat the request to finish")
	_, err := inner.Users().GetByID(context.Background(), domain.UserIDFromString(userID))
	assert.ErrorIs(t, err, storage.ErrNotFound)
}

type failingSecondCleaner struct{ calls int }

func (c *failingSecondCleaner) DeleteByUser(context.Context, string) error {
	c.calls++
	if c.calls >= 2 {
		return errors.New("session store is down")
	}
	return nil
}

type okRevoker struct{}

func (okRevoker) RevokeUser(context.Context, string) error { return nil }

// A session store failing after the user's tokens were revoked for good cannot
// be fixed by repeating the request: the answer must say an operator is needed
// and must not claim the account is deleted or ask the caller to retry.
func TestDeleteUser_OperatorRequiredIsNotAskedToRepeat(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfg := &config.Config{
		Server: config.ServerConfig{RPID: "localhost", RPOrigin: "http://localhost:8080"},
		JWT:    config.JWTConfig{Secret: "test-secret", ExpiryHours: 24, Issuer: "test-wallet"},
	}
	inner := memory.NewStore()
	const userID = "user-operator-required"
	require.NoError(t, inner.Users().Create(context.Background(), &domain.User{
		UUID: domain.UserIDFromString(userID), DID: domain.HolderDID(userID),
	}))
	logger := zap.NewNop()
	services := service.NewServices(inner, cfg, logger)
	services.User.SetTokenBlacklist(okRevoker{})
	services.User.SetSessionCleaner(&failingSecondCleaner{})
	handlers := NewHandlers(services, cfg, logger, []string{"test"})
	router := gin.New()
	router.DELETE("/user", legacyAuthContext(userID), handlers.DeleteUser)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodDelete, "/user", nil))

	assert.Equal(t, http.StatusAccepted, w.Code, w.Body.String())
	assert.Contains(t, w.Body.String(), errCodeDeletionOperatorRequired)
	assert.Contains(t, w.Body.String(), `"result":"PENDING"`)
	assert.NotContains(t, w.Body.String(), errCodeDeletionIncomplete)
	assert.NotContains(t, w.Body.String(), "repeat the request to finish")
	_, err := inner.Users().GetByID(context.Background(), domain.UserIDFromString(userID))
	assert.NoError(t, err, "the record is kept for the operator")
}
