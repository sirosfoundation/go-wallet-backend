package tokengate

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage/memory"
)

type erroringUsers struct{}

func (erroringUsers) GetAuthCutoff(context.Context, domain.UserID) (time.Time, error) {
	return time.Time{}, errors.New("db down")
}

func TestGate_Check(t *testing.T) {
	ctx := context.Background()
	store := memory.NewStore()
	cutoff := time.Now().Add(-time.Minute).Truncate(time.Second)
	uid := domain.NewUserID()
	require.NoError(t, store.Users().Create(ctx, &domain.User{UUID: uid}))
	require.NoError(t, store.Users().InvalidateAuthBefore(ctx, uid, cutoff))
	fresh := domain.NewUserID()
	require.NoError(t, store.Users().Create(ctx, &domain.User{UUID: fresh}))
	g := New(store.Users())

	assert.NoError(t, (*Gate)(nil).Check(ctx, uid.String(), time.Time{}), "nil gate is a no-op")
	assert.NoError(t, g.Check(ctx, "", time.Time{}), "anonymous tokens pass")
	assert.NoError(t, g.Check(ctx, "unknown-user", cutoff.Add(-time.Hour)), "unknown users are not the gate's business")
	assert.NoError(t, g.Check(ctx, fresh.String(), time.Time{}), "no cut-off: even a token without iat passes")

	assert.ErrorIs(t, g.Check(ctx, uid.String(), cutoff.Add(-time.Second)), ErrRevoked, "issued before the cut-off")
	assert.ErrorIs(t, g.Check(ctx, uid.String(), cutoff), ErrRevoked, "issued in the same second as the cut-off")
	assert.ErrorIs(t, g.Check(ctx, uid.String(), time.Time{}), ErrRevoked, "no iat cannot prove it postdates the cut-off")
	assert.NoError(t, g.Check(ctx, uid.String(), cutoff.Add(time.Second)), "issued after the cut-off")

	err := New(erroringUsers{}).Check(ctx, uid.String(), time.Now())
	require.Error(t, err)
	assert.NotErrorIs(t, err, ErrRevoked, "a store failure is not reported as a revocation")
}

func TestIssuedAt(t *testing.T) {
	iat := time.Now().Truncate(time.Second)
	raw, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"iat": iat.Unix(), "sub": "x"}).SignedString([]byte("k"))
	require.NoError(t, err)
	assert.True(t, IssuedAt(raw).Equal(iat))
	assert.True(t, IssuedAt("not-a-jwt").IsZero())
	noIat, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"sub": "x"}).SignedString([]byte("k"))
	assert.True(t, IssuedAt(noIat).IsZero())

	assert.True(t, IssuedAtFromClaims(jwt.MapClaims{"iat": float64(iat.Unix())}).Equal(iat), "json-decoded number")
	assert.True(t, IssuedAtFromClaims(jwt.MapClaims{"iat": iat.Unix()}).Equal(iat), "int64")
	assert.True(t, IssuedAtFromClaims(jwt.MapClaims{}).IsZero())
}
