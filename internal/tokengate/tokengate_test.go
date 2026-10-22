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
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage/memory"
)

type erroringUsers struct{}

func (erroringUsers) GetAuthCutoff(context.Context, domain.UserID) (time.Time, error) {
	return time.Time{}, errors.New("db down")
}

func (erroringUsers) GetDeletionTombstone(context.Context, string) (*domain.DeletionTombstone, error) {
	return nil, errors.New("db down")
}

// notFoundUsers has no record for any user and a tombstone read that fails: the
// tombstone read must fail closed.
type notFoundUsers struct{ erroringUsers }

func (notFoundUsers) GetAuthCutoff(context.Context, domain.UserID) (time.Time, error) {
	return time.Time{}, storage.ErrNotFound
}

func TestGate_DeletedUser(t *testing.T) {
	ctx := context.Background()
	store := memory.NewStore()
	uid := domain.NewUserID()
	require.NoError(t, store.Users().Create(ctx, &domain.User{UUID: uid}))
	g := New(store.Users())
	iat := time.Now().Add(-time.Minute)

	require.NoError(t, g.Check(ctx, uid.String(), iat), "live user, no cut-off")

	require.NoError(t, store.Users().Delete(ctx, uid))
	assert.NoError(t, g.Check(ctx, uid.String(), iat), "no record and no tombstone: an external identity, not judged")
	assert.NoError(t, RefuseNow(WithSubject(ctx, uid.String(), iat), store.Users()))

	require.NoError(t, store.Users().PutDeletionTombstone(ctx, &domain.DeletionTombstone{
		UserID: uid.String(), DeletedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour),
	}))
	err := g.Check(ctx, uid.String(), iat)
	assert.ErrorIs(t, err, ErrAccountDeleted)
	assert.ErrorIs(t, err, ErrRevoked, "callers that map ErrRevoked need no change")
	assert.ErrorIs(t, g.Check(ctx, uid.String(), time.Now().Add(time.Hour)), ErrRevoked, "a token issued after the deletion is refused as well")
	assert.ErrorIs(t, RefuseNow(WithSubject(ctx, uid.String(), iat), store.Users()), ErrRevoked)
	assert.NoError(t, g.Check(ctx, domain.NewUserID().String(), iat), "other users are unaffected")

	// A failing tombstone read is an error, never a pass.
	err = New(notFoundUsers{}).Check(ctx, uid.String(), iat)
	require.Error(t, err)
	assert.NotErrorIs(t, err, ErrRevoked)
	require.Error(t, RefuseNow(WithSubject(ctx, uid.String(), iat), notFoundUsers{}))
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

func TestRefuseLoaded(t *testing.T) {
	cutoff := time.Now().Truncate(time.Second)
	ctx := context.Background()

	assert.NoError(t, RefuseLoaded(ctx, cutoff), "no token iat on the context: not judged")
	assert.NoError(t, RefuseLoaded(WithIssuedAt(ctx, cutoff.Add(-time.Hour)), time.Time{}), "no cut-off refuses nothing")
	assert.ErrorIs(t, RefuseLoaded(WithIssuedAt(ctx, cutoff.Add(-time.Second)), cutoff), ErrRevoked)
	assert.ErrorIs(t, RefuseLoaded(WithIssuedAt(ctx, cutoff), cutoff), ErrRevoked, "same second as the cut-off")
	assert.ErrorIs(t, RefuseLoaded(WithIssuedAt(ctx, time.Time{}), cutoff), ErrRevoked, "an unreadable iat cannot prove it postdates the cut-off")
	assert.NoError(t, RefuseLoaded(WithIssuedAt(ctx, cutoff.Add(time.Second)), cutoff))
}

func TestRefuseNow(t *testing.T) {
	ctx := context.Background()
	store := memory.NewStore()
	cutoff := time.Now().Truncate(time.Second)
	uid := domain.NewUserID()
	require.NoError(t, store.Users().Create(ctx, &domain.User{UUID: uid}))
	require.NoError(t, store.Users().InvalidateAuthBefore(ctx, uid, cutoff))

	assert.NoError(t, RefuseNow(ctx, store.Users()), "no token on the context: not judged")
	assert.NoError(t, RefuseNow(WithSubject(ctx, uid.String(), cutoff.Add(-time.Hour)), nil), "no lookup: not judged")
	assert.ErrorIs(t, RefuseNow(WithSubject(ctx, uid.String(), cutoff.Add(-time.Hour)), store.Users()), ErrRevoked)
	assert.NoError(t, RefuseNow(WithSubject(ctx, uid.String(), cutoff.Add(time.Hour)), store.Users()))
	assert.NoError(t, RefuseNow(WithSubject(ctx, "unknown", cutoff.Add(-time.Hour)), store.Users()), "the gate is not an existence check")
	err := RefuseNow(WithSubject(ctx, uid.String(), cutoff), erroringUsers{})
	require.Error(t, err)
	assert.NotErrorIs(t, err, ErrRevoked, "a store failure is not a revocation")
}

// NoUserRecords is the registry's explicit "no user database" lookup: a gate
// over it must never refuse a token, however old or odd, for cut-off reasons.
func TestNoUserRecords_NeverRefuses(t *testing.T) {
	g := New(NoUserRecords{})
	require.NotNil(t, g, "NoUserRecords is a real lookup, not the nil-gate shortcut")
	now := time.Now()
	for name, iat := range map[string]time.Time{
		"recent": now, "ancient": now.Add(-10 * 365 * 24 * time.Hour), "zero iat": {},
	} {
		assert.NoError(t, g.Check(context.Background(), "any-user", iat), name)
	}
	_, err := NoUserRecords{}.GetAuthCutoff(context.Background(), domain.UserIDFromString("u"))
	assert.ErrorIs(t, err, storage.ErrNotFound)
	assert.NoError(t, RefuseIfDeleted(context.Background(), NoUserRecords{}, "u"))
}
