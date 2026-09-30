package service

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type recordingCleaner struct {
	users []string
	err   error
}

func (r *recordingCleaner) DeleteByUser(_ context.Context, userID string) error {
	r.users = append(r.users, userID)
	return r.err
}

func TestMultiSessionCleaner_DeleteByUser(t *testing.T) {
	ctx := context.Background()

	t.Run("fans out to every cleaner and skips nil entries", func(t *testing.T) {
		a, b := &recordingCleaner{}, &recordingCleaner{}
		m := MultiSessionCleaner{a, nil, b}
		require.NoError(t, m.DeleteByUser(ctx, "alice"))
		assert.Equal(t, []string{"alice"}, a.users)
		assert.Equal(t, []string{"alice"}, b.users)
	})

	t.Run("a failing cleaner does not stop the others; first error is returned", func(t *testing.T) {
		errA, errB := errors.New("a failed"), errors.New("b failed")
		a, b, c := &recordingCleaner{err: errA}, &recordingCleaner{err: errB}, &recordingCleaner{}
		m := MultiSessionCleaner{a, b, c}
		err := m.DeleteByUser(ctx, "bob")
		assert.ErrorIs(t, err, errA)
		assert.NotErrorIs(t, err, errB)
		assert.Equal(t, []string{"bob"}, c.users, "later cleaners still run")
	})

	t.Run("empty and all-nil cleaners are no-ops", func(t *testing.T) {
		assert.NoError(t, MultiSessionCleaner{}.DeleteByUser(ctx, "x"))
		assert.NoError(t, MultiSessionCleaner{nil}.DeleteByUser(ctx, "x"))
	})
}
