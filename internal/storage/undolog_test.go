package storage

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUndoLog_TakeSemantics(t *testing.T) {
	now := time.Unix(1000, 0)
	one, two, three := 1, 2, 3
	build := func() *UndoLog[int] {
		l := &UndoLog[int]{}
		l.Push(now, "a", nil)
		l.Push(now, "b", &one)
		l.Push(now, "c", &two)
		return l
	}

	t.Run("head returns its before and leaves the log below", func(t *testing.T) {
		l := build()
		kind, before := l.Take(now, "c")
		assert.Equal(t, UndoHead, kind)
		assert.Equal(t, &two, before)
		assert.Len(t, *l, 2)
	})
	t.Run("a non-head write is spliced and the next write inherits its before", func(t *testing.T) {
		l := build()
		kind, before := l.Take(now, "b")
		assert.Equal(t, UndoSpliced, kind)
		assert.Equal(t, &one, before)
		require.Len(t, *l, 2)
		assert.Equal(t, "c", (*l)[1].Token)
		assert.Equal(t, &one, (*l)[1].Before)
	})
	t.Run("unknown and empty tokens are missing", func(t *testing.T) {
		l := build()
		kind, _ := l.Take(now, "zzz")
		assert.Equal(t, UndoMissing, kind)
		kind, _ = l.Take(now, "")
		assert.Equal(t, UndoMissing, kind)
		assert.Len(t, *l, 3)
	})
	t.Run("entries older than the max age are dropped", func(t *testing.T) {
		l := build()
		kind, _ := l.Take(now.Add(UndoLogMaxAge+time.Second), "c")
		assert.Equal(t, UndoMissing, kind)
		assert.Empty(t, *l)
	})
	t.Run("the oldest entries are dropped beyond the max length", func(t *testing.T) {
		l := &UndoLog[int]{}
		for i := 0; i < UndoLogMaxLen+4; i++ {
			l.Push(now, fmt.Sprintf("t%d", i), &three)
		}
		assert.Len(t, *l, UndoLogMaxLen)
		assert.Equal(t, "t4", (*l)[0].Token)
		kind, _ := l.Take(now, "t0")
		assert.Equal(t, UndoMissing, kind)
	})
}
