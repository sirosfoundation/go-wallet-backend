package storage

import "time"

// UndoLogMaxAge is how long a write stays undoable. A conditional rollback
// (DeleteIfUnchanged, RestoreIfUnchanged, RestoreAttestation) runs within the
// deadline of the request that made the write, so an entry older than this can
// no longer have a live rollback; it is dropped, and a rollback naming its
// write token then reports ErrNotFound exactly as for a token that is not on
// the record. It bounds the log without a confirm call, and a crash can never
// leave a permanent pending marker.
const UndoLogMaxAge = 2 * time.Minute

// UndoLogMaxLen is the most writes a record remembers; the oldest are dropped
// first. Sixteen concurrent unconfirmed writes to one record is far beyond any
// real concurrency.
const UndoLogMaxLen = 16

// UndoEntry is one write a record remembers: the write token it set, when, and
// the record as it was just before (nil when the write created the record).
type UndoEntry[T any] struct {
	Token  string    `bson:"token"`
	At     time.Time `bson:"at"`
	Before *T        `bson:"before"`
}

// UndoLog is a record's undo log, oldest write first; the last entry is the
// write that produced the record's current WriteToken. The stores keep it next
// to the record (a side map in memory, a bson field in MongoDB), never in the
// domain struct, so it cannot reach an API response or an export.
//
// Rolling back a write by its token (Take):
//   - the head (the newest write): the record goes back to the entry's Before
//     snapshot, including that snapshot's own write token, so the write below
//     becomes the head again and its own rollback is armed;
//   - a write with newer writes on top: it is spliced out and the next write's
//     Before becomes this write's Before, leaving the newer write's values in
//     place (a rollback of that newer write then restores the state without
//     this one);
//   - a token that is not in the log (confirmed long ago, pruned, never
//     written): UndoMissing, nothing to undo.
type UndoLog[T any] []UndoEntry[T]

// UndoKind says what Take did.
type UndoKind int

const (
	UndoMissing UndoKind = iota // token not in the log
	UndoHead                    // newest write removed: restore the returned before (nil: delete)
	UndoSpliced                 // an older write removed: current values stay
)

// Prune drops entries older than UndoLogMaxAge relative to now.
func (l *UndoLog[T]) Prune(now time.Time) {
	cutoff := now.Add(-UndoLogMaxAge)
	kept := (*l)[:0]
	for _, e := range *l {
		if !e.At.Before(cutoff) {
			kept = append(kept, e)
		}
	}
	*l = kept
}

// Push records a write and prunes by age and length.
func (l *UndoLog[T]) Push(now time.Time, token string, before *T) {
	l.Prune(now)
	*l = append(*l, UndoEntry[T]{Token: token, At: now, Before: before})
	if n := len(*l) - UndoLogMaxLen; n > 0 {
		*l = append(UndoLog[T](nil), (*l)[n:]...)
	}
}

// Take removes the write with this token from the log. For UndoHead and
// UndoSpliced it returns the removed write's Before snapshot.
func (l *UndoLog[T]) Take(now time.Time, token string) (UndoKind, *T) {
	l.Prune(now)
	idx := -1
	for i, e := range *l {
		if e.Token == token {
			idx = i
			break
		}
	}
	if token == "" || idx < 0 {
		return UndoMissing, nil
	}
	before := (*l)[idx].Before
	if idx == len(*l)-1 {
		*l = (*l)[:idx]
		return UndoHead, before
	}
	(*l)[idx+1].Before = before
	*l = append((*l)[:idx], (*l)[idx+1:]...)
	return UndoSpliced, before
}

// Peek returns the Before snapshot of the write with this token and whether it
// is in the (age-pruned) log, without changing the log.
func (l UndoLog[T]) Peek(now time.Time, token string) (*T, bool) {
	cutoff := now.Add(-UndoLogMaxAge)
	for _, e := range l {
		if token != "" && e.Token == token && !e.At.Before(cutoff) {
			return e.Before, true
		}
	}
	return nil, false
}
