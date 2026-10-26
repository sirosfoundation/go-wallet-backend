package engine

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

type fakeReplaceable struct {
	events []string
	next   SessionTransport
}

func (f *fakeReplaceable) SendJSON(interface{}) error                  { return nil }
func (f *fakeReplaceable) ReadMessage(context.Context) ([]byte, error) { return nil, nil }
func (f *fakeReplaceable) Close() error                                { return nil }
func (f *fakeReplaceable) retire()                                     { f.events = append(f.events, "retire") }
func (f *fakeReplaceable) handOff(n SessionTransport) {
	f.events = append(f.events, "handoff")
	f.next = n
}

// ReplaceTransport works against the interface alone: retire before the swap,
// handOff (with the successor) after it, and plain transports are just swapped.
func TestSession_ReplaceTransport_UsesInterfaceOnly(t *testing.T) {
	old, next := &fakeReplaceable{}, &fakeReplaceable{}
	s := &Session{transport: old}
	s.ReplaceTransport(next)
	assert.Same(t, next, s.currentTransport())
	assert.Equal(t, []string{"retire", "handoff"}, old.events)
	assert.Same(t, next, old.next)

	plain := &wsTransport{}
	s2 := &Session{transport: plain}
	s2.ReplaceTransport(next)
	assert.Same(t, next, s2.currentTransport())
}
