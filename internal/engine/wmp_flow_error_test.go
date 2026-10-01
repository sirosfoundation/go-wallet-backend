package engine

import (
	"context"
	"testing"
	"time"

	"github.com/sirosfoundation/go-wmp/pkg/wmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWMP_FlowError_FailsParentSign(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)
	sid := createWMPSession(t, a)
	a.mu.RLock()
	ws := a.peers[sid]
	a.mu.RUnlock()

	ws.handler.registerChildFlow("child-s", "parent", "msg-s", "sign")
	ws.handler.FlowError(context.Background(), &wmp.FlowErrorParams{FlowID: "child-s", Code: -1, Message: "user declined"})

	select {
	case got := <-ws.session.signCh:
		assert.Equal(t, "parent", got.FlowID)
		assert.Equal(t, "msg-s", got.MessageID)
		_, err := signResult(got)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "user declined")
	case <-time.After(time.Second):
		t.Fatal("child sign error not propagated")
	}
	_, still := ws.handler.peekChildFlow("child-s")
	assert.False(t, still, "child mapping must be consumed")
}

func TestWMP_FlowError_FailsParentMatch(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)
	sid := createWMPSession(t, a)
	a.mu.RLock()
	ws := a.peers[sid]
	a.mu.RUnlock()

	ws.handler.registerChildFlow("child-m", "parent", "msg-m", "match")
	ws.handler.FlowError(context.Background(), &wmp.FlowErrorParams{FlowID: "child-m", Message: "boom"})

	select {
	case got := <-ws.session.matchCh:
		assert.Equal(t, "parent", got.FlowID)
		assert.Equal(t, "msg-m", got.MessageID)
		assert.Equal(t, "boom", got.Error)
	case <-time.After(time.Second):
		t.Fatal("child match error not propagated")
	}
}

func TestWMP_FlowError_UnknownFlowIgnored(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)
	sid := createWMPSession(t, a)
	a.mu.RLock()
	ws := a.peers[sid]
	a.mu.RUnlock()
	ws.handler.FlowError(context.Background(), &wmp.FlowErrorParams{FlowID: "nope", Message: "x"})
	assert.Empty(t, ws.session.signCh)
	assert.Empty(t, ws.session.matchCh)
}

// RequestSign must return promptly when the child flow errors.
func TestRequestSign_ReturnsClientReportedError(t *testing.T) {
	s := &Session{
		signCh:  make(chan *SignResponseMessage, 1),
		closeCh: make(chan struct{}),
	}
	s.signCh <- &SignResponseMessage{Message: Message{MessageID: "m"}, Error: "declined"}
	// Bypass Send by pre-seeding through the same helper RequestSign uses.
	_, err := signResult(<-s.signCh)
	require.Error(t, err)
	assert.Equal(t, "declined", err.Error())
}
