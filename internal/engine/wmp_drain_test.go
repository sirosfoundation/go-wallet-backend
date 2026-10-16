package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/sirosfoundation/go-wmp/pkg/wmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWMP_Drain_RejectsNewRequests(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)
	sid := createWMPSession(t, a)

	a.Drain()
	a.Drain() // idempotent

	body := wmpRequest("1", "wmp.session.create", wmp.SessionCreateParams{
		WMP:      wmp.Metadata{Version: wmp.Version},
		Security: wmp.SecurityMode{Mode: "tls"},
		Auth:     &wmp.AuthObject{Type: "bearer", Token: testToken("user-2", "tenant-a")},
	})
	req := httptest.NewRequest(http.MethodPost, WMPRPCPath, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+testToken("user-2", "tenant-a"))
	w := httptest.NewRecorder()
	a.HandleWMPRPC(w, req)
	assert.Equal(t, http.StatusServiceUnavailable, w.Code)

	req = httptest.NewRequest(http.MethodGet, WMPEventsPath+"?session_id="+sid, nil)
	req.Header.Set("Authorization", "Bearer "+testToken("user-1", "tenant-a"))
	w = httptest.NewRecorder()
	a.HandleWMPEvents(w, req)
	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

// A session.create that was admitted before the drain but reaches the
// publication step after it must be refused, not leaked.
func TestWMP_Drain_RefusesSessionCreateAtPublication(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)
	a.Drain()

	body := wmpRequest("1", "wmp.session.create", wmp.SessionCreateParams{
		WMP:      wmp.Metadata{Version: wmp.Version},
		Security: wmp.SecurityMode{Mode: "tls"},
		Auth:     &wmp.AuthObject{Type: "bearer", Token: testToken("user-3", "tenant-a")},
	})
	resp, err := a.HandleRPC(context.Background(), "", "", "", body)
	require.NoError(t, err)
	var r wmp.Response
	require.NoError(t, json.Unmarshal(resp, &r))
	require.NotNil(t, r.Error)
	assert.Equal(t, wmp.ErrRateLimited, r.Error.Code)

	a.mu.RLock()
	assert.Empty(t, a.peers, "no session may be registered while draining")
	assert.Empty(t, a.eventBufs)
	a.mu.RUnlock()
	assert.Equal(t, 0, int(m.activeConnections.Load()), "the slot must be released")
}

func TestWMP_Close_DrainsFirst(t *testing.T) {
	a, m := testWMPAdapter()
	defer m.Close()
	a.Close()
	assert.True(t, a.isDraining())
}
