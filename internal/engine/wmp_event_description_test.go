package engine

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/sirosfoundation/go-wmp/pkg/wmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// event_description must survive the WMP -> engine conversion to the issuer.
func TestWMP_CredentialNotification_ForwardsEventDescription(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)
	m.cfg.HTTPClient.AllowPrivateIPs = true // the issuer is a loopback httptest server
	sid := createWMPSession(t, a)
	a.mu.RLock()
	ws := a.peers[sid]
	a.mu.RUnlock()

	bodies := make(chan string, 1)
	issuer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		bodies <- string(b)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer issuer.Close()
	ws.session.notifications.put("flow-d", &notificationContext{
		endpoint: issuer.URL, accessToken: "tok", tokenType: "Bearer",
		notificationID: "n-d", expiresAt: time.Now().Add(time.Minute),
	})

	ws.handler.CredentialNotification(context.Background(), &wmp.CredentialNotificationParams{
		WMP: wmp.Metadata{Version: wmp.Version, SessionID: sid}, FlowID: "flow-d",
		NotificationID: "n-d", Event: "credential_accepted", EventDescription: "stored ok",
	})

	select {
	case b := <-bodies:
		var p notificationRequestBody
		require.NoError(t, json.Unmarshal([]byte(b), &p))
		assert.Equal(t, "stored ok", p.EventDescription)
	case <-time.After(3 * time.Second):
		ev, _ := a.Events(sid)
		select {
		case e := <-ev:
			t.Logf("event: %s", e)
		default:
		}
		t.Fatal("issuer never received the notification")
	}
}
