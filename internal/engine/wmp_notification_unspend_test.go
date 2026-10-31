package engine

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/sirosfoundation/go-wmp/pkg/wmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A failure to obtain the DPoP proof sends nothing to the issuer, so it must not
// spend the notification_id (or the context): the wallet may retry the same
// notification. Once the issuer was contacted the id is spent for good.

// refuseSign is the wallet's refusal of a sign_client_auth sub-flow.
func refuseSign(w *chanWallet, start map[string]any) {
	w.push(map[string]any{"id": start["id"], "result": map[string]any{"wmp": meta(w.sid), "flow_id": rpcParams(start)["flow_id"], "flow_type": "sign"}})
	w.push(notification(wmp.MethodFlowError, map[string]any{"wmp": meta(w.sid), "flow_id": rpcParams(start)["flow_id"],
		"code": wmp.ErrFlowError, "message": "refused", "data": map[string]any{"reason": "rejected"}}))
}

func forwardedOK(t *testing.T, w *chanWallet, flowID string) {
	t.Helper()
	method, p := w.outcome(flowID)
	require.Equal(t, wmp.MethodFlowComplete, method, "%v", p)
}

// The wallet refuses (or fails) the proof, then retries the same id: it is
// forwarded once; a replay after that is context_unavailable.
func TestWMPNotification_RefusedProofDoesNotSpendTheID(t *testing.T) {
	answers := map[string]func(w *chanWallet, start map[string]any){
		"wallet errors": refuseSign,
		"no proof": func(w *chanWallet, start map[string]any) {
			w.push(map[string]any{"id": start["id"], "result": map[string]any{"wmp": meta(w.sid), "flow_id": rpcParams(start)["flow_id"], "flow_type": "sign"}})
			w.push(notification(wmp.MethodFlowComplete, map[string]any{"wmp": meta(w.sid), "flow_id": rpcParams(start)["flow_id"], "result": map[string]any{}}))
		},
		"wallet refuses the start": func(w *chanWallet, start map[string]any) {
			w.push(map[string]any{"id": start["id"], "error": map[string]any{"code": wmp.ErrFlowError, "message": "no"}})
		},
	}
	for name, answer := range answers {
		t.Run(name, func(t *testing.T) {
			e := newChanEnv(t, "DPoP", false)
			w := e.wallet("alice", fullTAC, "oid4vci", "credential_notification")
			w.issue("f1")
			w.notify("n1", "f1", "nid-1", "credential_accepted")
			answer(w, w.method(wmp.MethodFlowStart))
			reason, _ := w.reason("n1")
			assert.Equal(t, "signing_failed", reason)
			assert.Equal(t, 0, e.iss.count())

			w.notify("n2", "f1", "nid-1", "credential_accepted") // the retry
			w.answerSign(e.key, "access-1")
			forwardedOK(t, w, "n2")
			assert.Equal(t, 1, e.iss.count())

			w.notify("n3", "f1", "nid-1", "credential_accepted") // a replay after the forward
			reason, _ = w.reason("n3")
			assert.Equal(t, "context_unavailable", reason)
			assert.Equal(t, 1, e.iss.count(), "the issuer was contacted once")
		})
	}
}

// A proof that times out is the same: nothing was sent, the retry works.
func TestWMPNotification_TimedOutProofDoesNotSpendTheID(t *testing.T) {
	e := newChanEnv(t, "DPoP", false)
	w := e.wallet("alice", fullTAC, "oid4vci", "credential_notification")
	w.issue("f1")
	w.notify("n1", "f1", "nid-1", "credential_accepted", map[string]any{"timeout": 1})
	w.method(wmp.MethodFlowStart) // the sign request, left unanswered
	reason, _ := w.reason("n1")
	assert.Equal(t, "timeout", reason)
	assert.Equal(t, 0, e.iss.count())

	w.notify("n2", "f1", "nid-1", "credential_accepted")
	w.answerSign(e.key, "access-1")
	forwardedOK(t, w, "n2")
	assert.Equal(t, 1, e.iss.count())
}

// Once the issuer was contacted a failure stays spent: the issuer asks for a DPoP
// nonce, the wallet then refuses the second proof, and the id is not given back.
func TestWMPNotification_FailureAfterTheIssuerWasContactedStaysSpent(t *testing.T) {
	e := newChanEnv(t, "DPoP", false)
	e.iss.challenge = 1
	w := e.wallet("alice", fullTAC, "oid4vci", "credential_notification")
	w.issue("f1")
	w.notify("n1", "f1", "nid-1", "credential_accepted")
	w.answerSign(e.key, "access-1") // the first proof: the issuer answers with a nonce challenge
	refuseSign(w, w.method(wmp.MethodFlowStart))
	reason, _ := w.reason("n1")
	assert.Equal(t, "signing_failed", reason)
	assert.Equal(t, 1, e.iss.count(), "the issuer was contacted once")

	w.notify("n2", "f1", "nid-1", "credential_accepted")
	reason, _ = w.reason("n2")
	assert.Equal(t, "context_unavailable", reason, "spent: the issuer saw the first request")
	assert.Equal(t, 1, e.iss.count())
}

// An encrypted response (the wallet names the ids): a refused proof gives back
// only that id; the other ids keep working and each is still single use.
func TestWMPNotification_EncryptedResponseRefusedProofGivesTheIDBack(t *testing.T) {
	e := newChanEnv(t, "DPoP", true)
	w := e.wallet("alice", fullTAC, "oid4vci", "credential_notification")
	w.issue("f1")

	w.notify("n1", "f1", "id-a", "credential_accepted")
	refuseSign(w, w.method(wmp.MethodFlowStart))
	reason, _ := w.reason("n1")
	assert.Equal(t, "signing_failed", reason)

	w.notify("n2", "f1", "id-b", "credential_accepted")
	w.answerSign(e.key, "access-1")
	forwardedOK(t, w, "n2")

	w.notify("n3", "f1", "id-a", "credential_accepted") // given back
	w.answerSign(e.key, "access-1")
	forwardedOK(t, w, "n3")

	w.notify("n4", "f1", "id-b", "credential_accepted")
	reason, _ = w.reason("n4")
	assert.Equal(t, "context_unavailable", reason, "id-b was forwarded")
	assert.Equal(t, 2, e.iss.count())
}

// The legacy wmp.credential.notification method cannot route a sign request to
// the finished issuance flow. For a client-held DPoP token the failure to obtain
// the proof must not burn the context: the ack is rejected as on WebSocket and
// the wallet can retry through the credential_notification flow.
func TestWMPNotification_LegacyMethodClientHeldDoesNotBurnTheContext(t *testing.T) {
	e := newChanEnv(t, "DPoP", false)
	w := e.wallet("alice", fullTAC, "oid4vci", "credential_notification")
	w.issue("f1")
	ws := e.a.session(w.sid)
	e.m.dispatchCredentialNotification(ws.session, &CredentialNotificationMessage{
		Message: Message{Type: TypeCredentialNotification, FlowID: "f1"}, NotificationID: "nid-1", Event: "credential_accepted"})
	ev := w.method(wmp.MethodMessageDeliver)
	body, _ := rpcParams(ev)["body"].(map[string]any)
	assert.Equal(t, "rejected", body["status"])
	raw := fmt.Sprint(body)
	assert.Contains(t, raw, "forwarding failed")
	assert.NotContains(t, strings.ToLower(raw), "dpop", "nothing of the failure is echoed")
	assert.Equal(t, 0, e.iss.count())

	w.notify("n1", "f1", "nid-1", "credential_accepted")
	w.answerSign(e.key, "access-1")
	forwardedOK(t, w, "n1")
	assert.Equal(t, 1, e.iss.count())
}

// An engine-held key needs no sign request: the legacy method forwards as before.
func TestWMPNotification_LegacyMethodEngineHeldKeyStillForwards(t *testing.T) {
	e := newChanEnv(t, "Bearer", false)
	w := e.wallet("alice", fullTAC, "oid4vci", "credential_notification")
	w.issue("f1")
	ws := e.a.session(w.sid)
	e.m.dispatchCredentialNotification(ws.session, &CredentialNotificationMessage{
		Message: Message{Type: TypeCredentialNotification, FlowID: "f1"}, NotificationID: "nid-1", Event: "credential_accepted"})
	ev := w.method(wmp.MethodMessageDeliver)
	body, _ := rpcParams(ev)["body"].(map[string]any)
	assert.Equal(t, "forwarded", body["status"])
	assert.Equal(t, 1, e.iss.count())
}

// The store: unspend gives an id back only while its registration is the latest
// and unexpired, keeps the original expiry, and frees the id's slot of the 256.
func TestNotificationContextStore_Unspend(t *testing.T) {
	put := func(s *notificationContextStore, nid string) {
		s.put("f1", &notificationContext{endpoint: "https://i/n", notificationID: nid, principal: "p"})
	}
	t.Run("a known id and its context come back with the original expiry", func(t *testing.T) {
		s := newNotificationContextStore()
		put(s, "n1")
		used := s.claim("f1", "p", "n1")
		require.NotNil(t, used)
		assert.Nil(t, s.claim("f1", "p", "n1"), "claimed")
		handed := *used
		s.unspend("f1", &handed, "n1")
		back := s.claim("f1", "p", "n1")
		require.NotNil(t, back)
		assert.True(t, back.expiresAt.Equal(used.expiresAt), "a retry does not extend the context's life")
	})
	t.Run("a superseded registration is not revived", func(t *testing.T) {
		s := newNotificationContextStore()
		put(s, "n1")
		used := s.claim("f1", "p", "n1")
		require.NotNil(t, used)
		put(s, "n2") // the flow registered again: the newer one owns the flow id
		handed := *used
		s.unspend("f1", &handed, "n1")
		assert.Nil(t, s.claim("f1", "p", "n1"), "the old id is not back")
		assert.NotNil(t, s.claim("f1", "p", "n2"), "the newer registration is untouched")
	})
	t.Run("a superseded registration is not revived even when the newer one is spent", func(t *testing.T) {
		s := newNotificationContextStore()
		put(s, "n1")
		used := s.claim("f1", "p", "n1")
		require.NotNil(t, used)
		put(s, "n2")
		require.NotNil(t, s.claim("f1", "p", "n2")) // the newer one is spent: the flow id is free again
		handed := *used
		s.unspend("f1", &handed, "n1")
		assert.Nil(t, s.claim("f1", "p", "n1"), "the old registration does not come back into a free flow id")
	})
	t.Run("an expired context is not revived", func(t *testing.T) {
		s := newNotificationContextStore()
		put(s, "n1")
		used := s.claim("f1", "p", "n1")
		require.NotNil(t, used)
		handed := *used
		handed.expiresAt = time.Now().Add(-time.Second)
		s.unspend("f1", &handed, "n1")
		assert.Nil(t, s.claim("f1", "p", "n1"))
	})
	t.Run("a context that knows no id gets the id back and its slot", func(t *testing.T) {
		s := newNotificationContextStore()
		put(s, "")
		var first *notificationContext
		for i := 0; i < maxBlindNotificationIDs; i++ {
			nc := s.claim("f1", "p", fmt.Sprintf("id-%d", i))
			require.NotNil(t, nc, i)
			if i == 0 {
				first = nc
			}
		}
		assert.Nil(t, s.claim("f1", "p", "one-too-many"), "the 256 bound holds")
		handed := *first
		s.unspend("f1", &handed, "id-0")
		assert.NotNil(t, s.claim("f1", "p", "id-0"), "the id is usable again, in the slot it freed")
		assert.Nil(t, s.claim("f1", "p", "id-0"), "and single use")
		assert.Nil(t, s.claim("f1", "p", "one-too-many"), "the bound still holds")
	})
	t.Run("a WebSocket context (no principal) is put back whole", func(t *testing.T) {
		s := newNotificationContextStore()
		s.put("f1", &notificationContext{endpoint: "https://i/n", notificationID: "n1"})
		nc := s.takeForNotification("f1", "n1")
		require.NotNil(t, nc)
		handed := *nc
		s.unspend("f1", &handed, "n1")
		assert.NotNil(t, s.take("f1"))
	})
}
