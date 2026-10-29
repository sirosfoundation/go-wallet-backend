package engine

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"go.uber.org/zap"
)

const secretSeedA = "d41d8cd98f00b204e9800998ecf8427e"
const secretSeedB = "0cc175b9c0f1b6a831c399e269772661"

// captureHandler returns a handler whose session echoes every sent message to
// the returned channel.
func captureHandler(t *testing.T) (*OID4VCIHandler, chan map[string]json.RawMessage, func()) {
	t.Helper()
	msgs := make(chan map[string]json.RawMessage, 8)
	conn, cleanup := wsTestServer(t, func(srvConn *websocket.Conn) {
		defer srvConn.Close()
		for {
			_, data, err := srvConn.ReadMessage()
			if err != nil {
				return
			}
			var m map[string]json.RawMessage
			if json.Unmarshal(data, &m) == nil {
				msgs <- m
			}
		}
	})
	session := testSession(conn)
	flow := &Flow{ID: "f1", Session: session, Data: map[string]interface{}{}}
	h := &OID4VCIHandler{clientAuthMode: clientAuthLegacy, legacyAttestationRequested: true}
	h.BaseHandler = BaseHandler{Flow: flow, Logger: zap.NewNop()}
	return h, msgs, cleanup
}

func nextMsg(t *testing.T, ch chan map[string]json.RawMessage) map[string]json.RawMessage {
	t.Helper()
	select {
	case m := <-ch:
		return m
	case <-time.After(5 * time.Second):
		t.Fatal("no message sent: flow hung")
		return nil
	}
}

// --- issuer-metadata auxiliary data advertisement ---

// toWalletAux advertises a Secret Value delivery to the wallet: the response
// must be encrypted.
const toWalletAux = `{"to_wallet":[{"type":"hash_commitment","alg":"sha-256","path":["org.iso.18013.5.1","ssc"]}]}`

// seedCfg is a credential configuration that delivers a Secret Value to the
// wallet (auxiliary_data_supported.to_wallet).
func seedCfg() *CredentialConfig {
	return &CredentialConfig{Format: "mso_mdoc", AuxiliaryDataSupported: json.RawMessage(toWalletAux)}
}
