package engine

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
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

// --- issuer-metadata seed advertisement ---

func seedCfg(cm string) *CredentialConfig {
	c := &CredentialConfig{Format: "mso_mdoc"}
	if cm != "" {
		c.CredentialMetadata = json.RawMessage(cm)
	}
	return c
}

const advOK = `{"display":[{"name":"x"}],"org.siros.secret_seed":{"namespaces":["org.iso.18013.5.1"]}}`

func TestSecretSeedAdvertised(t *testing.T) {
	for name, cm := range map[string]string{
		"none":                "",
		"no member":           `{"display":[]}`,
		"not an object":       `["x"]`,
		"credential_metadata": `null`,
	} {
		t.Run("absent/"+name, func(t *testing.T) {
			ok, err := secretSeedAdvertised(seedCfg(cm))
			require.NoError(t, err)
			assert.False(t, ok)
		})
	}
	ok, err := secretSeedAdvertised(seedCfg(advOK))
	require.NoError(t, err)
	assert.True(t, ok)
	for _, edge := range []string{
		`{"namespaces":["a","b","c","d","e","f","g","h"]}`,
		`{"namespaces":["` + strings.Repeat("n", 64) + `"]}`,
	} {
		ok, err = secretSeedAdvertised(seedCfg(`{"org.siros.secret_seed":` + edge + `}`))
		require.NoError(t, err)
		assert.True(t, ok)
	}

	for name, adv := range map[string]string{
		"hex values not namespaces": `{"ns":"` + secretSeedA + `"}`,
		"hex alongside namespaces":  `{"namespaces":["a"],"seed":"` + secretSeedA + `"}`,
		"namespaces as hex string":  `{"namespaces":"` + secretSeedA + `"}`,
		"namespaces object":         `{"namespaces":{"a":"` + secretSeedA + `"}}`,
		"empty namespaces":          `{"namespaces":[]}`,
		"nine namespaces":           `{"namespaces":["a","b","c","d","e","f","g","h","i"]}`,
		"duplicate namespace":       `{"namespaces":["a","a"]}`,
		"namespace 65 bytes":        `{"namespaces":["` + strings.Repeat("n", 65) + `"]}`,
		"reserved name":             `{"namespaces":["namespaces"]}`,
		"extra non-string member":   `{"namespaces":["a"],"x":1}`,
		"empty namespace name":      `{"namespaces":[""]}`,
		"non-string namespace":      `{"namespaces":[7]}`,
		"empty object":              `{}`,
		"not an object":             `"` + secretSeedA + `"`,
		"null":                      `null`,
	} {
		t.Run("malformed/"+name, func(t *testing.T) {
			ok, err := secretSeedAdvertised(seedCfg(`{"org.siros.secret_seed":` + adv + `}`))
			require.Error(t, err)
			assert.False(t, ok)
			assert.NotContains(t, err.Error(), secretSeedA)
		})
	}
}

// A malformed advertisement makes the configuration "not offered": it is
// dropped when the issuer metadata is decoded (privatedata-spec 5A.3).
func TestCredentialConfigurations_MalformedSeedAdvertisementNotOffered(t *testing.T) {
	var c CredentialConfigurations
	require.NoError(t, json.Unmarshal([]byte(`{
		"good":{"format":"mso_mdoc","credential_metadata":`+advOK+`},
		"none":{"format":"mso_mdoc"},
		"hex":{"format":"mso_mdoc","credential_metadata":{"org.siros.secret_seed":{"ns":"`+secretSeedA+`"}}},
		"dup":{"format":"mso_mdoc","credential_metadata":{"org.siros.secret_seed":{"namespaces":["a","a"]}}}}`), &c))
	assert.Contains(t, c, "good")
	assert.Contains(t, c, "none")
	assert.NotContains(t, c, "hex")
	assert.NotContains(t, c, "dup")
}

func TestLogIgnoredCredentialConfigurations_MalformedSeedAdvertisementNoContent(t *testing.T) {
	core, logs := observer.New(zap.DebugLevel)
	h := &OID4VCIHandler{}
	h.BaseHandler = BaseHandler{Logger: zap.New(core)}
	src := map[string]interface{}{"credential_configurations_supported": map[string]interface{}{
		"hex": map[string]interface{}{"format": "mso_mdoc", "credential_metadata": map[string]interface{}{
			"org.siros.secret_seed": map[string]interface{}{"ns": secretSeedA}}},
	}}
	h.logIgnoredCredentialConfigurations(src, CredentialConfigurations{})
	require.Equal(t, 1, logs.Len())
	e := logs.All()[0]
	assert.NotContains(t, e.Message, secretSeedA)
	for _, f := range e.Context {
		assert.NotContains(t, f.String, secretSeedA)
	}
}
