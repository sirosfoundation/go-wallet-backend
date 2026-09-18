package engine

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// clientAuthClient is a scripted "wallet" on the far end of the WebSocket
// that answers every sign_request the handler sends. It records the params
// it saw so tests can assert on what the engine asked for.
type clientAuthClient struct {
	mu       sync.Mutex
	requests []SignRequestMessage
	// respond builds the response for one request; nil answers with an
	// empty sign_response (a client that does not know the action).
	respond func(req SignRequestMessage) SignResponseMessage
	// silent makes the client never answer, to exercise the probe timeout.
	silent bool
}

func (c *clientAuthClient) seen() []SignRequestMessage {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]SignRequestMessage, len(c.requests))
	copy(out, c.requests)
	return out
}

// newClientAuthHandler wires an OID4VCIHandler to a session whose peer is the
// scripted client. Unlike testOID4VCIHandler it leaves clientAuthMode
// undecided, so the first authenticated request probes the client.
func newClientAuthHandler(t *testing.T, httpClient *http.Client, client *clientAuthClient) (*OID4VCIHandler, *Session, func()) {
	t.Helper()
	conn, cleanup := wsTestServer(t, func(srvConn *websocket.Conn) {
		defer srvConn.Close()
		for {
			_, data, err := srvConn.ReadMessage()
			if err != nil {
				return
			}
			var probe struct {
				Type MessageType `json:"type"`
			}
			if json.Unmarshal(data, &probe) != nil || probe.Type != TypeSignRequest {
				continue // progress etc.
			}
			var req SignRequestMessage
			require.NoError(t, json.Unmarshal(data, &req))
			client.mu.Lock()
			client.requests = append(client.requests, req)
			client.mu.Unlock()
			if client.silent {
				continue
			}
			var resp SignResponseMessage
			if client.respond != nil {
				resp = client.respond(req)
			}
			resp.Type = TypeSignResponse
			resp.FlowID = req.FlowID
			resp.MessageID = req.MessageID
			_ = srvConn.WriteJSON(resp)
		}
	})
	session := testSession(conn)
	// Route sign_responses arriving on the client side of the socket into
	// the session's sign channel, as the real read loop would.
	go func() {
		for {
			_, data, err := conn.ReadMessage()
			if err != nil {
				return
			}
			var probe struct {
				Type MessageType `json:"type"`
			}
			if json.Unmarshal(data, &probe) != nil || probe.Type != TypeSignResponse {
				continue
			}
			var msg SignResponseMessage
			if json.Unmarshal(data, &msg) == nil {
				session.signCh <- &msg
			}
		}
	}()
	flow := &Flow{ID: "flow-1", Session: session, Data: make(map[string]interface{})}
	h := &OID4VCIHandler{httpClient: httpClient}
	h.BaseHandler = BaseHandler{Flow: flow, Logger: zap.NewNop()}
	h.authServerIssuer = "https://as.example.com"
	h.clientID = "https://wallet.example.com/cb"
	return h, session, cleanup
}

// supportingClient answers sign_client_auth like an SDK that holds the key:
// always a dpop_key_id, a proof when htm/htu were asked, a WIA + PoP when an
// audience was asked. The PoP embeds a counter so freshness is observable.
func supportingClient() *clientAuthClient {
	var n int
	c := &clientAuthClient{}
	c.respond = func(req SignRequestMessage) SignResponseMessage {
		if req.Action != SignActionSignClientAuth {
			return SignResponseMessage{}
		}
		n++
		resp := SignResponseMessage{DPoPKeyID: "instance-key-1"}
		if req.Params.HTM != "" {
			resp.DPoPProof = "dpop-proof-" + string(rune('0'+n))
		}
		if req.Params.Audience != "" {
			resp.ClientAttestation = "wia.jwt"
			resp.ClientAttestationPoP = "pop-" + string(rune('0'+n))
		}
		return resp
	}
	return c
}

// tokenServer is a token endpoint that records the headers of every request
// and optionally demands a DPoP nonce on the first one.
func tokenServer(t *testing.T, requireNonce bool) (*httptest.Server, *[]http.Header) {
	t.Helper()
	var headers []http.Header
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		mu.Lock()
		headers = append(headers, r.Header.Clone())
		n := len(headers)
		mu.Unlock()
		if requireNonce && n == 1 {
			w.Header().Set("DPoP-Nonce", "server-nonce")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"use_dpop_nonce"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"at","token_type":"DPoP","refresh_token":"rt"}`))
	}))
	return srv, &headers
}

func TestResolveClientAuth_ClientHeld_TokenRequestCarriesFreshProofAndPoP(t *testing.T) {
	client := supportingClient()
	srv, headers := tokenServer(t, false)
	defer srv.Close()
	h, _, cleanup := newClientAuthHandler(t, srv.Client(), client)
	defer cleanup()

	metadata := &IssuerMetadata{TokenEndpoint: srv.URL}
	token, err := h.exchangePreAuthCode(context.Background(), metadata, "code", "")
	require.NoError(t, err)
	require.Equal(t, "at", token.AccessToken)

	assert.Equal(t, clientAuthClientHeld, h.clientAuthMode)
	assert.Equal(t, "instance-key-1", h.dpopKeyID)
	assert.Nil(t, h.dpopKey, "engine must not hold a DPoP key in client-held mode")

	require.Len(t, *headers, 1)
	hdr := (*headers)[0]
	assert.Equal(t, "dpop-proof-1", hdr.Get("DPoP"))
	assert.Equal(t, "wia.jwt", hdr.Get("OAuth-Client-Attestation"))
	assert.Equal(t, "pop-1", hdr.Get("OAuth-Client-Attestation-PoP"))

	reqs := client.seen()
	require.Len(t, reqs, 1)
	assert.Equal(t, SignActionSignClientAuth, reqs[0].Action)
	assert.Equal(t, "POST", reqs[0].Params.HTM)
	assert.Equal(t, srv.URL, reqs[0].Params.HTU)
	assert.Equal(t, "https://as.example.com", reqs[0].Params.Audience)
	assert.Equal(t, "https://wallet.example.com/cb", reqs[0].Params.Issuer)
	assert.Empty(t, reqs[0].Params.ATH, "no ath at the token endpoint")
	assert.Empty(t, reqs[0].Params.KeyID, "no key_id before the client has named its key")

	// The refresh_token relay names the client's key, not a private JWK.
	assert.Equal(t, "instance-key-1", h.dpopKeyIDForRefreshToken(token))
	assert.Empty(t, h.dpopJWKForRefreshToken(token))
}

func TestResolveClientAuth_ClientHeld_NonceRetrySignsAgainWithNonce(t *testing.T) {
	client := supportingClient()
	srv, headers := tokenServer(t, true)
	defer srv.Close()
	h, _, cleanup := newClientAuthHandler(t, srv.Client(), client)
	defer cleanup()

	_, err := h.exchangePreAuthCode(context.Background(), &IssuerMetadata{TokenEndpoint: srv.URL}, "code", "")
	require.NoError(t, err)

	require.Len(t, *headers, 2)
	assert.Equal(t, "dpop-proof-1", (*headers)[0].Get("DPoP"))
	assert.Equal(t, "dpop-proof-2", (*headers)[1].Get("DPoP"), "retry must carry a newly signed proof")
	assert.Equal(t, "pop-2", (*headers)[1].Get("OAuth-Client-Attestation-PoP"), "retry must carry a fresh PoP, not a replay")

	reqs := client.seen()
	require.Len(t, reqs, 2)
	assert.Empty(t, reqs[0].Params.DPoPNonce)
	assert.Equal(t, "server-nonce", reqs[1].Params.DPoPNonce)
	assert.Equal(t, "instance-key-1", reqs[1].Params.KeyID, "later requests name the settled key")
}

func TestResolveClientAuth_ClientHeld_ResourceRequestCarriesATHOnly(t *testing.T) {
	client := supportingClient()
	var got http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		_, _ = w.Write([]byte(`{"credential":"cred"}`))
	}))
	defer srv.Close()
	h, _, cleanup := newClientAuthHandler(t, srv.Client(), client)
	defer cleanup()

	metadata := &IssuerMetadata{CredentialEndpoint: srv.URL}
	token := &TokenResponse{AccessToken: "the-token", TokenType: "DPoP"}
	_, err := h.requestCredential(context.Background(), metadata, token, "cfg", &CredentialConfig{Format: "dc+sd-jwt"}, nil)
	require.NoError(t, err)

	assert.Equal(t, "dpop-proof-1", got.Get("DPoP"))
	assert.Empty(t, got.Get("OAuth-Client-Attestation"), "resource requests carry no attestation")

	reqs := client.seen()
	require.Len(t, reqs, 1)
	assert.Empty(t, reqs[0].Params.Audience)
	assert.Equal(t, accessTokenHash("the-token"), reqs[0].Params.ATH)
}

func TestResolveClientAuth_ClientHeld_MissingProofIsAnError(t *testing.T) {
	client := &clientAuthClient{respond: func(SignRequestMessage) SignResponseMessage {
		return SignResponseMessage{DPoPKeyID: "k"} // supports the action but returned no proof
	}}
	srv, headers := tokenServer(t, false)
	defer srv.Close()
	h, _, cleanup := newClientAuthHandler(t, srv.Client(), client)
	defer cleanup()

	_, err := h.exchangePreAuthCode(context.Background(), &IssuerMetadata{TokenEndpoint: srv.URL}, "code", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no DPoP proof")
	assert.Empty(t, *headers, "no request may go out unsigned")
}

func TestResolveClientAuth_FallsBackToLegacyOnEmptyResponse(t *testing.T) {
	// A client that answers unknown actions with an empty sign_response
	// (both SDKs since kotlin#154 / swift#122) - and also declines the
	// legacy request_attestation.
	client := &clientAuthClient{}
	srv, headers := tokenServer(t, false)
	defer srv.Close()
	h, _, cleanup := newClientAuthHandler(t, srv.Client(), client)
	defer cleanup()

	token, err := h.exchangePreAuthCode(context.Background(), &IssuerMetadata{TokenEndpoint: srv.URL}, "code", "")
	require.NoError(t, err)

	assert.Equal(t, clientAuthLegacy, h.clientAuthMode)
	require.NotNil(t, h.dpopKey, "legacy mode generates the engine-held key")
	require.Len(t, *headers, 1)
	assert.NotEmpty(t, (*headers)[0].Get("DPoP"), "legacy DPoP proof signed by the engine")
	assert.Empty(t, (*headers)[0].Get("OAuth-Client-Attestation"))

	reqs := client.seen()
	require.Len(t, reqs, 2, "probe, then the one-shot legacy request_attestation")
	assert.Equal(t, SignActionSignClientAuth, reqs[0].Action)
	assert.Equal(t, SignActionRequestAttestation, reqs[1].Action)

	assert.NotEmpty(t, h.dpopJWKForRefreshToken(token), "legacy relays the private JWK")
	assert.Empty(t, h.dpopKeyIDForRefreshToken(token))
}

func TestResolveClientAuth_LegacyReplaysAttestationOnce(t *testing.T) {
	// Legacy client: knows request_attestation only.
	client := &clientAuthClient{respond: func(req SignRequestMessage) SignResponseMessage {
		if req.Action == SignActionRequestAttestation {
			return SignResponseMessage{ClientAttestation: "wia.jwt", ClientAttestationPoP: "legacy-pop"}
		}
		return SignResponseMessage{}
	}}
	srv, headers := tokenServer(t, true)
	defer srv.Close()
	h, _, cleanup := newClientAuthHandler(t, srv.Client(), client)
	defer cleanup()

	_, err := h.exchangePreAuthCode(context.Background(), &IssuerMetadata{TokenEndpoint: srv.URL}, "code", "")
	require.NoError(t, err)

	require.Len(t, *headers, 2)
	assert.Equal(t, "legacy-pop", (*headers)[0].Get("OAuth-Client-Attestation-PoP"))
	assert.Equal(t, "legacy-pop", (*headers)[1].Get("OAuth-Client-Attestation-PoP"), "legacy mode replays, by design")
	reqs := client.seen()
	require.Len(t, reqs, 2, "one probe and one request_attestation, no per-request asks in legacy mode")
}

func TestResolveClientAuth_FallsBackToLegacyOnTimeout(t *testing.T) {
	old := clientAuthRequestTimeout
	oldAtt := attestationRequestTimeout
	clientAuthRequestTimeout = 100 * time.Millisecond
	attestationRequestTimeout = 100 * time.Millisecond
	defer func() { clientAuthRequestTimeout = old; attestationRequestTimeout = oldAtt }()

	client := &clientAuthClient{silent: true}
	srv, headers := tokenServer(t, false)
	defer srv.Close()
	h, _, cleanup := newClientAuthHandler(t, srv.Client(), client)
	defer cleanup()

	_, err := h.exchangePreAuthCode(context.Background(), &IssuerMetadata{TokenEndpoint: srv.URL}, "code", "")
	require.NoError(t, err)
	assert.Equal(t, clientAuthLegacy, h.clientAuthMode)
	require.Len(t, *headers, 1)
	assert.NotEmpty(t, (*headers)[0].Get("DPoP"))
}

func TestResolveClientAuth_PresetKeyMeansLegacyWithoutProbe(t *testing.T) {
	// A renewal that presented dpop_jwk, or a client that pre-resolved its
	// attestation: the engine already holds the key, so no probe is sent.
	client := supportingClient()
	srv, _ := tokenServer(t, false)
	defer srv.Close()
	h, _, cleanup := newClientAuthHandler(t, srv.Client(), client)
	defer cleanup()
	key, err := generateDPoPKey()
	require.NoError(t, err)
	h.dpopKey = key
	h.legacyAttestationRequested = true

	_, err = h.exchangePreAuthCode(context.Background(), &IssuerMetadata{TokenEndpoint: srv.URL}, "code", "")
	require.NoError(t, err)
	assert.Equal(t, clientAuthLegacy, h.clientAuthMode)
	assert.Empty(t, client.seen(), "no sign_client_auth probe when the engine holds the key")
}

func TestResolveClientAuth_RenewalWithKeyIDSkipsProbeAndNamesKey(t *testing.T) {
	client := supportingClient()
	srv, _ := tokenServer(t, false)
	defer srv.Close()
	h, _, cleanup := newClientAuthHandler(t, srv.Client(), client)
	defer cleanup()
	// What Execute does for FlowStartMessage{RefreshToken, DPoPKeyID}.
	h.clientAuthMode = clientAuthClientHeld
	h.dpopKeyID = "instance-key-1"

	_, err := h.exchangeRefreshToken(context.Background(), &IssuerMetadata{TokenEndpoint: srv.URL}, "rt")
	require.NoError(t, err)
	reqs := client.seen()
	require.Len(t, reqs, 1)
	assert.Equal(t, "instance-key-1", reqs[0].Params.KeyID, "renewal must ask the client to sign with the original key")
}

func TestClientHeldDPoPSigner_NotificationAfterFlowComplete(t *testing.T) {
	client := supportingClient()
	var got http.Header
	notif := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer notif.Close()
	h, session, cleanup := newClientAuthHandler(t, notif.Client(), client)
	defer cleanup()
	h.clientAuthMode = clientAuthClientHeld
	h.dpopKeyID = "instance-key-1"

	nc := &notificationContext{
		endpoint:    notif.URL,
		accessToken: "at",
		tokenType:   "DPoP",
		dpopSigner:  h.dpopSigner(),
	}
	require.IsType(t, &clientHeldDPoPSigner{}, nc.dpopSigner)
	_ = session // the signer addresses the completed flow's id on this session

	err := sendNotification(context.Background(), notif.Client(), nc, "n-1", notificationEventAccepted, "", zap.NewNop())
	require.NoError(t, err)
	assert.Equal(t, "dpop-proof-1", got.Get("DPoP"))
	reqs := client.seen()
	require.Len(t, reqs, 1)
	assert.Equal(t, "flow-1", reqs[0].FlowID)
	assert.Equal(t, accessTokenHash("at"), reqs[0].Params.ATH)
	assert.Equal(t, "instance-key-1", reqs[0].Params.KeyID)
}

func TestSendFlowComplete_RelaysDPoPKeyID(t *testing.T) {
	// Echo server: whatever the session sends comes back on conn for inspection.
	conn, cleanup := wsTestServer(t, func(srvConn *websocket.Conn) {
		defer srvConn.Close()
		_, data, err := srvConn.ReadMessage()
		if err != nil {
			return
		}
		_ = srvConn.WriteMessage(websocket.TextMessage, data)
	})
	defer cleanup()
	session := testSession(conn)
	err := session.SendFlowCompleteWithRefreshToken("f", nil, "", "rt", "", "instance-key-1")
	require.NoError(t, err)
	var received map[string]interface{}
	require.NoError(t, conn.ReadJSON(&received))
	assert.Equal(t, "rt", received["refresh_token"])
	assert.Equal(t, "instance-key-1", received["dpop_key_id"])
	_, hasJWK := received["dpop_jwk"]
	assert.False(t, hasJWK, "client-held mode relays no private key")
}

func TestAccessTokenHash(t *testing.T) {
	assert.Empty(t, accessTokenHash(""))
	// RFC 9449 §4.2: base64url(SHA-256(access_token)), unpadded.
	assert.Equal(t, "fUHyO2r2Z3DZ53EsNrWBb0xWXoaNy59IiKCAqksmQEo", accessTokenHash("Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU"))
}
