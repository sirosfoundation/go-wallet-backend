package engine

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
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

func TestResolveClientAuth_ClientHeld_AttestationChallengeRetry(t *testing.T) {
	client := supportingClient()

	var mu sync.Mutex
	var attempts int

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		mu.Lock()
		attempts++
		n := attempts
		mu.Unlock()
		if n == 1 {
			w.Header().Set("OAuth-Client-Attestation-Challenge", "chal-abc")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"use_attestation_challenge"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"at","token_type":"DPoP"}`))
	}))
	defer srv.Close()

	h, _, cleanup := newClientAuthHandler(t, srv.Client(), client)
	defer cleanup()

	token, err := h.exchangePreAuthCode(context.Background(), &IssuerMetadata{TokenEndpoint: srv.URL}, "code", "")
	require.NoError(t, err)
	assert.Equal(t, "at", token.AccessToken)

	reqs := client.seen()
	require.Len(t, reqs, 2)
	assert.Empty(t, reqs[0].Params.AttestationChallenge, "first PoP carries no challenge yet")
	assert.Equal(t, "chal-abc", reqs[1].Params.AttestationChallenge, "retry must carry the server challenge")
	assert.Empty(t, h.attestationChallenge, "spent once the AS accepts the request")
}

// TestResolveClientAuth_ClientHeld_ChallengeSurvivesNonceRetry: a challenge
// rejected only for a missing DPoP nonce was never spent, and an AS without a
// challenge_endpoint offers no way to get another.
func TestResolveClientAuth_ClientHeld_ChallengeSurvivesNonceRetry(t *testing.T) {
	client := supportingClient()

	var mu sync.Mutex
	var attempts int

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		mu.Lock()
		attempts++
		n := attempts
		mu.Unlock()
		switch n {
		case 1:
			w.Header().Set("OAuth-Client-Attestation-Challenge", "chal-abc")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"use_attestation_challenge"}`))
		case 2:
			w.Header().Set("DPoP-Nonce", "server-nonce")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"use_dpop_nonce"}`))
		default:
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"at","token_type":"DPoP"}`))
		}
	}))
	defer srv.Close()

	h, _, cleanup := newClientAuthHandler(t, srv.Client(), client)
	defer cleanup()

	_, err := h.exchangePreAuthCode(context.Background(), &IssuerMetadata{TokenEndpoint: srv.URL}, "code", "")
	require.NoError(t, err)

	reqs := client.seen()
	require.Len(t, reqs, 3)
	assert.Equal(t, "chal-abc", reqs[1].Params.AttestationChallenge)
	assert.Equal(t, "chal-abc", reqs[2].Params.AttestationChallenge, "nonce retry must keep the unspent challenge")
	assert.Equal(t, "server-nonce", reqs[2].Params.DPoPNonce)
	assert.Empty(t, h.attestationChallenge, "spent once the AS accepts the request")
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
	_, err := h.requestCredential(context.Background(), metadata, token, "cfg", &CredentialConfig{Format: "dc+sd-jwt"}, nil, nil)
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

// challengeAS is an AS whose metadata advertises a challenge endpoint handing
// out chal-1, chal-2, ..., and whose token endpoint records request headers.
type challengeAS struct {
	*httptest.Server
	mu             sync.Mutex
	metadataHits   int
	challengeHits  int
	challengeFails bool
	tokenHeaders   []http.Header
}

func newChallengeAS(t *testing.T) *challengeAS {
	t.Helper()
	as := &challengeAS{}
	mux := http.NewServeMux()

	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
		as.mu.Lock()
		as.metadataHits++
		as.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"issuer":"` + as.URL + `","token_endpoint":"` + as.URL + `/token","challenge_endpoint":"` + as.URL + `/challenge"}`))
	})

	mux.HandleFunc("/challenge", func(w http.ResponseWriter, r *http.Request) {
		as.mu.Lock()
		as.challengeHits++
		n := as.challengeHits
		fail := as.challengeFails
		as.mu.Unlock()
		if fail {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("OAuth-Client-Attestation-Challenge", "chal-"+strconv.Itoa(n))
	})

	mux.HandleFunc("/par", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"request_uri":"urn:par:1"}`))
	})

	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		as.mu.Lock()
		as.tokenHeaders = append(as.tokenHeaders, r.Header.Clone())
		as.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"at","token_type":"DPoP"}`))
	})

	as.Server = httptest.NewServer(mux)

	t.Cleanup(as.Close)

	return as
}

func (as *challengeAS) counts() (metadata, challenge, token int) {
	as.mu.Lock()
	defer as.mu.Unlock()
	return as.metadataHits, as.challengeHits, len(as.tokenHeaders)
}

func TestPrefetchChallenge_ClientHeld_FirstTokenRequestCarriesChallenge(t *testing.T) {
	as := newChallengeAS(t)
	client := supportingClient()
	h, _, cleanup := newClientAuthHandler(t, as.Client(), client)
	defer cleanup()

	// token_endpoint already known from issuer metadata: AS metadata must
	// still be read to discover challenge_endpoint.
	metadata := &IssuerMetadata{CredentialIssuer: as.URL, TokenEndpoint: as.URL + "/token"}
	_, err := h.exchangePreAuthCode(context.Background(), metadata, "code", "")
	require.NoError(t, err)

	metadataHits, challengeHits, tokenHits := as.counts()
	assert.Equal(t, 1, metadataHits)
	assert.Equal(t, 1, challengeHits)
	assert.Equal(t, 1, tokenHits, "no use_attestation_challenge round-trip")

	reqs := client.seen()
	require.Len(t, reqs, 1)
	assert.Equal(t, "chal-1", reqs[0].Params.AttestationChallenge)
	assert.Empty(t, h.attestationChallenge, "spent once the AS accepts the request")
}

func TestPrefetchChallenge_ClientHeld_FreshChallengePerPoP(t *testing.T) {
	as := newChallengeAS(t)
	client := supportingClient()
	h, _, cleanup := newClientAuthHandler(t, as.Client(), client)
	defer cleanup()
	h.challengeEndpoint = as.URL + "/challenge"

	parAuth, err := h.resolveClientAuth(context.Background(), clientAuthNeeds{attestation: true})
	require.NoError(t, err)
	_, err = h.sendPushedAuthorizationRequest(context.Background(), as.URL+"/par", url.Values{}, parAuth)
	require.NoError(t, err)
	metadata := &IssuerMetadata{CredentialIssuer: as.URL, TokenEndpoint: as.URL + "/token"}
	_, err = h.exchangeAuthCode(context.Background(), metadata, "code", "https://wallet.example.com/cb", "")
	require.NoError(t, err)

	reqs := client.seen()
	require.Len(t, reqs, 2)
	assert.Equal(t, "chal-1", reqs[0].Params.AttestationChallenge)
	assert.Equal(t, "chal-2", reqs[1].Params.AttestationChallenge)
}

func TestPrefetchChallenge_Legacy_RequestAttestationCarriesChallenge(t *testing.T) {
	as := newChallengeAS(t)
	client := &clientAuthClient{respond: func(req SignRequestMessage) SignResponseMessage {
		if req.Action == SignActionRequestAttestation {
			return SignResponseMessage{ClientAttestation: "wia.jwt", ClientAttestationPoP: "legacy-pop"}
		}
		return SignResponseMessage{}
	}}
	h, _, cleanup := newClientAuthHandler(t, as.Client(), client)
	defer cleanup()

	metadata := &IssuerMetadata{CredentialIssuer: as.URL, TokenEndpoint: as.URL + "/token"}
	_, err := h.exchangePreAuthCode(context.Background(), metadata, "code", "")
	require.NoError(t, err)

	reqs := client.seen()
	require.Len(t, reqs, 2)
	assert.Equal(t, SignActionRequestAttestation, reqs[1].Action)
	assert.Equal(t, "chal-1", reqs[1].Params.AttestationChallenge, "unused probe challenge carries over")
	_, challengeHits, _ := as.counts()
	assert.Equal(t, 1, challengeHits)
}

func TestPrefetchChallenge_SkippedForPreSuppliedAttestation(t *testing.T) {
	as := newChallengeAS(t)
	client := supportingClient()
	h, _, cleanup := newClientAuthHandler(t, as.Client(), client)
	defer cleanup()
	// What Execute does for FlowStartMessage{ClientAttestation, ClientAttestationPoP}.
	h.attestationProvider = &TransportSuppliedAttestation{WIA: "wia.jwt", PoP: "upfront-pop", ID: h.clientID}
	require.NoError(t, h.useLegacyClientAuth())

	metadata := &IssuerMetadata{CredentialIssuer: as.URL, TokenEndpoint: as.URL + "/token"}
	_, err := h.exchangePreAuthCode(context.Background(), metadata, "code", "")
	require.NoError(t, err)

	_, challengeHits, _ := as.counts()
	assert.Zero(t, challengeHits, "a pre-signed PoP cannot carry a new challenge")
	as.mu.Lock()
	defer as.mu.Unlock()
	assert.Equal(t, "upfront-pop", as.tokenHeaders[0].Get("OAuth-Client-Attestation-PoP"))
}

func TestPrefetchChallenge_EndpointFailureIsNotFatal(t *testing.T) {
	as := newChallengeAS(t)
	as.challengeFails = true
	client := supportingClient()
	h, _, cleanup := newClientAuthHandler(t, as.Client(), client)
	defer cleanup()

	metadata := &IssuerMetadata{CredentialIssuer: as.URL, TokenEndpoint: as.URL + "/token"}
	_, err := h.exchangePreAuthCode(context.Background(), metadata, "code", "")
	require.NoError(t, err)

	reqs := client.seen()
	require.Len(t, reqs, 1)
	assert.Empty(t, reqs[0].Params.AttestationChallenge)
}

func TestAccessTokenHash(t *testing.T) {
	assert.Empty(t, accessTokenHash(""))
	// RFC 9449 §4.2: base64url(SHA-256(access_token)), unpadded.
	assert.Equal(t, "fUHyO2r2Z3DZ53EsNrWBb0xWXoaNy59IiKCAqksmQEo", accessTokenHash("Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU"))
}

// scriptedTokenAS is an AS whose token endpoint answers from a script, one
// step per request. withChallengeEndpoint controls whether its metadata
// advertises a challenge_endpoint (handing out chal-1, chal-2, ...).
type scriptedTokenAS struct {
	*httptest.Server
	mu            sync.Mutex
	steps         []func(w http.ResponseWriter)
	tokenHits     int
	challengeHits int
}

func tokenStepUseChallenge(challenge string) func(w http.ResponseWriter) {
	return func(w http.ResponseWriter) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("OAuth-Client-Attestation-Challenge", challenge)
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"use_attestation_challenge"}`))
	}
}

func tokenStepUseNonce(nonce string) func(w http.ResponseWriter) {
	return func(w http.ResponseWriter) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("DPoP-Nonce", nonce)
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"use_dpop_nonce"}`))
	}
}

func tokenStepOK(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"access_token":"at","token_type":"DPoP"}`))
}

func newScriptedTokenAS(t *testing.T, withChallengeEndpoint bool, steps ...func(w http.ResponseWriter)) *scriptedTokenAS {
	t.Helper()
	as := &scriptedTokenAS{steps: steps}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		ce := ""
		if withChallengeEndpoint {
			ce = `,"challenge_endpoint":"` + as.URL + `/challenge"`
		}
		_, _ = w.Write([]byte(`{"issuer":"` + as.URL + `","token_endpoint":"` + as.URL + `/token"` + ce + `}`))
	})
	mux.HandleFunc("/challenge", func(w http.ResponseWriter, r *http.Request) {
		as.mu.Lock()
		as.challengeHits++
		n := as.challengeHits
		as.mu.Unlock()
		w.Header().Set("OAuth-Client-Attestation-Challenge", "chal-"+strconv.Itoa(n))
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		as.mu.Lock()
		i := as.tokenHits
		as.tokenHits++
		as.mu.Unlock()
		if i >= len(as.steps) {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		as.steps[i](w)
	})
	as.Server = httptest.NewServer(mux)
	t.Cleanup(as.Close)
	return as
}

func exchangeScripted(t *testing.T, as *scriptedTokenAS, client *clientAuthClient) error {
	t.Helper()
	h, _, cleanup := newClientAuthHandler(t, as.Client(), client)
	defer cleanup()
	metadata := &IssuerMetadata{CredentialIssuer: as.URL, TokenEndpoint: as.URL + "/token"}
	_, err := h.exchangePreAuthCode(context.Background(), metadata, "code", "")
	return err
}

// A request rejected with use_dpop_nonce was not accepted, so the challenge it
// carried may not have been consumed. Without a challenge endpoint the engine
// cannot fetch another one, so the retry must resend the same challenge along
// with the nonce rather than drop it.
func TestChallengeRetry_NoEndpoint_NonceRetryKeepsChallenge(t *testing.T) {
	as := newScriptedTokenAS(t, false,
		tokenStepUseChallenge("C1"), tokenStepUseNonce("N1"), tokenStepOK)
	client := supportingClient()
	require.NoError(t, exchangeScripted(t, as, client))

	reqs := client.seen()
	require.Len(t, reqs, 3)
	assert.Empty(t, reqs[0].Params.AttestationChallenge)
	assert.Equal(t, "C1", reqs[1].Params.AttestationChallenge)
	assert.Empty(t, reqs[1].Params.DPoPNonce)
	assert.Equal(t, "C1", reqs[2].Params.AttestationChallenge, "nonce-only retry must keep the challenge")
	assert.Equal(t, "N1", reqs[2].Params.DPoPNonce)
}

// The prefetched challenge is only spent once the AS accepts the request, so a
// nonce-only retry reuses it instead of fetching another.
func TestChallengeRetry_Endpoint_NonceRetryReusesUnspentChallenge(t *testing.T) {
	as := newScriptedTokenAS(t, true, tokenStepUseNonce("N1"), tokenStepOK)
	client := supportingClient()
	require.NoError(t, exchangeScripted(t, as, client))

	reqs := client.seen()
	require.Len(t, reqs, 2)
	assert.Equal(t, "chal-1", reqs[0].Params.AttestationChallenge)
	assert.Equal(t, "chal-1", reqs[1].Params.AttestationChallenge)
	assert.Equal(t, "N1", reqs[1].Params.DPoPNonce)
	as.mu.Lock()
	defer as.mu.Unlock()
	assert.Equal(t, 1, as.challengeHits)
}

// challenge -> nonce -> challenge again (the AS consumed the first one) ->
// success needs four requests: nonce retries must not eat the budget the
// challenge retries need.
func TestChallengeRetry_NonceRetryDoesNotExhaustBudget(t *testing.T) {
	as := newScriptedTokenAS(t, false,
		tokenStepUseChallenge("C1"), tokenStepUseNonce("N1"), tokenStepUseChallenge("C2"), tokenStepOK)
	client := supportingClient()
	require.NoError(t, exchangeScripted(t, as, client))

	reqs := client.seen()
	require.Len(t, reqs, 4)
	assert.Equal(t, "C2", reqs[3].Params.AttestationChallenge)
	assert.Equal(t, "N1", reqs[3].Params.DPoPNonce)
}

// In legacy mode the WIA+PoP is requested once and replayed. A PAR that the AS
// accepted spent the challenge bound into that PoP, so the token request must
// not replay it: the attestation is re-requested with a fresh challenge.
func TestPrefetchChallenge_Legacy_PARSpendsChallengeTokenGetsFreshAttestation(t *testing.T) {
	as := newChallengeAS(t)
	client := &clientAuthClient{respond: func(req SignRequestMessage) SignResponseMessage {
		if req.Action == SignActionRequestAttestation {
			return SignResponseMessage{ClientAttestation: "wia.jwt", ClientAttestationPoP: "legacy-pop"}
		}
		return SignResponseMessage{}
	}}
	h, _, cleanup := newClientAuthHandler(t, as.Client(), client)
	defer cleanup()
	h.challengeEndpoint = as.URL + "/challenge"

	parAuth, err := h.resolveClientAuth(context.Background(), clientAuthNeeds{attestation: true})
	require.NoError(t, err)
	_, err = h.sendPushedAuthorizationRequest(context.Background(), as.URL+"/par", url.Values{}, parAuth)
	require.NoError(t, err)

	metadata := &IssuerMetadata{CredentialIssuer: as.URL, TokenEndpoint: as.URL + "/token"}
	_, err = h.exchangeAuthCode(context.Background(), metadata, "code", "https://wallet.example.com/cb", "")
	require.NoError(t, err)

	var attest []SignRequestMessage
	for _, r := range client.seen() {
		if r.Action == SignActionRequestAttestation {
			attest = append(attest, r)
		}
	}
	require.Len(t, attest, 2, "token request must not replay the PoP whose challenge PAR spent")
	assert.Equal(t, "chal-1", attest[0].Params.AttestationChallenge)
	assert.Equal(t, "chal-2", attest[1].Params.AttestationChallenge)
}
