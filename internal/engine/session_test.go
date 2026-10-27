package engine

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	gojose "github.com/go-jose/go-jose/v4"
	gojosejwt "github.com/go-jose/go-jose/v4/jwt"
	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-tokenauth/claims"
	tokenvalidator "github.com/sirosfoundation/go-tokenauth/validator"

	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

// setupEngineTokenValidatorTest starts a local JWKS server and a
// go-tokenauth validator pointed at it, mirroring the same helper used in
// pkg/middleware and internal/server tests.
func setupEngineTokenValidatorTest(t *testing.T) (*tokenvalidator.Validator, *ecdsa.PrivateKey, string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	jwk := gojose.JSONWebKey{Key: &key.PublicKey, KeyID: "test-key", Algorithm: string(gojose.ES256)}
	jwks := gojose.JSONWebKeySet{Keys: []gojose.JSONWebKey{jwk}}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jwks) //nolint:errcheck
	}))
	t.Cleanup(srv.Close)

	v := tokenvalidator.New(tokenvalidator.Config{
		JWKSURL: srv.URL,
		Issuer:  "test-issuer",
		// go-tokenauth v0.5.0 made Config.Audiences mandatory - both
		// validation paths now refuse to validate at all when it's empty
		// (closing a fail-open audience-confusion gap). This mirrors the
		// real deployment's Audiences: cfg.AS.Audiences, with route-level
		// restriction (result.HasAudience) still layered on top, so it
		// must list every audience any test in this file signs a token
		// for.
		Audiences: []string{"wallet-registry", "wallet-backend", "some-other-audience"},
	})
	v.Start(context.Background())
	t.Cleanup(v.Stop)

	// Poll until the validator has actually fetched the JWKS, rather than
	// sleeping a fixed duration (flaky under slow/contended CI runners).
	probe := signEngineToken(t, key, "test-issuer", claims.AccessTokenClaims{
		Claims: gojosejwt.Claims{Audience: gojosejwt.Audience{"wallet-registry"}},
	})
	require.Eventually(t, func() bool {
		_, err := v.Validate(context.Background(), probe)
		return err == nil
	}, 2*time.Second, 10*time.Millisecond, "validator did not fetch JWKS in time")

	return v, key, "test-issuer"
}

func signEngineToken(t *testing.T, key *ecdsa.PrivateKey, issuer string, cl claims.AccessTokenClaims) string {
	t.Helper()

	signer, err := gojose.NewSigner(
		gojose.SigningKey{Algorithm: gojose.ES256, Key: key},
		(&gojose.SignerOptions{}).WithType("JWT").WithHeader("kid", "test-key"),
	)
	require.NoError(t, err)

	now := time.Now()
	cl.Claims = gojosejwt.Claims{
		Issuer:    issuer,
		Subject:   cl.Claims.Subject,
		Audience:  cl.Claims.Audience,
		IssuedAt:  gojosejwt.NewNumericDate(now),
		NotBefore: gojosejwt.NewNumericDate(now.Add(-1 * time.Second)),
		Expiry:    gojosejwt.NewNumericDate(now.Add(5 * time.Minute)),
	}

	raw, err := gojosejwt.Signed(signer).Claims(cl).Serialize()
	require.NoError(t, err)
	return raw
}

// TestManager_ConnectionLimit_CountsUnhandshakedConnections is a regression
// test: an upgraded connection that never sends a handshake must still count
// against the session limit. Before this fix, the limit only counted
// len(m.sessions), which is populated post-handshake — letting an attacker
// open unlimited unauthenticated connections without ever being counted.
func TestManager_ConnectionLimit_CountsUnhandshakedConnections(t *testing.T) {
	cfg := &config.Config{JWT: config.JWTConfig{Secret: "test-secret", Issuer: "test-issuer"}}
	m := NewManager(cfg, zap.NewNop())

	server := httptest.NewServer(http.HandlerFunc(m.HandleConnection))
	defer server.Close()
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")

	ws, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	require.NoError(t, err)
	defer func() { _ = ws.Close() }()

	// Never send a handshake message.
	require.Eventually(t, func() bool {
		return m.activeConnections.Load() == 1
	}, time.Second, 10*time.Millisecond, "unhandshaked connection was not counted")

	m.sessionsMu.RLock()
	sessionCount := len(m.sessions)
	m.sessionsMu.RUnlock()
	assert.Zero(t, sessionCount, "connection never handshaked, so it must not appear in sessions")

	require.NoError(t, ws.Close())
	require.Eventually(t, func() bool {
		return m.activeConnections.Load() == 0
	}, time.Second, 10*time.Millisecond, "connection count did not decrement after close")
}

// TestManager_ConnectionLimit_RejectsAtCapacity is a regression test: once
// activeConnections is at capacity, new connection attempts are rejected with
// 503 even if m.sessions is empty (i.e. even if nobody has handshaked yet).
func TestManager_ConnectionLimit_RejectsAtCapacity(t *testing.T) {
	cfg := &config.Config{JWT: config.JWTConfig{Secret: "test-secret", Issuer: "test-issuer"}}
	m := NewManager(cfg, zap.NewNop())
	m.activeConnections.Store(maxConnections)

	server := httptest.NewServer(http.HandlerFunc(m.HandleConnection))
	defer server.Close()

	resp, err := http.Get(server.URL)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}

// TestManager_ConnectionLimit_NoOvershootUnderConcurrency is a regression
// test: checking activeConnections.Load() against the limit and only then
// incrementing is racy — many concurrent requests can all read a value
// under the limit before any of them increments, letting the total overshoot
// maxConnections. Reserving via Add(1) first (and rolling back on
// rejection) closes that gap.
//
// Connections must stay open (real WebSocket upgrades that never send a
// handshake) rather than failing immediately — an immediately-failing
// "connection" releases its slot right away, so it can't hold room open
// long enough to contend with the others. A starting gate forces all dial
// attempts to fire at once, to maximize genuine concurrent contention on
// the counter.
func TestManager_ConnectionLimit_NoOvershootUnderConcurrency(t *testing.T) {
	cfg := &config.Config{JWT: config.JWTConfig{Secret: "test-secret", Issuer: "test-issuer"}}
	m := NewManager(cfg, zap.NewNop())

	const room = 5 // slots left before the limit
	m.activeConnections.Store(maxConnections - room)

	server := httptest.NewServer(http.HandlerFunc(m.HandleConnection))
	defer server.Close()
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")

	const concurrent = 30 // more than `room`, to force contention
	ready := make(chan struct{})
	var wg sync.WaitGroup
	var accepted atomic.Int64
	var rejected atomic.Int64
	conns := make([]*websocket.Conn, concurrent)
	for i := 0; i < concurrent; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-ready
			ws, resp, err := websocket.DefaultDialer.Dial(wsURL, nil)
			if err == nil {
				accepted.Add(1)
				conns[i] = ws
				return
			}
			if resp != nil && resp.StatusCode == http.StatusServiceUnavailable {
				rejected.Add(1)
			}
		}(i)
	}
	close(ready) // release all dial attempts at once
	wg.Wait()
	defer func() {
		for _, c := range conns {
			if c != nil {
				_ = c.Close()
			}
		}
	}()

	assert.Equal(t, int64(concurrent), accepted.Load()+rejected.Load(),
		"every attempt should be either accepted or explicitly rejected with 503")
	assert.LessOrEqual(t, accepted.Load(), int64(room),
		"at most `room` connections should have been accepted while they're all still open")
	assert.LessOrEqual(t, m.activeConnections.Load(), int64(maxConnections),
		"activeConnections must never exceed maxConnections under concurrent requests")
}

// TestManager_validateToken_GoTokenauth_AllowsRegistryAudience is a
// regression test for the engine transport audience restriction: the engine
// transport, like the AuthZEN proxy, only needs a wallet-registry or
// wallet-backend audience.
func TestManager_validateToken_GoTokenauth_AllowsRegistryAudience(t *testing.T) {
	cfg := &config.Config{JWT: config.JWTConfig{Secret: "test-secret", Issuer: "test-issuer"}}
	m := NewManager(cfg, zap.NewNop())
	v, key, issuer := setupEngineTokenValidatorTest(t)
	m.SetTokenValidator(v)

	token := signEngineToken(t, key, issuer, claims.AccessTokenClaims{
		Claims:   gojosejwt.Claims{Audience: gojosejwt.Audience{"wallet-registry"}},
		TenantID: "test-tenant",
		TAC:      "r",
		ACR:      "urn:siros:acr:passkey",
	})

	_, tenantID, tac, err := m.validateToken(context.Background(), token)
	require.NoError(t, err)
	assert.Equal(t, "test-tenant", tenantID)
	assert.Equal(t, claims.TAC("r"), tac)
}

// TestManager_validateToken_GoTokenauth_RejectsOtherAudience confirms a
// token scoped to a different audience is not usable on the engine
// transport, mirroring the AuthZEN proxy restriction.
func TestManager_validateToken_GoTokenauth_RejectsOtherAudience(t *testing.T) {
	cfg := &config.Config{JWT: config.JWTConfig{Secret: "test-secret", Issuer: "test-issuer"}}
	m := NewManager(cfg, zap.NewNop())
	v, key, issuer := setupEngineTokenValidatorTest(t)
	m.SetTokenValidator(v)

	token := signEngineToken(t, key, issuer, claims.AccessTokenClaims{
		Claims:   gojosejwt.Claims{Audience: gojosejwt.Audience{"some-other-audience"}},
		TenantID: "test-tenant",
		TAC:      "r",
		ACR:      "urn:siros:acr:passkey",
	})

	_, _, _, err := m.validateToken(context.Background(), token)
	assert.Error(t, err)
}

// fakeEngineBlacklist is a minimal TokenBlacklistChecker test double.
type fakeEngineBlacklist struct {
	revoked      map[string]bool
	revokedUsers map[string]bool
}

func (f *fakeEngineBlacklist) IsBlacklisted(ctx context.Context, jti string) bool {
	return f.revoked[jti]
}

func (f *fakeEngineBlacklist) IsUserRevoked(ctx context.Context, userID string) bool {
	return f.revokedUsers[userID]
}

// TestManager_validateToken_GoTokenauth_RevokedUserDenied proves the #391
// review fix (round 2): the WebSocket handshake's go-tokenauth path checks
// user-level revocation itself, since the shared *tokenvalidator.Validator's
// own Revocation checker only ever sees a jti, never a user_id - so
// DeleteUser's bulk revocation would otherwise never be consulted here.
func TestManager_validateToken_GoTokenauth_RevokedUserDenied(t *testing.T) {
	cfg := &config.Config{JWT: config.JWTConfig{Secret: "test-secret", Issuer: "test-issuer"}}
	m := NewManager(cfg, zap.NewNop())
	v, key, issuer := setupEngineTokenValidatorTest(t)
	m.SetTokenValidator(v)
	m.SetTokenBlacklist(&fakeEngineBlacklist{revokedUsers: map[string]bool{"revoked-user": true}})

	token := signEngineToken(t, key, issuer, claims.AccessTokenClaims{
		Claims:   gojosejwt.Claims{Audience: gojosejwt.Audience{"wallet-registry"}, Subject: "revoked-user"},
		TenantID: "test-tenant",
		TAC:      "r",
		ACR:      "urn:siros:acr:passkey",
	})

	_, _, _, err := m.validateToken(context.Background(), token)
	assert.Error(t, err)
}

type stubFlowHandler struct{}

func (stubFlowHandler) Execute(ctx context.Context, msg *FlowStartMessage) error { return nil }
func (stubFlowHandler) Cancel()                                                  {}

func newManagerWithStubOID4VCIHandler(t *testing.T) *Manager {
	t.Helper()
	cfg := &config.Config{JWT: config.JWTConfig{Secret: "test-secret", Issuer: "test-issuer"}}
	m := NewManager(cfg, zap.NewNop())
	m.RegisterFlowHandler(ProtocolOID4VCI, func(flow *Flow, cfg *config.Config, logger *zap.Logger, trustSvc *TrustService, registry *RegistryClient, verifiers storage.VerifierStore, trustCache *TrustCache) (FlowHandler, error) {
		return stubFlowHandler{}, nil
	})
	return m
}

// runHandleFlowStart wires a Manager+Session whose conn is the client side
// of wsTestServer, calls handleFlowStart, and returns whatever the session
// sent (as observed server-side via srvConn), or nil if nothing arrived
// within a short window. session.conn.WriteJSON sends the message from the
// test's "session" (client dialer conn) to the server-side handler
// (srvConn) - matching the existing TestSendFlowComplete_* convention,
// where the assertion always happens in the server-side callback, not by
// reading back from the dialer conn.
func runHandleFlowStart(t *testing.T, m *Manager, tac claims.TAC, protocol Protocol) *FlowErrorMessage {
	t.Helper()
	return runHandleFlowStartWithID(t, m, tac, protocol, "")
}

// runHandleFlowStartWithID is runHandleFlowStart with an explicit flow_id -
// the field a WS client fully controls - for exercising flow_id-dependent
// behavior (e.g. the short-flow_id-vs-log-truncation regression below).
func runHandleFlowStartWithID(t *testing.T, m *Manager, tac claims.TAC, protocol Protocol, flowID string) *FlowErrorMessage {
	t.Helper()

	result := make(chan *FlowErrorMessage, 1)
	conn, cleanup := wsTestServer(t, func(srvConn *websocket.Conn) {
		// Deliberately shorter than the outer select's timeout below, so a
		// successful (no-message) flow start reliably delivers nil to
		// result well before the outer timeout could ever race it.
		_ = srvConn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		_, data, err := srvConn.ReadMessage()
		if err != nil {
			result <- nil
			return
		}
		var msg FlowErrorMessage
		if err := json.Unmarshal(data, &msg); err != nil {
			result <- nil
			return
		}
		result <- &msg
	})
	defer cleanup()

	session := testSession(conn)
	session.TAC = tac

	m.handleFlowStart(session, &FlowStartMessage{Message: Message{FlowID: flowID}, Protocol: protocol})

	select {
	case msg := <-result:
		return msg
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for server-side callback")
		return nil
	}
}

func TestManager_handleFlowStart_RejectsInsufficientTAC(t *testing.T) {
	m := newManagerWithStubOID4VCIHandler(t)

	msg := runHandleFlowStart(t, m, "r", ProtocolOID4VCI) // OID4VCI (issuance) requires 'i'
	if msg == nil {
		t.Fatal("expected a flow_error, got none")
	}
	assert.Equal(t, ErrCodeForbidden, msg.Error.Code)
}

func TestManager_handleFlowStart_AllowsSufficientTAC(t *testing.T) {
	m := newManagerWithStubOID4VCIHandler(t)

	// Should reach stubFlowHandler.Execute (which succeeds immediately and
	// sends nothing) rather than being rejected by the TAC gate.
	msg := runHandleFlowStart(t, m, "i", ProtocolOID4VCI)
	if msg != nil {
		t.Fatalf("expected no flow_error, got code %q", msg.Error.Code)
	}
}

// TestManager_handleFlowStart_RejectsEmptyTAC pins the fail-closed rule: an
// empty session.TAC means "no permissions" (as for the HTTP routes'
// MustHaveTAC), so a protocol with a required permission is refused. Every
// token is a go-tokenauth token since the legacy tokens, which had no TAC
// concept, were removed, so there is no token for which an empty TAC means
// "not applicable".
func TestManager_handleFlowStart_RejectsEmptyTAC(t *testing.T) {
	m := newManagerWithStubOID4VCIHandler(t)

	msg := runHandleFlowStart(t, m, "", ProtocolOID4VCI)
	if msg == nil {
		t.Fatal("expected a flow_error for an empty TAC, got none")
	}
	assert.Equal(t, ErrCodeForbidden, msg.Error.Code)
}

// TestManager_handleFlowStart_ShortFlowIDDoesNotPanic is a regression test:
// flow_id is fully client-controlled (any string in the WS flow_start
// message), and the per-flow logger used to truncate it to 8 characters for
// log lines must never run ahead of the handler's own recover(). Before the
// fix, any non-empty flow_id under 8 characters panicked on the slice at
// that truncation, before defer registered - crashing the goroutine (and,
// unrecovered, the whole process) instead of returning a flow_error.
func TestManager_handleFlowStart_ShortFlowIDDoesNotPanic(t *testing.T) {
	m := newManagerWithStubOID4VCIHandler(t)

	for _, flowID := range []string{"a", "1234567"} {
		t.Run(flowID, func(t *testing.T) {
			// Reaching this line at all (rather than crashing the test
			// binary on an unrecovered panic) is the regression check.
			msg := runHandleFlowStartWithID(t, m, "i", ProtocolOID4VCI, flowID)
			if msg != nil {
				t.Fatalf("expected no flow_error for a valid short flow_id, got code %q", msg.Error.Code)
			}
		})
	}
}

// ===== SendFlowComplete tests =====

func TestSendFlowComplete_IncludesDataMapFields(t *testing.T) {
	// Server side: read the flow_complete message and verify it has issuer fields
	conn, cleanup := wsTestServer(t, func(srvConn *websocket.Conn) {
		defer srvConn.Close()
		_, data, err := srvConn.ReadMessage()
		if err != nil {
			return
		}
		var msg map[string]interface{}
		if err := json.Unmarshal(data, &msg); err != nil {
			return
		}
		// Write the parsed message back so the test client can read it
		_ = srvConn.WriteJSON(msg)
	})
	defer cleanup()

	session := testSession(conn)
	flow := &Flow{
		ID:      "test-flow-complete",
		Session: session,
		Data:    make(map[string]interface{}),
	}
	flow.Data["credential_issuer"] = "https://issuer.example.com"
	flow.Data["selected_credential_configuration_id"] = "PID_SD_JWT"

	session.flowsMu.Lock()
	session.flows["test-flow-complete"] = flow
	session.flowsMu.Unlock()

	credentials := []CredentialResult{
		{Format: "dc+sd-jwt", Credential: "eyJ..."},
	}

	err := session.SendFlowComplete("test-flow-complete", credentials, "")
	require.NoError(t, err)

	// Read the echoed message from server
	var received map[string]interface{}
	err = conn.ReadJSON(&received)
	require.NoError(t, err)

	assert.Equal(t, "flow_complete", received["type"])
	assert.Equal(t, "test-flow-complete", received["flow_id"])
	assert.Equal(t, "https://issuer.example.com", received["credential_issuer"])
	assert.Equal(t, "PID_SD_JWT", received["selected_credential_configuration_id"])
}

func TestSendFlowComplete_NoFlowOmitsIssuerFields(t *testing.T) {
	conn, cleanup := wsTestServer(t, func(srvConn *websocket.Conn) {
		defer srvConn.Close()
		_, data, err := srvConn.ReadMessage()
		if err != nil {
			return
		}
		var msg map[string]interface{}
		if err := json.Unmarshal(data, &msg); err != nil {
			return
		}
		_ = srvConn.WriteJSON(msg)
	})
	defer cleanup()

	session := testSession(conn)
	// No flow registered for this ID

	err := session.SendFlowComplete("nonexistent-flow", nil, "https://redirect.example.com")
	require.NoError(t, err)

	var received map[string]interface{}
	err = conn.ReadJSON(&received)
	require.NoError(t, err)

	assert.Equal(t, "flow_complete", received["type"])
	assert.Equal(t, "https://redirect.example.com", received["redirect_uri"])
	// Issuer fields should not be present (no flow, so no Data map)
	_, hasIssuer := received["credential_issuer"]
	_, hasConfig := received["selected_credential_configuration_id"]
	assert.False(t, hasIssuer, "credential_issuer should not be present when flow is nil")
	assert.False(t, hasConfig, "selected_credential_configuration_id should not be present when flow is nil")
}

func TestSendFlowComplete_EmptyDataMapOmitsIssuerFields(t *testing.T) {
	conn, cleanup := wsTestServer(t, func(srvConn *websocket.Conn) {
		defer srvConn.Close()
		_, data, err := srvConn.ReadMessage()
		if err != nil {
			return
		}
		var msg map[string]interface{}
		if err := json.Unmarshal(data, &msg); err != nil {
			return
		}
		_ = srvConn.WriteJSON(msg)
	})
	defer cleanup()

	session := testSession(conn)
	flow := &Flow{
		ID:      "empty-data-flow",
		Session: session,
		Data:    make(map[string]interface{}),
		// Data map empty — no credential_issuer or selected_credential_configuration_id
	}
	session.flowsMu.Lock()
	session.flows["empty-data-flow"] = flow
	session.flowsMu.Unlock()

	err := session.SendFlowComplete("empty-data-flow", nil, "")
	require.NoError(t, err)

	var received map[string]interface{}
	err = conn.ReadJSON(&received)
	require.NoError(t, err)

	_, hasIssuer := received["credential_issuer"]
	_, hasConfig := received["selected_credential_configuration_id"]
	assert.False(t, hasIssuer, "credential_issuer should not be present when Data map is empty")
	assert.False(t, hasConfig, "selected_credential_configuration_id should not be present when Data map is empty")
}

// TestSendFlowCompleteWithRefreshToken_IncludesRefreshToken covers the
// credential re-issuance/renewal plan's Phase 1 first step: an OID4VCI
// refresh_token must actually reach the client instead of being silently
// discarded (as internal/engine/oid4vci.go's TokenResponse.RefreshToken
// field previously was - parsed, never read again).
func TestSendFlowCompleteWithRefreshToken_IncludesRefreshToken(t *testing.T) {
	conn, cleanup := wsTestServer(t, func(srvConn *websocket.Conn) {
		defer srvConn.Close()
		_, data, err := srvConn.ReadMessage()
		if err != nil {
			return
		}
		var msg map[string]interface{}
		if err := json.Unmarshal(data, &msg); err != nil {
			return
		}
		_ = srvConn.WriteJSON(msg)
	})
	defer cleanup()

	session := testSession(conn)
	flow := &Flow{
		ID:      "test-flow-refresh-token",
		Session: session,
		Data:    make(map[string]interface{}),
	}
	session.flowsMu.Lock()
	session.flows["test-flow-refresh-token"] = flow
	session.flowsMu.Unlock()

	credentials := []CredentialResult{
		{Format: "dc+sd-jwt", Credential: "eyJ..."},
	}

	err := session.SendFlowCompleteWithRefreshToken("test-flow-refresh-token", credentials, "", "opaque-refresh-token-value", "", "")
	require.NoError(t, err)

	var received map[string]interface{}
	err = conn.ReadJSON(&received)
	require.NoError(t, err)

	assert.Equal(t, "opaque-refresh-token-value", received["refresh_token"])
}

// TestSendFlowCompleteWithRefreshToken_EmptyOmitsField confirms an empty
// refresh_token (the common case - most issuers don't return one) doesn't
// add a spurious empty field to the wire message, matching every other
// omitempty field on FlowCompleteMessage.
func TestSendFlowCompleteWithRefreshToken_EmptyOmitsField(t *testing.T) {
	conn, cleanup := wsTestServer(t, func(srvConn *websocket.Conn) {
		defer srvConn.Close()
		_, data, err := srvConn.ReadMessage()
		if err != nil {
			return
		}
		var msg map[string]interface{}
		if err := json.Unmarshal(data, &msg); err != nil {
			return
		}
		_ = srvConn.WriteJSON(msg)
	})
	defer cleanup()

	session := testSession(conn)
	flow := &Flow{
		ID:      "test-flow-no-refresh-token",
		Session: session,
		Data:    make(map[string]interface{}),
	}
	session.flowsMu.Lock()
	session.flows["test-flow-no-refresh-token"] = flow
	session.flowsMu.Unlock()

	err := session.SendFlowCompleteWithRefreshToken("test-flow-no-refresh-token", nil, "", "", "", "")
	require.NoError(t, err)

	var received map[string]interface{}
	err = conn.ReadJSON(&received)
	require.NoError(t, err)

	_, hasRefreshToken := received["refresh_token"]
	assert.False(t, hasRefreshToken, "refresh_token should be omitted when empty")
}

// TestBaseHandler_CompleteWithRefreshToken covers the BaseHandler-level
// delegation to Session.SendFlowCompleteWithRefreshToken (mirroring
// TestBaseHandler_RequestMatch's pattern in match_test.go) - the actual
// OID4VCI call sites (internal/engine/oid4vci.go) go through this method,
// not SendFlowCompleteWithRefreshToken directly.
func TestBaseHandler_CompleteWithRefreshToken(t *testing.T) {
	conn, cleanup := wsTestServer(t, func(srvConn *websocket.Conn) {
		defer srvConn.Close()
		_, data, err := srvConn.ReadMessage()
		if err != nil {
			return
		}
		var msg map[string]interface{}
		if err := json.Unmarshal(data, &msg); err != nil {
			return
		}
		_ = srvConn.WriteJSON(msg)
	})
	defer cleanup()

	session := testSession(conn)
	flow := &Flow{
		ID:      "flow-handler-refresh-token",
		Session: session,
	}
	handler := &BaseHandler{
		Flow:   flow,
		Logger: zap.NewNop(),
	}

	credentials := []CredentialResult{
		{Format: "dc+sd-jwt", Credential: "eyJ..."},
	}
	err := handler.CompleteWithRefreshToken(credentials, "", "handler-refresh-token-value", "", "")
	require.NoError(t, err)

	var received map[string]interface{}
	err = conn.ReadJSON(&received)
	require.NoError(t, err)

	assert.Equal(t, "handler-refresh-token-value", received["refresh_token"])
}

// dialAndHandshakeAsUser dials m's HandleConnection over a real WebSocket, completes the handshake
// for userID with an AS session token (engineSessionToken) and waits for the session to be registered.
// (Named distinctly from keepalive_test.go's dialAndHandshake, which always
// authenticates as the same fixed user and manages its own Manager/server.)
func dialAndHandshakeAsUser(t *testing.T, m *Manager, wsURL, userID string) *websocket.Conn {
	t.Helper()

	tokenString := engineSessionToken(t, m, userID)

	ws, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	require.NoError(t, err)

	require.NoError(t, ws.WriteJSON(HandshakeMessage{
		Message:  Message{Type: TypeHandshake},
		AppToken: tokenString,
	}))

	var complete Message
	require.NoError(t, ws.ReadJSON(&complete))
	require.Equal(t, TypeHandshakeComplete, complete.Type)

	require.Eventually(t, func() bool {
		m.sessionsMu.RLock()
		defer m.sessionsMu.RUnlock()
		for _, s := range m.sessions {
			if s.UserID == userID {
				return true
			}
		}
		return false
	}, time.Second, 10*time.Millisecond, "session was not registered after handshake")

	return ws
}

// TestManager_CloseUserSessions_ClosesLiveConnection is a regression test
// for #393: PR #391 closed the gap where a *new* WebSocket handshake for a
// deleted user's token would still be accepted (see the IsUserRevoked
// checks in validateToken), but an already-established connection for that
// user was never touched by account deletion at all - it stayed open and
// fully usable until it disconnected on its own. This asserts the live
// connection is actually closed by the server, not merely that a fresh
// handshake attempt would now be rejected.
func TestManager_CloseUserSessions_ClosesLiveConnection(t *testing.T) {
	cfg := &config.Config{JWT: config.JWTConfig{Secret: "test-secret", Issuer: "test-issuer"}}
	m := NewManager(cfg, zap.NewNop())

	server := httptest.NewServer(http.HandlerFunc(m.HandleConnection))
	defer server.Close()
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")

	const deletedUser = "user-being-deleted"
	ws := dialAndHandshakeAsUser(t, m, wsURL, deletedUser)
	defer func() { _ = ws.Close() }()

	closed := m.CloseUserSessions(deletedUser, "account deleted")
	assert.Equal(t, 1, closed, "exactly the deleted user's one live session should have been closed")

	// The client must observe the connection actually closing.
	require.Eventually(t, func() bool {
		_, _, err := ws.ReadMessage()
		return err != nil
	}, time.Second, 10*time.Millisecond, "client did not observe the server closing the connection")

	// And the manager's own bookkeeping must reflect that too, via the
	// same natural teardown path a client-initiated disconnect takes
	// (unregisterSession) - not a special-cased removal.
	require.Eventually(t, func() bool {
		m.sessionsMu.RLock()
		defer m.sessionsMu.RUnlock()
		stillIndexed := hasUserIndexed(m, deletedUser)
		return len(m.sessions) == 0 && !stillIndexed
	}, time.Second, 10*time.Millisecond, "session bookkeeping was not cleaned up after close")
}

// TestManager_CloseUserSessions_ClosesAllOfThatUsersSessions is a
// regression test: a user can hold more than one concurrent session
// (multiple devices), and CloseUserSessions must close every one of them,
// not just the single entry Manager.userIndex happens to hold ("last
// connection wins" - see registerSession).
func TestManager_CloseUserSessions_ClosesAllOfThatUsersSessions(t *testing.T) {
	cfg := &config.Config{JWT: config.JWTConfig{Secret: "test-secret", Issuer: "test-issuer"}}
	m := NewManager(cfg, zap.NewNop())

	server := httptest.NewServer(http.HandlerFunc(m.HandleConnection))
	defer server.Close()
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")

	const deletedUser = "multi-device-user"

	// Manually register two sessions for the same user directly in
	// m.sessions, bypassing registerSession's "close the existing session
	// for this user" replacement behavior on handshake - the whole point
	// here is to exercise the case where more than one live session for a
	// user coexists (e.g. a future multi-session model), which
	// CloseUserSessions must still handle correctly by scanning
	// m.sessions rather than only consulting userIndex.
	ws1 := dialAndHandshakeAsUser(t, m, wsURL, "other-user-not-touched")
	defer func() { _ = ws1.Close() }()
	m.sessionsMu.Lock()
	for _, s := range m.sessions {
		if s.UserID == "other-user-not-touched" {
			s.UserID = deletedUser
		}
	}
	m.sessionsMu.Unlock()

	ws2 := dialAndHandshakeAsUser(t, m, wsURL, deletedUser)
	defer func() { _ = ws2.Close() }()

	m.sessionsMu.RLock()
	preCount := 0
	for _, s := range m.sessions {
		if s.UserID == deletedUser {
			preCount++
		}
	}
	m.sessionsMu.RUnlock()
	require.Equal(t, 2, preCount, "test setup must produce two live sessions for the same user")

	closed := m.CloseUserSessions(deletedUser, "account deleted")
	assert.Equal(t, 2, closed, "both of the deleted user's sessions should have been closed")

	for _, ws := range []*websocket.Conn{ws1, ws2} {
		require.Eventually(t, func() bool {
			_, _, err := ws.ReadMessage()
			return err != nil
		}, time.Second, 10*time.Millisecond, "client did not observe the server closing the connection")
	}
}

// TestManager_CloseUserSessions_NeverTouchesOtherUsers is a regression test
// guarding against the most dangerous possible bug in this feature: closing
// account A's session must never close account B's.
func TestManager_CloseUserSessions_NeverTouchesOtherUsers(t *testing.T) {
	cfg := &config.Config{JWT: config.JWTConfig{Secret: "test-secret", Issuer: "test-issuer"}}
	m := NewManager(cfg, zap.NewNop())

	server := httptest.NewServer(http.HandlerFunc(m.HandleConnection))
	defer server.Close()
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")

	deletedWS := dialAndHandshakeAsUser(t, m, wsURL, "deleted-user")
	defer func() { _ = deletedWS.Close() }()
	survivorWS := dialAndHandshakeAsUser(t, m, wsURL, "innocent-bystander")
	defer func() { _ = survivorWS.Close() }()

	closed := m.CloseUserSessions("deleted-user", "account deleted")
	assert.Equal(t, 1, closed)

	require.Eventually(t, func() bool {
		_, _, err := deletedWS.ReadMessage()
		return err != nil
	}, time.Second, 10*time.Millisecond, "the deleted user's connection should have closed")

	// The survivor must remain fully functional: prove it with a single
	// bounded read, not a require.Never loop of repeated timed-out reads.
	// gorilla/websocket's Conn latches an internal readErr on the first
	// read error - including a plain deadline timeout - and every later
	// NextReader/ReadMessage call just returns that same cached error
	// without attempting a fresh read (see gorilla/websocket's
	// Conn.NextReader: "for c.readErr == nil { ... }"). So a loop that
	// re-arms the deadline and reads again on every tick would go blind to
	// a real close after its first (expected) timeout: every subsequent
	// read would keep returning that same latched timeout error forever,
	// "passing" even if the code under test regressed and closed the
	// connection moments later.
	require.NoError(t, survivorWS.SetReadDeadline(time.Now().Add(200*time.Millisecond)))
	_, _, err := survivorWS.ReadMessage()
	if err != nil {
		var netErr net.Error
		if !errors.As(err, &netErr) || !netErr.Timeout() {
			t.Fatalf("an innocent bystander's session must never be closed (ReadMessage returned: %v)", err)
		}
	}
	require.NoError(t, survivorWS.SetReadDeadline(time.Time{}))

	m.sessionsMu.RLock()
	stillPresent := hasUserIndexed(m, "innocent-bystander")
	m.sessionsMu.RUnlock()
	assert.True(t, stillPresent, "the innocent bystander must still be registered")
}

// TestManager_DeleteByUser_ClosesLiveConnection exercises the exact seam
// service.UserService.DeleteUser calls through: Manager.DeleteByUser is
// wired into service.MultiSessionCleaner alongside the persistent
// SessionStore's own DeleteByUser (see cmd/server/main.go). Manager itself
// duck-types service.SessionCleaner without engine importing that package.
func TestManager_DeleteByUser_ClosesLiveConnection(t *testing.T) {
	cfg := &config.Config{JWT: config.JWTConfig{Secret: "test-secret", Issuer: "test-issuer"}}
	m := NewManager(cfg, zap.NewNop())

	server := httptest.NewServer(http.HandlerFunc(m.HandleConnection))
	defer server.Close()
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")

	const deletedUser = "deleted-via-service-seam"
	ws := dialAndHandshakeAsUser(t, m, wsURL, deletedUser)
	defer func() { _ = ws.Close() }()

	require.NoError(t, m.DeleteByUser(context.Background(), deletedUser))

	require.Eventually(t, func() bool {
		_, _, err := ws.ReadMessage()
		return err != nil
	}, time.Second, 10*time.Millisecond, "client did not observe the server closing the connection")
}

// TestManager_CloseUserSessions_EmptyUserIDIsNoOp guards against the
// interface's most obvious foot-gun: every anonymous/unauthenticated
// session also has UserID == "", so matching on an empty string would
// close all of them.
func TestManager_CloseUserSessions_EmptyUserIDIsNoOp(t *testing.T) {
	cfg := &config.Config{JWT: config.JWTConfig{Secret: "test-secret", Issuer: "test-issuer"}}
	m := NewManager(cfg, zap.NewNop())

	assert.Zero(t, m.CloseUserSessions("", "account deleted"))
}

// TestManager_RegisterSession_RejectsAlreadyRevokedUser is a regression
// test for a TOCTOU window found in review of #393: validateToken's own
// IsUserRevoked check (in handleNewConnection, immediately before
// registerSession is called) happens before a Session object even exists.
// A user revoked in the gap between that check and registerSession
// actually inserting the session into m.sessions would otherwise register
// successfully and become a permanent zombie - CloseUserSessions (and
// therefore account deletion) can only ever close a session already
// present in m.sessions at the moment it scans.
//
// This constructs the session directly (bypassing validateToken
// entirely) to test registerSession's own recheck in isolation, rather
// than trying to win an actual goroutine race against real handshake
// timing.
func TestManager_RegisterSession_RejectsAlreadyRevokedUser(t *testing.T) {
	cfg := &config.Config{JWT: config.JWTConfig{Secret: "test-secret", Issuer: "test-issuer"}}
	m := NewManager(cfg, zap.NewNop())
	m.SetTokenBlacklist(&fakeEngineBlacklist{revokedUsers: map[string]bool{"already-revoked-user": true}})

	srvConnCh := make(chan *websocket.Conn, 1)
	clientConn, cleanup := wsTestServer(t, func(srvConn *websocket.Conn) {
		srvConnCh <- srvConn
	})
	defer cleanup()
	srvConn := <-srvConnCh

	session := &Session{
		ID:       "revoked-user-session",
		UserID:   "already-revoked-user",
		conn:     srvConn,
		flows:    make(map[string]*Flow),
		logger:   zap.NewNop(),
		actionCh: make(chan *FlowActionMessage, 1),
		signCh:   make(chan *SignResponseMessage, 1),
		matchCh:  make(chan *MatchResponseMessage, 1),
		closeCh:  make(chan struct{}, 1),
		stopPing: make(chan struct{}),
	}

	accepted := m.registerSession(session)
	assert.False(t, accepted, "a session for an already-revoked user must be rejected")

	m.sessionsMu.RLock()
	_, present := m.sessions[session.ID]
	_, indexed := m.userIndex[session.userKey()]
	m.sessionsMu.RUnlock()
	assert.False(t, present, "a rejected session must not be added to m.sessions")
	assert.False(t, indexed, "a rejected session must not be added to m.userIndex")

	require.Eventually(t, func() bool {
		_, _, err := clientConn.ReadMessage()
		return err != nil
	}, time.Second, 10*time.Millisecond, "client did not observe the server closing the connection")
}

// TestManager_RegisterSession_RejectsRevokedUser_WithoutBlacklistFeature is
// a regression test for #403: the engine's own revocation signal
// (Manager.RevokeUser / isUserRevoked) must reject an already-revoked
// user's session even with no TokenBlacklistChecker wired at all - not
// merely with the optional security.token_blacklist feature "disabled" in
// config, but genuinely absent (m.blacklist == nil, matching a deployment
// that never calls SetTokenBlacklist). Mirrors
// TestManager_RegisterSession_RejectsAlreadyRevokedUser, but drives the
// rejection through RevokeUser instead of a fake blacklist.
func TestManager_RegisterSession_RejectsRevokedUser_WithoutBlacklistFeature(t *testing.T) {
	cfg := &config.Config{JWT: config.JWTConfig{Secret: "test-secret", Issuer: "test-issuer"}}
	m := NewManager(cfg, zap.NewNop())
	// Deliberately no SetTokenBlacklist call: m.blacklist stays nil.
	m.RevokeUser("already-revoked-user")

	srvConnCh := make(chan *websocket.Conn, 1)
	clientConn, cleanup := wsTestServer(t, func(srvConn *websocket.Conn) {
		srvConnCh <- srvConn
	})
	defer cleanup()
	srvConn := <-srvConnCh

	session := &Session{
		ID:       "revoked-user-session-no-blacklist",
		UserID:   "already-revoked-user",
		conn:     srvConn,
		flows:    make(map[string]*Flow),
		logger:   zap.NewNop(),
		actionCh: make(chan *FlowActionMessage, 1),
		signCh:   make(chan *SignResponseMessage, 1),
		matchCh:  make(chan *MatchResponseMessage, 1),
		closeCh:  make(chan struct{}, 1),
		stopPing: make(chan struct{}),
	}

	accepted := m.registerSession(session)
	assert.False(t, accepted, "a session for a manager-revoked user must be rejected even with no TokenBlacklist wired at all")

	m.sessionsMu.RLock()
	_, present := m.sessions[session.ID]
	m.sessionsMu.RUnlock()
	assert.False(t, present, "a rejected session must not be added to m.sessions")

	require.Eventually(t, func() bool {
		_, _, err := clientConn.ReadMessage()
		return err != nil
	}, time.Second, 10*time.Millisecond, "client did not observe the server closing the connection")
}

// TestManager_DeleteByUser_WorksWithoutTokenBlacklistFeature is the
// end-to-end regression test for #403: account deletion (via
// Manager.DeleteByUser, the exact seam service.UserService.DeleteUser
// calls through - see cmd/server/main.go) must both close an
// already-established session AND reject a brand new handshake attempt
// for that user, entirely independent of the optional
// security.token_blacklist feature - which this test never configures at
// all (no SetTokenBlacklist call; m.blacklist is nil throughout).
func TestManager_DeleteByUser_WorksWithoutTokenBlacklistFeature(t *testing.T) {
	cfg := &config.Config{JWT: config.JWTConfig{Secret: "test-secret", Issuer: "test-issuer"}}
	m := NewManager(cfg, zap.NewNop())

	server := httptest.NewServer(http.HandlerFunc(m.HandleConnection))
	defer server.Close()
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")

	const userID = "deleted-no-blacklist-feature"
	ws := dialAndHandshakeAsUser(t, m, wsURL, userID)
	defer func() { _ = ws.Close() }()

	// Simulate account deletion through the actual seam
	// service.UserService.DeleteUser calls (see cmd/server/main.go).
	require.NoError(t, m.DeleteByUser(context.Background(), userID))

	// The already-open session must actually close.
	require.Eventually(t, func() bool {
		_, _, err := ws.ReadMessage()
		return err != nil
	}, time.Second, 10*time.Millisecond, "the deleted user's existing session did not close")

	// A brand new handshake attempt for the same (now-revoked) user must
	// also be rejected - not just the already-open session closed.
	tokenString := engineSessionToken(t, m, userID)

	ws2, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	require.NoError(t, err)
	defer func() { _ = ws2.Close() }()
	require.NoError(t, ws2.WriteJSON(HandshakeMessage{
		Message:  Message{Type: TypeHandshake},
		AppToken: tokenString,
	}))

	var msg Message
	require.NoError(t, ws2.ReadJSON(&msg))
	assert.Equal(t, TypeError, msg.Type, "a new handshake for a revoked user must be rejected, not completed")
}

// engineKeys remembers the signing key of the validator engineSessionToken installs on a Manager.
var engineKeys sync.Map // *Manager -> *ecdsa.PrivateKey

// engineSessionToken returns an ES256 session token for userID, installing a JWKS-backed
// validator on m on first use.
func engineSessionToken(t *testing.T, m *Manager, userID string) string {
	t.Helper()
	_, key, issuer := ensureEngineValidator(t, m)
	return signEngineToken(t, key, issuer, claims.AccessTokenClaims{
		Claims:   gojosejwt.Claims{Audience: gojosejwt.Audience{"wallet-backend"}, Subject: userID},
		TenantID: "test-tenant",
		TAC:      "rwl",
		ACR:      "urn:siros:acr:passkey",
	})
}

func ensureEngineValidator(t *testing.T, m *Manager) (*tokenvalidator.Validator, *ecdsa.PrivateKey, string) {
	t.Helper()
	if k, ok := engineKeys.Load(m); ok {
		return m.tokenValidator, k.(*ecdsa.PrivateKey), "test-issuer"
	}
	v, key, issuer := setupEngineTokenValidatorTest(t)
	m.SetTokenValidator(v)
	engineKeys.Store(m, key)
	t.Cleanup(func() { engineKeys.Delete(m) })
	return v, key, issuer
}

// With no validator wired every token is refused (fail closed).
func TestManager_validateToken_NoValidatorFailsClosed(t *testing.T) {
	m := NewManager(&config.Config{JWT: config.JWTConfig{Secret: "test-secret", Issuer: "test-issuer"}}, zap.NewNop())

	hmacToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss": "test-issuer", "user_id": "u", "tenant_id": "t", "exp": time.Now().Add(time.Hour).Unix(),
	}).SignedString([]byte("test-secret"))
	require.NoError(t, err)

	_, _, _, err = m.validateToken(context.Background(), hmacToken)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no token validator")
}

// An HS256 token signed with jwt.secret is refused even with a validator wired.
func TestManager_validateToken_HMACTokenRefused(t *testing.T) {
	m := NewManager(&config.Config{JWT: config.JWTConfig{Secret: "test-secret", Issuer: "test-issuer"}}, zap.NewNop())
	v, _, issuer := setupEngineTokenValidatorTest(t)
	m.SetTokenValidator(v)

	hmacToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss": issuer, "aud": "wallet-backend", "user_id": "u", "tenant_id": "t",
		"exp": time.Now().Add(time.Hour).Unix(),
	}).SignedString([]byte("test-secret"))
	require.NoError(t, err)

	_, _, _, err = m.validateToken(context.Background(), hmacToken)
	require.Error(t, err)
}

// A done context fails closed in validateToken (never read as "not revoked").
func TestManager_validateToken_CancelledContextFailsClosed(t *testing.T) {
	m := NewManager(&config.Config{}, zap.NewNop())
	token := engineSessionToken(t, m, "test-user-123")
	m.SetTokenBlacklist(&fakeEngineBlacklist{})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, _, err := m.validateToken(ctx, token)
	require.ErrorIs(t, err, context.Canceled)

	// Sanity: the same token is accepted with a live context.
	uid, tenantID, tac, err := m.validateToken(context.Background(), token)
	require.NoError(t, err)
	assert.Equal(t, "test-user-123", uid)
	assert.Equal(t, "test-tenant", tenantID)
	assert.Equal(t, claims.TAC("rwl"), tac)
}

// Two RequestSign calls pending at once (a flow awaiting a decryption while a
// notification worker asks for a DPoP proof) must each get their own reply,
// whichever order the replies arrive in and whichever waiter reads them.
func TestSession_RequestSign_ConcurrentWaitersGetOwnReplies(t *testing.T) {
	srvConnCh := make(chan *websocket.Conn, 1)
	clientConn, cleanup := wsTestServer(t, func(srvConn *websocket.Conn) { srvConnCh <- srvConn })
	defer cleanup()
	srvConn := <-srvConnCh
	session := &Session{
		ID:       "s",
		conn:     srvConn,
		flows:    make(map[string]*Flow),
		logger:   zap.NewNop(),
		signCh:   make(chan *SignResponseMessage, 20),
		closeCh:  make(chan struct{}, 1),
		stopPing: make(chan struct{}),
	}

	type result struct {
		resp *SignResponseMessage
		err  error
	}
	results := make(map[string]chan result)
	for _, name := range []string{"a", "b"} {
		ch := make(chan result, 1)
		results[name] = ch
		go func() {
			r, err := session.RequestSign(context.Background(), "f", SignActionGenerateProof, SignRequestParams{JWE: name})
			ch <- result{r, err}
		}()
	}

	// Collect both requests, then answer in reverse order of arrival.
	var reqs []SignRequestMessage
	for len(reqs) < 2 {
		var req SignRequestMessage
		require.NoError(t, clientConn.ReadJSON(&req))
		reqs = append(reqs, req)
	}
	for i := len(reqs) - 1; i >= 0; i-- {
		session.signCh <- &SignResponseMessage{
			Message:       Message{Type: TypeSignResponse, MessageID: reqs[i].MessageID},
			TransactionID: reqs[i].Params.JWE, // tag the reply with its owner
		}
	}
	for name, ch := range results {
		select {
		case r := <-ch:
			require.NoError(t, r.err)
			assert.Equal(t, name, r.resp.TransactionID, "waiter %s got another waiter's reply", name)
		case <-time.After(5 * time.Second):
			t.Fatalf("waiter %s never got its reply", name)
		}
	}
}

// hasUserIndexed reports whether userID has an entry in m.userIndex under any
// tenant. The caller must hold m.sessionsMu.
func hasUserIndexed(m *Manager, userID string) bool {
	for k := range m.userIndex {
		if k.UserID == userID {
			return true
		}
	}
	return false
}

// newMultiTenantTestSession returns a session bound to a real (loopback)
// WebSocket connection, so registerSession's supersede path closes a live
// connection exactly as in production.
func newMultiTenantTestSession(t *testing.T, id, tenantID, userID string) *Session {
	t.Helper()
	srvConnCh := make(chan *websocket.Conn, 1)
	_, cleanup := wsTestServer(t, func(srvConn *websocket.Conn) { srvConnCh <- srvConn })
	t.Cleanup(cleanup)
	return &Session{
		ID: id, TenantID: tenantID, UserID: userID, conn: <-srvConnCh,
		flows: make(map[string]*Flow), logger: zap.NewNop(),
	}
}

// sessionConnClosed reports whether the session's server-side connection has
// been closed (a control write on a closed connection fails).
func sessionConnClosed(s *Session) bool {
	return s.conn.WriteControl(websocket.PingMessage, nil, time.Now().Add(time.Second)) != nil
}

// isCurrentSessionForTest reports whether s is still the registered session for its
// (tenant, user).
func (m *Manager) isCurrentSessionForTest(s *Session) bool {
	m.sessionsMu.RLock()
	defer m.sessionsMu.RUnlock()
	if m.sessions[s.ID] != s {
		return false
	}
	return s.UserID == "" || m.userIndex[s.userKey()] == s
}

// A user in tenants A and B keeps one session in each; a second session in
// the same tenant supersedes only that tenant's first.
func TestManager_RegisterSession_OneSessionPerTenantUser(t *testing.T) {
	cfg := &config.Config{JWT: config.JWTConfig{Secret: "test-secret", Issuer: "test-issuer"}}
	m := NewManager(cfg, zap.NewNop())
	defer m.Close()

	a1 := newMultiTenantTestSession(t, "a1", "tenant-a", "user-1")
	b1 := newMultiTenantTestSession(t, "b1", "tenant-b", "user-1")
	require.True(t, m.registerSession(a1))
	require.True(t, m.registerSession(b1))

	assert.False(t, sessionConnClosed(a1), "a session in tenant B must not supersede tenant A's")
	assert.True(t, m.isCurrentSessionForTest(a1))
	assert.True(t, m.isCurrentSessionForTest(b1))
	gotA, err := m.GetSessionByUser("tenant-a", "user-1")
	require.NoError(t, err)
	assert.Same(t, a1, gotA)
	gotB, err := m.GetSessionByUser("tenant-b", "user-1")
	require.NoError(t, err)
	assert.Same(t, b1, gotB)

	a2 := newMultiTenantTestSession(t, "a2", "tenant-a", "user-1")
	require.True(t, m.registerSession(a2))
	assert.True(t, sessionConnClosed(a1))
	assert.False(t, m.isCurrentSessionForTest(a1))
	assert.True(t, m.isCurrentSessionForTest(a2))
	assert.True(t, m.isCurrentSessionForTest(b1), "tenant B session must survive tenant A supersede")
	assert.False(t, sessionConnClosed(b1))

	// Unregistering the superseded session must not drop its successor's index.
	m.unregisterSession(a1)
	assert.True(t, m.isCurrentSessionForTest(a2))

	// Anonymous sessions are never indexed or superseded.
	an1 := newMultiTenantTestSession(t, "an1", "tenant-a", "")
	an2 := newMultiTenantTestSession(t, "an2", "tenant-a", "")
	require.True(t, m.registerSession(an1))
	require.True(t, m.registerSession(an2))
	assert.True(t, m.isCurrentSessionForTest(an1))
	assert.True(t, m.isCurrentSessionForTest(an2))
	assert.False(t, sessionConnClosed(an1))
}

// Persisted session bookkeeping is also per (tenant, user).
func TestManager_RegisterSession_StoreKeepsBothTenants(t *testing.T) {
	cfg := &config.Config{JWT: config.JWTConfig{Secret: "test-secret", Issuer: "test-issuer"}}
	m := NewManager(cfg, zap.NewNop())
	store := NewMemorySessionStore(zap.NewNop())
	m.SetSessionStore(store)
	defer m.Close()
	ctx := context.Background()

	require.True(t, m.registerSession(newMultiTenantTestSession(t, "a1", "tenant-a", "user-1")))
	require.True(t, m.registerSession(newMultiTenantTestSession(t, "b1", "tenant-b", "user-1")))
	_, err := store.GetByUser(ctx, "tenant-a", "user-1")
	require.NoError(t, err)
	_, err = store.GetByUser(ctx, "tenant-b", "user-1")
	require.NoError(t, err)

	require.True(t, m.registerSession(newMultiTenantTestSession(t, "a2", "tenant-a", "user-1")))
	_, err = store.Get(ctx, "a1")
	assert.ErrorIs(t, err, ErrSessionNotFound)
	_, err = store.Get(ctx, "b1")
	require.NoError(t, err)
	got, err := store.GetByUser(ctx, "tenant-a", "user-1")
	require.NoError(t, err)
	assert.Equal(t, "a2", got.ID)
}

// User-wide revocation closes the user's sessions in every tenant.
func TestManager_CloseUserSessions_ClosesSessionsInAllTenants(t *testing.T) {
	cfg := &config.Config{JWT: config.JWTConfig{Secret: "test-secret", Issuer: "test-issuer"}}
	m := NewManager(cfg, zap.NewNop())
	defer m.Close()

	a := newMultiTenantTestSession(t, "a", "tenant-a", "user-1")
	b := newMultiTenantTestSession(t, "b", "tenant-b", "user-1")
	other := newMultiTenantTestSession(t, "other", "tenant-a", "user-2")
	require.True(t, m.registerSession(a))
	require.True(t, m.registerSession(b))
	require.True(t, m.registerSession(other))

	assert.Equal(t, 2, m.CloseUserSessions("user-1", "account deleted"))
	assert.True(t, sessionConnClosed(a))
	assert.True(t, sessionConnClosed(b))
	assert.False(t, sessionConnClosed(other))
}

func TestMemorySessionStore_DeleteByUser_AllTenants(t *testing.T) {
	store := NewMemorySessionStore(zap.NewNop())
	ctx := context.Background()
	exp := time.Now().Add(time.Hour)
	for _, s := range []*SessionData{
		{ID: "a", UserID: "u", TenantID: "ta", ExpiresAt: exp},
		{ID: "b", UserID: "u", TenantID: "tb", ExpiresAt: exp},
		{ID: "c", UserID: "other", TenantID: "ta", ExpiresAt: exp},
	} {
		require.NoError(t, store.Put(ctx, s))
	}
	require.NoError(t, store.Delete(ctx, "ta", "u", "a"))
	_, err := store.GetByUser(ctx, "tb", "u")
	require.NoError(t, err, "deleting tenant A's session must not drop tenant B's index")

	require.NoError(t, store.DeleteByUser(ctx, "u"))
	_, err = store.Get(ctx, "b")
	assert.ErrorIs(t, err, ErrSessionNotFound)
	_, err = store.Get(ctx, "c")
	assert.NoError(t, err)
}

// A token without a tenant_id claim belongs to the default tenant (as the
// HTTP middleware already treats it), so a WebSocket session for it is
// indexed and persisted under "default" rather than under an empty tenant.
func TestManager_validateToken_MissingTenantNormalisedToDefault(t *testing.T) {
	cfg := &config.Config{JWT: config.JWTConfig{Secret: "test-secret", Issuer: "test-issuer"}}
	m := NewManager(cfg, zap.NewNop())
	v, key, issuer := setupEngineTokenValidatorTest(t)
	m.SetTokenValidator(v)

	token := signEngineToken(t, key, issuer, claims.AccessTokenClaims{
		Claims: gojosejwt.Claims{Audience: gojosejwt.Audience{"wallet-registry"}},
		TAC:    "r",
		ACR:    "urn:siros:acr:passkey",
	})
	_, tenantID, _, err := m.validateToken(context.Background(), token)
	require.NoError(t, err)
	assert.Equal(t, "default", tenantID)
}

func TestManager_RegisterSession_EmptyTenantIndexedAsDefault(t *testing.T) {
	cfg := &config.Config{JWT: config.JWTConfig{Secret: "test-secret", Issuer: "test-issuer"}}
	m := NewManager(cfg, zap.NewNop())
	store := NewMemorySessionStore(zap.NewNop())
	m.SetSessionStore(store)
	defer m.Close()
	ctx := context.Background()

	empty := newMultiTenantTestSession(t, "empty", "", "user-nt")
	require.True(t, m.registerSession(empty))
	got, err := m.GetSessionByUser("default", "user-nt")
	require.NoError(t, err, "an empty-tenant session must be found under the default tenant")
	assert.Same(t, empty, got)
	_, err = m.GetSessionByUser("", "user-nt")
	assert.NoError(t, err, "an empty tenant resolves to default on lookup too")
	_, err = store.GetByUser(ctx, "default", "user-nt")
	assert.NoError(t, err, "the persisted session must be under the default tenant")
	listed, err := m.ListSessions(ctx, "")
	require.NoError(t, err)
	assert.Len(t, listed, 1)

	// A session explicitly in the default tenant supersedes the empty-tenant one.
	explicit := newMultiTenantTestSession(t, "explicit", "default", "user-nt")
	require.True(t, m.registerSession(explicit))
	assert.True(t, sessionConnClosed(empty))
	assert.False(t, m.isCurrentSessionForTest(empty))
	assert.True(t, m.isCurrentSessionForTest(explicit))
}

// TestHandleNewConnection_EmptyTACRefusedOnFlowStart drives the real WebSocket
// handshake and flow_start with real go-tokenauth tokens: a token with an
// empty TAC is authenticated (the handshake completes) but gets no
// permissions, so flow_start is refused for a protocol that needs one; a token
// with a sufficient TAC works.
func TestHandleNewConnection_EmptyTACRefusedOnFlowStart(t *testing.T) {
	m := newManagerWithStubOID4VCIHandler(t)
	v, key, issuer := setupEngineTokenValidatorTest(t)
	m.SetTokenValidator(v)

	server := httptest.NewServer(http.HandlerFunc(m.HandleConnection))
	t.Cleanup(server.Close)
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")

	token := func(tac claims.TAC) string {
		return signEngineToken(t, key, issuer, claims.AccessTokenClaims{
			Claims:   gojosejwt.Claims{Audience: gojosejwt.Audience{"wallet-backend"}, Subject: "user-0123456789"},
			TenantID: "test-tenant",
			TAC:      tac,
			ACR:      "urn:siros:acr:passkey",
		})
	}

	cases := []struct {
		name      string
		tac       claims.TAC
		forbidden bool
	}{
		{"empty TAC refused", "", true},
		{"insufficient TAC refused", "r", true},
		{"sufficient TAC allowed", claims.TAC(requiredTACForProtocol[ProtocolOID4VCI]), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ws, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
			require.NoError(t, err)
			defer func() { _ = ws.Close() }()
			require.NoError(t, ws.WriteJSON(HandshakeMessage{Message: Message{Type: TypeHandshake}, AppToken: token(tc.tac)}))
			var complete HandshakeCompleteMessage
			require.NoError(t, ws.ReadJSON(&complete))
			require.Equal(t, TypeHandshakeComplete, complete.Type)

			require.NoError(t, ws.WriteJSON(FlowStartMessage{
				Message:  Message{Type: TypeFlowStart, FlowID: "flow-1234"},
				Protocol: ProtocolOID4VCI,
			}))
			_ = ws.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			var fe FlowErrorMessage
			err = ws.ReadJSON(&fe)
			if tc.forbidden {
				require.NoError(t, err)
				assert.Equal(t, ErrCodeForbidden, fe.Error.Code)
			} else {
				assert.Error(t, err, "no flow_error expected")
			}
		})
	}
}
