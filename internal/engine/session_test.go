package engine

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
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

	v := tokenvalidator.New(tokenvalidator.Config{JWKSURL: srv.URL, Issuer: "test-issuer"})
	v.Start(context.Background())
	t.Cleanup(v.Stop)

	// Poll until the validator has actually fetched the JWKS, rather than
	// sleeping a fixed duration (flaky under slow/contended CI runners).
	probe := signEngineToken(t, key, "test-issuer", claims.AccessTokenClaims{})
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
	cfg := &config.Config{JWT: config.JWTConfig{Secret: "test-secret"}}
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
	cfg := &config.Config{JWT: config.JWTConfig{Secret: "test-secret"}}
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
	cfg := &config.Config{JWT: config.JWTConfig{Secret: "test-secret"}}
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

func TestManager_validateToken_UserID(t *testing.T) {
	cfg := &config.Config{
		JWT: config.JWTConfig{
			Secret: "test-secret",
		},
	}
	logger := zap.NewNop()
	m := NewManager(cfg, logger)

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id":   "test-user-123",
		"tenant_id": "test-tenant",
		"exp":       time.Now().Add(time.Hour).Unix(),
	})
	tokenString, err := token.SignedString([]byte("test-secret"))
	require.NoError(t, err)

	userID, tenantID, tac, err := m.validateToken(tokenString)
	require.NoError(t, err)
	assert.Equal(t, "test-user-123", userID)
	assert.Equal(t, "test-tenant", tenantID)
	// Regression: the legacy HMAC path has no TAC concept at all - callers
	// (handleFlowStart) must treat this as "not applicable", not "no
	// permissions". See requiredTACForProtocol's doc comment.
	assert.Equal(t, claims.TAC(""), tac)
}

func TestManager_validateToken_UUID(t *testing.T) {
	// Test wallet-backend-server compatibility: token has "uuid" instead of "user_id"
	cfg := &config.Config{
		JWT: config.JWTConfig{
			Secret: "test-secret",
		},
	}
	logger := zap.NewNop()
	m := NewManager(cfg, logger)

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"uuid": "uuid-user-456",
		"v":    1, // wallet-backend-server includes version
		"exp":  time.Now().Add(time.Hour).Unix(),
	})
	tokenString, err := token.SignedString([]byte("test-secret"))
	require.NoError(t, err)

	userID, tenantID, _, err := m.validateToken(tokenString)
	require.NoError(t, err)
	assert.Equal(t, "uuid-user-456", userID)
	assert.Empty(t, tenantID) // wallet-backend-server tokens don't have tenant_id
}

func TestManager_validateToken_UserIDTakesPrecedence(t *testing.T) {
	// When both user_id and uuid are present, user_id should take precedence
	cfg := &config.Config{
		JWT: config.JWTConfig{
			Secret: "test-secret",
		},
	}
	logger := zap.NewNop()
	m := NewManager(cfg, logger)

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": "native-user",
		"uuid":    "compat-user",
		"exp":     time.Now().Add(time.Hour).Unix(),
	})
	tokenString, err := token.SignedString([]byte("test-secret"))
	require.NoError(t, err)

	userID, _, _, err := m.validateToken(tokenString)
	require.NoError(t, err)
	assert.Equal(t, "native-user", userID)
}

func TestManager_validateToken_MissingBothUserIDAndUUID(t *testing.T) {
	cfg := &config.Config{
		JWT: config.JWTConfig{
			Secret: "test-secret",
		},
	}
	logger := zap.NewNop()
	m := NewManager(cfg, logger)

	// Create token without user_id or uuid
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"some_other_claim": "value",
		"exp":              time.Now().Add(time.Hour).Unix(),
	})
	tokenString, err := token.SignedString([]byte("test-secret"))
	require.NoError(t, err)

	_, _, _, err = m.validateToken(tokenString)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing user_id or uuid")
}

func TestManager_validateToken_InvalidSigningMethod(t *testing.T) {
	cfg := &config.Config{
		JWT: config.JWTConfig{
			Secret: "test-secret",
		},
	}
	logger := zap.NewNop()
	m := NewManager(cfg, logger)

	// Create token with None signing method (not HMAC)
	token := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims{
		"user_id": "test-user",
		"exp":     time.Now().Add(time.Hour).Unix(),
	})
	tokenString, _ := token.SignedString(jwt.UnsafeAllowNoneSignatureType)

	_, _, _, err := m.validateToken(tokenString)
	assert.Error(t, err)
}

func TestManager_validateToken_ExpiredToken(t *testing.T) {
	cfg := &config.Config{
		JWT: config.JWTConfig{
			Secret: "test-secret",
		},
	}
	logger := zap.NewNop()
	m := NewManager(cfg, logger)

	// Create expired token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": "test-user",
		"exp":     time.Now().Add(-time.Hour).Unix(),
	})
	tokenString, err := token.SignedString([]byte("test-secret"))
	require.NoError(t, err)

	_, _, _, err = m.validateToken(tokenString)
	assert.Error(t, err)
}

func TestManager_validateToken_WrongSecret(t *testing.T) {
	cfg := &config.Config{
		JWT: config.JWTConfig{
			Secret: "correct-secret",
		},
	}
	logger := zap.NewNop()
	m := NewManager(cfg, logger)

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": "test-user",
		"exp":     time.Now().Add(time.Hour).Unix(),
	})
	tokenString, err := token.SignedString([]byte("wrong-secret"))
	require.NoError(t, err)

	_, _, _, err = m.validateToken(tokenString)
	assert.Error(t, err)
}

func TestManager_validateToken_NbfSlightlyInFuture(t *testing.T) {
	cfg := &config.Config{
		JWT: config.JWTConfig{
			Secret: "test-secret",
		},
	}
	logger := zap.NewNop()
	m := NewManager(cfg, logger)

	// Token with nbf 2 seconds in the future — within the 5s leeway
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": "test-user",
		"nbf":     time.Now().Add(2 * time.Second).Unix(),
		"exp":     time.Now().Add(time.Hour).Unix(),
	})
	tokenString, err := token.SignedString([]byte("test-secret"))
	require.NoError(t, err)

	userID, _, _, err := m.validateToken(tokenString)
	require.NoError(t, err)
	assert.Equal(t, "test-user", userID)
}

func TestManager_validateToken_NbfBeyondLeeway(t *testing.T) {
	cfg := &config.Config{
		JWT: config.JWTConfig{
			Secret: "test-secret",
		},
	}
	logger := zap.NewNop()
	m := NewManager(cfg, logger)

	// Token with nbf 10 seconds in the future — beyond the 5s leeway
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": "test-user",
		"nbf":     time.Now().Add(10 * time.Second).Unix(),
		"exp":     time.Now().Add(time.Hour).Unix(),
	})
	tokenString, err := token.SignedString([]byte("test-secret"))
	require.NoError(t, err)

	_, _, _, err = m.validateToken(tokenString)
	assert.Error(t, err)
}

// TestManager_validateToken_GoTokenauth_AllowsRegistryAudience is a
// regression test for the engine transport audience restriction: the engine
// transport, like the AuthZEN proxy, only needs a wallet-registry or
// wallet-backend audience.
func TestManager_validateToken_GoTokenauth_AllowsRegistryAudience(t *testing.T) {
	cfg := &config.Config{JWT: config.JWTConfig{Secret: "test-secret"}}
	m := NewManager(cfg, zap.NewNop())
	v, key, issuer := setupEngineTokenValidatorTest(t)
	m.SetTokenValidator(v)

	token := signEngineToken(t, key, issuer, claims.AccessTokenClaims{
		Claims:   gojosejwt.Claims{Audience: gojosejwt.Audience{"wallet-registry"}},
		TenantID: "test-tenant",
		TAC:      "r",
		ACR:      "urn:siros:acr:passkey",
	})

	_, tenantID, tac, err := m.validateToken(token)
	require.NoError(t, err)
	assert.Equal(t, "test-tenant", tenantID)
	assert.Equal(t, claims.TAC("r"), tac)
}

// TestManager_validateToken_GoTokenauth_RejectsOtherAudience confirms a
// token scoped to a different audience is not usable on the engine
// transport, mirroring the AuthZEN proxy restriction.
func TestManager_validateToken_GoTokenauth_RejectsOtherAudience(t *testing.T) {
	cfg := &config.Config{JWT: config.JWTConfig{Secret: "test-secret"}}
	m := NewManager(cfg, zap.NewNop())
	v, key, issuer := setupEngineTokenValidatorTest(t)
	m.SetTokenValidator(v)

	token := signEngineToken(t, key, issuer, claims.AccessTokenClaims{
		Claims:   gojosejwt.Claims{Audience: gojosejwt.Audience{"some-other-audience"}},
		TenantID: "test-tenant",
		TAC:      "r",
		ACR:      "urn:siros:acr:passkey",
	})

	_, _, _, err := m.validateToken(token)
	assert.Error(t, err)
}

// ===== handleFlowStart TAC enforcement tests =====

// stubFlowHandler is a minimal FlowHandler that succeeds immediately,
// for tests that only care whether handleFlowStart's TAC gate let the
// flow reach a handler at all, not what the handler itself does.
type stubFlowHandler struct{}

func (stubFlowHandler) Execute(ctx context.Context, msg *FlowStartMessage) error { return nil }
func (stubFlowHandler) Cancel()                                                  {}

func newManagerWithStubOID4VCIHandler(t *testing.T) *Manager {
	t.Helper()
	cfg := &config.Config{JWT: config.JWTConfig{Secret: "test-secret"}}
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

	m.handleFlowStart(session, &FlowStartMessage{Protocol: protocol})

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

// TestManager_handleFlowStart_NoOpWhenTACEmpty is a regression test: an
// empty session.TAC means "not applicable" (legacy auth, no TAC concept at
// all - see Manager.validateToken), not "no permissions". A legacy-
// authenticated session must not be blocked from starting any flow.
func TestManager_handleFlowStart_NoOpWhenTACEmpty(t *testing.T) {
	m := newManagerWithStubOID4VCIHandler(t)

	msg := runHandleFlowStart(t, m, "", ProtocolOID4VCI)
	if msg != nil {
		t.Fatalf("expected no flow_error, got code %q", msg.Error.Code)
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

	err := session.SendFlowCompleteWithRefreshToken("test-flow-refresh-token", credentials, "", "opaque-refresh-token-value")
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

	err := session.SendFlowCompleteWithRefreshToken("test-flow-no-refresh-token", nil, "", "")
	require.NoError(t, err)

	var received map[string]interface{}
	err = conn.ReadJSON(&received)
	require.NoError(t, err)

	_, hasRefreshToken := received["refresh_token"]
	assert.False(t, hasRefreshToken, "refresh_token should be omitted when empty")
}
