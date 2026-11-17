package engine

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

func TestAuthorizationResponseIssuer(t *testing.T) {
	for _, resumed := range []bool{false, true} {
		for _, tc := range []struct {
			name       string
			advertised *bool
			requireIss bool
			response   string
			wantError  string
		}{
			{"advertised missing", boolPointer(true), false, "", "missing iss"},
			{"advertised empty", boolPointer(true), false, `,"iss":""`, "empty iss"},
			{"advertised null", boolPointer(true), false, `,"iss":null`, "must be a string"},
			{"advertised incorrect", boolPointer(true), false, `,"iss":"https://wrong.example"`, "issuer mismatch"},
			{"credential issuer is not AS", boolPointer(true), false, `,"iss":"https://credentials.example"`, "issuer mismatch"},
			{"trailing slash differs", boolPointer(true), false, `,"iss":"$AS/"`, "issuer mismatch"},
			{"duplicate", boolPointer(true), false, `,"iss":"https://wrong.example","iss":"$AS"`, "duplicate iss"},
			{"multiple values", boolPointer(true), false, `,"iss":["$AS","$AS"]`, "must be a string"},
			{"advertised matching", boolPointer(true), false, `,"iss":"$AS"`, ""},
			{"verifier mismatch", boolPointer(true), false, `,"iss":"$AS","code_verifier":"wrong"`, "code_verifier does not match"},
			{"unadvertised absent", nil, false, "", ""},
			{"explicit false absent", boolPointer(false), false, "", ""},
			{"unadvertised mismatch", nil, false, `,"iss":"https://wrong.example"`, "issuer mismatch"},
			{"explicit false mismatch", boolPointer(false), false, `,"iss":"https://wrong.example"`, "issuer mismatch"},
			{"FAPI missing", nil, true, "", "missing iss"},
			{"FAPI matching", boolPointer(false), true, `,"iss":"$AS"`, ""},
		} {
			name := tc.name + "/live"
			if resumed {
				name = tc.name + "/resumed"
			}
			t.Run(name, func(t *testing.T) {
				var tokenRequests atomic.Int32
				mux := http.NewServeMux()
				mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
					doc := map[string]interface{}{
						"issuer":                 "http://" + r.Host,
						"authorization_endpoint": "http://" + r.Host + "/authorize",
						"token_endpoint":         "http://" + r.Host + "/token",
					}
					if tc.advertised != nil {
						doc["authorization_response_iss_parameter_supported"] = *tc.advertised
					}
					_ = json.NewEncoder(w).Encode(doc)
				})
				mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
					tokenRequests.Add(1)
					_ = json.NewEncoder(w).Encode(TokenResponse{AccessToken: "token"})
				})
				server := httptest.NewServer(mux)
				defer server.Close()
				metadata := &IssuerMetadata{
					CredentialIssuer:     "https://credentials.example",
					AuthorizationServers: []string{server.URL},
					TokenEndpoint:        server.URL + "/token",
				}
				response := strings.ReplaceAll(tc.response, "$AS", server.URL)
				cfg := &config.Config{
					JWT:      config.JWTConfig{Secret: "test-authorization-context-secret-32-bytes"},
					Security: config.SecurityConfig{RequireAuthorizationResponseIssuer: tc.requireIss},
				}

				var err error
				if resumed {
					h, cleanup := testOID4VCIHandler(t, server.Client())
					defer cleanup()
					h.Config = cfg
					msg := &FlowStartMessage{AuthCode: "code", CodeVerifier: "verifier", RedirectURI: "https://wallet.example.com/cb"}
					oauthMeta := &oauthServerMetadata{}
					if tc.advertised != nil {
						oauthMeta.AuthorizationResponseIssParameterSupported = *tc.advertised
					}
					prepareAuthCodeResumption(t, h, msg, metadata, oauthMeta)
					base, marshalErr := json.Marshal(msg)
					require.NoError(t, marshalErr)
					payload := append(base[:len(base)-1], []byte(response+"}")...)
					err = json.Unmarshal(payload, msg)
					if err == nil {
						_, err = h.resumeWithAuthCode(context.Background(), msg, metadata)
					}
				} else {
					actions := make(chan *FlowActionMessage, 1)
					conn, cleanup := wsTestServer(t, func(conn *websocket.Conn) {
						defer conn.Close()
						for {
							var progress FlowProgressMessage
							if conn.ReadJSON(&progress) != nil {
								return
							}
							var data struct {
								State          string `json:"state"`
								Context        string `json:"authorization_context"`
								ExpectedIssuer string `json:"expected_issuer"`
								RequireIssuer  bool   `json:"require_iss"`
							}
							if json.Unmarshal(progress.Payload, &data) != nil || data.State == "" {
								continue
							}
							assert.NotEmpty(t, data.Context)
							assert.Equal(t, server.URL, data.ExpectedIssuer)
							assert.Equal(t, tc.requireIss || (tc.advertised != nil && *tc.advertised), data.RequireIssuer)
							payload := `{"code":"code","state":"` + data.State + `"` + response + `}`
							actions <- &FlowActionMessage{Action: ActionAuthorizationComplete, Payload: json.RawMessage(payload)}
						}
					})
					defer cleanup()
					session := testSession(conn)
					flow := registerTestFlow(session, "issuance")
					flow.actions = actions
					h := &OID4VCIHandler{
						BaseHandler: BaseHandler{Flow: flow, Config: cfg, Logger: zap.NewNop()},
						httpClient:  server.Client(), redirectURI: "https://wallet.example.com/cb",
						clientAuthMode: clientAuthLegacy, legacyAttestationRequested: true,
					}
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()
					_, err = h.handleAuthorizationCode(ctx, &CredentialOffer{}, metadata, &CredentialConfig{Scope: "pid"})
				}
				if tc.wantError != "" {
					require.ErrorContains(t, err, tc.wantError)
					assert.Zero(t, tokenRequests.Load(), "invalid response must never reach token endpoint")
				} else {
					require.NoError(t, err)
					assert.EqualValues(t, 1, tokenRequests.Load())
				}
			})
		}
	}
}

func boolPointer(value bool) *bool { return &value }

func TestResumeAuthorizationTransactionBinding(t *testing.T) {
	for _, tc := range []struct {
		name      string
		mutate    func(*OID4VCIHandler, *FlowStartMessage, *IssuerMetadata)
		wantError string
	}{
		{"missing context", func(_ *OID4VCIHandler, m *FlowStartMessage, _ *IssuerMetadata) { m.AuthorizationContext = "" }, "authorization_context is required"},
		{"tampered context", func(_ *OID4VCIHandler, m *FlowStartMessage, _ *IssuerMetadata) { m.AuthorizationContext += "invalid" }, "invalid or expired"},
		{"state mismatch", func(_ *OID4VCIHandler, m *FlowStartMessage, _ *IssuerMetadata) { m.State = "wrong" }, "state parameter mismatch"},
		{"missing state", func(_ *OID4VCIHandler, m *FlowStartMessage, _ *IssuerMetadata) { m.State = "" }, "state parameter mismatch"},
		{"verifier mismatch", func(_ *OID4VCIHandler, m *FlowStartMessage, _ *IssuerMetadata) { m.CodeVerifier = "wrong" }, "code_verifier does not match"},
		{"redirect mismatch", func(_ *OID4VCIHandler, m *FlowStartMessage, _ *IssuerMetadata) { m.RedirectURI += "/wrong" }, "redirect_uri does not match"},
		{"tenant mismatch", func(h *OID4VCIHandler, _ *FlowStartMessage, _ *IssuerMetadata) { h.Flow.Session.TenantID = "other" }, "does not match this flow"},
		{"user mismatch", func(h *OID4VCIHandler, _ *FlowStartMessage, _ *IssuerMetadata) { h.Flow.Session.UserID = "other" }, "does not match this flow"},
		{"AS changed", func(_ *OID4VCIHandler, _ *FlowStartMessage, md *IssuerMetadata) {
			md.AuthorizationServer = "https://other.example"
		}, "does not match this flow"},
		{"issuer changed", func(_ *OID4VCIHandler, _ *FlowStartMessage, md *IssuerMetadata) { md.CredentialIssuer += "/other" }, "does not match this flow"},
		{"client changed", func(h *OID4VCIHandler, _ *FlowStartMessage, _ *IssuerMetadata) { h.clientID = "other" }, "does not match this flow"},
		{"expired context", func(h *OID4VCIHandler, m *FlowStartMessage, md *IssuerMetadata) {
			transaction, err := h.parseAuthorizationContext(m.AuthorizationContext, md)
			require.NoError(t, err)
			transaction.ExpiresAt = jwt.NewNumericDate(time.Now().Add(-time.Minute))
			key, err := h.authorizationContextKey()
			require.NoError(t, err)
			m.AuthorizationContext, err = jwt.NewWithClaims(jwt.SigningMethodHS256, transaction).SignedString(key)
			require.NoError(t, err)
		}, "invalid or expired"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var tokenRequests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/token" {
					tokenRequests.Add(1)
				}
				w.WriteHeader(http.StatusNotFound)
			}))
			defer server.Close()
			h, cleanup := testOID4VCIHandler(t, server.Client())
			defer cleanup()
			md := &IssuerMetadata{CredentialIssuer: server.URL, TokenEndpoint: server.URL + "/token"}
			msg := &FlowStartMessage{AuthCode: "code", CodeVerifier: "verifier", RedirectURI: "https://wallet.example.com/cb"}
			prepareAuthCodeResumption(t, h, msg, md, nil)
			tc.mutate(h, msg, md)
			_, err := h.resumeWithAuthCode(context.Background(), msg, md)
			require.ErrorContains(t, err, tc.wantError)
			assert.Zero(t, tokenRequests.Load())
		})
	}
}

func TestResumeAuthorizationCannotDowngradeIssuerRequirement(t *testing.T) {
	for _, discoveryFails := range []bool{false, true} {
		t.Run(map[bool]string{false: "changed metadata", true: "discovery failure"}[discoveryFails], func(t *testing.T) {
			var tokenRequests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/token" {
					tokenRequests.Add(1)
					_ = json.NewEncoder(w).Encode(TokenResponse{AccessToken: "token"})
				} else if discoveryFails {
					w.WriteHeader(http.StatusServiceUnavailable)
				} else {
					_ = json.NewEncoder(w).Encode(map[string]interface{}{
						"issuer":         "http://" + r.Host,
						"token_endpoint": "http://" + r.Host + "/different-token",
						"authorization_response_iss_parameter_supported": false,
						"code_challenge_methods_supported":               []string{},
					})
				}

			}))
			defer server.Close()
			h, cleanup := testOID4VCIHandler(t, server.Client())
			defer cleanup()
			md := &IssuerMetadata{CredentialIssuer: server.URL, TokenEndpoint: server.URL + "/token"}
			msg := &FlowStartMessage{AuthCode: "code", CodeVerifier: "verifier", RedirectURI: "https://wallet.example.com/cb"}
			prepareAuthCodeResumption(t, h, msg, md, &oauthServerMetadata{AuthorizationResponseIssParameterSupported: true})
			_, err := h.resumeWithAuthCode(context.Background(), msg, md)
			require.ErrorContains(t, err, "missing iss")
			assert.Zero(t, tokenRequests.Load())
			issuer := server.URL
			msg.AuthorizationResponseIssuer = &issuer
			md.TokenEndpoint = server.URL + "/different-token"
			_, err = h.resumeWithAuthCode(context.Background(), msg, md)
			require.NoError(t, err)
			assert.EqualValues(t, 1, tokenRequests.Load(), "must use originally bound token endpoint")
		})
	}
}

func TestAuthorizationContextSurvivesNewHandler(t *testing.T) {
	var tokenRequests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/token" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		tokenRequests.Add(1)
		_ = json.NewEncoder(w).Encode(TokenResponse{AccessToken: "token"})
	}))
	defer server.Close()
	original, cleanup := testOID4VCIHandler(t, server.Client())
	defer cleanup()
	original.clientID = "registered-wallet"
	md := &IssuerMetadata{CredentialIssuer: server.URL, TokenEndpoint: server.URL + "/token"}
	issuer := server.URL
	msg := &FlowStartMessage{
		AuthCode: "code", CodeVerifier: "verifier", RedirectURI: "https://wallet.example.com/cb",
		AuthorizationResponseIssuer: &issuer,
	}
	prepareAuthCodeResumption(t, original, msg, md, &oauthServerMetadata{AuthorizationResponseIssParameterSupported: true})

	resumed, resumeCleanup := testOID4VCIHandler(t, server.Client())
	defer resumeCleanup()
	resumed.Config = original.Config
	resumed.clientID = original.clientID
	resumed.Flow.Session.ID = "new-session"
	_, err := resumed.resumeWithAuthCode(context.Background(), msg, md)
	require.NoError(t, err)
	assert.EqualValues(t, 1, tokenRequests.Load())
}
