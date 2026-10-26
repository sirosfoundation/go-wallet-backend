package engine

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// zkpClientMetadata is a client_metadata as a zkp_req verifier sends it. The
// vp_formats_supported member is not modelled by ClientMetadata, so it only
// survives if the raw object is relayed.
const zkpClientMetadata = `{"jwks":{"keys":[{"kty":"EC","crv":"P-256","use":"enc","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}]},` +
	`"vp_formats_supported":{"zkp_req":{"system_id_values":["longfellow-libzk-v1"],"proof_system_values":["vega"]}},` +
	`"future_member":{"a":[1,2,3]}}`

func TestExtractRawClientMetadata(t *testing.T) {
	req := `{"client_id":"x","client_metadata":` + zkpClientMetadata + `}`
	raw, err := extractRawClientMetadata([]byte(req))
	require.NoError(t, err)
	assert.JSONEq(t, zkpClientMetadata, string(raw))

	for name, in := range map[string]string{
		"absent":        `{"client_id":"x"}`,
		"null":          `{"client_metadata":null}`,
		"not an object": `{"client_metadata":"str"}`,
		"garbage":       `not json`,
	} {
		raw, err := extractRawClientMetadata([]byte(in))
		require.NoError(t, err, name)
		assert.Nil(t, raw, name)
	}
}

func TestParseRequestJWT_KeepsClientMetadataVerbatim(t *testing.T) {
	payload := `{"response_type":"vp_token","client_id":"x","response_mode":"direct_post.jwt",` +
		`"dcql_query":{"credentials":[{"id":"q","format":"zkp_req","_req":[{"k":1}]}]},"client_metadata":` + zkpClientMetadata + `}`
	jwt := "e30." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".sig"
	h := &OID4VPHandler{BaseHandler: BaseHandler{Logger: zap.NewNop()}}

	authReq, err := h.parseRequestJWT(jwt)
	require.NoError(t, err)
	assert.JSONEq(t, zkpClientMetadata, string(authReq.ClientMetadataRaw))
	// Q3: the DCQL query, with its unknown format and _req member, is untouched.
	assert.JSONEq(t, `{"credentials":[{"id":"q","format":"zkp_req","_req":[{"k":1}]}]}`, string(authReq.DCQLQuery))
}

func TestFetchClientMetadata_ReturnsRawObject(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(zkpClientMetadata))
	}))
	defer srv.Close()
	h := &OID4VPHandler{BaseHandler: BaseHandler{Logger: zap.NewNop()}}
	h.httpClient = srv.Client()

	cm, raw, err := h.fetchClientMetadata(context.Background(), srv.URL)
	require.NoError(t, err)
	assert.NotNil(t, cm)
	assert.JSONEq(t, zkpClientMetadata, string(raw))
}

func TestSignRequestParams_ClientMetadata_RoundTripAndOmitted(t *testing.T) {
	p := SignRequestParams{ClientMetadata: json.RawMessage(zkpClientMetadata)}
	b, err := json.Marshal(p)
	require.NoError(t, err)
	var back SignRequestParams
	require.NoError(t, json.Unmarshal(b, &back))
	assert.JSONEq(t, zkpClientMetadata, string(back.ClientMetadata))

	b, err = json.Marshal(SignRequestParams{})
	require.NoError(t, err)
	assert.NotContains(t, string(b), "client_metadata")
}

func TestMatchRequestMessage_ClientMetadata_RoundTripAndOmitted(t *testing.T) {
	m := MatchRequestMessage{DCQLQuery: json.RawMessage(`{}`), ClientMetadata: json.RawMessage(zkpClientMetadata)}
	b, err := json.Marshal(m)
	require.NoError(t, err)
	var back MatchRequestMessage
	require.NoError(t, json.Unmarshal(b, &back))
	assert.JSONEq(t, zkpClientMetadata, string(back.ClientMetadata))

	b, err = json.Marshal(MatchRequestMessage{DCQLQuery: json.RawMessage(`{}`)})
	require.NoError(t, err)
	assert.NotContains(t, string(b), "client_metadata")
}

func TestRequestMatchWithClientMetadata_SendsIt(t *testing.T) {
	h, _, received, cleanup := newSelectionTestHandler(t)
	defer cleanup()
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_, _ = h.RequestMatchWithClientMetadata(ctx, json.RawMessage(`{"credentials":[]}`), &VerifiedRequestInputs{ClientMetadata: json.RawMessage(zkpClientMetadata)})

	msg := awaitMessage(t, received, "match_request")
	cm, ok := msg["client_metadata"].(map[string]any)
	require.True(t, ok, "client_metadata must be a JSON object on the wire")
	assert.Contains(t, cm, "vp_formats_supported")
}

func TestRequestCredentialSelection_RelaysClientMetadata(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  json.RawMessage
		want bool
	}{{"present", json.RawMessage(zkpClientMetadata), true}, {"absent", nil, false}} {
		t.Run(tc.name, func(t *testing.T) {
			h, session, received, cleanup := newSelectionTestHandler(t)
			defer cleanup()
			authReq := &AuthorizationRequest{
				DCQLQuery:         json.RawMessage(`{"credentials":[{"id":"q","format":"zkp_req"}]}`),
				ClientMetadataRaw: tc.raw,
			}
			feedAction(t, session, h.Flow.ID, ActionDecline, map[string]string{"reason": "x"})
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_, _ = h.requestCredentialSelection(ctx, authReq, &VerifierInfo{})

			msg := awaitMessage(t, received, "flow_progress")
			cm, has := msg["client_metadata"]
			if !has {
				if m, ok := msg["payload"].(map[string]any); ok {
					cm, has = m["client_metadata"]
				}
			}
			if tc.want {
				require.True(t, has, "msg: %v", msg)
				assert.Contains(t, cm, "vp_formats_supported")
			} else {
				assert.False(t, has)
			}
		})
	}
}

// RFC 7638 section 3.1 example key and its published SHA-256 thumbprint.
func TestComputeVerifierJWKThumbprint_RFC7638Vector(t *testing.T) {
	jwks := `{"keys":[{"kty":"RSA","use":"enc","e":"AQAB","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"}]}`
	h := &OID4VPHandler{BaseHandler: BaseHandler{Logger: zap.NewNop()}}
	got, err := h.computeVerifierJWKThumbprint(&AuthorizationRequest{
		ResponseMode:   ResponseModeDirectPostJWT,
		ClientMetadata: &ClientMetadata{JWKS: json.RawMessage(jwks)},
	})
	require.NoError(t, err)
	assert.Equal(t, "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs", got)
}

func TestRequestVPSignature_DirectPostJWTWithoutKeyFailsBeforeSigning(t *testing.T) {
	h, _, received, cleanup := newSelectionTestHandler(t)
	defer cleanup()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := h.requestVPSignature(ctx, &AuthorizationRequest{ResponseMode: ResponseModeDirectPostJWT, ClientID: "x"},
		[]ConsentSelection{{CredentialID: "c", CredentialQueryID: "q"}}, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "direct_post.jwt")
	select {
	case m := <-received:
		t.Fatalf("no sign_request may be sent, got %v", m)
	case <-time.After(150 * time.Millisecond):
	}
}

// A zkp_req presentation is a base64url string of a CBOR ZkpPresentation: no
// newline, and not JSON. It must land untouched in {queryId: [token]}.
func TestBuildDCQLVPToken_ZkpPresentationString(t *testing.T) {
	token := base64.RawURLEncoding.EncodeToString([]byte{0xa1, 0x62, 'h', 'i', 0x01, 0xff, 0xfe})
	out, err := buildDCQLVPToken(token, []ConsentSelection{{CredentialID: "c", CredentialQueryID: "zkp"}})
	require.NoError(t, err)
	assert.JSONEq(t, `{"zkp":["`+token+`"]}`, out)
}

// A query with an unknown format and `_req` member passes the consent check
// unchanged (it only reads the members it needs).
func TestCheckConsentAgainstDCQL_ZkpReqQuery(t *testing.T) {
	q := json.RawMessage(`{"credentials":[{"id":"zkp","format":"zkp_req","_req":[{"x":1}]}]}`)
	v, err := checkConsentAgainstDCQL(q, []ConsentSelection{{CredentialID: "c", CredentialQueryID: "zkp"}})
	require.NoError(t, err)
	assert.Nil(t, v)
}

func TestRequestVPSignature_RelaysClientMetadataToSignRequest(t *testing.T) {
	h, _, received, cleanup := newSelectionTestHandler(t)
	defer cleanup()
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	_, _ = h.requestVPSignature(ctx, &AuthorizationRequest{
		ResponseMode:      ResponseModeDirectPostJWT,
		ClientID:          "x",
		ClientMetadata:    &ClientMetadata{JWKS: json.RawMessage(`{"keys":[{"kty":"EC","crv":"P-256","use":"enc","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}]}`)},
		ClientMetadataRaw: json.RawMessage(zkpClientMetadata),
	}, []ConsentSelection{{CredentialID: "c", CredentialQueryID: "q"}}, "")

	msg := awaitMessage(t, received, "sign_request")
	params, _ := msg["params"].(map[string]any)
	cm, ok := params["client_metadata"].(map[string]any)
	require.True(t, ok, "params: %v", params)
	assert.Contains(t, cm, "vp_formats_supported")
	assert.NotEmpty(t, params["verifier_jwk_thumbprint"])
}

// paddedClientMetadata returns a JSON object of exactly size bytes.
func paddedClientMetadata(t *testing.T, size int) string {
	t.Helper()
	const head, tail = `{"pad":"`, `"}`
	require.Greater(t, size, len(head)+len(tail))
	out := head + strings.Repeat("x", size-len(head)-len(tail)) + tail
	require.Len(t, out, size)
	return out
}

func TestFetchClientMetadata_SizeBound(t *testing.T) {
	atLimit := paddedClientMetadata(t, MaxClientMetadataBytes)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/over" {
			_, _ = w.Write([]byte(paddedClientMetadata(t, MaxClientMetadataBytes+1)))
			return
		}
		_, _ = w.Write([]byte(atLimit))
	}))
	defer srv.Close()
	h := &OID4VPHandler{BaseHandler: BaseHandler{Logger: zap.NewNop()}}
	h.httpClient = srv.Client()

	_, raw, err := h.fetchClientMetadata(context.Background(), srv.URL+"/at")
	require.NoError(t, err, "exactly at the limit is accepted")
	assert.Len(t, raw, MaxClientMetadataBytes)

	cm, raw, err := h.fetchClientMetadata(context.Background(), srv.URL+"/over")
	require.ErrorIs(t, err, errClientMetadataTooLarge, "limit+1 is refused, not truncated")
	assert.Nil(t, cm)
	assert.Nil(t, raw)
}

func TestClientMetadata_InlineSizeBound(t *testing.T) {
	h := &OID4VPHandler{BaseHandler: BaseHandler{Logger: zap.NewNop()}}

	// Inside a request object (JWT payload and plain JSON).
	for _, tc := range []struct {
		size int
		ok   bool
	}{{MaxClientMetadataBytes, true}, {MaxClientMetadataBytes + 1, false}} {
		cm := paddedClientMetadata(t, tc.size)
		payload := `{"client_id":"x","client_metadata":` + cm + `}`
		jwt := "e30." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".sig"
		authReq, err := h.parseRequestJWT(jwt)
		if tc.ok {
			require.NoError(t, err)
			assert.Len(t, authReq.ClientMetadataRaw, tc.size)
		} else {
			require.ErrorIs(t, err, errClientMetadataTooLarge)
		}
		raw, err := extractRawClientMetadata([]byte(payload))
		if tc.ok {
			require.NoError(t, err)
			assert.Len(t, raw, tc.size)
		} else {
			require.ErrorIs(t, err, errClientMetadataTooLarge)
		}
	}

	// Inline in the authorization request URL.
	for _, tc := range []struct {
		size int
		ok   bool
	}{{MaxClientMetadataBytes, true}, {MaxClientMetadataBytes + 1, false}} {
		q := url.Values{"client_id": {"x"}, "client_metadata": {paddedClientMetadata(t, tc.size)}}
		authReq, err := h.parseRequestFromURL(&url.URL{Scheme: "openid4vp", RawQuery: q.Encode()})
		if tc.ok {
			require.NoError(t, err)
			assert.Len(t, authReq.ClientMetadataRaw, tc.size)
		} else {
			require.ErrorIs(t, err, errClientMetadataTooLarge)
		}
	}

	// A normal few-KB value is untouched.
	q := url.Values{"client_id": {"x"}, "client_metadata": {zkpClientMetadata}}
	authReq, err := h.parseRequestFromURL(&url.URL{Scheme: "openid4vp", RawQuery: q.Encode()})
	require.NoError(t, err)
	assert.JSONEq(t, zkpClientMetadata, string(authReq.ClientMetadataRaw))
}
