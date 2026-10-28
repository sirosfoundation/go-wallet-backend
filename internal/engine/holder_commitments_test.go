package engine

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func hcCfg(cm string) *CredentialConfig {
	c := &CredentialConfig{
		VCT: "urn:example:vct",
		ProofTypesSupported: map[string]interface{}{
			"jwt": map[string]interface{}{"alg_values_supported": []string{"ES256"}},
		},
	}
	if cm != "" {
		c.CredentialMetadata = json.RawMessage(cm)
	}
	return c
}

const hcAdv = `{"org.siros.holder_commitments":{"commitments":["psc"]}}`

func TestHolderCommitmentsAdvertisement(t *testing.T) {
	for name, cm := range map[string]string{"none": "", "no member": `{"display":[]}`, "not object": `[1]`} {
		present, _, ok := HolderCommitmentsAdvertisement(json.RawMessage(cm))
		assert.False(t, present, name)
		assert.False(t, ok, name)
	}
	present, names, ok := HolderCommitmentsAdvertisement(json.RawMessage(hcAdv))
	assert.True(t, present)
	assert.True(t, ok)
	assert.Equal(t, []string{"psc"}, names)
	// unknown but well-formed names are fine and are not "psc"
	adv, err := holderCommitmentPSCAdvertised(hcCfg(`{"org.siros.holder_commitments":{"commitments":["other"]}}`))
	require.NoError(t, err)
	assert.False(t, adv)

	hexv := strings.Repeat("ab", 32)
	for name, v := range map[string]string{
		"hex value":        `"` + hexv + `"`,
		"hex name":         `{"commitments":["` + hexv[:16] + `"]}`,
		"values not names": `{"psc":"` + hexv + `"}`,
		"extra member":     `{"commitments":["psc"],"x":"` + hexv + `"}`,
		"empty list":       `{"commitments":[]}`,
		"five names":       `{"commitments":["a","b","c","d","e"]}`,
		"duplicate":        `{"commitments":["psc","psc"]}`,
		"long name":        `{"commitments":["` + strings.Repeat("a", 33) + `"]}`,
		"uppercase":        `{"commitments":["PSC"]}`,
		"non string":       `{"commitments":[7]}`,
		"string list":      `{"commitments":"psc"}`,
		"null":             `null`,
		"empty object":     `{}`,
	} {
		t.Run("malformed/"+name, func(t *testing.T) {
			cfg := hcCfg(`{"org.siros.holder_commitments":` + v + `}`)
			adv, err := holderCommitmentPSCAdvertised(cfg)
			require.Error(t, err)
			assert.False(t, adv)
			assert.NotContains(t, err.Error(), hexv)
			var cc CredentialConfigurations
			require.NoError(t, json.Unmarshal([]byte(`{"x":{"format":"dc+sd-jwt","credential_metadata":{"org.siros.holder_commitments":`+v+`}},"ok":{"format":"dc+sd-jwt"}}`), &cc))
			assert.NotContains(t, cc, "x", "malformed advertisement: configuration not offered")
			assert.Contains(t, cc, "ok")
		})
	}
	var cc CredentialConfigurations
	require.NoError(t, json.Unmarshal([]byte(`{"x":{"format":"dc+sd-jwt","credential_metadata":`+hcAdv[:]+`}}`), &cc))
	assert.Contains(t, cc, "x")
}

func fakeJWT(claims map[string]interface{}) string {
	p, _ := json.Marshal(claims)
	return "e30." + base64.RawURLEncoding.EncodeToString(p) + ".sig"
}

func b64(n int) string { return base64.RawURLEncoding.EncodeToString(make([]byte, n)) }

// runProofs runs requestProofs against a fake wallet that records the sign
// params and answers with the given proof JWT.
func runProofs(t *testing.T, cfg *CredentialConfig, jwt string) (SignRequestParams, []ProofObject, error) {
	t.Helper()
	paramsCh := make(chan SignRequestParams, 1)
	conn, cleanup := wsTestServer(t, func(srvConn *websocket.Conn) {
		defer srvConn.Close()
		_, data, err := srvConn.ReadMessage()
		if err != nil {
			return
		}
		var req SignRequestMessage
		if json.Unmarshal(data, &req) != nil {
			return
		}
		paramsCh <- req.Params
		_ = srvConn.WriteJSON(SignResponseMessage{
			Message: Message{Type: TypeSignResponse, FlowID: req.FlowID, MessageID: req.MessageID},
			Proofs:  []ProofObject{{ProofType: "jwt", JWT: jwt}},
		})
	})
	defer cleanup()
	session := testSession(conn)
	go func() {
		_, data, err := conn.ReadMessage()
		if err != nil {
			return
		}
		var m SignResponseMessage
		if json.Unmarshal(data, &m) == nil {
			session.dispatchSignResponse(&m)
		}
	}()
	h := &OID4VCIHandler{}
	h.BaseHandler = BaseHandler{Flow: &Flow{ID: "f", Session: session, Data: map[string]interface{}{}}, Logger: zap.NewNop()}
	proofs, _, err := h.requestProofs(context.Background(), &IssuerMetadata{CredentialIssuer: "https://issuer.example.com"}, cfg, "n", "", nil)
	var p SignRequestParams
	select {
	case p = <-paramsCh:
	default:
	}
	return p, proofs, err
}

func TestRequestProofs_HolderCommitmentPSC(t *testing.T) {
	good := fakeJWT(map[string]interface{}{"nonce": "n", PSCProofClaim: b64(32)})

	t.Run("advertised: params carry request and good proof accepted", func(t *testing.T) {
		p, proofs, err := runProofs(t, hcCfg(hcAdv), good)
		require.NoError(t, err)
		require.Len(t, proofs, 1)
		assert.Equal(t, []string{"psc"}, p.HolderCommitments)
		assert.Equal(t, "urn:example:vct", p.CredentialType)
		assert.Equal(t, "https://issuer.example.com", p.CredentialIssuer)
	})
	t.Run("not advertised: exactly as before", func(t *testing.T) {
		p, _, err := runProofs(t, hcCfg(""), fakeJWT(map[string]interface{}{"nonce": "n"}))
		require.NoError(t, err)
		assert.Empty(t, p.HolderCommitments)
		assert.Empty(t, p.CredentialType)
		assert.Empty(t, p.CredentialIssuer)
	})
	t.Run("advertised but no vct/doctype: refused", func(t *testing.T) {
		cfg := hcCfg(hcAdv)
		cfg.VCT = ""
		_, _, err := runProofs(t, cfg, good)
		require.Error(t, err)
	})
	t.Run("doctype is the credential type for mdoc", func(t *testing.T) {
		cfg := hcCfg(hcAdv)
		cfg.VCT, cfg.Doctype = "", "org.iso.18013.5.1.mDL"
		p, _, err := runProofs(t, cfg, good)
		require.NoError(t, err)
		assert.Equal(t, "org.iso.18013.5.1.mDL", p.CredentialType)
	})

	pad := base64.URLEncoding.EncodeToString(make([]byte, 32))
	for name, claims := range map[string]map[string]interface{}{
		"claim omitted":         {"nonce": "n"},
		"31 bytes":              {PSCProofClaim: b64(31)},
		"33 bytes":              {PSCProofClaim: b64(33)},
		"padded":                {PSCProofClaim: pad},
		"std alphabet":          {PSCProofClaim: strings.Repeat("+", 43)},
		"not a string":          {PSCProofClaim: 5},
		"empty":                 {PSCProofClaim: ""},
		"hex 64 chars":          {PSCProofClaim: strings.Repeat("ab", 32)},
		"embedded newline":      {PSCProofClaim: b64(32)[:20] + "\r\n" + b64(32)[20:]},
		"nonzero trailing bits": {PSCProofClaim: strings.Repeat("A", 42) + "B"},
		"wrong claim nm":        {"psc": b64(32)},
	} {
		t.Run("wallet misbehaves/"+name, func(t *testing.T) {
			_, proofs, err := runProofs(t, hcCfg(hcAdv), fakeJWT(claims))
			require.Error(t, err)
			assert.Nil(t, proofs)
			for _, v := range claims {
				if s, ok := v.(string); ok && len(s) > 8 {
					assert.NotContains(t, err.Error(), s)
				}
			}
		})
	}
	t.Run("not a JWT", func(t *testing.T) {
		_, _, err := runProofs(t, hcCfg(hcAdv), "garbage")
		require.Error(t, err)
	})
}

func TestPSCConflict_Relayed(t *testing.T) {
	const desc = "org.siros.psc_conflict: this subject is bound to a different wallet secret; ask the issuer operator to approve a reset"
	run := func(t *testing.T, status int, body string, hdr ...string) (*ErrorCodeAndMsg, error) {
		calls := 0
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls++
			w.Header().Set("Content-Type", "application/json")
			if len(hdr) > 0 && calls > 1 {
				// A retry would succeed: only the first answer is the conflict.
				_, _ = w.Write([]byte(`{"credentials":[{"credential":"x"}]}`))
				return
			}
			if len(hdr) > 0 {
				w.Header().Set("DPoP-Nonce", hdr[0])
			}
			w.WriteHeader(status)
			_, _ = w.Write([]byte(body))
		}))
		defer srv.Close()
		got := make(chan FlowErrorMessage, 4)
		conn, cleanup := wsTestServer(t, func(srvConn *websocket.Conn) {
			defer srvConn.Close()
			for {
				_, data, err := srvConn.ReadMessage()
				if err != nil {
					return
				}
				var m FlowErrorMessage
				if json.Unmarshal(data, &m) == nil && m.Type == TypeFlowError {
					got <- m
				}
			}
		})
		defer cleanup()
		h, c2 := testOID4VCIHandler(t, srv.Client())
		defer c2()
		h.Flow.Session.conn = conn
		_, err := h.requestCredential(context.Background(), &IssuerMetadata{CredentialEndpoint: srv.URL},
			&TokenResponse{AccessToken: "t", TokenType: "Bearer"}, "cfg", hcCfg(hcAdv), nil, nil)
		select {
		case m := <-got:
			return &ErrorCodeAndMsg{m.Error.Code, m.Error.Message}, err
		case <-timeAfter():
			return nil, err
		}
	}
	t.Run("conflict gets its own code and the issuer text", func(t *testing.T) {
		e, err := run(t, 400, `{"error":"invalid_request","error_description":"`+desc+`"}`)
		require.Error(t, err)
		require.NotNil(t, e)
		assert.Equal(t, ErrCodePSCConflict, e.Code)
		assert.Equal(t, desc, e.Msg)
	})
	t.Run("conflict carrying a DPoP-Nonce header is still terminal", func(t *testing.T) {
		e, err := run(t, 400, `{"error":"invalid_request","error_description":"`+desc+`"}`, "n1")
		require.Error(t, err)
		require.NotNil(t, e)
		assert.Equal(t, ErrCodePSCConflict, e.Code)
	})
	t.Run("other 400 stays CREDENTIAL_ERROR", func(t *testing.T) {
		e, err := run(t, 400, `{"error":"invalid_request","error_description":"something else"}`)
		require.Error(t, err)
		require.NotNil(t, e)
		assert.Equal(t, ErrCodeCredentialError, e.Code)
	})
	t.Run("prefix on another status is not a conflict", func(t *testing.T) {
		e, _ := run(t, 500, `{"error":"server_error","error_description":"`+desc+`"}`)
		require.NotNil(t, e)
		assert.Equal(t, ErrCodeCredentialError, e.Code)
	})
	t.Run("message is capped and control characters stripped", func(t *testing.T) {
		m, ok := pscConflictMessage(400, []byte(`{"error":"x","error_description":"org.siros.psc_conflict: a\u0000b\n`+strings.Repeat("z", 2000)+`"}`))
		require.True(t, ok)
		assert.LessOrEqual(t, len(m), maxPSCConflictMessageBytes)
		assert.NotContains(t, m, "\n")
		assert.NotContains(t, m, "\x00")
	})
}

type ErrorCodeAndMsg struct {
	Code ErrorCode
	Msg  string
}

func timeAfter() <-chan time.Time { return time.After(3 * time.Second) }

func TestCheckPSCNeedsProof(t *testing.T) {
	h, cleanup := testOID4VCIHandler(t, http.DefaultClient)
	defer cleanup()
	cfg := hcCfg(hcAdv)
	require.NoError(t, h.checkPSCNeedsProof(cfg))
	cfg.ProofTypesSupported = nil
	require.Error(t, h.checkPSCNeedsProof(cfg), "psc advertised but no proof type: refuse")
	cfg = hcCfg("")
	cfg.ProofTypesSupported = nil
	require.NoError(t, h.checkPSCNeedsProof(cfg), "no advertisement: unchanged")
}
