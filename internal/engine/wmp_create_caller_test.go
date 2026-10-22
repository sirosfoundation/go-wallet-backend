package engine

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sirosfoundation/go-wmp/pkg/wmp"
)

func createBodyWithAuth(token string) []byte {
	p := wmp.SessionCreateParams{
		WMP:      wmp.Metadata{Version: wmp.Version},
		Security: wmp.SecurityMode{Mode: "tls"},
	}
	if token != "" {
		p.Auth = &wmp.AuthObject{Type: "bearer", Token: token}
	}
	return wmpRequest("1", "wmp.session.create", p)
}

func callerFor(t *testing.T, m *Manager, token string) wmpCaller {
	t.Helper()
	id, err := m.validateTokenAuth(context.Background(), token)
	require.NoError(t, err)
	return wmpCaller{UserID: id.UserID, TenantID: id.TenantID, TokenID: id.JTI, TAC: id.TAC, EnforceTAC: id.EnforceTAC}
}

func errReason(t *testing.T, resp []byte) string {
	t.Helper()
	var r struct {
		Error *struct {
			Code int             `json:"code"`
			Data json.RawMessage `json:"data"`
		} `json:"error"`
	}
	require.NoError(t, json.Unmarshal(resp, &r))
	require.NotNil(t, r.Error, "expected error: %s", resp)
	return string(r.Error.Data)
}

func TestWMP_SessionCreate_BodyAuthMustMatchCaller(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)
	ctx := context.Background()

	hdr := testToken("user-a", "tenant-a")
	caller := callerFor(t, m, hdr)

	// Same token in header and body works; owner is the caller.
	resp, err := a.HandleRPCAs(ctx, "", caller, createBodyWithAuth(hdr))
	require.NoError(t, err)
	assert.Contains(t, string(resp), "resumption_token")

	// Absent body credential uses the caller.
	resp, err = a.HandleRPCAs(ctx, "", caller, createBodyWithAuth(""))
	require.NoError(t, err)
	assert.Contains(t, string(resp), "resumption_token")

	a.mu.RLock()
	for _, ws := range a.peers {
		assert.Equal(t, "user-a", ws.session.UserID)
		assert.Equal(t, "tenant-a", ws.session.TenantID)
	}
	a.mu.RUnlock()

	// Mismatches: all must fail identically to an invalid token.
	invalid := errReason(t, mustRPC(t, a, ctx, caller, createBodyWithAuth("garbage")))
	for name, tok := range map[string]string{
		"different user":   testToken("user-b", "tenant-a"),
		"different tenant": testToken("user-a", "tenant-b"),
	} {
		a2, m2 := testWMPAdapter()
		c2 := callerFor(t, m2, hdr)
		got := errReason(t, mustRPC(t, a2, ctx, c2, createBodyWithAuth(tok)))
		assert.Equal(t, invalid, got, name)
		a2.mu.RLock()
		assert.Empty(t, a2.peers, name)
		assert.Empty(t, a2.resumptionTokens, name)
		a2.mu.RUnlock()
		cleanupWMP(a2, m2)
	}
}

func TestSameIdentity(t *testing.T) {
	c := wmpCaller{UserID: "u", TenantID: "t"}
	assert.True(t, sameIdentity(tokenIdentity{UserID: "u", TenantID: "t"}, c))
	assert.False(t, sameIdentity(tokenIdentity{UserID: "v", TenantID: "t"}, c))
	assert.False(t, sameIdentity(tokenIdentity{UserID: "u", TenantID: "x"}, c))

	anon := wmpCaller{TenantID: "t", TokenID: "jti-1"}
	assert.True(t, sameIdentity(tokenIdentity{TenantID: "t", JTI: "jti-1"}, anon))
	assert.False(t, sameIdentity(tokenIdentity{TenantID: "t", JTI: "jti-2"}, anon), "different anonymous token")
	assert.False(t, sameIdentity(tokenIdentity{TenantID: "t"}, wmpCaller{TenantID: "t"}), "anonymous without jti")
	assert.False(t, sameIdentity(tokenIdentity{UserID: "u", TenantID: "t", JTI: "jti-1"}, anon))
}

func mustRPC(t *testing.T, a *WMPAdapter, ctx context.Context, c wmpCaller, body []byte) []byte {
	t.Helper()
	resp, err := a.HandleRPCAs(ctx, "", c, body)
	require.NoError(t, err)
	return resp
}
