package engine

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sirosfoundation/go-wmp/pkg/wmp"
)

// go-wmp's HTTPS+SSE client does not set Wmp-Session-Id; the session travels
// in params.wmp.session_id, and the server must accept it from there.
func TestWMP_HTTPEndpoint_RPC_SessionIDFromBodyMetadata(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)
	sid := createWMPSession(t, a)

	post := func(tok, header, bodySID string) *httptest.ResponseRecorder {
		body := wmpRequest("7", wmp.MethodFlowCancel, wmp.FlowCancelParams{
			WMP: wmp.Metadata{Version: wmp.Version, SessionID: bodySID}, FlowID: "nope",
		})
		req := httptest.NewRequest(http.MethodPost, WMPRPCPath, strings.NewReader(string(body)))
		req.Header.Set("Authorization", "Bearer "+tok)
		if header != "" {
			req.Header.Set("Wmp-Session-Id", header)
		}
		w := httptest.NewRecorder()
		a.HandleWMPRPC(w, req)
		return w
	}
	owner := testToken("user-1", "tenant-a")

	// Header absent, body metadata present: dispatched to the session.
	w := post(owner, "", sid)
	require.Equal(t, http.StatusOK, w.Code)
	assert.NotEqual(t, wmp.ErrNotAuthorized, rpcErrCode(t, w.Body.Bytes()), "must not be 'missing session ID'")
	var r wmp.Response
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &r))
	if r.Error != nil {
		assert.NotContains(t, string(w.Body.Bytes()), "missing session ID")
	}

	// Both absent: refused.
	w = post(owner, "", "")
	assert.Contains(t, w.Body.String(), "missing session ID")

	// Header and body disagree: refused.
	w = post(owner, sid, "some-other-session")
	assert.Equal(t, http.StatusBadRequest, w.Code)

	// Header and body agree: fine.
	w = post(owner, sid, sid)
	assert.Equal(t, http.StatusOK, w.Code)

	// Ownership is still enforced for a body-supplied session ID.
	w = post(testToken("user-2", "tenant-a"), "", sid)
	assert.Equal(t, http.StatusNotFound, w.Code)
	w = post(testToken("user-1", "tenant-b"), "", sid)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestBodySessionID(t *testing.T) {
	assert.Equal(t, "s1", bodySessionID([]byte(`{"params":{"wmp":{"session_id":"s1"}}}`)))
	assert.Equal(t, "", bodySessionID([]byte(`{"params":[1,2]}`)))
	assert.Equal(t, "", bodySessionID([]byte(`garbage`)))
	assert.Equal(t, "", bodySessionID(nil))
}
