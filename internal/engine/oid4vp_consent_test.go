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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

const consentTestQuery = `{
 "credentials":[
  {"id":"pid","format":"dc+sd-jwt","claims":[
     {"id":"a","path":["given_name"]},{"id":"b","path":["family_name"]},
     {"id":"c","path":["address","street"]},{"id":"d","path":["nationalities",null,"code"]}]},
  {"id":"pid_sets","claims":[{"id":"x","path":["a"]},{"id":"y","path":["b"]},{"id":"z","path":["c"]}],
     "claim_sets":[["x","y"],["z"]]},
  {"id":"mdl","format":"mso_mdoc","claims":[{"path":["org.iso.18013.5.1","family_name"]},{"path":["org.iso.18013.5.1","portrait"]}]},
  {"id":"noclaims","format":"dc+sd-jwt"},
  {"id":"multi","multiple":true}
 ]}`

func sel(q string, claims ...string) ConsentSelection {
	return ConsentSelection{CredentialQueryID: q, CredentialID: "1", DisclosedClaims: claims}
}

func TestCheckConsentAgainstDCQL(t *testing.T) {
	tests := []struct {
		name   string
		query  string
		sel    []ConsentSelection
		reason string
		qid    string
	}{
		{"valid bare names", consentTestQuery, []ConsentSelection{sel("pid", "given_name", "family_name")}, "", ""},
		{"valid joined path", consentTestQuery, []ConsentSelection{sel("pid", "given_name", "address.street")}, "", ""},
		{"valid bare last element of nested", consentTestQuery, []ConsentSelection{sel("pid", "street")}, "", ""},
		{"wildcard joined index", consentTestQuery, []ConsentSelection{sel("pid", "nationalities.0.code")}, "", ""},
		{"wildcard joined empty", consentTestQuery, []ConsentSelection{sel("pid", "nationalities..code")}, "", ""},
		{"child of requested path", consentTestQuery, []ConsentSelection{sel("pid", "address.street.name")}, "", ""},
		{"always disclosed", consentTestQuery, []ConsentSelection{sel("pid", "vct", "given_name")}, "", ""},
		{"empty disclosed", consentTestQuery, []ConsentSelection{sel("pid")}, "", ""},
		{"unknown query id", consentTestQuery, []ConsentSelection{sel("other", "given_name")}, consentReasonOutsideQuery, ""}, // client-supplied id is kept out of the violation
		{"empty query id", consentTestQuery, []ConsentSelection{sel("", "given_name")}, consentReasonOutsideQuery, ""},
		{"claim outside query", consentTestQuery, []ConsentSelection{sel("pid", "given_name", "birth_date")}, consentReasonClaimOutside, "pid"},
		{"parent of requested path is a superset", consentTestQuery, []ConsentSelection{sel("pid", "address")}, consentReasonClaimOutside, "pid"},
		{"claim of another query", consentTestQuery, []ConsentSelection{sel("pid", "portrait")}, consentReasonClaimOutside, "pid"},
		{"claim_sets first combo", consentTestQuery, []ConsentSelection{sel("pid_sets", "a", "b")}, "", ""},
		{"claim_sets second combo", consentTestQuery, []ConsentSelection{sel("pid_sets", "c")}, "", ""},
		{"claim_sets subset of one combo", consentTestQuery, []ConsentSelection{sel("pid_sets", "a")}, "", ""},
		{"claim_sets mixed combos", consentTestQuery, []ConsentSelection{sel("pid_sets", "a", "c")}, consentReasonClaimOutside, "pid_sets"},
		{"mdoc namespace joined", consentTestQuery, []ConsentSelection{sel("mdl", "org.iso.18013.5.1.family_name")}, "", ""},
		{"mdoc element only", consentTestQuery, []ConsentSelection{sel("mdl", "portrait")}, "", ""},
		{"mdoc wrong namespace", consentTestQuery, []ConsentSelection{sel("mdl", "org.other.family_name")}, consentReasonClaimOutside, "mdl"},
		{"mdoc extra element", consentTestQuery, []ConsentSelection{sel("mdl", "birth_date")}, consentReasonClaimOutside, "mdl"},
		{"no-claims query, empty disclosed", consentTestQuery, []ConsentSelection{sel("noclaims")}, "", ""},
		{"no-claims query, claims disclosed", consentTestQuery, []ConsentSelection{sel("noclaims", "given_name")}, consentReasonClaimOutside, "noclaims"},
		{"duplicate query id", consentTestQuery, []ConsentSelection{sel("pid", "given_name"), sel("pid", "given_name")}, consentReasonDuplicate, "pid"},
		{"duplicate allowed with multiple", consentTestQuery, []ConsentSelection{sel("multi"), sel("multi")}, "", ""},
		{"two different queries", consentTestQuery, []ConsentSelection{sel("pid", "given_name"), sel("mdl", "portrait")}, "", ""},
		{"credential_sets: known option ids",
			`{"credentials":[{"id":"a"},{"id":"b"},{"id":"c"}],"credential_sets":[{"options":[["a"],["b"]]}]}`,
			[]ConsentSelection{sel("a")}, "", ""},
		{"credential_sets: id in no option",
			`{"credentials":[{"id":"a"},{"id":"b"},{"id":"c"}],"credential_sets":[{"options":[["a"],["b"]]}]}`,
			[]ConsentSelection{sel("c")}, consentReasonOutsideQuery, "c"},
		{"credential_sets: several sets combined",
			`{"credentials":[{"id":"a"},{"id":"b"},{"id":"c"}],"credential_sets":[{"options":[["a"]]},{"options":[["b","c"]],"required":false}]}`,
			[]ConsentSelection{sel("a"), sel("b"), sel("c")}, "", ""},
		{"values constraint does not affect path",
			`{"credentials":[{"id":"a","claims":[{"path":["age_over_18"],"values":[true]}]}]}`,
			[]ConsentSelection{sel("a", "age_over_18")}, "", ""},
		{"integer path element",
			`{"credentials":[{"id":"a","claims":[{"path":["list",1]}]}]}`,
			[]ConsentSelection{sel("a", "list.1")}, "", ""},
		{"integer path element mismatch",
			`{"credentials":[{"id":"a","claims":[{"path":["list",1,"x"]}]}]}`,
			[]ConsentSelection{sel("a", "list.2.x")}, consentReasonClaimOutside, "a"},
		{"trailing wildcard allows any bare name",
			`{"credentials":[{"id":"a","claims":[{"path":["address",null]}]}]}`,
			[]ConsentSelection{sel("a", "street")}, "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, err := checkConsentAgainstDCQL(json.RawMessage(tt.query), tt.sel)
			require.NoError(t, err)
			if tt.reason == "" {
				assert.Nil(t, v)
				return
			}
			require.NotNil(t, v)
			assert.Equal(t, tt.reason, v.Reason)
			assert.Equal(t, tt.qid, v.QueryID)
			assert.Contains(t, v.Error(), tt.reason)
		})
	}
}

func TestCheckConsentAgainstDCQL_Unparseable(t *testing.T) {
	for _, q := range []string{`not json`, `{}`, `{"credentials":[]}`} {
		_, err := checkConsentAgainstDCQL(json.RawMessage(q), []ConsentSelection{sel("a")})
		assert.Error(t, err, q)
	}
}

// consentHandler builds a handler with the given mode and an observed logger.
func consentHandler(t *testing.T, mode config.DCQLConsentCheckMode) (*OID4VPHandler, *Session, chan map[string]any, *observer.ObservedLogs, func()) {
	t.Helper()
	h, session, received, cleanup := newSelectionTestHandler(t)
	core, logs := observer.New(zap.WarnLevel)
	h.Logger = zap.New(core)
	h.Config = &config.Config{Presentation: config.PresentationConfig{DCQLConsentCheck: mode}}
	return h, session, received, logs, cleanup
}

func TestRequestCredentialSelection_ConsentCheckModes(t *testing.T) {
	violating := []ConsentSelection{sel("pid", "given_name", "SECRET_CLAIM_NAME")}

	run := func(t *testing.T, mode config.DCQLConsentCheckMode) (selected []ConsentSelection, err error, notified int32, received chan map[string]any, logs *observer.ObservedLogs) {
		h, session, rec, lg, cleanup := consentHandler(t, mode)
		defer cleanup()
		var n int32
		verifier := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			require.NoError(t, r.ParseForm())
			assert.Equal(t, "access_denied", r.PostForm.Get("error"))
			assert.Equal(t, verifierRefusedDescription, r.PostForm.Get("error_description"))
			atomic.AddInt32(&n, 1)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"redirect_uri":"https://verifier.example/done"}`))
		}))
		defer verifier.Close()
		authReq := &AuthorizationRequest{
			DCQLQuery:   json.RawMessage(consentTestQuery),
			ResponseURI: verifier.URL,
			State:       "s",
		}
		feedAction(t, session, h.Flow.ID, ActionConsent, ConsentPayload{SelectedCredentials: violating})
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		selected, err = h.requestCredentialSelection(ctx, authReq, &VerifierInfo{})
		if mode == config.DCQLConsentCheckEnforce {
			msg := awaitMessage(t, rec, string(TypeFlowError))
			flowErr := msg["error"].(map[string]any)
			assert.Equal(t, string(ErrCodePresentationError), flowErr["code"])
			assert.Equal(t, "https://verifier.example/done", flowErr["details"].(map[string]any)["redirect_uri"])
		}
		return selected, err, atomic.LoadInt32(&n), rec, lg
	}

	assertNoLeak := func(t *testing.T, logs *observer.ObservedLogs) {
		for _, e := range logs.All() {
			assert.NotContains(t, e.Message, "SECRET_CLAIM_NAME")
			for _, f := range e.Context {
				assert.NotContains(t, f.String, "SECRET_CLAIM_NAME")
			}
		}
	}

	t.Run("enforce refuses, tells verifier, does not proceed", func(t *testing.T) {
		selected, err, notified, _, logs := run(t, config.DCQLConsentCheckEnforce)
		require.Error(t, err)
		assert.Nil(t, selected)
		assert.EqualValues(t, 1, notified)
		require.Equal(t, 1, logs.Len())
		fields := logs.All()[0].ContextMap()
		assert.Equal(t, consentReasonClaimOutside, fields["reason"])
		assert.Equal(t, "pid", fields["credential_query_id"])
		assertNoLeak(t, logs)
	})
	t.Run("warn logs and proceeds", func(t *testing.T) {
		selected, err, notified, _, logs := run(t, config.DCQLConsentCheckWarn)
		require.NoError(t, err)
		assert.Equal(t, violating, selected)
		assert.EqualValues(t, 0, notified)
		require.Equal(t, 1, logs.Len())
		assert.Equal(t, consentReasonClaimOutside, logs.All()[0].ContextMap()["reason"])
		assertNoLeak(t, logs)
	})
	t.Run("default (unset) is warn", func(t *testing.T) {
		selected, err, notified, _, logs := run(t, "")
		require.NoError(t, err)
		assert.NotNil(t, selected)
		assert.EqualValues(t, 0, notified)
		assert.Equal(t, 1, logs.Len())
	})
	t.Run("off does nothing", func(t *testing.T) {
		selected, err, notified, _, logs := run(t, config.DCQLConsentCheckOff)
		require.NoError(t, err)
		assert.NotNil(t, selected)
		assert.EqualValues(t, 0, notified)
		assert.Equal(t, 0, logs.Len())
	})
}

func TestVetConsent_EdgeCases(t *testing.T) {
	logger := zap.NewNop()
	enforce := &config.Config{Presentation: config.PresentationConfig{DCQLConsentCheck: config.DCQLConsentCheckEnforce}}
	h := &OID4VPHandler{BaseHandler: BaseHandler{Logger: logger, Config: enforce}}

	// No DCQL query (legacy request): nothing to compare with.
	assert.NoError(t, h.vetConsent(&AuthorizationRequest{}, []ConsentSelection{sel("x", "y")}))

	// A query that cannot be interpreted refuses in enforce mode.
	err := h.vetConsent(&AuthorizationRequest{DCQLQuery: json.RawMessage(`{"credentials":`)}, []ConsentSelection{sel("x")})
	var v *consentViolation
	require.ErrorAs(t, err, &v)
	assert.Equal(t, consentReasonUnparseable, v.Reason)

	// A conforming consent passes in enforce mode.
	assert.NoError(t, h.vetConsent(&AuthorizationRequest{DCQLQuery: json.RawMessage(consentTestQuery)}, []ConsentSelection{sel("pid", "given_name")}))

	// Nil config behaves as the default (warn).
	h.Config = nil
	assert.NoError(t, h.vetConsent(&AuthorizationRequest{DCQLQuery: json.RawMessage(consentTestQuery)}, []ConsentSelection{sel("nope")}))
}

// A claim path may hold only strings, non-negative integers and null. Anything
// else must be reported as unparseable, never read as a wildcard (which would
// authorise every disclosure).
func TestCheckConsentAgainstDCQL_UnsupportedPathElementsAreUnparseable(t *testing.T) {
	for _, path := range []string{`[true]`, `[{}]`, `["a", false]`, `[-1]`, `[1.5]`, `[]`, `[["x"]]`} {
		q := `{"credentials":[{"id":"pid","format":"dc+sd-jwt","claims":[{"path":` + path + `}]}]}`
		_, err := checkConsentAgainstDCQL(json.RawMessage(q), []ConsentSelection{sel("pid", "anything")})
		assert.Error(t, err, "path %s must be unparseable", path)
	}
	// The accepted elements still work: string, integer, null.
	q := `{"credentials":[{"id":"pid","format":"dc+sd-jwt","claims":[{"path":["a",0,null]}]}]}`
	v, err := checkConsentAgainstDCQL(json.RawMessage(q), []ConsentSelection{sel("pid", "a.0.b")})
	require.NoError(t, err)
	assert.Nil(t, v)

	q = `{"credentials":[{"id":"pid","format":"dc+sd-jwt","claims":[{"path":` + tooLongPath() + `}]}]}`
	_, err = checkConsentAgainstDCQL(json.RawMessage(q), []ConsentSelection{sel("pid", "x")})
	assert.Error(t, err, "an over-long path must be refused")
}

func tooLongPath() string {
	parts := make([]string, maxClaimPathElems+1)
	for i := range parts {
		parts[i] = `"a"`
	}
	return "[" + strings.Join(parts, ",") + "]"
}

// Many wildcards against a long non-matching entry must not blow up: the
// matcher is memoised, so this finishes at once instead of exploring ~10^7
// states.
func TestMatchJoinedPath_ManyWildcardsIsFast(t *testing.T) {
	path := make([]interface{}, 12)
	path[11] = "z" // the wildcards can never satisfy this
	entry := strings.Repeat("a.", 24) + "b"

	done := make(chan bool, 1)
	go func() { done <- matchJoinedPath(entry, path) }()
	select {
	case got := <-done:
		assert.False(t, got)
	case <-time.After(2 * time.Second):
		t.Fatal("matchJoinedPath did not finish: wildcard matching is not polynomial")
	}
}

func TestMatchJoinedPath_WildcardBoundaries(t *testing.T) {
	assert.True(t, matchJoinedPath("a.b.c", []interface{}{"a", nil, "c"}))
	assert.True(t, matchJoinedPath("a..c", []interface{}{"a", nil, "c"}), "a wildcard may match no characters")
	assert.True(t, matchJoinedPath("a.b.c.d", []interface{}{"a", nil}), "a descendant is a subset")
	assert.False(t, matchJoinedPath("a.b", []interface{}{"a", nil, "c"}))
	assert.True(t, matchJoinedPath("org.iso.18013.5.1.family_name", []interface{}{"org.iso.18013.5.1", "family_name"}))
}

// Over-long entries are refused without being matched at all.
func TestClaimPathMatcher_OverlongEntry(t *testing.T) {
	m := claimPathMatcher{{"a", nil}}
	assert.False(t, m.allows("a."+strings.Repeat("x", maxClaimEntryLen)))
}

func TestLoggableID_Bounded(t *testing.T) {
	assert.Equal(t, "pid", loggableID("pid"))
	long := strings.Repeat("é", maxLoggedQueryID+10)
	got := loggableID(long)
	assert.LessOrEqual(t, len([]rune(got)), maxLoggedQueryID+3)
	assert.True(t, strings.HasSuffix(got, "..."))
}
