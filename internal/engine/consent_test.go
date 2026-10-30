package engine

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

// decisionOf is an accepted consent of the given selections, for tests that
// drive the sign request directly.
func decisionOf(selected ...ConsentSelection) consentDecision {
	return consentDecision{Selected: selected}
}

func policyFor(mode config.DCQLConsentCheckMode) (consentPolicy, *observer.ObservedLogs) {
	core, logs := observer.New(zap.WarnLevel)
	return newConsentPolicy(&config.Config{Presentation: config.PresentationConfig{DCQLConsentCheck: mode}}, zap.New(core)), logs
}

// The consent component decides for every transport: what it accepts, refuses
// and hands to the sign request does not depend on the wire that carried the
// answer. (consent_ws.go, and any other transport's translation, only translate.)
func TestConsentPolicy_Decide(t *testing.T) {
	query := json.RawMessage(consentTestQuery)

	t.Run("a decline is accepted as it is, whatever the query", func(t *testing.T) {
		p, _ := policyFor(config.DCQLConsentCheckEnforce)
		d, err := p.Decide(json.RawMessage(`not json`), consentAnswer{Declined: true, Reason: "no thanks"})
		require.NoError(t, err)
		assert.True(t, d.Declined)
		assert.Equal(t, "no thanks", d.Reason)
		assert.Empty(t, d.Selected)
	})

	t.Run("a consent that selects nothing is refused in every mode", func(t *testing.T) {
		for _, mode := range []config.DCQLConsentCheckMode{config.DCQLConsentCheckOff, config.DCQLConsentCheckWarn, config.DCQLConsentCheckEnforce} {
			p, _ := policyFor(mode)
			_, err := p.Decide(query, consentAnswer{})
			var r *consentRefusal
			require.ErrorAs(t, err, &r, string(mode))
			assert.Equal(t, consentReasonNoSelection, r.Reason)
		}
	})

	t.Run("modes", func(t *testing.T) {
		outside := consentAnswer{Selections: []ConsentSelection{{CredentialQueryID: "not-in-query"}}}
		for mode, refuses := range map[config.DCQLConsentCheckMode]bool{
			config.DCQLConsentCheckEnforce: true, config.DCQLConsentCheckWarn: false, config.DCQLConsentCheckOff: false, "": false,
		} {
			p, logs := policyFor(mode)
			d, err := p.Decide(query, outside)
			if refuses {
				var r *consentRefusal
				require.ErrorAs(t, err, &r)
				assert.Equal(t, consentReasonOutsideQuery, r.Reason)
				assert.Empty(t, r.QueryID, "a query id the request does not define is not carried")
			} else {
				require.NoError(t, err, string(mode))
				assert.Len(t, d.Selected, 1)
			}
			warned := mode != config.DCQLConsentCheckOff
			assert.Equal(t, warned, logs.Len() == 1, "mode %q logs %d", mode, logs.Len())
		}
	})

	t.Run("duplicates, claims and an unreadable query", func(t *testing.T) {
		p, _ := policyFor(config.DCQLConsentCheckEnforce)
		for name, tc := range map[string]struct {
			dcql   json.RawMessage
			sel    []ConsentSelection
			reason string
		}{
			"duplicate query":   {query, []ConsentSelection{{CredentialQueryID: "pid"}, {CredentialQueryID: "pid"}}, consentReasonDuplicate},
			"claim outside":     {query, []ConsentSelection{sel("pid", "SECRET")}, consentReasonClaimOutside},
			"unparseable query": {json.RawMessage(`{"credentials":`), []ConsentSelection{sel("x")}, consentReasonUnparseable},
		} {
			_, err := p.Decide(tc.dcql, consentAnswer{Selections: tc.sel})
			var r *consentRefusal
			require.ErrorAs(t, err, &r, name)
			assert.Equal(t, tc.reason, r.Reason, name)
		}
		_, err := p.Decide(query, consentAnswer{Selections: []ConsentSelection{{CredentialQueryID: "multi"}, {CredentialQueryID: "multi"}}})
		assert.NoError(t, err, "a query with multiple may be selected twice")
	})

	t.Run("no query (legacy request) has nothing to compare with", func(t *testing.T) {
		p, _ := policyFor(config.DCQLConsentCheckEnforce)
		_, err := p.Decide(nil, consentAnswer{Selections: []ConsentSelection{sel("x", "y")}})
		assert.NoError(t, err)
	})

	t.Run("a nil config is the default, warn", func(t *testing.T) {
		d, err := newConsentPolicy(nil, zap.NewNop()).Decide(query, consentAnswer{Selections: []ConsentSelection{sel("nope")}})
		require.NoError(t, err)
		assert.Len(t, d.Selected, 1)
	})

	t.Run("a refusal never carries a claim name", func(t *testing.T) {
		p, logs := policyFor(config.DCQLConsentCheckEnforce)
		_, err := p.Decide(query, consentAnswer{Selections: []ConsentSelection{sel("pid", "SECRET_CLAIM_NAME")}})
		require.Error(t, err)
		assert.NotContains(t, err.Error(), "SECRET_CLAIM_NAME")
		for _, e := range logs.All() {
			assert.NotContains(t, e.Message, "SECRET_CLAIM_NAME")
			for _, f := range e.Context {
				assert.NotContains(t, f.String, "SECRET_CLAIM_NAME")
			}
		}
	})
}

// What the sign request names is the decision and nothing else: the query ids
// (and, on the WebSocket wire only, the credential id and claims the client
// chose), and the handle unchanged.
func TestConsentDecision_SignInclusion(t *testing.T) {
	p, _ := policyFor(config.DCQLConsentCheckOff)

	d, err := p.Decide(nil, consentAnswer{Selections: []ConsentSelection{{CredentialQueryID: "q1"}, {CredentialQueryID: "q2"}}, Handle: "abcdefghijklmnopqrstuv"})
	require.NoError(t, err)
	refs, handle := d.signInclusion()
	assert.Equal(t, []CredentialRef{{CredentialQueryID: "q1"}, {CredentialQueryID: "q2"}}, refs)
	assert.Equal(t, "abcdefghijklmnopqrstuv", handle)

	ws, err := p.Decide(nil, consentAnswer{Selections: []ConsentSelection{sel("pid", "given_name")}})
	require.NoError(t, err)
	refs, handle = ws.signInclusion()
	assert.Equal(t, []CredentialRef{{CredentialQueryID: "pid", CredentialID: "1", DisclosedClaims: []string{"given_name"}}}, refs)
	assert.Empty(t, handle, "the WebSocket wire has no handle")
}
