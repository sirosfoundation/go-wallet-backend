package engine

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

// Reason classes for a consent that does not fit the DCQL query. These are
// the only things logged about a violation: never a claim name or value.
const (
	consentReasonOutsideQuery = "consent_outside_query"
	consentReasonDuplicate    = "consent_duplicate_query"
	consentReasonClaimOutside = "consent_claim_outside_query"
	consentReasonUnparseable  = "consent_query_unparseable"
)

// consentViolation describes why a consent does not fit the DCQL query.
type consentViolation struct {
	Reason  string
	QueryID string
}

func (v *consentViolation) Error() string {
	return "consent does not fit the DCQL query: " + v.Reason
}

// dcqlConsentQuery is the part of a DCQL query the consent check needs.
type dcqlConsentQuery struct {
	Credentials []struct {
		ID       string `json:"id"`
		Multiple bool   `json:"multiple"`
		Claims   []struct {
			ID   string        `json:"id"`
			Path []interface{} `json:"path"`
		} `json:"claims"`
		ClaimSets [][]string `json:"claim_sets"`
	} `json:"credentials"`
	CredentialSets []struct {
		Options [][]string `json:"options"`
	} `json:"credential_sets"`
}

// alwaysDisclosed lists top-level claims a client may legitimately report as
// disclosed without the verifier having asked: they are never selectively
// disclosable.
var alwaysDisclosed = map[string]bool{
	"iss": true, "iat": true, "exp": true, "nbf": true, "vct": true, "cnf": true, "status": true,
}

// claimPathMatcher decides whether one disclosed_claims entry is authorised
// by a set of requested DCQL claim paths.
//
// Clients spell an entry two ways: the wallet-frontend joins the whole path
// with "." (["eu.pid","given_name"] -> "eu.pid.given_name", a null wildcard
// joins as the empty string), while the Kotlin and Swift SDKs send only the
// last path element ("given_name"). Both are accepted. A null path element
// matches any element; an entry that is a descendant of a requested path
// (the requested claim is an object) is a subset and is accepted.
type claimPathMatcher [][]interface{}

func pathElemString(e interface{}) (string, bool) {
	switch v := e.(type) {
	case string:
		return v, true
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64), true
	}
	return "", false // null (wildcard) or unsupported
}

func (m claimPathMatcher) allows(entry string) bool {
	if alwaysDisclosed[entry] {
		return true
	}
	for _, p := range m {
		if len(p) == 0 {
			continue
		}
		// Bare last-element form.
		if last, ok := pathElemString(p[len(p)-1]); !ok || last == entry {
			return true
		}
		if matchJoinedPath(entry, p) {
			return true
		}
	}
	return false
}

// matchJoinedPath reports whether entry is the "."-joined form of path or of
// a descendant of it. Elements may themselves contain dots (an mdoc
// namespace such as "org.iso.18013.5.1"), so entry is not split; each element
// is matched as a prefix ending at a dot boundary, and a null element matches
// any run of characters up to a dot boundary (including none).
func matchJoinedPath(entry string, path []interface{}) bool {
	if len(path) == 0 {
		return entry == "" || strings.HasPrefix(entry, ".")
	}
	if s, ok := pathElemString(path[0]); ok {
		if !strings.HasPrefix(entry, s) {
			return false
		}
		rest := entry[len(s):]
		if len(path) == 1 {
			return matchJoinedPath(rest, path[1:])
		}
		return strings.HasPrefix(rest, ".") && matchJoinedPath(rest[1:], path[1:])
	}
	// Wildcard element: try each boundary.
	for i := 0; i <= len(entry); i++ {
		if i < len(entry) && entry[i] != '.' {
			continue
		}
		rest := entry[i:]
		if len(path) == 1 {
			if matchJoinedPath(rest, path[1:]) {
				return true
			}
			continue
		}
		if strings.HasPrefix(rest, ".") && matchJoinedPath(rest[1:], path[1:]) {
			return true
		}
	}
	return false
}

// checkConsentAgainstDCQL compares a consent with the DCQL query the backend
// sent. It returns nil when the consent fits, a *consentViolation when it does
// not, and an error when the query cannot be interpreted (callers treat that
// as a violation: "cannot compare" never means "allowed").
//
// Enforced: every selected query id exists in the query; no query id is
// selected twice unless it sets `multiple`; when credential_sets exists, only
// ids that appear in some option are selected; disclosed_claims entries are
// authorised by the query's claims (or by one claim_set, as a subset). A
// credential query with no claims authorises no disclosed claims.
// Not enforced: that credential_sets are satisfied, `values` constraints, and
// what the resulting vp_token contains.
func checkConsentAgainstDCQL(dcql json.RawMessage, selected []ConsentSelection) (*consentViolation, error) {
	var q dcqlConsentQuery
	if err := json.Unmarshal(dcql, &q); err != nil {
		return nil, fmt.Errorf("parse dcql_query: %w", err)
	}
	if len(q.Credentials) == 0 {
		return nil, errors.New("dcql_query has no credentials")
	}
	idx := make(map[string]int, len(q.Credentials))
	for i, c := range q.Credentials {
		idx[c.ID] = i
	}

	var inSets map[string]bool
	if len(q.CredentialSets) > 0 {
		inSets = map[string]bool{}
		for _, cs := range q.CredentialSets {
			for _, opt := range cs.Options {
				for _, id := range opt {
					inSets[id] = true
				}
			}
		}
	}

	count := map[string]int{}
	for _, s := range selected {
		i, ok := idx[s.CredentialQueryID]
		if !ok || (inSets != nil && !inSets[s.CredentialQueryID]) {
			return &consentViolation{Reason: consentReasonOutsideQuery, QueryID: s.CredentialQueryID}, nil
		}
		count[s.CredentialQueryID]++
		if count[s.CredentialQueryID] > 1 && !q.Credentials[i].Multiple {
			return &consentViolation{Reason: consentReasonDuplicate, QueryID: s.CredentialQueryID}, nil
		}
		if !claimsAuthorised(q.Credentials[i].Claims, q.Credentials[i].ClaimSets, s.DisclosedClaims) {
			return &consentViolation{Reason: consentReasonClaimOutside, QueryID: s.CredentialQueryID}, nil
		}
	}
	return nil, nil
}

// claimsAuthorised reports whether every disclosed entry is authorised.
// An empty disclosed list is always fine: the frontend sends it when the
// query names no claims, and clients treat it as "what the query requests".
func claimsAuthorised(claims []struct {
	ID   string        `json:"id"`
	Path []interface{} `json:"path"`
}, claimSets [][]string, disclosed []string) bool {
	if len(disclosed) == 0 {
		return true
	}
	all := make(claimPathMatcher, 0, len(claims))
	byID := map[string]claimPathMatcher{}
	for _, c := range claims {
		all = append(all, c.Path)
		if c.ID != "" {
			byID[c.ID] = append(byID[c.ID], c.Path)
		}
	}
	if len(claimSets) == 0 {
		return allAllowed(all, disclosed)
	}
	for _, set := range claimSets {
		var m claimPathMatcher
		for _, id := range set {
			m = append(m, byID[id]...)
		}
		if allAllowed(m, disclosed) {
			return true
		}
	}
	return false
}

func allAllowed(m claimPathMatcher, disclosed []string) bool {
	for _, d := range disclosed {
		if !m.allows(d) {
			return false
		}
	}
	return true
}

// vetConsent applies the configured dcql_consent_check to a consent. It
// returns a non-nil error only when the presentation must be refused; in warn
// mode a violation is logged and nil returned. The log carries the reason
// class and query id only.
func (h *OID4VPHandler) vetConsent(authReq *AuthorizationRequest, selected []ConsentSelection) error {
	mode := config.DCQLConsentCheckWarn
	if h.Config != nil {
		mode = h.Config.Presentation.DCQLConsentCheck.Effective()
	}
	if mode == config.DCQLConsentCheckOff || len(authReq.DCQLQuery) == 0 {
		return nil
	}
	v, err := checkConsentAgainstDCQL(authReq.DCQLQuery, selected)
	if err != nil {
		v = &consentViolation{Reason: consentReasonUnparseable}
	}
	if v == nil {
		return nil
	}
	if mode == config.DCQLConsentCheckEnforce {
		h.Logger.Warn("consent refused: does not fit the DCQL query",
			zap.String("reason", v.Reason), zap.String("credential_query_id", v.QueryID))
		return v
	}
	h.Logger.Warn("consent does not fit the DCQL query (warn mode, proceeding)",
		zap.String("reason", v.Reason), zap.String("credential_query_id", v.QueryID))
	return nil
}
