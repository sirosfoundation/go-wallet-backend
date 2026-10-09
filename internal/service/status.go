package service

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
	"github.com/sirosfoundation/go-wallet-backend/pkg/statuslist"
	"github.com/sirosfoundation/go-wallet-backend/pkg/trust"
)

// StatusService answers "what does this Token Status List say, and can the
// backend vouch for it?" (POST /status/v1/lists; see
// docs/adr/013-status-checking-outside-the-engine.md). Clients read their own
// index locally, so the backend never learns which credential is asked about.
//
// Fail-closed: a list is "verified" only if fetched, verified and its signer
// accepted by the trust service (go-trust); everything else is "undetermined"
// with a Reason. No outcome ever says a credential is valid.
//
// Privacy: the requested URIs reveal what a user holds, so this service never
// logs a URI or the Checker's errors (they contain URIs), emits no audit
// events, persists nothing and is not handed the user. Its only state is the
// Checker's in-process cache of public data.
type StatusService struct {
	lister       StatusLister
	logger       *zap.Logger
	maxLists     int
	timeout      time.Duration
	maxListBytes int
	now          func() time.Time
}

// StatusLister is the verified-list accessor of statuslist.Checker.
type StatusLister interface {
	List(ctx context.Context, uri string) (*statuslist.VerifiedList, error)
}

// Request-validation errors of StatusService.Lists.
var (
	// ErrStatusInvalidRequest: empty request, or an item without a uri or with a bad etag.
	ErrStatusInvalidRequest = errors.New("invalid status list request")
	// ErrStatusTooManyLists: more lists than the configured cap.
	ErrStatusTooManyLists = errors.New("too many status lists in one request")
)

// Per-item states of a status list result.
const (
	// StatusStateVerified: the list is verified and trusted; Lst and Bits are set.
	StatusStateVerified = "verified"
	// StatusStateUndetermined: the backend cannot vouch for the list (see Reason).
	StatusStateUndetermined = "undetermined"
	// StatusStateNotModified: the caller's etag is current; the list is not repeated.
	StatusStateNotModified = "not_modified"
)

const (
	maxStatusURILength  = 2048
	maxStatusETagLength = 128
)

// StatusListRequest names one list. ETag is the etag of the version the
// caller already holds ("" for none).
type StatusListRequest struct {
	URI  string `json:"uri"`
	ETag string `json:"etag,omitempty"`
}

// StatusListResult is the outcome for one list.
type StatusListResult struct {
	URI   string `json:"uri"`
	State string `json:"state"`
	// Reason is set only when State is undetermined.
	Reason string `json:"reason,omitempty"`
	// Bits and Lst (unpadded base64url of the signed token's compressed `lst`)
	// are set only when verified.
	Bits *int   `json:"bits,omitempty"`
	Lst  string `json:"lst,omitempty"`
	// IssuedAt, ExpiresAt and TTL are the token's iat, exp and ttl (unix
	// seconds; exp and ttl only if present); verified only.
	IssuedAt  *int64 `json:"iat,omitempty"`
	ExpiresAt *int64 `json:"exp,omitempty"`
	TTL       *int64 `json:"ttl,omitempty"`
	// FreshUntil (JSON expires_at) is when this version stops being fresh.
	FreshUntil *int64 `json:"expires_at,omitempty"`
	// ETag identifies this version of the list (verified and not_modified).
	ETag string `json:"etag,omitempty"`
	// SignerTrust is the trust action that accepted the signer.
	SignerTrust string `json:"signer_trust,omitempty"`
}

// NewStatusService returns the service for cfg, or nil when
// status_check.enabled is false. Without a PDP in trustSvc every list is
// undetermined (trust_unavailable).
func NewStatusService(cfg *config.Config, trustSvc *trust.Service, logger *zap.Logger) *StatusService {
	sc := cfg.StatusCheck
	if !sc.Enabled {
		return nil
	}
	checker := statuslist.NewChecker(cfg.HTTPClient.NewHTTPClient(0), cfg.HTTPClient.AllowsPlaintext(), nil).
		WithSignerTrustAction(statusSignerTrust(trustSvc, sc.StatusListSignerFallback)).
		WithMinEntries(sc.StatusListMinEntries).
		WithMaxConcurrentLoads(sc.StatusListMaxConcurrentLoads)
	return NewStatusServiceWithLister(checker, sc, logger)
}

// NewStatusServiceWithLister builds the service around any StatusLister
// (statuslist.Checker in production, a fake in tests).
func NewStatusServiceWithLister(l StatusLister, sc config.StatusCheckConfig, logger *zap.Logger) *StatusService {
	s := &StatusService{
		lister:       l,
		logger:       logger,
		maxLists:     sc.MaxListsPerRequest,
		timeout:      time.Duration(sc.RequestTimeoutSeconds) * time.Second,
		maxListBytes: sc.MaxListBytes,
		now:          time.Now,
	}
	if s.maxLists <= 0 {
		s.maxLists = config.DefaultStatusMaxListsPerRequest
	}
	if s.timeout <= 0 {
		s.timeout = config.DefaultStatusRequestTimeoutSeconds * time.Second
	}
	if s.maxListBytes <= 0 {
		s.maxListBytes = config.DefaultStatusMaxListBytes
	}
	return s
}

// MaxLists is the cap on lists per request.
func (s *StatusService) MaxLists() int { return s.maxLists }

// statusSignerTrust adapts the trust service to statuslist.SignerTrustAction
// via EvaluateStatusListSigner: action "status-list-signer" first; a negative
// is final, and only an error falls back to the credential-issuer role (when
// status_list_signer_fallback is on). The go-trust deployment should define a
// status-list-signer policy (docs/adr/012). "No PDP" and "evaluation failed"
// come back as untrusted, so they are turned into errors to keep them apart
// from a genuine negative.
func statusSignerTrust(svc *trust.Service, fallbackOnError bool) statuslist.SignerTrustAction {
	return func(ctx context.Context, subject string, km *trust.KeyMaterial) (bool, string, error) {
		if svc == nil {
			return false, "", errors.New("no trust service configured")
		}
		info, err := svc.EvaluateStatusListSigner(ctx, subject, "", km, fallbackOnError)
		if err != nil {
			return false, "", err
		}
		if info.Trusted {
			return true, info.Action, nil
		}
		if info.Framework == trust.FrameworkNone {
			return false, "", errors.New("no trust PDP configured")
		}
		if info.EvaluationFailed {
			return false, "", errors.New("trust evaluation failed")
		}
		return false, "", nil
	}
}

// Lists returns one result per distinct uri in reqs, in first-occurrence order
// (a repeated uri keeps its first etag). Per-list failures are not errors; only
// a malformed request or one over the cap is. tenantID scopes trust and the
// cache and is the only caller context received.
func (s *StatusService) Lists(ctx context.Context, tenantID string, reqs []StatusListRequest) ([]StatusListResult, error) {
	if len(reqs) == 0 {
		return nil, fmt.Errorf("%w: no lists", ErrStatusInvalidRequest)
	}
	if len(reqs) > s.maxLists {
		return nil, fmt.Errorf("%w: at most %d", ErrStatusTooManyLists, s.maxLists)
	}
	distinct := make([]StatusListRequest, 0, len(reqs))
	seen := make(map[string]struct{}, len(reqs))
	for _, r := range reqs {
		if r.URI == "" {
			return nil, fmt.Errorf("%w: an item has no uri", ErrStatusInvalidRequest)
		}
		if len(r.ETag) > maxStatusETagLength {
			return nil, fmt.Errorf("%w: etag too long", ErrStatusInvalidRequest)
		}
		if _, dup := seen[r.URI]; dup {
			continue
		}
		seen[r.URI] = struct{}{}
		distinct = append(distinct, r)
	}

	start := s.now()
	ctx, cancel := context.WithTimeout(trust.ContextWithTenant(ctx, tenantID), s.timeout)
	defer cancel()

	results := make([]StatusListResult, len(distinct))
	var wg sync.WaitGroup
	for i := range distinct {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i] = s.one(ctx, distinct[i])
		}(i)
	}
	wg.Wait()

	// Counts, outcomes and duration only: never a uri, never a user.
	var verified, notModified, undetermined int
	reasons := map[string]int{}
	for _, r := range results {
		switch r.State {
		case StatusStateVerified:
			verified++
		case StatusStateNotModified:
			notModified++
		default:
			undetermined++
			reasons[r.Reason]++
		}
	}
	fields := []zap.Field{
		zap.Int("lists", len(results)), zap.Int("verified", verified),
		zap.Int("not_modified", notModified), zap.Int("undetermined", undetermined),
		zap.Duration("duration", s.now().Sub(start)),
	}
	for reason, n := range reasons {
		fields = append(fields, zap.Int("undetermined_"+reason, n))
	}
	s.logger.Debug("status lists served", fields...)
	return results, nil
}

// one resolves a single list; anything but a complete List result is undetermined.
func (s *StatusService) one(ctx context.Context, r StatusListRequest) (res StatusListResult) {
	undetermined := func(reason statuslist.Reason) StatusListResult {
		return StatusListResult{URI: r.URI, State: StatusStateUndetermined, Reason: string(reason)}
	}
	// gin does not recover this goroutine; a panic must not crash or read as success.
	defer func() {
		if p := recover(); p != nil {
			res = undetermined(statuslist.ReasonMalformed)
		}
	}()
	if !statusURIAllowed(r.URI) {
		return undetermined(statuslist.ReasonURINotAllowed)
	}
	vl, err := s.lister.List(ctx, r.URI)
	if err != nil {
		return undetermined(statuslist.Classify(err))
	}
	if vl == nil {
		return undetermined(statuslist.ReasonMalformed)
	}
	if len(vl.Lst) > s.maxListBytes {
		return undetermined(statuslist.ReasonTooLarge)
	}
	switch vl.Bits {
	case 1, 2, 4, 8:
	default:
		return undetermined(statuslist.ReasonMalformed)
	}
	if len(vl.Lst) == 0 || vl.ETag == "" {
		return undetermined(statuslist.ReasonMalformed)
	}
	fresh := vl.FreshUntil.Unix()
	if r.ETag != "" && r.ETag == vl.ETag {
		return StatusListResult{
			URI: r.URI, State: StatusStateNotModified, ETag: vl.ETag,
			FreshUntil: &fresh, SignerTrust: vl.SignerAction,
		}
	}
	bits, iat := vl.Bits, vl.IssuedAt.Unix()
	out := StatusListResult{
		URI: r.URI, State: StatusStateVerified, Bits: &bits,
		Lst: base64.RawURLEncoding.EncodeToString(vl.Lst), IssuedAt: &iat,
		FreshUntil: &fresh, ETag: vl.ETag, SignerTrust: vl.SignerAction,
	}
	if vl.ExpiresAt != nil {
		exp := vl.ExpiresAt.Unix()
		out.ExpiresAt = &exp
	}
	if vl.TTL > 0 {
		ttl := int64(vl.TTL / time.Second)
		out.TTL = &ttl
	}
	return out
}

// statusURIAllowed accepts an absolute https URI with a host, no userinfo and
// no fragment, of bounded length.
func statusURIAllowed(raw string) bool {
	if len(raw) > maxStatusURILength {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	return u.Scheme == "https" && u.Hostname() != "" && u.User == nil && u.Fragment == "" && u.Opaque == ""
}
