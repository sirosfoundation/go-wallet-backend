# Trust Handling Cleanup — Solution Proposals

Based on the 12-issue gap analysis, incorporating these design constraints:

1. **Defer UI** — Make data available; don't change presentation layer
2. **No "frameworks"** — Remove `framework` field; expose auxiliary go-trust metadata instead
3. **Remove dead fields & code**
4. **No frontend trust evaluation** — Local cert validation is legacy. Pre-registered entities use pre-computed trust. Frontend only does its own evaluation for proxy transport with unknown entities

---

## Wire-Format Redesign (Prerequisite for Issues #1–#5, #7, #9)

The root cause of several issues is the current wire types. Proposed replacements:

### Backend: `TrustInfo` (pkg/trust/service.go)

```go
// Before
type TrustInfo struct {
    Trusted      bool     `json:"trusted"`
    Framework    string   `json:"framework,omitempty"`
    Reason       string   `json:"reason,omitempty"`
    Certificates []string `json:"certificates,omitempty"`
}

// After
type TrustInfo struct {
    TrustedStatus string                 `json:"trusted_status"`          // "trusted" | "unknown" | "untrusted"
    Reason        string                 `json:"reason,omitempty"`
    Metadata      map[string]interface{} `json:"metadata,omitempty"`      // auxiliary info from PDP
}
```

- **`Framework` removed** (per constraint #2) — no frameworks exist.
- **`Certificates` removed** (per constraint #3) — never populated, dead field.
- **`Trusted bool` → `TrustedStatus string`** — tri-state aligns with frontend `OID4VPVerifierInfo.trustedStatus`. Values:
  - `"trusted"` — PDP returned `decision: true`
  - `"untrusted"` — PDP returned `decision: false`
  - `"unknown"` — no PDP configured, PDP unreachable, or evaluation error
- **`Metadata` added** (per constraint #2) — carries PDP `context.trust_metadata` (e.g. trust chain details, DID doc fragments, ETSI TSL service info).

Add string constants:

```go
const (
    TrustStatusTrusted   = "trusted"
    TrustStatusUntrusted = "untrusted"
    TrustStatusUnknown   = "unknown"
)
```

### Backend: `VerifierInfo` (internal/engine/messages.go)

```go
// Before
type VerifierInfo struct {
    Name      string    `json:"name"`
    Logo      *LogoInfo `json:"logo,omitempty"`
    Trusted   bool      `json:"trusted"`
    Framework string    `json:"framework,omitempty"`
}

// After
type VerifierInfo struct {
    Name          string                 `json:"name"`
    Logo          *LogoInfo              `json:"logo,omitempty"`
    TrustedStatus string                 `json:"trusted_status"`          // "trusted" | "unknown" | "untrusted"
    Reason        string                 `json:"reason,omitempty"`
    Metadata      map[string]interface{} `json:"metadata,omitempty"`
}
```

- **`Trusted bool` → `TrustedStatus string`** — fixes field name mismatch with frontend (Issue #1)
- **`Framework` removed** (per constraint #2)
- **`Reason` added** — surfaces PDP reason to frontend (Issue #3)
- **`Metadata` added** — auxiliary PDP info available for UI designers (Issue #5)

### Frontend: `OID4VPVerifierInfo` — no change needed

The type already has `trustedStatus?: 'trusted' | 'unknown' | 'untrusted'` — it will now be populated correctly by the backend.

### Frontend: `OID4VCIIssuerInfo` (src/lib/transport/types/OID4VCITypes.ts)

```typescript
// Before
export interface OID4VCIIssuerInfo {
    identifier: string;
    name?: string;
    logo?: string;
}

// After
export interface OID4VCIIssuerInfo {
    identifier: string;
    name?: string;
    logo?: string;
    trustedStatus?: 'trusted' | 'unknown' | 'untrusted';
    reason?: string;
    metadata?: Record<string, unknown>;
}
```

This makes issuer trust data available to UI designers without changing any rendering (Issue #4).

---

## Issue-by-Issue Solutions

### Issue #1: Backend/Frontend Field Name Mismatch [CRITICAL]

**Problem:** Backend sends `{"trusted": true, "framework": "authzen"}`, frontend expects `{"trusted_status": "trusted"}`.

**Solution:** Apply the wire-format redesign above. In `oid4vp.go`, change:

```go
// Before
verifier.Trusted = trustInfo.Trusted
verifier.Framework = trustInfo.Framework

// After
verifier.TrustedStatus = trustInfo.TrustedStatus
verifier.Reason = trustInfo.Reason
verifier.Metadata = trustInfo.Metadata
```

In `service.go evaluate()`, change the return to build the new `TrustInfo`:

```go
// Before
return &TrustInfo{
    Trusted:   resp.Decision,
    Framework: "authzen",
    Reason:    resp.Reason,
}, nil

// After
status := TrustStatusUntrusted
if resp.Decision {
    status = TrustStatusTrusted
}
return &TrustInfo{
    TrustedStatus: status,
    Reason:        resp.Reason,
    Metadata:      normalizeMetadata(resp.TrustMetadata),
}, nil
```

And the "no evaluator configured" path:

```go
// Before
return &TrustInfo{
    Trusted:   true,
    Framework: "none",
    Reason:    "Trust evaluation not configured",
}, nil

// After
return &TrustInfo{
    TrustedStatus: TrustStatusUnknown,
    Reason:        "trust evaluation not configured",
}, nil
```

All enforcement checks change from `!info.Trusted` to `info.TrustedStatus == TrustStatusUntrusted`.

**Scope:** Backend only. Frontend types already match.

---

### Issue #2: Consent UI Doesn't Render Trust Status [HIGH]

**Problem:** `SelectCredentialsPopup.jsx` shows only domain + purpose.

**Solution:** **Deferred per constraint #1.** Once Issue #1 is fixed, `verifierInfo.trustedStatus` and `verifierInfo.reason` are populated and available in the flow result object — UI designers can render a shield icon / badge / warning banner at their discretion.

**No code changes required.** Document the availability of `trustedStatus`, `reason`, and `metadata` on `OID4VPVerifierInfo` for UI designers.

---

### Issue #3: VerifierInfo Missing Reason [HIGH]

**Problem:** Backend `VerifierInfo` has no `Reason` field; PDP reason is lost.

**Solution:** Included in the wire-format redesign — `VerifierInfo` now carries `Reason` and `Metadata`. In `oid4vp.go evaluateVerifierTrust()`:

```go
verifier.Reason = trustInfo.Reason
verifier.Metadata = trustInfo.Metadata
```

For error cases, set appropriate values:

```go
// Before
verifier.Trusted = false
verifier.Framework = "error"

// After
verifier.TrustedStatus = TrustStatusUnknown
verifier.Reason = "trust evaluation error: " + err.Error()
```

---

### Issue #4: OID4VCI Has No Issuer Trust Type in Frontend [HIGH]

**Problem:** `OID4VCIIssuerInfo` lacks trust fields. The backend sends `TrustInfo` in `StepTrustEvaluated` but the frontend type doesn't capture it.

**Solution:** Two changes:

1. **Frontend type** — Add `trustedStatus`, `reason`, `metadata` to `OID4VCIIssuerInfo` (shown above)

2. **Backend** — Create an `IssuerInfo` type analogous to `VerifierInfo`:

```go
type IssuerInfo struct {
    Identifier    string                 `json:"identifier"`
    Name          string                 `json:"name,omitempty"`
    Logo          *LogoInfo              `json:"logo,omitempty"`
    TrustedStatus string                 `json:"trusted_status"`
    Reason        string                 `json:"reason,omitempty"`
    Metadata      map[string]interface{} `json:"metadata,omitempty"`
}
```

In `oid4vci.go`, change `StepTrustEvaluated` payload from raw `TrustInfo` to `IssuerInfo`:

```go
issuerInfo := &IssuerInfo{
    Identifier:    issuer,
    Name:          metadata.Display[0].Name, // if available
    Logo:          logo,                       // if available
    TrustedStatus: info.TrustedStatus,
    Reason:        info.Reason,
    Metadata:      info.Metadata,
}
_ = h.Progress(StepTrustEvaluated, issuerInfo)
```

3. **Frontend WebSocketTransport.ts** — `mapOID4VCIResponse` should extract `issuerInfo` from `trust_evaluated` step and attach to result.

---

### Issue #5: PDP TrustMetadata Discarded by service.go [HIGH]

**Problem:** `authzen/evaluator.go fromAuthZENResponse()` correctly extracts `resp.Context.TrustMetadata` into `result.TrustMetadata`, but `service.go evaluate()` ignores it.

**Solution:** Add `normalizeMetadata()` helper and use it when building `TrustInfo`:

```go
func normalizeMetadata(raw interface{}) map[string]interface{} {
    if raw == nil {
        return nil
    }
    switch v := raw.(type) {
    case map[string]interface{}:
        return v
    default:
        return map[string]interface{}{"data": v}
    }
}
```

Then in `evaluate()`:

```go
return &TrustInfo{
    TrustedStatus: status,
    Reason:        resp.Reason,
    Metadata:      normalizeMetadata(resp.TrustMetadata),
}, nil
```

This flows PDP auxiliary data (trust chain info, DID doc, ETSI TSL details) through to the frontend where UI designers can display it.

---

### Issue #6: OID4VP Doesn't Set CredentialType for PDP [HIGH]

**Problem:** `extractVerifierKeyMaterial()` never sets `KeyMaterial.CredentialType`; PDP receives empty `credential_type` context.

**Solution:** Extract VCT/format from `PresentationDefinition` (analogous to `collectCredentialTypes` in OID4VCI) and set it on `KeyMaterial`:

```go
func (h *OID4VPHandler) collectVerifierCredentialTypes(pd *PresentationDefinition) string {
    if pd == nil {
        return ""
    }
    var types []string
    for _, desc := range pd.InputDescriptors {
        if desc.Format != nil {
            // Extract VCT from format constraints if available
            for format := range desc.Format {
                types = append(types, format)
            }
        }
    }
    if len(types) == 1 {
        return types[0]
    }
    return strings.Join(types, ",")
}
```

In `evaluateVerifierTrust()`, before calling `EvaluateVerifier`:

```go
if keyMaterial != nil && keyMaterial.CredentialType == "" {
    keyMaterial.CredentialType = h.collectVerifierCredentialTypes(authReq.PresentationDefinition)
}
```

---

### Issue #7: No Dedicated trust_evaluated Step for OID4VP [MEDIUM]

**Problem:** OID4VCI sends `StepTrustEvaluated` with full trust info; OID4VP embeds trust in `VerifierInfo` within `StepRequestParsed`.

**Solution:** With the enriched `VerifierInfo` (now carrying `TrustedStatus`, `Reason`, `Metadata`), _all trust data is already present in both `StepRequestParsed` and `StepAwaitingConsent`_. Adding a separate `trust_evaluated` step would just duplicate this data.

**Keep the current OID4VP flow structure unchanged.** The enriched `VerifierInfo` makes a separate step unnecessary. Document that for OID4VP, trust info is on `verifier` in `request_parsed` and `awaiting_consent` steps.

For OID4VCI, consider wrapping trust in `IssuerInfo` (see Issue #4) for symmetry — both flows surface trust via entity info objects.

---

### Issue #8: V1→V2 Trust Error Code Gap [MEDIUM]

**Problem:** `UriHandlerProvider.tsx` catches `NONTRUSTED_VERIFIER` (V1 enum); V2 sends `UNTRUSTED_VERIFIER` error code.

**Solution:** Two parts:

1. **Deprecate `verifyRequestUriAndCerts.ts`** (per constraint #4) — Mark as deprecated with clear comments. In V2 WebSocket flows, this code is never called; the backend does all trust evaluation. Remove all calls from V2 code paths.

2. **V2 error handling in `WebSocketTransport.ts`** — `mapOID4VPResponse` already handles `flow_error` messages. Ensure the error result object maps `UNTRUSTED_VERIFIER` to a recognizable error type so the transport consumer can display the appropriate message.

3. **UriHandlerProvider.tsx** — This file is V1-only. For V2 flows (WebSocket), error handling goes through the transport layer. No change needed to UriHandlerProvider itself; it remains the V1 path. When V1 is eventually removed, UriHandlerProvider and `verifyRequestUriAndCerts.ts` go with it.

---

### Issue #9: TrustInfo.Certificates Dead Field [MEDIUM]

**Problem:** `Certificates []string` in `TrustInfo` is never populated.

**Solution:** **Removed in the wire-format redesign** (see above). No code references populate this field; it can be deleted. Any certificate/chain information from the PDP flows through `Metadata` if the PDP supplies it.

---

### Issue #10: PDP-Unreachable vs PDP-Denied Indistinguishable [MEDIUM]

**Problem:** Both PDP-unreachable and PDP-denied produce `Decision=false`.

**Solution:** The tri-state `TrustedStatus` handles this:

| Scenario | TrustedStatus | Reason |
|---|---|---|
| PDP says trusted | `"trusted"` | "trust evaluation successful" |
| PDP says not trusted | `"untrusted"` | PDP-supplied reason |
| PDP unreachable | `"unknown"` | "AuthZEN PDP error: connection refused" |
| PDP not configured | `"unknown"` | "trust evaluation not configured" |
| PDP timeout | `"unknown"` | "AuthZEN PDP error: context deadline exceeded" |

In `authzen/evaluator.go Evaluate()`:

```go
// Before (on PDP error):
return &trust.EvaluationResponse{
    Decision: false,
    Reason:   fmt.Sprintf("AuthZEN PDP error: %v", err),
}, nil

// After: add an Error flag
return &trust.EvaluationResponse{
    Decision: false,
    Error:    true,   // NEW: distinguishes "denied" from "unreachable"
    Reason:   fmt.Sprintf("AuthZEN PDP error: %v", err),
}, nil
```

Add `Error bool` to `EvaluationResponse`. In `service.go evaluate()`:

```go
status := TrustStatusUntrusted
if resp.Decision {
    status = TrustStatusTrusted
} else if resp.Error {
    status = TrustStatusUnknown
}
```

**Enforcement policy:** `TrustStatusUntrusted` blocks; `TrustStatusUnknown` blocks when PDP is configured (fail-closed). The frontend gets the correct status for distinct UI treatment.

---

### Issue #11: SD-JWT Trust Anchors Always Empty [LOW]

**Problem:** SD-JWT VC `cnf` claim and issuer key binding aren't extracted for trust evaluation.

**Solution:** **Deferred.** This is a credential-format-specific enhancement. When SD-JWT support matures:
1. Extract issuer DID/URL from SD-JWT issuer (`iss` claim)
2. Extract JWKS from `cnf` claim for key binding verification
3. Pass to `EvaluateIssuer()` as normal `KeyMaterial`

No structural change needed — the current `KeyMaterial` types support this. Just needs format-specific extraction logic.

---

### Issue #12: Dead Code in Evaluator [LOW]

**Problem:** `Resolve()`, `NewEvaluatorWithDiscovery()` in `authzen/evaluator.go` are unused, plus legacy types in `evaluator.go`.

**Solution:** Remove per constraint #3:

From `authzen/evaluator.go`:
- `NewEvaluatorWithDiscovery()` — unused, calls `authzenclient.Discover()` which may not exist
- `Resolve()` — unused, no call sites
- `EvaluateX5C()` — unused convenience method (evaluation goes through `Evaluate()`)

From `pkg/trust/evaluator.go`:
- `Subject` struct — deprecated, only used internally for legacy compat
- `Resource` struct — deprecated, same
- `Action` struct — deprecated, same
- `SubjectType` type alias — only used to define Subject.Type
- Clean up `EvaluationRequest` to remove legacy fields (`Subject`, `Resource`, `LegacyAction`, `Context`) — use the `trustapi.EvaluationRequest` fields directly

**Note:** The legacy type cleanup in `evaluator.go` is a larger refactor. Do the `authzen/evaluator.go` dead code removal first; schedule the legacy type cleanup separately.

---

## Frontend: Remove Local Trust Evaluation (Constraint #4)

Per design constraint #4, the frontend should never do its own trust evaluation. Changes:

1. **Deprecate `verifyRequestUriAndCerts.ts`** — Add `@deprecated` JSDoc. This is V1 legacy code that duplicates backend trust evaluation.

2. **Remove `OPENID4VP_SAN_DNS_CHECK` config flags** — These gate V1 certificate checking that is now handled server-side.

3. **Pre-registered entities** — For entities registered via admin API, the backend pre-computes trust status and returns it in `VerifierInfo`/`IssuerInfo`. No frontend change needed — the tri-state `trustedStatus` covers this:
   - Pre-registered + trusted → `"trusted"`
   - Pre-registered + untrusted → `"untrusted"` (shouldn't happen but handles revocation)
   - Not pre-registered, PDP evaluated → `"trusted"` or `"untrusted"`
   - Not pre-registered, no PDP → `"unknown"`

4. **Proxy transport exception** — When using `HttpProxyTransport` with an unknown issuer/verifier, the proxy backend should evaluate trust and return the result. The frontend simply displays what the backend decides. No local evaluation needed even in this case.

---

## Implementation Order

| Phase | Issues | Effort | Description |
|---|---|---|---|
| **1** | #1, #3, #5, #9, #10 | Medium | Wire-format redesign: new `TrustInfo`/`VerifierInfo`, remove dead fields, plumb metadata, tri-state status |
| **2** | #4 | Small | Add `IssuerInfo` type, update OID4VCI flow, update frontend types |
| **3** | #6 | Small | Extract credential type for OID4VP PDP calls |
| **4** | #12 | Small | Remove dead code from evaluator |
| **5** | #8 | Small | Deprecate `verifyRequestUriAndCerts.ts`, document V2 error handling |
| **6** | #2, #7 | Deferred | UI rendering of trust status (for UI designers) |
| **7** | #11 | Deferred | SD-JWT trust anchor extraction |

Phase 1 is the critical path — it fixes the field mismatch and sets up all other changes. Phases 2–4 can be done in any order after Phase 1. Phase 5 is cleanup. Phases 6–7 are deferred.
