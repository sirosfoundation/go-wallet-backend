# Proxy Elimination Implementation Plan

## Overview

This document outlines the implementation plan for eliminating the open HTTP proxy
from the wallet architecture. The plan consists of four interdependent workstreams
that together provide a secure, protocol-aware API for credential issuance and
verification flows.

## Problem Statement

The current wallet architecture uses an open HTTP proxy (`/proxy` endpoint) that:

1. **Security Risk**: Allows arbitrary HTTP requests to external URLs
2. **Privacy Concern**: Creates a binding between browser/user and backend
3. **No Protocol Awareness**: Treats all requests as generic HTTP

**Goal**: Replace the open proxy with protocol-specific APIs that only permit
requests necessary for issuance and verification flows.

## API Versioning Strategy

The API versioning aligns with the transport mechanism:

| Version | Transport | Status | Purpose |
|---------|-----------|--------|---------|
| **v1**  | REST (HTTP) | Current | Traditional REST endpoints, includes `/proxy` |
| **v2**  | WebSocket | New | Protocol-aware flows, no arbitrary URLs |

**Key principle**: API v2 = WebSocket protocol. The v2 API is not a REST API
with new endpoints, but rather a fundamentally different transport model where
the backend drives protocol flows.

## Trust Evaluation Architecture

A critical architectural insight: **VCTMs enable pre-computed trust**.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                      TRUST EVALUATION TIMING                                │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │ PRE-COMPUTED TRUST (VCTM Registration)                               │  │
│  │                                                                       │  │
│  │   1. Admin/User registers VCTM URL                                   │  │
│  │   2. Backend fetches issuer metadata                                 │  │
│  │   3. TrustEvaluator evaluates trust policies                         │  │
│  │   4. Store metadata + trust decision in registry                     │  │
│  │                                                                       │  │
│  │   ✅ Performance: Trust decision cached at registration time         │  │
│  │   ✅ Use case: Known issuers, federation members, pre-approved list  │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
│                                                                             │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │ JUST-IN-TIME TRUST (Fallback for unknown issuers)                    │  │
│  │                                                                       │  │
│  │   1. Credential presented from unregistered issuer                   │  │
│  │   2. Fetch issuer metadata on-demand                                 │  │
│  │   3. TrustEvaluator evaluates trust policies                         │  │
│  │   4. Cache result for future presentations                           │  │
│  │                                                                       │  │
│  │   ⚠️ Performance: Trust evaluation adds latency to presentation      │  │
│  │   ✅ Use case: Ad-hoc issuers, first-time encounters                 │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
│                                                                             │
│  HYBRID MODEL: Try pre-computed first, fallback to JIT if needed           │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Why Pre-computed Trust Matters

1. **Performance**: Trust policy evaluation can involve network calls (OIDF
   discovery, ETSI TSL traversal, X.509 chain validation). Doing this at
   registration time amortizes the cost across all credential presentations.

2. **User Experience**: Credential acceptance is instant for known issuers.
   The wallet can show trust status without delays.

3. **Operational Control**: Deployment administrators can curate a list of
   trusted issuers through VCTM registration, enabling policy enforcement.

4. **Graceful Degradation**: Unknown issuers still work via JIT evaluation,
   the user just sees a brief delay the first time.

## Workstreams

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         IMPLEMENTATION WORKSTREAMS                          │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐  │
│  │ 1. VCTM     │    │ 2. Trust    │    │ 3. WebSocket│    │ 4. Frontend │  │
│  │ Registry    │───▶│ Integration │───▶│ Protocol    │───▶│ Integration │  │
│  │             │    │             │    │ (API v2)    │    │             │  │
│  │ ✅ MERGED   │    │ 🔄 NEXT     │    │ 📋 DESIGNED │    │ 📋 DESIGNED │  │
│  └─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘  │
│                                                                             │
│  Legend: ✅ Complete  🔄 In Progress  📋 Design Complete  ⬜ Not Started   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 1. VCTM Registry (Complete)

**Status**: ✅ Complete (Merged to main)

**Purpose**: Server-side caching and resolution of Verifiable Credential Type
Metadata (VCTM) with embedded images. This is also the primary storage for
**pre-computed trust decisions**.

**Location**: `go-wallet-backend/internal/registry/`

**Key Deliverables**:
- [x] VCTM fetcher with caching
- [x] Image embedding (logos, backgrounds)
- [x] REST API endpoints (`/api/v1/vctm/*`)
- [ ] Trust evaluation at registration time (Phase 1.2)
- [ ] Trust status included in stored/returned VCTMs

**Proxy Traffic Reduction**: ~25%

---

### 2. Trust Abstraction Layer (Mostly Complete)

**Status**: 🔄 Integration Pending

**Purpose**: Unified interface for evaluating trust across multiple frameworks
(OIDF, EBSI, X.509, ETSI TSL). Called at **VCTM registration time** to
pre-compute trust decisions.

**Existing Implementation**:
- `go-trust/pkg/trustapi/` - Core interfaces (TrustEvaluator, KeyResolver)
- `go-trust/pkg/registry/` - Multi-registry support with strategies
- `go-wallet-backend/pkg/trust/` - Wallet-specific wrapper and factory

**Documents**:
- Architecture: `go-trust/docs/ARCHITECTURE-MULTI-REGISTRY.md`
- Multi-Registry Strategies: `go-trust/docs/MULTI-REGISTRY-STRATEGIES.md`
- Trust Metadata: `go-trust/docs/TRUST_METADATA_IMPLEMENTATION.md`
- OIDF Mapping: `go-trust/docs/OIDFED_PROTOCOL_MAPPING.md`

**Key Deliverables**:
- [x] `TrustEvaluator` interface (go-trust/pkg/trustapi)
- [x] Multi-registry support (go-trust/pkg/registry)
- [x] Trust status enumeration (`trusted`, `unknown`, `untrusted`)
- [ ] **Call from VCTM registry at registration time** ← NEXT STEP
- [ ] **JIT evaluation service for unknown issuers** (fallback)
- [ ] Policy expression language (optional, future)

**Dependencies**: None (foundational)

**Integration Points**:
- VCTM Registry calls `TrustEvaluator` when registering new VCTMs
- Trust decision stored alongside VCTM metadata
- WebSocket protocol uses cached trust for known issuers
- JIT evaluation for credentials from unregistered issuers

---

### 3. WebSocket Protocol - API v2 (Designed)

**Status**: 📋 Design Complete

**Purpose**: Unified WebSocket channel for all credential issuance and verification
flows, replacing protocol-specific proxy calls. **This is API v2** - a fundamentally
different transport model, not just new REST endpoints.

**Documents**:
- Protocol Specification: `go-wallet-backend/docs/websocket-protocol-spec.md`
- External Fetches Analysis: `go-wallet-backend/docs/wallet-frontend-external-fetches.md`

**Key Deliverables**:
- [ ] WebSocket endpoint (`/api/v2/wallet`)
- [ ] Flow handlers (OID4VCI, OID4VP)
- [ ] Integrated signing (DPoP, key attestation)
- [ ] SSRF mitigations (IP blocklist, schema validation)
- [ ] Shared services (VCTMFetcher, TrustEvaluator, MetadataCache)
- [ ] Use pre-computed trust from VCTM registry when available
- [ ] JIT evaluation fallback for unregistered issuers

**Dependencies**:
- Trust Abstraction Layer (for JIT evaluation fallback)
- VCTM Registry (for pre-computed trust lookup)

**Proxy Traffic Reduction**: Remaining ~75% (100% total with VCTM)

---

### 4. Frontend Integration (Designed)

**Status**: 📋 Design Complete

**Purpose**: Update wallet-frontend with transport abstraction layer supporting
both HTTP/proxy (legacy/v1) and WebSocket (new/v2) transports.

**Documents**:
- Integration Design: `go-wallet-backend/docs/frontend-websocket-integration.md`

**Key Deliverables**:
- [ ] `IFlowTransport` interface
- [ ] `HttpProxyTransport` (wraps existing v1 flows)
- [ ] `WebSocketTransport` (new v2 flows)
- [ ] `FlowTransportContext` provider
- [ ] Transport allow-list configuration
- [ ] Hybrid flow hooks (`useOID4VCIFlow`, `useOID4VPFlow`)

**Dependencies**:
- WebSocket Protocol (backend must be available)

**Configuration**:
- `VITE_WS_URL`: WebSocket endpoint URL
- `VITE_ALLOWED_TRANSPORTS`: Allow-list (`http`, `websocket`, or both)

---

## Implementation Order

```
Phase 1: Foundation (Weeks 1-2)
├─ 1.1 ✅ VCTM Registry merged
├─ 1.2 Add TrustEvaluator to VCTM registration flow
├─ 1.3 Store trust decisions alongside VCTMs
└─ 1.4 Add JIT trust evaluation service (fallback for unknown issuers)

Phase 2: Backend Protocol - API v2 (Weeks 3-5)
├─ 2.1 Implement WebSocket endpoint (`/api/v2/wallet`)
├─ 2.2 Implement OID4VCI flow handler (uses pre-computed trust)
├─ 2.3 Implement OID4VP flow handler
├─ 2.4 Add shared services integration (VCTM lookup, JIT fallback)
└─ 2.5 Backend testing and deployment

Phase 3: Frontend Integration (Weeks 6-7)
├─ 3.1 Add transport abstraction layer
├─ 3.2 Implement WebSocketTransport (v2)
├─ 3.3 Add FlowTransportContext and configuration
├─ 3.4 Update flow hooks to use transport abstraction
└─ 3.5 Frontend testing

Phase 4: Validation & Rollout (Week 8)
├─ 4.1 End-to-end testing with both transports (v1 + v2)
├─ 4.2 Performance benchmarking (compare pre-computed vs JIT trust)
├─ 4.3 Gradual rollout (WebSocket/v2 opt-in)
└─ 4.4 Documentation updates
```

## Milestone Definitions

### M1: Pre-computed Trust (End of Phase 1)
- VCTM Registry evaluates trust at registration time
- Trust decisions stored alongside VCTM metadata
- Frontend can display trust indicators from cached data
- JIT fallback service available for unregistered issuers

### M2: API v2 Available (End of Phase 2)
- WebSocket endpoint functional (`/api/v2/wallet`)
- OID4VCI flow working end-to-end via WebSocket
- OID4VP flow working end-to-end via WebSocket
- Pre-computed trust from VCTM registry used when available
- JIT evaluation used for unknown issuers
- HTTP proxy (v1) still available as fallback

### M3: Frontend Complete (End of Phase 3)
- Transport abstraction in place
- v1 (HTTP/proxy) and v2 (WebSocket) transports both functional
- Configuration switch between transports
- Seamless upgrade path for existing deployments

### M4: Production Ready (End of Phase 4)
- WebSocket (v2) as preferred transport
- Option to disable HTTP proxy (v1) via configuration
- Performance comparison documented (pre-computed vs JIT)
- Monitoring and metrics in place
- Documentation complete

## Risk Mitigation

| Risk | Mitigation |
|------|------------|
| WebSocket connectivity issues (firewalls, proxies) | HTTP transport remains available; SSE alternative documented |
| Trust framework complexity | Start with single framework (OIDF), add others incrementally |
| Breaking existing flows | Transport abstraction preserves existing code paths |
| Performance regression | Benchmark before/after; WebSocket should be faster |

## Success Criteria

1. **Security**: No arbitrary URL fetching from frontend
2. **Privacy**: Optional IP privacy via OHTTP (orthogonal)
3. **Functionality**: All existing flows work via WebSocket (v2)
4. **Configuration**: Deployments can disable HTTP proxy (v1) entirely
5. **Performance**: Pre-computed trust enables instant trust display
6. **Graceful Degradation**: JIT fallback for unregistered issuers

## Document References

| Document | Location | Purpose |
|----------|----------|---------|
| WebSocket Protocol Spec | `go-wallet-backend/docs/websocket-protocol-spec.md` | API v2 protocol design, message formats, flow definitions |
| Frontend Integration | `go-wallet-backend/docs/frontend-websocket-integration.md` | Transport abstraction, TypeScript interfaces |
| External Fetches Analysis | `go-wallet-backend/docs/wallet-frontend-external-fetches.md` | Problem analysis, proxy usage catalog |
| Trust Architecture | `go-trust/docs/ARCHITECTURE-MULTI-REGISTRY.md` | Multi-registry trust framework |
| VCTM Registry | `go-wallet-backend/internal/registry/` | Implementation of metadata + trust caching |

## Next Steps

### Immediate: Trust Evaluation at VCTM Registration

The VCTM registry is merged. The next task is adding trust evaluation at
**registration time** so trust decisions are pre-computed:

**Files to modify**: `go-wallet-backend/internal/registry/handler.go`

**Changes**:
1. Add `TrustEvaluator` field to Handler struct (optional dependency)
2. Update `NewHandler()` to accept evaluator
3. When **registering** a VCTM, evaluate issuer trust
4. Store trust decision alongside VCTM in storage
5. Include trust status in responses (new field)

**Interface** (from `go-wallet-backend/pkg/trust`):
```go
type TrustEvaluator interface {
    Evaluate(ctx context.Context, req *EvaluationRequest) (*TrustDecision, error)
    SupportsKeyType(kt KeyType) bool
    Name() string
    Healthy() bool
}
```

**Pre-computed trust workflow**:
```
POST /api/v1/vctm/register
  ↓
Fetch VCTM from URL
  ↓
Extract issuer identifier
  ↓
Call TrustEvaluator.Evaluate()  ← Trust evaluation happens HERE
  ↓
Store VCTM + TrustDecision in DB
  ↓
Return response with trust_status
```

**Trust decision stored with VCTM**:
```go
type StoredVCTM struct {
    VCT             string         `json:"vct"`              // Existing
    Metadata        *VCTMDocument  `json:"metadata"`         // Existing
    EmbeddedImages  map[string]... `json:"embedded_images"`  // Existing
    TrustStatus     string         `json:"trust_status"`     // NEW: "trusted", "unknown", "untrusted"
    TrustEvaluator  string         `json:"trust_evaluator"`  // NEW: Which evaluator made decision
    TrustEvaluatedAt time.Time     `json:"trust_evaluated_at"` // NEW: When evaluated
    TrustMetadata   map[string]any `json:"trust_metadata"`   // NEW: Framework-specific info
}
```

### After Trust Integration

1. Add JIT trust evaluation service for unregistered issuers
2. Begin WebSocket endpoint implementation (`/api/v2/wallet`)
3. Implement OID4VCI flow handler (uses VCTM registry for trust lookup)
4. Implement OID4VP flow handler
5. Coordinate with wallet-frontend team on v2 integration timeline

### Branch Reconciliation Note

The `feature/api-versioning-discover-trust` branch predates the VCTM registry
merge and had a different API versioning concept. That branch's discover-and-trust
endpoint concept is now subsumed by:

1. **Pre-computed trust**: VCTM registration includes trust evaluation
2. **API v2 = WebSocket**: Not new REST endpoints

The useful code from that branch (TrustService implementation) can be cherry-picked
or adapted for the JIT fallback service.
