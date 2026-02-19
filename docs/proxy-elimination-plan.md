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

A critical architectural insight: **Trust is per-tenant**.

Each tenant may have different trust anchors, federation endpoints, and policies
configured in go-trust. Trust evaluation results can be cached in the existing
per-tenant issuer store (`domain.CredentialIssuer`), but the trust decision for
the same issuer may differ between tenants.

The wallet needs:
1. **VCTM Registry**: "How do I display this credential type?" (keyed by `vct`)
2. **TrustService**: "Is this issuer trusted for this tenant?" (tenant + issuer)
3. **Existing Issuer Store**: Per-tenant issuer config with cached trust status

### Separation of Concerns

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                      TRUST EVALUATION ARCHITECTURE                          │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  VCTM Registry                    TrustService                              │
│  ─────────────                    ────────────                              │
│  Question: "How display?"         Question: "Is trusted (for tenant)?"      │
│  Key: vct identifier              Key: tenant_id + issuer identifier        │
│  Storage: Persistent              Storage: Cached in CredentialIssuer       │
│                                                                             │
│  Returns:                         Returns:                                  │
│  - Display name                   - Trust status (trusted/unknown/untrusted)│
│  - Logo, colors, background       - Trust framework used                    │
│  - Schema for rendering           - Certificate chain (if applicable)       │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │ Per-Tenant Trust                                                    │   │
│  │                                                                     │   │
│  │   Tenant A: go-trust config → OIDF federation anchor A             │   │
│  │   Tenant B: go-trust config → OIDF federation anchor B             │   │
│  │                                                                     │   │
│  │   Same issuer → different trust result per tenant                  │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  Existing domain.CredentialIssuer (per-tenant):                             │
│  - CredentialIssuerIdentifier (issuer URL)                                  │
│  - TrustStatus, TrustFramework (cached evaluation)                          │
│  - TrustEvaluatedAt (for TTL/refresh)                                       │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Trust Evaluation Strategy

**At-Registration Trust with Background Refresh**:
- Trust evaluated when issuers are registered
- Background worker refreshes stale trust (TTL-based)
- JIT fallback for unregistered issuers

**Issuer Metadata Endpoint** (`/issuer-metadata`):
- Located on registry server (standalone mode)
- Takes issuer identifier parameter
- Fetches metadata, evaluates trust via go-trust
- Returns combined metadata + trust status
- Standalone mode: stateless, no database persistence

**Per-Tenant Configuration** (via Admin API):
- `trust_endpoint`: go-trust service URL (or default)
- `trust_ttl`: How long trust results are valid
- `refresh_interval`: Background refresh frequency

### Why Per-Tenant Trust

1. **Different Trust Anchors**: Each tenant may trust different federation roots
2. **Policy Isolation**: Tenant A's trust policy shouldn't affect Tenant B
3. **Existing Model**: `domain.CredentialIssuer` already has TenantID
4. **Caching**: Trust results cached per-tenant with TTL for freshness

## Workstreams

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         IMPLEMENTATION WORKSTREAMS                          │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐  │
│  │ 1. VCTM     │    │ 2. Trust    │    │ 3. WebSocket│    │ 4. Frontend │  │
│  │ Registry    │───▶│ Service     │───▶│ Protocol    │───▶│ Integration │  │
│  │             │    │             │    │ (API v2)    │    │             │  │
│  │ ✅ COMPLETE │    │ ✅ COMPLETE │    │ 📋 DESIGNED │    │ 📋 DESIGNED │  │
│  └─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘  │
│                                                                             │
│  Legend: ✅ Complete  🔄 In Progress  📋 Design Complete  ⬜ Not Started   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 1. VCTM Registry (Complete)

**Status**: ✅ Complete (Merged to main)

**Purpose**: Server-side caching and resolution of Verifiable Credential Type
Metadata (VCTM) with embedded images. Provides display metadata for credentials.

**Location**: `go-wallet-backend/internal/registry/`

**Key Deliverables**:
- [x] VCTM fetcher with caching
- [x] Image embedding (logos, backgrounds)
- [x] REST API endpoints (`/api/v1/vctm/*`)

**Proxy Traffic Reduction**: ~25%

---

### 2. Trust Service (Complete)

**Status**: ✅ Complete

**Purpose**: Query-based trust evaluation using go-trust evaluators. Returns
trust status for any issuer identifier with TTL caching.

**Location**: 
- `go-wallet-backend/internal/service/trust.go` - TrustService wrapper
- `go-wallet-backend/internal/registry/issuer_metadata.go` - /issuer-metadata handler
- `go-wallet-backend/internal/registry/trust_refresh.go` - Background refresh worker

**Key Deliverables**:
- [x] `TrustService` wrapping go-trust evaluators
- [x] `/issuer-metadata` endpoint on registry server
- [x] Trust status (trusted/unknown/untrusted) with framework info
- [x] Per-tenant trust configuration (trust_endpoint, trust_ttl, refresh_interval)
- [x] Background refresh worker for stale trust evaluations
- [x] Admin API support for trust configuration

**Integration Points**:
- Registry server: standalone /issuer-metadata endpoint (stateless)
- Main server: per-tenant trust via CredentialIssuer persistence
- VCTM Registry for credential display metadata
- WebSocket protocol for trust queries during protocol flows

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

### M1: Trust Integration (End of Phase 1) - IN PROGRESS
- ✅ VCTM Registry merged
- ✅ TrustService wrapping go-trust evaluators
- ✅ JIT discover-and-trust endpoint
- ✅ Trust fields in CredentialIssuer (TrustStatus, TrustFramework, TrustEvaluatedAt)
- ⬜ Per-tenant TrustEvaluator configuration
- ⬜ Admin API integration (evaluate on issuer create/update)
- ⬜ Frontend can display trust indicators

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

### ✅ Completed in `feature/trust-evaluation` branch

1. **TrustService** (`internal/service/trust.go`): Wraps go-trust evaluators
   for issuer/verifier trust evaluation with multi-framework support.

2. **JIT Trust Endpoint** (`internal/api/discover_trust.go`):
   - `POST /api/discover-and-trust` - Evaluate issuer trust on-demand
   - Fetches issuer metadata and IACA certificates
   - Returns trust status, framework, and certificate chain

3. **Trust Fields in CredentialIssuer** (`internal/domain/credential.go`):
   - `TrustStatus` (trusted/untrusted/unknown)
   - `TrustFramework` (oidf/ebsi/x509/etc.)
   - `TrustEvaluatedAt` (for TTL-based refresh)

4. **API Version Capabilities** (`internal/api/version.go`):
   - Version discovery endpoint
   - Capability negotiation structure

### 🔄 Gaps Identified

| Gap | Description | Priority |
|-----|-------------|----------|
| **Per-tenant TrustEvaluator** | TrustService needs per-tenant go-trust config | High |
| **Admin API integration** | Create/update issuer should trigger trust eval | High |
| **Cache persistence** | discover-and-trust should cache to CredentialIssuer | Medium |
| **TTL refresh** | Background job to refresh stale trust status | Medium |
| **go-trust config per tenant** | How do tenants configure their trust anchors? | High |

### Open Questions

1. **Per-Tenant Trust Configuration**: How is go-trust configured per tenant?
   - Option A: Tenant-specific config files (e.g., `/config/tenants/{id}/trust.yaml`)
   - Option B: Database-stored trust anchors per tenant
   - Option C: Tenant profile references shared trust configs

2. **Trust TTL Policy**: How long should cached trust be valid?
   - Suggested: 24 hours for federation-based, 1 hour for IACA/X.509

3. **Trust Refresh Strategy**: Eager vs lazy refresh?
   - Eager: Background job refreshes all issuers periodically
   - Lazy: Refresh on access when TTL expired

4. **Existing Issuers Migration**: How to populate trust for existing issuers?
   - Migration script to evaluate all existing CredentialIssuer records

### Recommended Next Steps

**Immediate (Complete Trust Integration):**

1. **Wire per-tenant TrustEvaluator config** - Determine how tenants configure
   trust anchors and implement config loading per tenant.

2. **Integrate with Admin Issuer API** - When `POST /admin/tenants/:id/issuers`
   is called, invoke TrustService to evaluate and populate trust fields.

3. **Persist from discover-and-trust** - Option to save JIT results to
   CredentialIssuer for future lookups.

**Near-term (WebSocket Protocol):**

4. **Begin WebSocket endpoint** (`/api/v2/wallet`) - This is the bulk of
   proxy elimination work.

5. **OID4VCI flow handler** - First protocol to implement over WebSocket.

**Example Admin API integration:**
```go
// In admin_handlers.go CreateIssuer:
func (h *AdminHandler) CreateIssuer(c *gin.Context) {
    // ... existing validation ...
    
    // Evaluate trust for the new issuer
    if h.trustService != nil {
        trustResult, err := h.trustService.EvaluateIssuer(c.Request.Context(), 
            req.CredentialIssuerIdentifier, tenant.ID)
        if err == nil {
            issuer.TrustStatus = domain.TrustStatus(trustResult.Status)
            issuer.TrustFramework = trustResult.Framework
            now := time.Now()
            issuer.TrustEvaluatedAt = &now
        }
    }
    
    // ... save issuer ...
}
```
