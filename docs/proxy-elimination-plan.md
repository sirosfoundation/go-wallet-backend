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

A critical architectural insight: **Trust is a question you ask, not data you store**.

Trust evaluation is a runtime query, not a persistent entity. The wallet needs:
1. **VCTM Registry**: "How do I display this credential type?" (keyed by `vct`)
2. **TrustService**: "Is this issuer trusted?" (keyed by issuer identifier)
3. **Existing Issuer Store**: Wallet configuration via Admin API (`domain.CredentialIssuer`)

### Separation of Concerns

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                      TRUST EVALUATION ARCHITECTURE                          │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  VCTM Registry                    TrustService                              │
│  ─────────────                    ────────────                              │
│  Question: "How display?"         Question: "Is trusted?"                   │
│  Key: vct identifier              Key: issuer identifier                    │
│  Storage: Persistent              Storage: TTL cache only                   │
│                                                                             │
│  Returns:                         Returns:                                  │
│  - Display name                   - Trust status (trusted/unknown/untrusted)│
│  - Logo, colors, background       - Trust framework used                    │
│  - Schema for rendering           - Certificate chain (if applicable)       │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │ Credential Display Flow                                             │   │
│  │                                                                     │   │
│  │   credential.vct ───▶ VCTM Registry ───▶ visual metadata            │   │
│  │   credential.iss ───▶ TrustService  ───▶ trust marker (✓/✗/?)      │   │
│  │                                                                     │   │
│  │   Both are needed to display: [EU PID] ✓                            │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  Existing Admin API (domain.CredentialIssuer):                              │
│  - Wallet configuration of known issuers                                    │
│  - Per-tenant issuer management                                             │
│  - Updated separately from trust evaluation                                 │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Trust Evaluation Endpoints

**JIT Evaluation** (`/api/discover-and-trust`):
- Takes issuer identifier, returns trust evaluation
- Fetches metadata, runs TrustEvaluator
- Results cached with TTL (not persisted)
- Used for any issuer, known or unknown

### Why Service-Based Trust

1. **Simplicity**: No new entity stores, no duplication with existing issuer management
2. **Freshness**: Trust status can change; TTL cache ensures reasonable freshness
3. **Flexibility**: Issuers issue multiple credential types in multiple formats
4. **Separation**: VCTM describes types, TrustService evaluates entities

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
- `go-wallet-backend/internal/api/discover_trust.go` - JIT evaluation endpoint

**Key Deliverables**:
- [x] `TrustService` wrapping go-trust evaluators
- [x] `/api/discover-and-trust` JIT evaluation endpoint
- [x] Trust status (trusted/unknown/untrusted) with framework info

**Integration Points**:
- Existing issuer management via Admin API (`domain.CredentialIssuer`)
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

### M1: Pre-computed Trust (End of Phase 1) - IN PROGRESS
- ✅ VCTM Registry merged
- ✅ IssuerStore with trust status per issuer
- ✅ Trust evaluation at issuer registration time
- ✅ JIT discover-and-trust endpoint for unknown issuers
- ⬜ Wire up IssuerStore in main server
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

### ✅ Completed: Issuer Store and Trust Evaluation

The `trust-evaluation` branch now contains:

1. **IssuerStore** (`internal/registry/issuer.go`): Separate storage for issuers
   with trust status, indexed by issuer ID and credential types.

2. **TrustService** (`internal/service/trust.go`): Wraps go-trust evaluators
   for issuer/verifier trust evaluation.

3. **Issuer API Endpoints** (when IssuerStore is configured):
   - `GET /api/v1/vctm/issuers` - List all issuers
   - `GET /api/v1/vctm/issuers/:id` - Get specific issuer
   - `POST /api/v1/vctm/issuers` - Register issuer (triggers trust evaluation)
   - `DELETE /api/v1/vctm/issuers/:id` - Remove issuer
   - `GET /api/v1/vctm/credentials/:vct/issuers` - Get issuers for credential type

4. **JIT Trust Endpoint** (`/api/discover-and-trust`): For unknown issuers
   not pre-registered via the issuer API.

### Current: Wire Up IssuerStore in Main Server

**Files to modify**: `cmd/server/main.go` or server setup code

**Changes needed**:
1. Create IssuerStore with cache path
2. Load IssuerStore on startup
3. Pass IssuerStore to registry Handler via `WithIssuerStore()` option
4. Optionally pass TrustService via `WithTrustService()` option

**Example wiring**:
```go
// Create issuer store
issuerCachePath := filepath.Join(cacheDir, "issuers.json")
issuerStore := registry.NewIssuerStore(issuerCachePath)
if err := issuerStore.Load(); err != nil {
    logger.Warn("failed to load issuer cache", zap.Error(err))
}

// Create trust service (optional)
trustService := service.NewTrustService(cfg, logger)

// Create registry handler with issuer support
registryHandler := registry.NewHandler(
    vctmStore,
    dynamicCacheConfig,
    imageEmbedConfig,
    logger,
    registry.WithIssuerStore(issuerStore),
    registry.WithTrustService(trustService),
)
```

### Next: Frontend Integration for Trust Display

When displaying credentials, the frontend needs to:

1. Look up VCTM by credential type (vct) → get display metadata
2. Look up issuer by credential's issuer identifier → get trust status
3. Display VCTM metadata + issuer trust marker

**API flow**:
```
GET /api/v1/vctm/type-metadata?vct=eu.europa.ec.pid.1
  → Returns: display info, logo, schema

GET /api/v1/vctm/issuers/<url-encoded-issuer-id>
  → Returns: trust_status, trust_framework, trust_reason
  
OR (combined):
GET /api/v1/vctm/credentials/eu.europa.ec.pid.1/issuers
  → Returns: list of issuers with trust status
```

### After Frontend Integration

1. Begin WebSocket endpoint implementation (`/api/v2/wallet`)
2. Implement OID4VCI flow handler (uses IssuerStore for trust lookup)
3. Implement OID4VP flow handler
4. Coordinate with wallet-frontend team on transport abstraction
