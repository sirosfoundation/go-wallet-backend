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

## Workstreams

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         IMPLEMENTATION WORKSTREAMS                          │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐  │
│  │ 1. VCTM     │    │ 2. Trust    │    │ 3. WebSocket│    │ 4. Frontend │  │
│  │ Registry    │───▶│ Abstraction │───▶│ Protocol    │───▶│ Integration │  │
│  │             │    │ Layer       │    │             │    │             │  │
│  │ ✅ DONE     │    │ 🔄 IN PROG  │    │ 📋 DESIGNED │    │ 📋 DESIGNED │  │
│  └─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘  │
│                                                                             │
│  Legend: ✅ Complete  🔄 In Progress  📋 Design Complete  ⬜ Not Started   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 1. VCTM Registry (Complete)

**Status**: ✅ Complete (PR #22)

**Purpose**: Server-side caching and resolution of Verifiable Credential Type
Metadata (VCTM) with embedded images.

**Documents**:
- Implementation: `go-wallet-backend/` (feature/vctm-registry branch)
- PR: https://github.com/sirosfoundation/go-wallet-backend/pull/22

**Key Deliverables**:
- [x] VCTM fetcher with caching
- [x] Image embedding (logos, backgrounds)
- [x] REST API endpoints (`/api/v1/vctm/*`)
- [x] Trust evaluation interface integration point

**Proxy Traffic Reduction**: ~25%

---

### 2. Trust Abstraction Layer (In Progress)

**Status**: 🔄 In Progress

**Purpose**: Unified interface for evaluating trust across multiple frameworks
(OIDF, EBSI, X.509, ETSI TSL).

**Documents**:
- Architecture: `go-trust/docs/ARCHITECTURE-MULTI-REGISTRY.md`
- Multi-Registry Strategies: `go-trust/docs/MULTI-REGISTRY-STRATEGIES.md`
- Trust Metadata: `go-trust/docs/TRUST_METADATA_IMPLEMENTATION.md`
- OIDF Mapping: `go-trust/docs/OIDFED_PROTOCOL_MAPPING.md`

**Key Deliverables**:
- [ ] `TrustEvaluator` interface
- [ ] Multi-registry support (parallel queries)
- [ ] Trust status enumeration (`trusted`, `unknown`, `untrusted`)
- [ ] Integration with VCTM registry
- [ ] Policy expression language (optional)

**Dependencies**: None (foundational)

**Integration Points**:
- VCTM Registry uses `TrustEvaluator` for issuer validation
- WebSocket protocol includes trust status in metadata responses

---

### 3. WebSocket Protocol (Designed)

**Status**: 📋 Design Complete

**Purpose**: Unified WebSocket channel for all credential issuance and verification
flows, replacing protocol-specific proxy calls.

**Documents**:
- Protocol Specification: `go-wallet-backend/docs/websocket-protocol-spec.md`
- External Fetches Analysis: `go-wallet-backend/docs/wallet-frontend-external-fetches.md`

**Key Deliverables**:
- [ ] WebSocket endpoint (`/api/v2/wallet`)
- [ ] Flow handlers (OID4VCI, OID4VP)
- [ ] Integrated signing (DPoP, key attestation)
- [ ] SSRF mitigations (IP blocklist, schema validation)
- [ ] Shared services (VCTMFetcher, TrustEvaluator, MetadataCache)

**Dependencies**:
- Trust Abstraction Layer (for trust evaluation in flows)
- VCTM Registry (for metadata resolution)

**Proxy Traffic Reduction**: Remaining ~75% (100% total with VCTM)

---

### 4. Frontend Integration (Designed)

**Status**: 📋 Design Complete

**Purpose**: Update wallet-frontend with transport abstraction layer supporting
both HTTP/proxy (legacy) and WebSocket (new) transports.

**Documents**:
- Integration Design: `go-wallet-backend/docs/frontend-websocket-integration.md`

**Key Deliverables**:
- [ ] `IFlowTransport` interface
- [ ] `HttpProxyTransport` (wraps existing)
- [ ] `WebSocketTransport` (new)
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
├─ 1.1 Complete Trust Abstraction Layer core interfaces
├─ 1.2 Integrate TrustEvaluator with VCTM Registry
└─ 1.3 Deploy VCTM Registry (merge PR #22)

Phase 2: Backend Protocol (Weeks 3-5)
├─ 2.1 Implement WebSocket endpoint and connection handling
├─ 2.2 Implement OID4VCI flow handler
├─ 2.3 Implement OID4VP flow handler
├─ 2.4 Add shared services integration
└─ 2.5 Backend testing and deployment

Phase 3: Frontend Integration (Weeks 6-7)
├─ 3.1 Add transport abstraction layer
├─ 3.2 Implement WebSocketTransport
├─ 3.3 Add FlowTransportContext and configuration
├─ 3.4 Update flow hooks to use transport abstraction
└─ 3.5 Frontend testing

Phase 4: Validation & Rollout (Week 8)
├─ 4.1 End-to-end testing with both transports
├─ 4.2 Performance benchmarking
├─ 4.3 Gradual rollout (WebSocket opt-in)
└─ 4.4 Documentation updates
```

## Milestone Definitions

### M1: Trust Integration (End of Phase 1)
- VCTM Registry deployed with trust evaluation
- Issuer metadata includes trust status
- Frontend can display trust indicators

### M2: WebSocket Available (End of Phase 2)
- WebSocket endpoint functional
- OID4VCI flow working end-to-end via WebSocket
- OID4VP flow working end-to-end via WebSocket
- HTTP proxy still available as fallback

### M3: Frontend Complete (End of Phase 3)
- Transport abstraction in place
- Configuration switch between HTTP and WebSocket
- Both transports tested and functional

### M4: Production Ready (End of Phase 4)
- WebSocket as preferred transport
- Option to disable HTTP proxy via configuration
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
3. **Functionality**: All existing flows work via WebSocket
4. **Configuration**: Deployments can disable HTTP proxy entirely
5. **Performance**: Flow latency equal or better than HTTP

## Document References

| Document | Location | Purpose |
|----------|----------|---------|
| WebSocket Protocol Spec | `go-wallet-backend/docs/websocket-protocol-spec.md` | Protocol design, message formats, flow definitions |
| Frontend Integration | `go-wallet-backend/docs/frontend-websocket-integration.md` | Transport abstraction, TypeScript interfaces |
| External Fetches Analysis | `go-wallet-backend/docs/wallet-frontend-external-fetches.md` | Problem analysis, proxy usage catalog |
| Trust Architecture | `go-trust/docs/ARCHITECTURE-MULTI-REGISTRY.md` | Multi-registry trust framework |
| VCTM Registry PR | PR #22 on go-wallet-backend | Implementation of metadata caching |

## Next Steps

1. **Immediate**: Review and merge VCTM Registry PR #22
2. **This Week**: Complete TrustEvaluator interface in go-trust
3. **Next Week**: Begin WebSocket endpoint implementation
4. **Ongoing**: Coordinate with wallet-frontend team on integration timeline
