# Proxy Elimination Implementation Plan

## Overview

This document outlines the implementation plan for eliminating the open HTTP proxy
from the wallet architecture. The plan consists of:

1. A **hybrid binary architecture** that separates concerns into deployable modes
2. A **WebSocket protocol** (API v2) that replaces arbitrary URL fetching
3. **Client-side credential management** that preserves privacy

## Problem Statement

The current wallet architecture uses an open HTTP proxy (`/proxy` endpoint) that:

1. **Security Risk**: Allows arbitrary HTTP requests to external URLs
2. **Privacy Concern**: Creates a binding between browser/user and backend
3. **No Protocol Awareness**: Treats all requests as generic HTTP
4. **Monolithic Design**: All services in one binary, cannot scale independently

**Goals**:
- Replace open proxy with protocol-specific APIs
- Enable privacy-preserving deployment options (local engine for native apps)
- Allow independent scaling of different service roles
- Keep credentials encrypted and client-controlled

---

## Hybrid Binary Architecture

The wallet backend is built as a **single binary** that can operate in different
modes, enabling flexible deployment from development (all-in-one) to production
(distributed services).

### Operating Modes

```
go-wallet --mode=<mode>

Modes:
  all       Run all services (development/simple deployments)
  backend   User management, admin API, background workers
  engine    WebSocket protocol flows (API v2)
  registry  VCTM registry, issuer metadata
  auth      Authentication server (WebAuthn, OAuth)
  storage   Encrypted credential storage
```

### Service Responsibilities

| Mode | Responsibilities | State | Scaling |
|------|------------------|-------|---------|
| **backend** | Admin API, tenant config, background workers | Database | Horizontal |
| **engine** | WebSocket flows, signing coordination, external fetches | Stateless | Horizontal |
| **registry** | VCTM cache, issuer metadata, trust evaluation | Cache + DB | Horizontal |
| **auth** | User registration, login, WebAuthn, OAuth AS | Database | Horizontal |
| **storage** | Encrypted credential blobs, sync | Database | Horizontal |

### Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         HYBRID BINARY ARCHITECTURE                          │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│    ┌─────────────────────────────────────────────────────────────────┐     │
│    │                      CLIENT (Browser/Native)                     │     │
│    │  ┌──────────────────────────────────────────────────────────┐   │     │
│    │  │  Local Storage: Encrypted credentials, keys, preferences │   │     │
│    │  │  Capabilities: Signing, Encryption, Credential Matching  │   │     │
│    │  └──────────────────────────────────────────────────────────┘   │     │
│    └──────────────────────────┬──────────────────────────────────────┘     │
│                               │                                             │
│          ┌────────────────────┼────────────────────┐                       │
│          │                    │                    │                       │
│          ▼                    ▼                    ▼                       │
│   ┌──────────────┐    ┌──────────────┐    ┌──────────────┐                │
│   │    engine    │    │     auth     │    │   storage    │                │
│   │  (WebSocket) │    │   (OAuth)    │    │  (Encrypted) │                │
│   │              │    │              │    │              │                │
│   │ Protocol     │    │ WebAuthn     │    │ Credential   │                │
│   │ flows        │    │ Login/Reg    │    │ blobs        │                │
│   │ Signing req  │    │ JWT issuance │    │ Sync         │                │
│   └──────┬───────┘    └──────┬───────┘    └──────┬───────┘                │
│          │                   │                   │                         │
│          │                   │                   │                         │
│   ┌──────┴───────────────────┴───────────────────┴───────┐                │
│   │              Shared Read-Only Data Layer              │                │
│   │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐   │                │
│   │  │ Tenant      │  │ JWT Keys    │  │ Rate Limit  │   │                │
│   │  │ Config      │  │             │  │ Config      │   │                │
│   │  └─────────────┘  └─────────────┘  └─────────────┘   │                │
│   └──────────────────────────┬───────────────────────────┘                │
│                              │                                             │
│          ┌───────────────────┼───────────────────┐                        │
│          │                   │                   │                        │
│          ▼                   ▼                   ▼                        │
│   ┌──────────────┐    ┌──────────────┐    ┌──────────────┐               │
│   │   registry   │    │   backend    │    │  go-trust    │               │
│   │              │    │              │    │  (external)  │               │
│   │ VCTM cache   │    │ Admin API    │    │              │               │
│   │ Issuer meta  │    │ Tenant mgmt  │    │ Trust eval   │               │
│   │ Trust cache  │    │ Background   │    │ Federation   │               │
│   └──────────────┘    └──────────────┘    └──────────────┘               │
│                                                                           │
└───────────────────────────────────────────────────────────────────────────┘
```

### Deployment Scenarios

#### Development: All-in-One
```bash
go-wallet --mode=all --config=config.yaml
# Single process, all services, simple setup
```

#### Production: Cloud Distributed
```bash
# Separate containers/pods
go-wallet --mode=auth     --config=auth.yaml
go-wallet --mode=storage  --config=storage.yaml
go-wallet --mode=engine   --config=engine.yaml
go-wallet --mode=registry --config=registry.yaml
go-wallet --mode=backend  --config=backend.yaml
```

#### Native App: Local Engine for Privacy
```
┌────────────────────────────────────────────────────────────────┐
│                     NATIVE APP DEPLOYMENT                       │
│                                                                 │
│   ┌─────────────────────────────────────────────────────────┐  │
│   │                    Native App Process                    │  │
│   │  ┌───────────────┐  ┌───────────────────────────────┐   │  │
│   │  │    engine     │  │         App UI                │   │  │
│   │  │ (embedded)    │◄─┤  Signing, Credential Matching │   │  │
│   │  │               │  │                               │   │  │
│   │  │ External HTTP │  │  Encrypted local storage      │   │  │
│   │  │ to issuers/   │  └───────────────────────────────┘   │  │
│   │  │ verifiers     │                                      │  │
│   │  └───────┬───────┘                                      │  │
│   └──────────┼──────────────────────────────────────────────┘  │
│              │                                                  │
│              ▼                                                  │
│   ┌──────────────────┐        ┌──────────────────┐             │
│   │ Issuers/Verifiers│        │  Cloud Backend   │             │
│   │    (External)    │        │  (auth+storage)  │             │
│   │                  │        │                  │             │
│   │ Cloud never sees │        │ Only sees:       │             │
│   │ these requests   │        │ - Login          │             │
│   │                  │        │ - Encrypted blobs│             │
│   └──────────────────┘        └──────────────────┘             │
│                                                                 │
│   Privacy: Cloud backend never observes credential flows        │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## API Versioning Strategy

| Version | Transport | Mode | Purpose |
|---------|-----------|------|---------|
| **v1** | REST | backend, auth, storage, registry | Traditional REST endpoints |
| **v2** | WebSocket | engine | Protocol-aware flows, no arbitrary URLs |

**Key principle**: API v2 = WebSocket protocol via the **engine** mode.

---

## Engine: Stateless Protocol Flows

The **engine** is designed to be stateless and privacy-conscious:

### What Engine Does
- Orchestrates OID4VCI/OID4VP flows via WebSocket
- Makes external HTTP requests to issuers/verifiers
- Requests signatures from client (keys never leave client)
- Evaluates trust via go-trust
- Looks up VCTM for display metadata

### What Engine Does NOT Do
- Store credentials (client → storage directly)
- Know full credential inventory (client does matching)
- Manage users or tenants (backend does this)
- Handle authentication (auth service does this)

### Engine Dependencies (Read-Only)

| Dependency | Source | Access |
|------------|--------|--------|
| JWT validation keys | Shared config | Read-only |
| Tenant config | Database (read) | Read-only |
| VCTM metadata | Registry HTTP | HTTP |
| Trust endpoint | From tenant config | HTTP |
| SSRF blocklist | Config file | Static |

### Client-Side Credential Matching (Privacy Model)

During OID4VP flows, the engine sends the presentation_definition to the client,
and the client performs credential matching locally:

```
Engine → Client: { "step": "match_credentials", "presentation_definition": {...} }
Client → Engine: { "action": "credentials_matched", "selected": [...] }
```

This ensures the engine never sees the user's full credential inventory.

---

## Service Separation Details

### Auth Service (`--mode=auth`)

Handles user identity, distinct from credential operations:

| Endpoint | Purpose |
|----------|---------|
| `POST /auth/register` | User registration (WebAuthn) |
| `POST /auth/login` | User authentication |
| `POST /auth/token` | JWT token issuance |
| `GET /.well-known/jwks.json` | Public keys for JWT validation |
| `POST /auth/webauthn/*` | WebAuthn ceremony endpoints |

**State**: User database, WebAuthn credentials
**Scaling**: Horizontal (session-less JWT model)

### Storage Service (`--mode=storage`)

Handles encrypted credential storage:

| Endpoint | Purpose |
|----------|---------|
| `GET /storage/credentials` | List encrypted blobs |
| `PUT /storage/credentials/:id` | Store encrypted blob |
| `DELETE /storage/credentials/:id` | Delete blob |
| `GET /storage/sync` | Sync state for multi-device |

**Key insight**: Storage service only sees encrypted blobs. Client holds
encryption keys. Server cannot read credential content.

**State**: Encrypted blob database
**Scaling**: Horizontal

### Registry Service (`--mode=registry`)

Handles credential type and issuer metadata:

| Endpoint | Purpose |
|----------|---------|
| `GET /type-metadata` | VCTM lookup |
| `GET /issuer-metadata` | Issuer metadata + trust |
| `POST /vctm` | Register/update VCTM |

**State**: VCTM cache, trust evaluation cache
**Scaling**: Horizontal (cache can be shared Redis)

### Backend Service (`--mode=backend`)

Handles administration and background tasks:

| Endpoint | Purpose |
|----------|---------|
| `POST /admin/tenants` | Tenant management |
| `POST /admin/tenants/:id/issuers` | Issuer configuration |
| Background workers | Trust refresh, cleanup |

**State**: Full database access
**Scaling**: Limited (admin operations are rare)

---

## Trust Evaluation Architecture

A critical architectural insight: **Trust is per-tenant**.

Each tenant may have different trust anchors, federation endpoints, and policies
configured in go-trust.

### Trust Lookup Locations

| Service | Trust Access |
|---------|--------------|
| **engine** | Calls go-trust via AuthZEN during flows |
| **registry** | Caches trust results with VCTM/issuer metadata |
| **backend** | Background refresh of stale trust evaluations |

### Separation of Concerns

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                      TRUST EVALUATION ARCHITECTURE                          │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  VCTM Registry (registry mode)    TrustService (engine calls go-trust)     │
│  ─────────────────────────────    ────────────────────────────────────     │
│  Question: "How display?"         Question: "Is trusted (for tenant)?"      │
│  Key: vct identifier              Key: tenant_id + issuer identifier        │
│  Storage: Cache + database        Storage: Per-request (stateless)          │
│                                                                             │
│  Returns:                         Returns:                                  │
│  - Display name                   - Trust status (trusted/unknown/untrusted)│
│  - Logo, colors, background       - Trust framework used                    │
│  - Schema for rendering           - Certificate chain (if applicable)       │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Per-Tenant Configuration

```yaml
# Tenant config (shared data layer)
tenants:
  tenant-a:
    trust_endpoint: https://trust-a.example.com  # go-trust instance
    trust_ttl: 24h
    allowed_protocols: [oid4vci, oid4vp]
  tenant-b:
    trust_endpoint: https://trust-b.example.com
    trust_ttl: 12h
```

## Workstreams

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         IMPLEMENTATION WORKSTREAMS                          │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐  │
│  │ 1. VCTM     │    │ 2. Trust &  │    │ 3. Hybrid   │    │ 4. Frontend │  │
│  │ Registry    │───▶│ Discovery   │───▶│ Binary +    │───▶│ Integration │  │
│  │             │    │             │    │ WebSocket   │    │             │  │
│  │ ✅ COMPLETE │    │ ✅ COMPLETE │    │ 📋 DESIGNED │    │ 📋 DESIGNED │  │
│  └─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘  │
│                                                                             │
│  Legend: ✅ Complete  🔄 In Progress  📋 Design Complete  ⬜ Not Started   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 1. VCTM Registry (Complete)

**Status**: ✅ Complete (Merged to main)

**Mode**: `--mode=registry` (or embedded in `--mode=all`)

**Purpose**: Server-side caching and resolution of Verifiable Credential Type
Metadata (VCTM) with embedded images. Provides display metadata for credentials.

**Location**: `go-wallet-backend/internal/registry/`

**Key Deliverables**:
- [x] VCTM fetcher with caching
- [x] Image embedding (logos, backgrounds)
- [x] REST API endpoints (`GET /type-metadata`, `GET /issuer-metadata`)

**Proxy Traffic Reduction**: ~25%

---

### 2. Trust & Metadata Discovery (Complete)

**Status**: ✅ Complete

**Purpose**: Internal services for entity metadata discovery and trust evaluation
via go-trust (AuthZEN). Used by engine during credential issuance and presentation.

**Architecture**: All trust configuration (X.509, TSL, OIDF federation, etc.) is
managed by go-trust. The engine calls go-trust endpoints via AuthZEN protocol.

**Location**: 
- `go-wallet-backend/internal/metadata/` - Entity metadata discovery services
  - `issuer.go` - OpenID4VCI issuer metadata discovery + IACA certificates
  - `verifier.go` - OpenID4VP verifier/client metadata discovery
- `go-wallet-backend/pkg/trust/authzen/` - AuthZEN client for go-trust endpoints
- `go-wallet-backend/internal/registry/trust_refresh.go` - Background refresh worker

**Key Deliverables**:
- [x] Issuer metadata discovery (OpenID4VCI `.well-known/openid-credential-issuer`)
- [x] Verifier metadata discovery (OpenID4VP `client_metadata` / `client_metadata_uri`)
- [x] IACA certificate fetching for mDOC (`mdoc_iacas_uri`)
- [x] AuthZEN client for go-trust trust evaluation
- [x] Background refresh worker (runs in `--mode=backend`)
- [x] Per-tenant trust configuration via `Tenant.TrustConfig`

**Integration**:
- Engine (`--mode=engine`) uses metadata discovery during flows
- Registry (`--mode=registry`) caches trust results
- Backend (`--mode=backend`) runs background refresh

---

### 3. Hybrid Binary + WebSocket Engine (Designed)

**Status**: 📋 Design Complete

**Purpose**: 
1. Restructure codebase into hybrid binary with operating modes
2. Implement WebSocket protocol endpoint in engine mode
3. Enable privacy-preserving local engine for native apps

**Documents**:
- Protocol Specification: `go-wallet-backend/docs/websocket-protocol-spec.md`
- External Fetches Analysis: `go-wallet-backend/docs/wallet-frontend-external-fetches.md`

**Key Deliverables**:

#### 3.1 Binary Mode Infrastructure
- [ ] Mode flag and dispatcher (`--mode=all|backend|engine|registry|auth|storage`)
- [ ] Shared configuration loading for all modes
- [ ] JWT validation keys accessible to all modes (read-only)
- [ ] Tenant config accessible to engine (read-only)

#### 3.2 Engine Mode (`--mode=engine`)
- [ ] WebSocket endpoint (`/api/v2/wallet`)
- [ ] Flow handlers (OID4VCI, OID4VP)
- [ ] Client-side credential matching protocol
- [ ] Signing coordination (sign_request/sign_response)
- [ ] SSRF mitigations (IP blocklist, schema validation)
- [ ] Registry client for VCTM lookups
- [ ] AuthZEN client for trust evaluation

#### 3.3 Auth Mode (`--mode=auth`)
- [ ] Extract authentication endpoints from current API
- [ ] WebAuthn registration and authentication
- [ ] JWT token issuance
- [ ] JWKS endpoint for public keys

#### 3.4 Storage Mode (`--mode=storage`)
- [ ] Extract credential storage endpoints
- [ ] Encrypted blob CRUD operations
- [ ] Multi-device sync support

**Proxy Traffic Reduction**: Remaining ~75% (100% total with registry)

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
- [ ] `CredentialMatcher` for client-side matching
- [ ] `FlowTransportContext` provider
- [ ] Transport configuration

**Dependencies**:
- Engine mode available (`--mode=engine`)

**Configuration**:
- `VITE_ENGINE_WS_URL`: WebSocket endpoint URL
- `VITE_AUTH_URL`: Authentication service URL
- `VITE_STORAGE_URL`: Storage service URL

---

## Implementation Order

```
Phase 1: Foundation (Complete)
├─ 1.1 ✅ VCTM Registry merged
├─ 1.2 ✅ Trust & Discovery services
├─ 1.3 ✅ Per-tenant trust configuration
└─ 1.4 ✅ Background trust refresh

Phase 2: Hybrid Binary Infrastructure (Weeks 1-2)
├─ 2.1 Add --mode flag and dispatcher to main.go
├─ 2.2 Refactor into internal/modes/ packages
│      ├─ modes/engine/    (WebSocket, flows)
│      ├─ modes/auth/      (WebAuthn, OAuth)
│      ├─ modes/storage/   (credential blobs)
│      ├─ modes/registry/  (existing, extracted)
│      ├─ modes/backend/   (admin, background)
│      └─ modes/all/       (development mode)
├─ 2.3 Shared config loading for all modes
├─ 2.4 JWT validation accessible to all modes
└─ 2.5 Tenant config accessible to engine (read-only)

Phase 3: Engine Mode + WebSocket Protocol (Weeks 3-5)
├─ 3.1 Implement WebSocket endpoint in engine mode
├─ 3.2 Implement OID4VCI flow handler
├─ 3.3 Implement OID4VP flow handler
├─ 3.4 Client-side credential matching protocol
├─ 3.5 Signing coordination (sign_request/sign_response)
└─ 3.6 SSRF mitigations and testing

Phase 4: Service Separation (Weeks 6-7)
├─ 4.1 Extract auth endpoints to --mode=auth
├─ 4.2 Extract storage endpoints to --mode=storage
├─ 4.3 Add health checks and service discovery
└─ 4.4 Docker/Kubernetes configurations

Phase 5: Frontend Integration (Weeks 8-9)
├─ 5.1 Transport abstraction layer
├─ 5.2 WebSocketTransport implementation
├─ 5.3 Client-side credential matcher
├─ 5.4 Service URL configuration
└─ 5.5 End-to-end testing

Phase 6: Validation & Rollout (Week 10)
├─ 6.1 End-to-end testing all deployment modes
├─ 6.2 Performance benchmarking
├─ 6.3 Documentation
└─ 6.4 Gradual rollout
```

## Milestone Definitions

### M1: Foundation (Complete)
- ✅ VCTM Registry with image embedding
- ✅ Trust evaluation via go-trust (AuthZEN)
- ✅ Per-tenant trust configuration
- ✅ Metadata discovery services

### M2: Hybrid Binary Infrastructure
- Single binary with `--mode` flag
- All modes share config loading
- JWT validation accessible to all modes
- `--mode=all` works identically to current behavior
- Tests pass for all modes

### M3: Engine Mode Available
- WebSocket endpoint functional (`/api/v2/wallet`)
- OID4VCI flow working via WebSocket
- OID4VP flow working via WebSocket
- Client-side credential matching protocol
- Engine is stateless (can be scaled horizontally)
- Local engine mode works for native app testing

### M4: Services Separated
- `--mode=auth` handles authentication independently
- `--mode=storage` handles credential storage independently
- All modes can run in separate containers
- Health check and service discovery working

### M5: Frontend Complete
- Transport abstraction in place
- v1 (HTTP/proxy) and v2 (WebSocket) both functional
- Client-side credential matching implemented
- Multi-service URL configuration working

### M6: Production Ready
- Native app local engine deployment documented
- Cloud distributed deployment documented
- Proxy disabled in new deployments
- Performance metrics captured

## Risk Mitigation

| Risk | Mitigation |
|------|------------|
| WebSocket connectivity issues | HTTP transport remains available; SSE alternative documented |
| Mode separation complexity | `--mode=all` provides simple development experience |
| Service discovery overhead | Start with static config, add discovery later |
| Breaking existing flows | Transport abstraction preserves existing code paths |
| Performance regression | Local engine mode eliminates network hops for native apps |

## Success Criteria

1. **Security**: No arbitrary URL fetching; protocol-defined operations only
2. **Privacy**: Local engine option eliminates cloud observation of flows
3. **Scalability**: Services can be scaled independently
4. **Flexibility**: Single binary runs as any mode
5. **Simplicity**: `--mode=all` as simple as current single-binary deployment
6. **Performance**: Engine stateless, horizontally scalable

## Data Flow Summary

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              DATA FLOW PATHS                                │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │                           CLIENT                                      │  │
│  │                                                                       │  │
│  │   Keys (local) ─────────────────────────────────────────────────┐    │  │
│  │   Credentials (encrypted local) ────────────────────────────┐   │    │  │
│  │   Matching logic (local) ────────────────────────────────┐  │   │    │  │
│  │                                                          │  │   │    │  │
│  └──────────────────────────────────────────────────────────┼──┼───┼────┘  │
│                                                             │  │   │       │
│      ┌───────────────┬──────────────────┬──────────────────┘  │   │       │
│      │               │                  │                     │   │       │
│      ▼               ▼                  ▼                     ▼   ▼       │
│  ┌────────┐    ┌──────────┐    ┌──────────────┐    ┌──────────────────┐  │
│  │ engine │    │ storage  │    │    auth      │    │   External       │  │
│  │        │    │          │    │              │    │   (direct)       │  │
│  │ Sees:  │    │ Sees:    │    │ Sees:        │    │                  │  │
│  │ - flow │    │ - opaque │    │ - username   │    │ Signing happens  │  │
│  │   type │    │   blobs  │    │ - credential │    │ locally, result  │  │
│  │ - one  │    │          │    │   ID         │    │ sent to engine   │  │
│  │   cred │    │ Cannot:  │    │              │    │                  │  │
│  │   at a │    │ - decrypt│    │ Cannot:      │    │                  │  │
│  │   time │    │ - read   │    │ - see flows  │    │                  │  │
│  │        │    │   content│    │ - see creds  │    │                  │  │
│  │ Cannot:│    │          │    │              │    │                  │  │
│  │ - see  │    │          │    │              │    │                  │  │
│  │   full │    │          │    │              │    │                  │  │
│  │   store│    │          │    │              │    │                  │  │
│  └────┬───┘    └──────────┘    └──────────────┘    └──────────────────┘  │
│       │                                                                   │
│       ▼                                                                   │
│  ┌──────────────────────────────────────────────────────────────────────┐│
│  │                    EXTERNAL SERVICES                                  ││
│  │  ┌────────────┐  ┌────────────┐  ┌────────────┐  ┌────────────┐     ││
│  │  │  Issuers   │  │  Verifiers │  │  go-trust  │  │  Registry  │     ││
│  │  │  (OID4VCI) │  │  (OID4VP)  │  │  (AuthZEN) │  │  (VCTM)    │     ││
│  │  └────────────┘  └────────────┘  └────────────┘  └────────────┘     ││
│  └──────────────────────────────────────────────────────────────────────┘│
│                                                                          │
│  KEY PRIVACY PROPERTIES:                                                 │
│  ─────────────────────                                                  │
│  • Engine sees credentials one-at-a-time (during flow)                  │
│  • Engine never sees full credential store                              │
│  • Storage sees only encrypted blobs (cannot decrypt)                   │
│  • Auth sees only identity (not credentials or flows)                   │
│  • Client does credential matching locally                              │
│  • Keys never leave client                                              │
│  • Local engine mode: cloud sees nothing about flows                    │
│                                                                          │
└──────────────────────────────────────────────────────────────────────────┘
```

## Document References

| Document | Location | Purpose |
|----------|----------|---------|
| WebSocket Protocol Spec | `docs/websocket-protocol-spec.md` | API v2 protocol, message formats, flow definitions |
| Frontend Integration | `docs/frontend-websocket-integration.md` | Transport abstraction, TypeScript interfaces |
| External Fetches | `docs/wallet-frontend-external-fetches.md` | Proxy usage analysis, traffic reduction targets |
| Trust Architecture | `go-trust/docs/ARCHITECTURE-*.md` | Multi-registry trust framework |
| VCTM Registry | `internal/registry/` | Metadata + trust caching implementation |

## Configuration Examples

### Development Mode (All-in-One)

```yaml
# config.yaml
mode: all
server:
  http_port: 8080
  ws_port: 8081
database:
  url: postgres://localhost:5432/wallet
jwt:
  secret: ${JWT_SECRET}
trust:
  default_endpoint: http://localhost:8090
registry:
  vctm_sources:
    - https://registry.siros.org/vctm
```

```bash
go-wallet --mode=all --config=config.yaml
```

### Production: Distributed

```yaml
# engine.yaml
mode: engine
server:
  ws_port: 8081
jwt:
  jwks_url: http://auth:8080/.well-known/jwks.json
tenants:
  source: postgres://db:5432/wallet  # Read-only
registry:
  url: http://registry:8082
trust:
  default_endpoint: http://go-trust:8090
ssrf:
  blocked_cidrs: [10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16]
```

```yaml
# auth.yaml
mode: auth
server:
  http_port: 8080
database:
  url: postgres://db:5432/wallet
jwt:
  secret: ${JWT_SECRET}
webauthn:
  rp_id: wallet.example.com
  rp_origins: [https://wallet.example.com]
```

```yaml
# storage.yaml
mode: storage
server:
  http_port: 8083
database:
  url: postgres://db:5432/wallet
jwt:
  jwks_url: http://auth:8080/.well-known/jwks.json
```

### Native App: Local Engine

```yaml
# local-engine.yaml
mode: engine
server:
  ws_port: 8081
  listen: 127.0.0.1  # Local only
jwt:
  jwks_url: https://auth.wallet.example.com/.well-known/jwks.json
trust:
  default_endpoint: https://trust.siros.org
registry:
  url: https://registry.siros.org
```

Native app embeds engine binary, connects locally, all external fetches happen
from user's device - cloud infrastructure never observes credential flows.

## Next Steps

### Immediate (Phase 2: Hybrid Binary Infrastructure)

1. **Add mode dispatcher** to `cmd/wallet/main.go`:
   ```go
   mode := flag.String("mode", "all", "Run mode: all|backend|engine|registry|auth|storage")
   ```

2. **Create mode packages** under `internal/modes/`:
   - Extract existing functionality into appropriate modes
   - Ensure shared services are importable by all modes

3. **Refactor main server** startup to be mode-aware

### Near-term (Phase 3: Engine Mode)

4. **Implement WebSocket endpoint** in `internal/modes/engine/`

5. **Implement flow handlers** for OID4VCI and OID4VP

6. **Add client-side matching** protocol to WebSocket spec

### Documentation Updates Needed

- [ ] Update `websocket-protocol-spec.md` with client-side matching protocol
- [ ] Create deployment guide for distributed mode
- [ ] Create native app integration guide
- [ ] Update API documentation for service separation
