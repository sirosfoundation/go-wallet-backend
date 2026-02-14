# ADR-011: Multi-Tenancy Design

| Status | Decision Date | Supersedes |
|--------|--------------|------------|
| **ACCEPTED** | 2026-02-14 | Previous path-based routing design |

## Context

This document describes the multi-tenancy architecture for the SIROS wallet platform, covering frontend URL routing, backend tenant resolution, and deployment configurations.

## Decision

Use **header-based tenant routing** (`X-Tenant-ID`) instead of path-based routing (`/t/:tenantID/...`). The JWT `tenant_id` claim is authoritative for authenticated requests.

---

# Multi-Tenancy Design Proposal

This document describes the proposed multi-tenancy architecture for the SIROS wallet platform, covering frontend URL routing, backend tenant resolution, and deployment configurations.

## Overview

The multi-tenancy design enables a single wallet frontend deployment to serve multiple tenants while routing API requests to tenant-specific (or shared) backend instances. The design prioritizes:

1. **Backward compatibility**: Existing single-tenant deployments work unchanged
2. **Deployment flexibility**: Supports shared backends, tenant-isolated backends, and hybrid models
3. **Security**: Passkey-based authentication provides the security boundary; tenant routing is convenience/isolation

## URL Structure

### Frontend Routes

| URL Pattern | Tenant ID | Notes |
|-------------|-----------|-------|
| `id.siros.org/` | `default` | Single-tenant or default tenant |
| `id.siros.org/credentials` | `default` | No `/id/` prefix → default tenant |
| `id.siros.org/id/sunet/` | `sunet` | Custom tenant |
| `id.siros.org/id/sunet/credentials` | `sunet` | Tenant-scoped page |

**Rule**: If the path begins with `/id/`, the next path component is the tenant ID. Otherwise, the tenant is `default`.

### React Router Configuration

```
/                           → default tenant, home
/id/:tenantId/*             → custom tenant routes
/credentials                → default tenant, credentials page
/id/:tenantId/credentials   → custom tenant, credentials page
```

## API Communication

### X-Tenant-ID Header

All API requests from the frontend include an `X-Tenant-ID` header:

```
GET /issuer/all HTTP/1.1
Host: api.siros.org
X-Tenant-ID: sunet
Authorization: Bearer <jwt>
```

- **No tenant in URL path**: `/id/` prefix is for frontend routing only
- **Default tenant**: `X-Tenant-ID: default`
- **Header source**: Extracted from frontend URL and stored in session

### API Path Simplification

Previous design used path-based tenant prefixing for API calls:

```
# Old approach (removed)
/t/sunet/issuer/all
```

New approach uses flat paths with header:

```
# New approach
/issuer/all  +  X-Tenant-ID: sunet
```

## Backend Tenant Resolution

### Request Flow

```
┌─────────────────────────────────────────────────────────────────────┐
│ Frontend                                                            │
│   URL: id.siros.org/id/sunet/credentials                            │
│   Tenant stored: sunet                                              │
└─────────────────────────────────────────────────────────────────────┘
                │
                │ GET /issuer/all
                │ X-Tenant-ID: sunet
                ▼
┌─────────────────────────────────────────────────────────────────────┐
│ Load Balancer (optional)                                            │
│   - Routes to tenant-specific backend if configured                 │
│   - Or passes through to shared backend                             │
└─────────────────────────────────────────────────────────────────────┘
                │
                ▼
┌─────────────────────────────────────────────────────────────────────┐
│ Backend                                                             │
│   Tenant resolution:                                                │
│   1. Authenticated: JWT tenant_id claim (authoritative)             │
│   2. Unauthenticated: X-Tenant-ID header                            │
└─────────────────────────────────────────────────────────────────────┘
```

### Tenant Resolution Priority (Backend)

| Request Type | Tenant Source | Notes |
|--------------|---------------|-------|
| Authenticated | JWT `tenant_id` claim | Signed, cannot be spoofed |
| Unauthenticated | `X-Tenant-ID` header | Used for login/register begin |

### Security Model

The `X-Tenant-ID` header can theoretically be spoofed, but this has minimal security impact:

1. **Authenticated requests**: JWT `tenant_id` is authoritative; header is ignored or validated against JWT
2. **Unauthenticated requests**: 
   - `login/begin`: Returns challenge, but attacker still needs valid passkey for that tenant
   - `login/finish`: WebAuthn assertion validated against tenant's credential store—wrong tenant = no match = auth fails
   - `register/begin`: Could register in wrong tenant (UX issue, not security breach)

**The passkey is the security boundary**: A user cannot authenticate to a tenant unless they possess a passkey registered in that tenant.

## Deployment Scenarios

### Scenario 1: Single Tenant

```
┌─────────────────┐     ┌─────────────────┐
│    Frontend     │────▶│     Backend     │
│  id.example.com │     │  api.example.com│
└─────────────────┘     └─────────────────┘
```

- No `/id/` prefix needed
- `X-Tenant-ID: default` on all requests
- Standard `VITE_WALLET_BACKEND_URL` configuration

### Scenario 2: Multi-Tenant Shared Backend

```
┌─────────────────┐     ┌─────────────────┐
│    Frontend     │────▶│  Shared Backend │
│   id.siros.org  │     │   api.siros.org │
└─────────────────┘     └─────────────────┘
        │
        ├── /id/sunet/...   → X-Tenant-ID: sunet
        ├── /id/example/... → X-Tenant-ID: example
        └── /...            → X-Tenant-ID: default
```

- Single backend serves all tenants
- Backend uses `X-Tenant-ID` header to scope database queries
- Configuration: `VITE_WALLET_BACKEND_URL=https://api.siros.org`

### Scenario 3: Multi-Tenant Isolated Backends

```
┌─────────────────┐
│    Frontend     │
│   id.siros.org  │
└────────┬────────┘
         │ X-Tenant-ID: sunet
         ▼
┌─────────────────┐
│  Load Balancer  │
│  (tenant-aware) │
└────────┬────────┘
    ┌────┴────┐
    ▼         ▼
┌───────┐ ┌────────┐
│ sunet │ │example │
│backend│ │backend │
└───────┘ └────────┘
```

- Each tenant has dedicated backend
- Load balancer routes based on `X-Tenant-ID` header
- Frontend uses single backend URL; LB handles distribution
- For more complex routing needs, see Appendix D: Pluggable Backend URL Resolver

### Scenario 4: Hybrid with Load Balancer

```
┌─────────────────┐
│    Frontend     │
│   id.siros.org  │
└────────┬────────┘
         │ X-Tenant-ID: sunet
         ▼
┌─────────────────┐     ┌─────────────────┐
│  Load Balancer  │────▶│ sunet backend   │
│  (tenant-aware) │     │ (eu-north-1)    │
└─────────────────┘     └─────────────────┘
                   └───▶┌─────────────────┐
                        │ default backend │
                        │ (us-east-1)     │
                        └─────────────────┘
```

- LB reads `X-Tenant-ID` header for routing decisions
- Can add caching, rate limiting per tenant
- Frontend uses single backend URL; LB handles distribution

## Implementation Changes

### Frontend Changes

1. **`src/api/index.ts`**: Add `X-Tenant-ID` header to all requests ✅
2. **`src/lib/tenant.ts`**: Remove `buildTenantApiPath()` path prefixing (or make it return path unchanged) ✅
3. **`src/config.ts`**: Use static `VITE_WALLET_BACKEND_URL` (load balancer handles tenant routing) ✅
4. **`src/pages/Login/Login.tsx`**: Fixed tenant discovery redirect to use `/id/:tenantId/*` route pattern ✅

### Backend Changes

1. **TenantHeaderMiddleware**: Reads `X-Tenant-ID` header for unauthenticated requests, validates tenant exists and is enabled ✅
2. **JWT**: Includes `tenant_id` claim in token generation ✅
3. **AuthMiddleware**: Validates JWT tenant exists and is enabled; logs warning if X-Tenant-ID header mismatches JWT (JWT is authoritative) ✅
4. **CORS**: Allows `X-Tenant-ID` header ✅
5. **Routes**: Removed path-based tenant prefix `/t/:tenantID/...` routes ✅

### Security Guarantees

| Request Type | Tenant Source | Validation |
|--------------|---------------|------------|
| Unauthenticated | `X-Tenant-ID` header | Validated against store (exists + enabled) |
| Authenticated | JWT `tenant_id` claim | Validated against store (exists + enabled) |

If X-Tenant-ID header is present on authenticated requests and differs from JWT tenant_id, the mismatch is logged but JWT is authoritative.

### Environment Variables

| Variable | Purpose | Example |
|----------|---------|---------|
| `VITE_WALLET_BACKEND_URL` | Backend URL (load balancer) | `https://api.siros.org` |

## Migration Path

1. **Phase 1**: Add `X-Tenant-ID` header support to frontend and backend (alongside existing behavior) ✅
2. **Phase 2**: Backend accepts both header and path-based tenant (transition period) ✅
3. **Phase 3**: Remove path-based tenant routing from backend ✅
4. **Phase 4**: Remove `buildTenantApiPath()` path modification from frontend ✅

**Status**: Core multi-tenancy implementation complete. WebSocket tenant-awareness (Appendix C) deferred.

## Open Questions

1. **Default tenant naming**: Should "default" be configurable? Some deployments may want a different name.

Answer: This is lower priority and can be dealt with at a later time.

2. **Tenant validation**: Should the backend validate that the tenant exists before processing unauthenticated requests?

Answer: Yes, the backend should validate that the tenant exists before processing unauthenticated requests.

3. **Tenant discovery**: How do users discover their tenant ID? (Assumes out-of-band communication or branded URL)

Answer: Tenant discovery is done via passkey names currently. Before the user is registered it is assumed that a branded url or out-of-band mechanism is used to send the user to id.siros.org/id/<tenant_id> - eg via a QR code. There may be a way to help user natigation by maintaining the list of tenants that the user has authenticated to in browser local storage. Such a list could be used to render a discovery page on / along-side the standard login-page for the default tenant.

4. **WebSocket connections**: How should `WS_URL` be tenant-aware?

Answer: The WebSocket URL should be derived from the backend URL rather than configured separately. This ensures consistent tenant routing:
- Take the backend URL for the tenant (e.g., `https://sunet.api.siros.org`)
- Convert protocol: `https://` → `wss://`, `http://` → `ws://`  
- Append WebSocket path: `/ws/keystore`
- Result: `wss://sunet.api.siros.org/ws/keystore`

```typescript
export const getWebSocketUrl = (tenantId: string): string => {
  const backendUrl = getBackendUrl(tenantId);
  return backendUrl
    .replace(/^https:/, 'wss:')
    .replace(/^http:/, 'ws:');
};
```

For backward compatibility, if `VITE_WS_URL` is explicitly set, use it; otherwise derive from backend URL.

---

## Appendix A: WebSocket Client Keystore

The wallet platform implements a **client-side keystore** model where cryptographic keys are held by the browser/mobile app rather than on the server. The server communicates with the client via WebSocket to request signatures when needed.

### Feature Overview

| Operation | Use Case |
|-----------|----------|
| `signJwtPresentation` | VP signing during credential presentation to verifiers |
| `generateOpenid4vciProof` | Proof of possession during credential issuance |

### Request Flow

```
┌─────────────────────────────────────────────────────────────────────┐
│ Frontend (Browser)                                                  │
│   - Holds cryptographic keys in LocalStorage                        │
│   - WebSocket connection to backend                                 │
└──────────────────────────────┬──────────────────────────────────────┘
                               │ WebSocket (persistent)
                               │ wss://api.siros.org/ws/keystore
                               ▼
┌─────────────────────────────────────────────────────────────────────┐
│ Backend                                                             │
│   - Receives external request (e.g., credential issuance)          │
│   - Needs client to sign something                                  │
│   - Sends signing request via WebSocket                             │
│   - Waits for signed response                                       │
└─────────────────────────────────────────────────────────────────────┘
```

### Implementation Status

| Component | wallet-backend-server (Node.js) | go-wallet-backend |
|-----------|--------------------------------|-------------------|
| WebSocket manager | ✅ `SocketManagerService` | ✅ `websocket.Manager` |
| Keystore service | ✅ `ClientKeystoreService` | ✅ `KeystoreService` |
| Route | ✅ `/ws/keystore` | ✅ `/ws/keystore` (tenant from JWT) |
| JWT handshake | ✅ `appToken` in first message | ✅ Same protocol |
| Sign VP | ✅ `signJwtPresentation` | ✅ `SignJwtPresentation` |
| OpenID4VCI proof | ✅ `generateOpenid4vciProof` | ✅ `GenerateOpenid4vciProof` |

### Frontend Status

The frontend has partial implementation:
- `SigningRequestHandlers.ts` - handlers for incoming signing requests
- `WS_URL` configured but **not actively used**
- WebSocket connection establishment code appears to be missing

### Multi-Tenancy Considerations

1. **WebSocket route is tenant-agnostic**: `/ws/keystore`
   - Matches HTTP API pattern (no tenant in path)
   - Tenant determined from JWT in handshake message

2. **JWT handshake includes tenant**: First message contains `appToken` (JWT)
   - JWT includes `tenant_id` claim
   - Backend validates JWT and associates connection with `userID` and `tenantID`
   - No `X-Tenant-ID` header needed—WebSocket doesn't use HTTP headers after upgrade

3. **Connection lifecycle**: 
   - When user switches tenant, WebSocket should reconnect (new JWT with different tenant)
   - Connection is per-user, per-tenant

### Protocol Details

**Handshake (Client → Server)**:
```json
{
  "appToken": "eyJhbGciOiJIUzI1NiIs..."
}
```

**Server acknowledgement (Server → Client)**:
```json
{
  "type": "FIN_INIT"
}
```

**Signing request (Server → Client)**:
```json
{
  "message_id": "uuid",
  "request": {
    "action": "signJwtPresentation",
    "nonce": "...",
    "audience": "...",
    "verifiableCredentials": [...]
  }
}
```

**Signing response (Client → Server)**:
```json
{
  "message_id": "uuid",
  "response": {
    "action": "signJwtPresentation",
    "vpjwt": "eyJhbGciOiJFUzI1NiIs..."
  }
}
```

---

## Appendix B: Splitting Authorization Server from Backend

This section analyzes the implications of splitting the current monolithic backend into two separate server binaries:

- **go-wallet-authz**: User registration and authentication (WebAuthn)
- **go-wallet-backend**: Credential storage, issuers, verifiers, wallet operations

### Current Architecture (Monolithic)

```
┌─────────────────────────────────────────────────────────────────────┐
│                        go-wallet-backend                            │
├─────────────────────────────────────────────────────────────────────┤
│  Routes:                                                            │
│    /user/register, /login, /register-webauthn-*, /login-webauthn-*  │
│    /user/session/* (account, private-data, webauthn creds)         │
│    /storage/vc/*, /storage/vp/*                                    │
│    /issuer/*, /verifier/*                                          │
│    /proxy, /helper/*, /keystore/*, /wallet-provider/*              │
├─────────────────────────────────────────────────────────────────────┤
│  Services:                                                          │
│    User, Tenant, UserTenant, WebAuthn                              │  ← AuthZ
│    Credential, Presentation, Issuer, Verifier                      │  ← Backend
│    Keystore, Proxy, Helper, WalletProvider                         │  ← Backend
├─────────────────────────────────────────────────────────────────────┤
│  Storage: Single database connection (users, credentials, tenants)  │
└─────────────────────────────────────────────────────────────────────┘
```

### Proposed Architecture (Split)

```
┌─────────────────────────────────┐     ┌─────────────────────────────────┐
│        go-wallet-authz         │     │        go-wallet-backend        │
├─────────────────────────────────┤     ├─────────────────────────────────┤
│  Routes:                        │     │  Routes:                        │
│    /user/register               │     │    /user/session/account-info   │
│    /user/login                  │     │    /user/session/settings       │
│    /user/register-webauthn-*    │     │    /user/session/private-data   │
│    /user/login-webauthn-*       │     │    /storage/vc/*, /storage/vp/* │
│                                 │     │    /issuer/*, /verifier/*       │
│                                 │     │    /proxy, /helper/*, etc.      │
├─────────────────────────────────┤     ├─────────────────────────────────┤
│  Services:                      │     │  Services:                      │
│    User, Tenant, UserTenant     │     │    Credential, Presentation     │
│    WebAuthn                     │     │    Issuer, Verifier, Keystore   │
│                                 │     │    Proxy, Helper, WalletProvider│
├─────────────────────────────────┤     ├─────────────────────────────────┤
│  Storage: authz DB              │     │  Storage: backend DB            │
│    - users, tenants             │     │    - credentials, presentations │
│    - webauthn_credentials       │     │    - issuers, verifiers         │
│    - user_tenants               │     │    - (user_id reference only)   │
└─────────────────────────────────┘     └─────────────────────────────────┘
           │                                          │
           │  Issues JWT with:                        │  Validates JWT:
           │    user_id, tenant_id                    │    user_id, tenant_id
           └──────────────────────────────────────────┘
```

### Assumptions Required for Split

**1. Stateless Authentication via JWT**

The split works because authentication is already stateless:
- AuthZ issues a signed JWT containing `user_id` and `tenant_id`
- Backend validates JWT signature using shared secret or public key
- No session state needs to be shared between services

```go
// JWT claims (already implemented)
type Claims struct {
    UserID   string `json:"user_id"`
    TenantID string `json:"tenant_id"`
    jwt.RegisteredClaims
}
```

**Assumption**: JWT secret/keypair must be shared or use asymmetric keys (AuthZ signs with private key, Backend validates with public key).

**2. User ID as Foreign Key Only**

Backend references users by UUID only. It doesn't need to query user details:
- Credentials are owned by `user_id` (UUID)
- No need to JOIN with users table for normal operations
- User display name comes from frontend/JWT, not from backend lookup

**Assumption**: Backend never needs to look up user details beyond the ID in the JWT.

**3. Tenant Configuration Consistency**

Both services need tenant information:
- **AuthZ**: WebAuthn RP ID, allowed origins, user limits
- **Backend**: Issuer/verifier lists, storage quotas

**Assumption**: Either:
- A) Shared database with tenant table (read-only from Backend)
- B) Configuration sync mechanism (API, config files, or tenant service)
- C) Tenant config embedded in JWT claims (bloats token)

**4. WebAuthn Credential Management Split**

Currently, authenticated users can manage their WebAuthn credentials:
- `POST /user/session/webauthn/register-begin` - Add new credential
- `POST /user/session/webauthn/credential/:id/delete` - Delete credential

**Options**:
- A) Keep credential management in AuthZ, frontend calls AuthZ directly
- B) Backend proxies to AuthZ for credential management
- C) Move to a separate "account management" service

**5. Private Data Storage**

Currently `/user/session/private-data` is in the Backend (encrypted keystore data).

**Decision needed**: Is private data:
- A) Part of authentication (goes with AuthZ) - it's user account data
- B) Part of wallet storage (stays with Backend) - it's encrypted blob storage

### Benefits of Splitting

| Benefit | Description |
|---------|-------------|
| **Independent scaling** | AuthZ handles bursty login traffic; Backend handles steady CRUD operations |
| **Security isolation** | AuthZ handles sensitive WebAuthn operations; can be hardened separately |
| **Deployment flexibility** | Run AuthZ as shared service, Backend per-tenant |
| **Technology choice** | Could rewrite AuthZ in different language if needed |
| **Compliance** | AuthZ can be in different security zone (PCI-DSS, SOC2) |
| **Caching** | Backend responses are more cacheable (no session state) |
| **Simpler services** | Each service has a clearer, smaller scope |

### Drawbacks of Splitting

| Drawback | Description |
|----------|-------------|
| **Operational complexity** | Two services to deploy, monitor, upgrade |
| **Shared secret management** | JWT keys must be distributed securely |
| **Tenant sync** | Tenant configuration must be consistent across services |
| **Cross-service debugging** | Request tracing across service boundary |
| **WebAuthn credential management** | Authenticated user operations span both services |
| **Database migrations** | Schema changes may need coordination |
| **Latency** | Additional network hops if services communicate |

### Implementation Approach

If pursuing the split:

**Phase 1: Prepare for Split**
1. Ensure JWT contains all needed claims (`user_id`, `tenant_id`)
2. Remove any direct user table queries from Backend handlers
3. Define clear service boundaries for each handler

**Phase 2: Extract Shared Code**
1. Create `go-wallet-common` package with:
   - JWT validation
   - Middleware (tenant, auth)
   - Domain types (TenantID, UserID)
2. Both services depend on common package

**Phase 3: Split Binary**
1. Create `cmd/authz/main.go` with auth routes only
2. Modify `cmd/server/main.go` to exclude auth routes
3. Configure separate database connections (or shared with separate schemas)

**Phase 4: Deployment**
1. Deploy both services
2. Configure frontend to call each service for appropriate routes
3. Or: Use API gateway to route `/user/register*`, `/user/login*` to AuthZ

### Route Mapping

| Route | Current | Split |
|-------|---------|-------|
| `POST /user/register` | Backend | **AuthZ** |
| `POST /user/login` | Backend | **AuthZ** |
| `POST /user/*-webauthn-*` | Backend | **AuthZ** |
| `GET /user/session/account-info` | Backend | Backend or **AuthZ** |
| `POST /user/session/settings` | Backend | Backend |
| `*/user/session/private-data` | Backend | Backend |
| `*/user/session/webauthn/*` | Backend | **AuthZ** |
| `DELETE /user/session` | Backend | **Both** (delete user + data) |
| `/storage/*` | Backend | Backend |
| `/issuer/*`, `/verifier/*` | Backend | Backend |

### Recommendation

**Start with the header-based multi-tenancy first**, then evaluate the split:

1. The multi-tenancy design works regardless of monolith vs split
2. Header-based tenant routing (`X-Tenant-ID`) enables the split later:
   - AuthZ sets tenant in JWT
   - Backend reads tenant from JWT
   - No path-based coupling between services
3. Once multi-tenancy is stable, the split becomes a deployment choice rather than an architectural change

**When to split**:
- When authentication traffic patterns differ significantly from storage traffic
- When security requirements mandate separate deployments
- When different teams own authentication vs wallet functionality

---

## Appendix C: Frontend WebSocket Implementation

This appendix documents the requirements for fully implementing WebSocket client keystore functionality in the frontend.

### Current State

| Component | Status | Location |
|-----------|--------|----------|
| Type definitions | ✅ Complete | [shared.types.ts](../../wallet-frontend/src/types/shared.types.ts) |
| Signing handlers | ✅ Complete | [SigningRequestHandlers.ts](../../wallet-frontend/src/services/SigningRequestHandlers.ts) |
| `WS_URL` config | ✅ Defined | [config.ts](../../wallet-frontend/src/config.ts) |
| `appToken` storage | ✅ Stored | SessionStorage via `useSessionStorage` |
| WebSocket connection | ❌ Missing | Needs to be implemented |
| Connection lifecycle | ❌ Missing | Connect on login, disconnect on logout/tenant switch |
| Message routing | ❌ Missing | Dispatch incoming requests to handlers |
| Reconnection logic | ❌ Missing | Handle disconnects and reconnect |

### Required Implementation

#### 1. WebSocket Service (`src/services/WebSocketService.ts`)

Create a new service that manages the WebSocket connection:

```typescript
import { WS_URL } from '../config';
import { ServerSocketMessage, SignatureAction } from '../types/shared.types';
import { SigningRequestHandlerService } from './SigningRequestHandlers';
import { LocalStorageKeystore } from './LocalStorageKeystore';
import { BackendApi } from '../api';

export interface WebSocketServiceOptions {
  api: BackendApi;
  keystore: LocalStorageKeystore;
  appToken: string;
  tenantId: string;
  onDisconnect?: () => void;
}

export class WebSocketService {
  private socket: WebSocket | null = null;
  private options: WebSocketServiceOptions;
  private handlers = SigningRequestHandlerService();
  private reconnectAttempts = 0;
  private maxReconnectAttempts = 5;
  private reconnectDelay = 1000; // ms, doubles each attempt

  constructor(options: WebSocketServiceOptions) {
    this.options = options;
  }

  connect(): Promise<void> {
    return new Promise((resolve, reject) => {
      const wsUrl = this.buildWebSocketUrl();
      this.socket = new WebSocket(wsUrl);

      this.socket.onopen = () => {
        // Send handshake with appToken
        this.socket!.send(JSON.stringify({ appToken: this.options.appToken }));
      };

      this.socket.onmessage = (event) => {
        this.handleMessage(event);
        // Resolve after FIN_INIT is received
        try {
          const msg = JSON.parse(event.data);
          if (msg.type === 'FIN_INIT') {
            this.reconnectAttempts = 0;
            resolve();
          }
        } catch { /* ignore parse errors for non-JSON */ }
      };

      this.socket.onerror = (error) => {
        console.error('WebSocket error:', error);
        reject(error);
      };

      this.socket.onclose = () => {
        console.log('WebSocket closed');
        this.handleDisconnect();
      };
    });
  }

  private buildWebSocketUrl(): string {
    // Use configured WS_URL or derive from backend URL
    if (WS_URL) {
      return `${WS_URL}/ws/keystore`;
    }
    // Derive from BACKEND_URL (implemented in getWebSocketUrl)
    const backendUrl = this.options.api.getBackendUrl();
    return backendUrl
      .replace(/^https:/, 'wss:')
      .replace(/^http:/, 'ws:')
      + '/ws/keystore';
  }

  private handleMessage(event: MessageEvent): void {
    try {
      const msg = JSON.parse(event.data);
      
      // Handle control messages
      if (msg.type === 'FIN_INIT') {
        console.log('WebSocket handshake complete');
        return;
      }

      // Handle signing requests
      if (msg.request) {
        this.handleSigningRequest(msg as ServerSocketMessage);
      }
    } catch (e) {
      console.error('Failed to parse WebSocket message:', e);
    }
  }

  private async handleSigningRequest(msg: ServerSocketMessage): Promise<void> {
    const { api, keystore } = this.options;
    const { message_id, request } = msg;

    switch (request.action) {
      case SignatureAction.signJwtPresentation:
        await this.handlers.handleSignJwtPresentation(
          this.socket!,
          keystore,
          {
            message_id,
            audience: request.audience,
            nonce: request.nonce,
            verifiableCredentials: request.verifiableCredentials || []
          }
        );
        break;

      case SignatureAction.generateOpenid4vciProof:
        await this.handlers.handleGenerateOpenid4vciProofSigningRequest(
          api,
          this.socket!,
          keystore,
          {
            message_id,
            audience: request.audience,
            nonce: request.nonce,
            issuer: '' // Extract from request if available
          }
        );
        break;

      default:
        console.warn('Unknown signing action:', request.action);
    }
  }

  private handleDisconnect(): void {
    this.socket = null;
    
    if (this.options.onDisconnect) {
      this.options.onDisconnect();
    }

    // Attempt reconnection with exponential backoff
    if (this.reconnectAttempts < this.maxReconnectAttempts) {
      const delay = this.reconnectDelay * Math.pow(2, this.reconnectAttempts);
      this.reconnectAttempts++;
      console.log(`Reconnecting in ${delay}ms (attempt ${this.reconnectAttempts})`);
      setTimeout(() => this.connect().catch(console.error), delay);
    }
  }

  disconnect(): void {
    this.reconnectAttempts = this.maxReconnectAttempts; // Prevent reconnection
    if (this.socket) {
      this.socket.close();
      this.socket = null;
    }
  }

  isConnected(): boolean {
    return this.socket?.readyState === WebSocket.OPEN;
  }
}
```

#### 2. Integration with SessionContext

Modify `SessionContextProvider.tsx` to manage WebSocket lifecycle:

```typescript
// Add to SessionContextProvider.tsx

import { WebSocketService } from '../services/WebSocketService';

// Inside SessionContextProvider:
const [wsService, setWsService] = useState<WebSocketService | null>(null);

// Connect WebSocket when logged in
useEffect(() => {
  if (isLoggedIn && appToken && !wsService) {
    const service = new WebSocketService({
      api,
      keystore,
      appToken,
      tenantId: getCurrentTenantId(), // From tenant context/hook
      onDisconnect: () => {
        console.log('WebSocket disconnected');
        // Optionally show notification to user
      }
    });
    
    service.connect()
      .then(() => {
        console.log('WebSocket connected');
        setWsService(service);
      })
      .catch((err) => {
        console.error('WebSocket connection failed:', err);
      });
  }
  
  return () => {
    if (wsService) {
      wsService.disconnect();
      setWsService(null);
    }
  };
}, [isLoggedIn, appToken, api, keystore]);

// Disconnect on logout
const logout = useCallback(async () => {
  if (wsService) {
    wsService.disconnect();
    setWsService(null);
  }
  await keystore.close();
}, [keystore, wsService]);
```

#### 3. Extend Type Definitions

Update `shared.types.ts` to include issuer for OpenID4VCI:

```typescript
export type WalletKeystoreRequest = (
  { 
    action: SignatureAction.generateOpenid4vciProof; 
    nonce: string; 
    audience: string;
    issuer?: string;  // Add issuer field
  }
  | { 
    action: SignatureAction.signJwtPresentation; 
    nonce: string; 
    audience: string; 
    verifiableCredentials: any[];
  }
);
```

#### 4. Update Configuration

Add tenant-aware WebSocket URL derivation to `config.ts`:

```typescript
// config.ts additions

export const getWebSocketUrl = (tenantId: string): string => {
  // If explicit WS_URL is set, use it
  if (WS_URL) {
    return WS_URL;
  }
  
  // Derive from backend URL
  const backendUrl = getBackendUrl(tenantId);
  return backendUrl
    .replace(/^https:/, 'wss:')
    .replace(/^http:/, 'ws:');
};
```

### Multi-Tenancy Considerations

1. **Connection per tenant**: When user switches tenant, the WebSocket must reconnect with new JWT:
   - Old connection uses JWT with old `tenant_id`
   - Backend associates connection with `(userID, tenantID)` from JWT
   - Switching tenant requires new JWT → new connection

2. **Reconnection on tenant switch**: Add to tenant switching logic:
   ```typescript
   const switchTenant = async (newTenantId: string) => {
     // Disconnect existing WebSocket
     wsService?.disconnect();
     
     // Re-login to get new JWT with new tenant_id
     await api.loginWebauthn(keystore, ...);
     
     // New WebSocket connection will be established by SessionContext effect
   };
   ```

3. **JWT refresh**: If JWT expires, WebSocket connection may be rejected:
   - Backend should send error message before closing
   - Frontend should detect and trigger re-authentication

### Testing Requirements

| Test Case | Description |
|-----------|-------------|
| Connection establishment | Connect, send handshake, receive FIN_INIT |
| VP signing | Receive signJwtPresentation request, respond with vpjwt |
| OpenID4VCI proof | Receive generateOpenid4vciProof request, respond with proof_jwt |
| Reconnection | Disconnect server-side, verify client reconnects |
| Logout cleanup | Verify WebSocket closes on logout |
| Tenant switch | Verify reconnection with new JWT on tenant switch |
| Error handling | Invalid JWT, network failure, malformed messages |

### Implementation Priority

1. **Phase 1**: Basic connection + handshake
   - Create `WebSocketService.ts`
   - Add connection logic to `SessionContextProvider`
   - Test with manual backend requests

2. **Phase 2**: Message handling
   - Wire up `SigningRequestHandlers` to incoming messages
   - Test VP signing flow end-to-end

3. **Phase 3**: Robustness
   - Add reconnection logic with exponential backoff
   - Handle edge cases (network loss, JWT expiry)
   - Add connection status indicator to UI

4. **Phase 4**: Multi-tenancy
   - Integrate with tenant switching logic
   - Test cross-tenant scenarios

---

## Appendix D: Pluggable Backend URL Resolver

For advanced deployments where frontend-side routing is preferred over load balancer routing, a pluggable backend URL resolver can be implemented. This is NOT required for the first iteration—a load balancer reading the `X-Tenant-ID` header is simpler and sufficient.

### When to Consider This

- Client-side routing to geographically distributed backends
- Complex routing logic that can't be expressed in load balancer rules
- Deployments without a tenant-aware load balancer

### Resolution Priority

1. **Runtime JS hook** (most flexible): `window.__walletConfig.getBackendUrl(tenantId)`
2. **Environment template**: `VITE_BACKEND_URL_TEMPLATE=https://${tenantId}.api.siros.org`
3. **Static URL** (default, backward compatible): `VITE_WALLET_BACKEND_URL`

### TypeScript Interface

```typescript
// src/config.ts

export type BackendUrlResolver = (tenantId: string) => string;

// Global hook for runtime configuration
declare global {
  interface Window {
    __walletConfig?: {
      getBackendUrl?: BackendUrlResolver;
    };
  }
}

// Resolver implementation
export const getBackendUrl: BackendUrlResolver = (tenantId: string) => {
  // 1. Runtime JS hook
  if (window.__walletConfig?.getBackendUrl) {
    return window.__walletConfig.getBackendUrl(tenantId);
  }
  
  // 2. Template from environment
  if (import.meta.env.VITE_BACKEND_URL_TEMPLATE) {
    return import.meta.env.VITE_BACKEND_URL_TEMPLATE.replace('${tenantId}', tenantId);
  }
  
  // 3. Static URL (backward compatible)
  return import.meta.env.VITE_WALLET_BACKEND_URL || 'http://localhost:8080';
};
```

### Configuration Examples

#### Template-Based Multi-Tenant

```bash
# .env
VITE_BACKEND_URL_TEMPLATE=https://${tenantId}.api.siros.org
```

- `default` → `https://default.api.siros.org`
- `sunet` → `https://sunet.api.siros.org`

#### Custom JS Hook

```html
<!-- index.html or external /config.js -->
<script>
  window.__walletConfig = {
    getBackendUrl: (tenantId) => {
      // Region-aware routing
      const region = detectUserRegion();
      if (tenantId === 'default') {
        return `https://api.${region}.siros.org`;
      }
      return `https://${tenantId}.api.${region}.siros.org`;
    }
  };
</script>
```

#### External Configuration File

```html
<!-- index.html -->
<script src="/config.js"></script>
```

```javascript
// /config.js (served by deployer, can be updated without rebuild)
window.__walletConfig = {
  getBackendUrl: (tenantId) => {
    const backends = {
      'default': 'https://api.siros.org',
      'sunet': 'https://sunet.backend.eu-north-1.siros.org',
      'example': 'https://example.backend.us-east-1.siros.org',
    };
    return backends[tenantId] || backends['default'];
  }
};
```

## References

- [Wallet Frontend PR #993](https://github.com/wwWallet/wallet-frontend/pull/993) - Multi-tenancy support
- go-wallet-backend `feature/tenant-aware-routing` branch - Path-based implementation (to be adapted)
