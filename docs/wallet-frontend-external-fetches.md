# Wallet Frontend External Resource Fetches

This document analyzes all external static resource fetches initiated by wallet-frontend,
identifying opportunities to route traffic through purpose-specific backend APIs rather
than the generic proxy endpoint.

## Current Architecture

The wallet-frontend fetches external resources via two mechanisms:

1. **httpProxy** - Routes requests through backend `/proxy` endpoint or OHTTP relay
2. **Direct axios/fetch** - Bypasses proxy for certain operations

## External Resource Categories

### 1. OpenID4VCI Metadata (via httpProxy → backend `/proxy`)

| Resource | URL Pattern | Source |
|----------|-------------|--------|
| Credential Issuer Metadata | `{issuer}/.well-known/openid-credential-issuer` | OpenID4VCIHelper.ts |
| Authorization Server Metadata | `{authz-server}/.well-known/oauth-authorization-server` | OpenID4VCIHelper.ts |
| OpenID Configuration (fallback) | `{issuer}/.well-known/openid-configuration` | OpenID4VCIHelper.ts |
| Credential Offer URI | arbitrary URL from QR code | OpenID4VCI.ts |
| mDOC IACAs | `{mdoc_iacas_uri}` from metadata | OpenID4VCIHelper.ts |
| Logo images | `{logo.uri}` from issuer/credential display | OpenID4VCIHelper.ts |

### 2. VCT Type Metadata

| Resource | URL Pattern | Source |
|----------|-------------|--------|
| VCT Metadata (registry) | `{VCT_REGISTRY_URL}?vct=<vct>` | initializeCredentialEngine.ts |
| VCT Metadata (direct) | `{vct}` when vct is HTTP URL | wallet-common/getSdJwtVcMetadata.ts |
| VCT extends chain | `{extends}` URL from parent metadata | wallet-common/getSdJwtVcMetadata.ts |
| JWT-VC Issuer metadata | `{iss-origin}/.well-known/jwt-vc-issuer` | wallet-common/getSdJwtVcMetadata.ts |

### 3. Credential Rendering

| Resource | URL Pattern | Source |
|----------|-------------|--------|
| SVG Templates | `{rendering.svg_templates[0].uri}` | wallet-common/SDJWTVCParser.ts |
| Background Images | `{background_image.uri}` | wallet-common/openID4VCICredentialRendering.ts |
| Logo Images | `{logo.uri}` | wallet-common/openID4VCICredentialRendering.ts |

### 4. OHTTP (direct - bypasses proxy)

| Resource | URL Pattern | Source |
|----------|-------------|--------|
| Gateway Keys | `{gatewayKeysUrl}` (`application/ohttp-keys`) | ohttpHelpers.ts |
| Relay Requests | `{relayUrl}` (`message/ohttp-req`) | ohttpHelpers.ts |

### 5. Backend API Calls (direct to backend)

| Resource | URL Pattern | Source |
|----------|-------------|--------|
| Backend Status | `{BACKEND_URL}/status` | StatusContextProvider.tsx |
| Backend API | `{BACKEND_URL}/api/*` | Various |

## Strategy: Purpose-Specific APIs via Hybrid Binary

The wallet backend is built as a **hybrid binary** with multiple operating modes.
Each mode serves specific purposes, replacing the generic proxy:

### Operating Modes

```bash
go-wallet --mode=<mode>

Modes:
  all       Development: all services in one process
  engine    WebSocket protocol flows (OID4VCI, OID4VP)
  registry  VCTM and issuer metadata with image embedding
  auth      User authentication (WebAuthn, OAuth)
  storage   Encrypted credential storage
  backend   Admin API, background workers
```

### Traffic Routing

| Current Mechanism | Target Service | Mode | Status |
|-------------------|---------------|------|--------|
| VCT metadata via proxy | `GET /type-metadata` | registry | ✅ Complete |
| Images/SVG in VCTM | Embedded by registry | registry | ✅ Complete |
| Issuer metadata via proxy | `GET /issuer-metadata` | registry | ✅ Complete |
| OID4VCI flows via proxy | WebSocket `/api/v2/wallet` | engine | 📋 Designed |
| OID4VP flows via proxy | WebSocket `/api/v2/wallet` | engine | 📋 Designed |
| OHTTP gateway keys | Direct fetch (unchanged) | — | ✅ N/A |
| Login/Registration | `POST /auth/*` | auth | ✅ Current |
| Credential storage | `PUT /storage/*` | storage | ✅ Current |

### Privacy: Client-Side Credential Matching

The engine does NOT have access to the user's credential store. During OID4VP:

1. Engine sends `presentation_definition` to client via WebSocket
2. Client matches credentials locally (never sends full inventory)
3. Client returns only matched credential IDs
4. Engine requests signature for selected credentials only

See `websocket-protocol-spec.md` for the `match_credentials` protocol step.

### Native App: Local Engine Privacy

Native apps can embed the engine locally. In this mode:
- All OID4VCI/OID4VP flows happen on-device
- Cloud services only see login and encrypted storage
- Issuers/verifiers never know user's cloud identity

## Benefits of Purpose-Specific APIs

1. **Caching**: Registry can cache VCTM and issuer metadata
2. **Validation**: Engine validates all protocol messages
3. **Trust**: Registry/Engine integrate with go-trust via AuthZEN
4. **Privacy**: Client-side matching; local engine option
5. **Performance**: WebSocket eliminates round-trips
6. **Security**: No arbitrary URL fetching; SSRF mitigations built-in

## VCT Registry Image Embedding

The VCT Registry server (`--mode=registry`) embeds image URLs as data: URIs to
eliminate recursive fetching:

### Images Embedded

From VCTM documents:
- `display[].logo.uri`
- `display[].background_image.uri`
- `rendering.svg_templates[].uri` (SVG content)

### Reusability Across Services

The `ImageEmbedder` implementation (`internal/embed/image.go`) is designed as a
standalone package that can be imported by multiple modes:

1. **Registry mode** (`internal/modes/registry/`) - VCTM and issuer metadata
2. **Engine mode** (`internal/modes/engine/`) - During OID4VCI flows

The package supports customization via functional options:
- `WithExtractor(func)` - custom URL extraction logic
- `WithReplacer(func)` - custom URL replacement logic
- `WithHTTPClient(client)` - custom HTTP client

Same pattern: parse JSON → find image URLs → fetch → embed as data: URIs

The key difference for discovery/trust will be that it additionally calls go-trust
for certificate chain validation on `signed_metadata` JWTs before embedding images.
- `rendering.simple.logo.uri`
- `rendering.simple.background_image.uri`

### Implementation

The registry fetches images during VCTM retrieval and converts them to base64 data: URIs
before returning the VCTM to clients. This eliminates:

1. Secondary fetch requests from the frontend
2. CORS issues with image resources
3. Privacy leakage from image request timing

### Supported Image Types

- PNG (`image/png`)
- JPEG (`image/jpeg`)
- GIF (`image/gif`)
- WebP (`image/webp`)
- SVG (`image/svg+xml`)
- ICO (`image/x-icon`)

## Future Work

1. **Size Limits**: Enforce maximum image sizes to prevent abuse
2. **Content Verification**: Verify integrity of embedded images
3. **Offline Support**: Cache VCTM and issuer metadata for offline display

## WebSocket Engine: Complete Proxy Elimination

### How the Engine Eliminates Proxy Usage

All remaining proxy traffic is eliminated by the WebSocket engine (`--mode=engine`).
The engine handles protocol flows internally, making external HTTP requests on behalf
of the client while applying SSRF protections and trust validation.

| Current Proxy Usage | Engine Solution |
|--------------------|-----------------| 
| Issuer metadata fetch | Engine fetches during `oid4vci` flow |
| Issuer logo images | Embedded in `metadata_fetched` step |
| Token endpoint calls | Engine calls during flow |
| Credential endpoint calls | Engine calls during flow |
| Authorization server metadata | Engine fetches during flow |
| credential_offer_uri fetch | Engine validates and fetches |
| mDOC IACAs | Engine fetches and caches |
| Verifier metadata | Engine fetches during `oid4vp` flow |
| VP response submission | Engine submits during flow |

### Protocol-Aware Request Handling

Unlike the generic proxy, the engine:

1. **Validates URLs** - Only fetches from protocol-defined paths:
   - `/.well-known/openid-credential-issuer`
   - `/.well-known/oauth-authorization-server`
   - Endpoints declared in fetched metadata

2. **Blocks SSRF** - Rejects requests to:
   - Private IP ranges (10.x, 172.16-31.x, 192.168.x)
   - Localhost and link-local addresses
   - Cloud metadata endpoints

3. **Validates responses** - All fetched content validated against schemas

4. **Embeds images** - Logo and background images converted to data: URIs

5. **Evaluates trust** - Calls go-trust (AuthZEN) for issuer/verifier validation

### Proxy Traffic Reduction Summary

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         PROXY ELIMINATION PROGRESS                          │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  Current State (all via /proxy):                                            │
│  ██████████████████████████████████████████████████████████████ 100%       │
│                                                                             │
│  After Registry Mode (--mode=registry):                                     │
│  ░░░░░░░░░░░░░░░░██████████████████████████████████████████████ 75%        │
│  ^^^^^^^^^^^^^^^^^                                                          │
│  VCTM + issuer-metadata (25%)                                               │
│                                                                             │
│  After Engine Mode (--mode=engine):                                         │
│  ░░░░░░░░░░░░░░░░░▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓ 0%         │
│  ^ Registry (25%)  ^ Engine handles all flows (75%)                         │
│                                                                             │
│  Legend: █ = Proxy  ░ = Registry  ▓ = Engine                                │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Remaining Proxy: Emergency Fallback Only

After engine adoption, the `/proxy` endpoint can be:
1. Rate-limited severely
2. Logged for analysis
3. Eventually disabled

Keep for:
- Legacy frontend versions during migration
- Debug/development scenarios
- Non-conformant implementations (rare)

## Related Documents

| Document | Purpose |
|----------|---------|
| `proxy-elimination-plan.md` | Implementation plan, hybrid binary architecture |
| `websocket-protocol-spec.md` | WebSocket protocol, message formats, flow definitions |
| `frontend-websocket-integration.md` | Frontend transport abstraction |
