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

## Strategy: Purpose-Specific APIs

The goal is to move traffic from the generic proxy to purpose-specific backend APIs:

| Current Mechanism | Purpose-Specific API | Status |
|-------------------|---------------------|--------|
| VCT metadata via proxy | **VCT Registry** (`/type-metadata`) | ✅ PR #22 |
| Images/SVG in VCTM | **Embedded in VCTM** (data: URIs) | ✅ PR #22 |
| Issuer metadata via proxy | **Discovery/Trust API** (with go-trust) | ⏳ api-versioning-discovery-trust |
| Issuer logos/images | **Embedded in issuer metadata** | ⏳ api-versioning-discovery-trust |
| OHTTP gateway keys | Already separate endpoint | ✅ Complete |
| Credential offer URIs | Still needs proxy (arbitrary URLs) | — No change |
| mDOC IACAs | Could embed in discovery/trust | ⏳ Future |

## Benefits of Purpose-Specific APIs

1. **Caching**: Backend can implement intelligent caching strategies
2. **Validation**: Backend can validate and sanitize responses
3. **Trust**: Backend can verify signatures and trust chains
4. **Privacy**: Reduces frontend fingerprinting via request patterns
5. **Performance**: Backend can batch and prefetch related resources
6. **Security**: Reduces SSRF attack surface by limiting proxy scope

## VCT Registry Image Embedding

The VCT Registry server embeds image URLs as data: URIs to eliminate recursive fetching:

### Images Embedded

From VCTM documents:
- `display[].logo.uri`
- `display[].background_image.uri`
- `rendering.svg_templates[].uri` (SVG content)

### Reusability for Discovery/Trust API

The `ImageEmbedder` implementation (`internal/registry/image_embed.go`) is designed to be
reusable. When implementing issuer metadata image embedding in the discovery/trust work:

1. Move `ImageEmbedder` to a shared package (e.g., `internal/embed/`)
2. Import from both registry and discovery/trust handlers
3. Same pattern: parse JSON → find image URLs → fetch → embed as data: URIs

The key difference is that discovery/trust will additionally call go-trust for certificate
chain validation on `signed_metadata` JWTs before embedding images.
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

1. **Asset Registry**: Dedicated endpoint for logos, backgrounds, and SVGs
2. **Trust Evaluation**: Integrate image sources with trust framework
3. **Content Verification**: Verify integrity of embedded images
4. **Size Limits**: Enforce maximum image sizes to prevent abuse

## Next Targets for Proxy Elimination

### Priority 1: Issuer Metadata Images (High Impact)

**Current flow**: When displaying credentials from OpenID4VCI issuers, the frontend fetches
logo and background images via the proxy from URLs in `credential_issuer` metadata.

**Solution**: Add issuer metadata endpoint to the Discovery/Trust API (api-versioning-discovery-trust branch).
This endpoint would:
1. Fetch and cache issuer metadata from `/.well-known/openid-credential-issuer`
2. Validate `signed_metadata` JWTs using go-trust for certificate chain verification
3. Embed images using the same `ImageEmbedder` pattern from the VCTM registry
4. Return pre-validated, image-embedded metadata to frontends

**Architectural note**: This belongs in the discovery/trust work rather than the VCTM registry
because it requires trust validation (go-trust integration) which VCTM does not need.

**Files affected**:
- `wallet-frontend/src/lib/services/OpenID4VCIHelper.ts` - `getCredentialIssuerMetadata()`
- `wallet-common/src/functions/openID4VCICredentialRendering.ts`

**Estimated reduction**: ~60% of remaining proxy image traffic

### Priority 2: mDOC IACAs (Medium Impact)

**Current flow**: mDOC credentials include `mdoc_iacas_uri` pointing to issuer authority
certificate authorities. These are fetched via proxy each time.

**Solution**: Add IACA caching to the registry or Discover & Trust service. IACAs change
rarely and can be cached aggressively.

**Files affected**:
- `wallet-common/src/functions/OpenID4VCIHelper.ts` - IACA fetch logic

**Estimated reduction**: ~10% of proxy traffic (infrequent but predictable)

### Priority 3: JWT-VC Issuer Metadata (Medium Impact)

**Current flow**: For JWT-VC credentials without `vct`, the frontend fetches
`/.well-known/jwt-vc-issuer` from the issuer origin.

**Solution**: Route through Discover & Trust with caching. The metadata is static and
benefits from trust evaluation.

**Files affected**:
- `wallet-common/src/functions/getSdJwtVcMetadata.ts` - `getJwtVcMetadata()`

### Priority 4: Authorization Server Metadata (Lower Priority)

**Current flow**: OAuth AS metadata is fetched during credential issuance flow.

**Solution**: Already targeted by Discover & Trust PR #995. Caching here helps issuance
flow performance.

### Remaining Proxy Uses (Cannot Eliminate)

These will continue to require the generic proxy:

1. **Credential Offer URIs**: Arbitrary URLs from QR codes cannot be pre-cached
2. **Dynamic external resources**: URLs not known until presentation time
3. **One-time URLs**: Token endpoints, redirect URIs, etc.

## Proxy Traffic Reduction Summary

| Phase | Component | Traffic Reduction |
|-------|-----------|-------------------|
| ✅ Done | VCTM image embedding (PR #22) | ~25% |
| ⏳ Next | Discovery/Trust API with go-trust | ~50% |
|        | - Issuer metadata + image embedding | |
|        | - Authorization server metadata | |
|        | - JWT-VC issuer metadata | |
| ⏳ Future | mDOC IACAs | ~10% |
| — | Irreducible (dynamic URLs) | ~15% |

Total estimated proxy traffic reduction: **~85%**
