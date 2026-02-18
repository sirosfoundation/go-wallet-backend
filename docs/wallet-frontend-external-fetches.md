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
| VCT metadata via proxy | **VCT Registry** (`/type-metadata`) | PR #22 |
| `.well-known/*` via proxy | **Discover & Trust** (`/api/discover-and-trust`) | PR #995 |
| Images/SVG via proxy | **Embedded in VCTM** | This PR |
| OHTTP gateway keys | Already separate | Done |

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
