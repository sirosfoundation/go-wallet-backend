# Client ID Strategy for SIROS Wallet

## Status

Proposed — July 2026

## Summary

This document describes how client identifiers (`client_id`) are used across the
SIROS wallet ecosystem for both verifier (OID4VP) and issuer (OID4VCI) interactions,
and proposes a plan to eliminate dynamic/pre-registered client IDs in favor of
attestation-rooted identity.

---

## Current State

### Verifier → Wallet (OID4VP)

| Scheme | Mechanism | Implementation Status |
|--------|-----------|----------------------|
| `x509_san_dns:hostname` | JAR signed with X.509 cert; SAN must match | **Fully implemented** (go-wallet-backend + go-trust ETSI registry) |
| `x509_san_uri:uri` | JAR signed with X.509 cert; URI SAN must match | Parsed, partially validated |
| `x509_hash` | SHA-256 of leaf cert | Supported in wallet-common generation |
| `did:web:*` / `did:webvh:*` | DID document resolution; JWT verified against DID keys | Scheme inferred; resolution delegated to go-trust `didweb` registry |
| `verifier_attestation` | Third-party attestation JWT | Parsed in scheme inference; **not validated end-to-end** |
| `https://url` | URL-based (unsigned DC API fallback) | Works; no strong trust binding |
| `pre-registered` | Admin whitelist fallback | Catch-all in `parseClientIdScheme` |

**Trust evaluation path**: go-wallet-backend extracts key material → sends
`TrustEvaluationRequest` to frontend → frontend calls AuthZEN PDP (`/v1/evaluate`)
→ go-trust validates against registries (ETSI TSL, LoTE, did:web, OIDF).

Note: OpenID Federation is a **trust evaluation mechanism** within go-trust, not
a separate `client_id_scheme`. A verifier using `x509_san_dns` can be validated
via OIDF trust chains if its certificate issuer is discoverable through
federation. The `client_id_scheme` determines how identity is presented on the
wire; OIDF determines how trust in that identity is evaluated.

### Issuer → Wallet (OID4VCI)

| Scenario | `client_id` value | Auth method |
|----------|------------------|-------------|
| Admin-registered issuer | Static `CredentialIssuer.ClientID` | `private_key_jwt` (if `ClientJWK` set) |
| Unregistered issuer | `redirect_uri` (OID4VCI §7.1 convention) | Public client |
| Credential proof binding | N/A — wallet-provider key attestation | `attestation` proof type JWT |

DPoP (RFC 9449) is always used. The `attestation` proof type is preferred when
the issuer supports it (per `openid4vciProofTypePrecedence`).

**In progress**: A PR on go-wallet-backend implements full WIA (Wallet Instance
Attestation) + KA (Key Attestation) support. Corresponding code paths are being
added to wallet-frontend (limited support) and the native SDKs.

### SUNET/vc — Issuer and Verifier Service

SUNET/vc operates as both OID4VCI issuer (APIGW) and OID4VP verifier:

| Role | client_id handling | Status |
|------|-------------------|--------|
| **Issuer (APIGW)** | Static YAML client map; public clients only (`token_endpoint_auth_methods_supported: ["none"]`); PKCE + DPoP required | Production |
| **Verifier** | `x509_san_dns:{hostname}` derived from `verifier.public_url`; signed JARs with x5c | Production |
| **VP within issuance** | Same `x509_san_dns` for authorization consent VP requests | Production |
| **OpenID Federation** | `trust_model.type: "openid_federation"` configurable; DCQL `TrustedAuthority` supports it; actual resolution delegated to go-trust PDP | Partial |
| **DID identity** | Not used as own identity; can verify DID-bound credentials | Gap |

Key characteristics:
- All proof types supported: `jwt`, `attestation`, `di_vp`
- Signed metadata (`signed_metadata` JWT with x5c) on credential issuer endpoint
- HSM support via PKCS#11 for all signing operations
- Trust evaluation delegated to go-trust PDP when `pdp_url` configured
- **No OpenID Federation entity configuration served** — not a federation participant itself
- **No DID-based self-identification** — relies exclusively on X.509

### Native SDKs (siros-sdk-kotlin, siros-sdk-swift)

The native SDKs use a **thin-client / thick-backend** architecture:

| Capability | Kotlin | Swift | wallet-frontend |
|-----------|--------|-------|-----------------|
| AuthZEN trust eval via backend proxy | ✅ | ✅ | ✅ |
| `client_id_scheme` parsing on device | ❌ | ❌ | ✅ (typed `ClientIdScheme`) |
| x5c certificate chain forwarding | ✅ pass-through | ✅ pass-through | ✅ |
| Key Attestation (`attestation` proof) | ✅ | ✅ | ✅ |
| WIA (Wallet Instance Attestation) | ✅ | ✅ | ✅ |
| Native Platform Attestation | ✅ Play Integrity | ✅ App Attest | N/A |
| DPoP on device | ❌ (backend) | ❌ (backend) | ❌ (backend) |
| DID resolution on device | ❌ | ❌ | ❌ (backend) |
| OpenID Federation support | ❌ | ❌ | ❌ |
| Trust result metadata (framework, reason) | ❌ (bool only) | ❌ (bool only) | ✅ (typed) |
| OID4VP request_uri resolution on device | ❌ (backend) | ❌ (backend) | Partial |

The SDKs delegate all `client_id` processing to go-wallet-backend. They receive
pre-processed verifier info (name, client_id string) in `credential_selection`
payloads and only use `client_id` as the `audience` for VP proof signing.

---

## Problems with Current Approach

1. **Pre-registered client IDs for issuers** — Every issuer requires manual admin
   configuration of `ClientID` + `ClientJWK`. This doesn't scale and creates a
   deployment bottleneck.

2. **`redirect_uri` fallback** — Using the redirect URI as a client ID provides
   zero authentication value. Any party can claim any redirect URI.

3. **`verifier_attestation` not implemented** — Verifiers operating under trust
   frameworks that issue short-lived attestation JWTs (rather than long-lived X.509
   certs) cannot be validated.

4. **OpenID Federation not used for trust evaluation of x509 verifiers** —
   go-trust has a complete OIDF trust chain resolver, but verifiers using
   `x509_san_dns` currently only get validated against ETSI TSLs. A verifier
   whose cert chain roots in an OIDF trust anchor (rather than an ETSI TSL)
   cannot be validated today.

5. **DID-based verifier identity is incomplete** — `did:web` and `did:webvh` are
   parsed but the full flow (resolve → verify JAR signature → trust evaluate) needs
   tightening.

6. **SUNET/vc static client map** — The issuer requires wallet client_ids in a
   YAML map (`apigw.oauth_server.clients`). Adding a new wallet deployment means
   redeploying the issuer. No dynamic discovery of wallet identity.

7. **SUNET/vc not a federation participant** — It cannot serve entity
   configurations or be discovered via OIDF trust chains. Verifiers and issuers
   in the SIROS ecosystem are invisible to federation-based wallets.

8. **Native SDKs have no trust UI richness** — They receive a boolean trust
   result with no framework metadata, reason text, or trust marks. The user
   cannot make informed consent decisions on native platforms.

9. **Native SDKs cannot operate without backend** — If go-wallet-backend is
   unreachable, native apps cannot validate any verifier identity. There's no
   graceful degradation or cached trust state.

---

## Target Architecture

### Principle: No Pre-Registration, Only Attestation Chains

Every `client_id` must be verifiable through a cryptographic attestation chain
rooted in a trust list. The `client_id` string on the wire is a **handle** pointing
at the proof — never a value requiring out-of-band registration.

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    CLIENT_ID RESOLUTION MODEL                            │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  client_id on wire         Cryptographic proof         Trust anchor      │
│  ─────────────────         ────────────────────        ─────────────     │
│                                                                          │
│  client_id on wire         Cryptographic proof         Trust anchor      │
│  ─────────────────         ────────────────────        ─────────────     │
│                                                                          │
│  x509_san_dns:host    →    X.509 cert chain       →   ETSI TSL / CA    │
│                                                    →   OIDF trust chain │
│  x509_san_uri:uri     →    X.509 cert chain       →   ETSI TSL / CA    │
│  did:web:domain       →    DID Document (HTTPS)   →   LoTE / registry  │
│                                                    →   OIDF trust chain │
│  did:webvh:domain     →    DID Document (verified)→   LoTE / registry  │
│  verifier_attestation →    Attestation JWT chain  →   Trust framework  │
│                                                                          │
│  ✗ pre-registered     →    (REMOVED — no proof)                         │
│  ✗ redirect_uri       →    (DEV-ONLY — no proof)                        │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Plan: Verifier Side (Primary)

### Phase 1: Complete DID-based Client ID (did:web, did:webvh)

**Goal**: A verifier can use `client_id = "did:web:verifier.example.com"` and the
wallet fully validates it.

**Components**:

1. **go-wallet-backend** (`internal/engine/oid4vp.go`):
   - In `evaluateVerifierTrust()`, when scheme is `did`:
     - Call `trust.Service.ResolveDID()` which sends a resolution-only request
       to go-trust PDP, receives the DID Document in `TrustMetadata`
     - Extract verification method JWKs from the DID Document
     - Verify JAR JWT signature against resolved keys using
       `VerifyJWTWithResolvedKeys()`
     - Send the verified JWK as `keyMaterial` to frontend for trust evaluation
       (same path as x509 — no frontend-side DID resolution needed)
   - Support both `did:web` and `did:webvh` (version-history DIDs provide
     cryptographic audit trail of key rotations)

2. **go-trust** (`pkg/registry/didweb/`):
   - `did:web` resolution already implemented
   - Add `did:webvh` support: resolve version history, verify hash chain,
     return current verification methods
   - Return DID Document in AuthZEN response `trust_metadata` for key extraction

3. **wallet-frontend** and **native SDKs** (primary), **wallet-companion** (nice-to-have):
   - No DID-specific changes needed — DID resolution and JWT verification
     happen server-side in go-wallet-backend
   - Frontend/SDKs receive JWK key material (same as x509 flow)
   - Display DID-based verifier identity in consent UI

**did:webvh advantage**: Unlike `did:web` (which relies on current DNS/HTTPS
control), `did:webvh` provides a verifiable history chain. If a domain is
compromised, the version history reveals the tampering. This makes it suitable
for high-assurance verifiers.

### Phase 2: OpenID Federation as Trust Evaluation Backend

**Key insight**: OpenID Federation is fundamentally about validating a key — the
same thing X.509 certificate chains do. A verifier using `x509_san_dns` or `did`
on the wire should be evaluable via OIDF trust chains in go-trust, without
requiring a separate `client_id_scheme`. The `client_id_scheme` determines how
the verifier presents its identity; OIDF is one of several mechanisms go-trust
uses to *evaluate trust* in that identity.

**Goal**: go-trust can validate verifier/issuer keys against OIDF trust chains
regardless of the `client_id_scheme` used on the wire.

**Components**:

1. **go-trust** (`pkg/registry/oidfed/`):
   - Already implements trust chain resolution via `go-oidfed/lib`
   - Wire OIDF evaluation into the standard trust evaluation path so that:
     - A verifier using `x509_san_dns:host` can be trusted if the issuing CA
       appears in an OIDF-published trust list (not only ETSI TSL)
     - A verifier using `did:web:host` can be trusted if `host` is a known
       OIDF entity with `openid_relying_party` metadata
   - Extend AuthZEN request format to accept pre-supplied `trust_chain` array
     (avoids redundant resolution when the verifier provides it inline)
   - Return entity metadata (org name, logo, trust marks) in AuthZEN response
     context for consent UI

2. **go-wallet-backend** (`internal/engine/oid4vp.go`):
   - When JAR contains a `trust_chain` header parameter (per OID4VP §5.9.3.6),
     forward it to go-trust as part of the evaluation request
   - No new `client_id_scheme` constant needed — the verifier still uses
     `x509_san_dns` or `did` on the wire
   - go-trust decides internally whether to validate via ETSI TSL, OIDF, LoTE,
     or other registries

3. **SUNET/vc** (issuer/verifier):
   - Serve `.well-known/openid-federation` entity configuration (Phase 3a)
   - Include `trust_chain` in JAR headers when operating in federation context
   - Still use `x509_san_dns` as the `client_id_scheme` on the wire

**Trust chain validation model** (inside go-trust):
```
Entity Config (verifier)  →  Intermediate Entity Stmt  →  Trust Anchor
     ↓ signed by                    ↓ signed by              ↓
  verifier key              intermediate key           TA key (configured)

go-trust routes here when:
  - evaluating x509_san_dns and cert CA matches a federation-published CA list
  - evaluating did:web and the domain has an OIDF entity configuration
  - trust_chain array provided in the evaluation request
```

### Phase 3: Verifier Attestation Scheme

**Goal**: Support `client_id_scheme = "verifier_attestation"` for trust
frameworks that issue attestation JWTs rather than X.509 certs.

**Components**:

1. **go-wallet-backend**:
   - Parse `verifier_attestation` JWT from the `jwt` header parameter of the
     request object (per OID4VP §5.9.3.4)
   - Extract verifier public key from the attestation JWT payload (`cnf.jwk`)
   - Verify request JWT signature against that key
   - Forward the raw attestation JWT, attestation issuer identity, and
     attestation key material to go-trust via the evaluation context

2. **go-trust**:
   - Verify the attestation JWT signature against the attestation issuer's keys
   - Validate attestation claims (expiry, scope, verifier_id binding)
   - Existing registries (ETSI, OIDF, static) can validate the attestation
     issuer's key material — no new registry type needed for most deployments

3. **SUNET/vc** (verifier role):
   - No change needed — SUNET/vc uses `x509_san_dns` as its own scheme
   - However, if SUNET/vc verifier needs to operate under a trust framework
     that issues attestations (rather than certs), add `verifier_attestation`
     as an alternative identity scheme in verifier config

---

## Plan: Issuer/Verifier Service (SUNET/vc)

### Phase 3a: OpenID Federation Entity Configuration

**Goal**: SUNET/vc serves `.well-known/openid-federation` entity configurations
so wallets can discover and validate it via federation trust chains.

**Components**:

1. **Entity Configuration endpoint** (`/.well-known/openid-federation`):
   - Self-signed JWT containing entity metadata
   - `metadata.openid_credential_issuer` — issuer metadata per OID4VCI
   - `metadata.openid_relying_party` — verifier metadata per OID4VP
   - `authority_hints` — parent entities in the federation hierarchy
   - Signing key from existing `key_config` (same key as signed JARs)

2. **Subordinate statement support**:
   - Accept and cache subordinate statements from trust anchors
   - Serve them at `/.well-known/openid-federation?sub={entity_id}` (optional)
   - Or: rely on trust anchors to host subordinate statements (simpler)

3. **Configuration** (`config.yaml`):
   ```yaml
   federation:
     enabled: true
     entity_id: "https://issuer.example.com"
     authority_hints:
       - "https://trust-anchor.example.com"
     signing_key_config: # reuse existing key_config or separate
       private_key_path: "/pki/federation_signing.pem"
     metadata_policy: {}  # optional constraints
   ```

4. **Trust mark support** (optional):
   - Accept trust marks from trust mark issuers
   - Include in entity configuration under `trust_marks`
   - Wallets can display trust mark logos in consent UI

### Phase 3b: DID-based Issuer/Verifier Identity

**Goal**: SUNET/vc can optionally identify as `did:web` or `did:webvh` in
addition to (or instead of) `x509_san_dns`.

**Components**:

1. **DID Document serving** (`/.well-known/did.json` for `did:web`):
   - Auto-generate DID Document from existing signing keys
   - Include verification methods matching current `key_config`
   - For `did:webvh`: maintain version history with hash chain

2. **Verifier client_id via DID**:
   ```yaml
   verifier:
     client_id_scheme: "did"  # or "x509_san_dns" (default)
     did: "did:web:verifier.example.com"
   ```
   - When `client_id_scheme: "did"`, JAR's `client_id` = the DID
   - JWT signed with key referenced in DID Document
   - Wallet resolves DID → verifies signature → trusts based on LoTE/registry

3. **Issuer credential binding via DID**:
   - `credential_issuer_identifier` can be set to a DID
   - Credential `iss` claim = DID
   - Wallet resolves DID Document to obtain verification keys
   - Advantage: key rotation is transparent (update DID Document)

### Phase 3c: Eliminate Static Client Map

**Goal**: Replace `apigw.oauth_server.clients` YAML map with attestation-based
wallet identification.

**Components**:

1. **Accept wallet attestation in token requests**:
   - Add `client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"`
     support with wallet-provider-signed assertions
   - Validate assertion against configured wallet-provider trust anchors
   - Extract wallet instance identity from attestation claims
   - No pre-registration needed — any wallet with a valid attestation is accepted

2. **Wallet-provider trust configuration**:
   ```yaml
   apigw:
     oauth_server:
       wallet_provider_trust:
         - issuer: "https://wallet-provider.siros.se"
           jwks_uri: "https://wallet-provider.siros.se/.well-known/jwks.json"
         - issuer: "https://wallet-provider.other.eu"
           trust_anchor: "https://trust-anchor.eu"  # validate via OIDF
   ```

3. **Backward compatibility**:
   - Keep static `clients` map for legacy wallets during transition
   - Log deprecation warnings when static client lookup is used
   - Feature flag: `oauth_server.require_wallet_attestation: bool`

4. **Authorization endpoint changes**:
   - PAR endpoint accepts `client_assertion` instead of (or in addition to)
     `client_id` lookup
   - Token endpoint validates DPoP + client_assertion combination
   - PKCE remains mandatory regardless of authentication method

---

## Plan: Issuer Side (Second Priority)

### Phase 4: Issuer Trust via DID / OpenID Federation

**Goal**: Eliminate static `CredentialIssuer.ClientID` configuration. The wallet
authenticates to issuers using DPoP + key attestation; the wallet evaluates issuer
trust dynamically.

**Components**:

1. **Issuer trust evaluation** (mirror of verifier trust):
   - When receiving a credential offer, resolve the issuer's identity:
     - If issuer metadata contains `openid_federation` entity configuration:
       resolve trust chain, validate against configured trust anchors
     - If issuer identifier is a `did:web` / `did:webvh`: resolve DID Document,
       validate against LoTE registries
     - If issuer presents X.509 in credential signing: validate cert chain
       against ETSI TSL
   - Already partially exists: `createIssuerTrustEvaluator()` in wallet-frontend
     and `credential-issuer` subject type in go-trust

2. **Remove static ClientID dependency**:
   - The `CredentialIssuer.ClientID` field becomes **optional** (backward compat)
   - Default behavior: wallet authenticates as a public client with DPoP binding
   - The wallet-provider key attestation (`attestation` proof type) is the primary
     proof of wallet identity — no `client_id` needed beyond the spec-mandated
     parameter
   - When `client_id` must be sent (spec compliance): use the wallet instance's
     DID or the redirect_uri as a stable identifier derived from attestation
   - **Note**: WIA (Wallet Instance Attestation) + KA (Key Attestation) support
     is currently being implemented — PR in progress on go-wallet-backend with
     corresponding paths being added to wallet-frontend (limited) and native SDKs

3. **Issuer-side OpenID Federation**:
   - Wallet resolves `{issuer_url}/.well-known/openid-federation` to discover
     issuer entity configuration
   - Trust chain from issuer → intermediate → trust anchor validates the issuer
   - Issuer metadata (supported credentials, policies) extracted from resolved
     entity statement
   - This replaces the need for admin-configured issuer entries in production

4. **Issuer-side DID binding**:
   - Issuer metadata `credential_issuer_identifier` can be a DID
   - Wallet resolves DID Document, validates credential signatures against DID keys
   - Particularly useful for `did:webvh` where key history provides audit trail
     of issuer key rotations

### Phase 5: Deprecate Pre-Registration

1. Add configuration flag: `trust_config.allow_pre_registered: bool` (default: true
   during transition, false in production)
2. Log warnings when `pre-registered` or empty scheme is used
3. Remove `redirect_uri` fallback from `resolveClientID()` — require explicit
   dev-mode opt-in
4. Remove `CredentialIssuer.ClientID` / `ClientJWK` fields from domain model
   (breaking change, behind feature flag)

---

## Plan: Native SDKs (siros-sdk-kotlin, siros-sdk-swift)

### Phase 6: Typed Trust Evaluation Interface

**Goal**: Native SDKs present rich trust information to users matching the
wallet-frontend experience.

**Components**:

1. **Typed `TrustResult` model** (both SDKs):
   ```kotlin
   // Kotlin
   data class TrustResult(
       val trusted: Boolean,
       val framework: String?,        // e.g. "etsi-tl", "openid-federation", "lote"
       val reason: String?,           // human-readable explanation
       val verifierName: String?,     // display name from metadata/entity config
       val verifierLogo: String?,     // logo URL
       val trustMarks: List<TrustMark>?,  // federation trust marks
       val clientIdScheme: String,    // "x509_san_dns", "did", "verifier_attestation"
       val identifier: String,        // normalized identifier (hostname, DID, entity_id)
   )
   ```

   ```swift
   // Swift
   struct TrustResult {
       let trusted: Bool
       let framework: String?
       let reason: String?
       let verifierName: String?
       let verifierLogo: String?
       let trustMarks: [TrustMark]?
       let clientIdScheme: String
       let identifier: String
   }
   ```

2. **Parse extended trust evaluation response** from backend:
   - Currently SDKs extract only `trusted: bool` from the `flow_progress` payload
   - Extend to parse `context.framework`, `context.reason`, `context.entity_name`,
     `context.logo_uri`, `context.trust_marks` from AuthZEN response
   - go-wallet-backend already includes these in `TrustResultPayload`; SDKs just
     need to parse them

3. **Consent UI integration**:
   - Pass `TrustResult` to host app via delegate/callback
   - Host app renders trust level indicator, verifier name, framework badge,
     trust marks
   - Provide default UI components in SDK for common patterns

### Phase 7: Client ID Scheme Awareness on Device

**Goal**: Native SDKs understand `client_id_scheme` for richer consent context
and future offline/degraded operation.

**Components**:

1. **`ClientIdScheme` parsing** (mirror wallet-frontend's `parseClientIdScheme`):
   ```kotlin
   sealed class ClientIdScheme {
       data class X509SanDns(val hostname: String) : ClientIdScheme()
       data class X509SanUri(val uri: String) : ClientIdScheme()
       data class Did(val did: String, val method: String) : ClientIdScheme()
       data class OpenIDFederation(val entityId: String) : ClientIdScheme()
       data class VerifierAttestation(val attestationIssuer: String) : ClientIdScheme()
       data class Https(val url: String) : ClientIdScheme()
   }
   ```

2. **Extract scheme from backend progress payloads**:
   - `evaluating_trust` payload already contains `context.client_id_scheme`
   - Parse into typed model for UI consumption
   - Display scheme-appropriate identity info (hostname for x509, DID for did,
     org name for federation)

3. **Audience validation on device**:
   - When signing VP proofs, validate that `audience` parameter matches the
     parsed `client_id` from the consent step
   - Prevents MITM between backend and signing step

### Phase 8: Cached Trust State for Resilience

**Goal**: Native SDKs maintain a local trust cache enabling degraded-mode
operation when the backend is temporarily unreachable.

**Components**:

1. **Trust cache database** (SQLite / CoreData):
   - Cache recent `TrustResult` entries keyed by `(client_id_scheme, identifier)`
   - TTL-based expiry (configurable, default 24h)
   - Populate on every successful trust evaluation

2. **Degraded-mode behavior**:
   - If backend unreachable during trust evaluation:
     - Check local cache for recent positive result
     - If cached and not expired: proceed with warning indicator in UI
     - If no cache hit: block (fail-secure) with user-visible error
   - Never cache negative results (attacker could poison cache)

3. **Certificate/key pinning for known verifiers**:
   - High-frequency verifiers (e.g., government services) can have their
     x5c leaf cert fingerprint cached locally
   - Enables basic verification even without PDP access
   - Updated periodically via background sync with backend

---

## Implementation Priority

| Phase | Scope | Repos | Effort |
|-------|-------|-------|--------|
| 1 | did:web + did:webvh verifier | go-wallet-backend, go-trust, wallet-frontend | Medium |
| 2 | OpenID Federation trust eval backend | go-trust, go-wallet-backend | Medium |
| 3 | Verifier attestation | go-wallet-backend, go-trust | Small |
| 3a | SUNET/vc federation entity config | SUNET/vc | Medium |
| 3b | SUNET/vc DID-based identity | SUNET/vc | Medium |
| 3c | SUNET/vc eliminate static client map | SUNET/vc | Medium |
| 4 | Issuer trust (DID + OIDF) + WIA/KA | go-wallet-backend, go-trust, wallet-frontend, SUNET/vc | Large (in progress) |
| 5 | Deprecate pre-registration | go-wallet-backend | Small (config change) |
| 6 | Native SDK typed trust results | siros-sdk-kotlin, siros-sdk-swift | Small |
| 7 | Native SDK client_id_scheme awareness | siros-sdk-kotlin, siros-sdk-swift | Medium |
| 8 | Native SDK cached trust state | siros-sdk-kotlin, siros-sdk-swift | Medium |

**Dependency graph**:
```
Phase 1 ─┐
Phase 2 ─┼─→ Phase 4 ─→ Phase 5
Phase 3 ─┘        │
                   ↓
Phase 3a ─→ Phase 3c
Phase 3b ─┘

Phase 6 ─→ Phase 7 ─→ Phase 8  (independent of Phases 1-5)
```

Phases 1–3 and 3a–3b can proceed in parallel. Phase 4 depends on Phases 1–2
(reuses OIDF/DID infrastructure). Phase 3c depends on 3a (federation-based
wallet discovery). Phase 5 is a cleanup gate. Native SDK phases (6–8) are
independent and can start immediately.

---

## Code Changes Required

### go-wallet-backend

**`internal/domain/credential.go`** — Update scheme constants:
```go
var ValidClientIDSchemes = map[string]bool{
    "":                     true, // deprecated, warn
    "redirect_uri":         true, // dev-only, warn in prod
    "pre-registered":       true, // deprecated, warn
    "x509_san_dns":         true,
    "x509_san_uri":         true,
    "x509_hash":            true, // add
    "verifier_attestation": true,
    "did":                  true,
}
```

Note: `openid_federation` is intentionally NOT a separate `client_id_scheme`.
OIDF is a trust evaluation mechanism in go-trust, not a wire-level identifier.
Verifiers use `x509_san_dns` or `did` on the wire; go-trust resolves trust via
OIDF internally when appropriate.

**`internal/engine/oid4vp.go`** — Add scheme constants and dispatch:
```go
const (
    ClientIDSchemeX509Hash = "x509_hash"
)
```

In `evaluateVerifierTrust()`, add cases for:
- `did` (enhanced): full DID resolution → JWT verification → trust evaluation
- `verifier_attestation`: extract attestation JWT from `jwt` header param
- Forward `trust_chain` JWT header to go-trust when present (any scheme)

**`internal/engine/oid4vci.go`** — Issuer trust evaluation:
```go
// Before accepting credential, evaluate issuer trust
func (h *OID4VCIHandler) evaluateIssuerTrust() (*TrustResultPayload, error) {
    // 1. Check for OIDF entity configuration at issuer URL
    // 2. Check for DID-based issuer identifier
    // 3. Fall back to X.509 if credential is signed with cert chain
    // 4. Send to PDP via frontend trust evaluation step
}
```

### go-trust

**`pkg/registry/didweb/`** — Add `did:webvh` resolution (hash-chain verification).

**`pkg/registry/oidfed/`** — Accept pre-supplied `trust_chain` in evaluation
request to avoid redundant resolution.

**`pkg/trustapi/types.go`** — Route OIDF evaluation based on trust_chain
presence or domain-level OIDF entity discovery, not client_id_scheme.

### wallet-frontend (primary) / wallet-companion (nice-to-have)

- Handle DID resolution progress step from engine
- Display trust evaluation metadata (org name, trust mark logos) in consent UI
- Parse `trust_chain` from backend-provided context for display purposes

**Note**: wallet-companion is a secondary target. Most deployments use native
apps or the web client directly. wallet-companion should be kept on par where
feasible but is not a blocking dependency for any phase.

### SUNET/vc

**`internal/apigw/`** — Federation entity configuration:
- New handler: `GET /.well-known/openid-federation` → self-signed entity config JWT
- Include `metadata.openid_credential_issuer` and `metadata.oauth_authorization_server`
- Sign with existing `pki.Signer` key (reuse verifier/issuer key_config)

**`pkg/oauth2/clients.go`** — Wallet attestation authentication:
```go
// New: validate client_assertion from wallet-provider
func (c *Clients) ValidateWalletAttestation(assertion string, trustedProviders []WalletProviderConfig) (*WalletIdentity, error) {
    // 1. Parse JWT, extract wallet-provider issuer
    // 2. Validate signature against provider JWKS
    // 3. Check claims: exp, iat, sub (wallet instance)
    // 4. Return wallet identity (no pre-registration needed)
}
```

**`internal/verifier/`** — Optional DID-based client_id:
```go
// Support configurable client_id_scheme
switch cfg.Verifier.ClientIDScheme {
case "did":
    clientID = cfg.Verifier.DID  // e.g. "did:web:verifier.example.com"
case "x509_san_dns":
    clientID = fmt.Sprintf("x509_san_dns:%s", host)  // existing behavior (default)
}
```

**`pkg/model/config.go`** — New configuration:
```go
type FederationConfig struct {
    Enabled        bool     `yaml:"enabled"`
    EntityID       string   `yaml:"entity_id"`
    AuthorityHints []string `yaml:"authority_hints"`
    TrustMarks     []string `yaml:"trust_marks"`  // pre-issued trust mark JWTs
}

type VerifierConfig struct {
    // ... existing fields
    ClientIDScheme string            `yaml:"client_id_scheme"` // "x509_san_dns" (default) | "did"
    DID            string            `yaml:"did,omitempty"`
    Federation     *FederationConfig `yaml:"federation,omitempty"`
}
```

### siros-sdk-kotlin

**`sdk/wallet/.../SirosWallet.kt`** — Extended trust handling:
```kotlin
// Replace current boolean extraction:
private fun parseTrustResult(payload: JsonObject): TrustResult {
    val request = payload["request"]?.jsonObject
    val context = payload["context"]?.jsonObject
    return TrustResult(
        trusted = context?.get("decision")?.jsonPrimitive?.booleanOrNull ?: false,
        framework = context?.get("framework")?.jsonPrimitive?.contentOrNull,
        reason = context?.get("reason")?.jsonPrimitive?.contentOrNull,
        verifierName = context?.get("entity_name")?.jsonPrimitive?.contentOrNull,
        verifierLogo = context?.get("logo_uri")?.jsonPrimitive?.contentOrNull,
        clientIdScheme = request?.get("context")?.jsonObject
            ?.get("client_id_scheme")?.jsonPrimitive?.contentOrNull ?: "unknown",
        identifier = request?.get("subject_id")?.jsonPrimitive?.contentOrNull ?: "",
    )
}
```

**`sdk/credentials/.../ClientIdScheme.kt`** — New model:
```kotlin
sealed class ClientIdScheme {
    abstract val identifier: String
    data class X509SanDns(override val identifier: String) : ClientIdScheme()
    data class Did(override val identifier: String, val method: String) : ClientIdScheme()
    data class OpenIDFederation(override val identifier: String) : ClientIdScheme()
    data class VerifierAttestation(override val identifier: String) : ClientIdScheme()
    companion object {
        fun parse(clientId: String): ClientIdScheme = when {
            clientId.startsWith("x509_san_dns:") -> X509SanDns(clientId.removePrefix("x509_san_dns:"))
            clientId.startsWith("did:") -> Did(clientId, clientId.split(":")[1])
            clientId.startsWith("https://") -> OpenIDFederation(clientId)
            else -> X509SanDns(clientId)
        }
    }
}
```

### siros-sdk-swift

**`Sources/SirosWallet/SirosWallet.swift`** — Extended trust handling:
```swift
struct TrustResult {
    let trusted: Bool
    let framework: String?
    let reason: String?
    let verifierName: String?
    let verifierLogo: String?
    let clientIdScheme: String
    let identifier: String
}

func parseTrustResult(payload: [String: Any]) -> TrustResult {
    let context = payload["context"] as? [String: Any]
    let request = payload["request"] as? [String: Any]
    let reqContext = (request?["context"] as? [String: Any])
    return TrustResult(
        trusted: (context?["decision"] as? Bool) ?? false,
        framework: context?["framework"] as? String,
        reason: context?["reason"] as? String,
        verifierName: context?["entity_name"] as? String,
        verifierLogo: context?["logo_uri"] as? String,
        clientIdScheme: (reqContext?["client_id_scheme"] as? String) ?? "unknown",
        identifier: (request?["subject_id"] as? String) ?? ""
    )
}
```

**`Sources/SirosCredentials/ClientIdScheme.swift`** — New model:
```swift
enum ClientIdScheme {
    case x509SanDns(hostname: String)
    case did(did: String, method: String)
    case openIDFederation(entityId: String)
    case verifierAttestation(issuer: String)

    var identifier: String { /* ... */ }

    static func parse(_ clientId: String) -> ClientIdScheme {
        if clientId.hasPrefix("x509_san_dns:") { return .x509SanDns(hostname: String(clientId.dropFirst(13))) }
        if clientId.hasPrefix("did:") { return .did(did: clientId, method: String(clientId.split(separator: ":")[1])) }
        if clientId.hasPrefix("https://") { return .openIDFederation(entityId: clientId) }
        return .x509SanDns(hostname: clientId)
    }
}
```

---

## Security Considerations

1. **did:web TOCTOU** — DNS/HTTPS control can change between resolution and use.
   Mitigate with short cache TTLs and consider `did:webvh` for high-assurance cases.

2. **Federation trust anchor compromise** — A compromised trust anchor can issue
   rogue entity statements. Mitigate with multiple trust anchors and monitoring.

3. **Verifier attestation replay** — Attestation JWTs must be short-lived and
   audience-bound. Validate `exp`, `iat`, and `aud` claims.

4. **Removal of pre-registered scheme** — Must be gated behind feature flags with
   sufficient migration time. Breaking existing deployments is unacceptable without
   a transition period.

5. **Key attestation as wallet identity** — The wallet-provider key attestation
   replaces traditional `client_id` for issuer authentication. The wallet-provider
   must be a highly protected signing service (HSM-backed, short-lived attestations).

6. **Native SDK trust cache poisoning** — Cache must only store positive results
   from authenticated backend connections. TLS pinning is already implemented in
   both SDKs. Cache entries must include the full trust evaluation context to
   prevent downgrade attacks (e.g., cached `x509_san_dns` result should not
   satisfy a `did:web` lookup).

7. **SUNET/vc federation key management** — The entity configuration signing key
   has high blast radius (compromised key = impersonation of the entire issuer/verifier).
   Must be HSM-protected and rotated on schedule. Key ID (`kid`) must be stable
   for subordinate statement verification.

8. **Static client map removal timeline** — SUNET/vc's `apigw.oauth_server.clients`
   map removal requires all deployed wallet instances to support attestation-based
   auth. Minimum 6-month deprecation period with dual-mode support.

---

## References

- [OID4VP §5.9.3](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5.9.3) — Client Identifier Schemes
- [OID4VCI §7.1](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-7.1) — Client Authentication
- [did:web Method Specification](https://w3c-ccg.github.io/did-method-web/)
- [did:webvh Method Specification](https://identity.foundation/did-webvh/)
- [OpenID Federation 1.0](https://openid.net/specs/openid-federation-1_0.html)
- [ADR-012: Trust Evaluation Architecture](adr/012-trust-evaluation-architecture.md)
- [ETSI TS 119 475](https://www.etsi.org/deliver/etsi_ts/119400_119499/119475/) — WRPRC for EU-regulated verifiers
- [RFC 7591](https://www.rfc-editor.org/rfc/rfc7591) — OAuth 2.0 Dynamic Client Registration
- [HAIP §7.1.3](https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0.html) — Key Attestation
