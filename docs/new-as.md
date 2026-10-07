# Design for a new go-wallet-backend AS

## Requirements

The new AS must support all existing features in the current AS and should also adopt a more standard security model for tokens where refresh tokens are used to represent a service and access tokens are used to represent authorization for entity A (a user or a service) to access service B.

The new AS should also be able to handle both user-level access and services as well as admin-level access. The new AS should be based on a unified token format using JWTs signed by asymmetric keys.

The new AS should properly extend the current AS and should be integrated into the mode-based URL routing to allow the AS to be operated both as part of an all-in-one deployment or standalone.

The new AS must to the extent possible use the same db models as the current AS.

## Authentication

The user authenticates to the AS either using passkeys or via the OIDC RP. The result of the authentication is a session that is tracked in two ways:

1. **Session cookie**: An `HttpOnly`, `Secure`, `SameSite=Strict` cookie containing a high-entropy random string. This string is the `jti` of the session JWT stored server-side in the session DB.
2. **Session JWT** (server-side): Stored in the session DB, keyed by the cookie value (`jti`). Contains the user's identity, tenant, authentication context, and expiration.

The cookie is set in the response to the final step of the authentication flow. In order to support legacy clients, a simplified access token that has the same format as we currently implement may be returned along with the cookie and the "200 OK" response.

**Legacy clients** use this access token JWT directly just as today.

**Modern clients** ignore any JWT returned in the authentication flow and instead request access tokens when they are needed to call APIs on behalf of the user. This is covered in the Authorization section below.

### Authentication methods

- **Passkeys (WebAuthn)**: Default authentication method for end users.
- **OIDC RP**: Used for admin users. Claims from the OIDC IdP are mapped to the session JWT as follows:
  - `sub` ← IdP subject identifier (or mapped via tenant OIDC gate configuration)
  - `tenant_id` ← determined by the OIDC gate configuration on the tenant
  - `tac` ← assigned based on group/role claims from the IdP, per tenant policy
  - `acr` ← set to reflect OIDC authentication (e.g., `urn:siros:acr:oidc`)

### acr values

The `acr` (authentication context class reference) indicates the type of authentication performed when the session was created. This is carried forward into access tokens and can be used for step-up authentication decisions or policy enforcement.

Defined values:
- `urn:siros:acr:passkey` — passkey/WebAuthn authentication
- `urn:siros:acr:oidc` — OIDC RP authentication

## Access token format

Access tokens are short-lived JWTs signed with the AS's asymmetric key pair. All tokens share a common claim structure:

```jsonc
{
    // standard claims
    "jti": "<unique token id>",
    "exp": "<expiration timestamp>",
    "nbf": "<not-before timestamp>",
    "iat": "<issued-at timestamp>",
    "sub": "<user identifier>",
    "aud": "<target service>",
    "iss": "<AS URL>",
    "acr": "<authentication context>",
    // siros claims
    "tenant_id": "<tenant id>",
    "tac": "rwlidka"
}
```

### sub

Either the user identifier OR `$iss` if the token gives permissions to the service itself. This is used for "anonymous" tokens, e.g., for situations where the `$aud` should not know who the real subject is. This can for instance be used when resolving issuer metadata via the backend; the resolver service should be authenticated to avoid abuse but it doesn't have to know which user wants to resolve the issuer.

### tenant_id

The tenant scope of the token. The string `"*"` means the token applies to all tenants (cross-tenant tokens). Cross-tenant tokens must only be issued to subjects with admin-level privileges, enforced by SPOCP policy rules (see below).

### tac

`tac` (token access control) is the set of permissions that apply to the token. Represented as a string of permission characters:

- `r` — **read**: read access on a per-object basis
- `w` — **write**: write access on a per-object basis
- `l` — **list**: read access on directory-like structures (collections, indexes)
- `i` — **insert**: create new entries in directory-like structures
- `d` — **delete**: remove objects
- `k` — **delegate**: issue delegation tokens (see Delegation below)
- `a` — **admin**: full administrative rights

These permissions apply across all services but may not all be meaningful for every service. A token's `tac` is always a subset of (or equal to) the issuing session's maximum allowed permissions, enforced by SPOCP policy.

## Revocation

Token revocation is handled externally via a revocation store keyed by `jti`. When validating an access token, the verifying service checks the revocation store. Revoked tokens are rejected regardless of their `exp` claim.

The session JWT in the session DB can also be revoked, which prevents any further access tokens from being issued for that session.

## Key management

The AS signs access tokens using an asymmetric key pair (e.g., ECDSA P-256 or EdDSA).

- The AS exposes a **JWKS endpoint** (`/.well-known/jwks.json`) so that verifying services can discover the current public key(s).
- **Key rotation**: The AS supports multiple active keys identified by `kid`. During rotation, both old and new keys are published in the JWKS. The old key is removed after all tokens signed with it have expired.
- In standalone deployment, the JWKS endpoint is served by the AS directly. In all-in-one mode, it is served under the shared URL prefix.

## Authorization

When a client (wallet or SDK) needs to call an API on behalf of a user, it obtains an access token by doing a `POST` to the `/token` endpoint of the AS. The request includes:

- The session cookie (automatically sent by the browser, or explicitly by native clients)
- A **token request** JSON body specifying the desired access token properties

> For the concrete, current answer to "what `aud`/`tac` do I need to call
> route X" (including the identity-free `anonymous` request shape added
> after this design doc was written), see `docs/authorization-requirements.md`
> - this section covers the design rationale, not an exhaustive per-route
> reference.

### Token request format

```jsonc
{
    "aud": "<target service>",
    "tenant_id": "<tenant id>",   // optional, defaults to session tenant
    "tac": "rl"                   // optional, requested permissions
}
```

### Token issuance flow

```
Client                          AS                           SPOCP
  |                              |                              |
  |  POST /token                 |                              |
  |  Cookie: session=<jti>       |                              |
  |  Body: { aud, tenant_id,     |                              |
  |          tac }               |                              |
  |----------------------------->|                              |
  |                              |  1. Look up session JWT      |
  |                              |     by cookie value           |
  |                              |  2. Validate session:        |
  |                              |     - verify signature       |
  |                              |     - check exp              |
  |                              |     - check revocation store |
  |                              |  3. Build candidate token:   |
  |                              |     - new jti, iat, exp,nbf  |
  |                              |     - merge request + session|
  |                              |  4. Convert to s-expression  |
  |                              |----------------------------->|
  |                              |                              |
  |                              |  5. Evaluate against rules   |
  |                              |<-----------------------------|
  |                              |     allow / deny             |
  |                              |                              |
  |  6a. 200 + signed JWT        |                              |
  |  6b. 403 Forbidden           |                              |
  |<-----------------------------|                              |
```

### Token construction details

1. Create an empty claims set.
2. Add claims from the token request (`aud`, `tenant_id`, `tac`).
3. Add claims from the session JWT (`sub`, `acr`, and session-level `tenant_id` / `tac` as defaults where not overridden by the request).
4. Generate new `jti`, `iat` (now), `nbf` (now − 1 second), and `exp` (now + TTL).
5. Set `iss` to the AS URL.

The candidate token is converted to an s-expression: `(token (claim value) ...)` and evaluated against the configured SPOCP policy rules. If the evaluation returns true, the token is signed and returned; otherwise a `403 Forbidden` error is returned.

### Access token TTL

The default access token TTL is 2 minutes. Different TTLs may be configured per audience or use case:

- **API calls**: 2 minutes (default)
- **WebSocket handshake**: configurable, should cover connection setup
- **Long-running operations**: clients should re-request tokens as needed; operations that outlive the token must re-validate

### Example SPOCP policy rules

```
;; Users can only get tokens for their own tenant
(token (tenant_id %tenant%) (sub %user%))

;; Only admin users can request cross-tenant tokens
(token (tenant_id *) (tac (a)))

;; Delegation tokens can only be issued by tokens that already have 'k'
(token (tac (k)))

;; Read-only access is always allowed for authenticated users
(token (tac (r l)))
```

## Delegation

A token with the `k` (delegate) permission can be used to issue further tokens. Delegation tokens are always **downscoped**: the delegated token's `tac` must be a subset of the delegating token's `tac`, and `tenant_id` must match. This is enforced by SPOCP policy rules.

To issue a delegation token, the client POSTs to `/token` using the delegating access token as a Bearer token (instead of a session cookie). The same SPOCP evaluation applies.

## Deployment

The new AS integrates into the existing mode-based URL routing system. It registers as a `RouteProvider` under the `auth` mode:

- `--mode=auth` — standalone AS deployment
- `--mode=backend,auth` — combined backend + AS
- `--mode=all` — all services including AS

### Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/auth/passkey/register/begin` | Begin passkey registration |
| POST | `/auth/passkey/register/finish` | Complete passkey registration |
| POST | `/auth/passkey/login/begin` | Begin passkey login |
| POST | `/auth/passkey/login/finish` | Complete passkey login |
| GET | `/auth/oidc/login` | Initiate OIDC login |
| GET | `/auth/oidc/callback` | OIDC callback |
| POST | `/auth/token` | Request access token |
| DELETE | `/auth/session` | Logout / revoke session |
| GET | `/.well-known/jwks.json` | Public key set |

## Legacy client compatibility

### Problem

Existing clients (wallet-frontend, SDK clients) use an all-in-one token model:
- Login returns `appToken` (HMAC-SHA256 JWT, long-lived)
- Client stores in `sessionStorage`
- Every API call sends `Authorization: Bearer <appToken>`
- The same token serves as both session proof and access authorization

These clients cannot be updated atomically. The new AS supports them (while `as.legacy.enabled` is true) alongside new-style session cookies + short-lived access tokens.

### Design: dual-mode authentication

Login endpoints (`/auth/passkey/login/finish`, `/auth/oidc/callback`) detect client capability and respond accordingly.

**Client mode detection:**

| Signal | Interpretation |
|--------|---------------|
| `X-Token-Mode: session` header | New-style client |
| Absent header (default) | Legacy client |

**Legacy response** (preserves current format):
```jsonc
{
  "uuid": "...",
  "appToken": "<HMAC-SHA256 JWT>",    // same signing as today
  "refreshToken": "<HMAC-SHA256 JWT>", // if refresh enabled
  "displayName": "...",
  "tenantId": "..."
}
```

The legacy `appToken` is signed with the existing HMAC secret — no change to the token format or validation for legacy clients.

**New-style response:**
```
Set-Cookie: __Host-session=<jti>; HttpOnly; Secure; SameSite=Strict; Path=/
```
```jsonc
{
  "uuid": "...",
  "displayName": "...",
  "tenantId": "..."
}
```

No token in the body. Client uses the session cookie and calls `POST /auth/token` for short-lived access tokens.

### Legacy configuration

The legacy path has no expiry ramp-down and no sunset schedule. Legacy tokens are signed with `jwt.secret` and use the ordinary `jwt.expiry_hours` / `jwt.refresh_days` lifetimes. The `as.legacy` block has these keys:

```yaml
as:
  legacy:
    enabled: true             # default true; false turns the legacy AS off
    deprecation_header: false # see below
```

- `as.legacy.enabled` is the only switch, and it is acted on (see below).
- `as.legacy.deprecation_header` is parsed, but nothing currently sends the header: `DeprecationMiddleware` in `internal/as/deprecation.go` exists and is tested but is not mounted on any route, so setting it has no effect.
- `as.legacy.sunset_date` is deprecated and ignored (see below).

There is no `hmac_secret`, `max_expiry` or `reduction_schedule` key. The legacy HMAC secret is `jwt.secret`. The legacy AS is sunset only by setting `as.legacy.enabled=false`, after clients have moved to session mode.

### Disabling legacy: `as.legacy.enabled=false` (implemented)

The only switch is configuration. `as.legacy.enabled` defaults to `true`, so existing deployments are unchanged. Sunsetting the legacy AS is done only by flipping it to `false`, and clients must have moved to session mode first. The `as.legacy.sunset_date` setting (env `WALLET_AS_LEGACY_SUNSET_DATE`) is deprecated and ignored; a config that still sets it loads, and a warning is logged at startup saying so. With `as.legacy.enabled=false`:

- HMAC tokens are refused everywhere: `TokenAuthMiddleware`, the engine handshake (including the standalone-engine HMAC fallback), the no-AS `AuthMiddlewareWithBlacklist` path, and the keystore websocket. No legacy issuer is created.
- Legacy issuance answers `410 legacy_tokens_disabled`: `/user/{register,login}-webauthn-*` and `/user/session/refresh` (whether or not this process runs the AS) and legacy-mode (`X-Token-Mode` absent) `/auth/passkey/{login,register}/*`. These 410s sit before any OIDC gate, so legacy-mode requests get `legacy_tokens_disabled` rather than an OIDC error. Session-mode clients are unaffected.
- One startup log line states whether legacy is enabled.

The `backend` and `wallet-provider` roles refuse to start with `as.enabled=false` and `as.legacy.enabled=false`: they build a JWKS validator only when the AS is enabled, so no session token could be authenticated. Enable the AS or keep legacy on. Only the standalone engine can validate against a remote AS.

A standalone engine (`--mode=engine`, no backend provider) builds its own JWKS-backed validator from `as.external_url` so ES256 session tokens work and legacy can be switched off; with `as.legacy.enabled=false` and no `as.external_url` it refuses to start instead of rejecting every connection.

### JWKS fetching is guarded

go-tokenauth fetches the AS JWKS with `http.DefaultClient` (no client option in v0.4.0 or v0.5.0), which has no scheme policy and follows HTTPS-to-HTTP redirects. The backend therefore never lets it reach the network: a co-hosted AS serves its own keys to the validator in-process (loopback relay, no fetch), and processes that read a remote AS (isolated wallet-provider, standalone engine) fetch `<as.external_url>/auth/.well-known/jwks.json` and relay it to the validator over a loopback-only listener. That fetch uses the same narrow trust as the AS's OIDC client (`HTTPClientConfig.NewOwnASHTTPClient`): the hostname of `as.external_url` may be listed in `http_client.trusted_idp_hosts` (exact, case-insensitive hostnames), which lets it sit on a private or cluster-internal address and, for this one fetch only, be reached over plain `http`. A plain-`http` or private-address `as.external_url` whose host is not listed is refused (startup error for plain http, naming the host to add; a logged fetch error for a private https host) unless the global `http_client.allow_http` / `allow_private_ips` is set, which also loosens the policy for third-party issuers and verifiers and should not be used for this. Redirect hops are checked the same way (a redirect to an unlisted host is refused), cloud-metadata addresses stay blocked even if listed, the response is capped at 1 MiB, and other schemes are never allowed. The plaintext allowance exists because JWKS holds public keys only and the host is one the operator named explicitly; the OIDC identity-provider exchange gets no such allowance. Prefer an `https` `as.external_url` where the cluster offers one.

### Audience semantics

An audience list (`as.audiences`) applies to new-style (ES256/JWKS) tokens only. Legacy HMAC tokens carry the RP ID as `aud` and are never rejected by an audience list while legacy is enabled (signature, expiry and issuer are still checked). `RequireAudience` and the engine's `wallet-registry`/`wallet-backend` check follow the same rule.

### HSM-backed signing key

`as.signing_key_pkcs11` (`module_path`, `slot_id`, `key_label`, `pin` or `pin_path`, `pool_size`) uses the existing PKCS#11 signer and needs a binary built with `-tags pkcs11`; it is mutually exclusive with `as.signing_key_path`, is never inherited from the wallet provider, and supports ECDSA P-256/P-384 keys only (RSA is rejected because the AS signs access tokens only with ES256, ES384 or EdDSA, an AS-key restriction rather than a signer limitation; Ed25519 is unavailable over PKCS#11 because the PKCS#11 pool cannot handle `CKK_EC_EDWARDS` keys, so use `as.signing_key_path` for Ed25519). `kid` is the JWK thumbprint, as for file keys. Rotation is operational: re-issue and restart.

#### Docker images and trying it locally

The default image (`Dockerfile`) is a static, CGO-free binary on distroless: it has no libc and no PKCS#11 module, so `as.signing_key_pkcs11` (and the wallet-provider PKCS#11 key) **fail closed** there with `PKCS#11 support not compiled in (build with -tags pkcs11)`. Use the PKCS#11 image variant instead:

| Image | Built from | Use |
|---|---|---|
| `ghcr.io/sirosfoundation/go-wallet-backend` | `Dockerfile` | default; no HSM support |
| `ghcr.io/sirosfoundation/go-wallet-backend-pkcs11` | `Dockerfile.pkcs11` (target `runtime`) | production with an HSM: glibc, `CGO_ENABLED=1`, `-tags pkcs11`. It contains **no** PKCS#11 module: mount or `COPY` your HSM vendor's module and point `module_path` at it |
| local only, `--target softhsm` | `Dockerfile.pkcs11` | **development only**: adds SoftHSM2 and provisions a software token with a fresh P-256 key |

To try the HSM-backed key locally with SoftHSM, no HSM needed:

```sh
docker compose -f docker-compose.softhsm.yml up --build
curl -s localhost:8080/auth/.well-known/jwks.json   # the kid is the thumbprint of the key in the token
```

The entrypoint (`scripts/softhsm-entrypoint.sh`) initialises the token on first start, imports a generated key (the PEM is deleted afterwards), looks up the slot id (SoftHSM renumbers it), renders `configs/config.pkcs11-softhsm.yaml` and starts the server. The token lives in the `softhsm` volume, so the `kid` is stable across restarts; `docker compose -f docker-compose.softhsm.yml down -v` makes a new key. The default PINs are for development only (`SOFTHSM_USER_PIN`, `SOFTHSM_SO_PIN`). `make docker-build-pkcs11` and `make docker-build-softhsm` build the images locally.

#### Using a real HSM (module, module config and module path are injected)

The `runtime` image deliberately ships no PKCS#11 module. A real HSM comes with its own module, its own libraries and its own configuration; the deployer supplies all three, and nothing is baked into the image:

| What | How it is injected |
|---|---|
| The module (`.so`) and any libraries it needs | a read-only volume, for example `-v /opt/vendor/hsm:/opt/vendor:ro`; if the module needs libraries the image lacks, set `LD_LIBRARY_PATH` (for example `/opt/vendor`) |
| The path to the module | `as.signing_key_pkcs11.module_path`, or the environment variable `WALLET_AS_SIGNING_KEY_PKCS11_MODULE_PATH` |
| Slot, key label, PIN file, pool size | `slot_id`, `key_label`, `pin_path`, `pool_size`, or `WALLET_AS_SIGNING_KEY_PKCS11_SLOT_ID` / `_KEY_LABEL` / `_PIN_PATH` / `_POOL_SIZE`. Use `pin_path` with a mounted secret rather than an inline `pin` |
| The module's own configuration | whatever the vendor's module reads: a config file on a mounted volume plus the environment variable that points to it (for example `SOFTHSM2_CONF`, `YUBIHSM_PKCS11_CONF`, `ChrystokiConfigurationPath`, `PKCS11_PROXY_SOCKET`). The module is loaded into the server process, so it sees the container's environment as is |

The server runs as uid/gid 65532, so mounted files and any device or socket the module uses must be readable by that user. The same variables work for the wallet-provider key (`wallet_provider.pkcs11`, `WALLET_WALLET_PROVIDER_PKCS11_*`). `docker-compose.hsm.example.yml` shows the shape. This is tested with the plain `runtime` image by mounting SoftHSM's module, its libraries and its config as if they were a vendor's, using only the variables above (no signing key in the config file).

If the module cannot be loaded the server stops with `pkcs11pool: failed to load module: <path>`; it never falls back to a file key for the AS. If an HSM key is configured but the binary is the default distroless build, startup stops with a message naming the `go-wallet-backend-pkcs11` image (no stack trace); a configured `wallet_provider.pkcs11` that cannot be used is logged at error level at startup, together with whether `wallet_provider.private_key_path` is the fallback.

### Go-live checklist for removing the legacy path

0. **Precondition: all clients are moved to session mode BEFORE any backend turns legacy off** (siros-sdk-kotlin#235, siros-sdk-swift#179, wallet-frontend#322; go-siros-cli is intentionally out of scope).
1. Client audit clean: no client reads the body `appToken`, calls `/user/*-webauthn-*` or omits `X-Token-Mode: session`.
2. Any separate process validating session tokens (the registry: see #430) is migrated off the shared secret.
3. `client_mode=legacy` at zero for a full token lifetime plus refresh TTL.
4. Flip `as.legacy.enabled=false`; `jwt.secret` stays only for the OIDC state cookie.
5. After burn-in, delete `internal/as/legacy_token.go`, the HS256 `generateToken`/refresh paths in `internal/service`, the HMAC fallbacks in `pkg/middleware/auth.go`, `internal/engine/session.go`, `internal/websocket/manager.go`, the `Legacy` config and the `/user/*` login routes.
6. Rollback before step 5: set `as.legacy.enabled=true` and restart.

### Refresh token handling

- **Legacy mode**: legacy refresh tokens are issued and refreshed through `/user/session/refresh`, with the `jwt.expiry_hours` / `jwt.refresh_days` lifetimes (no reduced expiry).
- **New mode**: No refresh tokens. The session cookie plus `/auth/token` replaces this.

### Unified auth middleware

The middleware accepts both modes transparently:

```
Incoming request
     ↓
┌─ Has session cookie?
│   YES → new-style: validate asymmetric access token in Bearer header
│   NO  → Has Bearer token?
│         YES → try HMAC validation (legacy all-in-one token)
│               check exp, check revocation by jti
│         NO  → 401 Unauthorized
```

Backend service code sees the same context (`user_id`, `tenant_id`, `tac`) regardless of which auth path was taken.

### Monitoring and per-tenant control

- Log `client_mode=legacy|session` on every authenticated request for migration tracking
- Optional per-tenant override of `legacy.enabled` for early-adopter tenants

## Open questions

- Should the `/token` endpoint align with RFC 8693 (Token Exchange) for interoperability?
- What is the maximum session lifetime before re-authentication is required?
- Should `acr` drive step-up authentication requirements (e.g., require passkey for certain `tac` values even if session was established via OIDC)?

## Implementation plan

### Phase 1: Core token infrastructure

**Goal:** Asymmetric key signing for new-style access tokens alongside the existing HMAC infrastructure.

| Task | New/Modify | Description |
|------|-----------|-------------|
| 1.1 Key manager | New: `internal/as/keys.go` | Load ECDSA P-256 / EdDSA key pair from config (file or PKCS#11 via go-cryptoutil). Maintain `kid` → key mapping. Support multiple active keys for rotation. |
| 1.2 JWKS endpoint | New: `internal/as/jwks.go` | Serve `GET /.well-known/jwks.json` — export public keys in JWK format. |
| 1.3 Access token type | New: `internal/as/token.go` | `AccessTokenClaims` struct with `tac` field. Sign with asymmetric key, include `kid` header. TTL: 2 min default. |
| 1.4 Config extension | Modify: `pkg/config/config.go` | Add `AS` config section: signing key path/PKCS#11 URI, key rotation, default TTL, SPOCP rules dir, OIDC RP settings, legacy block. |

### Phase 2: Session management

**Goal:** Separate session identity from access authorization.

| Task | New/Modify | Description |
|------|-----------|-------------|
| 2.1 Session store | New: `internal/as/session.go` | Interface-backed session store (in-memory + Redis). Store session JWTs keyed by `jti`. |
| 2.2 Session cookie | New: `internal/as/cookie.go` | Issue `__Host-session` cookie. Cookie-to-session lookup. |
| 2.3 Session middleware | New: `internal/as/middleware.go` | Reads session cookie → resolves session → validates → sets context. |
| 2.4 ACR tracking | Integrated | Record `acr` at login time into session JWT. |

### Phase 3: Legacy compatibility layer

**Goal:** Existing clients continue working without modification.

| Task | New/Modify | Description |
|------|-----------|-------------|
| 3.1 Client detection | New: `internal/as/compat.go` | Detect legacy vs new-style from `X-Token-Mode` header. |
| 3.2 Legacy token issuer | New: `internal/as/legacy_token.go` | Issue HMAC all-in-one JWTs with the `jwt.expiry_hours` lifetime. |
| 3.3 Dual-mode login response | New: `internal/as/passkey.go`, `internal/as/oidc.go` | Based on client mode, return `appToken` in body (legacy) or set session cookie (new). |
| 3.4 Deprecation headers | New: `internal/as/deprecation.go` | `DeprecationMiddleware` exists but is not mounted, so no `Deprecation` header is sent yet. |
| 3.5 Refresh token compat | `/user/session/refresh` | Legacy refresh stays on the existing `/user/session/refresh` route; no `/auth/token/refresh` bridge route exists. |
| 3.6 Unified auth middleware | Modify: `pkg/middleware/auth.go` | Single middleware accepting both session-cookie+access-token and legacy Bearer tokens. Sets identical context. |

### Phase 4: SPOCP policy authorization

**Goal:** Policy-controlled token issuance via `/auth/token`.

| Task | New/Modify | Description |
|------|-----------|-------------|
| 4.1 SPOCP engine | New: `internal/as/policy.go` | Initialize `spocp.AdaptiveEngine`, load rules from configured directory. Interface-backed. |
| 4.2 Query builder | New: `internal/as/query.go` | Convert token request + session claims → SPOCP S-expression. Deterministic key ordering. |
| 4.3 Token endpoint | New: `internal/as/token_endpoint.go` | `POST /auth/token` — resolve session, validate, build candidate, SPOCP evaluate, sign + return or 403. |
| 4.4 Default rules | New: `rules/` directory | Ship defaults: own-tenant access, admin for cross-tenant, `r`+`l` always allowed. |

### Phase 5: Authentication endpoints

**Goal:** Re-route authentication under `/auth/` prefix, issue sessions.

| Task | New/Modify | Description |
|------|-----------|-------------|
| 5.1 Passkey auth | Refactor from `internal/service/webauthn.go` | `POST /auth/passkey/{register,login}/{begin,finish}`. Create session on success, set cookie, set `acr`. |
| 5.2 OIDC RP auth | New: `internal/as/oidc.go` | `GET /auth/oidc/login` → redirect. `GET /auth/oidc/callback` → validate, create session, set `acr`. |
| 5.3 Logout | New: `internal/as/logout.go` | `DELETE /auth/session` → revoke session, clear cookie. |

### Phase 6: Delegation

**Goal:** Tokens with `k` permission can issue downscoped tokens.

| Task | New/Modify | Description |
|------|-----------|-------------|
| 6.1 Bearer-based token request | Extend: `internal/as/token_endpoint.go` | When Bearer token present instead of session cookie, treat as delegation. Validate `k` in `tac`, enforce subset + tenant match. |
| 6.2 Delegation SPOCP rules | Extend: `rules/` | Separate ruleset for delegation queries. |

### Phase 7: Shared token validation library (`go-tokenauth`)

**Goal:** A single shared Go module that any service in the siros ecosystem can import to validate AS-issued tokens. This replaces the per-service middleware duplication in go-wallet-backend (`pkg/middleware`), facetec-api (`internal/middleware`), and vc (`pkg/httphelpers`).

**Module:** `github.com/sirosfoundation/go-tokenauth`

**Why a new module (not go-cryptoutil):** go-cryptoutil is a low-level crypto library with no HTTP dependencies. Token validation is HTTP-middleware-level concern with dependencies on Gin, JWKS fetching, caching, and context propagation.

#### Package structure

```
go-tokenauth/
├── go.mod
├── jwks/           # JWKS fetching and caching
│   └── jwks.go    # Fetcher with background refresh, key lookup by kid
├── claims/         # Token claims types and parsing
│   └── claims.go  # AccessTokenClaims, LegacyClaims, TAC utilities
├── validator/      # Core validation logic (framework-agnostic)
│   └── validator.go
├── gin/            # Gin middleware adapter
│   └── middleware.go
└── revocation/     # Revocation checking interface + implementations
    ├── interface.go
    ├── memory.go
    └── redis.go
```

#### Key types and interfaces

```go
package claims

// AccessTokenClaims represents a new-style asymmetric access token.
type AccessTokenClaims struct {
    jwt.RegisteredClaims
    TenantID string `json:"tenant_id"`
    TAC      TAC    `json:"tac"`
    ACR      string `json:"acr"`
}

// TAC is the token access control permission set.
type TAC string

func (t TAC) Has(perm byte) bool   // Check single permission
func (t TAC) HasAll(perms string) bool
func (t TAC) IsSubsetOf(other TAC) bool
```

```go
package validator

// Config configures the token validator.
type Config struct {
    // New-style token validation
    JWKSURL        string        // e.g., "https://as.example.com/.well-known/jwks.json"
    JWKSRefresh    time.Duration // Background refresh interval (default: 5m)
    Issuer         string        // Expected iss claim
    Audiences      []string      // Accepted aud values (this service's identifiers)

    // Legacy token validation (only while as.legacy.enabled)
    Legacy         LegacyConfig

    // Revocation
    Revocation     RevocationChecker // nil = no revocation checking
}

type LegacyConfig struct {
    Enabled    bool
    HMACSecret []byte   // Existing HMAC secret for legacy tokens
    Issuers    []string // Accepted legacy issuers
}

// RevocationChecker checks whether a token has been revoked.
type RevocationChecker interface {
    IsRevoked(ctx context.Context, jti string) bool
}

// Result is the validated identity context extracted from a token.
type Result struct {
    UserID   string
    DID      string
    TenantID string
    TAC      claims.TAC
    ACR      string
    JTI      string
    Mode     AuthMode // Legacy or Session
}

type AuthMode string
const (
    ModeLegacy  AuthMode = "legacy"
    ModeSession AuthMode = "session"
)
```

```go
package gin

// TokenAuth returns Gin middleware that validates both legacy and new-style tokens.
// It sets the validated Result into the Gin context for downstream handlers.
func TokenAuth(cfg validator.Config) gin.HandlerFunc

// MustHaveTAC returns Gin middleware that requires specific TAC permissions.
// Must be placed after TokenAuth in the middleware chain.
func MustHaveTAC(required string) gin.HandlerFunc

// GetResult extracts the validated token result from the Gin context.
func GetResult(c *gin.Context) (*validator.Result, bool)
```

#### Validation logic

The validator implements the dual-mode logic:

1. Extract Bearer token from `Authorization` header
2. Parse JWT header (without verifying) to determine token type:
   - `alg: HS256` → legacy path: validate with HMAC secret (if `Legacy.Enabled`)
   - `alg: ES256/EdDSA` + `kid` present → new-style path: validate with JWKS
3. Verify signature, `exp`, `nbf`, `iss`, `aud`
4. If revocation checker configured, check `jti`
5. Extract claims into `Result`
6. Set `Result` in Gin context

#### JWKS package

```go
package jwks

// Fetcher maintains a cached copy of JWKS keys from a remote endpoint.
type Fetcher struct { /* ... */ }

func NewFetcher(url string, refreshInterval time.Duration) *Fetcher
func (f *Fetcher) Start(ctx context.Context) // Start background refresh
func (f *Fetcher) GetKey(kid string) (crypto.PublicKey, error)
func (f *Fetcher) Stop()
```

Features:
- Background goroutine refreshes keys periodically
- Graceful handling of AS downtime (serves stale keys with warning log)
- On-demand fetch if `kid` not found in cache (handles key rotation race)
- Thread-safe

#### Adoption path

| Service | Current middleware | Migration |
|---------|---|---|
| **go-wallet-backend** | `pkg/middleware/auth.go` | Phase 3.6 replaces with `go-tokenauth/gin.TokenAuth()` |
| **facetec-api** | `internal/middleware/middleware.go` | Import `go-tokenauth`, replace `jwtTenantAuth()` with `gin.TokenAuth()` |
| **vc** | `pkg/httphelpers` | Import `go-tokenauth`, wire into httphelpers server setup |
| **go-r2ps-service** | (if applicable) | Same pattern |

Each service configures with its own `JWKSURL`, `Audiences`, and optionally its own `RevocationChecker` implementation.

| Task | New/Modify | Description |
|------|-----------|-------------|
| 7.1 go-tokenauth module | New repo: `github.com/sirosfoundation/go-tokenauth` | Shared validation library: JWKS fetcher, dual-mode validator, Gin middleware, TAC utilities, revocation interface. |
| 7.2 Adopt in go-wallet-backend | Modify: `pkg/middleware/auth.go` | Replace existing JWT validation with `go-tokenauth`. |
| 7.3 Adopt in facetec-api | Modify: `internal/middleware/middleware.go` | Replace `jwtTenantAuth()` with `go-tokenauth/gin.TokenAuth()`. |
| 7.4 Adopt in vc | Modify: `pkg/httphelpers` | Wire `go-tokenauth` into existing server setup. |

### Phase 8: Revocation and security hardening

**Goal:** Token and session revocation, abuse prevention.

| Task | New/Modify | Description |
|------|-----------|-------------|
| 8.1 Revocation store | New: `internal/as/revocation.go` | AS-side revocation store keyed by `jti`. Backs the `RevocationChecker` interface. |
| 8.2 Revocation implementations | In `go-tokenauth/revocation/` | In-memory (with periodic cleanup) and Redis implementations of `RevocationChecker`. |
| 8.3 Rate limiting | Extend token endpoint | Rate-limit `/auth/token` to prevent token spray. |

### Phase 9: RouteProvider integration

**Goal:** Wire into mode-based routing, maintain backward compatibility during migration.

| Task | New/Modify | Description |
|------|-----------|-------------|
| 9.1 AS provider | New: `internal/as/provider.go` | Implement `RouteProvider`. Register `/auth/*` and `/.well-known/jwks.json`. |
| 9.2 New mode | Modify: `internal/modes/modes.go` | Add `RoleAuth`. Support `--mode=auth`, `--mode=backend,auth`, `--mode=all`. |
| 9.3 Frontend integration | Coordinate | Update wallet-frontend login flow to use session cookies + `/auth/token`. |

### Implementation order

Phases 1–5 form the **MVP**. Phase 3 (legacy compat) is critical for day-one deployment — the new AS must be a drop-in replacement for existing clients.

Phase 6 (delegation) follows once the core is stable.

**Phase 7 (go-tokenauth) can be developed in parallel** with Phases 1–5, since it only needs to know the token format and JWKS endpoint contract. It should be ready before facetec-api and vc are updated to validate new-style tokens.

Phases 8–9 follow once the shared library is adopted.

### Key dependencies

- **go-spocp** (`github.com/sirosfoundation/go-spocp`): Already in `go.mod`, unused. Provides `AdaptiveEngine` for policy evaluation.
- **go-cryptoutil** (`github.com/sirosfoundation/go-cryptoutil`): PKCS#11 key loading if HSM-backed signing is needed.
- **go-tokenauth** (`github.com/sirosfoundation/go-tokenauth`): New shared library. All backend services import this for token validation.

---

## Implementation Status

### Completed (PR #229)

| Phase | Status | Tests |
|-------|--------|-------|
| Phase 1: Core token infrastructure | ✅ Done | Key loading, JWKS, token issue/verify, TAC |
| Phase 2: Session management | ✅ Done | In-memory store, cookie, cleanup |
| Phase 3: Legacy compatibility | ✅ Done | HMAC tokens, deprecation headers, compat mode |
| Phase 4: SPOCP policy authorization | ✅ Done | Policy evaluation, deny paths, query endpoint |
| Phase 5: Authentication endpoints | ✅ Done | Middleware, OIDC RP, passkey scaffolding |
| Phase 6: Delegation | ✅ Done | Downscope, re-delegation, cross-tenant denial |

**97 tests**, 62% statement coverage.

### Security hardening applied

- **Session/token binding**: `UnifiedAuthMiddleware` verifies the Bearer token's `sub` matches the session's `UserID` (prevents token/session mixing attacks).
- **Tenant enforcement**: Session-based token issuance rejects cross-tenant requests unless the session is cross-tenant (`TenantID == "*"`).
- **OIDC security**: Uses `cfg.ExternalURL` (not `Host` header) for redirect URIs; nonce is SHA-256 hashed in the OIDC state; all params use `url.Values` encoding.
- **Cookie security**: `__Host-` prefix with hardcoded `Secure=true`, `Path=/`, `HttpOnly`, `SameSite=Strict`.
- **HTTP client timeout**: OIDC token exchange uses 30s timeout.
- **TAC validation**: `TokenIssuer.Issue()` and `ParseAndVerify()` both validate TAC characters.
- **JWKS defensive copy**: `KeyManager.JWKS()` returns a copy of the key slice to prevent caller mutation.
- **Lifecycle management**: Session cleanup goroutine is tied to a cancellable context (not `context.Background()`).

### Phase 7: go-tokenauth (separate repo)

Status: ✅ Complete — `github.com/sirosfoundation/go-tokenauth` published with:
- JWKS fetcher with background refresh
- Dual-mode validator (HMAC legacy + asymmetric new-style)
- Gin middleware (`TokenAuth`, `MustHaveTAC`, `GetResult`)
- Revocation checker interface
- 19 tests passing
- Full CI/CD scaffolding (lint, security, CodeQL, SBOM, Scorecard, SonarCloud)

### Remaining work

| Phase | Task | Notes |
|-------|------|-------|
| 7.2 | Adopt go-tokenauth in go-wallet-backend | Replace `pkg/middleware/auth.go` |
| 7.3 | Adopt go-tokenauth in facetec-api | Replace `jwtTenantAuth()` |
| 7.4 | Adopt go-tokenauth in vc | Wire into httphelpers |
| 8 | Revocation + rate limiting | Revocation store, Redis checker, rate limits |
| 9 | RouteProvider integration | Mode-based routing, frontend coordination |
- **go-ztts** (discontinued): Reference patterns for SPOCP query construction, revocation store, replay guard, and per-profile key management.