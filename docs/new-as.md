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

## Open questions

- Should the `/token` endpoint align with RFC 8693 (Token Exchange) for interoperability?
- What is the maximum session lifetime before re-authentication is required?
- Should `acr` drive step-up authentication requirements (e.g., require passkey for certain `tac` values even if session was established via OIDC)?
