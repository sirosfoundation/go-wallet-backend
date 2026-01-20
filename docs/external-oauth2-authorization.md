# External OAuth2 Authorization Server Support

**Status**: Proposal  
**Date**: 2026-01-20  
**Author**: Analysis Document

## Executive Summary

This document analyzes options for adding external OAuth2/OIDC authorization server support to the wallet system. This would enable organizations to use their existing identity infrastructure (Azure AD, Okta, Keycloak, etc.) for wallet authentication.

## Current Authentication Architecture

### go-wallet-backend

The backend currently uses **WebAuthn (passkeys)** as the primary authentication mechanism:

- **Registration**: `/webauthn/register/start` → `/webauthn/register/finish`
- **Login**: `/webauthn/login/start` → `/webauthn/login/finish`
- **Token Format**: Self-issued JWT (HS256) signed with shared secret

Current JWT claims structure:
```go
claims := jwt.MapClaims{
    "user_id": user.UUID.String(),
    "did":     user.DID,
    "iss":     s.cfg.JWT.Issuer,
    "exp":     time.Now().Add(time.Duration(s.cfg.JWT.ExpiryHours) * time.Hour).Unix(),
    "iat":     time.Now().Unix(),
}
```

### wallet-frontend

- Stores `appToken` in session storage
- Sends `Authorization: Bearer <token>` with API requests
- Session management via `SessionContextProvider`
- Supports offline authentication via cached credentials

### Middleware

`AuthMiddleware` validates JWTs using HMAC (shared secret):
- Extracts `user_id` and `did` from claims
- Sets context for downstream handlers

## Business Drivers

1. **Enterprise Adoption**: Organizations want to use existing IdPs
2. **Single Sign-On (SSO)**: Reduce friction for enterprise users
3. **Compliance**: Meet organizational authentication policies
4. **Centralized Access Control**: Leverage IdP's MFA, conditional access
5. **User Provisioning**: Integrate with HR systems via IdP

## Option A: External IdP as Primary Authentication

### Overview

The wallet backend becomes an **OAuth2 Resource Server**, delegating all authentication to external identity providers.

### Architecture

```
┌─────────────┐    ┌───────────────┐    ┌─────────────────────┐
│   Wallet    │───►│  External IdP │───►│   Wallet Backend    │
│  Frontend   │◄───│  (Keycloak)   │◄───│ (Resource Server)   │
└─────────────┘    └───────────────┘    └─────────────────────┘
```

### Flow

1. User clicks "Login" in wallet frontend
2. Frontend redirects to external IdP
3. User authenticates with IdP (password, MFA, etc.)
4. IdP redirects back with authorization code
5. Frontend exchanges code for tokens (ID token + access token)
6. Frontend calls backend API with access token
7. Backend validates token via IdP's JWKS endpoint

### Backend Changes Required

- Replace `AuthMiddleware` to validate RS256/ES256 JWTs
- Implement JWKS caching and rotation
- Map external `sub` claim to internal user ID
- Auto-create users on first login (optional)
- Remove WebAuthn registration/login endpoints

### Configuration

```yaml
auth:
  type: "external"
  oidc:
    issuer: "https://idp.example.com/realms/wallet"
    audience: "wallet-backend"
    jwks_cache_ttl: "1h"
```

### Pros

- Standard OAuth2/OIDC implementation
- Enterprise-ready from day one
- Leverages mature IdP security features
- Single source of truth for identities

### Cons

- **Removes WebAuthn support entirely**
- **No offline authentication possible**
- Requires IdP infrastructure
- Increases dependency on external systems
- May not suit individual users without enterprise IdP

### Effort Estimate

- Backend: ~2 weeks
- Frontend: ~1 week
- Testing/Integration: ~1 week

---

## Option B: Hybrid Model (WebAuthn + External IdP)

### Overview

Keep WebAuthn as the primary authentication method, add external IdP as an **alternative authentication path**. Users can choose their preferred method.

### Architecture

```
┌─────────────┐
│   Wallet    │
│  Frontend   │
└─────┬───────┘
      │
      ├──── WebAuthn (existing) ────► Direct authentication
      │                               └─► Internal JWT
      │
      └──── External IdP (new) ──────► OAuth2 flow
                                       └─► Account linking
                                       └─► Internal JWT
```

### Flow (External IdP Path)

1. User clicks "Sign in with Corporate SSO"
2. Frontend initiates OAuth2 authorization code flow with PKCE
3. Backend generates state, stores in session
4. User redirects to IdP, authenticates
5. IdP redirects to backend callback endpoint
6. Backend validates code, retrieves tokens
7. Backend looks up or creates linked user
8. Backend issues internal JWT (same format as WebAuthn)
9. Frontend receives JWT, continues normally

### Backend Changes Required

**New Endpoints:**
```
GET  /auth/providers                    # List configured IdPs
GET  /auth/external/{provider}/authorize  # Initiate OAuth2 flow
GET  /auth/external/{provider}/callback   # Handle IdP callback
POST /auth/external/link                # Link existing account to IdP
DELETE /auth/external/link/{provider}   # Unlink IdP from account
```

**New Domain Models:**
```go
// ExternalIdentity links external IdP identities to wallet users
type ExternalIdentity struct {
    ID          string    `json:"id"`
    UserID      UserID    `json:"user_id"`      // Internal wallet user
    Provider    string    `json:"provider"`     // "azure-ad", "keycloak"
    Subject     string    `json:"subject"`      // IdP's sub claim
    Email       string    `json:"email"`        // From IdP (for display)
    LinkedAt    time.Time `json:"linked_at"`
    LastLoginAt time.Time `json:"last_login_at"`
}

// OIDCProvider represents a configured external IdP
type OIDCProvider struct {
    ID           string   `json:"id"`
    Name         string   `json:"name"`          // Display name
    Type         string   `json:"type"`          // "oidc", "saml"
    Issuer       string   `json:"issuer"`
    ClientID     string   `json:"client_id"`
    ClientSecret string   `json:"-"`             // Never expose
    Scopes       []string `json:"scopes"`
    Enabled      bool     `json:"enabled"`
}
```

**New Packages:**
```
pkg/
  oidc/
    provider.go      # OIDC provider configuration
    client.go        # OIDC RP client (authorization, token exchange)
    jwks.go          # JWKS fetching and caching
    claims.go        # Claim mapping and validation
internal/
  domain/
    external_identity.go
  storage/
    external_identity_store.go
  service/
    external_auth.go
  api/
    handlers_external_auth.go
```

### Frontend Changes Required

**New Components:**
```
src/
  pages/Login/
    ExternalLoginButton.tsx  # "Sign in with X" button
    ExternalCallback.tsx     # Handle OAuth2 callback
  pages/Settings/
    LinkedAccounts.tsx       # Manage linked IdPs
  services/
    ExternalAuth.ts          # OAuth2 flow utilities
  hooks/
    useAuthProviders.ts      # Fetch available providers
```

**Login Page Changes:**
- Add "Or sign in with" section
- Display configured IdP buttons
- Handle callback redirect

### Configuration

```yaml
external_auth:
  enabled: true
  allow_account_creation: true      # Create user on first SSO login
  require_account_linking: false    # Require existing account to link
  
  providers:
    - id: "azure-ad"
      name: "Microsoft Azure AD"
      type: "oidc"
      issuer: "https://login.microsoftonline.com/{tenant}/v2.0"
      client_id: "${AZURE_CLIENT_ID}"
      client_secret: "${AZURE_CLIENT_SECRET}"
      scopes: ["openid", "email", "profile"]
      claim_mapping:
        subject: "oid"        # Use oid instead of sub for Azure
        email: "email"
        name: "name"
      enabled: true
      
    - id: "corporate-keycloak"
      name: "Corporate SSO"
      type: "oidc"
      issuer: "https://sso.company.com/realms/employees"
      client_id: "wallet-app"
      client_secret: "${KEYCLOAK_CLIENT_SECRET}"
      scopes: ["openid", "email", "profile", "groups"]
      enabled: true
```

### Tenant Integration

External IdPs can be configured per-tenant:

```yaml
tenants:
  - id: "acme-corp"
    name: "ACME Corporation"
    external_auth:
      required: true              # Force SSO for this tenant
      allowed_providers: ["azure-ad"]
```

### Pros

- **Preserves WebAuthn** for individual users
- **Adds enterprise SSO** without removing existing auth
- **Offline support maintained** (WebAuthn works offline)
- Flexible: users choose authentication method
- Account linking allows gradual migration
- Tenant-aware: different IdPs per organization

### Cons

- More complex implementation
- Two auth paths to maintain
- Account linking UX complexity
- Potential for duplicate accounts if not handled carefully

### Effort Estimate

- Backend: ~3-4 weeks
- Frontend: ~2 weeks
- Testing/Integration: ~1-2 weeks

---

## Option C: Token Exchange (RFC 8693)

### Overview

Implement OAuth 2.0 Token Exchange (RFC 8693) to accept external tokens and exchange them for internal wallet tokens.

### Architecture

```
┌─────────────┐    ┌───────────────┐
│   External  │───►│    Wallet     │
│   System    │    │   Backend     │
└─────────────┘    └───────┬───────┘
                          │
                   Token Exchange
                          │
                   ┌──────▼──────┐
                   │ Internal JWT │
                   └─────────────┘
```

### Flow

1. External system obtains token from its IdP
2. External system calls wallet's token exchange endpoint
3. Wallet validates external token
4. Wallet issues internal JWT for the mapped user

### Endpoint

```
POST /auth/token
Content-Type: application/x-www-form-urlencoded

grant_type=urn:ietf:params:oauth:grant-type:token-exchange
subject_token={external_token}
subject_token_type=urn:ietf:params:oauth:token-type:access_token
requested_token_type=urn:ietf:params:oauth:token-type:access_token
```

### Response

```json
{
  "access_token": "eyJ...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "issued_token_type": "urn:ietf:params:oauth:token-type:access_token"
}
```

### Pros

- Standards-compliant (RFC 8693)
- Enables machine-to-machine integration
- Useful for backend service authentication
- Can coexist with other auth methods

### Cons

- **Not suitable for user-facing authentication**
- Requires trusted relationship with token issuers
- Complex trust configuration
- Limited browser support

### Use Cases

- Backend services calling wallet API
- Automated workflows
- Service accounts

### Effort Estimate

- Backend: ~1-2 weeks
- Frontend: N/A (not user-facing)
- Testing: ~1 week

---

## Comparison Matrix

| Aspect | Option A (External Only) | Option B (Hybrid) | Option C (Token Exchange) |
|--------|-------------------------|-------------------|--------------------------|
| WebAuthn Support | ❌ Removed | ✅ Preserved | ✅ Preserved |
| Offline Support | ❌ None | ✅ Via WebAuthn | ✅ Via WebAuthn |
| Enterprise SSO | ✅ Full | ✅ Full | ⚠️ Backend only |
| Individual Users | ❌ Requires IdP | ✅ WebAuthn | ✅ WebAuthn |
| Implementation | Medium | High | Low |
| Maintenance | Low | Medium | Low |
| Standards | OAuth2/OIDC | OAuth2/OIDC | RFC 8693 |
| User Experience | Simple | Flexible | N/A |

## Recommendation

**Option B (Hybrid Model)** is recommended for the following reasons:

1. **Backward Compatibility**: Existing WebAuthn users continue working
2. **Enterprise Ready**: Organizations can mandate SSO
3. **Flexibility**: Users choose their preferred authentication
4. **Offline Support**: Critical for wallet use cases
5. **Gradual Adoption**: Organizations can migrate at their pace
6. **Tenant Integration**: Natural fit with multi-tenancy

### Suggested Implementation Phases

**Phase 1: Core Infrastructure (2 weeks)**
- OIDC client library
- Provider configuration
- External identity storage

**Phase 2: Backend Endpoints (2 weeks)**
- Authorization initiation
- Callback handling
- Account linking

**Phase 3: Frontend Integration (2 weeks)**
- Login page SSO buttons
- Callback handling
- Settings page for linked accounts

**Phase 4: Tenant Integration (1 week)**
- Per-tenant provider configuration
- Required SSO enforcement

**Phase 5: Testing & Documentation (1 week)**
- Integration tests
- Security review
- Documentation

## Security Considerations

### All Options

1. **PKCE**: Mandatory for all OAuth2 flows (RFC 7636)
2. **State Parameter**: Prevent CSRF attacks
3. **Nonce**: Required for ID token validation
4. **Token Binding**: Consider DPoP for enhanced security
5. **HTTPS**: All endpoints must use TLS

### Account Linking (Option B)

1. **Re-authentication**: Require current auth before linking
2. **Email Verification**: Verify IdP email matches (optional)
3. **Audit Logging**: Log all linking/unlinking events
4. **Rate Limiting**: Prevent enumeration attacks

### Token Exchange (Option C)

1. **Trusted Issuers**: Explicitly whitelist allowed token issuers
2. **Audience Validation**: Verify tokens are intended for wallet
3. **Subject Mapping**: Secure mapping of external to internal users

## Open Questions

1. Should account creation be automatic on first SSO login?
2. Should users be able to unlink their only authentication method?
3. How to handle IdP-initiated logout (back-channel)?
4. Should we support SAML 2.0 in addition to OIDC?
5. How to handle IdP unavailability (fallback to WebAuthn)?

## References

- [RFC 6749 - OAuth 2.0](https://tools.ietf.org/html/rfc6749)
- [RFC 7636 - PKCE](https://tools.ietf.org/html/rfc7636)
- [RFC 8693 - Token Exchange](https://tools.ietf.org/html/rfc8693)
- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
- [WebAuthn Level 2](https://www.w3.org/TR/webauthn-2/)
