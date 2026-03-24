# OIDC Gate for Wallet Registration/Authentication

## Overview

Protect wallet registration and/or authentication endpoints with OpenID Connect authorization. Users must authenticate with an enterprise IdP (OP) before accessing the wallet.

## Use Cases

| Mode | Registration | Login | Example |
|------|-------------|-------|---------|
| `registration` | Protected | Open | Enterprise onboarding: employees must prove corporate identity to register |
| `login` | Open | Protected | Step-up auth: require enterprise login before wallet access |
| `both` | Protected (OP-A) | Protected (OP-B) | Different OPs per operation, or same OP |
| `none` | Open | Open | Default behavior (unchanged) |

## Design Decisions (Open Questions)

### 1. Token Type
- **Option A**: Validate ID tokens only (standard OIDC)
- **Option B**: Support access token + introspection endpoint
- **Recommendation**: Start with ID tokens; add access token support later if needed

### 2. Identity Binding
- **Option A**: One-time gate - validate token, proceed; no persistent link
- **Option B**: Bind enterprise `sub` to wallet user (audit trail, recovery)
- **Recommendation**: Support both via config flag `bind_identity`

### 3. Claim Requirements
- Validate issuer + audience (required)
- Optional: require specific claims (e.g., `email_verified: true`, `groups` membership)

### 4. Flow Orchestration
- **Frontend-driven (SPA)**: Frontend handles PKCE flow, passes ID token to backend
- **Backend-redirect**: Backend initiates authorization code flow
- **Recommendation**: Frontend-driven for wallet-frontend; document backend approach for other clients

## Architecture

```
┌─────────────┐     ┌──────────────┐     ┌─────────────┐
│   Frontend  │◄───►│ Enterprise   │     │  Wallet     │
│   (SPA)     │     │ IdP (OP)     │     │  Backend    │
└─────┬───────┘     └──────────────┘     └──────┬──────┘
      │                                         │
      │ 1. GET /api/v1/tenants/{id}             │
      │────────────────────────────────────────►│
      │       {oidc_gate: {...config...}}       │
      │◄────────────────────────────────────────│
      │                                         │
      │ 2. OIDC PKCE flow with IdP              │
      │◄──────────────────────────►             │
      │                                         │
      │ 3. POST /webauthn/register/start        │
      │    Authorization: Bearer <id_token>     │
      │────────────────────────────────────────►│
      │       (middleware validates token)      │
      │◄────────────────────────────────────────│
```

## Data Model

### Tenant Configuration Extension

```go
// OIDCGateMode defines which endpoints are protected
type OIDCGateMode string

const (
    OIDCGateModeNone         OIDCGateMode = "none"
    OIDCGateModeRegistration OIDCGateMode = "registration"
    OIDCGateModeLogin        OIDCGateMode = "login"
    OIDCGateModeBoth         OIDCGateMode = "both"
)

// OIDCGateConfig configures OIDC pre-authentication gates
type OIDCGateConfig struct {
    Mode OIDCGateMode `json:"mode" bson:"mode"`
    
    // OIDC Provider for registration gate
    RegistrationOP *OIDCProviderConfig `json:"registration_op,omitempty" bson:"registration_op,omitempty"`
    
    // OIDC Provider for login gate (nil = same as registration_op)
    LoginOP *OIDCProviderConfig `json:"login_op,omitempty" bson:"login_op,omitempty"`
    
    // Required claims for validation (e.g., {"email_verified": true})
    RequiredClaims map[string]interface{} `json:"required_claims,omitempty" bson:"required_claims,omitempty"`
    
    // Bind enterprise sub to wallet user
    BindIdentity bool `json:"bind_identity" bson:"bind_identity"`
}

// OIDCProviderConfig defines an OIDC provider for validation
type OIDCProviderConfig struct {
    // User-friendly display name (e.g., "Corporate SSO", "University Login")
    DisplayName string `json:"display_name,omitempty" bson:"display_name,omitempty"`
    
    // Issuer URL (used for token validation and OIDC discovery)
    Issuer string `json:"issuer" bson:"issuer"`
    
    // Client ID (public client for PKCE - no secret needed)
    ClientID string `json:"client_id" bson:"client_id"`
    
    // Optional: explicit JWKS URI (otherwise discovered from issuer)
    JWKSURI string `json:"jwks_uri,omitempty" bson:"jwks_uri,omitempty"`
    
    // Optional: required audience (defaults to client_id)
    Audience string `json:"audience,omitempty" bson:"audience,omitempty"`
    
    // Optional: OIDC scopes to request (defaults to "openid profile email")
    Scopes string `json:"scopes,omitempty" bson:"scopes,omitempty"`
}
```

### User Extension (if bind_identity = true)

```go
// EnterpriseIdentity stores bound enterprise IdP identity
type EnterpriseIdentity struct {
    Issuer    string    `json:"issuer" bson:"issuer"`
    Subject   string    `json:"subject" bson:"subject"`
    BindingAt time.Time `json:"binding_at" bson:"binding_at"`
}
```

## Implementation Plan

### Phase 1: Backend Core (go-wallet-backend)

1. **Domain model** - Add `OIDCGateConfig` to Tenant struct
2. **OIDC validation** - New `pkg/oidc` package for ID token validation
   - JWKS fetching/caching
   - Token signature verification
   - Claims validation
3. **Middleware** - `OIDCGateMiddleware` for conditional endpoint protection
4. **Admin API** - Update tenant CRUD to support `oidc_gate` configuration
5. **CLI** - Add `wallet-admin tenant configure-oidc-gate` command

### Phase 2: Frontend Integration (wallet-frontend)

1. **OIDC client** - Integrate `oidc-client-ts` library
2. **Gate flow** - Intercept registration/login, redirect to OP if configured
3. **Token passing** - Include ID token in Authorization header
4. **Error handling** - Handle token validation failures gracefully

### Phase 3: Testing & Documentation

1. **Unit tests** - Token validation, middleware behavior
2. **Integration tests** - Full flow with mock IdP
3. **Documentation** - Admin guide for configuring OIDC gates

## API Changes

### GET /api/v1/tenants/{id}

Response includes new field:
```json
{
  "id": "acme",
  "name": "ACME Corp",
  "oidc_gate": {
    "mode": "registration",
    "registration_op": {
      "display_name": "Corporate SSO",
      "issuer": "https://login.acme.com",
      "client_id": "wallet-app",
      "scopes": "openid profile email groups"
    },
    "bind_identity": true
  }
}
```

### Protected Endpoints (when gate is active)

Require `Authorization: Bearer <id_token>` header:
- `POST /webauthn/register/start` (if mode = "registration" or "both")
- `POST /webauthn/login/start` (if mode = "login" or "both")

Response on missing/invalid token: `401 Unauthorized`
```json
{
  "error": "oidc_gate_required",
  "message": "OIDC authentication required",
  "oidc_config": {
    "display_name": "Corporate SSO",
    "issuer": "https://login.acme.com",
    "client_id": "wallet-app",
    "scopes": "openid profile email groups"
  }
}
```

## Security Considerations

1. **Token replay** - Consider short-lived tokens + nonce binding
2. **JWKS caching** - Implement cache with reasonable TTL (e.g., 1 hour)
3. **Clock skew** - Allow configurable leeway for exp/iat/nbf validation
4. **Error messages** - Avoid leaking sensitive info in validation errors

## Open Questions

1. Should we support OIDC discovery, or require explicit JWKS URI?
2. Do we need to store the ID token for audit purposes?
3. Should claim requirements be per-OP or shared?
4. How to handle token refresh for long registration flows?
