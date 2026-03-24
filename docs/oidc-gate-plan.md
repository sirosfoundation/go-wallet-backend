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

---

## Frontend Implementation Plan (wallet-frontend)

### Overview

The frontend needs to detect OIDC gate requirements and redirect users through enterprise IdP authentication before allowing registration/login. The flow is frontend-driven using PKCE.

### Phase 1: API Types & Tenant Config (2-3 hours)

**Files to modify:**
- `src/api/types.ts` - Add OIDC gate types
- `src/context/TenantContext.tsx` - Extend with tenant config fetching

**Types to add:**
```typescript
// src/api/types.ts
export interface OIDCProviderConfig {
  display_name?: string;
  issuer: string;
  client_id: string;
  scopes?: string;
}

export interface OIDCGateConfig {
  mode: 'none' | 'registration' | 'login' | 'both';
  registration_op?: OIDCProviderConfig;
  login_op?: OIDCProviderConfig;
  bind_identity?: boolean;
}

export interface TenantConfig {
  id: string;
  name: string;
  display_name?: string;
  oidc_gate?: OIDCGateConfig;
  // ... other fields
}
```

**TenantContext changes:**
- Add state for `tenantConfig: TenantConfig | null`
- Fetch tenant config from `/api/v1/tenants/{id}` on mount
- Expose `requiresOIDCGateForRegistration()` and `requiresOIDCGateForLogin()` helpers

### Phase 2: OIDC Client Integration (4-6 hours)

**New files:**
- `src/lib/oidc.ts` - OIDC PKCE flow utilities
- `src/hooks/useOIDCGate.ts` - React hook for OIDC gate flow

**Implementation approach:**
1. Use `oidc-client-ts` library (standard, well-maintained)
2. Implement PKCE authorization code flow
3. Store tokens in sessionStorage (short-lived)

**Core functions in `src/lib/oidc.ts`:**
```typescript
interface OIDCConfig {
  issuer: string;
  clientId: string;
  redirectUri: string;
  scopes: string;
}

// Initialize OIDC client for given config
function createOIDCClient(config: OIDCConfig): UserManager;

// Start authorization flow (redirects to IdP)
async function startOIDCFlow(client: UserManager): Promise<void>;

// Handle callback from IdP, extract ID token
async function handleOIDCCallback(client: UserManager): Promise<User>;

// Get ID token for passing to backend
function getIdToken(): string | null;
```

### Phase 3: Login Page Integration (4-6 hours)

**Files to modify:**
- `src/pages/Login/Login.tsx` - Add OIDC gate detection and flow
- Add new component: `src/components/Auth/OIDCGatePrompt.tsx`

**Flow changes for registration:**
1. User enters username, clicks "Create Wallet"
2. Check `requiresOIDCGateForRegistration()` 
3. If true, show IdP prompt: "Authenticate with {display_name} to continue"
4. Redirect to IdP via PKCE flow
5. On callback, store ID token in session
6. Continue with WebAuthn registration, including `Authorization: Bearer <id_token>`

**Flow changes for login:**
1. User clicks "Login with Passkey"
2. Check `requiresOIDCGateForLogin()`
3. If true, show IdP prompt before WebAuthn
4. On successful OIDC, proceed with WebAuthn login with ID token

**OIDCGatePrompt component:**
```tsx
interface OIDCGatePromptProps {
  provider: OIDCProviderConfig;
  purpose: 'registration' | 'login';
  onContinue: () => void;
  onCancel: () => void;
}

// Shows: "Your organization requires you to authenticate with {display_name}"
// Button: "Continue with {display_name}"
```

### Phase 4: Callback Page (2-3 hours)

**New file:**
- `src/pages/OIDCCallback/OIDCCallback.tsx`

**Route:**
- Add `/cb` and `/id/:tenantId/cb` routes

**Logic:**
1. Parse authorization code from URL
2. Exchange for tokens via OIDC client
3. Store ID token in sessionStorage
4. Redirect back to registration/login flow with state preservation

### Phase 5: Error Handling (2-3 hours)

**Scenarios to handle:**
- IdP unreachable → Show error, offer retry
- Token validation failed (backend 401) → Clear session, restart flow
- User cancelled at IdP → Return to login page
- Identity binding mismatch (403) → "This wallet is bound to a different identity"

**Files:**
- Add `src/components/Auth/OIDCGateError.tsx`
- Update Login.tsx error handling

### Phase 6: Testing (4-6 hours)

**Manual testing:**
- Configure test tenant with Keycloak OIDC gate
- Test registration-only mode
- Test login-only mode
- Test both mode
- Test identity binding verification
- Test error scenarios

**Automated tests:**
- Unit tests for `src/lib/oidc.ts` (mock fetch)
- Integration tests with mock IdP
- Add E2E test in wallet-e2e-tests

### Dependencies

- `oidc-client-ts` - OIDC client library with PKCE support

### Files Summary

| File | Action | Description |
|------|--------|-------------|
| `src/api/types.ts` | Modify | Add OIDCGateConfig, TenantConfig types |
| `src/context/TenantContext.tsx` | Modify | Fetch tenant config, expose gate helpers |
| `src/lib/oidc.ts` | Create | OIDC PKCE flow utilities |
| `src/hooks/useOIDCGate.ts` | Create | React hook for gate flow |
| `src/pages/Login/Login.tsx` | Modify | Integrate OIDC gate detection and flow |
| `src/pages/OIDCCallback/OIDCCallback.tsx` | Create | Handle IdP redirect callback |
| `src/components/Auth/OIDCGatePrompt.tsx` | Create | IdP authentication prompt |
| `src/components/Auth/OIDCGateError.tsx` | Create | Error handling component |
| `package.json` | Modify | Add oidc-client-ts dependency |

### Estimated Effort

| Phase | Hours |
|-------|-------|
| Phase 1: API Types | 2-3 |
| Phase 2: OIDC Client | 4-6 |
| Phase 3: Login Integration | 4-6 |
| Phase 4: Callback Page | 2-3 |
| Phase 5: Error Handling | 2-3 |
| Phase 6: Testing | 4-6 |
| **Total** | **18-27** |

### Risks & Mitigations

1. **CORS issues with IdP** - May need proxy configuration for development
2. **Popup blocked** - Use full-page redirect (not popup) for OIDC flow
3. **Token expiry** - Check token validity before WebAuthn, refresh if needed
4. **Mobile browser issues** - Test redirect flows on iOS/Android browsers
