# OIDC Gate for Wallet Registration/Authentication

## Overview

Protect wallet registration and/or authentication endpoints with OpenID Connect authorization. Users must authenticate with an enterprise IdP (OP) before accessing the wallet.

## Status: Implemented ✅

This feature is implemented across:
- **Backend**: `go-wallet-backend` branch `feature/oidc-gate`
- **Frontend**: `wallet-frontend` branch `feature/oidc-gate`

## Use Cases

| Mode | Registration | Login | Example |
|------|-------------|-------|---------|
| `registration` | Protected | Open | Enterprise onboarding: employees must prove corporate identity to register |
| `login` | Open | Protected | Step-up auth: require enterprise login before wallet access |
| `both` | Protected (OP-A) | Protected (OP-B) | Different OPs per operation, or same OP |
| `none` | Open | Open | Default behavior (unchanged) |

## Design Decisions

### Token Type
- ID tokens only (standard OIDC)
- Token validated via JWKS from OIDC discovery

### Identity Binding
- Configurable via `bind_identity` flag
- When enabled, enterprise `sub` is bound to wallet user during registration
- Login verifies the bound identity matches

### Flow Orchestration
- **Frontend-driven PKCE**: Frontend handles the OIDC PKCE flow
- **Token passing**: ID token sent in `Authorization: Bearer <token>` header
- **Native support**: WebView apps can use NativeOIDCBridge interface

## Architecture

```
┌─────────────┐     ┌──────────────┐     ┌─────────────┐
│   Frontend  │◄───►│ Enterprise   │     │  Wallet     │
│   (SPA)     │     │ IdP (OP)     │     │  Backend    │
└─────┬───────┘     └──────────────┘     └──────┬──────┘
      │                                         │
      │ 1. GET /api/v1/tenants/{id}/config      │
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
    TenantID    TenantID  `json:"tenant_id" bson:"tenant_id"`
    Issuer      string    `json:"issuer" bson:"issuer"`
    Subject     string    `json:"subject" bson:"subject"`
    Email       string    `json:"email,omitempty" bson:"email,omitempty"`
    BindingType string    `json:"binding_type" bson:"binding_type"`
    BoundAt     time.Time `json:"bound_at" bson:"bound_at"`
}
```

## Backend Implementation

### Components

1. **Domain model** (`internal/domain/tenant.go`)
   - `OIDCGateConfig` - Gate configuration
   - `OIDCProviderConfig` - Per-OP settings
   - `EnterpriseIdentity` - Bound identity (when `bind_identity` enabled)

2. **OIDC validation** (`pkg/oidc/`)
   - `Validator` - JWT validation with JWKS
   - OIDC discovery for JWKS URI
   - Signature, expiry, issuer, audience validation

3. **Middleware** (`pkg/middleware/oidc_gate.go`)
   - `OIDCGateMiddleware` - Conditional endpoint protection
   - `ValidatorCache` - Caches validators per OP
   - Returns 401 with `oidc_config` for client retry

4. **Admin API** (`internal/api/admin_handlers.go`)
   - CRUD for `oidc_gate` in tenant configuration
   - Public config endpoint: `GET /api/v1/tenants/:id/config`

5. **CLI** (`cmd/wallet-admin/cmd/tenant.go`)
   - `configure-oidc-gate` command
   - Sync support in `sync.go`

## API

### GET /api/v1/tenants/:id/config

Public endpoint returning tenant configuration including OIDC gate settings.

Response:
```json
{
  "id": "acme",
  "name": "ACME Corp",
  "display_name": "ACME Corporation",
  "require_invite": false,
  "oidc_gate": {
    "mode": "registration",
    "registration_op": {
      "display_name": "Corporate SSO",
      "issuer": "https://login.acme.com",
      "client_id": "wallet-app",
      "scopes": "openid profile email"
    }
  }
}
```

### Protected Endpoints

When OIDC gate is enabled, these endpoints require `Authorization: Bearer <id_token>`:

**Registration gate** (mode = `registration` or `both`):
- `POST /user/register`
- `POST /user/register-webauthn-begin`
- `POST /user/register-webauthn-finish`

**Login gate** (mode = `login` or `both`):
- `POST /user/login`
- `POST /user/login-webauthn-begin`
- `POST /user/login-webauthn-finish`

### Error Response (401)

When token is missing or invalid:
```json
{
  "error": "oidc_gate_required",
  "message": "Authorization header required",
  "oidc_config": {
    "display_name": "Corporate SSO",
    "issuer": "https://login.acme.com",
    "client_id": "wallet-app",
    "scopes": "openid profile email"
  }
}
```

## Security Considerations

1. **Token validation** - Full JWT validation (signature, exp, iss, aud)
2. **JWKS caching** - Validators cached per issuer+audience combination
3. **Clock skew** - Standard leeway applied for exp/iat/nbf
4. **Error messages** - Generic errors avoid leaking sensitive info
5. **Required claims** - Configurable claim validation (e.g., `email_verified: true`)

## CLI Configuration

Configure OIDC gate using `wallet-admin`:

```bash
# Enable registration gate with identity binding
wallet-admin tenant configure-oidc-gate acme \
  --mode registration \
  --issuer https://login.acme.com \
  --client-id wallet-app \
  --display-name "Corporate SSO" \
  --scopes "openid profile email" \
  --bind-identity

# Enable both gates (different OPs)
wallet-admin tenant configure-oidc-gate acme \
  --mode both \
  --issuer https://login.acme.com \
  --client-id wallet-app \
  --login-issuer https://mfa.acme.com \
  --login-client-id wallet-mfa

# Disable gate
wallet-admin tenant configure-oidc-gate acme --mode none
```

---

## Frontend Implementation

### Overview

The frontend detects OIDC gate requirements and handles enterprise IdP authentication with explicit user action (button click). Registration and login gates are **independent** - a tenant may gate only registration, only login, both, or neither.

**Key design decisions:**
1. **Button-based UX** - No auto-redirect; user clicks explicit IdP button
2. **Two-step flow** - IdP auth first, then passkey selection
3. **WebView support** - Native bridge interface for apps using WebViews
4. **Independent gates** - Registration and login handled separately

### Gate Mode Combinations

| Mode | Registration | Login | Registration UI | Login UI |
|------|-------------|-------|-----------------|----------|
| `none` | Open | Open | Normal passkey buttons | Normal passkey buttons |
| `registration` | Gated | Open | IdP button → then passkey | Normal passkey buttons |
| `login` | Open | Gated | Normal passkey buttons | IdP button → then passkey |
| `both` | Gated | Gated | IdP button → then passkey | IdP button → then passkey |

### Components

| File | Description |
|------|-------------|
| `src/api/types.ts` | OIDC gate types (OIDCGateConfig, TenantConfig) |
| `src/context/TenantContext.tsx` | Fetches tenant config, exposes gate helpers |
| `src/lib/oidc.ts` | OIDC PKCE flow + native bridge support |
| `src/hooks/useOIDCGate.ts` | React hook for gate state machine |
| `src/pages/Login/Login.tsx` | Integrated gate detection, two-step flow |
| `src/pages/OIDCCallback/OIDCCallback.tsx` | Handles IdP redirect callback |
| `src/components/Auth/OIDCGateButton.tsx` | IdP authentication button |
| `src/components/Auth/OIDCGateUI.tsx` | Gate flow UI container |

### Routes

- `/cb` - OIDC callback (default tenant)
- `/id/:tenantId/cb` - OIDC callback (multi-tenant)

### Native Bridge Interface

For WebView apps using AppAuth-iOS/Android:

```typescript
interface NativeOIDCBridge {
  isAvailable(): boolean;
  startFlow(config: {
    issuer: string;
    clientId: string;
    scopes: string;
  }): Promise<{ idToken: string }>;
}
```

Inject as `window.NativeOIDCBridge` before loading the WebView.

---

## Testing

### Test Matrix

| Test Case | Mode | Action | Expected |
|-----------|------|--------|----------|
| 1 | none | Register | Normal passkey flow |
| 2 | none | Login | Normal passkey flow |
| 3 | registration | Register | IdP button → passkey |
| 4 | registration | Login | Normal passkey flow |
| 5 | login | Register | Normal passkey flow |
| 6 | login | Login | IdP button → passkey |
| 7 | both | Register | IdP button → passkey |
| 8 | both | Login | IdP button → passkey |
| 9 | both + bind_identity | Login with different IdP user | 403 error |

### Testing Setup

1. Configure a tenant with OIDC gate:
   ```bash
   wallet-admin tenant configure-oidc-gate test-tenant \
     --mode registration \
     --issuer https://your-idp.example.com \
     --client-id your-client-id \
     --display-name "Test IdP"
   ```

2. Configure your IdP (e.g., Keycloak, Azure AD):
   - Create a public OIDC client with PKCE
   - Set redirect URI: `http://localhost:5173/id/test-tenant/cb`
   - Scopes: `openid profile email`

3. Start services:
   ```bash
   # Backend
   cd go-wallet-backend && go run ./cmd/wallet-backend
   # Frontend
   cd wallet-frontend && yarn dev
   ```

4. Navigate to `http://localhost:5173/id/test-tenant/login` and test the flow.

2. **Handle OIDC in native code:**
   - Use AppAuth-iOS or AppAuth-Android
   - Open system browser for IdP login
   - Capture redirect via custom URL scheme
   - Pass ID token back to WebView

3. **Return token to WebView:**
```swift
webView.evaluateJavaScript("window._oidcResolve({ idToken: '\(token)' })")
```

### Estimated Effort

| Phase | Hours |
|-------|-------|
| Phase 1: API Types | 2-3 |
| Phase 2: OIDC Client + Native Bridge | 5-7 |
| Phase 3: Login Integration | 5-7 |
| Phase 4: Callback Page | 2-3 |
| Phase 5: Error Handling | 2-3 |
| Phase 6: Testing | 4-6 |
| **Total** | **20-29** |

### Risks & Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| CORS issues with IdP | Dev friction | Use proxy in dev; production uses same-origin |
| Token expiry mid-flow | UX interruption | Check token before WebAuthn; refresh if needed |
| WebView redirect blocked | App broken | Native bridge + AppAuth for WebView contexts |
| IdP blocks embedded WebView | Auth fails | System browser via ASWebAuthenticationSession/Custom Tabs |
| State lost on redirect | Flow broken | Store form data in sessionStorage before redirect |
| User switches tabs | Gate state lost | Session storage preserves state across tab switches |
| Long IdP sessions | Stale identity | Enforce `prompt=login` for critical flows |
| Independent gate timing | Confusing UX | Clear UI showing which step requires verification |
