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

The frontend needs to detect OIDC gate requirements and handle enterprise IdP authentication with explicit user action (button click). Registration and login gates are **independent** - a tenant may gate only registration, only login, both, or neither.

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
- Expose helpers:
  - `requiresOIDCGateForRegistration(): boolean`
  - `requiresOIDCGateForLogin(): boolean`
  - `getRegistrationOIDCProvider(): OIDCProviderConfig | null`
  - `getLoginOIDCProvider(): OIDCProviderConfig | null`

### Phase 2: OIDC Client Integration (4-6 hours)

**New files:**
- `src/lib/oidc.ts` - OIDC PKCE flow utilities
- `src/hooks/useOIDCGate.ts` - React hook for OIDC gate flow

**WebView/Native App Support:**

Native apps running wallet-frontend in a WebView can inject a bridge object:

```typescript
// Native bridge interface (injected by native app)
interface NativeOIDCBridge {
  // Check if native OIDC is available
  isAvailable(): boolean;
  
  // Start OIDC flow via native SDK (AppAuth-iOS/Android)
  // Returns promise that resolves with ID token
  startFlow(config: {
    issuer: string;
    clientId: string;
    scopes: string;
  }): Promise<{ idToken: string; }>;
}

declare global {
  interface Window {
    NativeOIDCBridge?: NativeOIDCBridge;
  }
}
```

**Flow mode detection:**
```typescript
// src/lib/oidc.ts
export type OIDCFlowMode = 'browser-redirect' | 'native-bridge';

export function getOIDCFlowMode(): OIDCFlowMode {
  if (window.NativeOIDCBridge?.isAvailable?.()) {
    return 'native-bridge';
  }
  return 'browser-redirect';
}
```

**Core functions in `src/lib/oidc.ts`:**
```typescript
interface OIDCConfig {
  issuer: string;
  clientId: string;
  redirectUri: string;
  scopes: string;
}

// Start OIDC flow - handles both browser and native modes
async function startOIDCFlow(
  config: OIDCConfig, 
  purpose: 'registration' | 'login'
): Promise<void>;

// Handle callback (browser mode only)
async function handleOIDCCallback(): Promise<{ idToken: string }>;

// Get stored ID token
function getStoredIdToken(purpose: 'registration' | 'login'): string | null;

// Clear stored ID token
function clearStoredIdToken(purpose: 'registration' | 'login'): void;
```

**Token storage:**
- Use `sessionStorage` with keys like `oidc_gate_registration_token`, `oidc_gate_login_token`
- Tokens are purpose-specific to avoid cross-contamination

### Phase 3: Login Page Integration (4-6 hours)

**Files to modify:**
- `src/pages/Login/Login.tsx` - Add OIDC gate detection and flow
- Add new component: `src/components/Auth/OIDCGateButton.tsx`

**State machine for gated flows:**
```typescript
type GateState = 
  | { status: 'idle' }                    // Initial state
  | { status: 'awaiting-oidc' }           // User clicked IdP button, flow in progress
  | { status: 'oidc-complete', token: string }  // IdP auth done, ready for passkey
  | { status: 'error', message: string }; // Error occurred
```

**Registration flow (mode = 'registration' or 'both'):**
```
┌─────────────────────────────────────────────────────────┐
│  Create your wallet                                      │
│                                                          │
│  Username: [___________________]                         │
│                                                          │
│  ┌─────────────────────────────────────────────────────┐│
│  │ 🏢 Sign up with Corporate SSO                       ││ ← Primary button
│  └─────────────────────────────────────────────────────┘│
│                                                          │
│  Your organization requires you to verify your identity  │
│  before creating a wallet.                               │
└─────────────────────────────────────────────────────────┘
```

**After OIDC success (registration):**
```
┌─────────────────────────────────────────────────────────┐
│  Choose your passkey type                                │
│  ✓ Verified: alice@acme.com                              │
│                                                          │
│  [👆 Platform Passkey] ← primary                         │
│  [🔑 Security Key]                                       │
│  [📱 Hybrid Passkey]                                     │
└─────────────────────────────────────────────────────────┘
```

**Login flow (mode = 'login' or 'both'):**
```
┌─────────────────────────────────────────────────────────┐
│  Welcome back                                            │
│                                                          │
│  ┌─────────────────────────────────────────────────────┐│
│  │ 🏢 Sign in with Corporate SSO                       ││
│  └─────────────────────────────────────────────────────┘│
│                                                          │
│  After verifying your identity, you'll use your          │
│  passkey to unlock your wallet.                          │
└─────────────────────────────────────────────────────────┘
```

**After OIDC success (login):**
```
┌─────────────────────────────────────────────────────────┐
│  Unlock your wallet                                      │
│  ✓ Verified: alice@acme.com                              │
│                                                          │
│  [👆 Unlock with Passkey] ← primary                      │
│  [🔑 Use Security Key]                                   │
│  [📱 Use Another Device]                                 │
└─────────────────────────────────────────────────────────┘
```

**Non-gated flows remain unchanged:**
- If `mode = 'none'`: Normal passkey buttons for both registration and login
- If `mode = 'registration'`: Login shows normal passkey buttons
- If `mode = 'login'`: Registration shows normal passkey buttons

**OIDCGateButton component:**
```tsx
interface OIDCGateButtonProps {
  provider: OIDCProviderConfig;
  purpose: 'registration' | 'login';
  onClick: () => void;
  disabled?: boolean;
}

// Renders: "🏢 Sign up with {display_name}" or "🏢 Sign in with {display_name}"
```

**Integration in WebauthnSignupLogin:**
```tsx
const { tenantConfig } = useTenant();
const [registrationGateState, setRegistrationGateState] = useState<GateState>({ status: 'idle' });
const [loginGateState, setLoginGateState] = useState<GateState>({ status: 'idle' });

// Check if THIS specific action requires a gate
const registrationRequiresGate = tenantConfig?.oidc_gate?.mode === 'registration' 
  || tenantConfig?.oidc_gate?.mode === 'both';
const loginRequiresGate = tenantConfig?.oidc_gate?.mode === 'login' 
  || tenantConfig?.oidc_gate?.mode === 'both';

// For registration tab
if (!isLogin && registrationRequiresGate && registrationGateState.status !== 'oidc-complete') {
  return <OIDCGateUI 
    provider={tenantConfig.oidc_gate.registration_op}
    purpose="registration"
    state={registrationGateState}
    onStart={handleStartRegistrationOIDC}
  />;
}

// For login tab
if (isLogin && loginRequiresGate && loginGateState.status !== 'oidc-complete') {
  return <OIDCGateUI
    provider={tenantConfig.oidc_gate.login_op}
    purpose="login"
    state={loginGateState}
    onStart={handleStartLoginOIDC}
  />;
}

// Otherwise, render normal passkey buttons
// (includes: non-gated flows, or gated flows after OIDC success)
```

### Phase 4: Callback Page (2-3 hours)

**New file:**
- `src/pages/OIDCCallback/OIDCCallback.tsx`

**Routes:**
- Add `/cb` and `/id/:tenantId/cb` routes for browser-based OIDC

**State preservation:**
- Store `purpose` ('registration' | 'login') in `state` parameter
- Store any form data (username) in sessionStorage before redirect
- Restore after callback

**Logic:**
1. Parse authorization code from URL
2. Exchange for tokens via OIDC client
3. Extract `purpose` from state parameter
4. Store ID token with purpose-specific key
5. Redirect back to `/login` or `/id/:tenantId/login`
6. Login page detects stored token, shows passkey step

### Phase 5: Error Handling (2-3 hours)

**Scenarios to handle:**

| Error | HTTP Status | User Message | Action |
|-------|-------------|--------------|--------|
| IdP unreachable | - | "Unable to reach identity provider" | Retry button |
| User cancelled at IdP | - | "Authentication cancelled" | Return to login |
| Token validation failed | 401 | "Session expired, please verify again" | Clear token, restart |
| Identity binding mismatch | 403 | "This wallet is registered to a different identity" | Explain, offer help |
| Token expired mid-flow | 401 | "Your session expired" | Restart OIDC flow |

**Files:**
- Add error UI in `src/components/Auth/OIDCGateError.tsx`
- Update Login.tsx to handle new error cases from backend

### Phase 6: Testing (4-6 hours)

**Manual test matrix:**

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

**Automated tests:**
- Unit tests for `src/lib/oidc.ts` (mock fetch)
- Unit tests for gate state machine
- E2E test with mock IdP in wallet-e2e-tests

### Dependencies

- `oidc-client-ts` - OIDC client library with PKCE support

### Files Summary

| File | Action | Description |
|------|--------|-------------|
| `src/api/types.ts` | Modify | Add OIDCGateConfig, TenantConfig types |
| `src/context/TenantContext.tsx` | Modify | Fetch tenant config, expose gate helpers |
| `src/lib/oidc.ts` | Create | OIDC PKCE flow + native bridge support |
| `src/hooks/useOIDCGate.ts` | Create | React hook for gate state machine |
| `src/pages/Login/Login.tsx` | Modify | Integrate gate detection, two-step flow |
| `src/pages/OIDCCallback/OIDCCallback.tsx` | Create | Handle IdP redirect callback |
| `src/components/Auth/OIDCGateButton.tsx` | Create | IdP authentication button |
| `src/components/Auth/OIDCGateUI.tsx` | Create | Gate flow UI container |
| `src/components/Auth/OIDCGateError.tsx` | Create | Error handling component |
| `package.json` | Modify | Add oidc-client-ts dependency |

### Native App Integration Guide

For native apps using WebViews:

1. **Inject the bridge before loading the WebView:**
```swift
// iOS example
let script = """
window.NativeOIDCBridge = {
  isAvailable: function() { return true; },
  startFlow: function(config) {
    return new Promise(function(resolve, reject) {
      window.webkit.messageHandlers.oidc.postMessage(config);
      window._oidcResolve = resolve;
      window._oidcReject = reject;
    });
  }
};
"""
webView.configuration.userContentController.addUserScript(...)
```

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
