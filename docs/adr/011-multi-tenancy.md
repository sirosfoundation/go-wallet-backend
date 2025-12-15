# Multi-Tenancy Design for go-wallet-backend

## Overview

This document describes the design for supporting multiple tenants in the go-wallet-backend. A tenant represents an isolated organization or deployment that shares the same backend infrastructure but maintains complete data isolation.

## Requirements

1. **User-Tenant Association**: A user can belong to multiple tenants
2. **Data Isolation**: Credentials, presentations, and related data must be completely isolated between tenants
3. **URL Routing**: All tenants accessible under the same domain
4. **Shared Infrastructure**: Single deployment serves all tenants
5. **Per-Tenant Configuration**: Issuers, verifiers, and trust configuration can be tenant-specific
6. **CDN-Friendly**: Frontend assets must be fully cacheable; no tenant-specific builds

## Tenant Identification Strategy Analysis

### Option A: URL Path Prefix (Server-Side Routing)

```
https://example.com/acme-corp/storage/vc
https://example.com/acme-corp/user/session/account-info
```

**Pros:**
- Clean REST semantics
- Server can route directly
- Standard pattern for multi-tenant SaaS

**Cons:**
- Requires CDN path-based routing rules or no CDN for frontend
- Either build tenant-specific frontends OR use complex CDN rewrites
- Creates deployment silos - defeats scalability goal

### Option B: URL Fragment (Client-Side Tenant Selection) ✅ RECOMMENDED

```
https://example.com/#acme-corp
https://example.com/#acme-corp/settings
```

**Pros:**
- **CDN-Perfect**: Single frontend build serves all tenants
- **No Server Routing**: Fragment never hits the server for static assets
- **Dynamic Tenant Switching**: User can switch tenants without reload
- **Deep Linking**: `/#tenant/path` still works for internal navigation
- **Same-Origin**: All API calls from same origin, simple CORS

**Cons:**
- Requires frontend to parse fragment and inject into API calls
- Fragment lost on some OAuth redirects (mitigated - see below)
- Non-standard REST pattern (tenant in header, not path)

### Option C: Subdomain per Tenant

```
https://acme-corp.example.com/storage/vc
```

**Pros:**
- Clean separation
- Natural for DNS-based routing

**Cons:**
- Requires wildcard DNS and SSL certificates
- WebAuthn RP ID complexity (needs rpId configuration per subdomain)
- More complex CDN configuration
- Cookie isolation complexities

## Frontend SPA Route Analysis

This section provides a detailed analysis of all SPA routes to inform the routing decision between fragment-based and path-based tenant identification.

### Complete Route Inventory

The following routes are defined in `wallet-frontend/src/App.jsx`:

| Route | Type | Purpose | OAuth Impact |
|-------|------|---------|--------------|
| `/` | Protected | Home/Dashboard | None |
| `/settings` | Protected | User settings | None |
| `/credential/:batchId` | Protected | Credential detail | None |
| `/credential/:batchId/history` | Protected | Credential history | None |
| `/credential/:batchId/details` | Protected | Credential details | None |
| `/history` | Protected | Transaction history | None |
| `/history/:transactionId` | Protected | Transaction detail | None |
| `/pending` | Protected | Pending items | None |
| `/add` | Protected | Add credential | None |
| `/send` | Protected | Send credential | None |
| `/verification/result` | Protected | Verification result | None |
| `/cb/*` | Protected | OAuth callbacks | **Critical** |
| `/login` | Public | Login page | Redirect target |
| `/login-state` | Public | Login state | None |
| `*` | Public | NotFound | None |

### Current Routing Implementation

- **Router**: BrowserRouter from react-router-dom v6+
- **Entry Point**: `wallet-frontend/src/index.jsx` wraps App in `<BrowserRouter>`
- **Protected Routes**: Wrapped in `ProtectedRoute` component (requires authentication)
- **Public Routes**: Accessible without authentication

### OAuth Callback Analysis

The `UriHandlerProvider.tsx` handles 3 OAuth flows via **query parameters** (not path):

1. **OpenID4VCI Credential Offer**: `?credential_offer=...` or `?credential_offer_uri=...`
2. **Authorization Code Response**: `?code=...&state=...`
3. **OpenID4VP Authorization Request**: `?client_id=...&request_uri=...`

**Key Insight**: OAuth flows use `window.location.search` (query params), not the path. This is important because:
- Query params are preserved in all redirect scenarios
- The `/cb/*` route is a catch-all for OAuth callbacks
- External services redirect to `example.com/cb?code=xyz&state=abc`

### Navigation Patterns Found

The codebase uses these navigation patterns (from grep analysis):

1. **Programmatic Navigation**: `useNavigate()` hook
   - `navigate('/add')` - relative paths
   - `navigate('/')` - home navigation
   - `navigate(-1)` - back navigation

2. **Declarative Navigation**: `<Link>` component
   - `<Link to="/">` in CredentialLayout.jsx

3. **External Redirects**: `window.location.href`
   - Used for OAuth authorization URLs
   - Verifier callback URLs
   - External service redirects

### Routing Option Comparison

#### Option A: Fragment Routing (`/#tenant/path`)

```
example.com/#default/                   → Home
example.com/#default/settings           → Settings
example.com/#default/credential/abc123  → Credential detail
example.com/#default/cb?code=xyz        → OAuth callback
```

| Aspect | Assessment |
|--------|------------|
| CDN Caching | ✅ **Perfect** - Single static bundle serves all tenants |
| Server Configuration | ✅ **None required** - Fragment never hits server |
| Tenant Switching | ✅ **Dynamic** - No page reload needed (except for keystore) |
| Deep Linking | ✅ **Works** - `/#tenant/path` shareable |
| Same-Origin Policy | ✅ **Simple** - All API calls from same origin |
| OAuth Redirects | ⚠️ **Requires workaround** - Fragment lost on redirect, must use `state` param |
| Router Migration | ⚠️ **Medium effort** - Switch BrowserRouter → HashRouter |
| URL Aesthetics | ⚠️ **Non-standard** - Hash in URL |
| SEO | ⚠️ **Poor** - Fragments not indexed (but wallet is not SEO-critical) |

**OAuth State Parameter Workaround:**
```javascript
// When initiating OAuth:
const state = btoa(JSON.stringify({
  tenant: currentTenant,
  nonce: crypto.randomUUID(),
  originalPath: location.hash
}));

// Redirect URL: example.com/cb?code=xyz&state=<encoded>

// On callback, restore tenant from state:
const { tenant } = JSON.parse(atob(state));
setStoredTenant(tenant);
```

#### Option B: Path Routing (`/tenant/path`)

```
example.com/default/                    → Home
example.com/default/settings            → Settings  
example.com/default/credential/abc123   → Credential detail
example.com/default/cb?code=xyz         → OAuth callback
```

| Aspect | Assessment |
|--------|------------|
| CDN Caching | ⚠️ **Requires configuration** - Need wildcard/rewrite rules |
| Server Configuration | ⚠️ **Required** - Server must return index.html for SPA routes |
| Tenant Switching | ✅ **Works** - URL path change |
| Deep Linking | ✅ **Clean** - Standard URL format |
| Same-Origin Policy | ✅ **Simple** - All API calls from same origin |
| OAuth Redirects | ✅ **Natural** - Path preserved through redirects |
| Router Migration | ✅ **Minimal** - Keep BrowserRouter, add basename |
| URL Aesthetics | ✅ **Standard** - Clean RESTful URLs |
| SEO | ✅ **Good** - Paths are indexable (if relevant) |

**CDN/Server Configuration Required:**
```nginx
# Nginx configuration for path-based routing
location ~ ^/[a-z0-9-]+/ {
    try_files $uri $uri/ /index.html;
}
```

```yaml
# CloudFront/CDN configuration
# Custom error response: 403/404 → /index.html with 200
```

### Migration Effort Comparison

#### Fragment Routing Migration

1. **Change Router** (`index.jsx`):
   ```tsx
   // Before
   import { BrowserRouter } from 'react-router-dom';
   
   // After
   import { HashRouter } from 'react-router-dom';
   ```

2. **Add Tenant Parser** (`src/lib/tenant.ts`): ~100 lines, new file

3. **Update API Client**: Add `X-Tenant-ID` header to all requests

4. **OAuth Flow Updates** (`UriHandlerProvider.tsx`):
   - Encode tenant in `state` parameter
   - Restore tenant on callback
   - ~50 lines of changes

5. **IndexedDB Isolation**: Prefix cache keys with tenant ID

**Estimated Files Changed**: 8-10 files
**Estimated Complexity**: Medium

#### Path Routing Migration

1. **Add Tenant to Router** (`App.jsx`):
   ```tsx
   // Wrap all routes in tenant prefix
   <Routes>
     <Route path="/:tenant/*" element={<TenantRoutes />} />
   </Routes>
   ```

2. **Update All Links/Navigation**: Add tenant prefix or use relative paths

3. **Add Tenant Context Provider**: Extract tenant from URL params

4. **Update API Client**: Add `X-Tenant-ID` header to all requests

5. **Server Configuration**: Configure nginx/CDN for SPA routing

**Estimated Files Changed**: 10-15 files
**Estimated Complexity**: Medium-High (more files, but more standard pattern)

### Recommendation Matrix

| If you prioritize... | Choose |
|---------------------|--------|
| CDN simplicity & caching efficiency | Fragment (`/#tenant`) |
| Clean URLs & minimal frontend changes | Path (`/tenant`) |
| Zero server/CDN configuration | Fragment (`/#tenant`) |
| OAuth redirect simplicity | Path (`/tenant`) |
| SEO (if applicable) | Path (`/tenant`) |
| Static hosting (GitHub Pages, S3) | Fragment (`/#tenant`) |
| Enterprise/traditional infrastructure | Path (`/tenant`) |

### Analysis Summary

**Fragment Routing** is optimal when:
- CDN caching is critical for performance/cost
- Deploying to static hosting without server control
- Willing to handle OAuth state parameter encoding
- URL aesthetics are less important than operational simplicity

**Path Routing** is optimal when:
- CDN can be configured for SPA routing
- Clean URLs are important for users/sharing
- Want to minimize OAuth flow complexity
- Have control over server/CDN configuration

### Decision Status: PENDING

This analysis is provided for team discussion. The recommended approach depends on:
1. Deployment infrastructure constraints
2. CDN configuration capabilities
3. Team preference for URL aesthetics vs. operational simplicity
4. OAuth flow complexity tolerance

## Recommended Design: URL Fragment + HTTP Header

### Architecture Overview

```
┌──────────────────────────────────────────────────────────────────┐
│                          CDN (CloudFront/Cloudflare)              │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │  Static Assets: example.com/*                               │ │
│  │  - Same cached bundle for ALL tenants                       │ │
│  │  - SPA routes handled client-side                           │ │
│  └─────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────┘
                               │
                               │ API calls include X-Tenant-ID header
                               ▼
┌──────────────────────────────────────────────────────────────────┐
│                      API Gateway / Load Balancer                  │
│  api.example.com/* or example.com/api/*                          │
└──────────────────────────────────────────────────────────────────┘
                               │
                               ▼
┌──────────────────────────────────────────────────────────────────┐
│                    go-wallet-backend                              │
│  - Extracts tenant from X-Tenant-ID header                       │
│  - Validates tenant membership                                    │
│  - Routes to tenant-scoped data                                   │
└──────────────────────────────────────────────────────────────────┘
```

### URL Patterns

**Frontend URLs (handled by SPA router):**
```
https://example.com/                    → Tenant selection page (or default)
https://example.com/#acme-corp          → Home page for acme-corp tenant
https://example.com/#acme-corp/settings → Settings page for acme-corp tenant
https://example.com/#acme-corp/credential/123 → Deep link to credential
```

**API URLs (backend - tenant in header):**
```
POST https://example.com/api/storage/vc
Header: X-Tenant-ID: acme-corp
Header: Authorization: Bearer <jwt>
```

### Fragment Format Options

**Option 1: Simple Fragment (Recommended)**
```
example.com/#tenant-id
example.com/#tenant-id/route/path
```
- Fragment starts with tenant ID
- Route follows after `/`
- Easy to parse: `hash.split('/')[0]` for tenant

**Option 2: Query-like Fragment**
```
example.com/#tenant=acme-corp&route=/settings
```
- More explicit but harder to use with React Router

**Recommendation:** Option 1 - Simple hierarchical fragment

## Data Model Changes

### New Domain Types

```go
// pkg/domain/tenant.go

// TenantID represents a unique tenant identifier (URL-safe slug)
type TenantID string

// Tenant represents an organizational tenant
type Tenant struct {
    ID          TenantID  `json:"id" bson:"_id" gorm:"primaryKey"`
    Name        string    `json:"name" bson:"name" gorm:"not null"`
    DisplayName string    `json:"display_name" bson:"display_name"`
    Enabled     bool      `json:"enabled" bson:"enabled" gorm:"default:true"`
    CreatedAt   time.Time `json:"created_at" bson:"created_at" gorm:"autoCreateTime"`
    UpdatedAt   time.Time `json:"updated_at" bson:"updated_at" gorm:"autoUpdateTime"`
}

// UserTenantMembership represents a user's membership in a tenant
type UserTenantMembership struct {
    ID        int64     `json:"id" bson:"_id,omitempty" gorm:"primaryKey;autoIncrement"`
    UserID    UserID    `json:"user_id" bson:"user_id" gorm:"index;not null"`
    TenantID  TenantID  `json:"tenant_id" bson:"tenant_id" gorm:"index;not null"`
    Role      string    `json:"role" bson:"role" gorm:"default:'user'"` // user, admin
    CreatedAt time.Time `json:"created_at" bson:"created_at" gorm:"autoCreateTime"`
    
    // Unique constraint: (user_id, tenant_id)
}
```

### Modified Domain Types

```go
// Changes to existing types - add TenantID field

// VerifiableCredential - add tenant scoping
type VerifiableCredential struct {
    ID                         int64            `json:"id" bson:"_id,omitempty" gorm:"primaryKey;autoIncrement"`
    TenantID                   TenantID         `json:"tenantId" bson:"tenant_id" gorm:"index;not null"` // NEW
    HolderDID                  string           `json:"holderDID" bson:"holder_did" gorm:"index;not null"`
    CredentialIdentifier       string           `json:"credentialIdentifier" bson:"credential_identifier" gorm:"index;not null"`
    // ... rest unchanged
    
    // Composite unique: (tenant_id, holder_did, credential_identifier)
}

// VerifiablePresentation - add tenant scoping
type VerifiablePresentation struct {
    ID                                      int64     `json:"id" bson:"_id,omitempty" gorm:"primaryKey;autoIncrement"`
    TenantID                                TenantID  `json:"tenantId" bson:"tenant_id" gorm:"index;not null"` // NEW
    HolderDID                               string    `json:"holderDID" bson:"holder_did" gorm:"index;not null"`
    PresentationIdentifier                  string    `json:"presentationIdentifier" bson:"presentation_identifier" gorm:"index;not null"`
    // ... rest unchanged
}

// CredentialIssuer - add tenant scoping (issuers can be per-tenant)
type CredentialIssuer struct {
    ID                         int64    `json:"id" bson:"_id,omitempty" gorm:"primaryKey;autoIncrement"`
    TenantID                   TenantID `json:"tenantId" bson:"tenant_id" gorm:"index;not null"` // NEW
    CredentialIssuerIdentifier string   `json:"credentialIssuerIdentifier" bson:"credential_issuer_identifier" gorm:"index;not null"`
    // ... rest unchanged
    
    // Composite unique: (tenant_id, credential_issuer_identifier)
}

// Verifier - add tenant scoping
type Verifier struct {
    ID       int64    `json:"id" bson:"_id,omitempty" gorm:"primaryKey;autoIncrement"`
    TenantID TenantID `json:"tenantId" bson:"tenant_id" gorm:"index;not null"` // NEW
    Name     string   `json:"name" bson:"name" gorm:"not null"`
    URL      string   `json:"url" bson:"url" gorm:"not null"`
}
```

### User Data - Shared Across Tenants

The `User` type remains **unchanged** and **shared across tenants**:
- Users authenticate once and can access multiple tenants
- WebAuthn credentials are user-level, not tenant-level
- The user's DID is global (but the *use* of that DID is tenant-scoped)

```go
// User remains global - NOT tenant-scoped
type User struct {
    UUID                UserID               `json:"uuid" bson:"_id"`
    Username            *string              `json:"username,omitempty" bson:"username,omitempty"`
    DID                 string               `json:"did" bson:"did"`
    // ... unchanged - no TenantID here
}
```

## Storage Interface Changes

```go
// storage/interface.go - add TenantStore

// TenantStore defines the interface for tenant storage operations
type TenantStore interface {
    Create(ctx context.Context, tenant *domain.Tenant) error
    GetByID(ctx context.Context, id domain.TenantID) (*domain.Tenant, error)
    GetAll(ctx context.Context) ([]*domain.Tenant, error)
    Update(ctx context.Context, tenant *domain.Tenant) error
    Delete(ctx context.Context, id domain.TenantID) error
}

// UserTenantStore defines the interface for user-tenant membership
type UserTenantStore interface {
    AddMembership(ctx context.Context, membership *domain.UserTenantMembership) error
    RemoveMembership(ctx context.Context, userID domain.UserID, tenantID domain.TenantID) error
    GetUserTenants(ctx context.Context, userID domain.UserID) ([]domain.TenantID, error)
    GetTenantUsers(ctx context.Context, tenantID domain.TenantID) ([]domain.UserID, error)
    IsMember(ctx context.Context, userID domain.UserID, tenantID domain.TenantID) (bool, error)
}

// Update CredentialStore - all methods take tenantID
type CredentialStore interface {
    Create(ctx context.Context, tenantID domain.TenantID, credential *domain.VerifiableCredential) error
    GetByID(ctx context.Context, tenantID domain.TenantID, id int64) (*domain.VerifiableCredential, error)
    GetByIdentifier(ctx context.Context, tenantID domain.TenantID, holderDID, credentialIdentifier string) (*domain.VerifiableCredential, error)
    GetAllByHolder(ctx context.Context, tenantID domain.TenantID, holderDID string) ([]*domain.VerifiableCredential, error)
    Update(ctx context.Context, tenantID domain.TenantID, credential *domain.VerifiableCredential) error
    Delete(ctx context.Context, tenantID domain.TenantID, holderDID, credentialIdentifier string) error
}

// Similar changes to PresentationStore, IssuerStore, VerifierStore...

// Store - add new stores
type Store interface {
    Users() UserStore           // Unchanged - global
    Tenants() TenantStore       // NEW
    UserTenants() UserTenantStore // NEW
    
    // These now require tenant context
    Credentials() CredentialStore
    Presentations() PresentationStore
    Issuers() IssuerStore
    Verifiers() VerifierStore
    
    Challenges() ChallengeStore // Unchanged - short-lived, global
    Close() error
    Ping(ctx context.Context) error
}
```

## API Changes

### URL Structure (Header-Based)

Backend API URLs remain unchanged - tenant is passed via HTTP header:

```
# All API calls use the same path structure
POST https://example.com/api/storage/vc
Header: X-Tenant-ID: acme-corp
Header: Authorization: Bearer <jwt>

GET https://example.com/api/user/session/account-info
Header: X-Tenant-ID: acme-corp
Header: Authorization: Bearer <jwt>
```

### New Endpoints

```
# Global endpoints (no tenant header required)
GET  /api/status                  → Health check
GET  /api/tenants                 → List public tenants
GET  /api/tenants/:id             → Get tenant metadata (public info)

# User endpoints (tenant-aware after login)
GET  /api/user/tenants            → List tenants for current user
POST /api/user/tenant/:id/join    → Request to join a tenant (if allowed)
```

### Router Changes

```go
// cmd/server/main.go - setupRouter changes

func setupRouter(cfg *config.Config, services *service.Services, logger *zap.Logger) *gin.Engine {
    router := gin.New()
    // ... middleware setup ...

    handlers := api.NewHandlers(services, cfg, logger)

    // API routes under /api prefix
    api := router.Group("/api")
    
    // Global routes (no tenant header required)
    {
        api.GET("/status", handlers.Status)
        api.GET("/tenants", handlers.ListPublicTenants)
        api.GET("/tenants/:id", handlers.GetTenantInfo)
    }

    // Tenant-scoped routes (require X-Tenant-ID header)
    tenantScoped := api.Group("/")
    tenantScoped.Use(middleware.TenantHeaderMiddleware(services)) // Extract from header
    {
        // WebAuthn registration/login - tenant context needed for membership
        user := tenantScoped.Group("/user")
        {
            user.POST("/register-webauthn-begin", handlers.StartWebAuthnRegistration)
            user.POST("/register-webauthn-finish", handlers.FinishWebAuthnRegistration)
            user.POST("/login-webauthn-begin", handlers.StartWebAuthnLogin)
            user.POST("/login-webauthn-finish", handlers.FinishWebAuthnLogin)
        }

        // Protected routes (authenticated + tenant member)
        protected := tenantScoped.Group("/")
        protected.Use(middleware.AuthMiddleware(cfg, logger))
        protected.Use(middleware.TenantMembershipMiddleware(services))
        {
            // User's tenant list
            protected.GET("/user/tenants", handlers.GetUserTenants)
            
            // Session routes
            session := protected.Group("/user/session")
            {
                session.GET("/account-info", handlers.GetAccountInfo)
                session.GET("/private-data", handlers.GetPrivateData)
                session.PUT("/private-data", handlers.PutPrivateData)
            }

            // Storage routes - tenant-scoped
            storageGroup := protected.Group("/storage")
            {
                storageGroup.GET("/vc", handlers.GetAllCredentials)
                storageGroup.POST("/vc", handlers.StoreCredential)
                storageGroup.DELETE("/vc/:credentialId", handlers.DeleteCredential)
                storageGroup.GET("/vp", handlers.GetAllPresentations)
                storageGroup.POST("/vp", handlers.StorePresentation)
                storageGroup.DELETE("/vp/:presentationId", handlers.DeletePresentation)
            }

            // Issuer routes - tenant-scoped
            protected.GET("/issuer/all", handlers.GetAllIssuers)
            
            // Verifier routes - tenant-scoped  
            protected.GET("/verifier/all", handlers.GetAllVerifiers)
        }
    }

    return router
}
```

### Middleware (Header-Based)

```go
// pkg/middleware/tenant.go

// TenantHeaderMiddleware extracts the tenant from X-Tenant-ID header
func TenantHeaderMiddleware(services *service.Services) gin.HandlerFunc {
    return func(c *gin.Context) {
        tenantIDStr := c.GetHeader("X-Tenant-ID")
        if tenantIDStr == "" {
            c.AbortWithStatusJSON(400, gin.H{"error": "X-Tenant-ID header required"})
            return
        }
        
        tenantID := domain.TenantID(tenantIDStr)
        
        tenant, err := services.Tenant.GetByID(c.Request.Context(), tenantID)
        if err != nil {
            c.AbortWithStatusJSON(404, gin.H{"error": "Tenant not found"})
            return
        }
        
        if !tenant.Enabled {
            c.AbortWithStatusJSON(403, gin.H{"error": "Tenant is disabled"})
            return
        }
        
        c.Set("tenant_id", tenantID)
        c.Set("tenant", tenant)
        c.Next()
    }
}

// TenantMembershipMiddleware verifies the user is a member of the current tenant
func TenantMembershipMiddleware(services *service.Services) gin.HandlerFunc {
    return func(c *gin.Context) {
        userID, _ := c.Get("user_id")
        tenantID, _ := c.Get("tenant_id")
        
        isMember, err := services.UserTenant.IsMember(
            c.Request.Context(),
            domain.UserIDFromString(userID.(string)),
            tenantID.(domain.TenantID),
        )
        if err != nil || !isMember {
            c.AbortWithStatusJSON(403, gin.H{"error": "Not a member of this tenant"})
            return
        }
        
        c.Next()
    }
}
```

### Handler Changes

Handlers need to extract `tenant_id` from context:

```go
// api/handlers.go

// Helper to get tenant ID from context
func (h *Handlers) getTenantID(c *gin.Context) (domain.TenantID, bool) {
    tenantID, exists := c.Get("tenant_id")
    if !exists {
        return "", false
    }
    return tenantID.(domain.TenantID), true
}

// Example: GetAllCredentials
func (h *Handlers) GetAllCredentials(c *gin.Context) {
    tenantID, ok := h.getTenantID(c)
    if !ok {
        c.JSON(500, gin.H{"error": "Tenant context missing"})
        return
    }
    
    holderDID, ok := h.getHolderDID(c)
    if !ok {
        c.JSON(401, gin.H{"error": "Unauthorized"})
        return
    }

    credentials, err := h.services.Credential.GetAll(c.Request.Context(), tenantID, holderDID)
    // ...
}
```

## Configuration Changes

```yaml
# config.yaml

server:
  host: 0.0.0.0
  port: 8080
  # ...

# NEW: Multi-tenancy configuration
tenants:
  # Default tenant for backward compatibility
  default_tenant: "default"
  
  # Allow automatic tenant creation on first user registration
  auto_create: false
  
  # Per-tenant overrides (optional)
  overrides:
    acme-corp:
      trust:
        type: "authzen"
        authzen:
          base_url: "https://acme-pdp.example.com"
    
    university:
      trust:
        type: "x509"
        x509:
          root_cert_paths: ["/etc/certs/university-ca.pem"]
```

## Migration Strategy

### Database Migration

```sql
-- 1. Add tenants table
CREATE TABLE tenants (
    id VARCHAR(64) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    display_name VARCHAR(255),
    enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 2. Add default tenant
INSERT INTO tenants (id, name, display_name, enabled) 
VALUES ('default', 'Default', 'Default Tenant', true);

-- 3. Add user_tenant_memberships table
CREATE TABLE user_tenant_memberships (
    id SERIAL PRIMARY KEY,
    user_id VARCHAR(36) NOT NULL REFERENCES users(uuid),
    tenant_id VARCHAR(64) NOT NULL REFERENCES tenants(id),
    role VARCHAR(32) DEFAULT 'user',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id, tenant_id)
);

-- 4. Migrate existing users to default tenant
INSERT INTO user_tenant_memberships (user_id, tenant_id)
SELECT uuid, 'default' FROM users;

-- 5. Add tenant_id to credentials
ALTER TABLE verifiable_credentials 
ADD COLUMN tenant_id VARCHAR(64) NOT NULL DEFAULT 'default' REFERENCES tenants(id);
CREATE INDEX idx_credentials_tenant ON verifiable_credentials(tenant_id);

-- 6. Add tenant_id to presentations
ALTER TABLE verifiable_presentations 
ADD COLUMN tenant_id VARCHAR(64) NOT NULL DEFAULT 'default' REFERENCES tenants(id);
CREATE INDEX idx_presentations_tenant ON verifiable_presentations(tenant_id);

-- 7. Add tenant_id to issuers and verifiers
ALTER TABLE credential_issuers 
ADD COLUMN tenant_id VARCHAR(64) NOT NULL DEFAULT 'default' REFERENCES tenants(id);

ALTER TABLE verifiers 
ADD COLUMN tenant_id VARCHAR(64) NOT NULL DEFAULT 'default' REFERENCES tenants(id);
```

## Frontend Changes (Fragment-Based Tenant Selection)

### URL Fragment Parsing

The frontend reads the tenant ID from the URL fragment and passes it via HTTP header.

```typescript
// src/lib/tenant.ts - NEW FILE

/**
 * Tenant management utilities for URL fragment-based tenant selection.
 * 
 * URL Format: https://example.com/#tenant-id/route/path
 * 
 * Examples:
 *   https://example.com/#acme-corp           → tenant: acme-corp, route: /
 *   https://example.com/#acme-corp/settings  → tenant: acme-corp, route: /settings
 *   https://example.com/#/settings           → tenant: default, route: /settings
 *   https://example.com/                     → tenant: default, route: /
 */

const DEFAULT_TENANT = 'default';
const TENANT_STORAGE_KEY = 'currentTenant';

export interface TenantRouteInfo {
  tenantId: string;
  route: string;
}

/**
 * Parse the URL fragment to extract tenant ID and route.
 */
export function parseTenantFromFragment(hash: string = window.location.hash): TenantRouteInfo {
  // Remove leading #
  const fragment = hash.startsWith('#') ? hash.substring(1) : hash;
  
  if (!fragment) {
    return { tenantId: getStoredTenant() || DEFAULT_TENANT, route: '/' };
  }
  
  // Split on first /
  const slashIndex = fragment.indexOf('/');
  
  if (slashIndex === -1) {
    // No route, just tenant: #acme-corp
    return { tenantId: fragment || DEFAULT_TENANT, route: '/' };
  }
  
  if (slashIndex === 0) {
    // Route only, no tenant: #/settings
    return { tenantId: getStoredTenant() || DEFAULT_TENANT, route: fragment };
  }
  
  // Both tenant and route: #acme-corp/settings
  const tenantId = fragment.substring(0, slashIndex);
  const route = fragment.substring(slashIndex); // includes leading /
  
  return { tenantId, route };
}

/**
 * Build a URL fragment from tenant and route.
 */
export function buildTenantFragment(tenantId: string, route: string = '/'): string {
  if (tenantId === DEFAULT_TENANT && route === '/') {
    return '';
  }
  if (tenantId === DEFAULT_TENANT) {
    return `#${route}`;
  }
  return `#${tenantId}${route}`;
}

/**
 * Get stored tenant from sessionStorage (persists across page reloads in same tab).
 */
export function getStoredTenant(): string | null {
  return sessionStorage.getItem(TENANT_STORAGE_KEY);
}

/**
 * Store current tenant in sessionStorage.
 */
export function setStoredTenant(tenantId: string): void {
  sessionStorage.setItem(TENANT_STORAGE_KEY, tenantId);
}

/**
 * Switch to a different tenant.
 * Updates URL fragment and reloads the app with new tenant context.
 */
export function switchTenant(tenantId: string): void {
  setStoredTenant(tenantId);
  window.location.hash = buildTenantFragment(tenantId, '/');
  // Force reload to reinitialize with new tenant context
  window.location.reload();
}
```

### Tenant Context Provider

```tsx
// src/context/TenantContext.tsx - NEW FILE

import React, { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import { parseTenantFromFragment, setStoredTenant, switchTenant, TenantRouteInfo } from '../lib/tenant';

interface TenantContextValue {
  tenantId: string;
  route: string;
  switchTenant: (tenantId: string) => void;
}

const TenantContext = createContext<TenantContextValue | null>(null);

export function TenantProvider({ children }: { children: ReactNode }) {
  const [tenantInfo, setTenantInfo] = useState<TenantRouteInfo>(() => 
    parseTenantFromFragment()
  );

  useEffect(() => {
    // Store tenant when it changes
    setStoredTenant(tenantInfo.tenantId);
  }, [tenantInfo.tenantId]);

  useEffect(() => {
    // Listen for hash changes (browser back/forward, manual URL edit)
    const handleHashChange = () => {
      const newInfo = parseTenantFromFragment();
      if (newInfo.tenantId !== tenantInfo.tenantId) {
        // Tenant changed - reload to reinitialize
        window.location.reload();
      } else {
        setTenantInfo(newInfo);
      }
    };

    window.addEventListener('hashchange', handleHashChange);
    return () => window.removeEventListener('hashchange', handleHashChange);
  }, [tenantInfo.tenantId]);

  const value: TenantContextValue = {
    tenantId: tenantInfo.tenantId,
    route: tenantInfo.route,
    switchTenant,
  };

  return (
    <TenantContext.Provider value={value}>
      {children}
    </TenantContext.Provider>
  );
}

export function useTenant(): TenantContextValue {
  const context = useContext(TenantContext);
  if (!context) {
    throw new Error('useTenant must be used within TenantProvider');
  }
  return context;
}
```

### API Client Changes

```typescript
// src/api/index.ts - UPDATE

import * as config from '../config';
import { getStoredTenant } from '../lib/tenant';

const walletBackendUrl = config.BACKEND_URL;

// Update buildGetHeaders to include tenant header
const buildGetHeaders = useCallback((
  headers: { [header: string]: string },
  options: { appToken?: string },
): { [header: string]: string } => {
  const authz = options?.appToken || appToken;
  const tenantId = getStoredTenant() || 'default';
  
  return {
    ...headers,
    'X-Tenant-ID': tenantId,  // ADD THIS LINE
    ...(authz ? { Authorization: `Bearer ${authz}` } : {}),
  };
}, [appToken]);

// buildMutationHeaders inherits from buildGetHeaders, so it gets the tenant too
```

### IndexedDB Tenant Isolation

Local cached data must be tenant-isolated:

```typescript
// src/indexedDB.ts - UPDATE

import { getStoredTenant } from './lib/tenant';

/**
 * Generate a tenant-scoped cache key.
 * This ensures credentials from tenant A don't appear in tenant B.
 */
function getTenantScopedKey(path: string, dbKey: string): string {
  const tenantId = getStoredTenant() || 'default';
  return `${tenantId}:${dbKey}`;
}

// Update addItem and getItem to use scoped keys
export async function addItem(path: string, dbKey: string, data: any): Promise<void> {
  const scopedKey = getTenantScopedKey(path, dbKey);
  const storeName = getMappedStoreName(path);
  // ... rest unchanged, use scopedKey
}

export async function getItem(path: string, dbKey: string): Promise<any> {
  const scopedKey = getTenantScopedKey(path, dbKey);
  const storeName = getMappedStoreName(path);
  // ... rest unchanged, use scopedKey
}
```

### App Provider Update

```tsx
// src/AppProvider.tsx - UPDATE

import { TenantProvider } from './context/TenantContext';

const AppProvider: React.FC<RootProviderProps> = ({ children }) => {
  return (
    <TenantProvider>  {/* ADD - should be outer provider */}
      <StatusContextProvider>
        <SessionContextProvider>
          {/* ... rest unchanged ... */}
        </SessionContextProvider>
      </StatusContextProvider>
    </TenantProvider>
  );
};
```

### Tenant Selection UI (Optional)

```tsx
// src/components/TenantSelector.tsx - NEW FILE

import React, { useState, useEffect } from 'react';
import axios from 'axios';
import * as config from '../config';
import { useTenant } from '../context/TenantContext';

interface Tenant {
  id: string;
  name: string;
  display_name: string;
}

export function TenantSelector() {
  const { tenantId, switchTenant } = useTenant();
  const [tenants, setTenants] = useState<Tenant[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // Fetch user's available tenants
    axios.get(`${config.BACKEND_URL}/api/user/tenants`, {
      headers: { 'X-Tenant-ID': tenantId }
    })
      .then(res => setTenants(res.data.tenants))
      .catch(err => console.error('Failed to load tenants', err))
      .finally(() => setLoading(false));
  }, [tenantId]);

  if (loading || tenants.length <= 1) {
    return null; // Don't show selector if only one tenant
  }

  return (
    <select 
      value={tenantId} 
      onChange={e => switchTenant(e.target.value)}
      className="tenant-selector"
    >
      {tenants.map(t => (
        <option key={t.id} value={t.id}>
          {t.display_name || t.name}
        </option>
      ))}
    </select>
  );
}
```

### Handling OAuth Redirects

OAuth/OpenID4VCI redirects need special handling since fragments aren't sent to servers:

```typescript
// src/hocs/UriHandlerProvider.tsx - UPDATE handle function

async function handle(urlToCheck: string) {
  const u = new URL(urlToCheck);
  
  // Check if this is an OAuth callback
  if (u.searchParams.get('code') || u.searchParams.get('credential_offer')) {
    // Preserve tenant context through OAuth flow using state parameter
    const state = u.searchParams.get('state');
    if (state) {
      try {
        const stateData = JSON.parse(atob(state));
        if (stateData.tenant && stateData.tenant !== tenantId) {
          // Restore tenant from OAuth state
          setStoredTenant(stateData.tenant);
        }
      } catch (e) {
        // State wasn't our tenant-encoded format
      }
    }
  }
  // ... rest of handler unchanged
}

// When generating authorization requests, encode tenant in state
const generateAuthRequest = (credentialIssuer, ...) => {
  const state = btoa(JSON.stringify({
    tenant: getStoredTenant(),
    nonce: crypto.randomUUID(),
  }));
  // Include state in authorization request
};
```

### Summary of Frontend Changes

| File | Change Type | Complexity |
|------|-------------|------------|
## JWT Token Changes

The JWT token should include tenant context:

```go
// pkg/middleware/auth.go

type JWTClaims struct {
    UserID   string `json:"sub"`
    TenantID string `json:"tenant,omitempty"` // NEW: tenant context
    jwt.RegisteredClaims
}
```

When a user logs in to a specific tenant, the token includes that tenant ID. This provides:
1. Validation that the user accessed the correct tenant
2. Ability to track which tenant the session is for

## Summary of Changes

### Backend Changes (go-wallet-backend)

| Component | Change Type | Description |
|-----------|-------------|-------------|
| `domain/tenant.go` | NEW | Tenant and UserTenantMembership types |
| `domain/credential.go` | MODIFY | Add TenantID field |
| `domain/presentation.go` | MODIFY | Add TenantID field |
| `storage/interface.go` | MODIFY | Add TenantStore, UserTenantStore; update method signatures |
| `storage/memory/` | MODIFY | Implement tenant-scoped stores |
| `storage/mongodb/` | MODIFY | Implement tenant-scoped stores |
| `service/tenant.go` | NEW | Tenant service |
| `service/user_tenant.go` | NEW | User-tenant membership service |
| `service/credential.go` | MODIFY | Add tenantID parameter |
| `pkg/middleware/tenant.go` | NEW | Tenant header and membership middleware |
| `api/handlers.go` | MODIFY | Extract tenant context from header |
| `cmd/server/main.go` | MODIFY | Add /api prefix, tenant-scoped routes |
| `pkg/config/config.go` | MODIFY | Add tenant configuration |

### Frontend Changes (wallet-frontend)

| File | Change Type | Description |
|------|-------------|-------------|
| `src/lib/tenant.ts` | NEW | Tenant parsing and management utilities (~70 lines) |
| `src/context/TenantContext.tsx` | NEW | React context for tenant state (~50 lines) |
| `src/api/index.ts` | MODIFY | Add X-Tenant-ID header to requests (1 line) |
| `src/indexedDB.ts` | MODIFY | Scope cache keys by tenant (~5 lines) |
| `src/AppProvider.tsx` | MODIFY | Add TenantProvider wrapper (2 lines) |
| `src/hocs/UriHandlerProvider.tsx` | MODIFY | Preserve tenant in OAuth flows (~15 lines) |
| `src/components/TenantSelector.tsx` | NEW (optional) | UI for switching tenants (~40 lines) |

**Total frontend code changes: ~180 lines** (mostly new code, minimal changes to existing)

## Security Considerations

1. **Tenant Isolation**: All database queries must include tenant_id to prevent cross-tenant data access
2. **Header Validation**: X-Tenant-ID header must be validated against database
3. **Default Tenant**: Consider if a "default" tenant should be accessible or require explicit selection
4. **Admin Access**: Consider separate admin routes for tenant management (no tenant header required)
5. **WebAuthn RP ID**: WebAuthn credentials are RP-scoped, so all tenants share the same RP ID
6. **Fragment Security**: URL fragments are not sent to server - tenant ID must be in header
7. **Local Storage Isolation**: IndexedDB keys must be tenant-scoped to prevent cache leakage

## CDN Configuration

With the fragment-based approach, CDN configuration is trivial:

```
# No special rules needed!
# All static assets cached as-is at example.com/*
# API calls go to api.example.com/* or example.com/api/*
```

This is the primary advantage over path-based tenant routing.

## Design Decisions

### 1. Tenant Discovery: Tenant Selector UI

**Decision**: Implement a simple tenant selector in the frontend.

**Rationale**:
- Tenants must not know about each other (isolation requirement)
- User-to-tenant mapping must be user-owned, not tenant-accessible
- Backend stores memberships but never exposes cross-tenant data

**Implementation**:
```typescript
// GET /api/user/tenants - Returns ONLY tenants the authenticated user belongs to
// Response: { tenants: [{ id, name, display_name, branding }] }
// This endpoint is protected - only the user can see their own memberships
```

**Flow**:
1. User visits `example.com/` (no tenant in fragment)
2. If not logged in → Login page
3. If logged in → Fetch user's tenants → Show selector if multiple
4. On tenant selection → Navigate to `example.com/#tenant-id`

### 2. Keystore: Per-Tenant Private Data

**Decision**: Each tenant has its own encrypted private data (keystore).

#### Analysis

**Option A: Shared Keystore (Single unlock for all tenants)**

| Pros | Cons |
|------|------|
| Single WebAuthn unlock | Credential leak affects all tenants |
| Simpler user experience | Harder to revoke access per-tenant |
| Less storage | Admin can't force re-key per tenant |
| | Cross-tenant key correlation possible |
| | Can't have different security policies per tenant |

**Option B: Per-Tenant Keystore (Unlock per tenant)** ✅ CHOSEN

| Pros | Cons |
|------|------|
| Complete tenant isolation | Multiple unlock prompts |
| Per-tenant security policies | More storage (one keystore per tenant) |
| Revoke tenant access without affecting others | Slightly more complex sync logic |
| No cross-tenant key correlation | |
| Tenant admin can enforce re-keying | |
| Easier compliance (data residency) | |

**Rationale for Per-Tenant**:
- Aligns with the core principle of complete tenant isolation
- A compromised keystore in tenant A doesn't expose tenant B credentials
- Tenant admins can enforce security policies independently
- Easier to implement "leave tenant" / "remove user" cleanly
- User unlocks only when switching tenants (not on every page load)

#### Backend Changes for Per-Tenant Keystore

```go
// The existing private_data endpoint becomes tenant-scoped
// GET  /api/user/session/private-data  (with X-Tenant-ID header)
// POST /api/user/session/private-data  (with X-Tenant-ID header)

// Domain change: PrivateData becomes tenant-scoped
type UserPrivateData struct {
    UserID     UserID   `json:"user_id" bson:"user_id" gorm:"index;not null"`
    TenantID   TenantID `json:"tenant_id" bson:"tenant_id" gorm:"index;not null"`
    PrivateData []byte  `json:"private_data" bson:"private_data"` // encrypted blob
    ETag       string   `json:"etag" bson:"etag"`
    UpdatedAt  time.Time `json:"updated_at" bson:"updated_at"`
    
    // Composite primary key: (user_id, tenant_id)
}
```

#### Frontend Changes for Per-Tenant Keystore

```typescript
// src/services/LocalStorageKeystore.ts - Storage keys become tenant-scoped

// Current (global):
// IndexedDB: privateData[userHandleB64u] = encryptedContainer

// New (per-tenant):
// IndexedDB: privateData[`${tenantId}:${userHandleB64u}`] = encryptedContainer

// The keystore unlock flow becomes:
// 1. User selects tenant (or navigates via fragment)
// 2. Check if keystore is open for THIS tenant
// 3. If not, prompt for WebAuthn unlock
// 4. Sync private data for this tenant
```

### 3. Credentials: Per-Tenant with No Sharing

**Decision**: Credentials are strictly per-tenant. Cross-tenant sharing is out of scope.

**Rationale**:
- Simplifies the data model significantly
- Aligns with organizational boundaries (credentials from Employer A shouldn't leak to Employer B)
- Future cross-tenant sharing (if needed) can be done via:
  - Explicit "credential export" feature
  - Internal re-issuance (issuer creates new credential in target tenant)
  - Both are user-initiated, auditable actions

### 4. Tenant Branding

**Decision**: Tenants can have custom branding (logo, colors, display name).

#### Backend: Tenant Metadata

```go
// domain/tenant.go - Extended Tenant struct

type TenantBranding struct {
    LogoURL        string `json:"logo_url,omitempty" bson:"logo_url,omitempty"`
    LogoDarkURL    string `json:"logo_dark_url,omitempty" bson:"logo_dark_url,omitempty"`
    PrimaryColor   string `json:"primary_color,omitempty" bson:"primary_color,omitempty"`   // hex: #3B82F6
    AccentColor    string `json:"accent_color,omitempty" bson:"accent_color,omitempty"`
    BackgroundURL  string `json:"background_url,omitempty" bson:"background_url,omitempty"`
    FaviconURL     string `json:"favicon_url,omitempty" bson:"favicon_url,omitempty"`
}

type Tenant struct {
    ID          TenantID       `json:"id" bson:"_id" gorm:"primaryKey"`
    Name        string         `json:"name" bson:"name" gorm:"not null"`
    DisplayName string         `json:"display_name" bson:"display_name"`
    Branding    TenantBranding `json:"branding" bson:"branding" gorm:"embedded"`
    Enabled     bool           `json:"enabled" bson:"enabled" gorm:"default:true"`
    CreatedAt   time.Time      `json:"created_at" bson:"created_at" gorm:"autoCreateTime"`
    UpdatedAt   time.Time      `json:"updated_at" bson:"updated_at" gorm:"autoUpdateTime"`
}
```

#### API Endpoints for Branding

```
# Public endpoint - no auth required (for login page branding)
GET /api/tenants/:id/branding
Response: {
  "display_name": "Acme Corp",
  "branding": {
    "logo_url": "https://cdn.example.com/acme/logo.svg",
    "primary_color": "#3B82F6",
    ...
  }
}

# Admin endpoint - tenant admin only
PUT /api/tenants/:id/branding  (requires tenant admin role)
```

#### Frontend: Dynamic Theming (wallet-frontend scope)

```typescript
// src/context/TenantContext.tsx - Extended with branding

interface TenantBranding {
  logoUrl?: string;
  logoDarkUrl?: string;
  primaryColor?: string;
  accentColor?: string;
  backgroundUrl?: string;
  faviconUrl?: string;
}

interface TenantContextValue {
  tenantId: string;
  displayName: string;
  branding: TenantBranding | null;
  isLoading: boolean;
  switchTenant: (tenantId: string) => void;
}

// Apply branding via CSS variables
useEffect(() => {
  if (branding?.primaryColor) {
    document.documentElement.style.setProperty('--color-primary', branding.primaryColor);
  }
  if (branding?.faviconUrl) {
    const link = document.querySelector("link[rel~='icon']");
    if (link) link.href = branding.faviconUrl;
  }
  if (branding?.logoUrl) {
    // Make available via context for Logo components
  }
}, [branding]);
```

#### Missing Frontend Pieces for Branding

| Component | Current State | Needed |
|-----------|--------------|--------|
| CSS Variables | Partially exists | Add tenant-specific overrides |
| Logo component | Hardcoded | Read from TenantContext |
| Favicon | Static | Dynamic update from branding |
| Login page | Generic | Show tenant branding if tenant known |
| Theme persistence | N/A | Cache branding in sessionStorage |

## Implementation Order

1. **Phase 1: Domain & Storage** - Add tenant types, UserPrivateData, and storage interfaces
2. **Phase 2: Migration** - Create migration scripts, add default tenant
3. **Phase 3: Middleware** - Implement tenant header extraction and validation
4. **Phase 4: Services** - Update services to accept tenant context
5. **Phase 5: Handlers** - Update handlers to use tenant context
6. **Phase 6: API Routes** - Add /api prefix, tenant-scoped routes
7. **Phase 7: Frontend Core** - Add tenant context, API header, IndexedDB scoping
8. **Phase 8: Frontend Keystore** - Per-tenant keystore storage and unlock
9. **Phase 9: Frontend OAuth** - Update OAuth flows to preserve tenant
10. **Phase 10: Tenant Selector UI** - Tenant selection component
11. **Phase 11: Branding Backend** - Tenant branding endpoints
12. **Phase 12: Branding Frontend** - Dynamic theming, logo components
13. **Phase 13: Testing** - Integration tests for multi-tenant scenarios
14. **Phase 14: Audit Infrastructure** - Per-tenant audit logging with external recipients
15. **Phase 15: Rate Limiting** - Per-tenant rate limiting middleware

## Resolved Design Questions

1. ~~**Auto-Join Policy**~~: ✅ **RESOLVED** - Configurable per-tenant
   - Each tenant configures: `invite-only`, `open`, or `approval-required`
   - See enrollment configuration below

2. ~~**Tenant Creation**~~: ✅ **RESOLVED** - Admin process via YAML configuration
   - Initial: YAML file loaded at container startup
   - Future: CRUD API with database backend and backup/snapshot

3. ~~**Rate Limiting**~~: ✅ **RESOLVED** - Per-tenant rate limiting
   - Configurable per tenant in YAML

4. ~~**Audit Logging**~~: ✅ **RESOLVED** - Per-tenant with customer-defined recipients
   - Always logged internally
   - Optional external recipients: webhook, syslog, S3

## Remaining Open Question

**Tenant Deletion / User Removal**: What happens to credentials when:
- User leaves a tenant voluntarily?
- Tenant admin removes a user?
- Tenant is deactivated/deleted?
- **Suggestion**: Credentials become inaccessible but remain for audit trail

---

## Tenant Configuration & Lifecycle

### Configuration-Driven Tenant Management

**Decision**: Tenants are defined via YAML configuration files, loaded at container startup.

**Rationale**:
- Simple operational model for initial deployment
- Easy to control which containers serve which tenants
- Configuration can be version-controlled
- Supports GitOps workflows
- Future: Add CRUD API for dynamic tenant management with database backup/snapshot

### Tenant Configuration File

```yaml
# config/tenants.yaml

tenants:
  - id: "acme-corp"
    name: "Acme Corporation"
    display_name: "Acme Corp Wallet"
    enabled: true
    
    branding:
      logo_url: "https://cdn.example.com/acme/logo.svg"
      logo_dark_url: "https://cdn.example.com/acme/logo-dark.svg"
      primary_color: "#3B82F6"
      accent_color: "#10B981"
      favicon_url: "https://cdn.example.com/acme/favicon.ico"
    
    enrollment:
      policy: "invite-only"  # invite-only | open | approval-required
      allowed_email_domains: ["acme.com", "acme.org"]
      auto_approve_domains: ["acme.com"]
    
    rate_limits:
      requests_per_minute: 100
      requests_per_hour: 1000
      storage_credentials_max: 500
      storage_presentations_max: 1000
    
    audit:
      enabled: true
      retention_days: 365
      log_recipients:
        - type: "webhook"
          url: "https://siem.acme.com/webhook/wallet-audit"
          headers:
            Authorization: "Bearer ${ACME_AUDIT_TOKEN}"
        - type: "syslog"
          host: "syslog.acme.com"
          port: 514
          protocol: "tcp"
    
    # Optional: tenant-specific trust configuration
    trust:
      x509_roots: "/etc/wallet/tenants/acme/trust-roots.pem"
      allowed_issuers:
        - "https://issuer.acme.com"
        - "https://gov-issuer.example.gov"

  - id: "university"
    name: "State University"
    display_name: "University Digital Wallet"
    enabled: true
    
    branding:
      logo_url: "https://cdn.example.com/university/logo.svg"
      primary_color: "#7C3AED"
    
    enrollment:
      policy: "open"
      allowed_email_domains: ["*.edu"]
    
    rate_limits:
      requests_per_minute: 50
      requests_per_hour: 500
    
    audit:
      enabled: true
      retention_days: 90
      # No external recipients - internal logging only

  - id: "default"
    name: "Default"
    display_name: "Digital Wallet"
    enabled: true
    enrollment:
      policy: "open"
    rate_limits:
      requests_per_minute: 30
      requests_per_hour: 300
    audit:
      enabled: true
      retention_days: 30
```

### Go Configuration Structures

```go
// pkg/config/tenant.go

type TenantEnrollment struct {
    Policy              string   `yaml:"policy" json:"policy"` // invite-only, open, approval-required
    AllowedEmailDomains []string `yaml:"allowed_email_domains" json:"allowed_email_domains,omitempty"`
    AutoApproveDomains  []string `yaml:"auto_approve_domains" json:"auto_approve_domains,omitempty"`
}

type TenantRateLimits struct {
    RequestsPerMinute       int `yaml:"requests_per_minute" json:"requests_per_minute"`
    RequestsPerHour         int `yaml:"requests_per_hour" json:"requests_per_hour"`
    StorageCredentialsMax   int `yaml:"storage_credentials_max" json:"storage_credentials_max,omitempty"`
    StoragePresentationsMax int `yaml:"storage_presentations_max" json:"storage_presentations_max,omitempty"`
}

type AuditLogRecipient struct {
    Type     string            `yaml:"type" json:"type"` // webhook, syslog, s3
    URL      string            `yaml:"url,omitempty" json:"url,omitempty"`
    Host     string            `yaml:"host,omitempty" json:"host,omitempty"`
    Port     int               `yaml:"port,omitempty" json:"port,omitempty"`
    Protocol string            `yaml:"protocol,omitempty" json:"protocol,omitempty"`
    Headers  map[string]string `yaml:"headers,omitempty" json:"headers,omitempty"`
    Bucket   string            `yaml:"bucket,omitempty" json:"bucket,omitempty"`
}

type TenantAudit struct {
    Enabled       bool                `yaml:"enabled" json:"enabled"`
    RetentionDays int                 `yaml:"retention_days" json:"retention_days"`
    LogRecipients []AuditLogRecipient `yaml:"log_recipients,omitempty" json:"log_recipients,omitempty"`
}

type TenantTrust struct {
    X509Roots      string   `yaml:"x509_roots,omitempty" json:"x509_roots,omitempty"`
    AllowedIssuers []string `yaml:"allowed_issuers,omitempty" json:"allowed_issuers,omitempty"`
}

type TenantConfig struct {
    ID          string           `yaml:"id" json:"id"`
    Name        string           `yaml:"name" json:"name"`
    DisplayName string           `yaml:"display_name" json:"display_name"`
    Enabled     bool             `yaml:"enabled" json:"enabled"`
    Branding    TenantBranding   `yaml:"branding,omitempty" json:"branding,omitempty"`
    Enrollment  TenantEnrollment `yaml:"enrollment" json:"enrollment"`
    RateLimits  TenantRateLimits `yaml:"rate_limits" json:"rate_limits"`
    Audit       TenantAudit      `yaml:"audit" json:"audit"`
    Trust       TenantTrust      `yaml:"trust,omitempty" json:"trust,omitempty"`
}

type TenantsConfig struct {
    Tenants []TenantConfig `yaml:"tenants"`
}
```

### Loading Tenant Configuration

```go
// pkg/config/loader.go

func LoadTenantsConfig(path string) (*TenantsConfig, error) {
    data, err := os.ReadFile(path)
    if err != nil {
        return nil, fmt.Errorf("failed to read tenants config: %w", err)
    }
    
    // Expand environment variables in the config
    expanded := os.ExpandEnv(string(data))
    
    var config TenantsConfig
    if err := yaml.Unmarshal([]byte(expanded), &config); err != nil {
        return nil, fmt.Errorf("failed to parse tenants config: %w", err)
    }
    
    // Validate and set defaults
    for i := range config.Tenants {
        if err := validateTenantConfig(&config.Tenants[i]); err != nil {
            return nil, fmt.Errorf("invalid tenant config for %s: %w", 
                config.Tenants[i].ID, err)
        }
    }
    
    return &config, nil
}

// Optional: Watch for config changes and reload
func WatchTenantsConfig(path string, onChange func(*TenantsConfig)) error {
    // Use fsnotify to watch for changes
    // On change, reload and call onChange callback
}
```

### Container Routing Strategy

For large-scale deployments, route traffic to tenant-specific container pools:

```
                     ┌─────────────────────────────────────┐
                     │           Load Balancer              │
                     │  (routes based on X-Tenant-ID)       │
                     └─────────────────────────────────────┘
                                      │
            ┌─────────────────────────┼─────────────────────────┐
            │                         │                         │
            ▼                         ▼                         ▼
┌───────────────────┐   ┌───────────────────┐   ┌───────────────────┐
│  Container Pool A  │   │  Container Pool B  │   │  Container Pool C  │
│  tenants.yaml:     │   │  tenants.yaml:     │   │  tenants.yaml:     │
│  - acme-corp       │   │  - university      │   │  - default         │
│  - partner-1       │   │  - school-district │   │  - trial-tenants   │
└───────────────────┘   └───────────────────┘   └───────────────────┘
```

**Benefits**:
- Tenant isolation at infrastructure level
- Independent scaling per tenant
- Blast radius containment
- Tenant-specific maintenance windows

### Per-Tenant Rate Limiting

```go
// pkg/middleware/ratelimit.go

type TenantRateLimiter struct {
    limiters map[domain.TenantID]*rate.Limiter
    configs  map[domain.TenantID]TenantRateLimits
    mu       sync.RWMutex
}

func NewTenantRateLimiter(tenants []TenantConfig) *TenantRateLimiter {
    rl := &TenantRateLimiter{
        limiters: make(map[domain.TenantID]*rate.Limiter),
        configs:  make(map[domain.TenantID]TenantRateLimits),
    }
    
    for _, t := range tenants {
        tid := domain.TenantID(t.ID)
        rl.configs[tid] = t.RateLimits
        // Per-minute rate limiter
        rl.limiters[tid] = rate.NewLimiter(
            rate.Limit(t.RateLimits.RequestsPerMinute)/60,
            t.RateLimits.RequestsPerMinute, // burst
        )
    }
    
    return rl
}

func TenantRateLimitMiddleware(rl *TenantRateLimiter) gin.HandlerFunc {
    return func(c *gin.Context) {
        tenantID, exists := c.Get("tenant_id")
        if !exists {
            c.Next()
            return
        }
        
        tid := tenantID.(domain.TenantID)
        limiter := rl.GetLimiter(tid)
        
        if limiter != nil && !limiter.Allow() {
            c.AbortWithStatusJSON(429, gin.H{
                "error": "Rate limit exceeded",
                "retry_after": limiter.Reserve().Delay().Seconds(),
            })
            return
        }
        
        c.Next()
    }
}
```

### Per-Tenant Audit Logging

```go
// pkg/audit/audit.go

type AuditEvent struct {
    Timestamp  time.Time         `json:"timestamp"`
    TenantID   domain.TenantID   `json:"tenant_id"`
    UserID     string            `json:"user_id,omitempty"`
    Action     string            `json:"action"`
    Resource   string            `json:"resource"`
    ResourceID string            `json:"resource_id,omitempty"`
    Details    map[string]any    `json:"details,omitempty"`
    IPAddress  string            `json:"ip_address,omitempty"`
    UserAgent  string            `json:"user_agent,omitempty"`
    Success    bool              `json:"success"`
    Error      string            `json:"error,omitempty"`
}

type AuditLogger interface {
    Log(ctx context.Context, event AuditEvent) error
    Close() error
}

// TenantAuditRouter routes audit events to tenant-specific destinations
type TenantAuditRouter struct {
    loggers  map[domain.TenantID][]AuditLogger
    internal *zap.Logger // Always log internally
}

func NewTenantAuditRouter(tenants []TenantConfig, logger *zap.Logger) (*TenantAuditRouter, error) {
    router := &TenantAuditRouter{
        loggers:  make(map[domain.TenantID][]AuditLogger),
        internal: logger,
    }
    
    for _, t := range tenants {
        tid := domain.TenantID(t.ID)
        
        if !t.Audit.Enabled {
            continue
        }
        
        var tenantLoggers []AuditLogger
        
        for _, recipient := range t.Audit.LogRecipients {
            switch recipient.Type {
            case "webhook":
                tenantLoggers = append(tenantLoggers, NewWebhookAuditLogger(recipient))
            case "syslog":
                tenantLoggers = append(tenantLoggers, NewSyslogAuditLogger(recipient))
            case "s3":
                tenantLoggers = append(tenantLoggers, NewS3AuditLogger(recipient))
            }
        }
        
        router.loggers[tid] = tenantLoggers
    }
    
    return router, nil
}

func (r *TenantAuditRouter) Log(ctx context.Context, event AuditEvent) error {
    // Always log internally
    r.internal.Info("audit",
        zap.String("tenant_id", string(event.TenantID)),
        zap.String("action", event.Action),
        zap.String("resource", event.Resource),
        zap.Bool("success", event.Success),
    )
    
    // Send to tenant-specific recipients (async)
    loggers := r.loggers[event.TenantID]
    for _, logger := range loggers {
        go func(l AuditLogger) {
            if err := l.Log(ctx, event); err != nil {
                r.internal.Error("failed to send audit log", 
                    zap.Error(err),
                    zap.String("tenant_id", string(event.TenantID)),
                )
            }
        }(logger)
    }
    
    return nil
}

// Example: Webhook audit logger
type WebhookAuditLogger struct {
    url     string
    headers map[string]string
    client  *http.Client
}

func (w *WebhookAuditLogger) Log(ctx context.Context, event AuditEvent) error {
    body, _ := json.Marshal(event)
    req, _ := http.NewRequestWithContext(ctx, "POST", w.url, bytes.NewReader(body))
    req.Header.Set("Content-Type", "application/json")
    for k, v := range w.headers {
        req.Header.Set(k, v)
    }
    
    resp, err := w.client.Do(req)
    if err != nil {
        return err
    }
    defer resp.Body.Close()
    
    if resp.StatusCode >= 400 {
        return fmt.Errorf("webhook returned %d", resp.StatusCode)
    }
    
    return nil
}
```

### Audit Event Types

```go
// pkg/audit/events.go

const (
    // Authentication events
    ActionUserLogin           = "user.login"
    ActionUserLogout          = "user.logout"
    ActionUserRegister        = "user.register"
    ActionWebAuthnRegister    = "webauthn.register"
    
    // Credential events
    ActionCredentialStore     = "credential.store"
    ActionCredentialDelete    = "credential.delete"
    ActionCredentialAccess    = "credential.access"
    
    // Presentation events
    ActionPresentationCreate  = "presentation.create"
    ActionPresentationDelete  = "presentation.delete"
    ActionPresentationShare   = "presentation.share"
    
    // Tenant events
    ActionTenantJoin          = "tenant.join"
    ActionTenantLeave         = "tenant.leave"
    ActionTenantMemberRemove  = "tenant.member.remove"
    
    // Admin events
    ActionTenantConfigUpdate  = "tenant.config.update"
    ActionTenantBrandingUpdate = "tenant.branding.update"
)
```

### Future: Tenant CRUD API with Backup/Snapshot

For future dynamic tenant management (with database backend):

```go
// Future API endpoints (super-admin only)

// Tenant CRUD
// POST   /api/admin/tenants              - Create tenant
// GET    /api/admin/tenants              - List all tenants  
// GET    /api/admin/tenants/:id          - Get tenant details
// PUT    /api/admin/tenants/:id          - Update tenant config
// DELETE /api/admin/tenants/:id          - Disable/delete tenant

// Backup & Snapshot (database backend required)
// POST   /api/admin/tenants/:id/snapshot - Create backup snapshot
// GET    /api/admin/tenants/:id/snapshots - List available snapshots
// POST   /api/admin/tenants/:id/restore  - Restore from snapshot
// GET    /api/admin/tenants/:id/export   - Export tenant config as YAML
```

---

## Document Status

| Aspect | Status |
|--------|--------|
| **Overall Status** | 🟡 **Draft - Pending Team Review** |
| **Date** | 2024-12-15 |
| **Author** | (Auto-generated design document) |

### Decisions Made

| Decision | Status | Notes |
|----------|--------|-------|
| Tenant in HTTP header for API calls | ✅ Decided | `X-Tenant-ID` header |
| Per-tenant credential isolation | ✅ Decided | Credentials, presentations scoped to tenant |
| Per-tenant keystore | ✅ Decided | Browser's localStorage with tenant prefix |
| YAML-based tenant configuration | ✅ Decided | `config/tenants.yaml` with hot-reload |
| Per-tenant branding | ✅ Decided | Logo, colors, favicon configurable |
| Per-tenant rate limiting | ✅ Decided | Token bucket per tenant |
| Per-tenant audit logging | ✅ Decided | Webhook, syslog, S3 recipients |
| Tenant auto-join policy | ✅ Decided | Per-tenant config: `auto_join`, `join_code` |
| Tenant selector UI | ✅ Decided | Dropdown in header when user has multiple tenants |

### Decisions Pending Team Input

| Decision | Options | Considerations |
|----------|---------|----------------|
| **Frontend routing approach** | Fragment (`/#tenant/path`) vs Path (`/tenant/path`) | See "Frontend SPA Route Analysis" section |

### Action Items

1. [ ] Team review of routing options (Fragment vs Path)
2. [ ] Decision on routing approach
3. [ ] Update this ADR with final decision
4. [ ] Begin implementation

---

*This ADR is ready for team discussion. Please review the "Frontend SPA Route Analysis" section and provide input on the routing approach preference.*
