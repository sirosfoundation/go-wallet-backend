# Dynamic Allowlist Design for Wallet Proxy

## Problem Statement

Trust frameworks (like OIDF or TRAIN) can contain thousands of issuers and verifiers, far exceeding the number that any individual wallet instance will actually interact with. Pre-populating a proxy allowlist from a trust framework would be:

1. **Wasteful**: Most entries would never be used
2. **Slow**: Large allowlists degrade filtering performance  
3. **Stale**: Trust framework membership changes over time
4. **Overkill**: A wallet typically interacts with 5-20 issuers/verifiers

Instead, the proxy allowlist should be populated **just-in-time** as the wallet discovers and interacts with issuers and verifiers.

## Analysis of Wallet Flows

### OpenID4VCI (Credential Issuance) Flow

The frontend processes credential offers as follows:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    CREDENTIAL OFFER ENTRY POINTS                            │
├─────────────────────────────────────────────────────────────────────────────┤
│  1. Deep link:     openid-credential-offer://?credential_offer={...}       │
│  2. QR code URL:   https://...?credential_offer={...}                       │
│  3. URI reference: https://...?credential_offer_uri=https://issuer/offer/x │
└─────────────────────────────────────────────────────────────────────────────┘
```

**The critical insight**: The `credential_issuer` field is available **before** any proxy request is made:

```typescript
// Credential offer contains issuer identifier upfront
const offer = {
  credential_issuer: "https://issuer.example.com",   // ← AVAILABLE IMMEDIATELY
  credential_configuration_ids: ["PID_SD_JWT"],
  grants: { ... }
}
```

**Proxied requests in order**:
| # | Endpoint | When to Allowlist |
|---|----------|-------------------|
| 1 | `{credential_offer_uri}` | Before this call (URI known from QR/deeplink) |
| 2 | `{issuer}/.well-known/openid-credential-issuer` | After parsing offer |
| 3 | `{issuer}/.well-known/oauth-authorization-server` | After parsing offer |
| 4 | `{authz_server}/par` | After metadata discovery |
| 5 | `{authz_server}/token` | After authorization |
| 6 | `{issuer}/credential` | After token exchange |
| 7 | `{issuer}/credential_deferred` | Only if deferred |

### OpenID4VP (Credential Presentation) Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    AUTHORIZATION REQUEST ENTRY POINTS                       │
├─────────────────────────────────────────────────────────────────────────────┤
│  1. QR code:   client_id=x509_san_dns:verifier.com&request_uri=https://... │
│  2. Deep link: openid4vp://?client_id=...&request_uri=https://verifier/... │
└─────────────────────────────────────────────────────────────────────────────┘
```

**The critical insight**: The `request_uri` hostname is available **before** any proxy request:

```typescript
// Authorization request contains verifier URL upfront
const params = {
  client_id: "x509_san_dns:verifier.example.com",
  request_uri: "https://verifier.example.com/request/abc123"  // ← AVAILABLE IMMEDIATELY
}
```

**Proxied requests in order**:
| # | Endpoint | When to Allowlist |
|---|----------|-------------------|
| 1 | `{request_uri}` | Before this call (URI from QR/deeplink) |
| 2 | `{response_uri}` | After parsing request object |

## Proposed Architecture

### Option 1: Frontend-Driven (Recommended)

The frontend explicitly tells the backend to add URLs to the allowlist before making proxy requests.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          FRONTEND-DRIVEN FLOW                               │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   CREDENTIAL OFFER RECEIVED                                                 │
│   ├── Parse offer (local, no network)                                      │
│   ├── Extract credential_issuer = "https://issuer.example.com"             │
│   │                                                                         │
│   ▼                                                                         │
│   POST /proxy/allow                          ←── NEW ENDPOINT               │
│   { "url": "https://issuer.example.com" }                                  │
│   Response: 200 OK                                                          │
│   │                                                                         │
│   ▼                                                                         │
│   POST /proxy                                ←── Now allowed                │
│   { "url": "https://issuer.example.com/.well-known/openid-credential-issuer" }
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

**New API Endpoint**:
```go
// POST /proxy/allow
type AllowRequest struct {
    URL        string `json:"url" binding:"required"`      // Base URL or specific URL
    TTL        int    `json:"ttl,omitempty"`               // Optional TTL in seconds
    Reason     string `json:"reason,omitempty"`            // "issuer" or "verifier" (for logging)
}
```

**Advantages**:
- Frontend controls exactly what gets allowlisted
- No need for backend to understand VCI/VP protocols
- Works with future protocol extensions
- Clear separation of concerns

**Disadvantages**:
- Requires frontend changes
- Two API calls instead of one

### Option 2: Backend Protocol-Aware

The backend parses the proxy request URL and auto-allows related endpoints.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        BACKEND PROTOCOL-AWARE FLOW                          │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   POST /proxy                                                               │
│   { "url": "https://issuer.example.com/.well-known/openid-credential-issuer" }
│   │                                                                         │
│   ▼                                                                         │
│   Backend recognizes .well-known/openid-credential-issuer pattern           │
│   ├── Auto-allows issuer.example.com for this session                      │
│   ├── Fetches metadata                                                      │
│   ├── Parses authorization_servers from response                           │
│   └── Auto-allows authorization server hostnames                           │
│                                                                             │
│   Response contains metadata + side-effect of expanded allowlist            │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Advantages**:
- No frontend changes required
- Single API call

**Disadvantages**:
- Backend must understand protocol details
- Implicit behavior is harder to debug
- Protocol changes require backend updates
- Security risk: backend auto-parses and trusts metadata content

### Option 3: Session-Scoped Allowlist (Hybrid)

Combine allowlist with session/flow tracking:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                       SESSION-SCOPED ALLOWLIST                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   POST /proxy/flow/start                                                    │
│   {                                                                         │
│     "type": "openid4vci",                                                  │
│     "credential_issuer": "https://issuer.example.com"                      │
│   }                                                                         │
│   Response: { "flow_id": "abc123" }                                        │
│   │                                                                         │
│   ▼                                                                         │
│   POST /proxy                                                               │
│   {                                                                         │
│     "flow_id": "abc123",                                                   │
│     "url": "https://issuer.example.com/.well-known/..."                    │
│   }                                                                         │
│   │                                                                         │
│   Backend validates URL belongs to flow's allowed domains                   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Advantages**:
- Clear flow boundaries
- Automatic cleanup when flow completes
- Better audit logging

**Disadvantages**:
- More complex state management
- Frontend must track flow IDs

## Recommended Implementation: Option 1 with Enhancements

### API Design

```go
// POST /proxy/allow - Add URL(s) to session allowlist
type ProxyAllowRequest struct {
    URLs   []string `json:"urls" binding:"required,min=1"`  // One or more URLs/hosts
    TTL    int      `json:"ttl,omitempty"`                  // TTL in seconds (default: 3600)
    Reason string   `json:"reason,omitempty"`               // "issuer", "verifier", "offer_uri"
}

type ProxyAllowResponse struct {
    Allowed []string `json:"allowed"`   // URLs that were added
    Expires int64    `json:"expires"`   // Unix timestamp when entries expire
}

// DELETE /proxy/allow - Remove URL(s) from allowlist
type ProxyRemoveRequest struct {
    URLs []string `json:"urls" binding:"required,min=1"`
}

// GET /proxy/allow - List currently allowed URLs (debug/admin)
type ProxyAllowListResponse struct {
    Entries []AllowlistEntry `json:"entries"`
}

type AllowlistEntry struct {
    URL       string `json:"url"`
    AddedAt   int64  `json:"added_at"`
    ExpiresAt int64  `json:"expires_at"`
    Reason    string `json:"reason,omitempty"`
}
```

### Integration Points

**1. Credential Offer Processing (Frontend)**

```typescript
async function handleCredentialOffer(offerURL: string) {
    const offer = parseCredentialOffer(offerURL);
    
    // Step 1: Allow the issuer before any proxy calls
    await api.post('/proxy/allow', {
        urls: [offer.credential_issuer],
        reason: 'issuer'
    });
    
    // Step 2: If offer_uri, allow that specific URL
    if (offer.credential_offer_uri) {
        await api.post('/proxy/allow', {
            urls: [offer.credential_offer_uri],
            reason: 'offer_uri'
        });
    }
    
    // Step 3: Now safe to proxy to issuer
    const metadata = await httpProxy.get(
        `${offer.credential_issuer}/.well-known/openid-credential-issuer`
    );
    
    // Step 4: Allow authorization server if different from issuer
    if (metadata.authorization_servers) {
        await api.post('/proxy/allow', {
            urls: metadata.authorization_servers,
            reason: 'authz_server'
        });
    }
}
```

**2. Authorization Request Processing (Frontend)**

```typescript
async function handleAuthorizationRequest(authzURL: string) {
    const params = parseAuthorizationRequest(authzURL);
    
    // Step 1: Allow the request_uri before fetching
    const requestUriHost = new URL(params.request_uri).origin;
    await api.post('/proxy/allow', {
        urls: [requestUriHost],
        reason: 'verifier'
    });
    
    // Step 2: Fetch the request object
    const requestObject = await httpProxy.get(params.request_uri);
    
    // Step 3: response_uri should be same host (verified by protocol)
    // No need to add separately since host is already allowed
}
```

### Backend Implementation

```go
// pkg/middleware/proxyfilter.go additions

// AllowlistEntry represents a dynamically added allowlist entry
type AllowlistEntry struct {
    URL       string
    Host      string
    AddedAt   time.Time
    ExpiresAt time.Time
    Reason    string
    UserID    string  // For per-user allowlists
}

// ProxyFilter enhanced with session-aware allowlist
type ProxyFilter struct {
    // ... existing fields ...
    
    // Per-user dynamic allowlist (user_id -> entries)
    userAllowlist map[string][]AllowlistEntry
    userMu        sync.RWMutex
    
    defaultTTL    time.Duration
}

// AddAllowedURLForUser adds a URL to a specific user's allowlist
func (f *ProxyFilter) AddAllowedURLForUser(userID, rawURL, reason string, ttl time.Duration) error {
    parsedURL, err := url.Parse(rawURL)
    if err != nil {
        return fmt.Errorf("invalid URL: %w", err)
    }
    
    if ttl == 0 {
        ttl = f.defaultTTL
    }
    
    entry := AllowlistEntry{
        URL:       rawURL,
        Host:      parsedURL.Host,
        AddedAt:   time.Now(),
        ExpiresAt: time.Now().Add(ttl),
        Reason:    reason,
        UserID:    userID,
    }
    
    f.userMu.Lock()
    defer f.userMu.Unlock()
    
    if f.userAllowlist == nil {
        f.userAllowlist = make(map[string][]AllowlistEntry)
    }
    f.userAllowlist[userID] = append(f.userAllowlist[userID], entry)
    
    return nil
}

// IsAllowedForUser checks if URL is allowed for a specific user
func (f *ProxyFilter) IsAllowedForUser(userID, rawURL string) (bool, string) {
    // First check static rules (blocklist, global allowlist)
    if allowed, reason := f.IsAllowed(rawURL); !allowed {
        return false, reason
    }
    
    // Check user-specific allowlist
    parsedURL, _ := url.Parse(rawURL)
    
    f.userMu.RLock()
    defer f.userMu.RUnlock()
    
    entries, exists := f.userAllowlist[userID]
    if !exists {
        // No user-specific entries - fall back to global behavior
        return true, ""  // Or false if strict mode
    }
    
    now := time.Now()
    for _, entry := range entries {
        if entry.ExpiresAt.Before(now) {
            continue  // Expired
        }
        if entry.Host == parsedURL.Host {
            return true, ""
        }
    }
    
    return false, "URL not in user allowlist"
}
```

### Trust Framework Integration

For cases where trust framework validation is required (not just allowlisting), the flow can be extended:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    TRUST FRAMEWORK VALIDATION                               │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   POST /proxy/allow                                                         │
│   {                                                                         │
│     "urls": ["https://issuer.example.com"],                                │
│     "reason": "issuer",                                                    │
│     "validate_trust": true   ←── Optional: verify against trust framework  │
│   }                                                                         │
│   │                                                                         │
│   ▼                                                                         │
│   Backend (if validate_trust):                                              │
│   ├── Query trust framework for issuer.example.com                         │
│   ├── Verify entity is registered and valid                                │
│   └── Return 403 if not in trust framework                                 │
│   │                                                                         │
│   ▼                                                                         │
│   Response: 200 OK (or 403 Forbidden)                                       │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

This separates:
1. **Allowlisting** (proxy security) - "Can the backend make this request?"
2. **Trust validation** (business logic) - "Is this a trusted entity?"

## Security Considerations

### Rate Limiting for Allowlist Endpoints

```go
// More restrictive rate limits for allowlist manipulation
proxyGroup.POST("/allow", 
    rateLimiter.Middleware(10, 20),  // 10 req/min, burst of 20
    handlers.ProxyAllow)
```

### Audit Logging

```go
func (h *Handlers) ProxyAllow(c *gin.Context) {
    // ... validation ...
    
    h.logger.Info("Allowlist updated",
        zap.String("user_id", userID),
        zap.Strings("urls", req.URLs),
        zap.String("reason", req.Reason),
        zap.Duration("ttl", ttl),
    )
}
```

### Maximum Allowlist Size

```go
const MaxUserAllowlistEntries = 100

func (f *ProxyFilter) AddAllowedURLForUser(...) error {
    f.userMu.Lock()
    defer f.userMu.Unlock()
    
    if len(f.userAllowlist[userID]) >= MaxUserAllowlistEntries {
        // Clean up expired entries first
        f.cleanupExpiredEntries(userID)
        
        if len(f.userAllowlist[userID]) >= MaxUserAllowlistEntries {
            return fmt.Errorf("allowlist limit exceeded")
        }
    }
    // ...
}
```

## Summary

The recommended approach is **frontend-driven just-in-time allowlisting**:

1. Frontend parses credential offers / authorization requests locally
2. Frontend calls `POST /proxy/allow` with discovered URLs before proxying
3. Backend validates URL format and adds to per-user allowlist with TTL
4. Subsequent proxy requests are allowed if URL matches allowlist
5. Entries automatically expire (cleanup via TTL)

This provides:
- **Minimal allowlist size**: Only URLs actually being used
- **Protocol agnostic**: Backend doesn't need to understand VCI/VP
- **Auditable**: Clear record of what was allowed and why
- **Secure**: Per-user isolation, rate limiting, TTL expiration
- **Future-proof**: Works with protocol extensions
