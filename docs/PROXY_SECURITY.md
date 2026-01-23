# Proxy Security Architecture

## Overview

The HTTP proxy in go-wallet-backend allows the wallet frontend to make requests to external services (issuers, verifiers) through the backend. This document describes the security architecture implemented to prevent abuse.

## Security Layers

### 1. Authentication (Required)

All proxy requests require a valid JWT bearer token. Only authenticated users can use the proxy.

### 2. Rate Limiting

Rate limiting is implemented using a token bucket algorithm:

```yaml
rate_limit:
  enabled: true
  requests_per_minute: 120      # General API limit
  burst_size: 20                # Allow temporary bursts
  proxy_requests_per_minute: 30 # Stricter limit for proxy
  proxy_burst_size: 5           # Smaller burst for proxy
```

**Features:**
- Per-user rate limits (uses user_id from JWT)
- Falls back to IP-based limiting for unauthenticated endpoints
- Separate, stricter limits for proxy requests
- Token bucket allows bursts while maintaining average rate

### 3. URL Filtering

The proxy filter validates all target URLs against security rules:

#### Blocklist (Always Blocked)

| Category | Examples | Reason |
|----------|----------|--------|
| Private IPs | `10.x.x.x`, `172.16.x.x`, `192.168.x.x` | Prevent SSRF to internal networks |
| Localhost | `localhost`, `127.0.0.1`, `::1` | Prevent local service access |
| Cloud Metadata | `169.254.169.254` | Prevent credential theft |
| Blocked Protocols | `file://`, `ftp://`, `gopher://` | Only HTTP(S) allowed |
| Blocked Hosts | Custom list in config | Block known-bad or internal services |

#### Allowlist (Dynamic + Static)

The allowlist can be configured in two ways:

1. **Static Allowlist**: Configured at startup
   ```yaml
   proxy:
     allowed_hosts:
       - "*.example.com"
       - "issuer.trusted.org"
   ```

2. **Dynamic Allowlist**: Updated at runtime from discovered services

## Dynamic Allowlist Architecture

### The Challenge

OpenID4VCI and OpenID4VP require the wallet to communicate with arbitrary issuers and verifiers discovered through various means:
- QR codes scanned by the user
- Deep links from applications
- Credential offer URLs
- Authorization request URLs

A static allowlist would break the user experience.

### Solution: Discovery-Based Dynamic Allowlist

```
┌─────────────────────────────────────────────────────────────────┐
│                        Proxy Filter                             │
│  ┌──────────────────┐    ┌──────────────────────────────────┐  │
│  │  Static Blocklist │    │       Allowlist (Combined)       │  │
│  │  - Private IPs    │    │  ┌─────────────────────────────┐ │  │
│  │  - Localhost      │    │  │   Static (from config)      │ │  │
│  │  - Metadata IPs   │    │  │   - *.trusted-federation.eu │ │  │
│  │  - file://, etc   │    │  │   - gov-issuer.example.com  │ │  │
│  └──────────────────┘    │  └─────────────────────────────┘ │  │
│                          │  ┌─────────────────────────────┐ │  │
│                          │  │   Dynamic (runtime)         │ │  │
│                          │  │   - discovered-issuer.com   │ │  │
│                          │  │   - verified-verifier.org   │ │  │
│                          │  └─────────────────────────────┘ │  │
│                          └──────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

### Integration Points

The dynamic allowlist is populated from:

1. **Issuer Discovery**: When processing credential offers
   ```go
   // In credential issuance handler
   func (h *Handlers) ProcessCredentialOffer(c *gin.Context) {
       issuerURL := offer.CredentialIssuer
       // Add issuer to allowlist
       h.proxyFilter.AddAllowedURL(issuerURL)
       // Continue with issuance...
   }
   ```

2. **Verifier Discovery**: When processing authorization requests
   ```go
   // In presentation handler
   func (h *Handlers) ProcessAuthorizationRequest(c *gin.Context) {
       verifierURL := request.ClientID
       // Add verifier to allowlist
       h.proxyFilter.AddAllowedURL(verifierURL)
       // Continue with presentation...
   }
   ```

3. **Registered Issuers/Verifiers**: From storage
   ```go
   // On startup or when listing issuers
   issuers, _ := store.ListIssuers(ctx)
   for _, issuer := range issuers {
       proxyFilter.AddAllowedURL(issuer.URL)
   }
   ```

4. **Trust Framework**: From trusted federation members
   ```go
   // If using OpenID Federation
   trustedEntities := trustFramework.GetTrustedEntities()
   for _, entity := range trustedEntities {
       proxyFilter.AddAllowedHost(entity.EntityID)
   }
   ```

### API for Dynamic Updates

```go
// ProxyFilter methods for dynamic allowlist management
type ProxyFilter interface {
    // Add a host to the dynamic allowlist
    AddAllowedHost(host string)
    
    // Add host from a URL
    AddAllowedURL(url string) error
    
    // Remove a host (e.g., when issuer is removed)
    RemoveAllowedHost(host string)
    
    // Get all currently allowed hosts
    GetAllowedHosts() []string
    
    // Check if a URL is allowed
    IsAllowed(url string) error
}
```

### Configuration

```yaml
proxy:
  enabled: true
  block_private_ips: true
  block_localhost: true
  block_metadata: true
  blocked_hosts:
    - "internal-service.local"
  allowed_hosts: []           # Empty = all non-blocked allowed (if dynamic_allowlist is also false)
  require_https: true         # Recommended for production
  dynamic_allowlist: true     # Enable auto-population from discovered services
  timeout: 30
```

### Security Considerations

1. **Empty Allowlist Behavior**: 
   - If both `allowed_hosts` and dynamic allowlist are empty, all non-blocked hosts are allowed
   - This provides an open-by-default experience for development
   - Production should use either static allowlist or trust framework integration

2. **Wildcard Support**:
   - `*.example.com` allows all subdomains
   - Use carefully to avoid overly permissive rules

3. **DNS Rebinding Protection**:
   - Hostnames are resolved and IPs checked against blocklist
   - Prevents DNS rebinding attacks to private IPs

4. **Timeout Protection**:
   - All proxy requests have a 30-second timeout
   - Prevents slow loris attacks

## Future Enhancements

1. **Trust Framework Integration**: Automatic allowlist from OpenID Federation Trust Anchors
2. **Per-User Allowlists**: Allow users to manage their own trusted services
3. **Request Logging**: Audit log of all proxy requests
4. **Content Type Filtering**: Restrict allowed response content types
5. **Response Size Limits**: Prevent memory exhaustion from large responses
