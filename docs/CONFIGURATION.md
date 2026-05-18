<!-- Regenerate with: go run developer_tools/scripts/gen_config_docs/main.go -->

# Configuration Reference

This document describes all configuration options for go-wallet-backend.
Configuration is loaded from a YAML file and can be overridden by environment variables.

Environment variables use the prefix `WALLET_` for the main backend and `REGISTRY_` for the registry server.

## Table of Contents

- [server](#server)
- [storage](#storage)
- [logging](#logging)
- [jwt](#jwt)
- [wallet_provider](#wallet-provider)
- [trust](#trust)
- [session_store](#session-store)
- [features](#features)
- [security](#security)
- [http_client](#http-client)
- [authzen_proxy](#authzen-proxy)
- [Registry Server](#registry-server)
- [registry.server](#registryserver)
- [registry.source](#registrysource)
- [registry.sources](#registrysources)
- [registry.cache](#registrycache)
- [registry.dynamic_cache](#registrydynamic-cache)
- [registry.image_embed](#registryimage-embed)
- [registry.filter](#registryfilter)
- [registry.rate_limit](#registryrate-limit)
- [registry.jwt](#registryjwt)
- [registry.logging](#registrylogging)
- [registry.http_client](#registryhttp-client)

---

## server

Environment prefix: `WALLET_SERVER`

| YAML Key | Env Variable | Type | Description |
|----------|-------------|------|-------------|
| `server.host` | `WALLET_SERVER_HOST` | string |  |
| `server.port` | `WALLET_SERVER_PORT` | integer |  |
| `server.admin_host` | `WALLET_SERVER_ADMIN_HOST` | string | Admin API bind address (defaults to Host) |
| `server.admin_port` | `WALLET_SERVER_ADMIN_PORT` | integer | Internal admin API port (0 to disable) |
| `server.engine_host` | `WALLET_SERVER_ENGINE_HOST` | string | WebSocket engine bind address (defaults to Host) |
| `server.engine_port` | `WALLET_SERVER_ENGINE_PORT` | integer | WebSocket engine port (defaults to Port if 0) |
| `server.registry_host` | `WALLET_SERVER_REGISTRY_HOST` | string | Registry bind address (defaults to Host) |
| `server.registry_port` | `WALLET_SERVER_REGISTRY_PORT` | integer | VCTM registry port (defaults to 8097) |
| `server.admin_token` | `WALLET_SERVER_ADMIN_TOKEN` | string | Bearer token for admin API (auto-generated if empty) |
| `server.admin_token_path` | `WALLET_SERVER_ADMIN_TOKEN_PATH` | string | Path to file containing admin token |
| `server.rp_id` | `WALLET_SERVER_RP_ID` | string |  |
| `server.rp_origin` | `WALLET_SERVER_RP_ORIGIN` | string | RPOrigin is the legacy single-origin setting. Kept for backward compatibility. New deployments should use RPOrigins. When both are set, RPOrigin is prepended. |
| `server.rp_origins` | `WALLET_SERVER_RP_ORIGINS` | string list |  |
| `server.rp_name` | `WALLET_SERVER_RP_NAME` | string |  |
| `server.base_url` | `WALLET_SERVER_BASE_URL` | string |  |
| `server.cors.allowed_origins` | `WALLET_SERVER_CORS_ALLOWED_ORIGINS` | string list | AllowedOrigins is a list of origins that may access the resource. Use "*" to allow all origins (default for development). |
| `server.cors.allowed_methods` | `WALLET_SERVER_CORS_ALLOWED_METHODS` | string list | AllowedMethods is a list of HTTP methods allowed for cross-origin requests. |
| `server.cors.allowed_headers` | `WALLET_SERVER_CORS_ALLOWED_HEADERS` | string list | AllowedHeaders is a list of request headers allowed in cross-origin requests. |
| `server.cors.exposed_headers` | `WALLET_SERVER_CORS_EXPOSED_HEADERS` | string list | ExposedHeaders is a list of headers that browsers are allowed to access. |
| `server.cors.allow_credentials` | `WALLET_SERVER_CORS_ALLOW_CREDENTIALS` | boolean | AllowCredentials indicates whether the request can include credentials. Cannot be true when AllowedOrigins is "*". |
| `server.cors.max_age` | `WALLET_SERVER_CORS_MAX_AGE` | integer | MaxAge indicates how long (in seconds) the results of a preflight request can be cached. |
| `server.external_urls.backend_url` | `WALLET_SERVER_EXTERNAL_URLS_BACKEND_URL` | string | BackendURL is the external URL for the backend service (for engine → backend calls) |
| `server.external_urls.engine_url` | `WALLET_SERVER_EXTERNAL_URLS_ENGINE_URL` | string | EngineURL is the external URL for the engine service (for WebSocket connections) |
| `server.external_urls.registry_url` | `WALLET_SERVER_EXTERNAL_URLS_REGISTRY_URL` | string | RegistryURL is the external URL for the registry service (for VCTM lookups) |
| `server.external_urls.admin_url` | `WALLET_SERVER_EXTERNAL_URLS_ADMIN_URL` | string | AdminURL is the external URL for the admin API (for inter-service admin calls) |
| `server.served_by_header` | `WALLET_SERVER_SERVED_BY_HEADER` | string | ServedByHeader sets the X-Served-By response header value. If nil (not configured), defaults to the system hostname. If set to empty string, the header is disabled. |
| `server.tls.enabled` | `WALLET_SERVER_TLS_ENABLED` | boolean | Enabled enables TLS for the HTTP listeners |
| `server.tls.cert_file` | `WALLET_SERVER_TLS_CERT_FILE` | string | CertFile is the path to the TLS certificate file |
| `server.tls.key_file` | `WALLET_SERVER_TLS_KEY_FILE` | string | KeyFile is the path to the TLS private key file |
| `server.tls.min_version` | `WALLET_SERVER_TLS_MIN_VERSION` | string | MinVersion is the minimum TLS version (tls12 or tls13, default: tls12) |
| `server.admin_tls.enabled` | `WALLET_SERVER_ADMIN_TLS_ENABLED` | boolean | Enabled enables TLS for the HTTP listeners |
| `server.admin_tls.cert_file` | `WALLET_SERVER_ADMIN_TLS_CERT_FILE` | string | CertFile is the path to the TLS certificate file |
| `server.admin_tls.key_file` | `WALLET_SERVER_ADMIN_TLS_KEY_FILE` | string | KeyFile is the path to the TLS private key file |
| `server.admin_tls.min_version` | `WALLET_SERVER_ADMIN_TLS_MIN_VERSION` | string | MinVersion is the minimum TLS version (tls12 or tls13, default: tls12) |

## storage

Environment prefix: `WALLET_STORAGE`

| YAML Key | Env Variable | Type | Description |
|----------|-------------|------|-------------|
| `storage.type` | `WALLET_STORAGE_TYPE` | string | memory, sqlite, mongodb |
| `storage.sqlite.path` | `WALLET_STORAGE_SQLITE_DB_PATH` | string |  |
| `storage.mongodb.uri` | `WALLET_STORAGE_MONGODB_URI` | string |  |
| `storage.mongodb.database` | `WALLET_STORAGE_MONGODB_DATABASE` | string |  |
| `storage.mongodb.timeout` | `WALLET_STORAGE_MONGODB_TIMEOUT` | integer | seconds |
| `storage.mongodb.password_path` | `WALLET_STORAGE_MONGODB_PASSWORD_PATH` | string | Path to file containing MongoDB password |
| `storage.mongodb.tls_enabled` | `WALLET_STORAGE_MONGODB_TLS_ENABLED` | boolean | TLS/mTLS configuration |
| `storage.mongodb.ca_path` | `WALLET_STORAGE_MONGODB_CA_PATH` | string | Path to CA certificate for server verification |
| `storage.mongodb.cert_path` | `WALLET_STORAGE_MONGODB_CERT_PATH` | string | Path to client certificate for mTLS |
| `storage.mongodb.key_path` | `WALLET_STORAGE_MONGODB_KEY_PATH` | string | Path to client key for mTLS |

## logging

Environment prefix: `WALLET_LOGGING`

| YAML Key | Env Variable | Type | Description |
|----------|-------------|------|-------------|
| `logging.level` | `WALLET_LOGGING_LEVEL` | string | debug, info, warn, error |
| `logging.format` | `WALLET_LOGGING_FORMAT` | string | json, text |

## jwt

Environment prefix: `WALLET_JWT`

| YAML Key | Env Variable | Type | Description |
|----------|-------------|------|-------------|
| `jwt.secret` | `WALLET_JWT_SECRET` | string |  |
| `jwt.secret_path` | `WALLET_JWT_SECRET_PATH` | string | Path to file containing JWT secret |
| `jwt.expiry_hours` | `WALLET_JWT_EXPIRY_HOURS` | integer |  |
| `jwt.refresh_days` | `WALLET_JWT_REFRESH_DAYS` | integer |  |
| `jwt.issuer` | `WALLET_JWT_ISSUER` | string |  |

## wallet_provider

Environment prefix: `WALLET_WALLET_PROVIDER`

| YAML Key | Env Variable | Type | Description |
|----------|-------------|------|-------------|
| `wallet_provider.private_key_path` | `WALLET_WALLET_PROVIDER_PRIVATE_KEY_PATH` | string |  |
| `wallet_provider.certificate_path` | `WALLET_WALLET_PROVIDER_CERTIFICATE_PATH` | string |  |
| `wallet_provider.ca_cert_path` | `WALLET_WALLET_PROVIDER_CA_CERT_PATH` | string |  |

## trust

Environment prefix: `WALLET_TRUST`

| YAML Key | Env Variable | Type | Description |
|----------|-------------|------|-------------|
| `trust.pdp_url` | `WALLET_TRUST_PDP_URL` | string | PDPURL is the URL of the AuthZEN PDP (Policy Decision Point) for trust evaluation. When set, operates in "default deny" mode - trust decisions require PDP approval. When empty, operates in "allow all" mode - requests are always considered trusted. |
| `trust.default_endpoint` | `WALLET_TRUST_DEFAULT_ENDPOINT` | string | DefaultEndpoint is deprecated. Use PDPURL instead. Retained for backward compatibility - if PDPURL is empty and DefaultEndpoint is set, DefaultEndpoint is used. Deprecated: This field will be removed in a future release. |
| `trust.registry_url` | `WALLET_TRUST_REGISTRY_URL` | string | RegistryURL is the URL for the VCTM registry service. |
| `trust.timeout` | `WALLET_TRUST_TIMEOUT` | integer | Timeout is the HTTP timeout for trust evaluation requests (seconds). |
| `trust.insecure_skip_verify` | `WALLET_TRUST_INSECURE_SKIP_VERIFY` | boolean | InsecureSkipVerify disables TLS certificate verification for PDP requests. Use only in development or when the PDP uses a self-signed certificate. |
| `trust.ca_cert_path` | `WALLET_TRUST_CA_CERT_PATH` | string | CACertPath is the path to a PEM-encoded CA certificate used to verify the PDP's TLS certificate. Set this when the PDP is signed by an internal/private CA. |
| `trust.issuer.pdp_url` | `WALLET_TRUST_ISSUER_PDP_URL` | string | PDPURL overrides the global PDP URL for this specific flow. Empty inherits from global. Set to "none" to explicitly disable trust. |
| `trust.verifier.pdp_url` | `WALLET_TRUST_VERIFIER_PDP_URL` | string | PDPURL overrides the global PDP URL for this specific flow. Empty inherits from global. Set to "none" to explicitly disable trust. |

## session_store

Environment prefix: `WALLET_SESSION_STORE`

| YAML Key | Env Variable | Type | Description |
|----------|-------------|------|-------------|
| `session_store.type` | `WALLET_SESSION_STORE_TYPE` | string | Type is the session store type: "memory" or "redis" |
| `session_store.redis.address` | `WALLET_SESSION_STORE_REDIS_ADDRESS` | string |  |
| `session_store.redis.password` | `WALLET_SESSION_STORE_REDIS_PASSWORD` | string |  |
| `session_store.redis.db` | `WALLET_SESSION_STORE_REDIS_DB` | integer |  |
| `session_store.redis.key_prefix` | `WALLET_SESSION_STORE_REDIS_KEY_PREFIX` | string |  |
| `session_store.default_ttl_hours` | `WALLET_SESSION_STORE_DEFAULT_TTL_HOURS` | integer | DefaultTTL is the default session TTL in hours |

## features

Environment prefix: `WALLET_FEATURES`

| YAML Key | Env Variable | Type | Description |
|----------|-------------|------|-------------|
| `features.proxy_enabled` | `WALLET_FEATURES_PROXY_ENABLED` | boolean | ProxyEnabled controls whether the /proxy endpoint is available. Set to false to disable the proxy (requires WebSocket engine for flows). Default: true (for backward compatibility) |
| `features.websocket_required` | `WALLET_FEATURES_WEBSOCKET_REQUIRED` | boolean | WebSocketRequired forces WebSocket transport for credential flows. When true, the proxy endpoint will return an error directing clients to use the WebSocket transport instead. Default: false |
| `features.credential_storage_enabled` | `WALLET_FEATURES_CREDENTIAL_STORAGE_ENABLED` | boolean | CredentialStorageEnabled controls whether server-side credential storage endpoints (/storage/vc/*) are available. By default, credentials are stored exclusively in the encrypted client-side private_data blob and the server-side storage path is unused. Set to true only if you need backward-compatible server-side credential storage. Default: false (server-side credential storage disabled) |

## security

Environment prefix: `WALLET_SECURITY`

| YAML Key | Env Variable | Type | Description |
|----------|-------------|------|-------------|
| `security.auth_rate_limit.enabled` | `WALLET_SECURITY_AUTH_RATE_LIMIT_ENABLED` | boolean | Enabled controls whether rate limiting is active |
| `security.auth_rate_limit.max_attempts` | `WALLET_SECURITY_AUTH_RATE_LIMIT_MAX_ATTEMPTS` | integer | MaxAttempts is the maximum number of login/registration attempts per window Default: 10 |
| `security.auth_rate_limit.window_seconds` | `WALLET_SECURITY_AUTH_RATE_LIMIT_WINDOW_SECONDS` | integer | WindowSeconds is the time window for rate limiting (in seconds) Default: 60 (1 minute) |
| `security.auth_rate_limit.lockout_seconds` | `WALLET_SECURITY_AUTH_RATE_LIMIT_LOCKOUT_SECONDS` | integer | LockoutSeconds is how long to lock out after exceeding the limit Default: 300 (5 minutes) |
| `security.aaguid_blacklist.enabled` | `WALLET_SECURITY_AAGUID_BLACKLIST_ENABLED` | boolean | Enabled controls whether AAGUID blacklist checking is active |
| `security.aaguid_blacklist.aaguids` | `WALLET_SECURITY_AAGUID_BLACKLIST_AAGUIDS` | string list | AAGUIDs is a list of blocked AAGUIDs (hex-encoded UUIDs without dashes) Example: ["00000000000000000000000000000000"] to block zero AAGUID |
| `security.aaguid_blacklist.reject_unknown` | `WALLET_SECURITY_AAGUID_BLACKLIST_REJECT_UNKNOWN` | boolean | RejectUnknown rejects authenticators with zero/unknown AAGUIDs Default: false (permissive - allows unknown authenticators) |
| `security.challenge_cleanup.enabled` | `WALLET_SECURITY_CHALLENGE_CLEANUP_ENABLED` | boolean | Enabled controls whether the cleanup worker runs |
| `security.challenge_cleanup.interval_seconds` | `WALLET_SECURITY_CHALLENGE_CLEANUP_INTERVAL_SECONDS` | integer | IntervalSeconds is how often to run cleanup (in seconds) Default: 300 (5 minutes) |
| `security.token_blacklist.enabled` | `WALLET_SECURITY_TOKEN_BLACKLIST_ENABLED` | boolean | Enabled controls whether token blacklist checking is active |
| `security.token_blacklist.cleanup_interval_seconds` | `WALLET_SECURITY_TOKEN_BLACKLIST_CLEANUP_INTERVAL_SECONDS` | integer | CleanupIntervalSeconds is how often to clean up expired blacklist entries Default: 3600 (1 hour) |
| `security.webauthn.attestation_conveyance` | `WALLET_SECURITY_WEBAUTHN_ATTESTATION_CONVEYANCE` | string | AttestationConveyance controls how the RP requests attestation from authenticators. Valid values: "none", "indirect", "direct", "enterprise" Default: "none" (recommended for most deployments - avoids certificate validation issues) Use "direct" only if you need to verify authenticator makes/models. |

## http_client

Environment prefix: `WALLET_HTTP_CLIENT`

| YAML Key | Env Variable | Type | Description |
|----------|-------------|------|-------------|
| `http_client.proxy_url` | `WALLET_HTTP_CLIENT_PROXY_URL` | string | ProxyURL is the URL of the HTTP proxy for egress requests (e.g., http://proxy:8080) |
| `http_client.timeout` | `WALLET_HTTP_CLIENT_TIMEOUT` | integer | Timeout is the timeout for HTTP requests in seconds (default: 30) |
| `http_client.insecure_skip_verify` | `WALLET_HTTP_CLIENT_INSECURE_SKIP_VERIFY` | boolean | InsecureSkipVerify disables TLS certificate verification (not recommended for production) |
| `http_client.allow_private_ips` | `WALLET_HTTP_CLIENT_ALLOW_PRIVATE_IPS` | boolean | AllowPrivateIPs permits outbound requests to private/internal/loopback/link-local ranges. Required when credential issuers run on Docker, k8s internal networks, or localhost. Default: false (private/loopback/cloud-metadata IPs are blocked by the SSRF DialContext). Set to true when issuers are hosted on internal networks (dev/staging environments). Env: WALLET_HTTP_CLIENT_ALLOW_PRIVATE_IPS |
| `http_client.allow_http` | `WALLET_HTTP_CLIENT_ALLOW_HTTP` | boolean | AllowHTTP permits non-TLS (plain HTTP) connections for metadata resolution. Default: false (HTTPS required). Use only for local development. Env: WALLET_HTTP_CLIENT_ALLOW_HTTP |

## authzen_proxy

Environment prefix: `WALLET_AUTHZEN_PROXY`

| YAML Key | Env Variable | Type | Description |
|----------|-------------|------|-------------|
| `authzen_proxy.enabled` | `WALLET_AUTHZEN_PROXY_ENABLED` | boolean | Enabled controls whether the /v1/evaluate endpoint is available. Default: true (set in defaultConfig) |
| `authzen_proxy.pdp_url` | `WALLET_AUTHZEN_PROXY_PDP_URL` | string | PDPURL is the backend PDP URL to proxy requests to. If empty, uses the global trust.pdp_url configuration. |
| `authzen_proxy.timeout` | `WALLET_AUTHZEN_PROXY_TIMEOUT` | integer | Timeout is the timeout for PDP requests in seconds. Default: 30 |
| `authzen_proxy.rules_file` | `WALLET_AUTHZEN_PROXY_RULES_FILE` | string | RulesFile is the path to a SPOCP rules file for query authorization. If empty, default wallet rules are used. |
| `authzen_proxy.allow_resolution` | `WALLET_AUTHZEN_PROXY_ALLOW_RESOLUTION` | boolean | AllowResolution controls whether resolution-only requests are allowed. Resolution requests fetch metadata (DID documents, entity configs) without key validation. Default: true |
| `authzen_proxy.fail_open_on_tenant_lookup_error` | `WALLET_AUTHZEN_PROXY_FAIL_OPEN_ON_TENANT_LOOKUP_ERROR` | boolean | FailOpenOnTenantLookupError controls behavior when per-tenant PDP lookup fails. If false (default), tenant lookup errors return an error to the client. If true, falls back to the global PDP URL on lookup errors. Security note: fail-closed (false) prevents bypassing per-tenant security policies. |

## Registry Server

The registry server (`cmd/registry`) has its own configuration file. It serves VCTM (Verifiable Credential Type Metadata) fetched from upstream registries.

Environment prefix: `REGISTRY`


## registry.server

Server configuration

Environment prefix: `REGISTRY_SERVER`

| YAML Key | Env Variable | Type | Description |
|----------|-------------|------|-------------|
| `server.host` | `REGISTRY_SERVER_HOST` | string |  |
| `server.port` | `REGISTRY_SERVER_PORT` | integer |  |
| `server.served_by_header` | `REGISTRY_SERVER_SERVEDBYHEADER` | string |  |
| `server.tls.enabled` | `REGISTRY_SERVER_TLS_ENABLED` | boolean | Enabled enables TLS for the HTTP listeners |
| `server.tls.cert_file` | `REGISTRY_SERVER_TLS_CERT_FILE` | string | CertFile is the path to the TLS certificate file |
| `server.tls.key_file` | `REGISTRY_SERVER_TLS_KEY_FILE` | string | KeyFile is the path to the TLS private key file |
| `server.tls.min_version` | `REGISTRY_SERVER_TLS_MIN_VERSION` | string | MinVersion is the minimum TLS version (tls12 or tls13, default: tls12) |

## registry.source

Source is the legacy single-registry source configuration. Use Sources for multi-registry support. If Sources is empty, Source is used.

Environment prefix: `REGISTRY_SOURCE`

| YAML Key | Env Variable | Type | Description |
|----------|-------------|------|-------------|
| `source.url` | `REGISTRY_SOURCE_URL` | string | URL of the upstream registry index. Supports both the legacy vctm-registry.json format and the TS11-compliant /api/v1/schemas.json endpoint – the format is auto-detected from the response. |
| `source.local_overrides` | `REGISTRY_SOURCE_LOCAL_OVERRIDES` | string list | LocalOverrides is a list of local file or directory paths containing VCTM JSON files. These are loaded at startup and take priority over entries fetched from the remote registry. Directories are scanned for *.json files. Entries are keyed by their "vct" field. |
| `source.poll_interval` | `REGISTRY_SOURCE_POLL_INTERVAL` | duration | PollInterval is how often to poll the upstream registry for updates |
| `source.timeout` | `REGISTRY_SOURCE_TIMEOUT` | duration | Timeout for HTTP requests to the upstream registry |

## registry.sources

Sources is an ordered list of remote registry URLs to fetch from. Schemas fetched from later sources in the list overwrite earlier ones, allowing a registry to extend or override another. When non-empty, the Source.URL field is ignored for remote fetching (Source.PollInterval and Source.LocalOverrides remain global settings). (list of entries, each with the fields below)

Environment prefix: `REGISTRY_SOURCES`

| YAML Key | Env Variable | Type | Description |
|----------|-------------|------|-------------|
| `sources[*].url` | `REGISTRY_SOURCES_URL` | string | URL of the upstream registry index. Supports both the legacy vctm-registry.json format and the TS11-compliant /api/v1/schemas.json endpoint – the format is auto-detected from the response. |
| `sources[*].timeout` | `REGISTRY_SOURCES_TIMEOUT` | duration | Timeout for HTTP requests to this source. Zero means no per-source timeout (the shared http.Client timeout applies). |

## registry.cache

Cache configuration

Environment prefix: `REGISTRY_CACHE`

| YAML Key | Env Variable | Type | Description |
|----------|-------------|------|-------------|
| `cache.path` | `REGISTRY_CACHE_PATH` | string | Path to the cache file (JSON format) |
| `cache.max_age` | `REGISTRY_CACHE_MAX_AGE` | duration | MaxAge is the maximum age of cached data before forcing a refresh |

## registry.dynamic_cache

DynamicCache configuration for on-demand URL fetching

Environment prefix: `REGISTRY_DYNAMIC_CACHE`

| YAML Key | Env Variable | Type | Description |
|----------|-------------|------|-------------|
| `dynamic_cache.enabled` | `REGISTRY_DYNAMIC_CACHE_ENABLED` | boolean | Enabled controls whether dynamic URL fetching is active |
| `dynamic_cache.default_ttl` | `REGISTRY_DYNAMIC_CACHE_DEFAULT_TTL` | duration | DefaultTTL is the default cache TTL for dynamically fetched VCTMs when no HTTP cache headers are present |
| `dynamic_cache.max_ttl` | `REGISTRY_DYNAMIC_CACHE_MAX_TTL` | duration | MaxTTL is the maximum cache TTL to respect from HTTP headers Values larger than this will be capped |
| `dynamic_cache.min_ttl` | `REGISTRY_DYNAMIC_CACHE_MIN_TTL` | duration | MinTTL is the minimum cache TTL; shorter values from HTTP headers will be bumped up to this value |
| `dynamic_cache.timeout` | `REGISTRY_DYNAMIC_CACHE_TIMEOUT` | duration | Timeout for HTTP requests when fetching VCTMs dynamically |
| `dynamic_cache.allowed_hosts` | `REGISTRY_DYNAMIC_CACHE_ALLOWED_HOSTS` | string list | AllowedHosts is an optional list of host patterns (regexps) that are allowed for dynamic fetching. If empty, all HTTPS hosts are allowed. |

## registry.image_embed

ImageEmbed configuration for embedding images as data URIs

Environment prefix: `REGISTRY_IMAGE_EMBED`

| YAML Key | Env Variable | Type | Description |
|----------|-------------|------|-------------|
| `image_embed.enabled` | `REGISTRY_IMAGE_EMBED_ENABLED` | boolean | Enabled controls whether image embedding is active |
| `image_embed.max_image_size` | `REGISTRY_IMAGE_EMBED_MAX_IMAGE_SIZE` | integer | MaxImageSize is the maximum size in bytes for images to embed Images larger than this will be left as URLs |
| `image_embed.timeout` | `REGISTRY_IMAGE_EMBED_TIMEOUT` | duration | Timeout for fetching individual images |
| `image_embed.concurrent_fetches` | `REGISTRY_IMAGE_EMBED_CONCURRENT_FETCHES` | integer | ConcurrentFetches is the maximum number of concurrent image fetches |

## registry.filter

Filter configuration for include/exclude patterns

Environment prefix: `REGISTRY_FILTER`

| YAML Key | Env Variable | Type | Description |
|----------|-------------|------|-------------|
| `filter.include_patterns` | `REGISTRY_FILTER_INCLUDE_PATTERNS` | string list | IncludePatterns are regexps that VCT IDs must match to be included If empty, all VCT IDs are included (unless excluded) |
| `filter.exclude_patterns` | `REGISTRY_FILTER_EXCLUDE_PATTERNS` | string list | ExcludePatterns are regexps that cause VCT IDs to be excluded |

## registry.rate_limit

Rate limiting configuration

Environment prefix: `REGISTRY_RATE_LIMIT`

| YAML Key | Env Variable | Type | Description |
|----------|-------------|------|-------------|
| `rate_limit.enabled` | `REGISTRY_RATE_LIMIT_ENABLED` | boolean | Enabled controls whether rate limiting is active |
| `rate_limit.authenticated_rpm` | `REGISTRY_RATE_LIMIT_AUTHENTICATED_RPM` | integer | AuthenticatedRPM is requests per minute for authenticated clients |
| `rate_limit.unauthenticated_rpm` | `REGISTRY_RATE_LIMIT_UNAUTHENTICATED_RPM` | integer | UnauthenticatedRPM is requests per minute for unauthenticated clients |
| `rate_limit.burst_multiplier` | `REGISTRY_RATE_LIMIT_BURST_MULTIPLIER` | integer | BurstMultiplier allows bursts of this multiple of the rate limit |

## registry.jwt

JWT configuration for authentication

Environment prefix: `REGISTRY_JWT`

| YAML Key | Env Variable | Type | Description |
|----------|-------------|------|-------------|
| `jwt.secret` | `REGISTRY_JWT_SECRET` | string | Secret is the shared secret for validating JWT signatures (HMAC) |
| `jwt.issuer` | `REGISTRY_JWT_ISSUER` | string | Issuer is the expected issuer claim in the JWT |
| `jwt.require_auth` | `REGISTRY_JWT_REQUIRE_AUTH` | boolean | RequireAuth requires authentication for all requests (if false, unauthenticated access is allowed) |

## registry.logging

Logging configuration

Environment prefix: `REGISTRY_LOGGING`

| YAML Key | Env Variable | Type | Description |
|----------|-------------|------|-------------|
| `logging.level` | `REGISTRY_LOGGING_LEVEL` | string | debug, info, warn, error |
| `logging.format` | `REGISTRY_LOGGING_FORMAT` | string | json, text |

## registry.http_client

HTTPClient configuration for outbound requests (proxy, TLS settings)

Environment prefix: `REGISTRY_HTTP_CLIENT`

| YAML Key | Env Variable | Type | Description |
|----------|-------------|------|-------------|
| `http_client.proxy_url` | `REGISTRY_HTTP_CLIENT_PROXY_URL` | string | ProxyURL is the URL of the HTTP proxy for egress requests (e.g., http://proxy:8080) |
| `http_client.timeout` | `REGISTRY_HTTP_CLIENT_TIMEOUT` | integer | Timeout is the timeout for HTTP requests in seconds (default: 30) |
| `http_client.insecure_skip_verify` | `REGISTRY_HTTP_CLIENT_INSECURE_SKIP_VERIFY` | boolean | InsecureSkipVerify disables TLS certificate verification (not recommended for production) |
| `http_client.allow_private_ips` | `REGISTRY_HTTP_CLIENT_ALLOW_PRIVATE_IPS` | boolean | AllowPrivateIPs permits outbound requests to private/internal/loopback/link-local ranges. Required when credential issuers run on Docker, k8s internal networks, or localhost. Default: false (private/loopback/cloud-metadata IPs are blocked by the SSRF DialContext). Set to true when issuers are hosted on internal networks (dev/staging environments). Env: WALLET_HTTP_CLIENT_ALLOW_PRIVATE_IPS |
| `http_client.allow_http` | `REGISTRY_HTTP_CLIENT_ALLOW_HTTP` | boolean | AllowHTTP permits non-TLS (plain HTTP) connections for metadata resolution. Default: false (HTTPS required). Use only for local development. Env: WALLET_HTTP_CLIENT_ALLOW_HTTP |

