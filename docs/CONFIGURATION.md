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
- [as](#as)
- [wallet_provider](#wallet_provider)
- [trust](#trust)
- [session_store](#session_store)
- [features](#features)
- [security](#security)
- [http_client](#http_client)
- [authzen_proxy](#authzen_proxy)
- [audit](#audit)
- [Registry Server](#registry-server)
- [registry.server](#registryserver)
- [registry.source](#registrysource)
- [registry.sources](#registrysources)
- [registry.cache](#registrycache)
- [registry.dynamic_cache](#registrydynamic_cache)
- [registry.image_embed](#registryimage_embed)
- [registry.filter](#registryfilter)
- [registry.rate_limit](#registryrate_limit)
- [registry.jwt](#registryjwt)
- [registry.logging](#registrylogging)
- [registry.http_client](#registryhttp_client)

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
| `server.wp_host` | `WALLET_SERVER_WP_HOST` | string | Wallet-provider bind address (defaults to Host) |
| `server.wp_port` | `WALLET_SERVER_WP_PORT` | integer | Wallet-provider port (0 = co-hosted with backend) |
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

## as

Environment prefix: `WALLET_AS`

| YAML Key | Env Variable | Type | Description |
|----------|-------------|------|-------------|
| `as.enabled` | `WALLET_AS_ENABLED` | boolean | Enabled controls whether the new AS is active. |
| `as.signing_key_path` | `WALLET_AS_SIGNING_KEY_PATH` | string | SigningKeyPath is the path to a PEM-encoded private key (ECDSA P-256, P-384, or Ed25519) used to sign access tokens. Mutually exclusive with SigningKeyPKCS11. |
| `as.signing_key_pkcs11` | `WALLET_AS_SIGNING_KEY_PKCS11` | string | SigningKeyPKCS11 is a PKCS#11 URI for HSM-backed signing. Mutually exclusive with SigningKeyPath. |
| `as.issuer` | `WALLET_AS_ISSUER` | string | Issuer is the value of the "iss" claim in issued access tokens. Defaults to JWT.Issuer if not set. |
| `as.default_token_ttl` | `WALLET_AS_DEFAULT_TOKEN_TTL` | duration | DefaultTokenTTL is the default access token lifetime. Default: 2m |
| `as.audience_ttls` | `WALLET_AS_AUDIENCE_TTLS` | map[string]time.Duration | AudienceTTLs allows per-audience TTL overrides. Keys are audience strings, values are durations. |
| `as.audiences` | `WALLET_AS_AUDIENCES` | string list | Audiences lists the accepted audience values for token validation. Tokens must contain at least one of these in their "aud" claim. When empty, audience validation is skipped. Documented values: "wallet-backend", "wallet-engine", "wallet-registry". |
| `as.rules_dir` | `WALLET_AS_RULES_DIR` | string | RulesDir is the path to a directory containing SPOCP policy rule files. |
| `as.session_ttl` | `WALLET_AS_SESSION_TTL` | duration | SessionTTL is the maximum session lifetime before re-authentication. Default: 24h |
| `as.default_max_tac` | `WALLET_AS_DEFAULT_MAX_TAC` | string | DefaultMaxTAC is the default maximum TAC for sessions created via passkey auth. Admin sessions (e.g. via OIDC) may get a different MaxTAC per policy. Default: "rwl" (read, write, list) |
| `as.legacy.enabled` | `WALLET_AS_LEGACY_ENABLED` | boolean | Enabled controls whether legacy HMAC tokens are accepted. Default: true (for backward compatibility) |
| `as.legacy.deprecation_header` | `WALLET_AS_LEGACY_DEPRECATION_HEADER` | boolean | DeprecationHeader controls whether Deprecation + Sunset headers are sent on legacy token responses. |
| `as.legacy.sunset_date` | `WALLET_AS_LEGACY_SUNSET_DATE` | string | SunsetDate is the date after which legacy tokens will no longer be supported. Used in the Sunset HTTP header. Format: RFC 3339 date (e.g. "2027-10-01T00:00:00Z"). |
| `as.external_url` | `WALLET_AS_EXTERNAL_URL` | string | ExternalURL is the public-facing base URL of the AS (e.g. "https://wallet.example.com"). Used to construct OIDC redirect URIs. Required when OIDC is used. |
| `as.insecure_cookies` | `WALLET_AS_INSECURE_COOKIES` | boolean | InsecureCookies disables the __Host- prefix and Secure flag on session cookies. Required for local development over HTTP. NEVER enable in production. |

## wallet_provider

Environment prefix: `WALLET_WALLET_PROVIDER`

| YAML Key | Env Variable | Type | Description |
|----------|-------------|------|-------------|
| `wallet_provider.private_key_path` | `WALLET_WALLET_PROVIDER_PRIVATE_KEY_PATH` | string |  |
| `wallet_provider.certificate_path` | `WALLET_WALLET_PROVIDER_CERTIFICATE_PATH` | string |  |
| `wallet_provider.ca_cert_path` | `WALLET_WALLET_PROVIDER_CA_CERT_PATH` | string |  |
| `wallet_provider.pkcs11.module_path` | `WALLET_WALLET_PROVIDER_PKCS11_MODULE_PATH` | string |  |
| `wallet_provider.pkcs11.slot_id` | `WALLET_WALLET_PROVIDER_PKCS11_SLOT_ID` | uint |  |
| `wallet_provider.pkcs11.pin` | `WALLET_WALLET_PROVIDER_PKCS11_PIN` | string |  |
| `wallet_provider.pkcs11.pin_path` | `WALLET_WALLET_PROVIDER_PKCS11_PIN_PATH` | string | Path to file containing PIN (preferred over inline PIN) |
| `wallet_provider.pkcs11.key_label` | `WALLET_WALLET_PROVIDER_PKCS11_KEY_LABEL` | string |  |
| `wallet_provider.pkcs11.pool_size` | `WALLET_WALLET_PROVIDER_PKCS11_POOL_SIZE` | integer | Session pool size (default 4) |
| `wallet_provider.wia.enabled` | `WALLET_WALLET_PROVIDER_WIA_ENABLED` | boolean | Enabled controls whether WIA endpoints are registered |
| `wallet_provider.wia.issuer` | `WALLET_WALLET_PROVIDER_WIA_ISSUER` | string | Issuer is the `iss` claim in WIA JWTs. Required when Mode is "ietf" (it's the only way a relying party can locate the JWKS to verify the WIA); unused/omitted when Mode is "etsi". |
| `wallet_provider.wia.mode` | `WALLET_WALLET_PROVIDER_WIA_MODE` | string | Mode selects which WIA trust model this wallet provider issues:    - "etsi" (default): the EUDI ARF v3.0 / EC TS03 v1.5.2 / ETSI TS 119     472-3 V1.1.1 model. The WIA always carries the signing certificate     chain in the `x5c` JOSE header; relying parties verify it against     the Trusted List for Wallet Providers (ETSI TS 119 472-3     AUTH-REQ-PROC-4.4.3-01 / TOKEN-REQ-PROC-4.5.2-01). No `iss` or     `kid` is set — TS03 v1.5 explicitly removed `iss` from the WIA;     Wallet Provider identity is inferred solely from the x5c signing     certificate. This is the only mode with a defined trust path under     the current EUDI/ARF/ETSI specs; use it when interoperating with     ARF-conformant PID/EAA Providers.    - "ietf": the generic IETF draft-ietf-oauth-attestation-based-client-auth     model, with no ARF/ETSI counterpart. The WIA omits `x5c` and     instead carries a `kid` header plus the `iss` claim (required);     relying parties resolve trust via JWKS discovery at     "<issuer>/.well-known/jwks.json" (see     RegisterWalletProviderJWKSRoute). Only meaningful for non-EUDI,     generic-OAuth ecosystems — an ARF-conformant PID/EAA Provider has     no spec-defined way to resolve trust via this path.  Note SUNET/vc's parseAttestationIdentity treats x5c as authoritative and `iss` as a secondary consistency check only when both are present, so "etsi" mode (no iss) and "ietf" mode (no x5c) are both unambiguous to that consumer. |
| `wallet_provider.wia.wallet_provider_uri` | `WALLET_WALLET_PROVIDER_WIA_WALLET_PROVIDER_URI` | string | WalletProviderURI is the expected `aud` in WIA-PoP JWTs (wallet provider identifier) |
| `wallet_provider.wia.wallet_name` | `WALLET_WALLET_PROVIDER_WIA_WALLET_NAME` | string | WalletName is the wallet_name claim in WIA JWT. REQUIRED by EC TS03 v1.5.2 §2.3.1 when Mode is "etsi" — Validate() enforces this (defaults to "SIROS ID" so it's populated out of the box). |
| `wallet_provider.wia.wallet_version` | `WALLET_WALLET_PROVIDER_WIA_WALLET_VERSION` | string | WalletVersion is the wallet_version claim. REQUIRED by EC TS03 v1.5.2 §2.3.1 ("Added `wallet_version` (REQUIRED) to the WIA") when Mode is "etsi" — Validate() enforces this; there is no sensible built-in default (it must reflect this deployment's actual released version). |
| `wallet_provider.wia.wallet_link` | `WALLET_WALLET_PROVIDER_WIA_WALLET_LINK` | string | WalletLink is the wallet download/info URI. SHOULD per TS03 §2.3.1; not enforced by Validate(). |
| `wallet_provider.wia.certification_info` | `WALLET_WALLET_PROVIDER_WIA_CERTIFICATIONINFO` | map[string]interface{} | CertificationInfo is the wallet_solution_certification_information claim. Free-form map included as-is in the WIA JWT. SHALL-required by TS03 §2.3.1 when Mode is "etsi", but TS03 itself notes the certification scheme is not yet finalized ("the exact content of wallet_solution_certification_information is undefined") — Validate() only warns (via the WIA service logger at startup) rather than hard failing, unlike WalletVersion. |
| `wallet_provider.wia.max_expiry_seconds` | `WALLET_WALLET_PROVIDER_WIA_MAX_EXPIRY_SECONDS` | integer | MaxExpirySeconds is the maximum WIA lifetime in seconds (CS-04 requires < 24h) |
| `wallet_provider.wia.challenge_ttl_seconds` | `WALLET_WALLET_PROVIDER_WIA_CHALLENGE_TTL_SECONDS` | integer | ChallengeTTLSeconds is the lifetime of WIA challenge nonces in seconds |
| `wallet_provider.wia.rate_limit.enabled` | `WALLET_WALLET_PROVIDER_WIA_RATE_LIMIT_ENABLED` | boolean | Enabled controls whether rate limiting is active |
| `wallet_provider.wia.rate_limit.max_attempts` | `WALLET_WALLET_PROVIDER_WIA_RATE_LIMIT_MAX_ATTEMPTS` | integer | MaxAttempts is the maximum number of login/registration attempts per window Default: 10 |
| `wallet_provider.wia.rate_limit.window_seconds` | `WALLET_WALLET_PROVIDER_WIA_RATE_LIMIT_WINDOW_SECONDS` | integer | WindowSeconds is the time window for rate limiting (in seconds) Default: 60 (1 minute) |
| `wallet_provider.wia.rate_limit.lockout_seconds` | `WALLET_WALLET_PROVIDER_WIA_RATE_LIMIT_LOCKOUT_SECONDS` | integer | LockoutSeconds is how long to lock out after exceeding the limit Default: 300 (5 minutes) |
| `wallet_provider.attestation.lifetime_seconds` | `WALLET_WALLET_PROVIDER_ATTESTATION_LIFETIME_SECONDS` | integer | LifetimeSeconds is the WIA lifetime. TS03 v1.5.2 caps this at < 24h (86400); this wallet provider defaults far below that (300s / 5 min) specifically so that WIA lifetime — not revocation-list checking — is the mechanism that bounds exposure from a compromised/revoked wallet instance. See the type-level comment above. |
| `wallet_provider.attestation.ka_expiry_seconds` | `WALLET_WALLET_PROVIDER_ATTESTATION_KA_EXPIRY_SECONDS` | integer | KAExpirySeconds is the key attestation JWT expiry. Short-lived by default (15s) for single-use credential issuance. |
| `wallet_provider.attestation.native_attestation.enabled` | `WALLET_WALLET_PROVIDER_ATTESTATION_NATIVE_ATTESTATION_ENABLED` | boolean | Enabled controls whether native platform attestation is required. |
| `wallet_provider.attestation.native_attestation.apple_app_attest_environment` | `WALLET_WALLET_PROVIDER_ATTESTATION_NATIVE_ATTESTATION_APPLE_APP_ATTEST_ENVIRONMENT` | string | AppleAppAttestEnvironment: "production" or "development" |
| `wallet_provider.attestation.native_attestation.apple_app_id` | `WALLET_WALLET_PROVIDER_ATTESTATION_NATIVE_ATTESTATION_APPLE_APP_ID` | string | AppleAppID is the full App ID (TeamID.BundleID) for Apple App Attest. |
| `wallet_provider.attestation.native_attestation.google_package_name` | `WALLET_WALLET_PROVIDER_ATTESTATION_NATIVE_ATTESTATION_GOOGLE_PACKAGE_NAME` | string | GooglePackageName is the Android package name for Play Integrity. |
| `wallet_provider.attestation.native_attestation.google_play_integrity_decryption_key` | `WALLET_WALLET_PROVIDER_ATTESTATION_NATIVE_ATTESTATION_GOOGLE_PLAY_INTEGRITY_DECRYPTION_KEY` | string | GooglePlayIntegrityDecryptionKey is the base64-encoded decryption key. Prefer GooglePlayIntegrityDecryptionKeyPath for production deployments. |
| `wallet_provider.attestation.native_attestation.google_play_integrity_decryption_key_path` | `WALLET_WALLET_PROVIDER_ATTESTATION_NATIVE_ATTESTATION_GOOGLE_PLAY_INTEGRITY_DECRYPTION_KEY_PATH` | string | GooglePlayIntegrityDecryptionKeyPath is a path to a file containing the decryption key (preferred over the inline value — same pattern as PKCS11.PINPath / JWT.SecretPath, so this AES key material can be mounted from a secret store instead of living in plain env vars/YAML). |
| `wallet_provider.attestation.native_attestation.google_play_integrity_verification_key` | `WALLET_WALLET_PROVIDER_ATTESTATION_NATIVE_ATTESTATION_GOOGLE_PLAY_INTEGRITY_VERIFICATION_KEY` | string | GooglePlayIntegrityVerificationKey is the base64-encoded verification key. Prefer GooglePlayIntegrityVerificationKeyPath for production deployments. |
| `wallet_provider.attestation.native_attestation.google_play_integrity_verification_key_path` | `WALLET_WALLET_PROVIDER_ATTESTATION_NATIVE_ATTESTATION_GOOGLE_PLAY_INTEGRITY_VERIFICATION_KEY_PATH` | string | GooglePlayIntegrityVerificationKeyPath is a path to a file containing the verification key (preferred over the inline value). |
| `wallet_provider.attestation.fido2_attestation.enabled` | `WALLET_WALLET_PROVIDER_ATTESTATION_FIDO2_ATTESTATION_ENABLED` | boolean | Enabled controls whether the FIDO2 key-attestation registration endpoint accepts and verifies attestation objects. Off by default — like NativeAttestation, this is an explicit opt-in trust decision. |
| `wallet_provider.attestation.status_list.enabled` | `WALLET_WALLET_PROVIDER_ATTESTATION_STATUS_LIST_ENABLED` | boolean | Enabled controls whether `client_status`/`key_storage_status` are emitted at all. Defaults to true (CS-04 conformance); set false to go back to omitting them. |
| `wallet_provider.attestation.status_list.uri` | `WALLET_WALLET_PROVIDER_ATTESTATION_STATUS_LIST_URI` | string | URI overrides the status list URI the claims reference. Defaults to this wallet provider's own endpoint, "<server.base_url>/wallet-provider/status-list". Set it only when the list is published somewhere else (e.g. behind a CDN on a different host than server.base_url). |
| `wallet_provider.attestation.status_list.maintenance_period_seconds` | `WALLET_WALLET_PROVIDER_ATTESTATION_STATUS_LIST_MAINTENANCE_PERIOD_SECONDS` | integer | MaintenancePeriodSeconds is how far ahead of issuance the claims' `exp` — the revocation *maintenance* commitment, independent of the token's own `exp` (CS-04 §7.2's note; TS-03 clause 2.4.1) — is set. CS-04 §7.2.2 requires at least 31 days remaining at presentation; this defaults to 45 days so a WUA still satisfies that after sitting unused for a fortnight. Values below 31 days are rejected by Validate() when StatusList is enabled. |

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
| `authzen_proxy.issuer_entitlement_mode` | `WALLET_AUTHZEN_PROXY_ISSUER_ENTITLEMENT_MODE` | string | IssuerEntitlementMode decides what happens when a PID or attestation provider is not registered for what it is offering: "warn" (default, report and continue), "fail" (refuse), or "off" (do not check).  The default is warn, not fail, because the ARF obligation to verify registration certificates applies 24 months after the amending Regulation enters into force. Until then, refusing a provider that has simply not been registered yet would break issuance that is currently legitimate. An unrecognised value is treated as warn rather than off, so a typo cannot silently disable the check. |
| `authzen_proxy.allow_resolution` | `WALLET_AUTHZEN_PROXY_ALLOW_RESOLUTION` | boolean | AllowResolution controls whether resolution-only requests are allowed. Resolution requests fetch metadata (DID documents, entity configs) without key validation. Default: true |
| `authzen_proxy.fail_open_on_tenant_lookup_error` | `WALLET_AUTHZEN_PROXY_FAIL_OPEN_ON_TENANT_LOOKUP_ERROR` | boolean | FailOpenOnTenantLookupError controls behavior when per-tenant PDP lookup fails. If false (default), tenant lookup errors return an error to the client. If true, falls back to the global PDP URL on lookup errors. Security note: fail-closed (false) prevents bypassing per-tenant security policies. |

## audit

Environment prefix: `WALLET_AUDIT`

| YAML Key | Env Variable | Type | Description |
|----------|-------------|------|-------------|
| `audit.enabled` | `WALLET_AUDIT_ENABLED` | boolean | Enabled enables SET audit event emission. |
| `audit.issuer` | `WALLET_AUDIT_ISSUER` | string | Issuer is the iss claim in SET records (e.g. "https://wallet.siros.org"). |
| `audit.key_path` | `WALLET_AUDIT_KEY_PATH` | string | KeyPath is the path to a PEM-encoded EC private key for signing SET records. |
| `audit.key_id` | `WALLET_AUDIT_KEY_ID` | string | KeyID is the kid used in SET JWS headers. |

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
| `server.cors.allowed_origins` | `REGISTRY_SERVER_CORS_ALLOWED_ORIGINS` | string list | AllowedOrigins is a list of origins that may access the resource. Use "*" to allow all origins (default for development). |
| `server.cors.allowed_methods` | `REGISTRY_SERVER_CORS_ALLOWED_METHODS` | string list | AllowedMethods is a list of HTTP methods allowed for cross-origin requests. |
| `server.cors.allowed_headers` | `REGISTRY_SERVER_CORS_ALLOWED_HEADERS` | string list | AllowedHeaders is a list of request headers allowed in cross-origin requests. |
| `server.cors.exposed_headers` | `REGISTRY_SERVER_CORS_EXPOSED_HEADERS` | string list | ExposedHeaders is a list of headers that browsers are allowed to access. |
| `server.cors.allow_credentials` | `REGISTRY_SERVER_CORS_ALLOW_CREDENTIALS` | boolean | AllowCredentials indicates whether the request can include credentials. Cannot be true when AllowedOrigins is "*". |
| `server.cors.max_age` | `REGISTRY_SERVER_CORS_MAX_AGE` | integer | MaxAge indicates how long (in seconds) the results of a preflight request can be cached. |

## registry.source

Source is the legacy single-registry source configuration. Use Sources for multi-registry support. If Sources is empty, Source is used.

Environment prefix: `REGISTRY_SOURCE`

| YAML Key | Env Variable | Type | Description |
|----------|-------------|------|-------------|
| `source.url` | `REGISTRY_SOURCE_URL` | string | URL of the upstream registry. The actual endpoint is determined by the Mode setting. |
| `source.mode` | `REGISTRY_SOURCE_MODE` | string (`ts11` or `registry`) | Mode selects which API endpoint to use: "ts11" (default) or "registry" (all credentials). |
| `source.local_overrides` | `REGISTRY_SOURCE_LOCAL_OVERRIDES` | string list | LocalOverrides is a list of local file or directory paths containing VCTM JSON files. These are loaded at startup and take priority over entries fetched from the remote registry. Directories are scanned for *.json files. Entries are keyed by their "vct" field. |
| `source.poll_interval` | `REGISTRY_SOURCE_POLL_INTERVAL` | duration | PollInterval is how often to poll the upstream registry for updates |
| `source.timeout` | `REGISTRY_SOURCE_TIMEOUT` | duration | Timeout for HTTP requests to the upstream registry |

## registry.sources

Sources is an ordered list of remote registry URLs to fetch from. Schemas fetched from later sources in the list overwrite earlier ones, allowing a registry to extend or override another. When non-empty, the Source.URL field is ignored for remote fetching (Source.PollInterval and Source.LocalOverrides remain global settings). (list of entries, each with the fields below)

Environment prefix: `REGISTRY_SOURCES`

| YAML Key | Env Variable | Type | Description |
|----------|-------------|------|-------------|
| `sources[*].url` | `REGISTRY_SOURCES_URL` | string | URL is the base URL of the registry (e.g. "https://registry.siros.org"). The actual endpoint path is determined by the Mode setting. For backward compatibility, if a full path to a specific endpoint is given (e.g. ending in schemas.json or registry.json), it is used as-is regardless of Mode. |
| `sources[*].mode` | `REGISTRY_SOURCES_MODE` | string (`ts11` or `registry`) | Mode selects which API endpoint to use: "ts11" (default) for only TS11-compliant credentials, or "registry" for all credentials including non-TS11. |
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
| `jwt.secret_path` | `REGISTRY_JWT_SECRET_PATH` | string | SecretPath is an alternative to Secret: path to a file containing the JWT secret. If both Secret and SecretPath are set, SecretPath takes precedence. |
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

