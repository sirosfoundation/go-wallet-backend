# Migrating the VCTM registry to the roles-based binary

The registry used to be a separate binary (`cmd/registry`) with its own config
file (`configs/registry.yaml`), its own `REGISTRY_*` environment variables and
its own HMAC-only JWT check. It is now the `registry` role of the main
`cmd/server` binary (`--mode=registry`), configured by a `registry:` section of
the backend config and protected by the shared go-tokenauth validator
(issue #430).

## Deprecation plan

| Release | Behaviour |
|---------|-----------|
| this release | `--registry-config` (default `configs/registry.yaml`), that file and `REGISTRY_*` variables still work as deprecated aliases: they are mapped onto `registry:` and a `DEPRECATED` warning names the new location. Keys set explicitly in the new `registry:` section or through `WALLET_REGISTRY_*` (presence in the file / environment, even if the value equals the default, e.g. `dynamic_cache.enabled: false` or `require_auth: false`) win over the same keys in the deprecated configuration, and a second warning lists the conflicting keys; keys the new configuration does not set are filled from the deprecated configuration. The helper image config `configs/config.registry.yaml` only sets `registry.dynamic_cache.enabled: true` (as the retired image did), so all other `REGISTRY_*` variables keep applying. `cmd/registry` and `make build-registry` are gone; `make run-registry` and `make docker-build-registry` remain and now use the main binary. |
| next release | the aliases and the `--registry-config` flag are removed. |

## Mapping

| Old (`registry.yaml` / `REGISTRY_*`) | New (backend config / `WALLET_*`) |
|---|---|
| `source.*`, `sources` | `registry.source.*`, `registry.sources` (`WALLET_REGISTRY_SOURCE_*`) |
| `cache.path`, `cache.max_age` | `registry.cache.*` |
| `dynamic_cache.*` | `registry.dynamic_cache.*` |
| `image_embed.*` | `registry.image_embed.*` |
| `filter.*` | `registry.filter.*` |
| `rate_limit.*` | `registry.rate_limit.*` |
| `jwt.require_auth` | `registry.require_auth` (`WALLET_REGISTRY_REQUIRE_AUTH`); a value set explicitly in the new configuration wins |
| `jwt.secret`, `jwt.secret_path`, `jwt.issuer` | **ignored, with a loud `DEPRECATED ... IGNORED` startup warning.** They configured HMAC (HS256) token validation, and the legacy HMAC authorization server was removed, so there is nothing left to validate with them (the secret file is not even read, so a missing one does not fail startup). The registry validates AS-issued tokens only: set `as.external_url` and `as.issuer` (falls back to the backend's `jwt.issuer`) instead |
| `server.host`, `server.port` | `server.registry_host`, `server.registry_port` when the registry runs alone; ignored in a combined process, which uses the backend's own listen settings |
| `server.cors`, `server.tls`, `server.served_by_header` | `server.cors`, `server.tls`, `server.served_by_header` (registry-only processes only; ignored in a combined process) |
| `logging.*` | `logging.*` (registry-only processes only) |
| `http_client.*` | `http_client.*` (registry-only processes only) |
| `trust.*` (present in the example file but never read) | dropped |

Environment variables: `REGISTRY_<KEY>` becomes `WALLET_REGISTRY_<KEY>` for the
registry keys (for example `REGISTRY_SOURCE_URL` becomes
`WALLET_REGISTRY_SOURCE_URL`), and the shared settings use their usual `WALLET_`
names (`REGISTRY_SERVER_PORT` becomes `WALLET_SERVER_REGISTRY_PORT`,
`REGISTRY_LOGGING_LEVEL` becomes `WALLET_LOGGING_LEVEL`).

If you pass an old-layout file with `--config` by mistake, top-level registry
keys (`source`, `cache`, `filter`, ...) are not applied and a warning tells you
to move them under `registry:`.

## Authentication changes

The registry no longer validates HMAC JWTs on its own, and no HMAC token is
accepted at all any more (the legacy HMAC authorization server was removed). With
`registry.require_auth: true` it uses the go-tokenauth validator like the other
roles, also when the process does not run the authorization server:

- ES256/ES384/EdDSA access tokens are verified against
  `<as.external_url>/auth/.well-known/jwks.json` (no override; fetched through
  the guarded `http_client`, so plain `http` needs `http_client.allow_http`) and
  must carry the `wallet-registry` audience;
- `as.external_url` and `as.issuer` (or `jwt.issuer`) must be set; startup
  names the missing ones. `jwt.secret` is not needed.

With `require_auth: false` the registry still recognises valid tokens when
`as.external_url` is set (they raise the rate limit); anything else, including
HMAC tokens, is served as unauthenticated.

### What a deployment with an old registry.yaml gets

The same rule as for the rest of the backend applies: a setting that *requests*
the removed legacy AS fails startup, a leftover that merely *configured* it is
ignored with a warning.

- `as.legacy.enabled=true` (or `WALLET_AS_LEGACY_ENABLED=true`) is refused,
  exactly as by the backend (`as.legacy.enabled=false`, and the other
  `as.legacy.*` settings, are accepted and ignored with a warning).
- The deprecated registry `jwt` block (`secret`, `secret_path`, `issuer`) is
  **ignored with a loud warning**: HMAC tokens signed with that secret are
  rejected (401 with `require_auth`, otherwise served as unauthenticated). There
  is no audience-independent compatibility path and no `server.rp_id`
  requirement any more.
- `jwt.require_auth: true` still maps to `registry.require_auth`, but without
  `as.external_url` the registry has no way to authenticate anyone, so startup
  **fails** (naming `as.external_url`) instead of starting in a state where every
  request is refused or, worse, unauthenticated. Set `as.external_url` and
  migrate clients to AS-issued session tokens.

## Example

Old `registry.yaml`:

```yaml
server: {host: 0.0.0.0, port: 8097}
source: {url: https://registry.siros.org/api/v1/schemas.json}
cache: {path: /data/vctm-cache.json}
jwt: {secret_path: /run/secrets/jwt, issuer: wallet-backend, require_auth: true}
```

New (registry-only) backend-layout config:

```yaml
server: {registry_port: 8097}
registry:
  source: {url: https://registry.siros.org/api/v1/schemas.json}
  cache: {path: /data/vctm-cache.json}
  require_auth: true
as:
  external_url: https://wallet.example.org
  issuer: wallet-backend   # expected "iss" of the AS-issued tokens
```

or, combined, put the `registry:` block into the existing backend config and
drop `--registry-config`.

## Deployment changes

- Command: `--mode ... registry ...` on the main image, or keep the
  `go-wallet-registry` image, which is now the main binary with `--mode=registry`
  as its entrypoint (transition helper). Container args that were
  `-config <registry.yaml>` must now point at a backend-layout file (or be
  dropped and use `WALLET_*` env vars).
- Combined deployments: drop `-registry-config` and move the file's content into
  the backend config's `registry:` section; drop `REGISTRY_*` variables.
- Registry-only deployments: mount a backend-layout config, expose 8097.

## HTTP paths

The registry role serves `/registry/type-metadata`, `/registry/credentials` and
`/registry/status`. A registry-only process (`--mode=registry`, including the
`go-wallet-registry` helper image) additionally serves `/type-metadata` and
`/credentials` at the root, exactly as the retired binary did, under the same
authentication and rate limiting, so existing clients keep working. `/status`
at the root is the server's own health endpoint (it cannot also be the registry
status); use `/registry/status` for the registry status.

When the engine and registry roles run in the same process, the engine's VCTM
lookups call the registry in-process (no network, unaffected by the outbound
loopback/plain-HTTP guards) unless `trust.registry_url` names an explicit
registry.

## Secrets in registry-only mode

A registry-only process reads no secret files: it validates tokens through the
AS JWKS and needs no `jwt.secret` / `jwt.secret_path`. Backend-only secret paths
(admin token, MongoDB password, wallet-provider PIN/keys) are not read either
and need not be mounted. The `jwt.secret_path` of an old registry file is never
read.
