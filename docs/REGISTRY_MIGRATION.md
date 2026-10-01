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
| `jwt.secret`, `jwt.secret_path` | top-level `jwt.secret` / `jwt.secret_path` (legacy HMAC only, see below). Registry-only processes only: the old values are used when no `jwt.secret` is already configured, and the old `secret_path` is read only while `as.legacy.enabled` is true; in a combined process they are ignored |
| `jwt.issuer` | top-level `jwt.issuer` (the expected `iss` of legacy HMAC tokens; registry-only processes only, ignored in a combined process). `as.issuer` is separate: it is the expected `iss` of asymmetric (AS-issued) tokens and falls back to `jwt.issuer` when unset, so set it explicitly if AS-issued tokens use a different issuer |
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

The registry no longer validates HMAC JWTs on its own. With
`registry.require_auth: true` it uses the go-tokenauth validator like the other
roles, also when the process does not run the authorization server:

- new-style (ES256/ES384/EdDSA) tokens are verified against
  `<as.external_url>/auth/.well-known/jwks.json` (no override) and must carry
  the `wallet-registry` audience;
- legacy HMAC tokens are accepted while `as.legacy.enabled` is true, are checked
  against `jwt.secret` (>= 32 bytes) and are never rejected because of the
  audience list;
- legacy validation also needs `server.rp_id` set to the RP ID of the backend
  that issued the tokens (their `aud` claim; go-tokenauth applies the audience
  list to legacy tokens too, so the registry cannot exempt them). A registry-only
  process refuses to start with the default `localhost` while legacy HMAC
  validation is enabled;
- `as.external_url`, `as.issuer` (or `jwt.issuer`) and, while legacy is enabled,
  `jwt.secret`/`jwt.secret_path` must be set; startup names the missing ones.

Deployments that migrate through the deprecated alias with the old HMAC-only
`jwt.require_auth: true` and no `as.external_url` keep starting (with a warning)
and continue to accept HMAC tokens; set `as.external_url` to accept AS-issued
tokens. Old registry secrets shorter than 32 bytes are no longer accepted; this is checked whenever legacy HMAC validation would use the secret (`as.legacy.enabled`), also with `require_auth: false`. The missing-`as.external_url` tolerance for the alias only applies while `as.legacy.enabled` is true.

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
jwt: {secret_path: /run/secrets/jwt, issuer: wallet-backend}
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

A registry-only process only reads `jwt.secret_path`, and only while
`as.legacy.enabled` is true. Backend-only secret paths (admin token, MongoDB
password, wallet-provider PIN/keys) are not read and need not be mounted. The
deprecated `jwt.secret_path` of an old registry file is only read when the
registry runs alone; in a combined process the backend's `jwt.*` is used.
