# Deployment Guide

## Prerequisites

- Go 1.21 or later (for building from source)
- Docker (for containerized deployment)
- Kubernetes cluster (for production deployment)
- MongoDB or SQLite (depending on storage backend)

## Local Development

### Quick Start

```bash
# Clone the repository
cd go-wallet-backend

# Copy and edit configuration
cp configs/config.yaml configs/config.local.yaml
# Edit configs/config.local.yaml with your settings

# Set the server secret (keys the OIDC state cookie; >= 32 bytes)
export WALLET_JWT_SECRET="your-secret-key-here"

# Build and run
make build
./bin/server -config configs/config.local.yaml
```

### Using In-Memory Storage

For development, use in-memory storage (no database required):

```yaml
# configs/config.local.yaml
storage:
  type: "memory"
```

### Using SQLite

For single-instance deployments:

```yaml
# configs/config.local.yaml
storage:
  type: "sqlite"
  sqlite:
    path: "/var/lib/wallet/wallet.db"
```

### Using MongoDB

For production deployments:

```yaml
# configs/config.local.yaml
storage:
  type: "mongodb"
  mongodb:
    uri: "mongodb://localhost:27017"
    database: "wallet"
```

## Docker Deployment

### Build Image

```bash
docker build -t go-wallet-backend:latest .
```

### Run Container

```bash
docker run -d \
  --name wallet-backend \
  -p 8080:8080 \
  -e WALLET_JWT_SECRET="your-secret-key" \
  -e WALLET_STORAGE_TYPE="mongodb" \
  -e WALLET_STORAGE_MONGODB_URI="mongodb://mongo:27017" \
  go-wallet-backend:latest
```

### Docker Compose

Create `docker-compose.yml`:

```yaml
version: '3.8'

services:
  wallet-backend:
    build: .
    ports:
      - "8080:8080"
    environment:
      WALLET_SERVER_PORT: 8080
      WALLET_STORAGE_TYPE: mongodb
      WALLET_STORAGE_MONGODB_URI: mongodb://mongo:27017
      WALLET_STORAGE_MONGODB_DATABASE: wallet
      WALLET_JWT_SECRET: ${JWT_SECRET}
      WALLET_LOGGING_LEVEL: info
    depends_on:
      - mongo
    restart: unless-stopped

  mongo:
    image: mongo:7
    ports:
      - "27017:27017"
    volumes:
      - mongo-data:/data/db
    restart: unless-stopped

volumes:
  mongo-data:
```

Run with:

```bash
export JWT_SECRET="your-secret-key"
docker-compose up -d
```

## Kubernetes Deployment

### Prerequisites

- Kubernetes cluster (EKS, GKE, AKS, or self-hosted)
- kubectl configured
- MongoDB Atlas or self-hosted MongoDB

### Create Namespace

```bash
kubectl create namespace wallet
```

### Create Secrets

```bash
# Create secret for JWT
kubectl create secret generic wallet-secrets \
  --namespace=wallet \
  --from-literal=jwt-secret='your-secret-key' \
  --from-literal=mongodb-uri='mongodb://user:pass@cluster.mongodb.net/wallet'
```

### Deployment Manifest

Create `k8s/deployment.yaml`:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: wallet-backend
  namespace: wallet
spec:
  replicas: 3
  selector:
    matchLabels:
      app: wallet-backend
  template:
    metadata:
      labels:
        app: wallet-backend
    spec:
      containers:
      - name: wallet-backend
        image: go-wallet-backend:latest
        ports:
        - containerPort: 8080
          name: http
        env:
        - name: WALLET_SERVER_HOST
          value: "0.0.0.0"
        - name: WALLET_SERVER_PORT
          value: "8080"
        - name: WALLET_STORAGE_TYPE
          value: "mongodb"
        - name: WALLET_STORAGE_MONGODB_URI
          valueFrom:
            secretKeyRef:
              name: wallet-secrets
              key: mongodb-uri
        - name: WALLET_STORAGE_MONGODB_DATABASE
          value: "wallet"
        - name: WALLET_JWT_SECRET
          valueFrom:
            secretKeyRef:
              name: wallet-secrets
              key: jwt-secret
        - name: WALLET_LOGGING_LEVEL
          value: "info"
        - name: WALLET_LOGGING_FORMAT
          value: "json"
        resources:
          requests:
            memory: "128Mi"
            cpu: "100m"
          limits:
            memory: "512Mi"
            cpu: "500m"
        livenessProbe:
          httpGet:
            path: /status
            port: 8080
          initialDelaySeconds: 10
          periodSeconds: 30
        readinessProbe:
          httpGet:
            path: /status
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 10
---
apiVersion: v1
kind: Service
metadata:
  name: wallet-backend
  namespace: wallet
spec:
  selector:
    app: wallet-backend
  ports:
  - protocol: TCP
    port: 80
    targetPort: 8080
  type: LoadBalancer
```

Apply:

```bash
kubectl apply -f k8s/deployment.yaml
```

### Rolling Upgrades and the Redis Session Store

Earlier releases kept the per-user session pointer at `<prefix>user:<userID>`.
This release scopes it by tenant at `<prefix>usert:<b64url(tenant)>:<b64url(userID)>`
(unpadded base64url, so the `:` separator is unambiguous) and adds a
`<prefix>userall:<userID>` index used for account deletion. The per-tenant
index moves from the TTL-less set `<prefix>tenant:<tenantID>` to the sorted set
`<prefix>tenantx:<tenantID>`; both indexes are scored by expiry, pruned on every
add and expire with their longest-lived member, so neither grows without bound.
The legacy `tenant:` sets are no longer written; `List`, `Delete` and
`DeleteByUser` drain them. The new pointer
deliberately does not reuse the `user:` namespace: the legacy key is the raw
user ID, so with `:` in IDs a legacy user `default:u` and the new
(tenant `default`, user `u`) would otherwise share one key and could overwrite
each other's pointer during a rolling upgrade. New writes use only the new keys. To keep sessions created by not-yet-upgraded replicas reachable
during a rolling upgrade, the store falls back to the legacy pointer:

- `GetByUser` uses the legacy pointer when the new one is absent, returns the
  session only if its user and (normalised) tenant match the request, and
  lazily backfills the new pointer and index.
  If the new pointer names a session that no longer exists (an old replica
  deleted it and wrote a replacement under the legacy pointer only), the stale
  pointer is dropped and the lookup resolves through the legacy pointer.
- Listing the `default` tenant also includes sessions that old replicas wrote
  with no tenant claim (the raw empty-tenant set).
- `DeleteByUser` and `Delete` also remove the legacy pointer, and delete the
  session it names only if that session belongs to the target user.

The fallback is bounded by the maximum session lifetime (`DefaultTTL`, 24h
unless configured): legacy keys carry the session TTL and disappear on their
own, after which the fallback finds nothing. Sessions still written by old
replicas during the rollout stay covered for the same window; complete the
rollout within it and no migration step is needed.

### WMP session affinity

The engine serves WMP over HTTP+SSE (`POST` and `GET` `/api/v2/wallet/rpc`,
`GET /api/v2/wallet/rpc/events`; discovery at `/.well-known/wmp-configuration`).
Session handling is go-wmp's (`wmp.SessionService`, `httpsse.NewSecuredServerHandler`);
what it keeps, it keeps in the memory of the replica that created the session:

- the stored WMP session, its owner and its resumption token;
- the per-session event log that `Last-Event-ID` replay reads, and the state go-wmp
  re-sends on `wmp.session.resume`;
- the engine session and the flows that run in it (they do not survive a replica
  change in any case).

With more than one engine replica the load balancer MUST therefore keep each client
on one replica. Every WMP request (`wmp.session.create`, every `POST`, the event
stream) carries the `Authorization: Bearer` header, so key affinity on a hash of
that header; `Wmp-Session-Id` and the `session_id` query parameter are present on
every request except `wmp.session.create`. A request that reaches another replica
is answered `-31000` (session not found; an unknown session and another user's are
indistinguishable by design) and the client has to create a new session.

Limits of header affinity: a refreshed token hashes differently and may land on
another replica, which has neither the session nor its resumption token, so the
client must create a new session after a token refresh unless the balancer keys on
`Wmp-Session-Id`. A replica that is restarted or drained (`SIGTERM` ends the
event streams and the sessions) loses its sessions the same way.

Everything else is spelled out by the protocol, not by deployment:

- A client that falls behind the replay window gets `410 Gone` on the event stream
  and resumes with `wmp.session.resume`; it then re-reads the state of its flows.
- `refresh_token`, `dpop_jwk` and `dpop_key_id` of a completed issuance are in the
  live event only; a replayed completion lists them in `redacted_members`.
- The Redis session store described above is the WebSocket engine's. It does
  not hold WMP sessions. Shared WMP
  session state needs a Redis `SessionStore` and `EventLog` for go-wmp, which is
  planned as a separate go-wmp module, and engine flows that survive a replica
  change; until then affinity is required.

### Horizontal Pod Autoscaler

Create `k8s/hpa.yaml`:

```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: wallet-backend-hpa
  namespace: wallet
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: wallet-backend
  minReplicas: 3
  maxReplicas: 10
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: 80
```

Apply:

```bash
kubectl apply -f k8s/hpa.yaml
```

### Ingress (Optional)

Create `k8s/ingress.yaml`:

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: wallet-backend-ingress
  namespace: wallet
  annotations:
    kubernetes.io/ingress.class: nginx
    cert-manager.io/cluster-issuer: letsencrypt-prod
spec:
  tls:
  - hosts:
    - wallet.example.com
    secretName: wallet-tls
  rules:
  - host: wallet.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: wallet-backend
            port:
              number: 80
```

Apply:

```bash
kubectl apply -f k8s/ingress.yaml
```

## VCTM Registry Deployment

The registry is a role of the main server binary. Deploy it either together
with other roles (`--mode=backend,registry,engine,auth`, served from the shared
HTTP port under `/registry`) or on its own (`--mode=registry`).

### Registry-only

```bash
./server --mode=registry --config configs/config.registry.yaml
```

or with the main image:

```bash
docker run -p 8097:8097 -v $PWD/registry.yaml:/etc/wallet/config.yaml \
  sirosfoundation/go-wallet-backend --mode=registry --config /etc/wallet/config.yaml
```

A registry-only process listens on `server.registry_host`/`server.registry_port`
(default `0.0.0.0:8097`); `WALLET_SERVER_REGISTRY_PORT` overrides it. Backend-only
settings (storage, `jwt.secret` when not needed, ...) are not required. The one
exception is `server.rp_id`: while `as.legacy.enabled` is true and a `jwt.secret`
is configured, it must be set to the RP ID of the backend that issues the legacy
HMAC tokens (their `aud` claim; go-tokenauth applies its audience list to them
too). Startup fails with a clear error if it is left at the default `localhost`;
alternatively set `as.legacy.enabled: false`. The one exemption is a
registry-only process started from the deprecated `registry.yaml` / `REGISTRY_*`
alias (which has no `rp_id`) with no `server.rp_id` set: it keeps starting and
validates legacy HMAC tokens without an audience check (signature, `jwt.issuer`,
expiry and revocation are still enforced) until the deprecated configuration is
removed; see [REGISTRY_MIGRATION.md](REGISTRY_MIGRATION.md).

When `registry.require_auth` is `true` the process needs the settings to build
the shared token validator (the AS itself is *not* run, keep `as.enabled` false):

| Setting | Why |
|---------|-----|
| `as.external_url` | JWKS is fetched from `<as.external_url>/auth/.well-known/jwks.json` (no override); in split mode set it to the AS's in-cluster URL (see [Split mode](#split-mode-as-jwks)) |
| `as.issuer` (or `jwt.issuer`) | expected `iss` |
| `jwt.secret` / `jwt.secret_path` (>= 32 bytes) | only while `as.legacy.enabled` is true (legacy HMAC tokens); set `as.legacy.enabled: false` to drop it |

New-style tokens must carry the `wallet-registry` audience. Startup fails with a
message naming any missing field.

### go-wallet-registry image (transition helper)

`sirosfoundation/go-wallet-registry` is still published for one transition
period. It is the same server binary with `--mode=registry` fixed in the
entrypoint and `--config /app/configs/config.registry.yaml` as the default
argument (`Dockerfile.registry`). Overriding the container args therefore keeps
the registry role; a mounted config file must be in the *backend* layout with a
`registry:` section. Listen port stays 8097. Prefer the main image with
`--mode=registry` for new deployments.

## Cloud Provider Specific

### AWS (ECS)

```bash
# Create ECR repository
aws ecr create-repository --repository-name go-wallet-backend

# Build and push image
aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin <account>.dkr.ecr.us-east-1.amazonaws.com
docker build -t go-wallet-backend .
docker tag go-wallet-backend:latest <account>.dkr.ecr.us-east-1.amazonaws.com/go-wallet-backend:latest
docker push <account>.dkr.ecr.us-east-1.amazonaws.com/go-wallet-backend:latest

# Create task definition and service using AWS Console or CLI
```

### Google Cloud (Cloud Run)

```bash
# Build and push to Container Registry
gcloud builds submit --tag gcr.io/PROJECT_ID/go-wallet-backend

# Deploy to Cloud Run
gcloud run deploy wallet-backend \
  --image gcr.io/PROJECT_ID/go-wallet-backend \
  --platform managed \
  --region us-central1 \
  --allow-unauthenticated \
  --set-env-vars WALLET_STORAGE_TYPE=mongodb \
  --set-env-vars WALLET_STORAGE_MONGODB_URI=mongodb+srv://user:pass@cluster.mongodb.net/wallet \
  --set-secrets WALLET_JWT_SECRET=jwt-secret:latest
```

### Azure (Container Instances)

```bash
# Create resource group
az group create --name wallet-rg --location eastus

# Create container
az container create \
  --resource-group wallet-rg \
  --name wallet-backend \
  --image go-wallet-backend:latest \
  --cpu 1 \
  --memory 1 \
  --port 8080 \
  --environment-variables \
    WALLET_STORAGE_TYPE=mongodb \
    WALLET_STORAGE_MONGODB_URI='mongodb://...' \
    WALLET_JWT_SECRET='your-secret'
```

### Authorization Server (required) and the removed legacy AS

AS-issued session tokens (ES256/ES384/EdDSA, validated through the AS JWKS) are
the **only** authentication mechanism: the legacy HMAC token path (HS256
`appToken`, `/user/*-webauthn-*`, refresh tokens) was removed. See
[new-as.md](new-as.md#removal-of-the-legacy-as) for the full migration note.

Operator checklist when upgrading:

- The `backend` role turns the AS on (like `auth`); configure its signing key
  (`as.signing_key_path` or `as.signing_key_pkcs11`, or let it inherit the wallet
  provider key) and rules. An explicit `as.enabled: false` makes the backend refuse to start.
- `as.legacy.enabled: true` (or `WALLET_AS_LEGACY_ENABLED=true`) makes the
  process refuse to start. `as.legacy.enabled: false`, `as.legacy.deprecation_header`,
  `as.legacy.sunset_date`, `jwt.expiry_hours` and `jwt.refresh_days` are accepted but
  ignored, with a startup warning each; delete them.
- `jwt.secret` is still required (>= 32 bytes): it keys the OIDC state-binding
  cookie; it signs no tokens. `jwt.issuer` is the fallback for `as.issuer`.
- Set `as.external_url` in every process that validates AS tokens, including the
  `backend` role: the validator fetches the AS JWKS from it, and config
  validation fails without it. The shipped sample configs set it.
- If you list `server.cors.allowed_headers`, include `X-Token-Mode`: it is
  mandatory on `/auth/passkey/*`, and an explicit list replaces the defaults, so a
  browser preflight without it fails.
- Clients that still use the legacy flow get `410 legacy_tokens_disabled`.

When `as.enabled` is true and `as.audiences` is empty or omitted, the backend
applies the documented default audiences (`wallet-backend`, `wallet-engine`,
`wallet-registry`) before validating the configuration. An explicitly
configured `as.audiences` is never altered (and no longer has to include
`server.rp_id`).

## Production Checklist

- [ ] Use MongoDB or other scalable database
- [ ] Set strong JWT secret (min 32 characters)
- [ ] Enable HTTPS/TLS
- [ ] Configure CORS origins
- [ ] Set `server.trusted_proxies` to your load balancer's addresses (or `["none"]` without one). Unset, every peer is trusted for `X-Forwarded-For`, so a direct caller can pick its own client IP and dodge the per-IP OIDC gate rate limit
- [ ] Set up monitoring and logging
- [ ] If running a standalone engine (`--mode=engine`, no backend) with `as.external_url`, read [Token revocation limits](#token-revocation-limits)
- [ ] Configure health checks
- [ ] Set resource limits
- [ ] Enable autoscaling
- [ ] Set up backups
- [ ] Configure secrets management
- [ ] Review security settings
- [ ] Test disaster recovery
- [ ] Document runbook

## Monitoring

### Prometheus Metrics (TODO)

When implemented, metrics will be available at `/metrics`:

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'wallet-backend'
    static_configs:
      - targets: ['wallet-backend:8080']
```

### WebSocket close reasons

Every engine WebSocket session that ends logs exactly one Info line,
`Session close reason`, and increments the counter
`siros_engine_ws_session_closed_total{reason}`. Use it to tell *why* clients
that keep reconnecting are being dropped.

| `reason` | Meaning | Extra fields |
| --- | --- | --- |
| `read_deadline` | No frame, ping or pong from the client within the read window (`ping_interval` + `pong_timeout`, default 3 s + 5 s) | `read_window`, `since_last_inbound` |
| `peer_close` | The client sent a close frame or the TCP connection was closed | `close_code` (numeric only; the peer's close text is never logged) |
| `superseded` | A newer connection for the same user replaced this one ("last connection wins") | `superseded_by_session_id` |
| `account_deleted`, `token_revoked`, `revocation_check_failed` | Closed by the server because the user or token was revoked, or the revocation store could not answer | |
| `write_error` | A ping or handshake write failed | |
| `server_shutdown` | `engine.Manager.Close` closed the session. The server binary does not currently call it on SIGTERM, so this is not expected in production | |
| `read_error` | Any other read failure | `error_class` (Go type only, no message) |
| `server_close` | Any other server-initiated close | |

Common fields: `session_id`, `session` (short user id), `tenant_id`,
`remote_addr` (the raw socket peer: behind a proxy this is the proxy, not the
client), `session_age`, `ping_interval`, `pong_timeout`.

The default JSON logger uses zap's production sampling (the first 100 lines
per second for a given level and message are kept, then every 100th), so a
burst of more than 100 disconnects in one second can drop some `Session close
reason` lines. The counter is never sampled and is the exact source for
totals.

When a connection supersedes another, the `Closing existing session` Info
line carries `old_session_id`/`new_session_id`, both ages and both remote
addresses, and the new connection's `Session established` line carries
`superseded_session_id` (empty if it superseded nothing). A client that
reconnects every few seconds with `read_deadline` closes points at keepalive
(the client not answering pings, or a proxy swallowing them); a stream of
`superseded` closes points at two sockets for one user fighting each other.

### Logs

Logs are output to stdout in JSON format:

```bash
# View logs (Docker)
docker logs -f wallet-backend

# View logs (Kubernetes)
kubectl logs -f deployment/wallet-backend -n wallet

# Stream logs to CloudWatch, Stackdriver, etc.
```

## Troubleshooting

### Cannot connect to database

Check MongoDB connection:

```bash
# Test MongoDB connection
mongosh "mongodb://localhost:27017/wallet"
```

Verify environment variables:

```bash
# Check container environment
docker exec wallet-backend env | grep WALLET
```

### High memory usage

Check resource limits:

```bash
# Kubernetes
kubectl top pods -n wallet

# Docker
docker stats wallet-backend
```

Adjust resources in deployment manifest.

### Authentication failures

Verify JWT secret is set:

```bash
echo $WALLET_JWT_SECRET
```

Access token lifetimes are `as.default_token_ttl` / `as.audience_ttls`; sessions live `as.session_ttl`.

## Backup and Restore

### MongoDB

```bash
# Backup
mongodump --uri="mongodb://localhost:27017/wallet" --out=/backup

# Restore
mongorestore --uri="mongodb://localhost:27017/wallet" /backup/wallet
```

### SQLite

```bash
# Backup
cp wallet.db wallet.db.backup

# Restore
cp wallet.db.backup wallet.db
```

## Scaling Guidelines

### Vertical Scaling

- Increase CPU/memory per instance
- Suitable for < 1000 users

### Horizontal Scaling

- Add more instances
- Use load balancer
- Required for > 1000 users

#### Token revocation with several replicas

Revoked access-token JTIs (logout) and revoked users (account deletion) are
kept in the **revocation store**, selected by
`security.token_blacklist.backend` (env
`WALLET_SECURITY_TOKEN_BLACKLIST_BACKEND`):

| Value | Behaviour |
|-------|-----------|
| *(empty, default)* | `storage` when `storage.type` is `mongodb`, otherwise `memory` |
| `storage` | MongoDB. Shared by all replicas and survives restarts. Requires `storage.type: mongodb` (rejected at startup otherwise) |
| `memory` | Per process. Lost on restart and not seen by other replicas |

The `storage` backend uses two collections in the storage database:
`revoked_tokens` (`_id` is the JTI, `expires_at` with a TTL index, so entries
disappear after the token's own expiry; the check compares `expires_at`
itself because MongoDB's TTL monitor only runs about once a minute) and
`revoked_users` (one document per revoked user, no TTL: a user revocation is
permanent). Reads go to the primary and writes use majority write concern,
so a revocation is seen by the next check on any replica. A secondary-read
lag is therefore not a concern for these collections.

The store fails closed. If it cannot be reached or set up, a revocation
lookup that cannot be answered refuses the request instead of accepting it:
API requests get `503 {"error":"Token revocation check unavailable"}`, the
token-delegation endpoint answers 503, a WebSocket handshake is refused, and a
token checked by the token validator is rejected with 401. Every lookup is
bounded to 5 seconds. A revocation write that fails
fails the request: logout (`POST /user/session/logout`, `DELETE /auth/session`)
and account deletion answer 500 and change nothing the client cannot retry
(the session cookie is kept, the user and their data are untouched); repeat
the request once the store is back. Nothing is queued or replayed by the
server: a failed revocation is not recorded until the client repeats the
request. Account deletion revokes first. A write that reported an error may
still have been stored, so a revoked user can still call `DELETE /user/session`
(and only that route) to complete the deletion, and a token whose jti was
revoked by an interrupted logout is still admitted by
`POST /user/session/logout` (and only that route), so the retry succeeds. Both
revocations are idempotent and are never withdrawn after a failure. If
the store cannot be set up at startup the process still starts, logs an
error and refuses authenticated requests until restarted.

A process that has no storage backend of its own, a standalone engine
(`--mode=engine`) or registry (`--mode=registry`), connects to the same
revocation collections using `storage.mongodb` when the setting resolves to
`storage`, so it rejects what the backend replicas revoked. Give such a
process the same `storage.mongodb` settings as the backend. If the setting is
`storage` (or unset with `storage.type: mongodb`) and the connection fails,
that process does not start. With `memory`, or unset with non-MongoDB
storage, it keeps no revocation state, because a process-local blacklist would
never see a revocation. The isolated wallet-provider (`--mode=wallet-provider`)
uses the same store through its own storage backend. The startup warning
about process-local state is logged by every one of these roles.

`Remove` (administrative override) deletes the jti revocation in the MongoDB
store as well; `Count` only reports the entries held by the local process.

Switching backend starts with an empty store: revocations recorded in the
old one are not carried over, so tokens revoked shortly before the switch
(access tokens live `as.default_token_ttl`, 2 minutes by default) may be
accepted again until they expire.

**Startup warning.** The configuration has no replica count, so a MongoDB
storage backend is taken as the sign that several replicas are plausible. In
that case the process logs a warning when `as.session_store` is `memory`
(AS sessions are per process) or when the token blacklist is enabled with
`backend: memory`. With in-memory storage nothing is logged: only one
process is possible.

### Token revocation limits

Revocation is enforced by the revocation store; see [Token revocation with several replicas](#token-revocation-with-several-replicas) for what the shared and the per-process backends cover.

<a id="split-mode-as-jwks"></a>
**Split mode: reaching the AS for its signing keys.** The standalone engine, a registry-only process and an isolated wallet-provider fetch the AS keys from `<as.external_url>/auth/.well-known/jwks.json`. In a split-pod deployment just set `as.external_url` to the AS's in-cluster URL (`http` or `https`). The JWKS is fetched by go-tokenauth without SSRF filtering or a plaintext check, because it is infrastructure-internal traffic between components of the same cluster; do not point `as.external_url` at anything outside your own infrastructure. Example (engine and registry pods):

```yaml
as:
  external_url: http://backend.wallet.svc:8080
```

**Standalone engine (`--mode=engine`, no backend provider):** with the shared MongoDB revocation store (see above) the engine rejects what the backend revoked. With `backend: memory`, or non-MongoDB storage, it keeps no revocation state: after a logout or user revocation at the backend, a token **stays valid at the standalone engine until it expires**, and a new WebSocket handshake with it is still accepted. The engine logs a warning at startup when it is built this way.

Mitigations:

- Use short access token TTLs, so the exposure window is bounded by the TTL.
- Co-host the engine with the backend (the default all-in-one mode), which shares the token blacklist.
- Use the shared MongoDB revocation store (see above), which a standalone engine reads too.

### Database Scaling

- MongoDB sharding
- Read replicas
- Connection pooling

## Support

For issues and questions:

- GitHub Issues: [link]
- Documentation: [link]
- Community: [link]
