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

# Set JWT secret
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
| `as.external_url` | JWKS is fetched from `<as.external_url>/auth/.well-known/jwks.json` (no override) |
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

### Authorization Server defaults (upgrade note)

When `as.enabled` is true and `as.audiences` is empty or omitted, the backend
applies the documented default audiences (`wallet-backend`, `wallet-engine`,
`wallet-registry`, plus `server.rp_id` while `as.legacy.enabled` is true)
before validating the configuration. Likewise, an empty `jwt.issuer` with
`as.legacy.enabled: true` falls back to `wallet-backend`. Configurations that
never set these (for example the siros-id-stack chart, which renders
`as.enabled: true` with legacy off and no `audiences`) therefore keep starting
unchanged. An explicitly configured `as.audiences` is never altered; with
legacy enabled it must include `server.rp_id`.

## Production Checklist

- [ ] Use MongoDB or other scalable database
- [ ] Set strong JWT secret (min 32 characters)
- [ ] Enable HTTPS/TLS
- [ ] Configure CORS origins
- [ ] Set `server.trusted_proxies` to your load balancer's addresses (or `["none"]` without one). Unset, every peer is trusted for `X-Forwarded-For`, so a direct caller can pick its own client IP and dodge the per-IP OIDC gate rate limit
- [ ] Set up monitoring and logging
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

Check token expiry settings in configuration.

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
the request once the store is back. Account deletion revokes first. A write
that reported an error may still have been stored, so a revoked user can still
call `DELETE /user/session` (and only that route) to complete the deletion;
the revocation is idempotent. If
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

Single-use refresh-token consumption and the refresh-token family markers
written on logout are **still per process** and are not covered by the
backend setting. With several replicas, or after a restart, a stolen refresh
token can still be exchanged on a replica that never handled the logout until
it expires (refresh tokens live `jwt.refresh_days`). Run a single replica for
the token-issuing role, or route a user's requests to the same replica
(session affinity), until that state is moved or removed.

`POST /user/session/logout` fails closed: if the refresh-token family cannot
be revoked it answers `500 {"error":"Failed to revoke session"}` instead of
`200`, and the client should retry (logout is idempotent). The access token's
jti is blacklisted only after the family revocation succeeds, so the same
token still authenticates on the retry.

**Startup warning.** The configuration has no replica count, so a MongoDB
storage backend is taken as the sign that several replicas are plausible. In
that case the process logs a warning when `as.session_store` is `memory`
(AS sessions are per process) or when the token blacklist is enabled with
`backend: memory`. With in-memory storage nothing is logged: only one
process is possible.

### Database Scaling

- MongoDB sharding
- Read replicas
- Connection pooling

## Support

For issues and questions:

- GitHub Issues: [link]
- Documentation: [link]
- Community: [link]
