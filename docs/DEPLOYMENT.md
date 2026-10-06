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
| `as.external_url` | JWKS is fetched from `<as.external_url>/auth/.well-known/jwks.json` (no override) The host must be listed in `http_client.trusted_idp_hosts` when it is a private/cluster-internal address or plain `http` (see [Split mode](#split-mode-as-jwks)) |
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
- An isolated `wallet-provider` and a standalone `engine` (no backend in the
  process) need `as.external_url` to fetch the AS JWKS.
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

Token revocation state is held **in memory, per process**: revoked access-token
JTIs (logout) and revoked users (account deletion). With one replica a logout or
account deletion is enforced immediately. With **several replicas, or after a
restart**, a revocation recorded on one replica is not seen by the others, so a
logged-out access token remains usable on a replica that never handled the
logout until it expires (`as.default_token_ttl`, 2 minutes by default).

Until a shared revocation store exists (tracked in #407 / #415), either run a
single replica for the token-issuing role, or route a user's requests to the
same replica (session affinity) and accept that a restart forgets revocations.
The AS session store itself is shared when it is MongoDB-backed, so sessions
survive across replicas and restarts; only the revocation markers are process-local.

### Token revocation limits

Token revocation (logout, revoked user) is enforced through an in-process token blacklist, so it only takes effect in the process that holds it (single-replica limitation, tracked in issues #407 and #415). A shared revocation source is not implemented.

<a id="split-mode-as-jwks"></a>
**Split mode: reaching the AS for its signing keys.** The standalone engine, a registry-only process and an isolated wallet-provider fetch the AS keys from `as.external_url`. In a split-pod deployment that is usually a cluster-internal address, which the default HTTP client policy refuses (plain http and a private address). Do not open the global `http_client.allow_http` / `allow_private_ips` for this: they also loosen the policy for third-party issuers and verifiers. Instead list exactly the AS host in `http_client.trusted_idp_hosts`; for this one fetch that host may be private and may use plain `http`. Cloud-metadata addresses stay blocked. Example (engine and registry pods):

```yaml
as:
  external_url: http://backend.wallet.svc:8080
http_client:
  trusted_idp_hosts: ["backend.wallet.svc"]   # or WALLET_HTTP_CLIENT_TRUSTED_IDP_HOSTS=backend.wallet.svc
```

Without the entry, startup fails with an error naming the host to add. Use an `https` `as.external_url` where available.

**Standalone engine (`--mode=engine`, no backend provider):** when `as.external_url` is set, the engine accepts AS-signed ES256 session tokens, but it has no revocation checker and no token blacklist is wired into it. Consequence: after a logout or user revocation at the backend, a token **stays valid at the standalone engine until it expires**; a new WebSocket handshake with it is still accepted. The engine logs a warning at startup when it is built this way.

Mitigations:

- Use short access token TTLs, so the exposure window is bounded by the TTL.
- Co-host the engine with the backend (the default all-in-one mode), which shares the token blacklist.

### Database Scaling

- MongoDB sharding
- Read replicas
- Connection pooling

## Support

For issues and questions:

- GitHub Issues: [link]
- Documentation: [link]
- Community: [link]
