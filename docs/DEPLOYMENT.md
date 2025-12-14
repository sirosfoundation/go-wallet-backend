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

## Production Checklist

- [ ] Use MongoDB or other scalable database
- [ ] Set strong JWT secret (min 32 characters)
- [ ] Enable HTTPS/TLS
- [ ] Configure CORS origins
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

### Database Scaling

- MongoDB sharding
- Read replicas
- Connection pooling

## Support

For issues and questions:

- GitHub Issues: [link]
- Documentation: [link]
- Community: [link]
