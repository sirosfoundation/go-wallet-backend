# Architecture Documentation

## Overview

The Go Wallet Backend is a cloud-native, horizontally scalable wallet backend server designed for managing verifiable credentials and presentations. It follows Go best practices and provides multiple storage backend options to avoid vendor lock-in.

## Design Principles

1. **Separation of Concerns**: Clear separation between domain, storage, service, and API layers
2. **Dependency Injection**: Services receive dependencies through constructors
3. **Interface-Based Design**: Storage layer fully abstracted through interfaces
4. **Cloud-Native**: Stateless design, external state management, health checks
5. **Standard Library First**: Minimal external dependencies, using only well-established libraries

## Architecture Layers

### 1. Domain Layer (`internal/domain/`)

Contains business entities and domain models:

- **User**: User accounts with WebAuthn credentials
- **VerifiableCredential**: Stored credentials in various formats
- **VerifiablePresentation**: Verifiable presentations
- **WebauthnChallenge**: WebAuthn challenges for authentication
- **CredentialIssuer**: Trusted credential issuers
- **Verifier**: Trusted verifiers

Domain models are storage-agnostic and include:
- JSON tags for API serialization
- BSON tags for MongoDB
- GORM tags for SQL databases

### 2. Storage Layer (`internal/storage/`)

Fully abstracted storage with multiple implementations:

#### Interfaces

- **UserStore**: User CRUD operations
- **CredentialStore**: Credential management
- **PresentationStore**: Presentation management
- **ChallengeStore**: WebAuthn challenge management
- **IssuerStore**: Issuer registry
- **VerifierStore**: Verifier registry
- **Store**: Aggregates all stores

#### Implementations

1. **Memory** (`internal/storage/memory/`):
   - In-memory storage using sync.RWMutex
   - Ideal for development and testing
   - No persistence

2. **SQLite** (`internal/storage/sqlite/`) [TODO]:
   - File-based SQL database using GORM
   - Single-instance deployments
   - Simple backup/restore

3. **MongoDB** (`internal/storage/mongodb/`) [TODO]:
   - Document database
   - Horizontal scaling
   - Production-ready

### 3. Service Layer (`internal/service/`)

Business logic and orchestration:

- **UserService**: User registration, authentication, JWT management
- **KeystoreService**: Key management, signing operations
- **IssuanceService** [TODO]: OpenID4VCI credential issuance
- **VerificationService** [TODO]: OpenID4VP presentation verification

Services are stateless and receive dependencies through constructors.

### 4. API Layer (`internal/api/`)

HTTP handlers using Gin framework:

- RESTful endpoints
- Request validation
- Response formatting
- Error handling

### 5. Middleware (`pkg/middleware/`)

HTTP middleware:

- **AuthMiddleware**: JWT authentication
- **Logger**: Request logging
- **RateLimit** [TODO]: Rate limiting
- **CORS**: Cross-origin resource sharing

### 6. Configuration (`pkg/config/`)

Configuration management:

- YAML file support
- Environment variable overrides
- Validation
- Defaults

## Data Flow

```
Client Request
    ↓
[Gin Router]
    ↓
[Middleware] (Auth, Logging, CORS)
    ↓
[API Handlers]
    ↓
[Service Layer] (Business Logic)
    ↓
[Storage Layer] (Persistence)
    ↓
[Database] (Memory/SQLite/MongoDB)
```

## Horizontal Scaling Strategy

### Stateless Design

All application state is stored externally:

- User sessions: JWT tokens (stateless) or Redis
- WebAuthn challenges: Shared storage (MongoDB/Redis)
- Credentials: Shared database

### Load Balancing

The application can run multiple instances behind a load balancer:

```
                    [Load Balancer]
                          |
            +-------------+-------------+
            |             |             |
        [Instance 1] [Instance 2] [Instance 3]
            |             |             |
            +-------------+-------------+
                          |
                    [MongoDB Cluster]
```

### Session Affinity

For WebSocket connections (client keystore):
- Use load balancer session affinity (sticky sessions)
- Or implement message broker (Redis Pub/Sub, Kafka)

### Configuration

Environment-based configuration allows different settings per instance:

```bash
# Instance 1
WALLET_SERVER_PORT=8080

# Instance 2
WALLET_SERVER_PORT=8081

# Shared database
WALLET_STORAGE_TYPE=mongodb
WALLET_STORAGE_MONGODB_URI=mongodb://cluster:27017
```

## Security

### Authentication

1. **Password-based**: bcrypt hashing
2. **WebAuthn**: Hardware security keys
3. **JWT**: Stateless session management

### Authorization

- JWT claims include user_id and did
- Middleware validates tokens
- Handlers check permissions

### Data Protection

- Passwords: bcrypt hashed
- Private data: Encrypted at rest [TODO]
- Transport: HTTPS/TLS in production
- Secrets: Environment variables, never committed

## Integration with vc Project

Reused components from `github.com/dc4eu/vc`:

1. **OpenID4VCI** (`pkg/openid4vci`):
   - Credential offer handling
   - Token exchange
   - Credential request

2. **OpenID4VP** (`pkg/openid4vp`):
   - Presentation request parsing
   - Presentation submission
   - Verification

3. **JWT/JWK** (`pkg/jose`):
   - Key management
   - JWT signing and verification
   - JWK handling

4. **SD-JWT-VC** (`pkg/sdjwtvc`):
   - Selective disclosure
   - SD-JWT creation/verification

5. **Models** (`pkg/model`):
   - Credential types
   - Configuration structures

## Deployment Architectures

### Development

```
[Developer Machine]
    ↓
[In-Memory Storage]
```

### Single Instance

```
[EC2/VM Instance]
    ↓
[SQLite Database]
```

### Production (Kubernetes)

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: wallet-backend
spec:
  replicas: 3
  template:
    spec:
      containers:
      - name: wallet-backend
        image: go-wallet-backend:latest
        env:
        - name: WALLET_STORAGE_TYPE
          value: "mongodb"
        - name: WALLET_STORAGE_MONGODB_URI
          valueFrom:
            secretKeyRef:
              name: wallet-secrets
              key: mongodb-uri
```

### Cloud Services

1. **AWS**:
   - ECS/EKS for containers
   - DocumentDB for MongoDB compatibility
   - Secrets Manager for secrets
   - CloudWatch for logging

2. **Google Cloud**:
   - GKE for Kubernetes
   - Cloud Run for serverless
   - MongoDB Atlas
   - Cloud Logging

3. **Azure**:
   - AKS for Kubernetes
   - Cosmos DB (MongoDB API)
   - Key Vault for secrets
   - Application Insights

## Health Checks

### Liveness Probe

```
GET /status
```

Returns 200 OK if the service is running.

### Readiness Probe

```
GET /health
```

Returns 200 OK if:
- Service is running
- Database is accessible
- All dependencies are healthy

## Monitoring and Observability

### Metrics [TODO]

- Request count
- Request duration
- Error rate
- Active users
- Credential operations

### Tracing [TODO]

- OpenTelemetry integration
- Distributed tracing
- Request correlation

### Logging

- Structured logging (JSON)
- Log levels: debug, info, warn, error
- Contextual information (user_id, request_id)

## Performance Considerations

### Caching [TODO]

- Issuer metadata
- Verifier registry
- Public keys
- JWK sets

### Database Optimization

- Indexes on frequently queried fields
- Compound indexes for multi-field queries
- Connection pooling

### Concurrency

- Goroutines for async operations
- Context for cancellation
- sync.RWMutex for in-memory storage

## Testing Strategy

1. **Unit Tests**: Test individual functions
2. **Integration Tests**: Test storage implementations
3. **API Tests**: Test HTTP endpoints
4. **E2E Tests**: Test complete flows

## Future Enhancements

1. **WebSocket Support**: Real-time communication for client keystores
2. **Redis Integration**: Session management, caching
3. **gRPC API**: High-performance API option
4. **Event Sourcing**: Audit trail for all operations
5. **Multi-tenancy**: Support for multiple organizations
6. **Admin API**: Management and monitoring
7. **Backup/Restore**: Automated backup solutions
8. **Rate Limiting**: Per-user and global limits
9. **OAuth2 Support**: Third-party authentication
10. **DID Methods**: Support for multiple DID methods

## References

- [W3C Verifiable Credentials](https://www.w3.org/TR/vc-data-model/)
- [OpenID for Verifiable Credential Issuance](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)
- [OpenID for Verifiable Presentations](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html)
- [WebAuthn](https://www.w3.org/TR/webauthn-2/)
- [DID Core](https://www.w3.org/TR/did-core/)
