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

- **UserService**: User registration and account management (tokens are issued by the AS, `internal/as`)
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

- **TokenAuthMiddleware**: validates AS-issued asymmetric session tokens (go-tokenauth, JWKS); HMAC tokens are never accepted
- **Logger**: Request logging
- **RateLimit** [TODO]: Rate limiting
- **CORS**: Cross-origin resource sharing

### 6. Configuration (`pkg/config/`)

Configuration management:

- YAML file support
- Environment variable overrides
- Validation
- Defaults

## Roles and the VCTM Registry

The server is one binary (`cmd/server`) whose functionality is selected with
`--mode` (`backend`, `auth`, `engine`, `registry`, `admin`, `wallet-provider`,
or a comma-separated list / `all`). The VCTM registry (`internal/registry`,
routes under `/registry`) is the `registry` role of that binary; there is no
separate registry binary. Its previous standalone form (`cmd/registry`, its own
config file and its own HMAC-only JWT validation) was retired in favour of:

- **One configuration.** Registry settings (`source`/`sources`, `cache`,
  `dynamic_cache`, `image_embed`, `filter`, `rate_limit`, `require_auth`) are
  the `registry:` section of the backend config (`pkg/config.RegistryConfig`).
  Server address, TLS, CORS, `logging`, `http_client` and `trusted_proxies`
  are the backend's own settings. When the registry role runs together with
  other roles it is served from the shared HTTP server; when it runs alone
  (`--mode=registry`) it listens on `server.registry_host`/`server.registry_port`
  (default `0.0.0.0:8097`) and only the registry-relevant parts of the config
  are validated (`config.LoadRegistryOnly`).
- **Shared authentication.** Registry routes use the same go-tokenauth
  validator as the other roles (`pkg/middleware.TokenAuthMiddleware` when
  `registry.require_auth` is true). The validator is built by
  `RegistryProvider.buildValidator` (`internal/server/providers.go`) the same
  way as for the standalone engine and the wallet-provider: the JWKS is fetched
  from `<as.external_url>/auth/.well-known/jwks.json` (no override) through the
  guarded `http_client` and a loopback relay, the expected issuer is `as.issuer`
  (falling back to `jwt.issuer`). It does not matter whether `as.enabled` is
  true: a registry-only process does not run the authorization server but
  validates the tokens it issues. There is no HMAC path: the legacy HMAC
  authorization server was removed, and a deprecated registry.yaml `jwt` secret
  is ignored with a warning (see REGISTRY_MIGRATION.md).
- **Audience rule.** Tokens must carry the `wallet-registry` audience.
- **Tenant and rate limiting.** The token's `tenant_id` claim is put into the
  Gin context (`tenant_id`) exactly as before and keys the authenticated rate
  limit. With `registry.require_auth: false` (default) unauthenticated access is
  allowed at the lower unauthenticated rate; valid tokens are still recognised.
  A co-located backend also supplies its tenant store and token blacklist, so
  disabled tenants and revoked users are rejected on registry routes too.

See [REGISTRY_MIGRATION.md](REGISTRY_MIGRATION.md) for moving off the retired
standalone registry configuration.

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

- User sessions: AS sessions (MongoDB-backed when shared across replicas) and short-lived asymmetric access tokens
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

1. **WebAuthn**: Hardware security keys
2. **AS session tokens**: cookie-bound AS session + short-lived ES256/ES384/EdDSA access tokens from `/auth/token` (the legacy HMAC token flow was removed, see [new-as.md](new-as.md#removal-of-the-legacy-as))

### Authorization

- Access token claims include `sub` (user), `tenant_id` and `tac` (permissions)
- Middleware validates tokens
- Handlers check permissions

### Data Protection

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
