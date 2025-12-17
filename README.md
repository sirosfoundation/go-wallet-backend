# Go Wallet Backend

**This is work in progress**

This is a proof of concept re-implementation of wwWallet/wallet-backend-server in golang. The intention is to build a version of the wwWallet backend that is ready for large scale production deployment.

## Features

- **Storage Abstraction**: Pluggable storage layer supporting in-memory, SQLite, and MongoDB
- **WebAuthn Support**: Passwordless authentication with hardware security keys
- **OpenID4VCI/VP**: Full support for credential issuance and verification
- **Cloud-Native**: Stateless design for horizontal scaling
- **Zero MySQL Dependency**: Choose from multiple storage backends
- **Standards-Compliant**: Implements W3C Verifiable Credentials and DID standards

## Architecture

### Project Structure

```
go-wallet-backend/
├── cmd/
│   └── server/          # Main application entry point
├── internal/
│   ├── api/             # HTTP handlers and routes
│   ├── domain/          # Business logic and domain models
│   ├── service/         # Service layer (keystores, issuance, etc.)
│   └── storage/         # Storage implementations
├── pkg/
│   ├── config/          # Configuration management
│   ├── middleware/      # HTTP middleware
│   └── webauthn/        # WebAuthn utilities
├── api/
│   └── openapi.yaml     # API specification
└── configs/
    └── config.yaml      # Default configuration
```

### Storage Layer

The storage layer is fully abstracted using the backend pattern:

#### Storage Interfaces

- **UserStore**: User management and authentication
- **CredentialStore**: Verifiable credential storage
- **PresentationStore**: Verifiable presentation storage  
- **ChallengeStore**: WebAuthn challenge management
- **IssuerStore**: Credential issuer management
- **VerifierStore**: Verifier management

#### Backend Implementations

| Backend | Use Case | Features |
|---------|----------|----------|
| **Memory** | Development/Testing | Fast, no setup required, data lost on restart |
| **MongoDB** | Production | Persistent, scalable, supports horizontal scaling |

The backend factory (`internal/backend`) automatically selects the appropriate storage implementation based on configuration.

```go
// Configuration-driven backend selection
store, err := backend.New(ctx, cfg)
if err != nil {
    log.Fatal(err)
}
defer store.Close()
```

### Horizontal Scaling

The application is designed to scale horizontally:

1. **Stateless Design**: All state stored in external storage backends
2. **Session Management**: Redis or MongoDB-backed sessions
3. **WebSocket Handling**: Session affinity or message broker integration
4. **Health Checks**: Built-in readiness and liveness probes

## Quick Start

### Prerequisites

- Go 1.21 or later
- Optional: MongoDB for production deployments
- Optional: Redis for session management

### Installation

#### Using binaries

```bash
# Clone the repository
git clone https://github.com/sirosfoundation/go-wallet-backend
cd go-wallet-backend

# Install dependencies
go mod download

# Build
make build

# Run
./bin/server
```

#### Using docker compose

```bash
docker compose up
```

### Configuration

Configuration can be provided via:
1. YAML file (default: `configs/config.yaml`)
2. Environment variables (prefixed with `WALLET_`)
3. Command-line flags

Example configuration:

```yaml
server:
  host: "0.0.0.0"
  port: 8080
  rp_id: "localhost"
  rp_origin: "http://localhost:8080"

storage:
  type: "mongodb"  # memory, sqlite, mongodb
  mongodb:
    uri: "mongodb://localhost:27017"
    database: "wallet"

logging:
  level: "info"
  format: "json"
```

Environment variables:

```bash
export WALLET_SERVER_PORT=8080
export WALLET_STORAGE_TYPE=mongodb
export WALLET_STORAGE_MONGODB_URI=mongodb://localhost:27017
```

## Development

### Building

```bash
# Build server
make build

# Run tests
make test

# Run with hot reload
make dev
```

### API Endpoints

#### Authentication (WebAuthn-only)

**Note:** Password-based authentication has been deprecated. All user authentication uses WebAuthn (passkeys/hardware security keys).

- `POST /webauthn/register/start` - Start WebAuthn registration
- `POST /webauthn/register/finish` - Finish WebAuthn registration  
- `POST /webauthn/login/start` - Start WebAuthn login
- `POST /webauthn/login/finish` - Finish WebAuthn login

**Deprecated endpoints (return HTTP 410 Gone):**
- `POST /user/register` - Use WebAuthn registration instead
- `POST /user/login` - Use WebAuthn login instead

#### Storage (Authenticated)
- `GET /storage/vc` - Get all credentials
- `POST /storage/vc` - Store credential
- `PUT /storage/vc/update` - Update credential
- `GET /storage/vc/:id` - Get credential by ID
- `DELETE /storage/vc/:id` - Delete credential
- `GET /storage/vp` - Get all presentations
- `POST /storage/vp` - Store presentation

#### Credential Issuance
- `GET /issuer/all` - Get all issuers
- `POST /issuer/authorize` - Authorize with issuer
- `POST /issuer/token` - Exchange authorization code

#### Verification
- `GET /verifier/all` - Get all verifiers
- `POST /verifier/verify` - Verify presentation

#### Status
- `GET /status` - Health check

## Deployment

### Docker

```bash
# Build image
docker build -t go-wallet-backend:latest .

# Run container
docker run -p 8080:8080 \
  -e WALLET_STORAGE_TYPE=mongodb \
  -e WALLET_STORAGE_MONGODB_URI=mongodb://mongo:27017 \
  go-wallet-backend:latest
```

### Kubernetes

See `deployments/kubernetes/` for example manifests.

Key features:
- Horizontal Pod Autoscaling
- Rolling updates
- Health checks
- ConfigMap/Secret management

### Cloud Providers

The application is designed to run on:
- AWS (ECS, EKS, Lambda)
- Google Cloud (GKE, Cloud Run)
- Azure (AKS, Container Instances)

## Security

- **Authentication**: JWT-based with WebAuthn support
- **Encryption**: All sensitive data encrypted at rest
- **HTTPS**: TLS 1.3 recommended for production
- **CORS**: Configurable cross-origin policies
- **Rate Limiting**: Built-in rate limiting middleware

## Reused Components from vc Project

- OpenID4VCI client (`pkg/openid4vci`)
- OpenID4VP verifier (`pkg/openid4vp`)
- JWT/JWK utilities (`pkg/jose`)
- DID key resolution (`pkg/keyresolver`)
- SD-JWT-VC support (`pkg/sdjwtvc`)
- Credential models (`pkg/model`)

## License

MIT License - see LICENSE file for details

## Contributing

Contributions welcome! Please read CONTRIBUTING.md for guidelines.

## Support

For issues and questions:
- GitHub Issues: https://github.com/sirosfoundation/go-wallet-backend/issues
- Documentation: https://github.com/sirosfoundation/go-wallet-backend/wiki
