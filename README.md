# Go Wallet Backend

<div align="center">

[![Go Reference](https://pkg.go.dev/badge/github.com/sirosfoundation/go-wallet-backend.svg)](https://pkg.go.dev/github.com/sirosfoundation/go-wallet-backend)
[![CI](https://github.com/sirosfoundation/go-wallet-backend/actions/workflows/ci.yml/badge.svg)](https://github.com/sirosfoundation/go-wallet-backend/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/sirosfoundation/go-wallet-backend)](https://goreportcard.com/report/github.com/sirosfoundation/go-wallet-backend)
[![codecov](https://codecov.io/gh/sirosfoundation/go-wallet-backend/branch/main/graph/badge.svg)](https://codecov.io/gh/sirosfoundation/go-wallet-backend)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

[![Docker](https://github.com/sirosfoundation/go-wallet-backend/actions/workflows/docker-publish.yml/badge.svg)](https://github.com/sirosfoundation/go-wallet-backend/actions/workflows/docker-publish.yml)
[![Latest Release](https://img.shields.io/github/v/release/sirosfoundation/go-wallet-backend?include_prereleases)](https://github.com/sirosfoundation/go-wallet-backend/releases)
[![Issues](https://img.shields.io/github/issues/sirosfoundation/go-wallet-backend)](https://github.com/sirosfoundation/go-wallet-backend/issues)
[![Last Commit](https://img.shields.io/github/last-commit/sirosfoundation/go-wallet-backend)](https://github.com/sirosfoundation/go-wallet-backend/commits/main)

</div>

**This is work in progress**

This is a proof of concept re-implementation of wwWallet/wallet-backend-server in golang. The intention is to build a version of the wwWallet backend that is ready for large scale production deployment.

## Features

- **Storage Abstraction**: Pluggable storage layer supporting in-memory, SQLite, and MongoDB
- **WebAuthn Support**: Passwordless authentication with hardware security keys
- **OpenID4VCI/VP**: Full support for credential issuance and verification
- **Cloud-Native**: Stateless design for horizontal scaling
- **Zero MySQL Dependency**: Choose from multiple storage backends
- **Standards-Compliant**: Implements W3C Verifiable Credentials and DID standards
- **Trust Delegation**: AuthZEN-based trust evaluation via go-trust PDP

## Trust Management

Trust evaluation is delegated to an external AuthZEN PDP (Policy Decision Point), typically [go-trust](https://github.com/sirosfoundation/go-trust). This design ensures:

- **Consistent trust policy** across all wallet operations
- **No local trust bypasses** - all trust decisions flow through the PDP
- **Flexible trust frameworks** - ETSI TSL, OpenID Federation, DID Web, or custom policies

### Configuration

```yaml
trust:
  # Default trust endpoint for all tenants
  default_endpoint: "http://go-trust:6001"
  
  # Timeout for trust evaluation requests
  timeout: 5s
```

### Per-Tenant Trust Override

Tenants can override the default trust endpoint via their configuration:

```json
{
  "id": "my-tenant",
  "trust_endpoint": "https://custom-pdp.example.com"
}
```

### Testing with Static Registries

For development and testing, go-trust provides static registries:

```bash
# Start go-trust with always-trusted registry (development)
gt --registry static:always-trusted

# Start go-trust with never-trusted registry (testing rejection)
gt --registry static:never-trusted
```

See [go-trust documentation](https://github.com/sirosfoundation/go-trust) for more details.

## Architecture

### Project Structure

```
go-wallet-backend/
├── cmd/
│   ├── server/          # Main application entry point
│   ├── registry/        # VCTM registry server
│   └── wallet-admin/    # Admin CLI tool
├── internal/
│   ├── api/             # HTTP handlers and routes
│   ├── domain/          # Business logic and domain models
│   ├── engine/          # Protocol engine (OID4VCI/VP state machines)
│   ├── service/         # Service layer (keystores, issuance, etc.)
│   ├── storage/         # Storage implementations
│   ├── modes/           # Server operation modes
│   ├── metadata/        # Issuer/verifier metadata fetching
│   └── registry/        # VCTM registry handlers
├── pkg/
│   ├── config/          # Configuration management
│   ├── middleware/      # HTTP middleware
│   ├── trust/           # Trust service (AuthZEN client)
│   └── logging/         # Structured logging
├── docs/
│   └── adr/             # Architecture Decision Records
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

### Multi-Tenancy

The wallet backend supports multiple tenants with isolated data. Users access tenant-scoped APIs through:

```
/t/{tenant_id}/...
```

Example: `/t/acme-corp/storage/vc` accesses credentials for the `acme-corp` tenant.

### Admin API (Port 8081)

The admin API runs on a separate port for internal management. It requires bearer token authentication.

**Authentication:**

The admin API requires a bearer token for all endpoints except `/admin/status`. The token can be:
- Set via the `WALLET_SERVER_ADMIN_TOKEN` environment variable
- Auto-generated on startup (logged to console if not set)

```bash
# Set a fixed token
export WALLET_SERVER_ADMIN_TOKEN=my-secret-admin-token

# Or let the server generate one (check logs for the token)
```

| Endpoint | Description |
|----------|-------------|
| `GET /admin/status` | Health check (no auth required) |
| `GET/POST /admin/tenants` | List/Create tenants |
| `GET/PUT/DELETE /admin/tenants/:id` | Manage a tenant |
| `GET/POST /admin/tenants/:id/users` | Manage tenant users |
| `GET/POST /admin/tenants/:id/issuers` | Manage credential issuers |
| `GET/POST /admin/tenants/:id/verifiers` | Manage verifiers |

**OpenAPI Specification**: [docs/openapi-admin.yaml](docs/openapi-admin.yaml)

#### Admin CLI (wallet-admin)

A command-line tool for managing the admin API:

```bash
# Build the CLI
make build-admin

# Or build manually
go build -o wallet-admin ./cmd/wallet-admin

# Configure the admin URL and token
export WALLET_ADMIN_URL=http://localhost:8081
export WALLET_ADMIN_TOKEN=my-secret-admin-token

# Or pass token via flag
./wallet-admin --token my-secret-admin-token tenant list

# List tenants
./wallet-admin tenant list

# Create a tenant
./wallet-admin tenant create --id my-tenant --name "My Tenant"

# Add an issuer to a tenant
./wallet-admin issuer create --tenant my-tenant --id my-issuer --name "My Issuer" \
  --issuer-url https://issuer.example.com \
  --client-id my-client

# Add a verifier
./wallet-admin verifier create --tenant my-tenant --id my-verifier --name "My Verifier" \
  --endpoint https://verifier.example.com

# Output as JSON
./wallet-admin tenant list --output json
```

**Commands:**

| Command | Description |
|---------|-------------|
| `tenant list` | List all tenants |
| `tenant create` | Create a new tenant |
| `tenant get <id>` | Get tenant details |
| `tenant update <id>` | Update a tenant |
| `tenant delete <id>` | Delete a tenant |
| `user list --tenant <id>` | List users in a tenant |
| `user add --tenant <id> --id <user-id>` | Add user to tenant |
| `user remove --tenant <id> --id <user-id>` | Remove user from tenant |
| `issuer list --tenant <id>` | List issuers in a tenant |
| `issuer create --tenant <id>` | Create an issuer |
| `issuer get <id> --tenant <id>` | Get issuer details |
| `issuer update <id> --tenant <id>` | Update an issuer |
| `issuer delete <id> --tenant <id>` | Delete an issuer |
| `verifier list --tenant <id>` | List verifiers in a tenant |
| `verifier create --tenant <id>` | Create a verifier |
| `verifier get <id> --tenant <id>` | Get verifier details |
| `verifier update <id> --tenant <id>` | Update a verifier |
| `verifier delete <id> --tenant <id>` | Delete a verifier |

**Flags:**

| Flag | Description |
|------|-------------|
| `--url, -u` | Admin API base URL (default: http://localhost:8081) |
| `--token, -t` | Admin API bearer token (or set WALLET_ADMIN_TOKEN) |
| `--output, -o` | Output format: table, json (default: table) |

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
