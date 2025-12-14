# Contributing to go-wallet-backend

Thank you for your interest in contributing! This document provides guidelines and instructions for contributing to the project.

## Code of Conduct

Be respectful, inclusive, and professional in all interactions.

## Getting Started

1. **Fork the repository**
   ```bash
   git clone https://github.com/sirosfoundation/go-wallet-backend
   cd go-wallet-backend
   ```

2. **Install dependencies**
   ```bash
   go mod download
   ```

3. **Run tests**
   ```bash
   make test
   ```

4. **Start the server**
   ```bash
   make run
   ```

## Development Workflow

### 1. Create a Branch

```bash
git checkout -b feature/my-feature
```

Branch naming:
- `feature/` - New features
- `fix/` - Bug fixes
- `docs/` - Documentation updates
- `refactor/` - Code refactoring
- `test/` - Test additions/updates

### 2. Make Changes

- Follow Go best practices
- Write clear, self-documenting code
- Add comments for complex logic
- Update documentation as needed

### 3. Run Tests

```bash
# Unit tests
make test

# With coverage
make test-coverage

# Linting
make lint
```

### 4. Commit Changes

Use [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>[optional scope]: <description>

[optional body]

[optional footer(s)]
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation only
- `style`: Code style (formatting, etc.)
- `refactor`: Code refactoring
- `test`: Adding tests
- `chore`: Maintenance tasks

Examples:
```bash
git commit -m "feat: add WebAuthn registration endpoint"
git commit -m "fix: resolve race condition in user store"
git commit -m "docs: update API documentation for credentials"
```

### 5. Push and Create PR

```bash
git push origin feature/my-feature
```

Then create a Pull Request on GitHub.

## Code Style

### Go Guidelines

Follow official Go guidelines:
- [Effective Go](https://go.dev/doc/effective_go)
- [Go Code Review Comments](https://github.com/golang/go/wiki/CodeReviewComments)

### Formatting

```bash
# Format code
go fmt ./...

# Or use gofmt
gofmt -s -w .
```

### Linting

```bash
# Install golangci-lint
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

# Run linter
make lint
```

### Naming Conventions

- **Packages**: lowercase, single word
- **Files**: lowercase with underscores (`user_service.go`)
- **Types**: PascalCase (`UserService`)
- **Functions**: camelCase for private, PascalCase for exported
- **Constants**: PascalCase or UPPER_CASE
- **Interfaces**: Usually -er suffix (`Store`, `UserStore`)

### Code Organization

```go
package mypackage

// Imports grouped by:
// 1. Standard library
// 2. External packages
// 3. Internal packages
import (
    "context"
    "fmt"
    
    "github.com/gin-gonic/gin"
    "go.uber.org/zap"
    
    "github.com/sirosfoundation/go-wallet-backend/internal/domain"
)

// Constants
const (
    DefaultTimeout = 30
)

// Variables
var (
    ErrNotFound = errors.New("not found")
)

// Types
type MyService struct {
    // ...
}

// Constructor
func NewMyService() *MyService {
    return &MyService{}
}

// Methods
func (s *MyService) DoSomething() error {
    // ...
}
```

## Testing Guidelines

### Unit Tests

```go
package mypackage

import (
    "testing"
    
    "github.com/stretchr/testify/assert"
)

func TestMyFunction(t *testing.T) {
    // Arrange
    input := "test"
    expected := "expected"
    
    // Act
    result := MyFunction(input)
    
    // Assert
    assert.Equal(t, expected, result)
}

func TestMyFunction_ErrorCase(t *testing.T) {
    // Test error conditions
    _, err := MyFunction("")
    assert.Error(t, err)
}
```

### Table-Driven Tests

```go
func TestMyFunction(t *testing.T) {
    tests := []struct {
        name     string
        input    string
        expected string
        wantErr  bool
    }{
        {"valid input", "test", "expected", false},
        {"empty input", "", "", true},
        {"special chars", "a@b#c", "a_b_c", false},
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            result, err := MyFunction(tt.input)
            
            if tt.wantErr {
                assert.Error(t, err)
            } else {
                assert.NoError(t, err)
                assert.Equal(t, tt.expected, result)
            }
        })
    }
}
```

### Coverage

Aim for >80% coverage for new code:

```bash
make test-coverage
# Open coverage.html in browser
```

## Documentation

### Code Comments

```go
// UserService handles user-related operations.
// It provides methods for registration, authentication, and user management.
type UserService struct {
    store  storage.Store
    logger *zap.Logger
}

// Register creates a new user account.
// It validates the input, hashes the password, generates a DID,
// and stores the user in the database.
//
// Returns the created user and nil error on success,
// or nil user and an error if registration fails.
func (s *UserService) Register(ctx context.Context, req *domain.RegisterRequest) (*domain.User, error) {
    // Implementation
}
```

### README Updates

Update README.md when adding:
- New features
- Configuration options
- API endpoints
- Dependencies

### API Documentation

Update `docs/API.md` when:
- Adding new endpoints
- Changing request/response formats
- Modifying authentication

## Pull Request Process

### Before Submitting

- [ ] Tests pass locally
- [ ] Linter passes
- [ ] Code is formatted
- [ ] Documentation updated
- [ ] Commit messages follow conventions
- [ ] No merge conflicts

### PR Description

Include:

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
How was this tested?

## Checklist
- [ ] Tests added/updated
- [ ] Documentation updated
- [ ] No breaking changes (or documented)
- [ ] Follows code style guidelines
```

### Review Process

1. Automated checks run (tests, linting)
2. Code review by maintainers
3. Address feedback
4. Approval required before merge
5. Squash and merge to main

## Project Structure

When adding new code, follow this structure:

```
internal/
├── api/          # HTTP handlers only
├── domain/       # Business entities, no dependencies
├── service/      # Business logic, orchestration
└── storage/      # Persistence, implementations

pkg/
├── config/       # Configuration management
├── middleware/   # HTTP middleware
└── <utility>/    # Reusable utilities

cmd/
└── server/       # Application entry points
```

## Adding New Features

### Storage Backend

1. Implement `storage.Store` interface
2. Add to `initStorage()` in `cmd/server/main.go`
3. Update configuration
4. Add tests
5. Update documentation

### API Endpoint

1. Add handler in `internal/api/handlers.go`
2. Add route in `cmd/server/main.go`
3. Add service method if needed
4. Add tests
5. Update `docs/API.md`

### Service

1. Create in `internal/service/`
2. Add to `Services` struct
3. Inject dependencies via constructor
4. Add tests
5. Update documentation

## Common Tasks

### Adding a Dependency

```bash
go get github.com/package/name
go mod tidy
```

### Updating Dependencies

```bash
go get -u ./...
go mod tidy
```

### Running Specific Tests

```bash
go test -v -run TestMyFunction ./internal/service/
```

### Debugging

```bash
# Use delve debugger
dlv debug cmd/server/main.go
```

## Questions?

- Check existing issues
- Review documentation
- Ask in discussions
- Contact maintainers

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
