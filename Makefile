# Go Wallet Backend

.PHONY: help build run test clean docker-build docker-run man install-man

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

build: ## Build the server binary
	@echo "Building server..."
	@go build -o bin/server cmd/server/main.go

build-admin: man ## Build the wallet-admin CLI tool (includes man page)
	@echo "Building wallet-admin CLI..."
	@go build -o bin/wallet-admin ./cmd/wallet-admin

build-all: build build-admin ## Build all binaries

man: ## Copy man pages to bin directory
	@echo "Copying man pages..."
	@mkdir -p bin/man/man1
	@cp docs/wallet-admin.1 bin/man/man1/

install-man: man ## Install man pages to system (requires sudo)
	@echo "Installing man pages..."
	@sudo install -m 644 docs/wallet-admin.1 /usr/local/share/man/man1/
	@sudo mandb

run: build ## Build and run the server
	@echo "Running server..."
	@./bin/server

dev: ## Run with hot reload (requires air)
	@echo "Running in development mode..."
	@air

test: ## Run tests
	@echo "Running tests..."
	@go test -v -race -cover ./...

# Packages excluded from coverage:
# - cmd/* - main packages with init/setup code
# - internal/storage/mongodb - requires real MongoDB instance
COVERAGE_PKGS = ./internal/api/... ./internal/backend/... ./internal/domain/... \
                ./internal/service/... ./internal/storage/memory/... \
                ./internal/websocket/... ./pkg/... ./tests/...

test-coverage: ## Run tests with coverage (excludes untestable packages)
	@echo "Running tests with coverage..."
	@go test -v -race -coverprofile=coverage.out -covermode=atomic $(COVERAGE_PKGS)
	@go tool cover -html=coverage.out -o coverage.html
	@go tool cover -func=coverage.out | tail -1

test-coverage-all: ## Run tests with coverage for all packages
	@echo "Running tests with coverage (all packages)..."
	@go test -v -race -coverprofile=coverage.out -covermode=atomic ./...
	@go tool cover -html=coverage.out -o coverage.html
	@go tool cover -func=coverage.out | tail -1

lint: ## Run linter
	@echo "Running linter..."
	@golangci-lint run

clean: ## Clean build artifacts
	@echo "Cleaning..."
	@rm -rf bin/
	@rm -f coverage.out coverage.html cover.out coverage_*.out
	@rm -f wallet.db
	@rm -f *.log

docker-build: ## Build Docker image
	@echo "Building Docker image..."
	@docker build -t go-wallet-backend:latest .

docker-build-branch: ## Build Docker image from a git branch/tag (usage: make docker-build-branch GIT_REF=feature/multi-tenancy TAG=test)
	@echo "Building Docker image from branch $(GIT_REF)..."
	@docker build --build-arg GIT_REF=$(GIT_REF) -t go-wallet-backend:$(or $(TAG),$(GIT_REF)) .

docker-run: docker-build ## Build and run Docker container
	@echo "Running Docker container..."
	@docker run -p 8080:8080 --rm go-wallet-backend:latest

deps: ## Download dependencies
	@echo "Downloading dependencies..."
	@go mod download
	@go mod verify

tidy: ## Tidy dependencies
	@echo "Tidying dependencies..."
	@go mod tidy

init-db: ## Initialize database (for SQLite)
	@echo "Initializing database..."
	@rm -f wallet.db
	@./bin/server --init-db

.DEFAULT_GOAL := help
