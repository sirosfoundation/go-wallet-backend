# Go Wallet Backend

.PHONY: help build run test clean docker-build docker-run

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

build: ## Build the server binary
	@echo "Building server..."
	@go build -o bin/server cmd/server/main.go

run: build ## Build and run the server
	@echo "Running server..."
	@./bin/server

dev: ## Run with hot reload (requires air)
	@echo "Running in development mode..."
	@air

test: ## Run tests
	@echo "Running tests..."
	@go test -v -race -cover ./...

test-coverage: ## Run tests with coverage
	@echo "Running tests with coverage..."
	@go test -v -race -coverprofile=coverage.out -covermode=atomic ./...
	@go tool cover -html=coverage.out -o coverage.html

lint: ## Run linter
	@echo "Running linter..."
	@golangci-lint run

clean: ## Clean build artifacts
	@echo "Cleaning..."
	@rm -rf bin/
	@rm -f coverage.out coverage.html
	@rm -f wallet.db
	@rm -f *.log

docker-build: ## Build Docker image
	@echo "Building Docker image..."
	@docker build -t go-wallet-backend:latest .

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
