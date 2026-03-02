#!/usr/bin/env bash
# Pre-commit hook for go-wallet-backend
# Runs golangci-lint before each commit to catch common issues
#
# Tests are run separately via CI/CD and `make test`

set -e

echo "Running pre-commit checks..."

# Check if we're in the right directory
if [ ! -f "go.mod" ]; then
    echo "Error: go.mod not found. Run this from the project root."
    exit 1
fi

# Check if golangci-lint is installed
if ! command -v golangci-lint &> /dev/null; then
    echo "Warning: golangci-lint not installed, skipping lint check"
    echo "Install it with: go install github.com/golangci-lint/golangci-lint/cmd/golangci-lint@latest"
    exit 0
fi

# Run golangci-lint on staged Go files
STAGED_GO_FILES=$(git diff --cached --name-only --diff-filter=ACM | grep "\.go$" || true)
if [ -n "$STAGED_GO_FILES" ]; then
    echo "Running golangci-lint..."
    if ! golangci-lint run --new-from-rev=HEAD~0 ./... 2>&1; then
        echo "golangci-lint failed - fix issues before committing"
        exit 1
    fi
    echo "golangci-lint passed"
else
    echo "No Go files staged"
fi

exit 0
